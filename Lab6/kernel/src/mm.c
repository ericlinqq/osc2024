#include "mm.h"
#include "arm/mmu.h"
#include "fork.h"
#include "list.h"
#include "memory.h"
#include "mini_uart.h"
#include "page_alloc.h"
#include "sched.h"
#include "slab.h"

void delete_page_tables(struct task_struct* task)
{
    if (task->mm.pgd == pg_dir)
        return;

    unsigned long* pgd = (unsigned long*)(task->mm.pgd + VA_START);

    for (int i = 0; i < PTRS_PER_TABLE; i++) {
        unsigned long* pud = (unsigned long*)((pgd[i] + VA_START) & PAGE_MASK);
        if (pud == (unsigned long*)VA_START)
            continue;
        for (int j = 0; j < PTRS_PER_TABLE; j++) {
            unsigned long* pmd =
                (unsigned long*)((pud[j] + VA_START) & PAGE_MASK);
            if (pmd == (unsigned long*)VA_START)
                continue;
            for (int k = 0; k < PTRS_PER_TABLE; k++) {
                unsigned long* pte =
                    (unsigned long*)((pmd[k] + VA_START) & PAGE_MASK);
                if (pte == (unsigned long*)VA_START)
                    continue;
                kfree(pte);
            }
            kfree(pmd);
        }
        kfree(pud);
    }
    kfree(pgd);

    task->mm.pgd = pg_dir;
}

struct vm_area_struct* find_vm_area(struct task_struct* task,
                                    enum vm_type vm_type)
{
    struct vm_area_struct* vm_area;
    list_for_each_entry (vm_area, &task->mm.mmap_list, list) {
        if (vm_area->vm_type == vm_type)
            return vm_area;
    }
    return NULL;
}

void add_vm_area(struct task_struct* task,
                 enum vm_type vm_type,
                 unsigned long va_start,
                 unsigned long pa_start,
                 unsigned long area_sz,
                 unsigned long vm_prot,
                 unsigned long vm_flags)
{
    struct vm_area_struct* vm_area = kmalloc(sizeof(struct vm_area_struct), 0);
    vm_area->vm_type = vm_type;
    vm_area->va_start = va_start;
    vm_area->pa_start = pa_start;
    vm_area->area_sz = area_sz;
    vm_area->vm_prot = vm_prot;
    vm_area->vm_flags = vm_flags;
    list_add(&vm_area->list, &task->mm.mmap_list);
}

unsigned long allocate_kernel_pages(size_t size, gfp_t flags)
{
    unsigned long page = (unsigned long)kmalloc(size, flags);
    if (!page)
        return 0;
    return page;
}

unsigned long allocate_user_pages(struct task_struct* task,
                                  enum vm_type vm_type,
                                  unsigned long va,
                                  size_t size,
                                  gfp_t flags,
                                  unsigned long vm_prot,
                                  unsigned long vm_flags)
{
    unsigned long page = (unsigned long)kmalloc(size, flags);
    if (!page)
        return 0;
    map_pages(task, vm_type, va, page, size, vm_prot, vm_flags);
    return page;
}

void map_table_entry(unsigned long* pte,
                     unsigned long va,
                     unsigned long pa,
                     unsigned long vm_prot)
{
    unsigned long index = va >> PAGE_SHIFT;
    index &= (PTRS_PER_TABLE - 1);

    unsigned long entry = pa | MMU_PTE_FLAGS;

    if (!(vm_prot & PROT_WRITE)) {
        entry &= ~(0b11 << 6);
        entry |= MM_ACCESS_RO;
    }

    pte[index] = entry;
}


unsigned long map_table(unsigned long* table,
                        unsigned long shift,
                        unsigned long va)
{
    unsigned long index = va >> shift;
    index &= (PTRS_PER_TABLE - 1);
    if (!table[index]) {
        unsigned long next_level_table =
            (unsigned long)kzmalloc(PAGE_SIZE, 0) - VA_START;
        unsigned long entry = next_level_table | MM_TYPE_PAGE_TABLE;
        table[index] = entry;
        return next_level_table;
    }

    return table[index] & PAGE_MASK;
}

void map_page(struct task_struct* task,
              unsigned long va,
              unsigned long page,
              unsigned long vm_prot,
              unsigned long vm_flags)
{
    if (task->mm.pgd == pg_dir)
        task->mm.pgd = (unsigned long)kzmalloc(PAGE_SIZE, 0) - VA_START;

    unsigned long pgd = task->mm.pgd;

    unsigned long pud =
        map_table((unsigned long*)(pgd + VA_START), PGD_SHIFT, va);

    unsigned long pmd =
        map_table((unsigned long*)(pud + VA_START), PUD_SHIFT, va);

    unsigned long pte =
        map_table((unsigned long*)(pmd + VA_START), PMD_SHIFT, va);

    map_table_entry((unsigned long*)(pte + VA_START), va, page - VA_START,
                    vm_prot);
}

void map_pages(struct task_struct* task,
               enum vm_type vm_type,
               unsigned long va,
               unsigned long page,
               size_t size,
               unsigned long vm_prot,
               unsigned long vm_flags)
{
    // size_t nr_pages = (size >> PAGE_SHIFT) + !!(size & (PAGE_SIZE - 1));
    size_t nr_pages = 1 << get_order(size);
    for (int i = 0; i < nr_pages; i++) {
        size_t offset = i << PAGE_SHIFT;
        map_page(task, va + offset, page + offset, vm_prot, vm_flags);
    }
    add_vm_area(task, vm_type, va, page - VA_START, nr_pages << PAGE_SHIFT,
                vm_prot, vm_flags);
}

int copy_virt_memory(struct task_struct* dst)
{
    struct task_struct* src = current_task;

    struct vm_area_struct* vm_area;
    list_for_each_entry (vm_area, &src->mm.mmap_list, list) {
        if (vm_area->vm_type == IO)
            continue;
        unsigned long kernel_va = allocate_user_pages(
            dst, vm_area->vm_type, vm_area->va_start, vm_area->area_sz, 0,
            vm_area->vm_prot, vm_area->vm_flags);
        if (!kernel_va)
            return -1;
        memcpy((void*)kernel_va, (const void*)vm_area->va_start,
               vm_area->area_sz);
    }

    map_pages(dst, IO, IO_PM_START_ADDR, IO_PM_START_ADDR,
              IO_PM_END_ADDR - IO_PM_START_ADDR, PROT_READ | PROT_WRITE,
              MAP_ANONYMOUS);

    return 0;
}

// static int ind = 1;

int do_mem_abort(unsigned long addr, unsigned long esr)
{
    uart_printf("[Translation fault]: 0x%x\n", addr);
    unsigned long addr_align = addr & PAGE_MASK;
    unsigned long dfs = (esr & 0b111111);

    if ((dfs & 0b111100) == 0b100) {
        unsigned long page = (unsigned long)kmalloc(PAGE_SIZE, 0);
        if (!page)
            return -1;
        // map_page(current_task, addr_align, page);
        // ind++;
        // if (ind > 2)
        // return -1;
        return 0;
    }

    if (dfs == 0b000100 || dfs == 0b000101 || dfs == 0b000110 ||
        dfs == 0b000111) {
        struct vm_area_struct* vm_area;
        list_for_each_entry (vm_area, &current_task->mm.mmap_list, list) {
            if (addr_align >= vm_area->va_start &&
                addr_align <=
                    (unsigned long)PAGE_ALIGN_UP(
                        (void*)(vm_area->va_start + vm_area->area_sz))) {
                // map_page(current_task, addr_align,
                //          vm_area->pa_start + (addr_align -
                //          vm_area->va_start));
                return 0;
            }
        }
    }

    return -1;
}


unsigned long* find_page_entry(struct task_struct* task, unsigned long va)
{
    if (task->mm.pgd == pg_dir)
        return NULL;

    unsigned long* pgd =
        (unsigned long*)((task->mm.pgd + VA_START) & PAGE_MASK);
    unsigned long pgd_idx = (va >> PGD_SHIFT) & (PTRS_PER_TABLE - 1);

    unsigned long* pud =
        (unsigned long*)((pgd[pgd_idx] + VA_START) & PAGE_MASK);
    if (pud == (unsigned long*)VA_START)
        return 0;

    unsigned long pud_idx = (va >> PUD_SHIFT) & (PTRS_PER_TABLE - 1);
    unsigned long* pmd =
        (unsigned long*)((pud[pud_idx] + VA_START) & PAGE_MASK);
    if (pmd == (unsigned long*)VA_START)
        return 0;

    unsigned long pmd_idx = (va >> PMD_SHIFT) & (PTRS_PER_TABLE - 1);
    unsigned long* pte =
        (unsigned long*)((pmd[pmd_idx] + VA_START) & PAGE_MASK);
    if (pte == (unsigned long*)VA_START)
        return 0;

    unsigned long pte_idx = (va >> PAGE_SHIFT) & (PTRS_PER_TABLE - 1);
    return pte + pte_idx;
}

void invalidate_page(struct task_struct* task, unsigned long va)
{
    unsigned long* entry = find_page_entry(task, va);
    *entry = MM_TYPE_INVALID;
}

void invalidate_pages(struct task_struct* task, unsigned long va, size_t size)
{
    size_t nr_pages = 1 << get_order(size);
    for (size_t i = 0; i < nr_pages; i++) {
        size_t offset = i << PAGE_SHIFT;
        invalidate_page(task, va + offset);
    }
}
