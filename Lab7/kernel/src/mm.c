#include "mm.h"
#include "arm/mmu.h"
#include "fork.h"
#include "list.h"
#include "memory.h"
#include "mini_uart.h"
#include "page_alloc.h"
#include "sched.h"
#include "slab.h"

#define alloc_vm_area() \
    (struct vm_area_struct*)kmem_cache_alloc(vm_area_struct, 0);
#define free_vm_area(ptr) kmem_cache_free(vm_area_struct, (ptr));

static struct kmem_cache* vm_area_struct;

int vm_init(void)
{
    vm_area_struct =
        kmem_cache_create("vm_area_struct", sizeof(struct vm_area_struct), -1);
    if (!vm_area_struct)
        return 0;
    return 1;
}

void free_vm(struct task_struct* task)
{
    struct vm_area_struct *vm_area, *safe;
    list_for_each_entry_safe (vm_area, safe, &task->mm.mmap_list, list) {
        list_del(&vm_area->list);
        free_vm_area(vm_area);
    }
    delete_page_tables(task);
}

inline void new_page_tables(struct task_struct* task)
{
    task->mm.pgd = (unsigned long)kzmalloc(PAGE_SIZE, 0) - VA_START;
}

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

void copy_page_tables(struct task_struct* dst, struct task_struct* src)
{
    if (src->mm.pgd == pg_dir)
        return;
    unsigned long* src_pgd = (unsigned long*)(src->mm.pgd + VA_START);
    unsigned long* dst_pgd = (unsigned long*)(dst->mm.pgd + VA_START);

    for (int i = 0; i < PTRS_PER_TABLE; i++) {
        unsigned long* src_pud =
            (unsigned long*)((src_pgd[i] + VA_START) & PAGE_MASK);

        if (src_pud == (unsigned long*)VA_START)
            continue;

        unsigned long* dst_pud =
            (unsigned long*)((dst_pgd[i] + VA_START) & PAGE_MASK);

        if (dst_pud == (unsigned long*)VA_START)
            dst_pgd[i] = ((unsigned long)kzmalloc(PAGE_SIZE, 0) - VA_START) |
                         MM_TYPE_PAGE_TABLE;

        dst_pud = (unsigned long*)((dst_pgd[i] + VA_START) & PAGE_MASK);

        for (int j = 0; j < PTRS_PER_TABLE; j++) {
            unsigned long* src_pmd =
                (unsigned long*)((src_pud[j] + VA_START) & PAGE_MASK);

            if (src_pmd == (unsigned long*)VA_START)
                continue;

            unsigned long* dst_pmd =
                (unsigned long*)((dst_pud[j] + VA_START) & PAGE_MASK);

            if (dst_pmd == (unsigned long*)VA_START)
                dst_pud[j] =
                    ((unsigned long)kzmalloc(PAGE_SIZE, 0) - VA_START) |
                    MM_TYPE_PAGE_TABLE;

            dst_pmd = (unsigned long*)((dst_pud[j] + VA_START) & PAGE_MASK);

            for (int k = 0; k < PTRS_PER_TABLE; k++) {
                unsigned long* src_pte =
                    (unsigned long*)((src_pmd[j] + VA_START) & PAGE_MASK);

                if (src_pte == (unsigned long*)VA_START)
                    continue;

                unsigned long* dst_pte =
                    (unsigned long*)((dst_pmd[k] + VA_START) & PAGE_MASK);

                if (dst_pte == (unsigned long*)VA_START)
                    dst_pmd[k] =
                        ((unsigned long)kzmalloc(PAGE_SIZE, 0) - VA_START) |
                        MM_TYPE_PAGE_TABLE;

                dst_pte = (unsigned long*)((dst_pmd[k] + VA_START) & PAGE_MASK);

                for (int l = 0; l < PTRS_PER_TABLE; l++) {
                    unsigned long entry = src_pte[l];
                    if (!(entry & PAGE_MASK))
                        continue;
                    entry &= ~(0b11 << 6);
                    entry |= MM_ACCESS_RO;
                    dst_pte[l] = entry;
                }
            }
        }
    }
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
    struct vm_area_struct* vm_area = alloc_vm_area();
    vm_area->vm_type = vm_type;
    vm_area->va_start = va_start & PAGE_MASK;
    vm_area->pa_start = pa_start & PAGE_MASK;
    vm_area->area_sz = (unsigned long)PAGE_ALIGN_UP((void*)area_sz);
    vm_area->vm_prot = vm_prot;
    vm_area->vm_flags = vm_flags;
    list_add(&vm_area->list, &task->mm.mmap_list);

    if (vm_area->vm_type != IO)
        page_refcnt_inc(phys_to_page((void*)vm_area->pa_start));
}

unsigned long allocate_kernel_pages(size_t size, gfp_t flags)
{
    unsigned long page = (unsigned long)kmalloc(size, flags);
    if (page == VA_START)
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
    if (page == VA_START)
        return 0;
    // map_pages(task, vm_type, va, page, size, vm_prot, vm_flags);
    add_vm_area(task, vm_type, va, page, size, vm_prot, vm_flags);
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
        new_page_tables(task);

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
        add_vm_area(dst, vm_area->vm_type, vm_area->va_start, vm_area->pa_start,
                    vm_area->area_sz, vm_area->vm_prot, vm_area->vm_flags);
        // if (vm_area->vm_type == IO)
        //     continue;
        // unsigned long kernel_va = allocate_user_pages(
        //     dst, vm_area->vm_type, vm_area->va_start, vm_area->area_sz, 0,
        //     vm_area->vm_prot, vm_area->vm_flags);
        // if (kernel_va == VA_START)
        //     return -1;
        // memcpy((void*)kernel_va, (const void*)vm_area->pa_start,
        //       vm_area->area_sz);
    }

    // map_pages(dst, IO, IO_PM_START_ADDR, IO_PM_START_ADDR,
    //           IO_PM_END_ADDR - IO_PM_START_ADDR, PROT_READ | PROT_WRITE,
    //           MAP_ANONYMOUS);
    // add_vm_area(dst, IO, IO_PM_START_ADDR, IO_PM_START_ADDR,
    //             IO_PM_END_ADDR - IO_PM_START_ADDR, PROT_READ | PROT_WRITE,
    //             MAP_ANONYMOUS);

    return 0;
}

int segmentation_fault_handler(unsigned long addr)
{
    uart_printf("[Segmentation fault]: 0x%x, Kill process\n", addr);
    exit_process();
    return 0;
}

int translation_fault_handler(unsigned long addr)
{
    uart_printf("[Translation fault]: 0x%x\n", addr);

    unsigned long addr_align = addr & PAGE_MASK;

    struct vm_area_struct* vm_area;

    list_for_each_entry (vm_area, &current_task->mm.mmap_list, list) {
        if (addr_align >= vm_area->va_start &&
            addr_align < (unsigned long)PAGE_ALIGN_UP(
                             (void*)(vm_area->va_start + vm_area->area_sz))) {
            map_page(current_task, addr_align,
                     vm_area->pa_start + (addr_align - vm_area->va_start),
                     vm_area->vm_prot, vm_area->vm_flags);
            return 0;
        }
    }

    return segmentation_fault_handler(addr);
    return -1;
}

int permission_fault_handler(unsigned long addr)
{
    uart_printf("[Permission fault]: 0x%x\n", addr);

    unsigned long addr_align = addr & PAGE_MASK;

    struct vm_area_struct* vm_area;
    list_for_each_entry (vm_area, &current_task->mm.mmap_list, list) {
        if (addr_align >= vm_area->va_start &&
            addr_align < (unsigned long)PAGE_ALIGN_UP((void*)vm_area->va_start +
                                                      vm_area->area_sz) &&
            vm_area->vm_prot & PROT_WRITE) {
            unsigned long pa_addr =
                vm_area->pa_start + (addr_align - vm_area->va_start);
            struct page* page = phys_to_page((void*)vm_area->pa_start);

            if (get_page_refcnt(page) > 1) {
                page_refcnt_dec(page);
                void* new_addr = kmalloc(vm_area->area_sz, 0);
                memcpy(new_addr, (void*)vm_area->pa_start, vm_area->area_sz);
                vm_area->pa_start = (unsigned long)new_addr;
                pa_addr = vm_area->pa_start + (addr_align - vm_area->va_start);
            }

            map_page(current_task, addr_align, pa_addr, vm_area->vm_prot,
                     vm_area->vm_flags);
            return 0;
        }
    }

    return segmentation_fault_handler(addr);
    return -1;
}


int do_mem_abort(unsigned long addr, unsigned long esr)
{
    unsigned long dfs = (esr & DFSC_MASK);

    if (dfs == TRANS_FAULT_0 || dfs == TRANS_FAULT_1 || dfs == TRANS_FAULT_2 ||
        dfs == TRANS_FAULT_3)
        return translation_fault_handler(addr);

    else if (dfs == PERM_FAULT_1 || dfs == PERM_FAULT_2 || dfs == PERM_FAULT_3)
        return permission_fault_handler(addr);

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
