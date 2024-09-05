#ifndef MM_H
#define MM_H

#define VA_START 0xffff000000000000

#define PHYS_MEMORY_SIZE 0x40000000

#define PAGE_MASK     0xfffffffffffff000
#define PAGE_SHIFT    12
#define TABLE_SHIFT   9
#define SECTION_SHIFT (PAGE_SHIFT + TABLE_SHIFT)  // 21

#define PAGE_SIZE    (1 << PAGE_SHIFT)     // 4K
#define SECTION_SIZE (1 << SECTION_SHIFT)  // 2M

#define LOW_MEMORY  (2 * SECTION_SIZE)  // 0x400000
#define HIGH_MEMORY DEVICE_BASE

#define PAGING_MEMORY (HIGH_MEMORY - LOW_MEMORY)
#define PAGING_PAGES  (PAGING_MEMORY / PAGE_SIZE)

#define PTRS_PER_TABLE (1 << TABLE_SHIFT)

#define PGD_SHIFT (PAGE_SHIFT + 3 * TABLE_SHIFT)
#define PUD_SHIFT (PAGE_SHIFT + 2 * TABLE_SHIFT)
#define PMD_SHIFT (PAGE_SHIFT + TABLE_SHIFT)

#define PG_DIR_SIZE (4 * PAGE_SIZE)


#define PROT_NONE  0
#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4

#define MAP_ANONYMOUS 0x20
#define MAP_POPULATE  1

#define DFSC_MASK 0b111111

#define TRANS_FAULT_0 0b000100
#define TRANS_FAULT_1 0b000101
#define TRANS_FAULT_2 0b000110
#define TRANS_FAULT_3 0b000111

#define PERM_FAULT_1 0b001101
#define PERM_FAULT_2 0b001110
#define PERM_FAULT_3 0b001111


#ifndef __ASSEMBLER__

#include "gfp_types.h"
#include "sched.h"

int vm_init(void);
void free_vm(struct task_struct* task);

void memzero(unsigned long src, unsigned long n);

void map_pages(struct task_struct* task,
               enum vm_type vm_type,
               unsigned long va,
               unsigned long page,
               size_t size,
               unsigned long vm_prot,
               unsigned long vm_flags);

int copy_virt_memory(struct task_struct* dst);
unsigned long allocate_kernel_pages(size_t size, gfp_t flags);
unsigned long allocate_user_pages(struct task_struct* task,
                                  enum vm_type vm_type,
                                  unsigned long va,
                                  size_t size,
                                  gfp_t flags,
                                  unsigned long vm_prot,
                                  unsigned long vm_flags);

struct vm_area_struct* find_vm_area(struct task_struct* task,
                                    enum vm_type vm_type);
void add_vm_area(struct task_struct* task,
                 enum vm_type vm_type,
                 unsigned long va_start,
                 unsigned long pa_start,
                 unsigned long area_sz,
                 unsigned long vm_prot,
                 unsigned long vm_flags);

void invalidate_pages(struct task_struct* task, unsigned long va, size_t size);
unsigned long* find_page_entry(struct task_struct* task, unsigned long va);

void new_page_tables(struct task_struct* task);
void delete_page_tables(struct task_struct* task);
void copy_page_tables(struct task_struct* dst, struct task_struct* src);

#endif

#endif /* MM_H */
