#include "entry.h"

#define S_FRAME_SIZE 16 * 17

.macro save_all
    sub sp, sp, #S_FRAME_SIZE
    stp x0, x1, [sp, #16 * 0]
    stp x2, x3, [sp, #16 * 1]
    stp x4, x5, [sp, #16 * 2]
    stp x6, x7, [sp, #16 * 3]
    stp x8, x9, [sp, #16 * 4]
    stp x10, x11, [sp, #16 * 5]
    stp x12, x13, [sp, #16 * 6]
    stp x14, x15, [sp, #16 * 7]
    stp x16, x17, [sp, #16 * 8]
    stp x18, x19, [sp, #16 * 9]
    stp x20, x21, [sp, #16 * 10]
    stp x22, x23, [sp, #16 * 11]
    stp x24, x25, [sp, #16 * 12]
    stp x26, x27, [sp, #16 * 13]
    stp x28, x29, [sp, #16 * 14]
    str x30, [sp, #16 * 15]
    
    // push information for nested interrupt
    mrs x0, spsr_el1
    mrs x1, elr_el1
    stp x0, x1, [sp, #16 * 16]

    // restore x0, x1
    ldp x0, x1, [sp, #16 * 0]
.endm

.macro load_all
    // pop information for nested interrupt
    ldp x0, x1, [sp, #16 * 16]
    msr spsr_el1, x0
    msr elr_el1, x1

    ldp x0, x1, [sp, #16 * 0]
    ldp x2, x3, [sp, #16 * 1]
    ldp x4, x5, [sp, #16 * 2]
    ldp x6, x7, [sp, #16 * 3]
    ldp x8, x9, [sp, #16 * 4]
    ldp x10, x11, [sp, #16 * 5]
    ldp x12, x13, [sp, #16 * 6]
    ldp x14, x15, [sp, #16 * 7]
    ldp x16, x17, [sp, #16 * 8]
    ldp x18, x19, [sp, #16 * 9]
    ldp x20, x21, [sp, #16 * 10]
    ldp x22, x23, [sp, #16 * 11]
    ldp x24, x25, [sp, #16 * 12]
    ldp x26, x27, [sp, #16 * 13]
    ldp x28, x29, [sp, #16 * 14]
    ldr x30, [sp, #16 * 15]

    add sp, sp, #S_FRAME_SIZE
.endm

.macro ventry label
    .align 7
    b \label
.endm

.macro handle_invalid_entry type
    save_all
    mov x0, #\type
    mrs x1, spsr_el1
    mrs x2, esr_el1
    mrs x3, elr_el1
    bl show_invalid_entry_message
    load_all
    eret
.endm

.macro handle_irq 
    save_all
    bl irq_handler
    load_all
    eret
.endm



.align 11
.globl exception_vector_table
exception_vector_table:
ventry sync_invalid_el1t
ventry irq_invalid_el1t
ventry fiq_invalid_el1t
ventry error_invalid_el1t 


ventry sync_invalid_el1h
ventry irq_invalid_el1h
ventry fiq_invalid_el1h
ventry error_invalid_el1h

ventry sync_invalid_el0_64
ventry irq_invalid_el0_64
ventry fiq_invalid_el0_64
ventry error_invalid_el0_64

ventry sync_invalid_el0_32
ventry irq_invalid_el0_32
ventry fiq_invalid_el0_32
ventry error_invalid_el0_32



sync_invalid_el1t:
handle_invalid_entry  SYNC_INVALID_EL1t

irq_invalid_el1t:
handle_invalid_entry  IRQ_INVALID_EL1t

fiq_invalid_el1t:
handle_invalid_entry  FIQ_INVALID_EL1t

error_invalid_el1t:
handle_invalid_entry  ERROR_INVALID_EL1t



sync_invalid_el1h:
handle_invalid_entry  SYNC_INVALID_EL1h

irq_invalid_el1h:
handle_irq 

fiq_invalid_el1h:
handle_invalid_entry  FIQ_INVALID_EL1h

error_invalid_el1h:
handle_invalid_entry  ERROR_INVALID_EL1h



sync_invalid_el0_64:
handle_invalid_entry  SYNC_INVALID_EL0_64

irq_invalid_el0_64:
handle_irq

fiq_invalid_el0_64:
handle_invalid_entry  FIQ_INVALID_EL0_64

error_invalid_el0_64:
handle_invalid_entry  ERROR_INVALID_EL0_64



sync_invalid_el0_32:
handle_invalid_entry  SYNC_INVALID_EL0_32

irq_invalid_el0_32:
handle_invalid_entry  IRQ_INVALID_EL0_32

fiq_invalid_el0_32:
handle_invalid_entry  FIQ_INVALID_EL0_32

error_invalid_el0_32:
handle_invalid_entry  ERROR_INVALID_EL0_32
