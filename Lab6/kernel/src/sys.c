#include "sys.h"
#include "cpio.h"
#include "fork.h"
#include "mailbox.h"
#include "memory.h"
#include "mini_uart.h"
#include "page_alloc.h"
#include "sched.h"
#include "signal.h"
#include "slab.h"

int sys_getpid(void)
{
    return current_task->pid;
}

size_t sys_uart_read(char buf[], size_t size)
{
    size_t i;
    for (i = 0; i < size; i++)
        buf[i] = uart_recv();

    return i;
}


size_t sys_uart_write(const char buf[], size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        if (buf[i] == '\n')
            uart_send('\r');
        uart_send(buf[i]);
    }
    return i;
}

int sys_exec(const char* name, char const* argv[])
{
    return cpio_load((char*)name);
}

int sys_fork(void)
{
    return copy_process(0, NULL, NULL, NULL);
}

void sys_exit(void)
{
    exit_process();
}


int sys_mbox_call(unsigned char ch, unsigned int* mbox)
{
    unsigned long offset =
        (unsigned long)mbox - ((unsigned long)mbox & PAGE_MASK);
    unsigned long* entry = find_page_entry(current_task, (unsigned long)mbox);
    unsigned int* mbox_map =
        (unsigned int*)(((*entry + VA_START) & PAGE_MASK) + offset);
    int res = mailbox_call(ch, mbox_map);
    return res;
}


void sys_kill(int pid)
{
    struct task_struct* target = find_task(pid);
    kill_task(target);
}


void sys_signal(int SIGNAL, void (*handler)())
{
    reg_sig_handler(current_task, SIGNAL, handler);
}


void sys_sigkill(int pid, int SIGNAL)
{
    struct task_struct* task = find_task(pid);
    if (!task)
        return;
    recv_sig(task, SIGNAL);
}

void* sys_mmap(void* addr,
               size_t len,
               int prot,
               int flags,
               int fd,
               int file_offset)
{
    struct vm_area_struct* vm_area;
    unsigned long addr_align = (unsigned long)addr & PAGE_MASK;
    if (addr) {
        list_for_each_entry (vm_area, &current_task->mm.mmap_list, list) {
            if (vm_area->va_start <= (unsigned long)addr &&
                vm_area->va_start + vm_area->area_sz > (unsigned long)addr) {
                addr = NULL;
                break;
            }
        }
    }

    if (!addr) {
        while (1) {
            bool used = false;
            list_for_each_entry (vm_area, &current_task->mm.mmap_list, list) {
                if (vm_area->va_start <= addr_align &&
                    vm_area->va_start + vm_area->area_sz > addr_align) {
                    used = true;
                    break;
                }
            }
            if (used)
                addr_align += PAGE_SIZE;
            else
                break;
        }
    }

    size_t len_align = (size_t)PAGE_ALIGN_UP((void*)len);


    allocate_user_pages(current_task, DATA, addr_align, len_align, 0, prot,
                        flags);

    return (void*)addr_align;
}

void sys_sig_return(void)
{
    do_sig_return();
}

void* const sys_call_table[] = {[SYS_GET_PID_NUMBER] = sys_getpid,
                                [SYS_UART_READ_NUMBER] = sys_uart_read,
                                [SYS_UART_WRITE_NUMBER] = sys_uart_write,
                                [SYS_EXEC_NUMBER] = sys_exec,
                                [SYS_FORK_NUMBER] = sys_fork,
                                [SYS_EXIT_NUMBER] = sys_exit,
                                [SYS_MBOX_CALL_NUMBER] = sys_mbox_call,
                                [SYS_KILL_NUMBER] = sys_kill,
                                [SYS_SIGNAL_NUMBER] = sys_signal,
                                [SYS_SIGKILL_NUMBER] = sys_sigkill,
                                [SYS_MMAP_NUMBER] = sys_mmap,
                                [SYS_SIG_RETURN_NUMBER] = sys_sig_return};
