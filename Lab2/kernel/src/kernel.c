#include "cpio.h"
#include "dtb.h"
#include "int.h"
#include "logo.h"
#include "memory.h"
#include "mini_uart.h"
#include "shell.h"
#include "string.h"

void kernel_main(uintptr_t x0)
{
    uart_init();
    uart_send_string("Welcome to Raspberry Pi 3B+\n");
    send_logo();


    /* get dtb addr */
    // uart_send_string("DTB addr: 0x");
    set_dtb_ptr((uintptr_t)x0);
    // uart_send_hex(get_dtb_ptr());
    // uart_send_string("\n");

    /* get cpio addr */
    fdt_traverse(fdt_find_cpio_ptr);


    // uart_send_string("CPIO addr: 0x");
    // uart_send_hex(get_cpio_ptr());
    // uart_send_string("\n");

    shell();

    while (1)
        ;
}
