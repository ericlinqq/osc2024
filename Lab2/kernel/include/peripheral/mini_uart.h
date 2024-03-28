#ifndef P_MINI_UART_H
#define P_MINI_UART_H

#include "peripheral/base.h"

#define AUX_ENABLES     (PBASE + 0x00215004)
#define AUX_MU_IO_REG   (PBASE + 0x00215040)
#define AUX_MU_IER_REG  (PBASE + 0x00215044)
#define AUX_MU_IIR_REG  (PBASE + 0x00215048)
#define AUX_MU_LCR_REG  (PBASE + 0x0021504C)
#define AUX_MU_MCR_REG  (PBASE + 0x00215050)
#define AUX_MU_LSR_REG  (PBASE + 0x00215054)
#define AUX_MU_CNTL_REG (PBASE + 0x00215060)
#define AUX_MU_BAUD_REG (PBASE + 0x00215068)

#endif /* P_MINI_UART_H */
