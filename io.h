#ifndef __IO_H_
#define __IO_H_

#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "xparameters.h"
#include "xstatus.h"
#include "xintc.h"
#include "xil_exception.h"
#include "xgpio.h"
#include "platform.h"
#include "xil_printf.h"
#include "mb_interface.h"

// general io offsets
#define IO_ADDR_HIGH_READ_ADDR_OFFSET	0
#define IO_ADDR_HIGH_READ_DATA_OFFSET	4	// size shares the same
#define IO_ADDR_HIGH_WRITE_ADDR_OFFSET	8
#define IO_ADDR_HIGH_WRITE_DATA_OFFSET	12
#define IO_ADDR_HIGH_WRITE_SIZE_OFFSET	16	// recipt shares the same
#define IO_ADDR_HIGH_IRQ_CLEAR_OFFSET	20
#define IO_ADDR_HIGH_TCS_COMMAND_OFFSET	24
#define IO_ADDR_HIGH_NON_TCS_COMMAND_OFFSET	28

// general io flags
#define IO_ADDR_HIGH_TCS_COMMAND_RECIPT_OFFSET	1		// should be used with the actual command to confirm
#define IO_ADDR_HIGH_TCS_COMMAND_START 			333
#define IO_ADDR_HIGH_TCS_COMMAND_STOP 			366
#define IO_ADDR_HIGH_NON_TCS_RESET		111

// device io related
#define IO_ADDR_HIGH_MB_4_TRANSFER_BASE 0x75006000LL
#define MB_IO_OFFSET_STATUS 0
#define MB_IO_OFFSET_PS_STATUS 4
#define MB_IO_OFFSET_LOG_PRINT 444

// IMX274 & IIC
#define IO_ADDR_HIGH_MB_4_IMX274_BASE 0x75001000LL
#define MMIO_IMX274_BASE 0xA0051000LL
#define IMX274_RESET_DELAY2			(2200)
#define XIIC_IISR_OFFSET     0x20 /* Interrupt Status Register */
#define XIIC_IIER_OFFSET     0x28 /* Interrupt Enable Register */
#define IMX274_GPIO_IRQ_BIT_MASK 0
#define IMX274_GPIO_RESET_BIT_MASK 0

// CSI 2
#define IO_ADDR_HIGH_MB_4_CSI_2_RXSS_BASE 0x75000000LL
#define MMIO_CSI_2_RXSS_BASE 0xA00F0000LL

// XDMSC
#define IO_ADDR_HIGH_MB_4_XDMSC_BASE 0x75002000LL
#define MMIO_XDMSC_BASE 0xA0250000LL
#define XDMSC_GPIO_RESET_BIT_MASK 1

// XG
#define IO_ADDR_HIGH_MB_4_XG_BASE 0x75003000LL
#define MMIO_XG_BASE 0xA0270000LL
#define XG_GPIO_RESET_BIT_MASK 2

// XCSC
#define IO_ADDR_HIGH_MB_4_XCSC_BASE 0x75004000LL
#define MMIO_XCSC_BASE 0xA0240000LL
#define XCSC_GPIO_RESET_BIT_MASK 3

// XSCALER
#define IO_ADDR_HIGH_MB_4_XSCALER_BASE 0x75005000LL
#define MMIO_XSCALER_BASE 0xA0200000LL
#define XSCALER_GPIO_RESET_BIT_MASK 4

// FBWRITER
#define IO_ADDR_HIGH_MB_4_FBWRITER_BASE 0x75007000LL
#define MMIO_FBWRITER_BASE 0xA0260000LL
#define FBWRITER_GPIO_RESET_BIT_MASK 5
#define FBWRITER_GPIO_IRQ_BIT_MASK 2

// XVCU
#define IO_ADDR_HIGH_MB_4_XVCU_DATA_BASE 0x800000000LL
#define MMIO_XVCU_BASE 0xA0100000LL
#define MMIO_AL5E_BASE 0xA0100000LL

//// r_hasher
//#define R_HASHER_VIOLATION_FLAG_ADDR 0x1260008
//
// e_hasher
//#define E_HASHER_VIOLATION_FLAG_ADDR 0x1210008
//#define E_HASHER_HASH_READING_CTRL_ADDR 0x240000
//#define E_HASHER_RESET_ADDR 0x240008
//#define E_HASHER_HASH_ADDR 0x200000
#define E_HASHER_NUM_OF_READ_NEEDED_4_HASH 8

u32 device_io_read(const u64 addr, const u32 size);
void device_io_write(const u64 addr, const u32 val, const u32 size);
int check_tcs_command_existence(const u64 os_addr_to_check, const u32 value_to_check_against);
void confirm_completion_of_tcs_command(const u64 os_addr_to_confirm, const u32 value_to_confirm);

#endif
