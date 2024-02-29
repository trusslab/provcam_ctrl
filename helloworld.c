/******************************************************************************
*
* Copyright (C) 2009 - 2014 Xilinx, Inc.  All rights reserved.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* Use of the Software is limited solely to applications:
* (a) running on a Xilinx device, or
* (b) that interact with a Xilinx device through a bus or interconnect.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
* XILINX  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
* Except as contained in this notice, the name of the Xilinx shall not be used
* in advertising or otherwise to promote the sale, use or other dealings in
* this Software without prior written authorization from Xilinx.
*
******************************************************************************/

/*
 * helloworld.c: simple test application
 *
 * This application configures UART 16550 to baud rate 9600.
 * PS7 UART (Zynq) is not initialized by this application, since
 * bootrom/bsp configures it to baud rate 115200
 *
 * ------------------------------------------------
 * | UART TYPE   BAUD RATE                        |
 * ------------------------------------------------
 *   uartns550   9600
 *   uartlite    Configurable only in HW design
 *   ps7_uart    115200 (configured by bootrom/bsp)
 */
#include "xparameters.h"
#include "xstatus.h"
#include "xintc.h"
#include "xil_exception.h"
#include "xgpio.h"

#include <stdio.h>
#include "platform.h"
#include "xil_printf.h"
#include "mb_interface.h"
#include <time.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// ecdsa
#include "micro-ecc/uECC.h"
#include <string.h>
#include <time.h>

// Base64
#include <stdint.h>
#include <stdlib.h>

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}


char *private_b64 = "sLNRiZYpJiMKIizZS67tZv9ePIEDlaNABXIPm/g5PS4=";
char *public_b64 = "GXVdaVpm48wuA+WFHs9K6ap02Y5uOMXXjOpCCo6ZRLP67PQz3J3RdNdFNxzUng6K9nTSIP+fFSd40T1CYDC3cg==";
// end of signing related

#include "sec_presets/presets.h"
#include "io.h"
#include "replay.h"

// Replay status
#define REPLAY_STATUS_INIT 0
#define REPLAY_STATUS_WAIT_4_START 1
#define REPLAY_STATUS_START 2
#define REPLAY_STATUS_WAIT_4_STOP 3
#define REPLAY_STATUS_STOP 4
#define REPLAY_STATUS_FINISHED 5

// IMX274 & IIC
u8 is_i2c_irq_triggerred = 0;
u8 imx274_current_status = 0;	// 0: init; 1: wait for start; 2: start; 3: wait for stop; 4: stop; 5: done;
Replay_toolset *imx274_replay_toolset = NULL;

// CSI 2
u8 csi2rxss_current_status = 0;	// 0: init; 1: wait for start; 2: start; 3: wait for stop; 4: stop; 5: done;
Replay_toolset *csi2rxss_replay_toolset = NULL;

// XDMSC
u8 xdmsc_current_status = 0;	// 0: init; 1: wait for start; 2: start; 3: wait for stop; 4: stop; 5: done;
Replay_toolset *xdmsc_replay_toolset = NULL;

// XG
u8 xg_current_status = 0;	// 0: init; 1: wait for start; 2: start; 3: wait for stop; 4: stop; 5: done;
Replay_toolset *xg_replay_toolset = NULL;

// XCSC
u8 xcsc_current_status = 0;	// 0: init; 1: wait for start; 2: start; 3: wait for stop; 4: stop; 5: done;
Replay_toolset *xcsc_replay_toolset = NULL;

// XSCALER
u8 xscaler_current_status = 0;	// 0: init; 1: wait for start; 2: start; 3: wait for stop; 4: stop; 5: done;
Replay_toolset *xscaler_replay_toolset = NULL;

// FBWRITER
u8 fbwriter_current_status = 0;	// 0: init; 1: wait for start; 2: start; 3: wait for stop; 4: stop; 5: done;
Replay_toolset *fbwriter_replay_toolset = NULL;

// XVCU
u8 is_xvcu_firmware_loaded = 0;

// logging related
#define DEBUG_RECORD_BLOCK_SIZE 4
#define DEBUG_RECORD_BASE_ADDR 0x800200000LL
u32 total_num_of_commands = 0;
u32 current_record_addr_offset = DEBUG_RECORD_BLOCK_SIZE;	// leave a block of space for total_num_of_commands
#define DEBUG_LOG_PRINT_MAX 1600
#define DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR IO_ADDR_HIGH_MB_4_FBWRITER_BASE
u8 can_record_irq = 1;
const u32 current_recording_irq_addr = 0x00000020;
int num_of_commands_counter = 0;
//u32 *i2c_addrs;
//u32 *i2c_vals;
//u8 *i2c_types;

// irq related
static XIntc InterruptController;
#define INTC_DEVICE_ID		  XPAR_INTC_0_DEVICE_ID
#define IRQ_CLEAR_MARK 666
XGpio irq_gpio;
u32 current_irq_value = 0;

// reset related
XGpio reset_gpio;
u32 current_reset_value = 0;

// r_hasher and e_hasher related
XGpio r_hasher_violation_flag_gpio;
XGpio e_hasher_ctrl_gpio;
XGpio e_hasher_violation_flag_gpio;
XGpio e_hasher_hash_gpio;

// status
#define MB_TCS_MODE_MARK 111
#define MB_NON_TCS_MODE_MARK 222
u8 is_in_tcs_mode = 1;
u8 is_tcs_driver_inited = 0;
u8 replay_confirmation_counter = 0;	// ensure that we only confirm the number of times we need; can be improved

// recording related
#define RECODING_STATUS_OFFSET 0x1A0
u8 is_recording_paused = 0;

// timing related
u64 mb_sys_timer = 0;

int sign_w_ecdsa(uint8_t *hash, uint8_t *sig)
{
    int i, c;
//	uint8_t private[32] = {0};
//	uint8_t public[64] = {0};
    uint8_t *private;
    uint8_t *public;
//	uint8_t hash[32] = {0};
//	uint8_t sig[64] = {0};

//	printf("making keys...\n");
//	if (!uECC_make_key(public, private, uECC_secp256r1())) {
//		printf("uECC_make_key() failed\n");
//		return 1;
//	}

//    printf("preparing keys...\n");
    long decode_size = strlen(private_b64);
//    printf("priv size: %d.\n", decode_size);
    private = base64_decode(private_b64, decode_size, &decode_size);
    decode_size = strlen(public_b64);
//    printf("pub size: %d.\n", decode_size);
    public = base64_decode(public_b64, decode_size, &decode_size);

    // for eval only
	memcpy(hash, public, sizeof(hash));

//	printf("signing with size: %d...\n", sizeof(hash));
//	if (!uECC_sign(private, hash, sizeof(hash), sig, uECC_secp256r1())) {
	if (!uECC_sign(private, hash, 32, sig, uECC_secp256r1())) {
		printf("uECC_sign() failed\n");
		return 1;
	}

//	printf("verifying...\n");
//	if (!uECC_verify(public, hash, sizeof(hash), sig, uECC_secp256r1())) {
//		printf("uECC_verify() failed\n");
//		return 1;
//	}

//	printf("freeing...\n");
    free(private);
    free(public);
    base64_cleanup();

//    printf("returning...\n");
    return 0;
}

int forward_read_command(const u64 base_os_addr, const u64 base_device_addr)
{
	u32 temp_addr, temp_data;

	// get size
	temp_data = lwea(base_os_addr + IO_ADDR_HIGH_READ_DATA_OFFSET);

	// read
	if ((temp_data == 32) || (temp_data == 16) || (temp_data == 8))
	{
		// get addr
		temp_addr = lwea(base_os_addr + IO_ADDR_HIGH_READ_ADDR_OFFSET);

		// read from device
		temp_data = device_io_read(base_device_addr + temp_addr, temp_data);

		// Record
		if ((base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR) && (!is_recording_paused))
		{
		//		if ((lwea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset - (DEBUG_RECORD_BLOCK_SIZE * 3)) == 0)
		//				&& (lwea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset - (DEBUG_RECORD_BLOCK_SIZE * 2)) == temp_addr)
		//				&& (lwea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset - DEBUG_RECORD_BLOCK_SIZE) == temp_data_8))
		//		{
		//			swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset - (DEBUG_RECORD_BLOCK_SIZE * 3), 2);
		//		}
		//		else
			{
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, 0);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_addr);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_data);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR, ++total_num_of_commands);
			}
		}

		// Debug print
//		if (base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR)
//			printf("Valid read during current_irq_value: %d, with addr: 0x%08x, data: 0x%08x.\n", current_irq_value, temp_addr, temp_data);

		// write it back
		swea(base_os_addr + IO_ADDR_HIGH_READ_DATA_OFFSET, temp_data);
	}

	return 0;
}

int forward_write_command(const u64 base_os_addr, const u64 base_device_addr)
{
	u32 temp_addr, temp_data, temp_trigger;

	// get size
	temp_trigger = lwea(base_os_addr + IO_ADDR_HIGH_WRITE_SIZE_OFFSET);

	// write
	if ((temp_trigger == 32) || (temp_trigger == 16) || (temp_trigger == 8))
	{
		// get addr & data to write
		temp_addr = lwea(base_os_addr + IO_ADDR_HIGH_WRITE_ADDR_OFFSET);
		temp_data = device_io_read(base_os_addr + IO_ADDR_HIGH_WRITE_DATA_OFFSET, temp_trigger);

		// Record
		if ((base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR) && (!is_recording_paused))
		{
			swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, 1);
			current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
			swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_addr);
			current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
			swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_data);
			current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
			swea(DEBUG_RECORD_BASE_ADDR, ++total_num_of_commands);
		}

		// Debug print
//		if (base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR)
//			printf("Valid write during current_irq_value: %d, with addr: 0x%08x, data: 0x%08x.\n", current_irq_value, temp_addr, temp_data);

		// write to device
		device_io_write(base_device_addr + temp_addr, temp_data, temp_trigger);

		// send write receipt
		swea(base_os_addr + IO_ADDR_HIGH_WRITE_SIZE_OFFSET, 0);
	}

	return 0;
}

int check_and_forward_write_command(const int current_mode, const void* addr_to_check_against, const void* sec_addr_to_check_against, const void* command_to_check_against, const void* sec_command_to_check_against, const u64 base_os_addr, const u64 base_device_addr)
{
	u32 temp_addr, temp_trigger;
	u32 temp_data_32;
	u16 temp_data_16;
	u8 temp_data_8;

	int not_match_with_first;

	// handle write
	temp_trigger = lwea(base_os_addr + IO_ADDR_HIGH_WRITE_SIZE_OFFSET);
	switch (temp_trigger)
	{
		case 8:
			temp_addr = lwea(base_os_addr + IO_ADDR_HIGH_WRITE_ADDR_OFFSET);
			temp_data_8 = lbuea(base_os_addr + IO_ADDR_HIGH_WRITE_DATA_OFFSET);

			not_match_with_first = memcmp(&temp_addr, addr_to_check_against, 4) && memcmp(&temp_data_8, command_to_check_against, 1);
			if ((current_mode == 2) && not_match_with_first && memcmp(&temp_addr, sec_addr_to_check_against, 4) && memcmp(&temp_data_8, sec_command_to_check_against, 1))
			{
				printf("(8)WRITE not match: addr: 0x%08x, val: 0x%08x, should be addr: 0x%08x, val: 0x%08x, or addr: 0x%08x, val: 0x%08x.\n", temp_addr, temp_data_8, *(u32*)(addr_to_check_against), *(u32*)(command_to_check_against), *(u32*)(sec_addr_to_check_against), *(u32*)(sec_command_to_check_against));
				return -1;
			}

			// Record
			if ((base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR) && (!is_recording_paused))
			{
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, 1);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_addr);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_data_8);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR, ++total_num_of_commands);
			}

			sbea(base_device_addr + temp_addr, temp_data_8);
			swea(base_os_addr + IO_ADDR_HIGH_WRITE_SIZE_OFFSET, 0);

			// Now we can continue recording irq
			if (temp_addr == current_recording_irq_addr)
				can_record_irq = 1;

			// Debug print
//			if ((num_of_commands_counter < DEBUG_LOG_PRINT_MAX) && (base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR))
//			{
//				i2c_addrs[num_of_commands_counter] = temp_addr;
//				i2c_vals[num_of_commands_counter] = temp_data_8;
//				i2c_types[++num_of_commands_counter] = 1;
//			}
//				printf("(8)WRITE: addr: 0x%08x, val: 0x%08x.\n", temp_addr, temp_data_8);

			if (!not_match_with_first)
				return 1;
			else
				return 2;
			break;
		case 16:
			temp_addr = lwea(base_os_addr + IO_ADDR_HIGH_WRITE_ADDR_OFFSET);
			temp_data_16 = lhuea(base_os_addr + IO_ADDR_HIGH_WRITE_DATA_OFFSET);

			not_match_with_first = memcmp(&temp_addr, addr_to_check_against, 4) && memcmp(&temp_data_16, command_to_check_against, 2);
			if ((current_mode == 2) && not_match_with_first && memcmp(&temp_addr, sec_addr_to_check_against, 4) && memcmp(&temp_data_16, sec_command_to_check_against, 2))
			{
				printf("(16)WRITE not match: addr: 0x%08x, val: 0x%08x, should be addr: 0x%08x, val: 0x%08x, or addr: 0x%08x, val: 0x%08x.\n", temp_addr, temp_data_16, *(u32*)(addr_to_check_against), *(u32*)(command_to_check_against), *(u32*)(sec_addr_to_check_against), *(u32*)(sec_command_to_check_against));
				return -1;
			}

			// Record
			if ((base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR) && (!is_recording_paused))
			{
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, 1);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_addr);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_data_16);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR, ++total_num_of_commands);
			}

			shea(base_device_addr + temp_addr, temp_data_16);
			swea(base_os_addr + IO_ADDR_HIGH_WRITE_SIZE_OFFSET, 0);

			// Now we can continue recording irq
			if (temp_addr == current_recording_irq_addr)
				can_record_irq = 1;

			// Debug print
//			if ((num_of_commands_counter < DEBUG_LOG_PRINT_MAX) && (base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR))
//			{
//				i2c_addrs[num_of_commands_counter] = temp_addr;
//				i2c_vals[num_of_commands_counter] = temp_data_16;
//				i2c_types[++num_of_commands_counter] = 1;
//			}
//				printf("(16)WRITE: addr: 0x%08x, val: 0x%08x.\n", temp_addr, temp_data_16);

			if (!not_match_with_first)
				return 1;
			else
				return 2;
			break;
		case 32:
			temp_addr = lwea(base_os_addr + IO_ADDR_HIGH_WRITE_ADDR_OFFSET);
			temp_data_32 = lwea(base_os_addr + IO_ADDR_HIGH_WRITE_DATA_OFFSET);

			not_match_with_first = memcmp(&temp_addr, addr_to_check_against, 4) && memcmp(&temp_data_32, command_to_check_against, 4);
			if ((current_mode == 2) && not_match_with_first && memcmp(&temp_addr, sec_addr_to_check_against, 4) && memcmp(&temp_data_32, sec_command_to_check_against, 4))
			{
				printf("(32)WRITE not match: addr: 0x%08x, val: 0x%08x, should be addr: 0x%08x, val: 0x%08x, or addr: 0x%08x, val: 0x%08x.\n", temp_addr, temp_data_32, *(u32*)(addr_to_check_against), *(u32*)(command_to_check_against), *(u32*)(sec_addr_to_check_against), *(u32*)(sec_command_to_check_against));
				return -1;
			}

			// Record
			if ((base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR) && (!is_recording_paused))
			{
				// Disable irq
//				XIntc_Disable(&InterruptController, XPAR_INTC_0_IIC_0_VEC_ID);

				// Log
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, 1);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_addr);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, temp_data_32);
				current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
				swea(DEBUG_RECORD_BASE_ADDR, ++total_num_of_commands);

				// Enable irq
//				XIntc_Enable(&InterruptController, XPAR_INTC_0_IIC_0_VEC_ID);
			}

			swea(base_device_addr + temp_addr, temp_data_32);
			swea(base_os_addr + IO_ADDR_HIGH_WRITE_SIZE_OFFSET, 0);

			// Now we can continue recording irq
			if (temp_addr == current_recording_irq_addr)
				can_record_irq = 1;

			// Debug print
//			if ((num_of_commands_counter < DEBUG_LOG_PRINT_MAX) && (base_os_addr == DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR))
//			{
//				i2c_addrs[num_of_commands_counter] = temp_addr;
//				i2c_vals[num_of_commands_counter] = temp_data_32;
//				i2c_types[++num_of_commands_counter] = 1;
//			}
//			if (base_os_addr == IO_ADDR_HIGH_MB_4_FBWRITER_BASE)
//				printf("(32)WRITE: addr: 0x%08x, val: 0x%08x.\n", temp_addr, temp_data_32);

			if (!not_match_with_first)
				return 1;
			else
				return 2;
			break;
		default:
			break;
	}

	return 0;
}

u32 replay_task(Replay_toolset *replay_toolset, const u64 dev_io_base_addr, const u32 irq_marker, u8 *irq_trigger_counter)
{
	// Return 0 if successfully executed, 1 if error, 2 if all finished
	u32 initial_counter = replay_toolset->current_replay_pointer;

	// return if finished
	if (replay_toolset->current_replay_pointer >= replay_toolset->current_replay_preset.preset_counter_total)
		return 2;

	// replay accordingly
	switch((replay_toolset->current_replay_preset.preset_cmd_type)[replay_toolset->current_replay_pointer])
	{
		case 0:
		{
			u32 val_read = device_io_read(dev_io_base_addr + (replay_toolset->current_replay_preset.preset_addr)[replay_toolset->current_replay_pointer], (replay_toolset->current_replay_preset.preset_cmd_size)[replay_toolset->current_replay_pointer]);

			if (val_read == (replay_toolset->current_replay_preset.preset_data)[replay_toolset->current_replay_pointer])
				++(replay_toolset->current_replay_pointer);
			else	// debug purpose only
				return val_read;
			break;
		}
		case 1:
			device_io_write(dev_io_base_addr + (replay_toolset->current_replay_preset.preset_addr)[replay_toolset->current_replay_pointer], (replay_toolset->current_replay_preset.preset_data)[replay_toolset->current_replay_pointer], (replay_toolset->current_replay_preset.preset_cmd_size)[replay_toolset->current_replay_pointer]);
			++(replay_toolset->current_replay_pointer);
			break;
		case 2:
			if (irq_trigger_counter && (*irq_trigger_counter))
				++(replay_toolset->current_replay_pointer);
			break;
		default:
		{
			printf("Incompatible command to be replayed at location: %d: type: %d, addr: 0x%08x, data: 0x%08x.\n",
					replay_toolset->current_replay_pointer, (replay_toolset->current_replay_preset.preset_cmd_type)[replay_toolset->current_replay_pointer], (replay_toolset->current_replay_preset.preset_addr)[replay_toolset->current_replay_pointer],
					(replay_toolset->current_replay_preset.preset_data)[replay_toolset->current_replay_pointer]);
			return 1;
		}

	}

	// Enable irq if needed (make sure we only enable it once)
	if (((replay_toolset->current_replay_preset.preset_cmd_type)[replay_toolset->current_replay_pointer] == 2) && ((initial_counter != replay_toolset->current_replay_pointer) || (replay_toolset->current_replay_pointer == 0)))
	{
		*irq_trigger_counter = 0;
		XIntc_Enable(&InterruptController, irq_marker);
	}

	return 0;
}

void update_irq_gpio()
{
	XGpio_DiscreteWrite(&irq_gpio, 1, current_irq_value);
}

void update_reset_gpio()
{
	XGpio_DiscreteWrite(&reset_gpio, 1, current_reset_value);
}

void reset_imx274()
{
	current_reset_value |= (0 << IMX274_GPIO_RESET_BIT_MASK);
	update_reset_gpio();
	usleep(IMX274_RESET_DELAY2);
	current_reset_value |= (1 << IMX274_GPIO_RESET_BIT_MASK);
//	printf("For getting imx274 out of reset, current_reset_value will be 0x%08x.\n", current_reset_value);
	update_reset_gpio();
	usleep(IMX274_RESET_DELAY2);
}

void reset_common(const u8 bitmask, u8 rst_val)
{
	current_reset_value |= (rst_val << bitmask);
	update_reset_gpio();
	usleep(3000);	// let's give it sometime to recover
	current_reset_value |= ((!rst_val) << bitmask);
	update_reset_gpio();
//	usleep(3000);	// let's give it sometime to recover
}

void reset_xdmsc()
{
	reset_common(XDMSC_GPIO_RESET_BIT_MASK, 1);
}

void reset_xg()
{
	reset_common(XG_GPIO_RESET_BIT_MASK, 1);
}

void reset_xcsc()
{
	reset_common(XCSC_GPIO_RESET_BIT_MASK, 1);
}

void reset_xscaler()
{
	reset_common(XSCALER_GPIO_RESET_BIT_MASK, 1);
}

void reset_fbwriter()
{
	reset_common(FBWRITER_GPIO_RESET_BIT_MASK, 1);
}

void reset_all()
{
	reset_imx274();
	reset_xdmsc();
	reset_xg();
	reset_xcsc();
	reset_xscaler();
	reset_fbwriter();
}

void perform_capture_reset()
{
	reset_fbwriter();
	reset_xscaler();
	reset_xcsc();
	reset_xg();
	reset_xdmsc();
	printf("%s: capture reset is performed.\n", __func__);
}

void check_and_reset()
{
	// for non-tcs mode after each capture session
	u32 potential_command = lwea(IO_ADDR_HIGH_MB_4_XSCALER_BASE + IO_ADDR_HIGH_NON_TCS_COMMAND_OFFSET);
	if (potential_command == IO_ADDR_HIGH_NON_TCS_RESET)
	{
		perform_capture_reset();
		swea(IO_ADDR_HIGH_MB_4_XSCALER_BASE + IO_ADDR_HIGH_NON_TCS_COMMAND_OFFSET, potential_command + 1);
	}
}

void clear_irq(const u64 base_os_addr)
{
	u32 temp_data;

	temp_data = lwea(base_os_addr + 20);

	// clear irqs?
	if (temp_data == IRQ_CLEAR_MARK)
	{
		switch(base_os_addr)
		{
			case IO_ADDR_HIGH_MB_4_IMX274_BASE:
				swea(base_os_addr + 20, temp_data + 1);
				current_irq_value &= ~(1 << IMX274_GPIO_IRQ_BIT_MASK);
				update_irq_gpio();
//				printf("Clearing an IRQ for IMX274 with new irq_gpio value: 0x%08x.\n", current_irq_value);
				XIntc_Enable(&InterruptController, XPAR_INTC_0_IIC_0_VEC_ID);
				break;
			case IO_ADDR_HIGH_MB_4_FBWRITER_BASE:
				swea(base_os_addr + 20, temp_data + 1);
				current_irq_value &= ~(1 << FBWRITER_GPIO_IRQ_BIT_MASK);
				update_irq_gpio();
//				printf("Clearing an IRQ for FBWRITER with new irq_gpio value: 0x%08x.\n", current_irq_value);
				XIntc_Enable(&InterruptController, XPAR_INTC_0_V_FRMBUF_WR_0_VEC_ID);
				break;

		}
	}
}

void irq_handler_imx274(void *CallbackRef){

	u32 pend, isr, ier;
	isr = lwea(MMIO_IMX274_BASE + XIIC_IISR_OFFSET);
	ier = lwea(MMIO_IMX274_BASE + XIIC_IIER_OFFSET);
	pend = isr & ier;

//	printf("Got a new irq for imx274 with is_in_tcs_mode: %d, pend: %d.\n", is_in_tcs_mode, pend);

	// For debugging only; is already inited, we treat it as in non-TCS mode
//	if (imx274_current_status)
//	{
//		printf("Got a new irq for imx274 with is_in_tcs_mode: %d, pend: %d.\n", is_in_tcs_mode, pend);
//
//		// Let's not forward 0
//		if (!pend)
//			return;
//
//		current_irq_value |= 1 << IMX274_GPIO_IRQ_BIT_MASK;
//		update_irq_gpio();
//		XIntc_Disable(&InterruptController, XPAR_INTC_0_IIC_0_VEC_ID);
//		return;
//	}

	if (is_in_tcs_mode)
	{
		// for replay
		++is_i2c_irq_triggerred;
		XIntc_Disable(&InterruptController, XPAR_INTC_0_IIC_0_VEC_ID);
	}
	else
	{
		current_irq_value |= 1 << IMX274_GPIO_IRQ_BIT_MASK;
		update_irq_gpio();
		XIntc_Disable(&InterruptController, XPAR_INTC_0_IIC_0_VEC_ID);
	}
//	current_irq_value |= 1 << IMX274_GPIO_IRQ_BIT_MASK;
//	update_irq_gpio();
//	XIntc_Disable(&InterruptController, XPAR_INTC_0_IIC_0_VEC_ID);

	// Only record new irq
//	u32 dummy_data = 0xFFFF;
//	if (pend && can_record_irq && (lwea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset - (DEBUG_RECORD_BLOCK_SIZE * 3)) != 2))
//	{
//		swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, 2);
//		current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
//		swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, dummy_data);
//		current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
//		swea(DEBUG_RECORD_BASE_ADDR + current_record_addr_offset, dummy_data);
//		current_record_addr_offset += DEBUG_RECORD_BLOCK_SIZE;
//		swea(DEBUG_RECORD_BASE_ADDR, ++total_num_of_commands);
//		can_record_irq = 0;
//	}
}

#define BIT(nr) (1UL << (nr))
#define XCSI_ISR_OFFSET			0x00000024
#define XCSI_ISR_ALLINTR_MASK		0xC03FFFFF
#define XCSI_ISR_STOP_SHIFT		17
#define XCSI_ISR_STOP_MASK		BIT(XCSI_ISR_STOP_SHIFT)
#define XCSI_INTR_MASK		(XCSI_ISR_ALLINTR_MASK & ~XCSI_ISR_STOP_MASK)
void irq_handler_rxss(void *CallbackRef){
	u32 status;
	status = lwea(MMIO_CSI_2_RXSS_BASE + XCSI_ISR_OFFSET);
	swea(MMIO_CSI_2_RXSS_BASE + XCSI_ISR_OFFSET, status & XCSI_INTR_MASK);
}

#define XILINX_FRMBUF_CTRL_AP_START			BIT(0)
#define XILINX_FRMBUF_FBW_MODE_PRESET_ON	128
#define XILINX_FRMBUF_ISR_AP_DONE_IRQ		BIT(0)
#define XILINX_FRMBUF_ISR_AP_READY_IRQ		BIT(1)
#define XILINX_FRMBUF_ISR_ALL_IRQ_MASK	\
		(XILINX_FRMBUF_ISR_AP_DONE_IRQ | \
		XILINX_FRMBUF_ISR_AP_READY_IRQ)
#define XILINX_FRMBUF_CTRL_OFFSET		0x00
#define XILINX_FRMBUF_GIE_OFFSET		0x04
#define XILINX_FRMBUF_IE_OFFSET			0x08
#define XILINX_FRMBUF_ISR_OFFSET		0x0c
#define XILINX_FRMBUF_WIDTH_OFFSET		0x10
#define XILINX_FRMBUF_HEIGHT_OFFSET		0x18
#define XILINX_FRMBUF_STRIDE_OFFSET		0x20
#define XILINX_FRMBUF_FMT_OFFSET		0x28
#define XILINX_FRMBUF_ADDR_OFFSET		0x30
#define XILINX_FRMBUF_ADDR2_OFFSET		0x3c
#define XILINX_FRMBUF_FID_OFFSET		0x48
#define XILINX_FRMBUF_LUMA_PLANE_ADDR	0xc400000
#define XILINX_FRMBUF_CHROMA_PLANE_ADDR_ADDR	0xc4e1000
#define XILINX_FRMBUF_VSIZE				720
#define XILINX_FRMBUF_HSIZE				1280
#define XILINX_FRMBUF_STRIDE			1280
#define XILINX_FRMBUF_FORMAT_ID			19
#define XILINX_FRMBUF_CHAN_MODE			128
static void xilinx_frmbuf_start_transfer()
{
	/* Start the transfer */
	swea(MMIO_FBWRITER_BASE + XILINX_FRMBUF_ADDR_OFFSET, XILINX_FRMBUF_LUMA_PLANE_ADDR);
	swea(MMIO_FBWRITER_BASE + XILINX_FRMBUF_ADDR2_OFFSET, XILINX_FRMBUF_CHROMA_PLANE_ADDR_ADDR);

	/* HW expects these parameters to be same for one transaction */
	swea(MMIO_FBWRITER_BASE + XILINX_FRMBUF_WIDTH_OFFSET, XILINX_FRMBUF_HSIZE);
	swea(MMIO_FBWRITER_BASE + XILINX_FRMBUF_STRIDE_OFFSET, XILINX_FRMBUF_STRIDE);
	swea(MMIO_FBWRITER_BASE + XILINX_FRMBUF_HEIGHT_OFFSET, XILINX_FRMBUF_VSIZE);
	swea(MMIO_FBWRITER_BASE + XILINX_FRMBUF_FMT_OFFSET, XILINX_FRMBUF_FORMAT_ID);

	/* Start the hardware */
	swea(MMIO_FBWRITER_BASE + XILINX_FRMBUF_CTRL_OFFSET, XILINX_FRMBUF_CTRL_AP_START | XILINX_FRMBUF_CHAN_MODE);
}
void irq_handler_fbwriter(void *CallbackRef){

	current_irq_value |= 1 << FBWRITER_GPIO_IRQ_BIT_MASK;
	update_irq_gpio();
	XIntc_Disable(&InterruptController, XPAR_INTC_0_V_FRMBUF_WR_0_VEC_ID);

	u32 status;
	status = lwea(MMIO_FBWRITER_BASE + XILINX_FRMBUF_ISR_OFFSET);
	swea(MMIO_FBWRITER_BASE + XILINX_FRMBUF_ISR_OFFSET, status & XILINX_FRMBUF_ISR_ALL_IRQ_MASK);

	if (status & XILINX_FRMBUF_ISR_ALL_IRQ_MASK) {
		xilinx_frmbuf_start_transfer();
	}
}
void irq_handler_timer(void *CallbackRef)
{
	++mb_sys_timer;
}

u64 get_time()
{
	return mb_sys_timer;
}

int already_printed_once = 0;
const u64 memory_to_check_for_printing_log = 0x800300000LL;
#define DEBUG_RECORD_BLOCK_SIZE 4
#define DEBUG_RECORD_BASE_ADDR 0x800400000LL
volatile u32 value_to_check;
void check_and_print_log()
{
	value_to_check = lwea(memory_to_check_for_printing_log);
	switch (value_to_check)
	{
		case 0xFFE:
		{
			if (!already_printed_once)
			{
				swea(DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR + RECODING_STATUS_OFFSET, 0xFFF);
				u32 total_num_of_commands_in_ps = lwea(DEBUG_RECORD_BASE_ADDR);
				printf("We currently have %d commands in MB, and %d commands in PS, pausing...\n", total_num_of_commands, total_num_of_commands_in_ps);
				already_printed_once = 1;
				is_recording_paused = 1;
			}
			break;
		}
		case 0xFFF:
		{
			if (!already_printed_once)
			{
				u32 total_num_of_commands_in_ps = lwea(DEBUG_RECORD_BASE_ADDR);
				printf("We currently have %d commands in MB, and %d commands in PS, cleaning...\n", total_num_of_commands, total_num_of_commands_in_ps);
				already_printed_once = 1;
				total_num_of_commands = 0;
				swea(DEBUG_RECORD_BASE_ADDR, 0);
				current_record_addr_offset = DEBUG_RECORD_BLOCK_SIZE;
			}
			break;
		}
		default:
			if (already_printed_once)
			{
				swea(DEBUG_LOG_CURRENT_DEBUGGING_IO_ADDR + RECODING_STATUS_OFFSET, 0);
				already_printed_once = 0;
				is_recording_paused = 0;
			}
	}
}

int check_and_switch_current_replay_preset(
	u32 *current_replay_counter,
	Replay_preset *current_preset,
	const u32 next_replay_preset_counter_total,
	u8 *next_replay_preset_cmd_type, u8 *next_replay_preset_size,
	u32 *next_replay_preset_addr, u32 *next_replay_preset_data
)
{
	// return 1 if switch, 0 if not

	// do nothing if null
	if ((!next_replay_preset_cmd_type) ||
		(!next_replay_preset_size) ||
		(!next_replay_preset_addr) ||
		(!next_replay_preset_data) ||
		(!next_replay_preset_counter_total))
		return 0;

	// if any of the existing preset is null, just assign
	if ((!(current_preset->preset_cmd_type)) ||
		(!(current_preset->preset_cmd_size)) ||
		(!(current_preset->preset_addr)) ||
		(!(current_preset->preset_data)))
	{
		current_preset->preset_cmd_type = next_replay_preset_cmd_type;
		current_preset->preset_cmd_size = next_replay_preset_size;
		current_preset->preset_addr = next_replay_preset_addr;
		current_preset->preset_data = next_replay_preset_data;
		current_preset->preset_counter_total = next_replay_preset_counter_total;
		return 1;
	}

	if (*current_replay_counter == current_preset->preset_counter_total)
	{
		current_preset->preset_cmd_type = next_replay_preset_cmd_type;
		current_preset->preset_cmd_size = next_replay_preset_size;
		current_preset->preset_addr = next_replay_preset_addr;
		current_preset->preset_data = next_replay_preset_data;
		current_preset->preset_counter_total = next_replay_preset_counter_total;
		*current_replay_counter = 0;
		return 1;
	}

	return 0;
}

void sync_replay_status(const u8 new_status)
{
	// We use IMX274 for master control, therefore we need to sync

	imx274_current_status = new_status;
	csi2rxss_current_status = new_status;
	xdmsc_current_status = new_status;
	xg_current_status = new_status;
	xcsc_current_status = new_status;
	xscaler_current_status = new_status;
	fbwriter_current_status = new_status;
}

u8 get_current_replay_status(void)
{
	// let's make sure all hardware is in sync
	u8 result_to_return = 255;
	if (imx274_current_status < result_to_return)
		result_to_return = imx274_current_status;
	if (csi2rxss_current_status < result_to_return)
		result_to_return = csi2rxss_current_status;
	if (xdmsc_current_status < result_to_return)
		result_to_return = xdmsc_current_status;
	if (xg_current_status < result_to_return)
		result_to_return = xg_current_status;
	if (xcsc_current_status < result_to_return)
		result_to_return = xcsc_current_status;
	if (xscaler_current_status < result_to_return)
		result_to_return = xscaler_current_status;
	if (fbwriter_current_status < result_to_return)
		result_to_return = fbwriter_current_status;

	return result_to_return;
}

void check_and_confirm_4_replay_with_normal_world(void)
{
	// check if we do confirmation
	if ((get_current_replay_status() == REPLAY_STATUS_WAIT_4_STOP) && (replay_confirmation_counter == 0))
	{
		confirm_completion_of_tcs_command(IO_ADDR_HIGH_MB_4_IMX274_BASE + IO_ADDR_HIGH_TCS_COMMAND_OFFSET, IO_ADDR_HIGH_TCS_COMMAND_START);
		++replay_confirmation_counter;
//		printf("confirming with normal world for starting...\n");
	}
	else if ((get_current_replay_status() == REPLAY_STATUS_FINISHED) && (replay_confirmation_counter == 1))
	{
		confirm_completion_of_tcs_command(IO_ADDR_HIGH_MB_4_IMX274_BASE + IO_ADDR_HIGH_TCS_COMMAND_OFFSET, IO_ADDR_HIGH_TCS_COMMAND_STOP);
		++replay_confirmation_counter;
//		printf("confirming with normal world for ending...\n");
	}
}

int replay_next_command_if_possible(
		Replay_toolset *current_replay_toolset, const u64 hw_mmio_base, const u32 irq_id, u8 *irq_trigger_counter
)
{
	// return 0 if success, 1 for completion of a preset, -1 for error

	// check if there is anything to replay (if no, treat it as completed)
	if ((!current_replay_toolset) ||
			(current_replay_toolset->current_replay_preset.preset_counter_total == 0) ||
			(!(current_replay_toolset->current_replay_preset.preset_cmd_type)))
	{
//		printf("%s: nothing to replay, check 1: %d, check 2: %d, check 3: %d.\n", __func__, (!current_replay_toolset), (current_replay_toolset->current_replay_preset.preset_counter_total == 0), (!(current_replay_toolset->current_replay_preset.preset_cmd_type)));
		return 1;
	}

	// Replay the next command
	current_replay_toolset->previous_replay_pointer = current_replay_toolset->current_replay_pointer;
	u32 debug_replay_result = replay_task(current_replay_toolset, hw_mmio_base, irq_id, irq_trigger_counter);
	if (debug_replay_result == 1)
	{
		printf("%s: replay error at counter: %d.\n", __func__, current_replay_toolset->current_replay_pointer);
		return -1;
	}
	else if (debug_replay_result == 2)
		return 1;

	// debug info
	if ((current_replay_toolset->previous_replay_pointer == current_replay_toolset->current_replay_pointer) &&
			(current_replay_toolset->last_stalling_pointer != current_replay_toolset->current_replay_pointer))
	{
		printf("%s: stall on hardware_base: 0x%016llx at %dth: type: %d, size: %d, addr: 0x%08x, data: 0x%08x (actural: 0x%08x).\n",
				__func__, hw_mmio_base, current_replay_toolset->current_replay_pointer,
				(current_replay_toolset->current_replay_preset.preset_cmd_type)[current_replay_toolset->previous_replay_pointer],
				(current_replay_toolset->current_replay_preset.preset_cmd_size)[current_replay_toolset->previous_replay_pointer],
				(current_replay_toolset->current_replay_preset.preset_addr)[current_replay_toolset->previous_replay_pointer],
				(current_replay_toolset->current_replay_preset.preset_data)[current_replay_toolset->previous_replay_pointer],
				debug_replay_result);
		current_replay_toolset->last_stalling_pointer = current_replay_toolset->current_replay_pointer;

		if ((hw_mmio_base == MMIO_IMX274_BASE) && ((current_replay_toolset->current_replay_preset.preset_addr)[current_replay_toolset->previous_replay_pointer] == 0x20))
		{
			printf("%s: skipping on potential stall...\n", __func__);

			++(current_replay_toolset->current_replay_pointer);

			// Enable irq if needed (make sure we only enable it once)
			if ((current_replay_toolset->current_replay_preset.preset_cmd_type)[current_replay_toolset->current_replay_pointer] == 2)
			{
				*irq_trigger_counter = 0;
				XIntc_Enable(&InterruptController, irq_id);
			}
		}
	}
//	if (current_replay_toolset->previous_replay_pointer != current_replay_toolset->current_replay_pointer)
//		printf("%s: successfully replay on hardware_base: 0x%016llx at %dth: type: %d, size: %d, addr: 0x%08x, data: 0x%08x.\n",
//				__func__, hw_mmio_base, current_replay_toolset->current_replay_pointer,
//				(current_replay_toolset->current_replay_preset.preset_cmd_type)[current_replay_toolset->previous_replay_pointer],
//				(current_replay_toolset->current_replay_preset.preset_cmd_size)[current_replay_toolset->previous_replay_pointer],
//				(current_replay_toolset->current_replay_preset.preset_addr)[current_replay_toolset->previous_replay_pointer],
//				(current_replay_toolset->current_replay_preset.preset_data)[current_replay_toolset->previous_replay_pointer]);

	return 0;
}

int replay_next_command_if_possible_4_fbwriter()
{
	// return 0 for success(maybe nothing happen), 1 for error

	// intialize it if needed
	if (!fbwriter_replay_toolset)
	{
		fbwriter_replay_toolset = alloc_new_replay_toolset(fbwriter_init_preset_num_of_commands,
				fbwriter_init_preset_cmd_type, fbwriter_init_preset_size, fbwriter_init_preset_addr,
				fbwriter_init_preset_data);
	}

	// replay next command
	int replay_result = 0;
	if ((fbwriter_current_status == REPLAY_STATUS_INIT) || (fbwriter_current_status == REPLAY_STATUS_START) || (fbwriter_current_status == REPLAY_STATUS_STOP))
	{

//		if ((fbwriter_current_status == REPLAY_STATUS_STOP) && (imx274_current_status == REPLAY_STATUS_STOP))
//			return 0;

		replay_result = replay_next_command_if_possible(fbwriter_replay_toolset, MMIO_FBWRITER_BASE, 0, NULL);
		if (replay_result == -1)
		{
			printf("fbwriter replay error at status: %d, counter: %d.\n", fbwriter_current_status, fbwriter_replay_toolset->current_replay_pointer);
			return 1;
		}
		else if (replay_result == 1)
		{
			++fbwriter_current_status;
//			printf("fbwriter_current_status is now changed to %d.\n", fbwriter_current_status);

			// change to next replay preset
			if (fbwriter_current_status == REPLAY_STATUS_WAIT_4_START)
			{
				replace_replay_preset_in_replay_toolset(fbwriter_replay_toolset, fbwriter_start_preset_num_of_commands,
						fbwriter_start_preset_cmd_type, xscaler_start_preset_size, fbwriter_start_preset_addr,
						fbwriter_start_preset_data);
			}
			else if (fbwriter_current_status == REPLAY_STATUS_WAIT_4_STOP)
			{
				replace_replay_preset_in_replay_toolset(fbwriter_replay_toolset, fbwriter_stop_preset_num_of_commands,
						fbwriter_stop_preset_cmd_type, fbwriter_stop_preset_size, fbwriter_stop_preset_addr,
						fbwriter_stop_preset_data);
			}
		}
	}

	return replay_result;
}

int replay_next_command_if_possible_4_xscaler()
{
	// return 0 for success(maybe nothing happen), 1 for error

	// intialize it if needed
	if (!xscaler_replay_toolset)
	{
		xscaler_replay_toolset = alloc_new_replay_toolset(xscaler_init_preset_num_of_commands,
				xscaler_init_preset_cmd_type, xscaler_init_preset_size, xscaler_init_preset_addr,
				xscaler_init_preset_data);
	}

	// replay next command
	int replay_result = 0;
	if ((xscaler_current_status == REPLAY_STATUS_INIT) || (xscaler_current_status == REPLAY_STATUS_START) || (xscaler_current_status == REPLAY_STATUS_STOP))
	{
//		if ((xscaler_current_status == REPLAY_STATUS_INIT) && (imx274_current_status == REPLAY_STATUS_INIT))
//			return 0;

		if ((xscaler_current_status == REPLAY_STATUS_STOP) && (imx274_current_status == REPLAY_STATUS_STOP))
			return 0;

		replay_result = replay_next_command_if_possible(xscaler_replay_toolset, MMIO_XSCALER_BASE, 0, NULL);
		if (replay_result == -1)
		{
			printf("xscaler replay error at status: %d, counter: %d.\n", xscaler_current_status, xscaler_replay_toolset->current_replay_pointer);
			return 1;
		}
		else if (replay_result == 1)
		{
			++xscaler_current_status;
//			printf("xscaler_current_status is now changed to %d.\n", xscaler_current_status);

			// change to next replay preset
			if (xscaler_current_status == REPLAY_STATUS_WAIT_4_START)
			{
				replace_replay_preset_in_replay_toolset(xscaler_replay_toolset, xscaler_start_preset_num_of_commands,
						xscaler_start_preset_cmd_type, xscaler_start_preset_size, xscaler_start_preset_addr,
						xscaler_start_preset_data);
			}
			else if (xscaler_current_status == REPLAY_STATUS_WAIT_4_STOP)
			{
				replace_replay_preset_in_replay_toolset(xscaler_replay_toolset, xscaler_stop_preset_num_of_commands,
						xscaler_stop_preset_cmd_type, xscaler_stop_preset_size, xscaler_stop_preset_addr,
						xscaler_stop_preset_data);
			}
		}
	}

	return replay_result;
}

int replay_next_command_if_possible_4_xcsc()
{
	// return 0 for success(maybe nothing happen), 1 for error

	// intialize it if needed
	if (!xcsc_replay_toolset)
	{
		xcsc_replay_toolset = alloc_new_replay_toolset(xcsc_init_preset_num_of_commands,
				xcsc_init_preset_cmd_type, xcsc_init_preset_size, xcsc_init_preset_addr,
				xcsc_init_preset_data);
	}

	// replay next command
	int replay_result = 0;
	if ((xcsc_current_status == REPLAY_STATUS_INIT) || (xcsc_current_status == REPLAY_STATUS_START) || (xcsc_current_status == REPLAY_STATUS_STOP))
	{
//		if ((xcsc_current_status == REPLAY_STATUS_INIT) && (imx274_current_status == REPLAY_STATUS_INIT))
//			return 0;

		// trick: need to wait for imx274 to finish starting first (otherwise imx274 replay will fail!)
		if ((xcsc_current_status == REPLAY_STATUS_START) && (imx274_current_status == REPLAY_STATUS_START))
			return 0;

		if ((xcsc_current_status == REPLAY_STATUS_STOP) && (imx274_current_status == REPLAY_STATUS_STOP))
			return 0;

		replay_result = replay_next_command_if_possible(xcsc_replay_toolset, MMIO_XCSC_BASE, 0, NULL);
		if (replay_result == -1)
		{
			printf("xcsc replay error at status: %d, counter: %d.\n", xcsc_current_status, xcsc_replay_toolset->current_replay_pointer);
			return 1;
		}
		else if (replay_result == 1)
		{
			++xcsc_current_status;
//			printf("xcsc_current_status is now changed to %d.\n", xcsc_current_status);

			// change to next replay preset
			if (xcsc_current_status == REPLAY_STATUS_WAIT_4_START)
			{
				replace_replay_preset_in_replay_toolset(xcsc_replay_toolset, xcsc_start_preset_num_of_commands,
						xcsc_start_preset_cmd_type, xcsc_start_preset_size, xcsc_start_preset_addr,
						xcsc_start_preset_data);
			}
			else if (xcsc_current_status == REPLAY_STATUS_WAIT_4_STOP)
			{
				replace_replay_preset_in_replay_toolset(xcsc_replay_toolset, xcsc_stop_preset_num_of_commands,
						xcsc_stop_preset_cmd_type, xcsc_stop_preset_size, xcsc_stop_preset_addr,
						xcsc_stop_preset_data);
			}
		}
	}

	return replay_result;
}

int replay_next_command_if_possible_4_xg()
{
	// return 0 for success(maybe nothing happen), 1 for error

	// intialize it if needed
	if (!xg_replay_toolset)
	{
		xg_replay_toolset = alloc_new_replay_toolset(xg_init_preset_num_of_commands,
				xg_init_preset_cmd_type, xg_init_preset_size, xg_init_preset_addr,
				xg_init_preset_data);
	}

	// replay next command
	int replay_result = 0;
	if ((xg_current_status == REPLAY_STATUS_INIT) || (xg_current_status == REPLAY_STATUS_START) || (xg_current_status == REPLAY_STATUS_STOP))
	{

//		if ((xg_current_status == REPLAY_STATUS_INIT) && (imx274_current_status == REPLAY_STATUS_INIT))
//			return 0;

		if ((xg_current_status == REPLAY_STATUS_STOP) && (imx274_current_status == REPLAY_STATUS_STOP))
			return 0;

		replay_result = replay_next_command_if_possible(xg_replay_toolset, MMIO_XG_BASE, 0, NULL);
		if (replay_result == -1)
		{
			printf("xg replay error at status: %d, counter: %d.\n", xg_current_status, xg_replay_toolset->current_replay_pointer);
			return 1;
		}
		else if (replay_result == 1)
		{
			++xg_current_status;
//			printf("xg_current_status is now changed to %d.\n", xg_current_status);

			// change to next replay preset
			if (xg_current_status == REPLAY_STATUS_WAIT_4_START)
			{
				replace_replay_preset_in_replay_toolset(xg_replay_toolset, xg_start_preset_num_of_commands,
						xg_start_preset_cmd_type, xg_start_preset_size, xg_start_preset_addr,
						xg_start_preset_data);
			}
			else if (xg_current_status == REPLAY_STATUS_WAIT_4_STOP)
			{
				replace_replay_preset_in_replay_toolset(xg_replay_toolset, xg_stop_preset_num_of_commands,
						xg_stop_preset_cmd_type, xg_stop_preset_size, xg_stop_preset_addr,
						xg_stop_preset_data);
			}
//			else if (xdmsc_current_status == REPLAY_STATUS_FINISHED)
//			{
//				reset_xg();
//			}
		}
	}

	return replay_result;
}

int replay_next_command_if_possible_4_xdmsc()
{
	// return 0 for success(maybe nothing happen), 1 for error

	// intialize it if needed
	if (!xdmsc_replay_toolset)
	{
		xdmsc_replay_toolset = alloc_new_replay_toolset(xdmsc_init_preset_num_of_commands,
				xdmsc_init_preset_cmd_type, xdmsc_init_preset_size, xdmsc_init_preset_addr,
				xdmsc_init_preset_data);
	}

	// replay next command
	int replay_result = 0;
	if ((xdmsc_current_status == REPLAY_STATUS_INIT) || (xdmsc_current_status == REPLAY_STATUS_START) || (xdmsc_current_status == REPLAY_STATUS_STOP))
	{

//		if ((xdmsc_current_status == REPLAY_STATUS_INIT) && (imx274_current_status == REPLAY_STATUS_INIT))
//			return 0;

		if ((xdmsc_current_status == REPLAY_STATUS_STOP) && (imx274_current_status == REPLAY_STATUS_STOP))
			return 0;

		replay_result = replay_next_command_if_possible(xdmsc_replay_toolset, MMIO_XDMSC_BASE, 0, NULL);
		if (replay_result == -1)
		{
			printf("xdmsc replay error at status: %d, counter: %d.\n", xdmsc_current_status, xdmsc_replay_toolset->current_replay_pointer);
			return 1;
		}
		else if (replay_result == 1)
		{
			++xdmsc_current_status;
//			printf("xdmsc_current_status is now changed to %d.\n", xdmsc_current_status);

			// change to next replay preset
			if (xdmsc_current_status == REPLAY_STATUS_WAIT_4_START)
			{
				replace_replay_preset_in_replay_toolset(xdmsc_replay_toolset, xdmsc_start_preset_num_of_commands,
						xdmsc_start_preset_cmd_type, xdmsc_start_preset_size, xdmsc_start_preset_addr,
						xdmsc_start_preset_data);
			}
			else if (xdmsc_current_status == REPLAY_STATUS_WAIT_4_STOP)
			{
				replace_replay_preset_in_replay_toolset(xdmsc_replay_toolset, xdmsc_stop_preset_num_of_commands,
						xdmsc_stop_preset_cmd_type, xdmsc_stop_preset_size, xdmsc_stop_preset_addr,
						xdmsc_stop_preset_data);
			}
//			else if (xdmsc_current_status == REPLAY_STATUS_FINISHED)
//			{
//				reset_xdmsc();
//			}
		}
	}

	return replay_result;
}

int replay_next_command_if_possible_4_csi2rxss()
{
	// return 0 for success(maybe nothing happen), 1 for error

	// intialize it if needed
	if (!csi2rxss_replay_toolset)
	{
		csi2rxss_replay_toolset = alloc_new_replay_toolset(csi2rxss_init_preset_num_of_commands,
				csi2rxss_init_preset_cmd_type, csi2rxss_init_preset_size, csi2rxss_init_preset_addr,
				csi2rxss_init_preset_data);
	}

	// replay next command
	int replay_result = 0;
	if ((csi2rxss_current_status == REPLAY_STATUS_INIT) || (csi2rxss_current_status == REPLAY_STATUS_START) || (csi2rxss_current_status == REPLAY_STATUS_STOP))
	{

//		if ((csi2rxss_current_status == REPLAY_STATUS_INIT) && (imx274_current_status == REPLAY_STATUS_INIT))
//			return 0;

		if ((csi2rxss_current_status == REPLAY_STATUS_STOP) && (imx274_current_status == REPLAY_STATUS_STOP))
			return 0;

		replay_result = replay_next_command_if_possible(csi2rxss_replay_toolset, MMIO_CSI_2_RXSS_BASE, XPAR_INTC_0_MIPICSISS_0_VEC_ID, NULL);
		if (replay_result == -1)
		{
			printf("csi2rxss replay error at status: %d, counter: %d.\n", csi2rxss_current_status, csi2rxss_replay_toolset->current_replay_pointer);
			return 1;
		}
		else if (replay_result == 1)
		{
			++csi2rxss_current_status;
//			printf("csi2rxss_current_status is now changed to %d.\n", csi2rxss_current_status);

			// change to next replay preset
			if (csi2rxss_current_status == REPLAY_STATUS_WAIT_4_START)
			{
				replace_replay_preset_in_replay_toolset(csi2rxss_replay_toolset, csi2rxss_start_preset_num_of_commands,
						csi2rxss_start_preset_cmd_type, csi2rxss_start_preset_size, csi2rxss_start_preset_addr,
						csi2rxss_start_preset_data);
			}
			else if (csi2rxss_current_status == REPLAY_STATUS_WAIT_4_STOP)
			{
				replace_replay_preset_in_replay_toolset(csi2rxss_replay_toolset, csi2rxss_stop_preset_num_of_commands,
						csi2rxss_stop_preset_cmd_type, csi2rxss_stop_preset_size, csi2rxss_stop_preset_addr,
						csi2rxss_stop_preset_data);
			}
		}
	}

	return replay_result;
}

int replay_next_command_if_possible_4_imx274()
{
	// return 0 for success(maybe nothing happen), 1 for error, 2 for completion

	// intialize it if needed
	if (!imx274_replay_toolset)
	{
		imx274_replay_toolset = alloc_new_replay_toolset(imx274_init_preset_num_of_commands,
				imx274_init_preset_cmd_type, imx274_init_preset_size, imx274_init_preset_addr,
				imx274_init_preset_data);
	}

	// replay next command
	int replay_result = 0;
	if ((imx274_current_status == REPLAY_STATUS_INIT) || (imx274_current_status == REPLAY_STATUS_START) || (imx274_current_status == REPLAY_STATUS_STOP))
	{
		replay_result = replay_next_command_if_possible(imx274_replay_toolset, MMIO_IMX274_BASE, XPAR_INTC_0_IIC_0_VEC_ID, &is_i2c_irq_triggerred);
//		replay_result = 1;

		if (replay_result == -1)
		{
			printf("imx274 replay error at status: %d, counter: %d.\n", imx274_current_status, imx274_replay_toolset->current_replay_pointer);
			return 1;
		}
		else if (replay_result == 1)
		{
			++imx274_current_status;
//			printf("imx274_current_status is now changed to %d.\n", imx274_current_status);

			// if imx274 is done stopping, let's reset others
			if (imx274_current_status == REPLAY_STATUS_FINISHED)
			{
				perform_capture_reset();
			}
		}

	} else if ((imx274_current_status == REPLAY_STATUS_WAIT_4_START) || (imx274_current_status == REPLAY_STATUS_WAIT_4_STOP))
	{
		// need to make sure all other hardware is in sync
		if (get_current_replay_status() != imx274_current_status)
		{
			return 0;
		}

		// check for if we execute next preset
		u32 data_to_check = lwea(IO_ADDR_HIGH_MB_4_IMX274_BASE + IO_ADDR_HIGH_TCS_COMMAND_OFFSET);

		if (data_to_check == IO_ADDR_HIGH_TCS_COMMAND_START)
		{
			replace_replay_preset_in_replay_toolset(imx274_replay_toolset, imx274_start_preset_num_of_commands,
					imx274_start_preset_cmd_type, imx274_start_preset_size, imx274_start_preset_addr,
					imx274_start_preset_data);
			sync_replay_status(imx274_current_status + 1);
		}
		else if (data_to_check == IO_ADDR_HIGH_TCS_COMMAND_STOP)
		{
			replace_replay_preset_in_replay_toolset(imx274_replay_toolset, imx274_stop_preset_num_of_commands,
					imx274_stop_preset_cmd_type, imx274_stop_preset_size, imx274_stop_preset_addr,
					imx274_stop_preset_data);
			sync_replay_status(imx274_current_status + 1);

//			perform_capture_reset();
		}
	}

	return 0;
}

void free_all_replay_toolset_if_possible()
{
	if (imx274_replay_toolset)
		xil_free(imx274_replay_toolset);

	if (csi2rxss_replay_toolset)
		xil_free(csi2rxss_replay_toolset);

	if (xdmsc_replay_toolset)
		xil_free(xdmsc_replay_toolset);

	if (xg_replay_toolset)
		xil_free(xg_replay_toolset);

	if (xcsc_replay_toolset)
		xil_free(xcsc_replay_toolset);

	if (xscaler_replay_toolset)
		xil_free(xscaler_replay_toolset);

	if (fbwriter_replay_toolset)
		xil_free(fbwriter_replay_toolset);
}

int init_commands(const int current_mode)
{
	u32 dummy_check = 0xFFF;
	int check_result = 0;

	// i2c
	if (!is_in_tcs_mode)
	{
		clear_irq(IO_ADDR_HIGH_MB_4_IMX274_BASE);
		forward_read_command(IO_ADDR_HIGH_MB_4_IMX274_BASE, MMIO_IMX274_BASE);
		forward_write_command(IO_ADDR_HIGH_MB_4_IMX274_BASE, MMIO_IMX274_BASE);
	}
	else
	{
//		clear_irq(IO_ADDR_HIGH_MB_4_IMX274_BASE);
//		forward_read_command(IO_ADDR_HIGH_MB_4_IMX274_BASE, MMIO_IMX274_BASE);
//		forward_write_command(IO_ADDR_HIGH_MB_4_IMX274_BASE, MMIO_IMX274_BASE);
		replay_next_command_if_possible_4_imx274();
	}

	// csi2rx
	if (!is_in_tcs_mode)
	{
		forward_read_command(IO_ADDR_HIGH_MB_4_CSI_2_RXSS_BASE, MMIO_CSI_2_RXSS_BASE);
		forward_write_command(IO_ADDR_HIGH_MB_4_CSI_2_RXSS_BASE, MMIO_CSI_2_RXSS_BASE);
	}
	else
	{
		replay_next_command_if_possible_4_csi2rxss();
	}

	// xdmsc
	if (!is_in_tcs_mode)
	{
		forward_read_command(IO_ADDR_HIGH_MB_4_XDMSC_BASE, MMIO_XDMSC_BASE);
		forward_write_command(IO_ADDR_HIGH_MB_4_XDMSC_BASE, MMIO_XDMSC_BASE);
	}
	else
	{
		replay_next_command_if_possible_4_xdmsc();
	}

	// xg
	if (!is_in_tcs_mode)
	{
		forward_read_command(IO_ADDR_HIGH_MB_4_XG_BASE, MMIO_XG_BASE);
		forward_write_command(IO_ADDR_HIGH_MB_4_XG_BASE, MMIO_XG_BASE);
	}
	else
	{
		replay_next_command_if_possible_4_xg();
	}

	// xcsc
	if (!is_in_tcs_mode)
	{
		forward_read_command(IO_ADDR_HIGH_MB_4_XCSC_BASE, MMIO_XCSC_BASE);
		forward_write_command(IO_ADDR_HIGH_MB_4_XCSC_BASE, MMIO_XCSC_BASE);
	}
	else
	{
		replay_next_command_if_possible_4_xcsc();
	}

	// xscaler
	if (!is_in_tcs_mode)
	{
		forward_read_command(IO_ADDR_HIGH_MB_4_XSCALER_BASE, MMIO_XSCALER_BASE);
		forward_write_command(IO_ADDR_HIGH_MB_4_XSCALER_BASE, MMIO_XSCALER_BASE);
	}
	else
	{
		replay_next_command_if_possible_4_xscaler();
	}

	// fbwriter
	clear_irq(IO_ADDR_HIGH_MB_4_FBWRITER_BASE);
	if (!is_in_tcs_mode)
	{
		forward_read_command(IO_ADDR_HIGH_MB_4_FBWRITER_BASE, MMIO_FBWRITER_BASE);
		forward_write_command(IO_ADDR_HIGH_MB_4_FBWRITER_BASE, MMIO_FBWRITER_BASE);
	}
	else
	{
		replay_next_command_if_possible_4_fbwriter();
	}

	// confirmation with normal world in tcs mode
	if (is_in_tcs_mode)
		check_and_confirm_4_replay_with_normal_world();

	// log printing
	check_and_print_log();

	// check if we want to perform a capture reset in non-tcs mode
	if (!is_in_tcs_mode)
	{
		check_and_reset();
	}

	return 0;
}


int check_and_forward_commands(const int current_mode)
{
	u32 dummy_check = 0xFFF;
	int check_result = 0;

	// i2c
	forward_read_command(IO_ADDR_HIGH_MB_4_IMX274_BASE, MMIO_IMX274_BASE);
	check_result = check_and_forward_write_command(0, &dummy_check, &dummy_check, &dummy_check, &dummy_check, IO_ADDR_HIGH_MB_4_IMX274_BASE, MMIO_IMX274_BASE);

	// csi2rx
	forward_read_command(IO_ADDR_HIGH_MB_4_CSI_2_RXSS_BASE, MMIO_CSI_2_RXSS_BASE);
	check_result = check_and_forward_write_command(0, &dummy_check, &dummy_check, &dummy_check, &dummy_check, IO_ADDR_HIGH_MB_4_CSI_2_RXSS_BASE, MMIO_CSI_2_RXSS_BASE);

	// xdmsc
	forward_read_command(IO_ADDR_HIGH_MB_4_XDMSC_BASE, MMIO_XDMSC_BASE);
	check_result = check_and_forward_write_command(0, &dummy_check, &dummy_check, &dummy_check, &dummy_check, IO_ADDR_HIGH_MB_4_XDMSC_BASE, MMIO_XDMSC_BASE);

	// xg
	forward_read_command(IO_ADDR_HIGH_MB_4_XG_BASE, MMIO_XG_BASE);
	check_result = check_and_forward_write_command(0, &dummy_check, &dummy_check, &dummy_check, &dummy_check, IO_ADDR_HIGH_MB_4_XG_BASE, MMIO_XG_BASE);

	// xcsc
	forward_read_command(IO_ADDR_HIGH_MB_4_XCSC_BASE, MMIO_XCSC_BASE);
	check_result = check_and_forward_write_command(0, &dummy_check, &dummy_check, &dummy_check, &dummy_check, IO_ADDR_HIGH_MB_4_XCSC_BASE, MMIO_XCSC_BASE);

	// xscaler
	forward_read_command(IO_ADDR_HIGH_MB_4_XSCALER_BASE, MMIO_XSCALER_BASE);
	check_result = check_and_forward_write_command(0, &dummy_check, &dummy_check, &dummy_check, &dummy_check, IO_ADDR_HIGH_MB_4_XSCALER_BASE, MMIO_XSCALER_BASE);

	// fbwriter
	forward_read_command(IO_ADDR_HIGH_MB_4_FBWRITER_BASE, MMIO_FBWRITER_BASE);
	check_result = check_and_forward_write_command(0, &dummy_check, &dummy_check, &dummy_check, &dummy_check, IO_ADDR_HIGH_MB_4_FBWRITER_BASE, MMIO_FBWRITER_BASE);

	return 0;
}

void set_current_status(u32 new_status)
{
	swea(IO_ADDR_HIGH_MB_4_TRANSFER_BASE + MB_IO_OFFSET_STATUS, new_status);
}

u32 get_ps_current_status()
{
	return lwea(IO_ADDR_HIGH_MB_4_TRANSFER_BASE + MB_IO_OFFSET_PS_STATUS);
}

int main()
{
    init_platform();

	int status;
    int should_sign = 0;
    int current_state = 0;

    // Myles: alloc log
//    printf("Log allocating...\n");
//	i2c_addrs = (u32*) malloc(sizeof(u32) * DEBUG_LOG_PRINT_MAX);
//	i2c_vals = (u32*) malloc(sizeof(u32) * DEBUG_LOG_PRINT_MAX);
//	i2c_types = (u8*) malloc(sizeof(u8) * DEBUG_LOG_PRINT_MAX);
//	if (!i2c_addrs || !i2c_vals || !i2c_types)
//	{
//		printf("Allocation for logging failed...\n");
//		return 1;
//	}
//	else
//	{
//		memset(i2c_addrs, 0, sizeof(u32) * DEBUG_LOG_PRINT_MAX);
//		memset(i2c_vals, 0, sizeof(u32) * DEBUG_LOG_PRINT_MAX);
//		memset(i2c_types, 0, sizeof(8) * DEBUG_LOG_PRINT_MAX);
//	}

	// Register GPIO
	printf("Registering GPIO devices...\n");
	status = XGpio_Initialize(&reset_gpio, XPAR_AXI_GPIO_DEVICE_RESETS_DEVICE_ID);
	if (status != XST_SUCCESS)
	{
		printf("Unable to register reset gpio...\n");
		return XST_FAILURE;
	}
	XGpio_SetDataDirection(&reset_gpio, 1, 0x0);
	status = XGpio_Initialize(&irq_gpio, XPAR_AXI_GPIO_DEVICE_IRQ_DEVICE_ID);
	if (status != XST_SUCCESS)
	{
		printf("Unable to register irq gpio...\n");
		return XST_FAILURE;
	}
	XGpio_SetDataDirection(&irq_gpio, 1, 0x0);
	status = XGpio_Initialize(&r_hasher_violation_flag_gpio, XPAR_AXI_GPIO_R_HASHER_ISP_2_DEVICE_ID);
	if (status != XST_SUCCESS)
	{
		printf("Unable to register r_hasher_violation_flag gpio...\n");
		return XST_FAILURE;
	}
	//	printf("Registering r_hasher_violation_flag direction...\n");
////	XGpio_SetDataDirection(&r_hasher_violation_flag_gpio, 2, ~0x0);
	status = XGpio_Initialize(&e_hasher_ctrl_gpio, XPAR_AXI_GPIO_AXIXBAR_DEBUG_INPUT_DEVICE_ID);
	if (status != XST_SUCCESS)
	{
		printf("Unable to register e_hasher_ctrl gpio...\n");
		return XST_FAILURE;
	}
//	printf("Registering e_hasher_ctrl_gpio direction...\n");
//	XGpio_SetDataDirection(&e_hasher_ctrl_gpio, 1, 0x0);
	status = XGpio_Initialize(&e_hasher_violation_flag_gpio, XPAR_AXI_GPIO_R_HASHER_MEM_W_DEBUG_DEVICE_ID);
	if (status != XST_SUCCESS)
	{
		printf("Unable to register e_hasher_violation gpio...\n");
		return XST_FAILURE;
	}
	//	printf("Registering e_hasher_violation_flag_gpio direction...\n");
////	XGpio_SetDataDirection(&e_hasher_violation_flag_gpio, 2, ~0x0);
	status = XGpio_Initialize(&e_hasher_hash_gpio, XPAR_AXI_GPIO_AXIXBAR_DEBUG_DEVICE_ID);
	if (status != XST_SUCCESS)
	{
		printf("Unable to register e_hasher_hash gpio...\n");
		return XST_FAILURE;
	}
//	printf("Registering e_hasher_hash_gpio direction...\n");
//	XGpio_SetDataDirection(&e_hasher_hash_gpio, 1, ~0x0);

	// set up irq handler
	printf("Setting up irq handler...\n");
	status = XIntc_Initialize(&InterruptController, INTC_DEVICE_ID);
	if (status != XST_SUCCESS) {
		printf("Failed to init irq controller...\n");
		return XST_FAILURE;
	}
	status = XIntc_SelfTest(&InterruptController);
	if (status != XST_SUCCESS) {
		printf("Failed to self test irq controller...\n");
		return XST_FAILURE;
	}

	status = XIntc_Connect(&InterruptController, XPAR_INTC_0_IIC_0_VEC_ID,
					   (XInterruptHandler)irq_handler_imx274,
					   (void *)0);
	if (status != XST_SUCCESS) {
		printf("Failed to connect irq handler for imx274(i2c)...\n");
		return XST_FAILURE;
	}
	status = XIntc_Connect(&InterruptController, XPAR_INTC_0_MIPICSISS_0_VEC_ID,
					   (XInterruptHandler)irq_handler_rxss,
					   (void *)0);
	if (status != XST_SUCCESS) {
		printf("Failed to connect irq handler for csi rxss...\n");
		return XST_FAILURE;
	}
	status = XIntc_Connect(&InterruptController, XPAR_INTC_0_V_FRMBUF_WR_0_VEC_ID,
					   (XInterruptHandler)irq_handler_fbwriter,
					   (void *)0);
	if (status != XST_SUCCESS) {
		printf("Failed to connect irq handler for fb writer...\n");
		return XST_FAILURE;
	}
	status = XIntc_Connect(&InterruptController, XPAR_MICROBLAZE_0_AXI_INTC_MB_TIMER_INTERRUPT_INTR,
					   (XInterruptHandler)irq_handler_timer,
					   (void *)0);
	if (status != XST_SUCCESS) {
		printf("Failed to connect irq handler for mb_timer...\n");
		return XST_FAILURE;
	}

	status = XIntc_Start(&InterruptController, XIN_REAL_MODE);
//	status = XIntc_Start(&InterruptController, XIN_SIMULATION_MODE);
	if (status != XST_SUCCESS) {
		printf("Failed to start irq controller...\n");
		return XST_FAILURE;
	}

	if (!is_in_tcs_mode)
	{
		XIntc_Enable(&InterruptController, XPAR_INTC_0_IIC_0_VEC_ID);
	}
	XIntc_Enable(&InterruptController, XPAR_INTC_0_MIPICSISS_0_VEC_ID);
	XIntc_Enable(&InterruptController, XPAR_INTC_0_V_FRMBUF_WR_0_VEC_ID);
	XIntc_Enable(&InterruptController, XPAR_MICROBLAZE_0_AXI_INTC_MB_TIMER_INTERRUPT_INTR);

	Xil_ExceptionInit();
	Xil_ExceptionRegisterHandler(XIL_EXCEPTION_ID_INT,
					(Xil_ExceptionHandler)XIntc_InterruptHandler,
					&InterruptController);
	Xil_ExceptionEnable();

//	status = XIntc_SimulateIntr(&InterruptController, XPAR_INTC_0_MIPICSISS_0_VEC_ID);
//	if (status != XST_SUCCESS) {
//		return XST_FAILURE;
//	}
//	status = XIntc_SimulateIntr(&InterruptController, XPAR_INTC_0_V_FRMBUF_WR_0_VEC_ID);
//	if (status != XST_SUCCESS) {
//		return XST_FAILURE;
//	}

	// sleep for PS init
	sleep(25);

	// eval
	u64 start, end;
	int eval_status = 0;	// 0 not started; 1 started; 2 stopped
	start = get_time();

	// Do all resets
	printf("Doing all resets...\n");
	reset_all();

	// Start init loop
	printf("Starting init loop with is_in_tcs_mode: %d...\n", is_in_tcs_mode);
    while (current_state == 0)
    {
    	if (!is_tcs_driver_inited)
    	{
    		switch(get_ps_current_status())
			{
				case MB_TCS_MODE_MARK:
					is_in_tcs_mode = 1;
					set_current_status(1);
					is_tcs_driver_inited = 1;
					break;
				case MB_NON_TCS_MODE_MARK:
					is_in_tcs_mode = 0;
					set_current_status(1);
					is_tcs_driver_inited = 1;
					break;
			}

    		if (is_tcs_driver_inited)
    			printf("According to PS, is_in_tcs_mode is set to: %d.\n", is_in_tcs_mode);
    	}

    	switch(init_commands(is_in_tcs_mode))
    	{
    		case -1:
    			current_state = 2;
    			should_sign = 0;
    			printf("init_commands failed...\n");
    			break;
    		case 1:
    			current_state = 1;
    			break;
    	}

    	// for eval only
    	switch (eval_status)
    	{
			case 0:
				if (get_current_replay_status() == REPLAY_STATUS_WAIT_4_START)
				{
		    		end = get_time();
		    		printf("Init is done with time elapsed: %ld...\n", (end - start));
		    		++eval_status;
				}
				break;
			case 1:
				if (get_current_replay_status() == REPLAY_STATUS_START)
				{
					++eval_status;
					start = get_time();
				}
				break;
			case 2:
				if (get_current_replay_status() == REPLAY_STATUS_WAIT_4_STOP)
				{
		    		end = get_time();
		    		printf("Start is done with time elapsed: %ld...\n", (end - start));
		    		++eval_status;
				}
				break;
			case 3:
				if (get_current_replay_status() == REPLAY_STATUS_STOP)
				{
					++eval_status;
					start = get_time();
				}
				break;
			case 4:
				if (get_current_replay_status() == REPLAY_STATUS_FINISHED)
				{
		    		end = get_time();
		    		printf("Stop is done with time elapsed: %ld...\n", (end - start));
		    		++eval_status;
				}
				break;
    	}

    	if (get_current_replay_status() == REPLAY_STATUS_FINISHED)
    	{
    		should_sign = 1;
			current_state = 2;
    		break;
    	}
    }

    // for eval only
    start = get_time();

//    printf("Done capture, going to report...\n");
    set_current_status(2);

    // final signature report
    uint8_t final_sig[64] = {0};

	// Start main loop
//	printf("Starting main loop with is_in_tcs_mode: %d, current_state: %d, should_sign: %d...\n", is_in_tcs_mode, current_state, should_sign);
//    while (current_state == 1)
//    {
//    	switch(check_and_forward_commands(is_in_tcs_mode))
//    	{
//    		case -1:
//    			should_sign = 0;
//    			current_state = 2;
//    			printf("Unexpected address or command detected, exiting...\n");
//    			break;
//    		case 1:
//    			should_sign = 1;
//    			current_state = 2;
//    			printf("done recording, going to sign...\n");
//    			break;
//    	}
//    }

    // Free for replay
//    printf("Going to free replay toolsets...\n");
    free_all_replay_toolset_if_possible();

    // Final
//    printf("Starting final part with is_in_tcs_mode: %d, current_state: %d, should_sign: %d...\n", is_in_tcs_mode, current_state, should_sign);
    if ((is_in_tcs_mode == 1) && (current_state == 2) && (should_sign == 1))
    {
    	// check violations
//    	printf("Going to check for violation...\n");
//    	int violation_checker_flag = 0;
    	int violation_checker_flag = XGpio_DiscreteRead(&r_hasher_violation_flag_gpio, 2) + XGpio_DiscreteRead(&e_hasher_violation_flag_gpio, 2);
    	if (violation_checker_flag)
    	{
    		printf("Violation detected, aborting with %04x...\n", violation_checker_flag);
    	}
    	else
    	{
    		// collect hash
			uint8_t hash[32] = {0};
			printf("Got final hash: {");
			for (int i = 0; i < E_HASHER_NUM_OF_READ_NEEDED_4_HASH; ++i)
			{
				*((u32*)(hash + i*4)) = XGpio_DiscreteRead(&e_hasher_hash_gpio, 1);
				XGpio_DiscreteWrite(&e_hasher_ctrl_gpio, 1, i+1);
				printf("%04x", *((u32*)(hash + i*4)));
			}
			printf("}\n");

			// Set signing status
			set_current_status(3);

			//    rsa_key_gen_test();
//			print("going to sign\n\r");
			if (sign_w_ecdsa(hash, final_sig))
				print("signing failed...\n\r");
//			print("signing done\n\r");
	//		rsa_signature_test();


			// Set done status
			set_current_status(4);
    	}
    } else
    {
    	printf("No signing is performed, done.\n");
    }

    // for eval only
    end = get_time();
    printf("Report generation time: %d.\n", (end - start));

    // print final signature
    printf("Got final signature: {");
	for (int i = 0; i < 16; ++i)
	{
		printf("%04x", *((u32*)(final_sig + i*4)));
	}
	printf("}\n");

    print("Successfully ran Hello World application\n\r");
    cleanup_platform();
    return 0;
}
