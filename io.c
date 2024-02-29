#include "io.h"

u32 device_io_read(const u64 addr, const u32 size)
{
	switch(size)
	{
		case 8:
			return lbuea(addr);
		case 16:
			return lhuea(addr);
		case 32:
			return lwea(addr);
		default:
			printf("%s: Error for reading size: %d at addr: 0x%08x.\n", __func__, size, addr);
	}

	return 0;
}

void device_io_write(const u64 addr, const u32 val, const u32 size)
{
	switch(size)
	{
		case 8:
			sbea(addr, (u8)val);
			break;
		case 16:
			shea(addr, (u16)val);
			break;
		case 32:
			swea(addr, val);
			break;
		default:
			printf("%s: Error for writing size: %d at addr: 0x%08x with data: 0x%08x.\n", __func__, size, addr, val);
	}
}

int check_tcs_command_existence(const u64 os_addr_to_check, const u32 value_to_check_against)
{
	// return 1 if matched, otherwise return 0

	u32 temp_data = 0;

	// get data
	temp_data = lwea(os_addr_to_check);

	// see if we get a match
	if (temp_data == value_to_check_against)
		return 1;
	else
		return 0;
}

void confirm_completion_of_tcs_command(const u64 os_addr_to_confirm, const u32 value_to_confirm)
{
	swea(os_addr_to_confirm, value_to_confirm + IO_ADDR_HIGH_TCS_COMMAND_RECIPT_OFFSET);
}

int check_and_confirm_tcs_command(const u64 os_addr_to_check, const u32 value_to_check_against, const u32 value_to_confirm)
{
	int check_result = check_tcs_command_existence(os_addr_to_check, value_to_check_against);

	// confirm if positive
	if (check_result)
	{
		confirm_completion_of_tcs_command(os_addr_to_check, value_to_confirm);
	}

	return check_result;
}
