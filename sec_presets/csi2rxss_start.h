u32 csi2rxss_start_preset_num_of_commands = 11;

u8 csi2rxss_start_preset_cmd_type[] = {
		1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1
};

u8 csi2rxss_start_preset_size[] = {
		32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32
};

u32 csi2rxss_start_preset_addr[] = {
		0x00000000, 0x00000000, 0x00000000, 0x00000010, 0x00000000, 0x00000000, 0x00000020, 0x00000020,
		0x00000028, 0x00000020, 0x00000020
};

u32 csi2rxss_start_preset_data[] = {
		0x00000001, 0x00000001, 0x00000003, 0x00000000, 0x00000003, 0x00000001, 0x00000000, 0x00000000,
		0xc03dffff, 0x00000000, 0x00000001
};
