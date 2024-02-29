u32 csi2rxss_stop_preset_num_of_commands = 5;

u8 csi2rxss_stop_preset_cmd_type[] = {
		0, 1, 0, 1, 1
};

u8 csi2rxss_stop_preset_size[] = {
		32, 32, 32, 32, 32
};

u32 csi2rxss_stop_preset_addr[] = {
		0x00000028, 0x00000028, 0x00000020, 0x00000020, 0x00000000
};

u32 csi2rxss_stop_preset_data[] = {
		0xc03dffff, 0x00000000, 0x00000001, 0x00000000, 0x00000000
};
