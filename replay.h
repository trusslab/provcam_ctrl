#ifndef __REPLAY_H_
#define __REPLAY_H_

struct Replay_preset{
	u32 preset_counter_total;
	u8 *preset_cmd_type;
	u8 *preset_cmd_size;
	u32 *preset_addr;
	u32 *preset_data;
};
typedef struct Replay_preset Replay_preset;

struct Replay_toolset{
	Replay_preset current_replay_preset;
	u32 current_replay_pointer;	// Aka. counter
	u32 previous_replay_pointer;
	u32 last_stalling_pointer;	// for debug
};
typedef struct Replay_toolset Replay_toolset;

Replay_toolset *alloc_new_replay_toolset(
		const u32 first_preset_counter_total,
		u8 *first_preset_cmd_type,
		u8 *first_preset_cmd_size,
		u32 *first_preset_addr,
		u32 *first_preset_data)
{
	Replay_toolset *new_replay_toolset = (Replay_toolset*) xil_malloc(sizeof(Replay_toolset));
	new_replay_toolset->current_replay_preset.preset_counter_total = first_preset_counter_total;
	new_replay_toolset->current_replay_preset.preset_cmd_type = first_preset_cmd_type;
	new_replay_toolset->current_replay_preset.preset_cmd_size = first_preset_cmd_size;
	new_replay_toolset->current_replay_preset.preset_addr = first_preset_addr;
	new_replay_toolset->current_replay_preset.preset_data = first_preset_data;
	new_replay_toolset->current_replay_pointer = 0;
	new_replay_toolset->previous_replay_pointer = 0;
	new_replay_toolset->last_stalling_pointer = 999;

	return new_replay_toolset;
}

void *replace_replay_preset_in_replay_toolset(
		Replay_toolset *replay_toolset,
		const u32 next_preset_counter_total,
		u8 *next_preset_cmd_type,
		u8 *next_preset_cmd_size,
		u32 *next_preset_addr,
		u32 *next_preset_data)
{
	replay_toolset->current_replay_preset.preset_counter_total = next_preset_counter_total;
	replay_toolset->current_replay_preset.preset_cmd_type = next_preset_cmd_type;
	replay_toolset->current_replay_preset.preset_cmd_size = next_preset_cmd_size;
	replay_toolset->current_replay_preset.preset_addr = next_preset_addr;
	replay_toolset->current_replay_preset.preset_data = next_preset_data;
	replay_toolset->current_replay_pointer = 0;
	replay_toolset->previous_replay_pointer = 0;
	replay_toolset->last_stalling_pointer = 999;
}

#endif
