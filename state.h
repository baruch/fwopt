#ifndef STATE_H
#define STATE_H

#include <stdint.h>

enum state_id {
	STATE_INVALID = 0x01,
	STATE_ESTABLISHED = 0x02,
	STATE_NEW = 0x04,
	STATE_RELATED = 0x08,
	STATE_UNTRACKED = 0x10,
};

uint32_t states_to_mask(char *states);
int mask_to_states(uint32_t mask, char *states);

#endif
