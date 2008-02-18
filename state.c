#include "state.h"
#include "macros.h"
#include <string.h>
#include <stdio.h>

static const struct {
	char *name;
	enum state_id val;
} state_names[] = {
	{"INVALID", STATE_INVALID},
	{"ESTABLISHED", STATE_ESTABLISHED},
	{"NEW", STATE_NEW},
	{"RELATED", STATE_RELATED},
	{"UNTRACKED", STATE_UNTRACKED},
};

static int state_find(const char *state, uint32_t *val)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(state_names); i++) {
		if (strcmp(state, state_names[i].name) == 0) {
			*val = state_names[i].val;
			return 0;
		}
	}

	return -1;
}

uint32_t states_to_mask(char *states)
{
	char *token;
	uint32_t mask = 0;
	for (token = strtok(states, ","); token; token = strtok(NULL, ",")) {
		uint32_t val = 0;
		int ret = state_find(token, &val);
		if (ret) {
			fprintf(stderr, "Unknown state '%s'\n", token);
			return 0;
		}

		mask |= val;
	}
	return mask;
}

int mask_to_states(uint32_t mask, char *states)
{
	int i, first = 1;

	for (i = 0; mask && i < ARRAY_SIZE(state_names); i++) {
		if (mask & state_names[i].val) {
			mask &= ~state_names[i].val;
			
			if (!first)
				*states++ = ',';
			strcpy(states, state_names[i].name);
			states += strlen(states);
			first = 0;
		}
	}

	if (mask) {
		fprintf(stderr, "An unknown value in mask, left=%x\n", mask);
		return -1;
	}

	return 0;
}
