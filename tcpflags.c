#include "tcpflags.h"
#include "macros.h"
#include <string.h>

static const struct {
	char *name;
	uint32_t val;
} tcpflags[] = {
	{"FIN", 0x01},
	{"SYN", 0x02},
	{"RST", 0x04},
	{"PSH", 0x08},
	{"ACK", 0x10},
	{"URG", 0x20},
	{"ECE", 0x40},
	{"CWR", 0x80},
	{"ALL", 0xFF},
	{"NONE",0x00},
};

int translate_tcp_flag(const char *name, uint32_t *val)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tcpflags); i++) {
		if (strcmp(tcpflags[i].name, name) == 0) {
			*val = tcpflags[i].val;
			return 0;
		}
	}
	return -1;
}

const char *name_from_tcp_flag(uint32_t flag)
{
	int i;
	
	for (i = 0; i < ARRAY_SIZE(tcpflags); i++) {
		if (tcpflags[i].val == flag)
			return tcpflags[i].name;
	}
	return NULL;
}

void list_from_tcp_flags(uint32_t flag, char *str)
{
	if (flag == 0) {
		strcpy(str, "NONE");
	} else if (flag == 0xFF) {
		strcpy(str, "ALL");
	} else {
		int i, first;

		for (i = 0, first = 1; i < ARRAY_SIZE(tcpflags) && tcpflags[i].val != 0xFF; i++) {
			if (tcpflags[i].val & flag) {
				if (!first)
					*str++ = ',';
				strcpy(str, tcpflags[i].name);
				str += strlen(str);
				first = 0;
			}
		}
	}
}
