#include "rules.h"

typedef struct Option Option;

extern char lex_line[1024];
extern int lex_lineno;
extern int lex_idx;
extern int lex_line_len;
extern int lex_last_token_idx;
extern int lex_prev_token_idx;

struct ipmask {
	uint32_t addr;
	uint32_t mask;
};

struct icmptype {
	uint16_t type;
	uint16_t code;
	int code_match;
};

int translate_icmp_type(const char *name, struct icmptype *icmp);
