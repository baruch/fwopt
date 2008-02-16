#ifndef RULES_H
#define RULES_H

#include <stdint.h>

typedef struct RuleTree RuleTree;
typedef struct Rule Rule;

typedef enum RuleAction {
	RULE_NOT_SET = 0,
	RULE_ACCEPT,
	RULE_DROP,
	RULE_REJECT,
	RULE_JUMP,
} RuleAction;


RuleTree *rules_init(const void *ctx);
void rules_output(RuleTree *rule_tree);
void rules_optimize(RuleTree *rule_tree);

int rules_append_rule(RuleTree *tree, const char *chain, Rule *rule);

Rule *rule_init(void);
int rule_set_iface_in(Rule *rule, const char *iface);
int rule_set_iface_out(Rule *rule, const char *iface);
int rule_set_proto_num(Rule *rule, uint8_t proto);
int rule_set_proto_name(Rule *rule, const char *proto_name);
int rule_set_addr_src(Rule *rule, uint32_t src_addr, uint32_t src_mask);
int rule_set_addr_dst(Rule *rule, uint32_t dst_addr, uint32_t dst_mask);
int rule_set_port_src(Rule *rule, uint16_t src_port);
int rule_set_port_dst(Rule *rule, uint16_t dst_port);
int rule_set_icmp_type(Rule *rule, int negate, uint16_t type);
int rule_set_icmp_type_code(Rule *rule, int negate, uint16_t type, uint16_t code);
int rule_set_action_name(Rule *rule, const char *action);

#endif
