#include "rules.h"
#include <talloc.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netdb.h>
#include <glib.h>
#include <arpa/inet.h>
#include <assert.h>
#include "tcpflags.h"
#include "state.h"

const char *name_from_icmp_type(uint16_t type, uint16_t code, int code_match);

#define IFACE_LEN 16
#define CHAIN_LEN 32

enum RuleCond {
	COND_IFACE_IN,
	COND_IFACE_OUT,
	COND_ADDR_SRC,
	COND_ADDR_DST,
	COND_PROTOCOL,
	COND_PORT_SRC,
	COND_PORT_DST,
	COND_ICMP_TYPE,
	COND_TCP_FLAGS,
	COND_TCP_OPTION,
	COND_MATCH_STATE,

	COND_NUM
};

enum RuleActionParam {
	ACTION_PARAM_LOG_LEVEL,
	ACTION_PARAM_LOG_PREFIX,

	ACTION_PARAM_NUM
};

struct Rule
{
	struct Rule *next;

	RuleAction action;
	char *jump_chain;

	void *cond[COND_NUM];
	void *actparam[ACTION_PARAM_NUM];
};


struct cond_operator_t {
	int (*intersect)(Rule *rule, int idx, void * cond_from);
	void (*output)(void *this, void *cond);
	void *(*dup)(void *ctx, void *cond);
	int (*cmp)(void *cond_a, void *cond_b);

	void *this;
};

struct actparam_operator_t {
	int (*intersect)(Rule *rule, int idx, void *actparam_from);
	void (*output)(RuleAction action, void *);
	void *(*dup)(void *ctx, void *cond);
};


static void rule_mid(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	printf(" ");
	vprintf(fmt, ap);
	va_end(ap);
}

static const char *negate_output(int negate)
{
	if (negate)
		return "! ";
	else
		return "";
}

#define SIMPLE_COND(name) \
	static cond_##name##_t *cond_##name##_alloc(void *ctx) \
	    { return talloc_zero(ctx, cond_##name##_t); }      \
	static void *cond_##name##_dup(void *ctx, void *cond)  \
	    { return talloc_memdup(ctx, cond, sizeof(cond_##name##_t)); }

typedef struct {
	char name[IFACE_LEN];
	int negate;
} cond_iface_t;

SIMPLE_COND(iface);

static void cond_iface_output(void *vthis, void *vcond)
{
	char *this = vthis;
	cond_iface_t *cond = vcond;
	rule_mid("%s %s%s", this, negate_output(cond->negate), cond->name);
}

static int cond_iface_cmp(void *va, void *vb)
{
	cond_iface_t *a = va;
	cond_iface_t *b = vb;

	if (!a)
		return 1;
	else if (!b)
		return -1;
	else if (a->negate != b->negate)
		return a->negate - b->negate;
	else
		return strncmp(a->name, b->name, IFACE_LEN);
}

static int cond_iface_intersect(Rule *rule, int idx, void *vcond_from)
{
	//struct cond_iface_t *from = vcond_from;

	assert(rule->cond[idx] != NULL);
	assert(vcond_from != NULL);

	assert(0); // It is not implemented yet!

	return -1;
}

typedef struct {
	uint8_t protocol;
	int negate;
} cond_proto_t;

SIMPLE_COND(proto);

static void cond_proto_output(void *vthis, void *vcond)
{
	cond_proto_t *cond = vcond;

	struct protoent *proto = getprotobynumber(cond->protocol);
	const char *neg = negate_output(cond->negate);
	if (!proto)
		rule_mid("-p %s%d", neg, cond->protocol);
	else
		rule_mid("-p %s%s", neg, proto->p_name);
}

static int cond_proto_intersect(Rule *rule, int idx, void *vcond_from)
{
	cond_proto_t *to = rule->cond[idx];
	cond_proto_t *from = vcond_from;
	if (to->protocol == from->protocol && to->negate == from->negate)
		return 0;
	else if (to->protocol != from->protocol && to->negate == from->negate)
		return -1;
	assert(0); // Not implemented yet
	return -1;
}

typedef struct {
	uint32_t addr;
	uint32_t mask;
	int neg;
} cond_addr_t;

SIMPLE_COND(addr);

static void cond_addr_output(void *vthis, void *vcond)
{
	cond_addr_t *cond = vcond;
	char *this = vthis;

	struct in_addr inaddr;
	char addr_str[4*4];

	inaddr.s_addr = htonl(cond->addr);
	strcpy(addr_str, inet_ntoa(inaddr));

	if (cond->mask != 0xFFFFFFFF) {
		inaddr.s_addr = htonl(cond->mask);
		rule_mid("%s %s%s/%s", this, negate_output(cond->neg), addr_str, inet_ntoa(inaddr));
	} else {
		rule_mid("%s %s%s", this, negate_output(cond->neg), addr_str);
	}
}

typedef struct {
	uint16_t port;
	int neg;
} cond_port_t;

SIMPLE_COND(port);

static void cond_port_output(void *vthis, void *vcond)
{
	cond_port_t *cond = vcond;
	const char *this = vthis;
	rule_mid("%s %s%u", this, negate_output(cond->neg), cond->port);
}

typedef struct {
	uint16_t type;
	uint16_t code;
	int neg : 1,
		code_match : 1;
} cond_icmptype_t;

SIMPLE_COND(icmptype);

static void cond_icmptype_output(void *vthis, void *vcond)
{
	cond_icmptype_t *cond = vcond;
	const char *name = name_from_icmp_type(cond->type, cond->code, cond->code_match);
	const char *neg = negate_output(cond->neg);
	if (name)
		rule_mid("--icmp-type %s%s", neg, name);
	else if (cond->code_match)
		rule_mid("--icmp-type %s%u/%u", neg, cond->type, cond->code);
	else
		rule_mid("--icmp-type %s%u", neg, cond->type);
}

typedef struct {
	uint8_t mask;
	uint8_t comp;
	int neg;
} cond_tcpflags_t;

SIMPLE_COND(tcpflags);

static void cond_tcpflags_output(void *vthis, void *vcond)
{
	cond_tcpflags_t *cond = vcond;
	if (cond->mask == 0x17 && cond->comp == 0x02) {
		rule_mid("%s--syn", negate_output(cond->neg));
	} else {
		char mask[80], comp[80];
		list_from_tcp_flags(cond->mask, mask);
		list_from_tcp_flags(cond->comp, comp);

		rule_mid("--tcp-flags %s%s %s", negate_output(cond->neg), mask, comp);
	}
}

static int cond_tcpflags_cmp(void *va, void *vb)
{
	cond_tcpflags_t *a = va;
	cond_tcpflags_t *b = vb;

	if (!a)
		return 1;
	else if (!b)
		return -1;
	else if (a->neg != b->neg)
		return a->neg - b->neg;
	else if (a->mask != b->mask)
		return a->mask - b->mask;
	else
		return a->comp - b->comp;
}


typedef struct {
	uint16_t option;
	uint16_t neg;
} cond_tcpopt_t;

SIMPLE_COND(tcpopt);

static void cond_tcpopt_output(void *vthis, void *vcond)
{
	cond_tcpopt_t *cond = vcond;
	rule_mid("--tcp-option %s%u", negate_output(cond->neg), cond->option);
}

typedef struct {
	uint32_t state;
	int neg;
} cond_state_t;

SIMPLE_COND(state);

static void cond_state_output(void *vthis, void *vcond)
{
	cond_state_t *cond = vcond;

	rule_mid("--match state");

	char states[120];
	int ret = mask_to_states(cond->state, states);
	if (!ret)
		rule_mid("%s--state %s", negate_output(cond->neg), states);
	else
		rule_mid("--state ERROR-UNKNOWN-MASK");
}

static int cond_state_cmp(void *va, void *vb)
{
	cond_state_t *a = va;
	cond_state_t *b = vb;

	if (!a)
		return 1;
	else if (!b)
		return -1;
	else if (a->neg != b->neg)
		return a->neg - b->neg;
	else
		return a->state - b->state;
}


#define COND_FUNC_FULL(name,this) cond_##name##_intersect, cond_##name##_output, cond_##name##_dup, cond_##name##_cmp, this

static const struct cond_operator_t cond_op[COND_NUM] = {
	[COND_IFACE_IN] = {COND_FUNC_FULL(iface, "-i")},
	[COND_IFACE_OUT] = {COND_FUNC_FULL(iface, "-o")},
	[COND_PROTOCOL] = {cond_proto_intersect, cond_proto_output, cond_proto_dup, NULL, NULL},
	[COND_ADDR_SRC] = {0, cond_addr_output, cond_addr_dup, NULL, "--src"},
	[COND_ADDR_DST] = {0, cond_addr_output, cond_addr_dup, NULL, "--dst"},
	[COND_PORT_SRC] = {0, cond_port_output, cond_port_dup, NULL, "--sport"},
	[COND_PORT_DST] = {0, cond_port_output, cond_port_dup, NULL, "--dport"},
	[COND_ICMP_TYPE] = {0, cond_icmptype_output, cond_icmptype_dup, NULL, NULL},
	[COND_TCP_FLAGS] = {0, cond_tcpflags_output, cond_tcpflags_dup, cond_tcpflags_cmp, NULL},
	[COND_TCP_OPTION] = {0, cond_tcpopt_output, cond_tcpopt_dup, NULL, NULL},
	[COND_MATCH_STATE] = {0, cond_state_output, cond_state_dup, cond_state_cmp, NULL},
};


static void actparam_loglevel_output(RuleAction action, void *vparam)
{
	const char *param = vparam;
	rule_mid("--log-level %s", param);
}

static void *actparam_strdup(void *ctx, void *param)
{
	return talloc_strdup(ctx, param);
}

static void actparam_logpref_output(RuleAction action, void *vparam)
{
	rule_mid("--log-prefix %s", (char*)vparam);
}

static const struct actparam_operator_t actparam_op[ACTION_PARAM_NUM] = {
	[ACTION_PARAM_LOG_LEVEL] = {NULL, actparam_loglevel_output, actparam_strdup},
	[ACTION_PARAM_LOG_PREFIX] = {NULL, actparam_logpref_output, actparam_strdup},
};

typedef struct Chain
{
	char *name;
	Rule *rules;
	Rule **tail;
} Chain;

struct RuleTree
{
	Chain *input;
	Chain *output;
	Chain *forward;

	int num_chains;
	Chain *chains[NUM_CHAINS];
};

static Chain *rules_new_chain_int(RuleTree *tree, const char *name)
{
	if (tree->num_chains >= NUM_CHAINS)
		return NULL;

	Chain *chain = talloc_zero(tree, Chain);
	chain->name = talloc_strdup(chain, name);
	chain->tail = &chain->rules;

	tree->chains[tree->num_chains++] = chain;

	return chain;
}

int rules_new_chain(RuleTree *tree, const char *name)
{
	return rules_new_chain_int(tree, name) != NULL ? 0 : -1;
}

static void rules_init_chains(RuleTree *rule_tree)
{
	rule_tree->input = rules_new_chain_int(rule_tree, "INPUT");
	rule_tree->output = rules_new_chain_int(rule_tree, "OUTPUT");
	rule_tree->forward = rules_new_chain_int(rule_tree, "FORWARD");
}

RuleTree *rules_init(const void *ctx)
{
	RuleTree *rule_tree = talloc_zero(ctx, struct RuleTree);
	rules_init_chains(rule_tree);
	return rule_tree;
}

static void rules_clear(RuleTree *tree)
{
	int i;

	for (i = 0; i < tree->num_chains; i++) {
		talloc_free(tree->chains[i]);
		tree->chains[i] = NULL;
	}
	tree->num_chains = 0;
	tree->input = NULL;
	tree->output = NULL;
	tree->forward = NULL;

	rules_init_chains(tree);
}

static int rules_get_chain_idx(RuleTree *tree, const char *name)
{
	int i;
	for (i=0; i < tree->num_chains; i++) {
		if (strcmp(name, tree->chains[i]->name) == 0)
			return i;
	}

	return -1;
}

static Chain *rules_get_chain(RuleTree *tree, const char *name)
{
	int idx = rules_get_chain_idx(tree, name);
	if (idx == -1)
		return NULL;
	else
		return tree->chains[idx];
}

static int rules_delete_chain_idx(RuleTree *tree, int idx)
{
	if (tree->chains[idx]->rules) {
		fprintf(stderr, "Cannot delete a non-empty chain '%s'\n", tree->chains[idx]->name);
		return -1;
	}

	if (idx <= 2) {
		fprintf(stderr, "Cannot delete INPUT, OUTPUT or FORWARD chains\n");
		return -1;
	}

	talloc_free(tree->chains[idx]);

	/* Move the chains down the list to avoid holes */
	for (; idx < tree->num_chains; idx++)
		tree->chains[idx] = tree->chains[idx+1];
	tree->num_chains--;

	return 0;
}

int rules_delete_chain(RuleTree *tree, const char *name)
{
	int idx = rules_get_chain_idx(tree, name);
	if (idx == -1) {
		fprintf(stderr, "Cannot delete a non-existent chain '%s'\n", name);
		return -1;
	}

	return rules_delete_chain_idx(tree, idx);
}

int rules_delete_chains(RuleTree *tree)
{
	while (tree->num_chains > 3) {
		int res = rules_delete_chain_idx(tree, tree->num_chains-1);
		if (res) {
			fprintf(stderr, "Failed deleting all chains\n");
			return -1;
		}
	}
	return 0;
}

static int rules_flush_chain_idx(RuleTree *tree, int idx)
{
	Chain *chain = tree->chains[idx];
	if (!chain) {
		fprintf(stderr, "No chain to flush at index %d\n", idx);
		return -1;
	}

	chain->tail = &chain->rules;

	while (chain->rules) {
		Rule *tmp = chain->rules;
		chain->rules = tmp->next;

		talloc_free(tmp);
	}

	return 0;
}

int rules_flush_all(RuleTree *tree)
{
	int i;
	for (i = 0; i < tree->num_chains; i++) {
		int ret = rules_flush_chain_idx(tree, i);
		if (ret)
			return ret;
	}
	return 0;
}

int rules_flush_chain(RuleTree *tree, const char *chain)
{
	int idx = rules_get_chain_idx(tree, chain);
	return rules_flush_chain_idx(tree, idx);
}

static void chain_add_rule(Chain *chain, Rule *rule)
{
	/* Add to the end of the chain linked list */
	*chain->tail = rule;
	chain->tail = &rule->next;

	(void)talloc_reference(chain, rule);
}

int rules_append_rule(RuleTree *tree, const char *chain_name, Rule *rule)
{
	Chain *chain = rules_get_chain(tree, chain_name);
	if (!chain) {
		fprintf(stderr, "Can't find chain '%s'\n", chain_name);
		return -1;
	}

	chain_add_rule(chain, rule);
	return 0;
}

Rule *rule_init(void)
{
	Rule *rule = talloc_zero(NULL, Rule);
	return rule;
}

static Rule *rule_dup(void *ctx, Rule *rule)
{
	Rule *newrule = talloc_zero(ctx, Rule);

	newrule->action = rule->action;
	if (newrule->action == RULE_JUMP)
		newrule->jump_chain = talloc_strdup(newrule, rule->jump_chain);

	int i;
	for (i = 0; i < COND_NUM; i++) {
		if (rule->cond[i])
			newrule->cond[i] = cond_op[i].dup(newrule, rule->cond[i]);
	}

	for (i = 0; i < ACTION_PARAM_NUM; i++) {
		if (rule->actparam[i])
			newrule->actparam[i] = actparam_op[i].dup(newrule, rule->actparam[i]);
	}

	return newrule;
}

static int rule_set_iface(Rule *rule, int cond, int negate, const char *iface)
{
	cond_iface_t *c = cond_iface_alloc(rule);
	strncpy(c->name, iface, IFACE_LEN);
	c->negate = negate;
	rule->cond[cond] = c;
	return 0;
}

int rule_set_iface_in(Rule *rule, int negate, const char *iface)
{
	if (rule->cond[COND_IFACE_IN]) {
		fprintf(stderr, "Rule already has input interface\n");
		return -1;
	}

	return rule_set_iface(rule, COND_IFACE_IN, negate, iface);
}

int rule_set_iface_out(Rule *rule, int negate, const char *iface)
{
	if (rule->cond[COND_IFACE_OUT]) {
		fprintf(stderr, "Rule already has output interface\n");
		return -1;
	}

	return rule_set_iface(rule, COND_IFACE_OUT, negate, iface);
}

int rule_set_proto_num(Rule *rule, int negate, uint8_t proto)
{
	if (rule->cond[COND_PROTOCOL]) {
		fprintf(stderr, "Rule already has protocol\n");
		return -1;
	}

	cond_proto_t *cond = cond_proto_alloc(rule);
	cond->negate = negate;
	cond->protocol = proto;
	rule->cond[COND_PROTOCOL] = cond;
	return 0;
}

int rule_set_proto_name(Rule *rule, int negate, const char *proto_name)
{
	if (!proto_name || !*proto_name) {
		fprintf(stderr, "Protocol name not provided\n");
		return -1;
	}

	if (strcmp(proto_name, "all") == 0 || strcmp(proto_name, "ALL") == 0)
		return 0;

	struct protoent *proto = getprotobyname(proto_name);
	if (!proto) {
		fprintf(stderr, "Unknown protocol '%s'\n", proto_name);
		return -1;
	}
	return rule_set_proto_num(rule, negate, proto->p_proto);
}

static inline int rule_is_proto(Rule *rule, uint8_t proto)
{
	cond_proto_t *cond = rule->cond[COND_PROTOCOL];
	return cond && cond->protocol == proto && !cond->negate;
}

static int rule_set_addr(Rule *rule, int idx, int negate, uint32_t addr, uint32_t mask)
{
	if (rule->cond[idx]) {
		fprintf(stderr, "Address match already set\n");
		return -1;
	}

	if (mask == 0)
		return 0;

	cond_addr_t *cond = cond_addr_alloc(rule);
	cond->neg = negate;
	cond->addr = addr;
	cond->mask = mask;
	rule->cond[idx] = cond;
	return 0;
}

int rule_set_addr_src(Rule *rule, int negate, uint32_t src_addr, uint32_t src_mask)
{
	return rule_set_addr(rule, COND_ADDR_SRC, negate, src_addr, src_mask);
}

int rule_set_addr_dst(Rule *rule, int negate, uint32_t dst_addr, uint32_t dst_mask)
{
	return rule_set_addr(rule, COND_ADDR_DST, negate, dst_addr, dst_mask);
}

static int rule_set_port(Rule *rule, int idx, int negate, uint16_t port)
{
	if (rule->cond[idx]) {
		fprintf(stderr, "Port matching is already set\n");
		return -1;
	}
	if (!rule_is_proto(rule, 6) && !rule_is_proto(rule, 17)) {
		fprintf(stderr, "Setting port but protocol is not udp nor tcp\n");
		return -1;
	}

	cond_port_t *cond = cond_port_alloc(rule);
	cond->neg = negate;
	cond->port = port;
	rule->cond[idx] = cond;
	return 0;
}

int rule_set_port_src(Rule *rule, int negate, uint16_t src_port)
{
	return rule_set_port(rule, COND_PORT_SRC, negate, src_port);
}

int rule_set_port_dst(Rule *rule, int negate, uint16_t dst_port)
{
	return rule_set_port(rule, COND_PORT_DST, negate, dst_port);
}

static int rule_set_icmp(Rule *rule, int negate, uint16_t type, uint16_t code, int code_match)
{
	if (rule->cond[COND_ICMP_TYPE]) {
		fprintf(stderr, "Setting icmp type but it is already set\n");
		return -1;
	}
	if (!rule_is_proto(rule, 1)) {
		fprintf(stderr, "Setting icmp type but protocol is not icmp\n");
		return -1;
	}
	cond_icmptype_t *cond = cond_icmptype_alloc(rule);
	cond->type = type;
	cond->code = code;
	cond->neg = negate;
	cond->code_match = code_match;
	rule->cond[COND_ICMP_TYPE] = cond;
	return 0;
}

int rule_set_icmp_type(Rule *rule, int negate, uint16_t type)
{
	return rule_set_icmp(rule, negate, type, 0, 0);
}

int rule_set_icmp_type_code(Rule *rule, int negate, uint16_t type, uint16_t code)
{
	return rule_set_icmp(rule, negate, type, code, 1);
}

int rule_set_tcp_flags(Rule *rule, int negate, uint32_t mask, uint32_t comp)
{
	if (rule->cond[COND_TCP_FLAGS]) {
		fprintf(stderr, "TCP flags matching already set\n");
		return -1;
	}

	if (!mask) {
		fprintf(stderr, "Empty mask for tcp flag matching\n");
		return -1;
	}

	if (comp & !mask) {
		fprintf(stderr, "Comparison will always fail\n");
		return -1;
	}

	cond_tcpflags_t *cond = cond_tcpflags_alloc(rule);
	cond->mask = mask;
	cond->comp = comp;
	cond->neg = negate;
	rule->cond[COND_TCP_FLAGS] = cond;
	return 0;
}

int rule_set_tcp_flags_by_name(Rule *rule, int negate, char *mask, char *comp)
{
	char *token;
	uint32_t mask_num = 0;
	uint32_t comp_num = 0;

	for (token = strtok(mask, ","); token; token = strtok(NULL, ",")) {
		uint32_t val = 0;
		int ret = translate_tcp_flag(token, &val);
		if (ret) {
			fprintf(stderr, "Invalid TCP flag '%s'\n", token);
			return -1;
		}
		mask_num |= val;
	}

	for (token = strtok(comp, ","); token; token = strtok(NULL, ",")) {
		uint32_t val = 0;
		int ret = translate_tcp_flag(token, &val);
		if (ret) {
			fprintf(stderr, "Invalid TCP flag '%s'\n", token);
			return -1;
		}
		comp_num |= val;
	}

	return rule_set_tcp_flags(rule, negate, mask_num, comp_num);
}


int rule_set_tcp_option(Rule *rule, int negate, uint32_t option)
{
	if (rule->cond[COND_TCP_OPTION]) {
		fprintf(stderr, "TCP option matching already set\n");
		return -1;
	}

	cond_tcpopt_t *cond = cond_tcpopt_alloc(rule);
	cond->option = option;
	cond->neg = negate;
	rule->cond[COND_TCP_OPTION] = cond;
	return 0;
}

int rule_set_match(Rule *rule, const char *name)
{
	if (strcmp(name, "state") == 0)
		return 0;

	fprintf(stderr, "Unknown match '%s'\n", name);
	return -1;
}

int rule_set_state(Rule *rule, int negate, char *states)
{
	if (rule->cond[COND_MATCH_STATE]) {
		fprintf(stderr, "State match already set\n");
		return -1;
	}

	uint32_t state = states_to_mask(states);
	if (!state)
		return -1;

	cond_state_t *cond = cond_state_alloc(rule);
	cond->state = state;
	cond->neg = negate;
	rule->cond[COND_MATCH_STATE] = cond;
	return 0;
}

int rule_set_action_name(Rule *rule, const char *action)
{
	if (rule->action != RULE_NOT_SET || !action) {
		fprintf(stderr, "Rule already set or action not provided\n");
		return -1;
	}

	if (strcmp(action, "ACCEPT") == 0)
		rule->action = RULE_ACCEPT;
	else if (strcmp(action, "DROP") == 0)
		rule->action = RULE_DROP;
	else if (strcmp(action, "REJECT") == 0)
		rule->action = RULE_REJECT;
	else if (strcmp(action, "LOG") == 0)
		rule->action = RULE_LOG;
	else if (strcmp(action, "RETURN") == 0) {
		fprintf(stderr, "Unsupported target RETURN\n");
		return -1;
	} else {
		rule->action = RULE_JUMP;
		rule->jump_chain = talloc_strdup(rule, action);
	}
	return 0;
}

int rule_set_log_level(Rule *rule, const char *level)
{
	if (rule->actparam[ACTION_PARAM_LOG_LEVEL]) {
		fprintf(stderr, "Log level is already set\n");
		return -1;
	}

	if (!level || !level[0]) {
		fprintf(stderr, "No log level given\n");
		return -1;
	}

	if (rule->action != RULE_LOG) {
		fprintf(stderr, "Rule is not for logging\n");
		return -1;
	}

	rule->actparam[ACTION_PARAM_LOG_LEVEL] = talloc_strdup(rule, level);
	return 0;
}

int rule_set_log_prefix(Rule *rule, const char *prefix)
{
	if (rule->actparam[ACTION_PARAM_LOG_PREFIX]) {
		fprintf(stderr, "Log prefix is already set\n");
		return -1;
	}

	if (!prefix || !prefix[0]) {
		fprintf(stderr, "No log prefix given\n");
		return -1;
	}

	if (rule->action != RULE_LOG) {
		fprintf(stderr, "Rule is not for logging\n");
		return -1;
	}

	rule->actparam[ACTION_PARAM_LOG_PREFIX] = talloc_strdup(rule, prefix);
	return 0;
}

static int rule_intersect(Rule *rule, Rule *source_rule)
{
	int i;
	for (i = 0; i < COND_NUM; i++) {
		if (!source_rule->cond[i])
			continue;

		if (!rule->cond[i])
			rule->cond[i] = cond_op[i].dup(rule, source_rule->cond[i]);
		else {
			int ret = cond_op[i].intersect(rule, i, source_rule->cond[i]);
			if (ret) {
				fprintf(stderr, "Intersection failed idx=%d\n", i);
				return -1;
			}
		}
	}

	if (rule->action == RULE_JUMP) {
		/* We replace the jump with the new action */
		rule->action = source_rule->action;
	} else if (rule->action != source_rule->action) {
		fprintf(stderr, "Dont know what to do about different actions...\n");
		return -1;
	}

	if (rule->jump_chain) {
		talloc_free(rule->jump_chain);
		rule->jump_chain = NULL;
	}
	if (rule->action == RULE_JUMP)
		rule->jump_chain = talloc_strdup(rule, source_rule->jump_chain);

	for (i = 0; i < ACTION_PARAM_NUM; i++) {
		switch (rule->action) {
			case RULE_JUMP:
			case RULE_ACCEPT:
			case RULE_DROP:
			case RULE_REJECT:
			case RULE_NOT_SET:
				if (rule->actparam[i]) {
					talloc_free(rule->actparam[i]);
					rule->actparam[i] = NULL;
				}
				break;
			case RULE_LOG:
				switch (i) {
					case ACTION_PARAM_LOG_LEVEL:
					case ACTION_PARAM_LOG_PREFIX:
						if (source_rule->actparam[i]) {
							if (rule->actparam[i]) {
								talloc_free(rule->actparam[i]);
								rule->actparam[i] = NULL;
							}
							rule->actparam[i] = actparam_op[i].dup(rule, source_rule->actparam[i]);
						}
						break;
					default:
						if (rule->actparam[i]) {
							talloc_free(rule->actparam[i]);
							rule->actparam[i] = NULL;
						}
						break;
				}
				break;
		}
	}

	return 0;
}

static void rule_start(void)
{
	printf("iptables");
}

static void rule_end(void)
{
	printf("\n");
}

static const char *action_name(RuleAction action, const char *chain_name)
{
	switch (action) {
		case RULE_ACCEPT: return "ACCEPT";
		case RULE_DROP: return "DROP";
		case RULE_REJECT: return "REJECT";
		case RULE_LOG: return "LOG";
		case RULE_JUMP: return chain_name;
		case RULE_NOT_SET: return "NOT_SET";
	}

	return "UNKNOWN";
}

static void rule_output(const char *chain_name, Rule *rule)
{
	rule_start();
	rule_mid("-A %s", chain_name);

	int i;
	for (i = 0; i < COND_NUM; i++) {
		if (rule->cond[i])
			cond_op[i].output(cond_op[i].this, rule->cond[i]);
	}

	rule_mid("-j %s", action_name(rule->action, rule->jump_chain));

	for (i = 0; i < ACTION_PARAM_NUM; i++) {
		if (rule->actparam[i])
			actparam_op[i].output(rule->action, rule->actparam[i]);
	}

	rule_end();
}

static void chain_output(Chain *chain, int create_chain)
{
	Rule *rule;

	if (create_chain) {
		rule_start();
		rule_mid("-N %s", chain->name);
		rule_end();
	}

	for (rule = chain->rules; rule; rule = rule->next)
		rule_output(chain->name, rule);
}

void rules_output(RuleTree *rule_tree)
{
	int i;

	/* Output the extra groups in reverse order so that referencing them will
	 * work as expected */
	for (i = rule_tree->num_chains-1; i >= 3; i--) {
		chain_output(rule_tree->chains[i], 1);
	}

	/* Output the standard chains, without chain creation command */
	chain_output(rule_tree->input, 0);
	chain_output(rule_tree->output, 0);
	chain_output(rule_tree->forward, 0);
}


/*********************************** Optimizer ***************************/

struct GroupRule;

typedef struct Group {
	struct Group *next;
	RuleAction action;
	Rule *rules;
	Rule **last_rule;
	struct GroupRule *groups;
} Group;

typedef struct GroupRule {
	struct GroupRule *next;
	Rule rule;
	struct Group group;
} GroupRule;

static inline int can_group_rule(Rule *first_rule, Rule *last_rule, Rule *checked_rule)
{
	assert(first_rule);
	assert(last_rule);
	assert(checked_rule);
	return first_rule->action == checked_rule->action && last_rule->action == checked_rule->action;
}

struct max_val_t {
	gpointer key;
	unsigned value;
	int idx;
};

struct ext_rule_t {
	struct ext_rule_t *next;
	Rule *rule;
};

struct tree_val_t {
	unsigned value;
	struct ext_rule_t *head;
	struct ext_rule_t **tail;
};

static int g_tree_talloc_array_destroy(void *array)
{
	GTree **tree = array;
	int idx;
	for (idx = 0; idx < COND_NUM; idx++) {
		if (tree[idx])
			g_tree_destroy(tree[idx]);
	}
	return 0;
}

static void group_rules(Rule *rule, struct max_val_t *maxer)
{
	GTree **tree = talloc_array(NULL, GTree*, COND_NUM);
	talloc_set_destructor((void*)tree, g_tree_talloc_array_destroy);

	int idx;

	for (idx = 0; idx < COND_NUM; idx++) {
		if (cond_op[idx].cmp)
			tree[idx] = g_tree_new((GCompareFunc)cond_op[idx].cmp);
	}

	/* Find the largest set of rules with a common condition that can be moved */
	for (; rule; rule = rule->next) {
		for (idx = 0; idx < COND_NUM; idx++) {
			if (!cond_op[idx].cmp || !rule->cond[idx])
				continue;
			void *cond = rule->cond[idx];
			struct tree_val_t *value = g_tree_lookup(tree[idx], cond);
			if (!value) {
				value = talloc_zero(tree, struct tree_val_t);
				value->value = 1;
				value->tail = &value->head;
				g_tree_insert(tree[idx], cond, value);
				continue;
			}


				value->value++;

			*value->tail = talloc(tree, struct ext_rule_t);
			(*value->tail)->rule = rule;
			value->tail = &(*value->tail)->next;

			if (value->value > maxer->value) {
				maxer->key = cond;
				maxer->value = value->value;
				maxer->idx = idx;
			}
		}
	}

	talloc_free(tree);
}

void optimize_chain(RuleTree *tree, Chain *chain)
{
	/* @todo Remove duplicate rules, also remove rules that are a subset of a previous rule. */

	/* Collate all common conditions to be able to find the maximum */
	struct max_val_t maxer = { 0, 0, -1 };

	group_rules(chain->rules, &maxer);

	if (maxer.value > 1) {
		/* Make a group out of this */
		GroupRule *grule = talloc_zero(group, GroupRule);
		grule->rule.cond[maxer.idx] = talloc_reference(grule, maxer.key);
		grule->group.action = group->action;
		
		/* Move all matching rules to this group */
		Rule **grule_last = &grule->group.rules;
		Rule **prule = &group->rules;
		while (*prule) {
			if (cond_op[maxer.idx].cmp(maxer.key, (*prule)->cond[maxer.idx]) == 0) {
				/* Remove the shared condition from the rule */
				talloc_free((*prule)->cond[maxer.idx]);
				(*prule)->cond[maxer.idx] = NULL;

				/* Chain the rule to the new group */
				*grule_last = *prule; /* Chain the rule to the new group rules */
				*prule = (*prule)->next; /* Remove the rule from the current group rules */
				grule_last = &(*grule_last)->next; /* Point the new group rules to the end of the list */
			} else {
				prule = &(*prule)->next;
			}
		}

		*grule_last = NULL; /* Terminate the new group rules list */

		/* Attach the new group to the end of the current group groups */
		GroupRule **pgrule;
		for (pgrule = &group->groups; *pgrule; pgrule = &(*pgrule)->next)
			;
		*pgrule = grule;

		/* Optimize the rest of the group again */
		optimize_chain(tree, chain);
	}
}

void rules_optimize(RuleTree *rule_tree)
{
	int i;

	for (i = rule_tree->num_chains-1; i > 0; i--)
		optimize_chain(rule_tree, rule_tree->chains[i]);
}

static void chain_linearize(RuleTree *tree, Chain *start_chain)
{
	Rule **prule = &start_chain->rules;
	while (*prule) {
		Rule *rule = *prule;

		if (rule->action != RULE_JUMP) {
			/* Nothing to do, go to next rule */
			prule = &rule->next;
		} else {
			/* A jump rule! Let's linearize its chain */
			Chain *chain = rules_get_chain(tree, rule->jump_chain);
			Rule *chain_rule;
			Rule *next_rule = rule;
			for (chain_rule = chain->rules; chain_rule; chain_rule = chain_rule->next) {
				Rule *newrule = rule_dup(start_chain, rule);

				int invalid = rule_intersect(newrule, chain_rule);
				if (invalid) {
					printf("# Throwing away rule due to invalid intersection\n");
					printf("# Base rule: ");
					rule_output(start_chain->name, rule);
					printf("# Second rule: ");
					rule_output(chain->name, chain_rule);
					talloc_free(newrule);
					continue;
				}

				newrule->next = next_rule->next;
				next_rule->next = newrule;
				next_rule = newrule;
			}

			/* Remove the jump rule */
			*prule = (*prule)->next;
			talloc_free(rule);
		}
	}
}

void rules_linearize(RuleTree *rule_tree)
{
	chain_linearize(rule_tree, rule_tree->input);
	chain_linearize(rule_tree, rule_tree->output);
	chain_linearize(rule_tree, rule_tree->forward);

	/* Remove all the extra chains */
	while (rule_tree->num_chains > 3) {
		int idx = rule_tree->num_chains-1;
		talloc_free(rule_tree->chains[idx]);
		rule_tree->chains[idx] = NULL;
		rule_tree->num_chains--;
	}
}
