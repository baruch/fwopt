#include "rules.h"
#include <talloc.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <glib.h>

#define IFACE_LEN 16
#define CHAIN_LEN 32

typedef enum RuleAction {
	RULE_ACCEPT,
	RULE_DROP,
	RULE_REJECT,
	RULE_JUMP,
} RuleAction;

typedef struct Rule
{
	struct Rule *next;

	char if_in[IFACE_LEN];
	char if_out[IFACE_LEN];
	uint8_t proto;
	uint32_t src_addr;
	uint32_t dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
	RuleAction action;
	char jump_chain[CHAIN_LEN];
} Rule;

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

static Chain *rules_new_chain(RuleTree *tree, const char *name)
{
	if (tree->num_chains >= NUM_CHAINS)
		return NULL;

	Chain *chain = talloc_zero(tree, Chain);
	chain->name = talloc_strdup(chain, name);
	chain->tail = &chain->rules;

	tree->chains[tree->num_chains++] = chain;

	return chain;
}

static void rules_init_chains(RuleTree *rule_tree)
{
	rule_tree->input = rules_new_chain(rule_tree, "INPUT");
	rule_tree->output = rules_new_chain(rule_tree, "OUTPUT");
	rule_tree->forward = rules_new_chain(rule_tree, "FORWARD");
}

static RuleTree *rules_init(const void *ctx)
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

Chain *rules_get_chain(RuleTree *tree, const char *name)
{
	int i;
	for (i=0; i < tree->num_chains; i++) {
		if (strcmp(name, tree->chains[i]->name) == 0)
			return tree->chains[i];
	}

	return NULL;
}

static void chain_add_rule(Chain *chain, Rule *rule)
{
	/* Add to the end of the chain linked list */
	*chain->tail = rule;
	chain->tail = &rule->next;
}

int rules_append_rule(RuleTree *tree, const char *chain_name, const char *if_in, const char *if_out,
		uint8_t proto, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port, uint16_t dst_port,
		RuleAction action)
{
	Chain *chain = rules_get_chain(tree, chain_name);
	if (!chain) {
		fprintf(stderr, "Can't find chain %s\n", chain_name);
		return -1;
	}

	Rule *rule = talloc_zero(chain, Rule);
	if (if_in)
		strncpy(rule->if_in, if_in, IFACE_LEN);
	if (if_out)
		strncpy(rule->if_out, if_out, IFACE_LEN);
	rule->proto = proto;
	rule->src_addr = src_addr;
	rule->dst_addr = dst_addr;
	rule->src_port = src_port;
	rule->dst_port = dst_port;
	rule->action = action;

	chain_add_rule(chain, rule);

	return 0;
}

RuleTree *rules_input(const void *ctx)
{
	RuleTree *tree = rules_init(ctx);

	/* For now we will insert here a static rule tree to optimize */
	rules_append_rule(tree, "INPUT", "eth0", NULL, IPPROTO_TCP, 0, 0, 0, 22, RULE_ACCEPT);
	rules_append_rule(tree, "INPUT", "eth0", NULL, IPPROTO_TCP, 0, 0, 0, 80, RULE_ACCEPT);
	rules_append_rule(tree, "INPUT", "eth0", NULL, IPPROTO_UDP, 0, 0, 0, 53, RULE_ACCEPT);
	rules_append_rule(tree, "INPUT", "eth0", NULL, IPPROTO_UDP, 0, 0, 0, 91, RULE_ACCEPT);

	return tree;
}

void rule_start(void)
{
	printf("iptables");
}

void rule_end(void)
{
	printf("\n");
}

void rule_mid(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	printf(" ");
	vprintf(fmt, ap);
	va_end(ap);
}

static const char *action_name(RuleAction action, const char *chain_name)
{
	switch (action) {
		case RULE_ACCEPT: return "ACCEPT";
		case RULE_DROP: return "DROP";
		case RULE_REJECT: return "REJECT";
		case RULE_JUMP: return chain_name;
	}

	return "UNKNOWN";
}

void rule_output(const char *chain_name, Rule *rule)
{
	rule_start();
	rule_mid("-A %s", chain_name);

	if (rule->if_in[0])
		rule_mid("-i %s", rule->if_in);
	if (rule->if_out[0])
		rule_mid("-o %s", rule->if_out);

	if (rule->src_addr)
		rule_mid("-s src_addr");
	if (rule->dst_addr)
		rule_mid("-d dst_addr");

	if (rule->proto)
		rule_mid("-p %d", rule->proto);
	if (rule->src_port)
		rule_mid("--sport %d", rule->src_port);
	if (rule->dst_port)
		rule_mid("--dport %d", rule->dst_port);

	rule_mid("-j %s", action_name(rule->action, rule->jump_chain));

	rule_end();
}

void chain_output(Chain *chain, int create_chain)
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

void rules_destroy(RuleTree *rule_tree)
{
	talloc_free(rule_tree);
}



/*********************************** Optimizer ***************************/

struct GroupRule;

typedef struct Group {
	struct Group *next;
	RuleAction action;
	Rule *rules;
	struct GroupRule *groups;
} Group;

typedef struct GroupRule {
	struct GroupRule *next;
	Rule rule;
	struct Group group;
} GroupRule;

static int can_merge_group_and_rule(Group *group, Rule *rule)
{
	return group && group->action == rule->action;
}

static Group *chain_to_group(RuleTree *rule_tree, Chain *chain)
{
	Group *head = NULL;
	Group **next = &head;
	Group *group = NULL;
	Rule *rule;

	for (rule = chain->rules; rule; rule = rule->next) {
		/* Do we need to open a new group? */
		if (!can_merge_group_and_rule(group, rule)) {
			group = talloc_zero(head, Group);
			group->action = rule->action;

			/* Link the group into the list */
			*next = group;
			next = &group->next;
		}

		/* Add the rule into this group */
		Rule *newrule = talloc_memdup(group, rule, sizeof(*rule));
		newrule->next = group->rules;
		group->rules = newrule;
	}

	return head;
}

struct max_val_t {
	gpointer key;
	unsigned value;
};

static gboolean max_val(gpointer key, gpointer value, gpointer data)
{
	struct max_val_t *maxer = (struct max_val_t *)data;
	unsigned uval = GPOINTER_TO_UINT(value);

	if (uval > maxer->value) {
		maxer->key = key;
		maxer->value = uval;
	}

	return FALSE;
}

void optimize_group(Group *group)
{
	if (!group)
		return;

	/* @todo Remove duplicate rules, also remove rules that are a subset of a previous rule. */

	/* Divide the group into the largest common sub-groups */
	GTree *tree_itf_in = g_tree_new_with_data((GCompareDataFunc)strncmp, GUINT_TO_POINTER(IFACE_LEN));
	Rule *rule;
	for (rule = group->rules; rule; rule = rule->next) {
		gpointer value = g_tree_lookup(tree_itf_in, rule->if_in);
		unsigned uval = value ? GPOINTER_TO_UINT(value) : 0;
		g_tree_insert(tree_itf_in, rule->if_in, GUINT_TO_POINTER(uval+1));
	}

	struct max_val_t maxer = { 0, 0 };
	g_tree_foreach(tree_itf_in, max_val, &maxer);
	g_tree_destroy(tree_itf_in);

	if (maxer.value > 1) {
		/* Make a group out of this */
		GroupRule *grule = talloc_zero(group, GroupRule);
		strncpy(grule->rule.if_in, maxer.key, IFACE_LEN);
		grule->group.action = group->action;
		
		/* Move all matching rules to this group */
		Rule **grule_last = &grule->group.rules;
		Rule **prule = &group->rules;
		while (*prule) {
			if (strncmp((*prule)->if_in, maxer.key, IFACE_LEN) == 0) {
				/* Chain the rule to the new group */
				*grule_last = *prule; /* Chain the rule to the new group rules */
				*prule = (*prule)->next; /* Remove the rule from the current group rules */
				grule_last = &(*grule_last)->next; /* Point the new group rules to the end of the list */
			} else {
				prule = &(*prule)->next;
			}
		}

		*grule_last = NULL; /* Terminate the new group rules list */

		/* Clear the shared condition from all rules */
		for (prule = &grule->group.rules; *prule; prule = &(*prule)->next)
			(*prule)->if_in[0] = '\0';

		/* Attach the new group to the end of the current group groups */
		GroupRule **pgrule;
		for (pgrule = &group->groups; *pgrule; pgrule = &(*pgrule)->next)
			;
		*pgrule = grule;
	}
}

void group_to_chains(Group *group, RuleTree *tree, Chain *base_chain);

void group_rule_to_chain(GroupRule *grule, RuleTree *tree, Chain *base_chain)
{
	static unsigned chain_id = 1;
	char chain_name[CHAIN_LEN];

	snprintf(chain_name, CHAIN_LEN, "chain_%u", chain_id);

	Chain *chain = rules_new_chain(tree, chain_name);

	Rule *rule = talloc(base_chain, Rule);
	memcpy(rule, &grule->rule, sizeof(Rule));
	strncpy(rule->jump_chain, chain_name, CHAIN_LEN);
	rule->action = RULE_JUMP;
	chain_add_rule(base_chain, rule);

	group_to_chains(&grule->group, tree, chain);
}

void group_to_chains(Group *group, RuleTree *tree, Chain *base_chain)
{
	if (!group)
		return;

	/* Add the ungrouped rules */
	while (group->rules) {
		Rule *tmp = group->rules;
		group->rules = tmp->next;
		tmp->next = NULL;

		chain_add_rule(base_chain, tmp);
	}

	/* Add the grouped rules */
	GroupRule *grule;
	for (grule = group->groups; grule; grule = grule->next)
		group_rule_to_chain(grule, tree, base_chain);
}

void rules_optimize(RuleTree *rule_tree)
{
	/* Create the new groups */
	Group *input_group = chain_to_group(rule_tree, rule_tree->input);
	Group *output_group = chain_to_group(rule_tree, rule_tree->output);
	Group *forward_group = chain_to_group(rule_tree, rule_tree->forward);

	/* Clear the old rules */
	rules_clear(rule_tree);

	/* Optimize and render groups into rules */
	optimize_group(input_group);
	group_to_chains(input_group, rule_tree, rule_tree->input);
	talloc_free(input_group);
	
	optimize_group(output_group);
	group_to_chains(output_group, rule_tree, rule_tree->output);
	talloc_free(output_group);

	optimize_group(forward_group);
	group_to_chains(forward_group, rule_tree, rule_tree->forward);
	talloc_free(forward_group);
}