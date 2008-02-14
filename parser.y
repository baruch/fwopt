%{
#include <stdio.h>
#include <stdint.h>
#include <talloc.h>
#include "parser.h"
#include "rules.h"
#include "parser.int.h"

static void yyerror(RuleTree *tree, const char *msg);
int yylex();

struct Option {
	struct Option *next;
	int code;
	union {
		char *name;
		uint32_t ip;
		uint16_t port;
	} u;
};

static Option *option_init(int code)
{
	Option *opt = talloc_zero(NULL, Option);
	opt->code = code;
	return opt;
}

static Option *option_init_name(int code, const char *name)
{
	Option *opt = option_init(code);
	opt->u.name = talloc_strdup(opt, name);
	return opt;
}

static Option *option_init_ip(int code, uint32_t ip)
{
	Option *opt = option_init(code);
	opt->u.ip = ip;
	return opt;
}

static Option *option_init_port(int code, uint16_t port)
{
	Option *opt = option_init(code);
	opt->u.port = port;
	return opt;
}

static Option *option_chain(Option *first, Option *next)
{
	if (first) {
		first->next = next;
		(void)talloc_reference(first, next);
		return first;
	}
	return next;
}

static int options_into_rule(Rule *rule, Option *head)
{
	int ret = 0;
	Option *tmp;

	for (tmp = head; tmp; tmp = tmp->next) {
		switch (tmp->code) {
		case T_OPT_IFACE_IN:
			rule_set_iface_in(rule, tmp->u.name);
			break;
		case T_OPT_SRC_IP:
			rule_set_addr_src(rule, tmp->u.ip);
			break;
		case T_OPT_DST_PORT:
			rule_set_port_dst(rule, tmp->u.port);
			break;
		}
	}

	talloc_free(head);
	return ret;
}

%}

%union {
	char *name;
	uint32_t ip;
	uint32_t num;
	Option *option;
}

%token T_OPT_APPEND T_OPT_NEW_CHAIN T_OPT_DELETE_CHAIN T_OPT_FLUSH
%token T_OPT_JUMP
%token T_OPT_IFACE_IN
%token T_OPT_SRC_IP
%token T_OPT_DST_PORT
%token<name> T_NAME
%token<num> T_NUMBER
%token T_SLASH
%token<ip> T_IP
%token T_IPTABLES
%token T_EOL

%type<option> options
%type<option> option

%start prog
%error-verbose
%parse-param {RuleTree *tree}

%%

prog
:
	commands done
;

done
:
	/* empty */
|
	T_EOL
;

commands
:
	/* empty */
|
	prefixed_command
|
	commands T_EOL prefixed_command
;

prefixed_command
:
	prefix command
;

command
:
	T_OPT_APPEND T_NAME options T_OPT_JUMP T_NAME options {
		Rule *rule = rule_init();
		if (rule_set_action_name(rule, $5)) {
			fprintf(stderr, "Illegal jump target '%s'\n", $5);
			YYABORT;
		}
		if (options_into_rule(rule, $3)) {
			fprintf(stderr, "Error setting options\n");
			YYABORT;
		}
		if (options_into_rule(rule, $6)) {
			fprintf(stderr, "Error setting options\n");
			YYABORT;
		}
		rules_append_rule(tree, $2, rule);
	}
|
	T_OPT_NEW_CHAIN T_NAME { printf("New chain %s\n", $2); }
|
	T_OPT_FLUSH { printf("Flush all rules\n"); }
|
	T_OPT_FLUSH T_NAME { printf("Flush chain '%s'\n", $2); }
|
	T_OPT_DELETE_CHAIN { printf("Delete all extra chains\n"); }
|
	T_OPT_DELETE_CHAIN T_NAME { printf("Delete chain '%s'\n", $2); }
;

prefix
:
	/* empty */
|
	T_IPTABLES
;

options
:
	/* empty */ { $$ = NULL; }
|
	options option { $$ = option_chain($1, $2); }
;

option
:
	T_OPT_IFACE_IN T_NAME { $$ = option_init_name(T_OPT_IFACE_IN, $2); }
|
	T_OPT_SRC_IP T_IP/*ipmask*/ { $$ = option_init_ip(T_OPT_SRC_IP, $2); }
|
	T_OPT_DST_PORT T_NUMBER { $$ = option_init_port(T_OPT_DST_PORT, $2); }
;

/*
ipmask
:
	T_IP
|
	T_IP T_SLASH T_NUMBER
|
	T_IP T_SLASH T_IP
;
*/

%%

static void yyerror(RuleTree *tree, const char *msg)
{
	fprintf(stderr, "Error: %s\n", msg);
}
