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
	enum {
		OPT_NAME,
		OPT_IP,
		OPT_PORT,
		OPT_U32,
	} type;
	union {
		const char *name;
		uint32_t u32;
		uint32_t ip;
		uint16_t port;
	} u;
};

static Option *option_init(int code, int type)
{
	Option *opt = talloc_zero(NULL, Option);
	opt->code = code;
	opt->type = type;
	return opt;
}

static Option *option_init_name(int code, const char *name)
{
	Option *opt = option_init(code, OPT_NAME);
	opt->u.name = name;
	talloc_steal(opt, name);
	return opt;
}

static Option *option_init_ip(int code, uint32_t ip)
{
	Option *opt = option_init(code, OPT_IP);
	opt->u.ip = ip;
	return opt;
}

static Option *option_init_port(int code, uint16_t port)
{
	Option *opt = option_init(code, OPT_PORT);
	opt->u.port = port;
	return opt;
}

static Option *option_init_u32(int code, uint32_t u32)
{
	Option *opt = option_init(code, OPT_U32);
	opt->u.u32 = u32;
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
		case T_OPT_IFACE_IN: ret = rule_set_iface_in(rule, tmp->u.name); break;
		case T_OPT_SRC_IP: ret = rule_set_addr_src(rule, tmp->u.ip);break;
		case T_OPT_DST_IP: ret = rule_set_addr_dst(rule, tmp->u.ip); break;
		case T_OPT_DST_PORT: ret = rule_set_port_dst(rule, tmp->u.port); break;
		case T_OPT_SRC_PORT: ret = rule_set_port_src(rule, tmp->u.port); break;
		case T_OPT_PROTO:
			if (tmp->type == OPT_NAME)
				ret = rule_set_proto_name(rule, tmp->u.name);
			else
				ret = rule_set_proto_num(rule, tmp->u.u32);
			break;
		default:
			fprintf(stderr, "Unknown option code %d\n", tmp->code);
			ret = -1;
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
%token T_OPT_SRC_IP T_OPT_DST_IP
%token T_OPT_PROTO T_OPT_SRC_PORT T_OPT_DST_PORT
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
			YYABORT;
		}
		if (options_into_rule(rule, $6)) {
			YYABORT;
		}
		rules_append_rule(tree, $2, rule);
		talloc_unlink(NULL, rule);
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
	T_OPT_DST_IP T_IP { $$ = option_init_ip(T_OPT_DST_IP, $2); }
|
	T_OPT_PROTO T_NAME { $$ = option_init_name(T_OPT_PROTO, $2); }
|
	T_OPT_PROTO T_NUMBER { $$ = option_init_u32(T_OPT_PROTO, $2); }
|
	T_OPT_SRC_PORT T_NUMBER { $$ = option_init_port(T_OPT_SRC_PORT, $2); }
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
