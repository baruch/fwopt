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
	int negate;
	enum {
		OPT_NULL,
		OPT_NAME,
		OPT_IP,
		OPT_PORT,
		OPT_U32,
		OPT_ICMP,
	} type;
	union {
		const char *name;
		uint32_t u32;
		struct ipmask ip;
		uint16_t port;
		struct icmptype icmp;
	} u;
};

static Option *option_init(int code, int type)
{
	Option *opt = talloc_zero(NULL, Option);
	opt->code = code;
	opt->type = type;
	return opt;
}

static Option *option_init_null(int code)
{
	return option_init(code, OPT_NULL);
}

static Option *option_init_name(int code, const char *name)
{
	Option *opt = option_init(code, OPT_NAME);
	opt->u.name = name;
	talloc_steal(opt, name);
	return opt;
}

static Option *option_init_ip(int code, struct ipmask ip)
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

static Option *option_init_icmp_type(int negate, struct icmptype icmp)
{
	Option *opt = option_init(T_OPT_ICMP_TYPE, OPT_ICMP);
	opt->negate = negate;
	opt->u.icmp = icmp;
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
		case T_OPT_IFACE_OUT: ret = rule_set_iface_out(rule, tmp->u.name); break;
		case T_OPT_SRC_IP: ret = rule_set_addr_src(rule, tmp->u.ip.addr, tmp->u.ip.mask);break;
		case T_OPT_DST_IP: ret = rule_set_addr_dst(rule, tmp->u.ip.addr, tmp->u.ip.mask); break;
		case T_OPT_DST_PORT: ret = rule_set_port_dst(rule, tmp->u.port); break;
		case T_OPT_SRC_PORT: ret = rule_set_port_src(rule, tmp->u.port); break;
		case T_OPT_PROTO:
			if (tmp->type == OPT_NAME)
				ret = rule_set_proto_name(rule, tmp->u.name);
			else
				ret = rule_set_proto_num(rule, tmp->u.u32);
			break;
		case T_OPT_ICMP_TYPE:
			if (tmp->u.icmp.code_match)
				ret = rule_set_icmp_type_code(rule, tmp->negate, tmp->u.icmp.type, tmp->u.icmp.code);
			else
				ret = rule_set_icmp_type(rule, tmp->negate, tmp->u.icmp.type);
			break;
		case T_OPT_MODULE:
		case T_OPT_STATE:
		case T_OPT_LOG_LEVEL:
		case T_OPT_LOG_PREFIX:
		case T_OPT_TCP_SYN:
			fprintf(stderr, "Unsupported option %d\n", tmp->code);
			break;
		default: {
			char msg[80];
			snprintf(msg, sizeof(msg), "Unknown option code %d", tmp->code);
			yyerror(NULL, msg);
			ret = -1;
			}
			break;
		}
	}

	talloc_free(head);
	return ret;
}

%}

%union {
	char *name;
	struct ipmask ip;
	struct icmptype icmp;
	uint32_t num;
	Option *option;
}

%token T_OPT_APPEND T_OPT_NEW_CHAIN T_OPT_DELETE_CHAIN T_OPT_FLUSH T_OPT_POLICY
%token T_OPT_JUMP
%token T_OPT_IFACE_IN T_OPT_IFACE_OUT
%token T_OPT_SRC_IP T_OPT_DST_IP
%token T_OPT_PROTO T_OPT_SRC_PORT T_OPT_DST_PORT
%token T_OPT_ICMP_TYPE
%token T_OPT_MODULE T_OPT_STATE
%token T_OPT_LOG_LEVEL T_OPT_LOG_PREFIX
%token T_OPT_TCP_SYN
%token T_OPT

%token T_IPTABLES
%token T_EOL T_SLASH T_EXCLAM

%token<name> T_NAME T_NAME_COMMA T_QUOTE
%token<num> T_NUMBER
%token<num> T_IP

%type<option> options
%type<option> option
%type<ip> ipmask
%type<num> ip
%type<num> negate
%type<icmp> icmp_type

%start prog
%error-verbose
%parse-param {RuleTree *tree}

%%

prog
:
	line
|
	prog T_EOL line
;

line
:
	/* empty */
|
	prefix command
;

command
:
	T_OPT_APPEND T_NAME options T_OPT_JUMP T_NAME options {
		Rule *rule = rule_init();
		if (rule_set_action_name(rule, $5)) {
			char msg[80];
			snprintf(msg, sizeof(msg), "Illegal jump target '%s'\n", $5);
			yyerror(tree, msg);
			YYABORT;
		}
		if (options_into_rule(rule, $3)) {
			yyerror(tree, "Options parsing failed");
			YYABORT;
		}
		if (options_into_rule(rule, $6)) {
			yyerror(tree, "Options parsing failed");
			YYABORT;
		}
		if (rules_append_rule(tree, $2, rule)) {
			yyerror(tree, "Rule append failed");
			YYABORT;
		}
		talloc_unlink(NULL, rule);
	}
|
	T_OPT_NEW_CHAIN T_NAME { rules_new_chain(tree, $2); }
|
	T_OPT_POLICY T_NAME T_NAME { printf("Policy for chain %s is %s\n", $2, $3); }
|
	T_OPT_FLUSH { if (rules_flush_all(tree)) YYABORT; }
|
	T_OPT_FLUSH T_NAME { if (rules_flush_chain(tree, $2)) YYABORT; }
|
	T_OPT_DELETE_CHAIN { if (rules_delete_chains(tree)) YYABORT; }
|
	T_OPT_DELETE_CHAIN T_NAME { if (rules_delete_chain(tree, $2)) YYABORT; }
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
	T_OPT_IFACE_OUT T_NAME { $$ = option_init_name(T_OPT_IFACE_OUT, $2); }
|
	T_OPT_SRC_IP ipmask { $$ = option_init_ip(T_OPT_SRC_IP, $2); }
|
	T_OPT_DST_IP ipmask { $$ = option_init_ip(T_OPT_DST_IP, $2); }
|
	T_OPT_PROTO T_NAME { $$ = option_init_name(T_OPT_PROTO, $2); }
|
	T_OPT_PROTO T_NUMBER { $$ = option_init_u32(T_OPT_PROTO, $2); }
|
	T_OPT_SRC_PORT T_NUMBER { $$ = option_init_port(T_OPT_SRC_PORT, $2); }
|
	T_OPT_DST_PORT T_NUMBER { $$ = option_init_port(T_OPT_DST_PORT, $2); }
|
	T_OPT_MODULE T_NAME { $$ = option_init_name(T_OPT_MODULE, $2); }
|
	T_OPT_STATE T_NAME_COMMA { $$ = option_init_name(T_OPT_STATE, $2); }
|
	T_OPT_LOG_LEVEL T_NAME { $$ = option_init_name(T_OPT_LOG_LEVEL, $2); }
|
	T_OPT_LOG_PREFIX T_QUOTE { $$ = option_init_name(T_OPT_LOG_PREFIX, $2); }
|
	T_OPT_TCP_SYN { $$ = option_init_null(T_OPT_TCP_SYN); }
|
	T_OPT_ICMP_TYPE negate icmp_type { $$ = option_init_icmp_type($2, $3); }
;

negate
:
	/* empty */ { $$ = 0; }
|
	T_EXCLAM { $$ = 1; }
;

icmp_type
:
	T_NUMBER { $$.type = $1; $$.code = $$.code_match = 0; }
|
	T_NUMBER T_SLASH T_NUMBER { $$.type = $1; $$.code = $3; $$.code_match = 1; }
|
	T_NAME { translate_icmp_type($1, &$$); }
;

ipmask
:
	ip { $$.addr = $1; $$.mask = 0xFFFFFFFF; }
|
	ip T_SLASH T_NUMBER { $$.addr = $1;
	                        $$.mask = 0;
				int i;
				for (i = 32; i > (32-$3); i--)
					$$.mask |= 1<<(i-1);
			      }
|
	ip T_SLASH T_IP { $$.addr = $1; $$.mask = $3; }
;

ip
:
	T_IP { $$ = $1; }
|
	T_NUMBER { $$ = $1; }
;

%%

static void yyerror(RuleTree *tree, const char *msg)
{
	fprintf(stderr, "Error: %s\n", msg);

	int ch = lex_line[lex_line_len-1];
	if (ch == '\r' || ch == '\n')
		lex_line[lex_line_len-1] = '\0';
	fprintf(stderr, "%s\n", lex_line);

	int i;
	for (i = 0; i < lex_prev_token_idx; i++)
		fprintf(stderr, " ");
	for (; i < lex_idx; i++)
		fprintf(stderr, "^");

	fprintf(stderr, "\n");
}
