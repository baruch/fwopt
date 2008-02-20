%{
#include <stdio.h>
#include <stdint.h>
#include <talloc.h>
#include <string.h>
#include "parser.h"
#include "rules.h"
#include "tcpflags.h"
#include "parser.int.h"

static void yyerror(RuleTree *tree, const char *msg, ...);

int yylex();

static Rule *rule;

#define RULE_CHECK(cond) if (cond) { yyerror(NULL, "Failed setting rule"); YYABORT; }

%}

%union {
	char *name;
	struct ipmask ip;
	struct icmptype icmp;
	uint32_t num;
}

%token T_OPT_APPEND T_OPT_NEW_CHAIN T_OPT_DELETE_CHAIN T_OPT_FLUSH T_OPT_POLICY
%token T_OPT_JUMP
%token T_OPT_IFACE_IN T_OPT_IFACE_OUT
%token T_OPT_SRC_IP T_OPT_DST_IP
%token T_OPT_PROTO T_OPT_SRC_PORT T_OPT_DST_PORT
%token T_OPT_ICMP_TYPE
%token T_OPT_MODULE T_OPT_STATE
%token T_OPT_LOG_LEVEL T_OPT_LOG_PREFIX
%token T_OPT_TCP_SYN T_OPT_TCP_FLAGS T_OPT_TCP_OPTION
%token T_OPT

%token T_IPTABLES
%token T_EOL T_SLASH T_EXCLAM

%token<name> T_NAME T_NAME_COMMA T_QUOTE
%token<num> T_NUMBER
%token<num> T_IP

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
	T_OPT_APPEND T_NAME options {
		if (rules_append_rule(tree, $2, rule)) {
			yyerror(tree, "Rule append failed");
			YYABORT;
		}
		talloc_unlink(NULL, rule);
		rule = NULL;
		talloc_free($2);
	}
|
	T_OPT_NEW_CHAIN T_NAME { RULE_CHECK(rules_new_chain(tree, $2)); talloc_free($2); }
|
	T_OPT_POLICY T_NAME T_NAME { printf("Policy for chain %s is %s\n", $2, $3); talloc_free($2); talloc_free($3); }
|
	T_OPT_FLUSH { RULE_CHECK(rules_flush_all(tree)); }
|
	T_OPT_FLUSH T_NAME { RULE_CHECK(rules_flush_chain(tree, $2)); talloc_free($2); }
|
	T_OPT_DELETE_CHAIN { RULE_CHECK(rules_delete_chains(tree)); }
|
	T_OPT_DELETE_CHAIN T_NAME { RULE_CHECK(rules_delete_chain(tree, $2)); talloc_free($2); }
;

prefix
:
	/* empty */
|
	T_IPTABLES
;

options
:
	/* empty */ { if (!rule) rule = rule_init(); }
|
	options option
;

option
:
	T_OPT_JUMP T_NAME { RULE_CHECK(rule_set_action_name(rule, $2)); talloc_free($2); }
|
	T_OPT_IFACE_IN negate T_NAME { RULE_CHECK(rule_set_iface_in(rule, $2, $3)); talloc_free($3); }
|
	T_OPT_IFACE_OUT negate T_NAME { RULE_CHECK(rule_set_iface_out(rule, $2, $3)); talloc_free($3); }
|
	T_OPT_SRC_IP negate ipmask { RULE_CHECK(rule_set_addr_src(rule, $2, $3.addr, $3.mask)); }
|
	T_OPT_DST_IP negate ipmask { RULE_CHECK(rule_set_addr_dst(rule, $2, $3.addr, $3.mask)); }
|
	T_OPT_PROTO negate T_NAME { RULE_CHECK(rule_set_proto_name(rule, $2, $3)); talloc_free($3); }
|
	T_OPT_PROTO negate T_NUMBER { RULE_CHECK(rule_set_proto_num(rule, $2, $3)); }
|
	T_OPT_SRC_PORT negate T_NUMBER { RULE_CHECK(rule_set_port_src(rule, $2, $3)); }
|
	T_OPT_DST_PORT negate T_NUMBER { RULE_CHECK(rule_set_port_dst(rule, $2, $3)); }
|
	T_OPT_MODULE T_NAME { RULE_CHECK(rule_set_match(rule, $2)); talloc_free($2); }
|
	negate T_OPT_STATE T_NAME_COMMA { RULE_CHECK(rule_set_state(rule, $1, $3)); talloc_free($3); }
|
	T_OPT_LOG_LEVEL T_NAME { RULE_CHECK(rule_set_log_level(rule, $2)); talloc_free($2); }
|
	T_OPT_LOG_PREFIX T_QUOTE { RULE_CHECK(rule_set_log_prefix(rule, $2)); talloc_free($2); }
|
	negate T_OPT_TCP_SYN {
	                       char mask[] = "SYN,RST,ACK,FIN";
			       char comp[] = "SYN";
			       RULE_CHECK(rule_set_tcp_flags_by_name(rule, $1, mask, comp));
			     }
|
	T_OPT_TCP_FLAGS negate T_NAME_COMMA T_NAME_COMMA
	                     {
			       int ret = rule_set_tcp_flags_by_name(rule, $2, $3, $4);
			       talloc_free($3);
			       talloc_free($4);
	 		       RULE_CHECK(ret);
			     }
|
	T_OPT_TCP_OPTION negate T_NUMBER { RULE_CHECK(rule_set_tcp_option(rule, $2, $3)); }
|
	T_OPT_ICMP_TYPE negate icmp_type {
	                                   int ret;
	                                   if ($3.code_match) {
				             ret = rule_set_icmp_type_code(rule, $2, $3.type, $3.code);
					   } else {
					     ret = rule_set_icmp_type(rule, $2, $3.type);
					   }
					   RULE_CHECK(ret);
					 }
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
	T_NAME { translate_icmp_type($1, &$$); talloc_free($1); }
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

static void yyerror(RuleTree *tree, const char *msg, ...)
{
	va_list ap;

	/* Print variable message */
	fprintf(stderr, "Error: ");
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	/* Print the line on which we have the error, remove trailing \n or \r */
	int ch = lex_line[lex_line_len-1];
	if (ch == '\r' || ch == '\n')
		lex_line[lex_line_len-1] = '\0';
	fprintf(stderr, "%s\n", lex_line);

	/* Print an index to the location of the error in the line */
	int i;
	for (i = 0; i < lex_prev_token_idx; i++)
		fprintf(stderr, " ");
	for (; i < lex_idx; i++)
		fprintf(stderr, "^");
	fprintf(stderr, "\n");
}
