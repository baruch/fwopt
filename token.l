%{
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <talloc.h>

#include "parser.int.h"
#include "parser.tab.h"

char lex_line[1024];
int lex_lineno;
int lex_idx;
int lex_line_len;
int lex_last_token_idx;
int lex_prev_token_idx;

static int my_yy_input(char *buf, int max_size)
{
	int result = YY_NULL;

	while (lex_idx >= lex_line_len) {
		char *tmp = fgets(lex_line, sizeof(lex_line), yyin);
		if (tmp == NULL) {
			result = YY_NULL;
			break;
		}
		lex_lineno++;
		lex_idx = 0;
		lex_last_token_idx = 0;
		lex_prev_token_idx = 0;
		lex_line_len = strlen(lex_line);
	}

	if (lex_idx < lex_line_len) {
		result = 1;
		buf[0] = lex_line[lex_idx++];
	}

	return result;
}

static void mark_token_start(void)
{
	lex_prev_token_idx = lex_last_token_idx;
	lex_last_token_idx = lex_idx;
}

#define YY_INPUT(buf, result, max_size) result = my_yy_input(buf, max_size)

%}

%option noyywrap
%option nounput

newline       [\r\n]
delimiter     [ \t]
whitespace    {delimiter}+
digit         [0-9]
number        {digit}+
letter        [a-zA-Z]
alnum         [a-zA-Z0-9]
word          {letter}+({number}|\+)?

%%

"#".*         { /* Ignore comments */ }
{whitespace}  { /* Ignore whitespace */ }
"/"           { mark_token_start(); return T_SLASH; }

"iptables"    { mark_token_start(); return T_IPTABLES; }

"-A"          { mark_token_start(); return T_OPT_APPEND; }
"-N"          { mark_token_start(); return T_OPT_NEW_CHAIN; }
"-F"          { mark_token_start(); return T_OPT_FLUSH; }
"-X"          { mark_token_start(); return T_OPT_DELETE_CHAIN; }
"-P"          { mark_token_start(); return T_OPT_POLICY; }
"-j"          { mark_token_start(); return T_OPT_JUMP; }
"-i"          |
"--in-interface" { mark_token_start(); return T_OPT_IFACE_IN; }
"-o"          |
"--out-interface" { mark_token_start(); return T_OPT_IFACE_OUT; }
"-s"          |
"--src"       |
"--source"    { mark_token_start(); return T_OPT_SRC_IP; }
"--dport"     |
"--destination-port" { mark_token_start(); return T_OPT_DST_PORT; }
"--sport"     |
"--source-port" { mark_token_start(); return T_OPT_SRC_PORT; }
"-p"          |
"--protocol"  { mark_token_start(); return T_OPT_PROTO; }
"-d"          |
"--dst"       |
"--destination" { mark_token_start(); return T_OPT_DST_IP; }
"-m"          { mark_token_start(); return T_OPT_MODULE; }
"--state"     { mark_token_start(); return T_OPT_STATE; }
"--log-level" { mark_token_start(); return T_OPT_LOG_LEVEL; }
"--log-prefix" { mark_token_start(); return T_OPT_LOG_PREFIX; }
"--syn"       { mark_token_start(); return T_OPT_TCP_SYN; }
-[-a-zA-Z]+   { mark_token_start(); return T_OPT; }

[0-9]+\.[0-9.]+ { mark_token_start();
		struct in_addr addr;
                int ret = inet_aton(yytext, &addr);
		if (ret == 0)
			REJECT;
		/* Valid IP address */
		yylval.num = ntohl(addr.s_addr);
                return T_IP;
              }
{number}      { mark_token_start(); sscanf(yytext, "%u", &yylval.num); return T_NUMBER; }
[a-zA-Z0-9_]+ { mark_token_start(); yylval.name = talloc_strdup(NULL, yytext); return T_NAME; }
[a-zA-Z0-9,]+ { mark_token_start(); yylval.name = talloc_strdup(NULL, yytext); return T_NAME_COMMA; }
\"[a-zA-Z0-9: ]*\" { mark_token_start(); yylval.name = talloc_strdup(NULL, yytext); return T_QUOTE; }
{newline}     { mark_token_start(); return T_EOL; }

