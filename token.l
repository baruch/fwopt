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

#define YY_INPUT(buf, result, max_size)                                      \
	do {                                                                 \
		while (lex_idx >= lex_line_len) {                            \
			char *tmp = fgets(lex_line, sizeof(lex_line), yyin); \
			if (tmp == NULL) {                                   \
				result = YY_NULL;                            \
				break; /* exit the while (0) */              \
			}                                                    \
			lex_lineno++;                                        \
			lex_idx = 0;                                         \
			lex_line_len = strlen(lex_line);                     \
		}                                                            \
		if (lex_idx < lex_line_len) {                                \
			result = 1;                                          \
			buf[0] = lex_line[lex_idx++];                        \
		} else                                                       \
			result = YY_NULL;                                    \
	} while(0)

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

"iptables"    { return T_IPTABLES; }

"-A"          { return T_OPT_APPEND; }
"-N"          { return T_OPT_NEW_CHAIN; }
"-F"          { return T_OPT_FLUSH; }
"-X"          { return T_OPT_DELETE_CHAIN; }
"-P"          { return T_OPT_POLICY; }
"-j"          { return T_OPT_JUMP; }
"-i"          |
"--in-interface" { return T_OPT_IFACE_IN; }
"-o"          |
"--out-interface" { return T_OPT_IFACE_OUT; }
"-s"          |
"--src"       |
"--source"    { return T_OPT_SRC_IP; }
"--dport"     |
"--destination-port" { return T_OPT_DST_PORT; }
"--sport"     |
"--source-port" { return T_OPT_SRC_PORT; }
"-p"          |
"--protocol"  { return T_OPT_PROTO; }
"-d"          |
"--dst"       |
"--destination" { return T_OPT_DST_IP; }
"-m"          { return T_OPT_MODULE; }
"--state"     { return T_OPT_STATE; }
"--log-level" { return T_OPT_LOG_LEVEL; }
"--log-prefix" { return T_OPT_LOG_PREFIX; }
-[-a-zA-Z]+   { return T_OPT; }

[0-9]+\.[0-9.]+ {
		struct in_addr addr;
                int ret = inet_aton(yytext, &addr);
		if (ret == 0)
			REJECT;
		/* Valid IP address */
		yylval.ip = ntohl(addr.s_addr);
                return T_IP;
              }
{number}      { sscanf(yytext, "%u", &yylval.num); return T_NUMBER; }
{word}        { yylval.name = talloc_strdup(NULL, yytext); return T_NAME; }
[a-zA-Z,]+    { yylval.name = talloc_strdup(NULL, yytext); return T_NAME_COMMA; }
\"[a-zA-Z0-9: ]*\" { yylval.name = talloc_strdup(NULL, yytext); return T_QUOTE; }
{newline}     { return T_EOL; }

