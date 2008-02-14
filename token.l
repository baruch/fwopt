%{
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "parser.int.h"
#include "parser.tab.h"
%}

%option noyywrap

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
"-j"          { return T_OPT_JUMP; }
"-i"          { return T_OPT_IFACE_IN; }
"-s"          { return T_OPT_SRC_IP; }
"--src"       { return T_OPT_SRC_IP; }
"--dport"     { return T_OPT_DST_PORT; }
"-d"          { return T_OPT_DST_IP; }
"--dst"       { return T_OPT_DST_IP; }

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
{word}        { yylval.name = strdup(yytext); return T_NAME; }
{newline}     { return T_EOL; }

