#ifndef PARSER_H
#define PARSER_H

#include "rules.h"

int yyparse(RuleTree *tree);
int yylex_destroy(void);

#endif
