#include "rules.h"
#include "parser.h"
#include <talloc.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
	void *ctx = talloc_init("ROOT");
	RuleTree *rule_tree = rules_init(ctx);

	int res = yyparse(rule_tree);
	if (res != 0) {
		fprintf(stderr, "Failed parsing input\n");
		return 1;
	}

	rules_optimize(rule_tree);
	rules_output(rule_tree);

	talloc_free(ctx);
	return 0;
}
