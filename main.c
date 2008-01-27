#include "rules.h"
#include <stdlib.h>

int main()
{
	RuleTree *rule_tree = rules_input(NULL);

	rules_optimize(rule_tree);
	rules_output(rule_tree);

	rules_destroy(rule_tree);
	return 0;
}
