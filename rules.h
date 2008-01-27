#ifndef RULES_H
#define RULES_H

typedef struct RuleTree RuleTree;

RuleTree *rules_input(const void *ctx);
void rules_output(RuleTree *rule_tree);
void rules_destroy(RuleTree *rule_tree);

void rules_optimize(RuleTree *rule_tree);

#endif
