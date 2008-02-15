#include "rules.h"
#include "parser.h"
#include <talloc.h>
#include <stdlib.h>
#include <stdio.h>

#define _GNU_SOURCE
#include <getopt.h>

static int leak_check = 0;

int main(int argc, char * const argv[])
{
	while (1) {
		static const struct option long_options[] = {
			{"leak-check", 0, &leak_check, 1},
			{"full-leak-check", 0, &leak_check, 2},
			{0, 0, 0, 0}
		};

		int c = getopt_long(argc, argv, "", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 0: break; /* Options with flags reach here */
		default:
			fprintf(stderr, "unknown option %d\n", c);
			exit(1);
			break;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Unknown extra arguments\n");
		exit(1);
	}

	switch (leak_check)
	{
	case 1: talloc_enable_leak_report(); break;
	case 2: talloc_enable_leak_report_full(); break;
	}

	void *ctx = talloc_init("ROOT");
	RuleTree *rule_tree = rules_init(ctx);

	int res = yyparse(rule_tree);
	yylex_destroy();
	if (res != 0) {
		fprintf(stderr, "Failed parsing input\n");
		return 1;
	}

	rules_optimize(rule_tree);
	rules_output(rule_tree);

	talloc_free(ctx);

	return 0;
}
