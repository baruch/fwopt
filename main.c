#include "rules.h"
#include "parser.h"
#include <talloc.h>
#include <stdlib.h>
#include <stdio.h>

#define _GNU_SOURCE
#include <getopt.h>

int main(int argc, char * const argv[])
{
	int leak_check = 0;
	int c;

	while (1) {
		int option_index = 0;

		static struct option long_options[] = {
			{"leak-check", 0, 0, 0},
			{"full-leak-check", 0, 0, 0},
		};

		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 0:
			switch (option_index) {
			case 0: leak_check = 1; break;
			case 1: leak_check = 2; break;
			default: fprintf(stderr, "Unknown long option %d\n", option_index); exit(1); break;
			}
			break;
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

	switch (leak_check) {
	case 1: talloc_report(NULL, stderr); break;
	case 2: talloc_report_full(NULL, stderr); break;
	}

	return 0;
}
