#include "rules.h"
#include "parser.h"
#include <talloc.h>
#include <stdlib.h>
#include <stdio.h>

#define _GNU_SOURCE
#include <getopt.h>

static int leak_check = 0;

static void parse_args(int argc, char *const argv[])
{
	int version = 0;

	const struct option long_options[] = {
		{"leak-check", 0, &leak_check, 1},
		{"full-leak-check", 0, &leak_check, 2},
		{"version", 0, &version, 1},
		{0, 0, 0, 0}
	};

	while (1) {

		int c = getopt_long(argc, argv, "V", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 0: break; /* Options with flags reach here */
		case 'V': version = 1; break;
		default:
			fprintf(stderr, "unknown option %d\n", c);
			exit(1);
			break;
		}
	}

	if (version) {
		printf("fwopt " VERSION " -- iptables rules optimizer\n");
		exit(2);
	}

	if (optind < argc) {
		fprintf(stderr, "Unknown extra arguments\n");
		exit(1);
	}
}

int main(int argc, char * const argv[])
{
	parse_args(argc, argv);

	switch (leak_check)
	{
	case 1: talloc_enable_leak_report(); break;
	case 2: talloc_enable_leak_report_full(); break;
	}

	void *ctx = talloc_init("ROOT");
	RuleTree *rule_tree = rules_init(ctx);

	int main_ret = 0;
	int res = yyparse(rule_tree);
	yylex_destroy();
	if (res != 0) {
		fprintf(stderr, "Failed parsing input\n");
		main_ret = 1;
	} else {
		rules_optimize(rule_tree);
		rules_output(rule_tree);
	}

	talloc_free(ctx);
	return main_ret;
}
