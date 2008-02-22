VERSION=0.1.99git

SRC=main.c rules.c parser.tab.c lex.yy.c icmptype.c tcpflags.c state.c
OBJ=$(SRC:%.c=%.o)
CFLAGS=-O0 -g -Wall -Werror -DNUM_CHAINS=255 $(shell pkg-config --cflags glib-2.0) -DVERSION="\"${VERSION}\""
LDFLAGS=-ltalloc $(shell pkg-config --libs glib-2.0)

fwopt: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

parser.tab.o: parser.tab.c parser.tab.h rules.h parser.h parser.int.h tcpflags.h macros.h Makefile
PARSER_OUT=parser.tab.c parser.tab.h parser.output
${PARSER_OUT}: parser.y Makefile
	bison -t -v -d $<

lex.yy.o: lex.yy.c parser.tab.h parser.int.h rules.h main.h Makefile
TOKEN_OUT=lex.yy.c
${TOKEN_OUT}: token.l Makefile
	flex $<

icmptype.o: icmptype.c parser.h Makefile
ICMP_OUT=icmptype.c
icmptype.c: icmptype.gperf Makefile
	gperf --output-file $@ $<

tags: ${SRC}
	ctags -R ${SRC} *.h

clean:
	-rm -f $(OBJ) fwopt tests/*.res ${PARSER_OUT} ${TOKEN_OUT} ${ICMP_OUT}

test: fwopt
	@for f in tests/*.in; do                       \
		./fwopt < $$f > $${f/.in/.res} 2>&1;   \
		diff -u $${f/.in/.out} $${f/.in/.res}; \
	done

test_linear: fwopt
	@for f in tests/*.in; do                       \
		./fwopt -l < $$f > $${f/.in/.res} 2>&1;   \
		diff -u $${f/.in/.linout} $${f/.in/.res}; \
	done

.PHONY: clean test

main.o: main.c rules.h parser.h main.h Makefile
rules.o: rules.c rules.h state.h tcpflags.h Makefile
tcpflags.o: tcpflags.c tcpflags.h macros.h Makefile
state.o: state.c state.h macros.h Makefile
