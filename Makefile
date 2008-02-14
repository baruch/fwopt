SRC=main.c rules.c parser.tab.c lex.yy.c
OBJ=$(SRC:%.c=%.o)
CFLAGS=-g -Wall -DNUM_CHAINS=255 $(shell pkg-config --cflags glib-2.0)
LDFLAGS=-ltalloc $(shell pkg-config --libs glib-2.0)

fwopt: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

parser.tab.o: parser.tab.c parser.tab.h rules.h parser.h parser.int.h
PARSER_OUT=parser.tab.c parser.tab.h parser.output
${PARSER_OUT}: parser.y
	bison -t -v -d $<

lex.yy.o: lex.yy.c parser.tab.h parser.int.h rules.h
TOKEN_OUT=lex.yy.c
${TOKEN_OUT}: token.l
	flex $<

clean:
	-rm -f $(OBJ) fwopt tests/*.res ${PARSER_OUT} ${TOKEN_OUT}

test: fwopt
	@for f in tests/*.in; do                   \
		echo "Test file $$f";                  \
		./fwopt < $$f > $${f/.in/.res};        \
		diff -u $${f/.in/.out} $${f/.in/.res}; \
	done

.PHONY: clean test

main.o: main.c rules.h
rules.o: rules.c rules.h
