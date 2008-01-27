SRC=main.c rules.c
OBJ=$(SRC:%.c=%.o)
CFLAGS=-g -Wall -Werror -DNUM_CHAINS=255 $(shell pkg-config --cflags glib-2.0)
LDFLAGS=-ltalloc $(shell pkg-config --libs glib-2.0)

fwopt: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	-rm -f $(OBJ) fwopt

.PHONY: clean

main.o: main.c rules.h
rules.o: rules.c rules.h
