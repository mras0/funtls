EXE=shatest

.PHONY: all test
all: $(EXE) tags

test: all
	./$(EXE)

CFLAGS+=-Wall -Wextra -std=c99
SRCFILES=shatest.c sha1.c usha.c

OBJS=$(patsubst %.c,%.o,$(SRCFILES))

CFLAGS+=-MMD # Generate .d files
-include $(OBJS:.o=.d)

$(EXE): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(EXE) *.o *.d tags

tags: $(SRCFILES)
	ctags --c++-kinds=+p --fields=+iaS --extra=+q $(SRCFILES) *.h 2>/dev/null
