EXE=shatest

.PHONY: all test
all: $(EXE) tags

test: all
	./$(EXE)

CFLAGS+=-Wall -Wextra -std=c99
CXXFLAGS+=-std=c++11 -Wall -Wextra -g3
SRCFILES=shatest.cpp sha1.c sha224-256.c

OBJS=$(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SRCFILES))) $(BOOSTOBJS)

CFLAGS+=-MMD # Generate .d files
CXXFLAGS+=-MMD # Generate .d files
-include $(OBJS:.o=.d)

$(EXE): $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(EXE) *.o *.d tags

tags: $(SRCFILES)
	ctags --c++-kinds=+p --fields=+iaS --extra=+q $(SRCFILES) *.h 2>/dev/null
