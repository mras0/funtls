EXE=asn1

.PHONY: all test
all: $(EXE) tags

test: all
	./$(EXE)

############# BOOST ASIO ####################################
BOOST=/home/mras/build/boost_1_57_0/
CXXFLAGS+=-I$(BOOST) -DBOOST_ALL_NO_LIB -pthread
#############################################################

VPATH=../hash/
CXXFLAGS+=-I../

CXXFLAGS+=-std=c++11 -Wall -Wextra -g3
CFLAGS+=-std=c99 -Wall -Wextra -g3
SRCFILES=main.cpp sha1.c sha224-256.c
OBJS=$(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SRCFILES))) $(BOOSTOBJS)

CFLAGS+=-MMD # Generate .d files
CXXFLAGS+=-MMD # Generate .d files
-include $(OBJS:.o=.d)

ifdef PROFILE
	CFLAGS+=-pg
	CXXFLAGS+=-pg
endif

ifdef OPTIMIZED
	CFLAGS+=-O3 -DNDEBUG
	CXXFLAGS+=-O3 -DNDEBUG
endif

ifndef NO_SANITIZE
ifndef OPTIMIZED
ifndef PROFILE
	CFLAGS+=-fsanitize=address
	CXXFLAGS+=-fsanitize=address
endif
endif
endif

$(EXE): $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(EXE) *.o *.d tags

tags: $(SRCFILES)
	ctags --c++-kinds=+p --fields=+iaS --extra=+q $(SRCFILES) *.h 2>/dev/null
