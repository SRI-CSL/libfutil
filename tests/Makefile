ifndef PROJECT_NAME
$(error Run this make from the root, aka one level up)
endif

ifeq ($(PROJECT_NAME),libfutil)

# Which OS is this? Can be overriden by setting it first
# eg to compile Windows edition on another platform use: $ make OS_NAME=Windows
ifeq ($(OS_NAME),)
override OS_NAME=$(shell uname -s)
endif

ifeq ($(OS_NAME),)
$(error "No OS Kernelname? ('uname -s' failed)")
endif

# Check for supported platforms
ifeq ($(OS_NAME),Linux)
else
ifeq ($(OS_NAME),Windows)
else
ifeq ($(OS_NAME),Darwin)
else
$(error "Unsupported platform: $(OS_NAME), possible: Linux, Windows, Darwin")
endif
endif
endif

ifeq ($(OS_RELEASE),)
OS_RELEASE=$(shell uname -r)
endif

ifeq ($(OS_PROC),)
OS_PROC=$(shell uname -m)
else
CFLAGS+=-march=$(OS_PROC)
endif

ifeq ($(OS_BITS),)
	ifeq ($(OS_PROC),x86_64)
		OS_BITS=64
	else
		OS_BITS=32
	endif
endif

# Default to no extension
EXT:=

# Figure out the HOSTCC
ifeq ($(HOSTCC),)
HOSTCC := $(CC)
endif

ifeq ($(shell echo $(CFLAGS) | grep -c "DEBUG"),0)
	CFLAGS += -O3 -fno-trapping-math -ftracer -ffast-math -DNDEBUG
	CFLAG S+= -fstack-protector -Wstack-protector -fstack-protector-all
ifeq ($(OS_BITS),64)
	CFLAGS += -fprefetch-loop-arrays
endif
else
	CFLAGS += -g3 -O0
endif

# Standard Warnings
CFLAGS	+=	-Wall
CFLAGS	+=	-Werror

# Extended warnings
CFLAGS	+=	-Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings
CFLAGS	+=	-Waggregate-return -Wstrict-prototypes -Wmissing-prototypes
CFLAGS	+=	-Wmissing-declarations -Wredundant-decls -Wnested-externs
CFLAGS	+=	-Winline -Wbad-function-cast -fstrict-aliasing
CFLAGS	+=	-fno-common -Wno-packed -Wswitch-default
ifneq ($(OS_NAME),Windows)
CFLAGS	+=	-Wformat=2 -Wformat-security
endif
CFLAGS	+=	-Wmissing-format-attribute
CFLAGS	+=	-D_REENTRANT -D_THREAD_SAFE -pipe -Wunused -Winit-self
CFLAGS	+=	-Wextra -Wno-long-long -Wmissing-include-dirs
CFLAGS	+=	-Wno-variadic-macros
CFLAGS	+=	-ansi -std=c99
CFLAGS	+=	-pedantic

# Enable GNU features (needed for our use of pthreads etc)
CFLAGS  +=	-D_GNU_SOURCE

# Linux
ifeq ($(OS_NAME),Linux)
CFLAGS	+= -D_LINUX
LDLIBS	+= -lpthread -lrt
MDGW_LIBS += -l rt
# We need librt for clock_gettime()
endif

# Darwin
ifeq ($(OS_NAME),Darwin)
CFLAGS  += -D_DARWIN
endif

# Try to get the Compiler version (assume gcc first)
CC_VERSION=$(shell $(CC) -v 2>&1 | grep "gcc version" | cut -f3 -d' ')
CC_TYPE=gcc

ifeq ($(CC_VERSION),)
ifeq ($(OS_NAME),Darwin)
# OSX 10.6 Snow Leopard
# gcc version 4.2.1 (Apple Inc. build 5666) (dot 3)
#
# OSX 10.7 Lion (Xcode 3.1)
# Apple clang version 3.1 (tags/Apple/clang-318.0.58) (based on LLVM 3.1svn)
#
# OSX 10.8 Mountain Lion (Xcode 4.2)
# Apple LLVM version 4.2 (clang-425.0.28) (based on LLVM 3.2svn)
#
# OSX 10.9 Mavericks (XCode 5)
# Apple LLVM version 5.0 (clang-500.1.69) (based on LLVM 3.3svn)
CC_VERSION=$(shell $(CC) -v 2>&1 | head -n1 | cut -f4 -d' ')
CC_TYPE=clang
# Don't report unused arguments
CFLAGS+=-Qunused-arguments
endif
endif

ifeq ($(CC_VERSION),)
ifneq ($(OS_NAME),Windows)
$(error "We don't have a (working) compiler? ${CC}")
endif
endif

ifeq ($(OS_BITS),32)
CFLAGS += -D_32BIT
CFLAGS+=-m32
LDFLAGS+=-m32
else
ifeq ($(OS_BITS),64)
CFLAGS += -D_64BIT
CFLAGS+=-m64
LDLAGS+=-m64
else
$(error Unknown number of bits: $(OS_BITS))
endif
endif

else

# Location of libfutil
LIBFUTIL:=../
OBJFUTIL:=$(LIBFUTIL)src/
CFLAGS  += -I$(LIBFUTIL)include/

endif # PROJECT_NAME != libfutil

# Prettifiers
LINK	= @echo "* Linking $@"; $(CC) $(CFLAGS) $(LDFLAGS)

# Dependencies we care about when they change
DEPS		=	Makefile

# Test addons
OBJS		+=	test.o				\
			test_buf.o			\
			test_misc.o			\
							\
			$(OBJFUTIL)buf.o		\
			$(OBJFUTIL)misc.o

ifeq ($(shell echo $(CFLAGS) | grep -c "DEBUG_STACKDUMPS"),1)
OBJS		+=	$(OBJFUTIL)stack.o
endif

export CFLAGS
export LDFLAGS

# The final targets we want to produce
all: $(DEPS) runtests
	@echo "* libfutil done"

# Include all the dependencies
-include $(OBJS:.o=.d)

depend: clean
	@echo "* Making dependencies"
	@$(MAKE) -s $(OBJS)
	@echo "* Making dependencies - done"

tags: $(SRCS)
	@echo "* Generating tags"
	@(TOTAG=`cat *.d | sed -e 's/[:\\]/ /g' -e 's/ /\n/g' | sort | uniq | tr '\n' ' ')` && \
	ctags -x >tags $${TOTAG} && \
	ctags -e >TAGS $${TOTAG} )
	@echo "* Generating tags - done"

%.o: %.c $(DEPS)
	@echo "* Compiling $@";
	@$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) $*.c > $*.d
	@cp -f $*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

runtests: test .FORCE
	@./test

test$(EXT): $(DEPS) $(OBJS)
	$(LINK) -o $@ $(OBJS) $(LDLIBS)

# Mark targets as phony
.PHONY: all runtests test

# Forced targets
.FORCE: 

