# $Id$

.PHONY: clean

PROG = logfmon
VERSION = 0.9

## Installation parameters

PREFIX = /usr/local

BIN_OWNER = bin
BIN_GROUP = root

### Programs

CC = gcc

ifeq ($(shell uname),SunOS)
YACC = yacc
YFLAGS = -d
else
YACC = bison
YFLAGS = -d -y
endif

LEX = flex
LFLAGS = -l

INSTALLBIN = install -D -g $(BIN_OWNER) -o $(BIN_GROUP) -m 555
INSTALLMAN = install -D -g $(BIN_OWNER) -o $(BIN_GROUP) -m 444

### Compilation

FILEMON = linux

SRCS = logfmon.c log.c rules.c xmalloc.c file.c context.c cache.c threads.c \
       getln.c action.c event-$(FILEMON).c y.tab.c lex.yy.c

DEFS = $(shell getconf LFS_CFLAGS) -DBUILD="\"$(VERSION) ($(FILEMON))\""

ifeq ($(shell uname),SunOS)
SRCS += daemon.c asprintf.c
DEFS += -DNO_PROGNAME -DNO_ASPRINTF -DNO_DAEMON -DNO_QUEUE_H
endif
ifeq ($(shell uname),Linux)
SRCS += strlcpy.c
DEFS += -D_GNU_SOURCE -DNO_STRLCPY -DUSE_GETLINE
endif

OBJS = $(patsubst %.c,%.o,$(SRCS))
CPPFLAGS = $(DEFS) -I.
CFLAGS = -pedantic -Wno-long-long -Wall -W -Wnested-externs		\
	 -Wformat-security -Wmissing-prototypes -Wstrict-prototypes	\
	 -Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual	\
	 -Wsign-compare 

LIBS_fam = -lfam
LIBS_linux = 
LIBS = -lm -lpthread $(LIBS_$(FILEMON))

CLEANFILES = $(PROG) y.tab.c lex.yy.c y.tab.h $(OBJS) depends.mk

all: logfmon

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) -o $@ $+

depends.mk: $(SRCS)
	$(CC) -MM $(SRCS) > $@

y.tab.c y.tab.h: parse.y
	$(YACC) $(YFLAGS) $<

lex.yy.c: lex.l
	$(LEX) $(LFLAGS) $<

install:
	$(INSTALLBIN) $(PROG) $(PREFIX)/sbin/$(PROG)
	$(INSTALLMAN) $(PROG).8 $(PREFIX)/man/man8/$(PROG).8
	$(INSTALLMAN) $(PROG).conf.5 $(PREFIX)/man/man5/$(PROG).conf.5

clean:
	-rm -f $(CLEANFILES)

#include depends.mk
