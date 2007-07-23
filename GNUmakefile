# $Id$

.PHONY: clean

PROG= logfmon
VERSION= 1.0

DEBUG= 1

PREFIX= /usr/local

BIN_OWNER= bin
BIN_GROUP= root

CC= gcc

ifeq ($(shell uname),SunOS)
YACC= yacc
YFLAGS= -d
else
YACC= bison
YFLAGS= -dy
endif

LEX= flex
LFLAGS= -l

INSTALLBIN= install -D -g $(BIN_OWNER) -o $(BIN_GROUP) -m 555
INSTALLMAN= install -D -g $(BIN_OWNER) -o $(BIN_GROUP) -m 444

FILEMON= linux

SRCS= logfmon.c log.c rules.c xmalloc.c xmalloc-debug.c file.c context.c \
      cache.c threads.c getln.c action.c event-$(FILEMON).c y.tab.c lex.yy.c

DEFS= $(shell getconf LFS_CFLAGS) -DBUILD="\"$(VERSION) ($(FILEMON))\""

ifeq ($(shell uname),SunOS)
SRCS+= compat/daemon.c compat/asprintf.c
DEFS+= -DNO_PROGNAME -DNO_ASPRINTF -DNO_DAEMON -DNO_QUEUE_H -DNO_TREE_H
endif
ifeq ($(shell uname),Linux)
SRCS+= compat/strlcpy.c compat/strlcat.c compat/strtonum.c
DEFS+= -D_GNU_SOURCE -DNO_STRLCPY -DNO_STRLCAT -DNO_STRTONUM \
       -DNO_QUEUE_H -DNO_TREE_H
# Required for LLONG_MAX and friends
CFLAGS+= -std=c99
endif

OBJS= $(patsubst %.c,%.o,$(SRCS))
CPPFLAGS+= $(DEFS) -I.
ifdef DEBUG
CFLAGS+= -g -ggdb -DDEBUG
LDFLAGS+= -rdynamic
LIBS+= -ldl
endif
#CFLAGS+= -pedantic -std=c99
CFLAGS+= -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS+= -Wwrite-strings -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+= -Wundef -Wshadow -Wbad-function-cast -Winline -Wcast-align

LIBS_fam= -lfam
LIBS_linux= 
LIBS+= -lm -lpthread $(LIBS_$(FILEMON))

CLEANFILES= $(PROG) y.tab.c lex.yy.c y.tab.h $(OBJS) .depend

all: logfmon

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) -o $@ $+

depend: $(SRCS)
	$(CC) -MM $(SRCS) > .depend

y.tab.c y.tab.h: parse.y
	$(YACC) $(YFLAGS) $<

lex.yy.c: lex.l
	$(LEX) $(LFLAGS) $<

install:
	$(INSTALLBIN) $(PROG) $(PREFIX)/sbin/$(PROG)
	$(INSTALLMAN) $(PROG).8 $(PREFIX)/man/man8/$(PROG).8
	$(INSTALLMAN) $(PROG).conf.5 $(PREFIX)/man/man5/$(PROG).conf.5

clean:
	rm -f $(CLEANFILES)

ifeq ($(wildcard .depend),.depend)
include .depend
endif
