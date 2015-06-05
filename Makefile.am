# $Id$

bin_PROGRAMS = logfmon
CLEANFILES = parse.c parse.h

EXTRA_DIST = \
	README \
	examples compat/*.[ch] \
	array.h \
	logfmon.h \
	event-inotify.c \
	event-kqueue.c \
	event-linux.c
dist-hook:
	make clean

CPPFLAGS += \
	-DSYSCONFFILE="\"$(sysconfdir)/logfmon.conf\"" \
	-DSYSCACHEFILE="\"$(localstatedir)/db/logfmon.cache\"" \
	-DSYSPIDFILE="\"$(localstatedir)/run/logfmon.pid\""
CFLAGS += -pthread -D_GNU_SOURCE -std=gnu99 -O2
if IS_DEBUG
CFLAGS += -g
CFLAGS += -Wno-long-long -Wall -W -Wnested-externs -Wformat=2
CFLAGS += -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
CFLAGS += -Wwrite-strings -Wshadow -Wpointer-arith -Wsign-compare
CFLAGS += -Wundef -Wbad-function-cast -Winline -Wcast-align
CFLAGS += -Wdeclaration-after-statement -Wno-pointer-sign
CPPFLAGS += -DDEBUG
endif
YFLAGS += -d

dist_man5_MANS = logfmon.conf.5
dist_man8_MANS = logfmon.8

dist_logfmon_SOURCES = \
	action.c \
	cache.c \
	context.c \
	file.c \
	getln.c \
	log.c \
	logfmon.c \
	rules.c \
	threads.c \
	xmalloc.c \
	\
	parse.y \
	lex.c

nodist_logfmon_SOURCES =
if !NO_KQUEUE
nodist_logfmon_SOURCES += event-kqueue.c
else
if !NO_INOTIFY
nodist_logfmon_SOURCES += event-inotify.c
else
nodist_logfmon_SOURCES += event-linux.c
endif
endif
if NO_ASPRINTF
nodist_logfmon_SOURCES += compat/asprintf.c
endif
if NO_DAEMON
nodist_logfmon_SOURCES += compat/daemon.c
endif
if NO_STRLCAT
nodist_logfmon_SOURCES += compat/strlcat.c
endif
if NO_STRLCPY
nodist_logfmon_SOURCES += compat/strlcpy.c
endif
if NO_STRTONUM
nodist_logfmon_SOURCES += compat/strtonum.c
endif
