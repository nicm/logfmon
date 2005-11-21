# $Id$

.SUFFIXES: .c .o .y .l .h .8 .8.gz .5 .5.gz

PROG= logfmon
VERSION= 0.8

OS!= uname

SRCS= logfmon.c log.c rules.c xmalloc.c file.c context.c cache.c threads.c \
	parse.y lex.l action.c
.if ${OS} == "Linux"
SRCS+= event-linux.c
.else
SRCS+= event.c
.endif

OBJS= ${SRCS:S/.c/.o/:S/.y/.o/:S/.l/.o/}

LEX= lex
YACC= yacc -d

CC= cc
CFLAGS+= -g
#CFLAGS+= -DDEBUG
CFLAGS+= -pedantic -Wno-long-long
CFLAGS+= -Wall -W -Wnested-externs
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare

PREFIX?= /usr/local
INSTALLBIN= install -g bin -o root -m 555
INSTALLMAN= install -g bin -o root -m 444

INCDIRS= -I- -I. -I/usr/local/include
LDFLAGS+= -L/usr/local/lib
LIBS= -lm
.if ${OS} == "OpenBSD" || ${OS} == "FreeBSD"
LDFLAGS+= -pthread
.else
LIBS+= -lpthread
.endif

TARFLAGS= -zxc -s '/.*/${PROG}-${VERSION}\/\0/'
DISTFILES= *.[chyl] ${PROG}.conf ${PROG}.conf.freebsd Makefile *.[1-9] \
	README make-linux.sh \
	rc.d/logfmon.sh.freebsd.5.3 rc.d/logfmon.sh.freebsd.4.10

CLEANFILES= ${PROG} *.o y.tab.c lex.yy.c y.tab.h .depend ${PROG}-*.tar.gz \
	*.[1-9].gz *~ *.ln ${PROG}.core

.c.o:
		${CC} ${CFLAGS} ${INCDIRS} -c ${.IMPSRC} -o ${.TARGET}

.l.o:
		${LEX} ${.IMPSRC}
		${CC} ${CFLAGS} ${INCDIRS} -c lex.yy.c -o ${.TARGET}

.y.o:
		${YACC} ${.IMPSRC}
		${CC} ${CFLAGS} ${INCDIRS} -c y.tab.c -o ${.TARGET}

all:		${PROG}

${PROG}:	${OBJS}
		${CC} ${LDFLAGS} -o ${PROG} ${LIBS} ${OBJS}

dist:		clean
		tar ${TARFLAGS} -f ${PROG}-${VERSION}.tar.gz ${DISTFILES}

depend:
		mkdep ${CFLAGS} ${SRCS}

install:	all
		${INSTALLBIN} ${PROG} ${PREFIX}/sbin/${PROG}
		${INSTALLMAN} ${PROG}.8 ${PREFIX}/man/man8/
		${INSTALLMAN} ${PROG}.conf.5 ${PREFIX}/man/man5/

uninstall:
		rm -f ${PREFIX}/sbin/${PROG}
		rm -f ${PREFIX}/man/man8/${PROG}.8
		rm -f ${PREFIX}/man/man5/${PROG}.conf.5

clean:
		rm -f ${CLEANFILES}
