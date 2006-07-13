# $Id$

.SUFFIXES: .c .o .y .l .h
.PHONY: clean index.html

PROG= logfmon
VERSION= 0.9b

OS!= uname
REL!= uname -r

FILEMON= kqueue
SRCS= logfmon.c log.c rules.c xmalloc.c file.c context.c cache.c threads.c \
	getln.c parse.y lex.l action.c event-${FILEMON}.c

OBJS= ${SRCS:S/.c/.o/:S/.y/.o/:S/.l/.o/}

LEX= lex
YACC= yacc -d

CC= cc
#CFLAGS+= -g -ggdb
#CFLAGS+= -DDEBUG
CFLAGS+= -pedantic -Wno-long-long
CFLAGS+= -Wall -W -Wnested-externs -Wformat-security
CFLAGS+= -Wmissing-prototypes -Wstrict-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -DBUILD="\"$(VERSION) ($(FILEMON))\""
CFLAGS+= -DUSE_FGETLN

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

TARFLAGS= 
DISTFILES= *.[chyl] ${PROG}.conf ${PROG}.conf.freebsd \
	GNUmakefile Makefile *.[1-9] README \
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
		tar -zxc \
			-s '/.*/${PROG}-${VERSION}\/\0/' \
			-f ${PROG}-${VERSION}.tar.gz ${DISTFILES}

port:
		find ports/OpenBSD/* -type f -and ! -path '*CVS*' | tar -zxc \
			-s '/ports\/OpenBSD/${PROG}/' \
			-I - \
			-f ${PROG}-${VERSION}-openbsd${REL}-port.tar.gz

depend:
		mkdep ${CFLAGS} ${SRCS}

index.html:
		nroff -mdoc logfmon.conf.5|m2h -u > logfmon.conf.5.html
		nroff -mdoc logfmon.8|m2h -u > logfmon.8.html
		awk ' \
			{ if ($$0 ~ /%%/) {			\
				name = substr($$0, 3);		\
				while ((getline < name) == 1) {	\
					print $$0;		\
				}				\
				close(name);			\
			} else {				\
				print $$0;			\
			} }' index.html.in > index.html
		rm -d logfmon.conf.5.html logfmon.8.html

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
