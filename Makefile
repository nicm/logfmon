# $Id$

.SUFFIXES: .c .o .y .l .h .8 .8.gz .5 .5.gz

VERSION= 0.6

OS!= uname

PROG= logfmon
SRCS= logfmon.c log.c rules.c xmalloc.c save.c file.c context.c \
      messages.c tags.c cache.c threads.c parse.y lex.l

.if ${OS} == "Linux"
SRCS+= event-linux.c
.else
SRCS+= event.c
.endif

OBJS= ${SRCS:S/.c/.o/:S/.y/.o/:S/.l/.o/}

LEX= lex
LEXFLAGS=

YACC= yacc
YACCFLAGS= -d

CC= cc
CFLAGS+= -Wall -W
CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare

MKDEP= mkdep
MKDEPFLAGS= 

RM= rm
RMFLAGS= -f

TAR= tar
TARFLAGS= -zxc -s '/.*/${PROG}-${VERSION}\/\0/'

GZIP= gzip
GZIPFLAGS= -9

CAT= cat
MV= mv

SED= sed

DESTDIR?= /usr/local

INSTALL= install
INSTALLBIN= -g bin -o root -m 555
INSTALLMAN= -g bin -o root -m 444

INCDIRS= -I- -I. -I/usr/local/include

LDFLAGS+= -L/usr/local/lib

LIBS= -lm

.if ${OS} == "FreeBSD"
LDFLAGS+= -pthread
.else
LIBS+= -lpthread
.endif

DISTFILES= *.[chyl] ${PROG}.conf ${PROG}.conf.freebsd Makefile *.[1-9] INSTALL make-linux.sh rc.d/logfmon.sh.freebsd.5.3 rc.d/logfmon.sh.freebsd.4.10

PORT?=ports/OpenBSD-3.6

.c.o:
		${CC} ${CFLAGS} ${INCDIRS} -c ${.IMPSRC} -o ${.TARGET}

.l.o:
		${LEX} ${LEXFLAGS} ${.IMPSRC}
		${CC} ${CFLAGS} ${INCDIRS} -c lex.yy.c -o ${.TARGET}

.y.o:
		${YACC} ${YACCFLAGS} ${.IMPSRC}
		${CC} ${CFLAGS} ${INCDIRS} -c y.tab.c -o ${.TARGET}

.5.5.gz .8.8.gz:
		${CAT} ${.IMPSRC} | ${GZIP} ${GZIPFLAGS} - > ${.TARGET}

all:		${PROG} ${PROG}.8.gz ${PROG}.conf.5.gz

${PROG}:	${OBJS}
		${CC} ${LDFLAGS} -o ${PROG} ${LIBS} ${OBJS}

dist:		clean
		${TAR} ${TARFLAGS} -f ${PROG}-${VERSION}.tar.gz ${DISTFILES}

depend:
		${MKDEP} ${MKDEPFLAGS} ${CFLAGS} ${SRCS}

install:	all
		${INSTALL} ${INSTALLBIN} ${PROG} ${DESTDIR}/sbin/${PROG}
		${INSTALL} ${INSTALLMAN} ${PROG}.8.gz ${DESTDIR}/man/man8/${PROG}.8.gz
		${INSTALL} ${INSTALLMAN} ${PROG}.conf.5.gz ${DESTDIR}/man/man5/${PROG}.conf.5.gz

update-ports:
		md5 releases/${PROG}-${VERSION}.tar.gz > ${PORT}/distinfo.new
		sha1 releases/${PROG}-${VERSION}.tar.gz >> ${PORT}/distinfo.new
		rmd160 releases/${PROG}-${VERSION}.tar.gz >> ${PORT}/distinfo.new
		${CAT} ${PORT}/distinfo.new | ${SED} -e 's/releases\///' > ${PORT}/distinfo
		${RM} ${RMFLAGS} ${PORT}/distinfo.new
		${CAT} ${PORT}/Makefile | ${SED} -e 's/${PROG}-[0-9]\.[0-9]/${PROG}-${VERSION}/' > ${PORT}/Makefile.new
		${MV} ${PORT}/Makefile.new ${PORT}/Makefile

uninstall:
		${RM} ${RMFLAGS} ${DESTDIR}/sbin/${PROG}
		${RM} ${RMFLAGS} ${DESTDIR}/man/man8/${PROG}.8.gz
		${RM} ${RMFLAGS} ${DESTDIR}/man/man5/${PROG}.conf.5.gz

clean:
		${RM} ${RMFLAGS} ${PROG} *.o y.tab.c lex.yy.c y.tab.h .depend ${PROG}-*.tar.gz *.[1-9].gz *~
