#!/bin/sh

set -x

if [ "$1" == "clean" ]; then
    rm -f logfmon *.o y.tab.c lex.yy.c y.tab.h *~
    exit
fi

CC=gcc
CFLAGS="-I- -I. -I/usr/local/include $CFLAGS \
        -Wall -W -Wmissing-prototypes -Wmissing-declarations \
        -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare"
LDFLAGS="-L/usr/local/lib"
LIBS="-lm -lpthread"

YACC="bison"
YACCFLAGS="-d -y"

LEX="lex"
LEXFLAGS=

[ ! -f y.tab.c ] && $YACC $YACCFLAGS parse.y
[ ! -f lex.yy.c ] && $LEX $LEXFLAGS lex.l

SRCS=`echo *.c`
for i in ${SRCS/event.c/}; do
    [ ! -f ${i%.c}.o ] && $CC $CFLAGS -c $i -o ${i%.c}.o
done

$CC $LDFLAGS -o logfmon $LIBS *.o
