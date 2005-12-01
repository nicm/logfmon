#!/bin/sh

if [ "$1" == "clean" ]; then
    rm -f logfmon *.o y.tab.c lex.yy.c y.tab.h *~
    exit
fi

if [ -z "$CC" ]; then
    CC="gcc"
    
    # Some versions of GCC 4 appear to be weird. Use 3 if possible.
    if which gcc-3.3 1>/dev/null 2>&1; then
	CC="gcc-3.3"
    fi
    if which gcc-3.4 1>/dev/null 2>&1; then
	CC="gcc-3.4"
    fi
fi

CFLAGS="-I- -I. -I/usr/local/include $CFLAGS \
	-D_GNU_SOURCE -D_LARGEFILE_SOURCE \
        -Wall -W -Wmissing-prototypes -Wmissing-declarations \
        -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare"
LDFLAGS="-L/usr/local/lib $LDFLAGS"
LIBS="-lm -lpthread"

[ -z "$YACC" ] && YACC="bison -d -y"
[ -z "$LEX" ] && LEX="lex"

[ ! -f y.tab.c ] && $YACC parse.y
[ ! -f lex.yy.c ] && $LEX lex.l

set -x
SRCS=`echo *.c| sed -e s'/event.c//'`
for i in $SRCS; do
    [ ! -f ${i%.c}.o ] && $CC $CFLAGS -c $i -o ${i%.c}.o
done

$CC $LDFLAGS -o logfmon $LIBS *.o
