#!/usr/bin/env bash

set -x

if [ "$1" == "clean" ]; then
    rm -f logfmon *.o y.tab.c lex.yy.c y.tab.h *~
    exit
fi

CFLAGS="-I- -I. -I/usr/local/include $CFLAGS \
        -Wall -W -Wmissing-prototypes -Wmissing-declarations \
        -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare"

yacc -d parse.y
lex lex.l

for i in *.c; do
    if [ "$i" != "event.c" ]; then
	if [ ! -f ${i%.c}.o ]; then 
	    gcc $CFLAGS -c $i -o ${i%.c}.o
	fi
    fi
done

gcc -L/usr/local/lib -o logfmon -lm -lpthread *.o
