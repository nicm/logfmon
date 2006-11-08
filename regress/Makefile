# $Id$

.PHONY: test-tags test-symlink

all:		test-tags test-symlink

test-tags:	
		${CC} -DREGRESS ${CFLAGS} ${INCDIRS} -I.. -c test-tags.c -o test-tags.o
		${CC} ${LDFLAGS} -L.. -o test-tags ${LIBS} ${OBJS:C/.*/..\/&/} test-tags.o
		./test-tags
		rm test-tags *.o

test-symlink:
		sh -x ./test-symlink.sh >test-symlink.result || exit 1
		diff -uw test-symlink.data test-symlink.result || exit 1
		rm test-symlink.result
