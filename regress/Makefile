# $Id$

.PHONY: test-tags

all:		test-tags

test-tags:	
		${CC} -DREGRESS ${CFLAGS} ${INCDIRS} -I.. -c test-tags.c -o test-tags.o
		${CC} ${LDFLAGS} -L.. -o test-tags ${LIBS} ${OBJS:C/.*/..\/&/} test-tags.o
		./test-tags
		rm test-tags *.o
