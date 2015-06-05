# $Id$

AC_INIT(logfmon, 1.3)

AC_CONFIG_AUX_DIR(etc)
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CANONICAL_HOST

: ${CFLAGS=""}

CPPFLAGS="$CPPFLAGS -I/usr/local/include"
LDFLAGS="$LDFLAGS -L/usr/local/lib"

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_YACC

test "$sysconfdir" = '${prefix}/etc' && sysconfdir=/etc
test "$localstatedir" = '${prefix}/var' && localstatedir=/var

AC_ARG_ENABLE(
	debug,
	AC_HELP_STRING(--enable-debug, create a debug build),
	found_debug=$enable_debug
)
AM_CONDITIONAL(IS_DEBUG, test "x$found_debug" = xyes)

AC_ARG_ENABLE(
	static,
	AC_HELP_STRING(--enable-static, create a static build),
	found_static=$enable_static
)
if test "x$found_static" = xyes; then
	LDFLAGS="$LDFLAGS -static"
fi

AC_CHECK_HEADERS(
	[ \
		sys/queue.h \
		sys/tree.h \
	]
)

AC_CHECK_FUNC(kqueue, found_kqueue=yes, found_kqueue=no)
AM_CONDITIONAL(NO_KQUEUE, [test "x$found_kqueue" = xno])
AC_CHECK_FUNC(inotify_init, found_inotify=yes, found_inotify=no)
AM_CONDITIONAL(NO_INOTIFY, [test "x$found_inotify" = xno])

AC_CHECK_FUNC(asprintf, found_asprintf=yes, found_asprintf=no)
if test "x$found_asprintf" = xyes; then
	AC_DEFINE(HAVE_ASPRINTF)
fi
AM_CONDITIONAL(NO_ASPRINTF, [test "x$found_asprintf" = xno])

AC_CHECK_FUNC(daemon, found_daemon=yes, found_daemon=no)
if test "x$found_daemon" = xyes; then
	AC_DEFINE(HAVE_DAEMON)
fi
AM_CONDITIONAL(NO_DAEMON, [test "x$found_daemon" = xno])

AC_CHECK_FUNC(strlcpy, found_strlcpy=yes, found_strlcpy=no)
if test "x$found_strlcpy" = xyes; then
	AC_DEFINE(HAVE_STRLCPY)
fi
AM_CONDITIONAL(NO_STRLCPY, [test "x$found_strlcpy" = xno])

AC_CHECK_FUNC(strlcat, found_strlcat=yes, found_strlcat=no)
if test "x$found_strlcat" = xyes; then
	AC_DEFINE(HAVE_STRLCAT)
fi
AM_CONDITIONAL(NO_STRLCAT, [test "x$found_strlcat" = xno])

AC_CHECK_FUNC(strtonum, found_strtonum=yes, found_strtonum=no)
if test "x$found_strtonum" = xyes; then
	AC_DEFINE(HAVE_STRTONUM)
fi
AM_CONDITIONAL(NO_STRTONUM, [test "x$found_strtonum" = xno])

AC_MSG_CHECKING(for __progname)
AC_LINK_IFELSE([AC_LANG_SOURCE(
	[
		#include <stdio.h>
		#include <stdlib.h>
		extern char *__progname;
		int main(void) {
			const char *cp = __progname;
			printf("%s\n", cp);
			exit(0);
		}
	])],
	[AC_DEFINE(HAVE___PROGNAME) AC_MSG_RESULT(yes)],
	AC_MSG_RESULT(no)
)

AC_OUTPUT(Makefile)
