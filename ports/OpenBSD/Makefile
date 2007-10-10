# $OpenBSD$

COMMENT=	monitor and process log files based on regexps

DISTNAME=	logfmon-1.0
CATEGORIES=	sysutils

HOMEPAGE=	http://logfmon.sourceforge.net/

MAINTAINER=	Nicholas Marriott <nicm@users.sourceforge.net>

# BSD
PERMIT_PACKAGE_CDROM=	Yes
PERMIT_PACKAGE_FTP=	Yes
PERMIT_DISTFILES_CDROM=	Yes
PERMIT_DISTFILES_FTP=	Yes
WANTLIB=	c m pthread

MASTER_SITES=	${MASTER_SITE_SOURCEFORGE:=logfmon/}

NO_REGRESS=	Yes

post-install:
	${INSTALL_DATA_DIR} ${PREFIX}/share/doc/logfmon
	${INSTALL_DATA} ${WRKSRC}/README ${PREFIX}/share/doc/logfmon
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/logfmon
	${INSTALL_DATA} ${WRKSRC}/logfmon.conf \
		${PREFIX}/share/examples/logfmon/example-logfmon.conf
	${INSTALL_DATA} ${WRKSRC}/logfmon.conf.freebsd \
		${PREFIX}/share/examples/logfmon/freebsd_example-logfmon.conf

.include <bsd.port.mk>
