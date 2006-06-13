/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicm@users.sourceforge.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <string.h>

#include "logfmon.h"

/* Three different versions of this is pretty excessive, considering the
   Solaris version will work on anything. */

#ifdef __GLIBC__

/* Linux/glibc using getline() */
char *
getln(FILE *fd, int *error)
{
	char	*buf = NULL;
	size_t	 len = 0;
	ssize_t	 res;

	res = getline(&buf, &len, fd);
	if (res == -1) {
		if (feof(fd)) {
			clearerr(fd);
			*error = 0;
			return (NULL);
		}
		*error = 1;
		return (NULL);
	}

	len = strlen(buf);
	if (len >= 1 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	return (buf);
}

#else /* __GLIBC__ */

#ifdef __SunOS__

/* Solaris */
char *
getln(FILE *fd, int *error)
{
	char	*buf;
	int	 ch;
	size_t	 len, used;

	len = 256;
	buf = xmalloc(len);

	used = 0;
	do {
		ch = fgetc(fd);
		if (ch == EOF) {
			if (feof(fd)) {
				clearerr(fd);
				*error = 0;
				return (NULL);
			}
			clearerr(fd);
			*error = 1;
			return (NULL);
		}

		while (used >= len) {
			len *= 2;
			buf = xrealloc(buf, 1, len);
		}
		buf[used++] = ch;
	} while (ch != '\n');

	buf[used - 1] = '\0';
	return (buf);
}

#else /* __SunOS__ */

/* BSD using fgetln() */
char *
getln(FILE *fd, int *error)
{
	char	*buf, *lbuf;
	size_t	 len;

	buf = fgetln(fd, &len);
	if (buf == NULL) {
		if (feof(fd)) {
			clearerr(fd);
			*error = 0;
			return (NULL);
		}
		clearerr(fd);
		*error = 1;
		return (NULL);
	}

	if (buf[len - 1] == '\n')
		len--;

	lbuf = xmalloc(len + 1);
	memcpy(lbuf, buf, len);
	lbuf[len] = '\0';

	return (lbuf);

}

#endif /* __SunOS__ */

#endif /* __GLIBC__ */
