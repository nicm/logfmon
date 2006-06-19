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

#ifdef USE_GETLINE

/* getline() */
char *
getln(FILE *fd, int *error, int *eol, size_t *read_len)
{
	char	*buf = NULL;
	size_t	 len = 0;
	ssize_t	 res;

	*error = 0;
	*eol = 0;

	res = getline(&buf, &len, fd);
	if (res == -1) {
		if (feof(fd)) {
			clearerr(fd);
			return (NULL);
		}
		*error = 1;
		return (NULL);
	}

	len = res;
	if (len >= 1 && buf[len - 1] == '\n') {
		*eol = 1;
		--len;
		buf[len] = '\0';
	}

	*read_len = len;
	return (buf);
}

#else /* USE_GETLINE */

#ifdef USE_FGETLN

/* fgetln() */
char *
getln(FILE *fd, int *error, int *eol, size_t *read_len)
{
	char	*buf, *lbuf;
	size_t	 len;

	*error = 0;
	*eol = 0;

	buf = fgetln(fd, &len);
	if (buf == NULL) {
		if (feof(fd)) {
			clearerr(fd);
			return (NULL);
		}
		clearerr(fd);
		*error = 1;
		return (NULL);
	}

	if (buf[len - 1] == '\n') {
		*eol = 1;
		len--;
	}

	lbuf = xmalloc(len + 1);
	memcpy(lbuf, buf, len);
	lbuf[len] = '\0';

	*read_len = len;
	return (lbuf);

}

#else /* USE_FGETLN */

char *
getln(FILE *fd, int *error, int *eol, size_t *read_len)
{
	char	*buf;
	int	 ch;
	size_t	 len, used;

	*error = 0;
	*eol = 0;

	len = 256;
	buf = xmalloc(len);

	used = 0;
	do {
		ch = fgetc(fd);
		if (ch == EOF) {
			if (feof(fd)) {
				if (used == 0) {
					clearerr(fd);
					return (NULL);
				}
				/* fake an EOL so that final unterminated
				   lines are returned */
				ch = '\n';
			} else {
				/* errors are always bad, even if there is
				   data sitting here */
				clearerr(fd);
				*error = 1;
				return (NULL);
			}
		}

		while (used >= len) {
			if (len > SIZE_MAX / 2)
				fatalx("len too large");
			len *= 2;
			buf = xrealloc(buf, 1, len);
		}
		buf[used++] = ch;
	} while (ch != '\n');

	buf[used - 1] = '\0';
	*eol = 1;

	*read_len = used - 1;
	return (buf);
}

#endif /* !USE_FGETLN */

#endif /* USE_GETLINE */
