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

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "logfmon.h"

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
				clearerr(fd);

				goto return_all;
			} else {
				/* save errno */
				*error = errno;

				clearerr(fd);

				if (errno == EINTR || errno == EAGAIN)
					goto return_all;

				xfree(buf);
				return (NULL);
			}
		}

		ENSURE_SIZE(buf, len, used + 1);
		buf[used++] = ch;
	} while (ch != '\n');

	*eol = 1;

	/* replace the \n */
	buf[used - 1] = '\0';
	*read_len = used - 1;

	return (buf);

return_all:
	if (used == 0) {
		xfree(buf);
		return (NULL);
	}

	/* return what we have and leave it to the caller's buffering */
	ENSURE_SIZE(buf, len, used);
	buf[used] = '\0';
	*read_len = used;
	return (buf);
}
