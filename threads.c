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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logfmon.h"

void *
pclose_thread(void *arg)
{
        pclose((FILE *) arg);
        return (NULL);
}

void *
exec_thread(void *arg)
{
	FILE	*fd;
	char	*cmd, *buf, *lbuf;
	size_t	len;

	if (conf.debug) {
		if (asprintf(&cmd, "%s 2>&1", (char *) arg) == -1)
			fatal("asprintf");
	} else {
		if (asprintf(&cmd, "%s 2>&1 1>/dev/null", (char *) arg) == -1)
			fatal("asprintf");
	}

	fd = popen(cmd, "r");
	if (fd == NULL)
		log_warn((char *) arg);

	lbuf = NULL;
	while ((buf = fgetln(fd, &len)) != NULL) {
		if (buf[len - 1] == '\n')
			buf[len - 1] = '\0';
		else {
			lbuf = xmalloc(len + 1);
			memcpy(lbuf, buf, len);
			lbuf[len] = '\0';
			buf = lbuf;
		}
		log_warnx("%s: %s", (char *) arg, buf);
	}
	free(lbuf);

	pclose(fd);

	free(cmd);

        free(arg);
        return (NULL);
}
