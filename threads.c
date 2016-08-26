/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicholas.marriott@gmail.com>
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logfmon.h"

void *
pclose_thread(void *arg)
{
	ENTER_THREAD();

	pclose((FILE *) arg);

	LEAVE_THREAD();
	return (NULL);
}

void *
exec_thread(void *arg)
{
	FILE	*fd;
	char	*cmd, *line;
	int	 error, eol;
	size_t	 len;

	ENTER_THREAD();

	if (conf.debug) {
		xasprintf(&cmd, "%s 2>&1", (char *) arg);
	} else
		xasprintf(&cmd, "%s 2>&1 1>/dev/null", (char *) arg);

	fd = popen(cmd, "r");
	if (fd == NULL)
		log_warn("%s", (char *) arg);

	while ((line = getln(fd, &error, &eol, &len)) != NULL) {
		if (!eol)
			log_warnx("%s: partial read from pipe", (char *) arg);

		log_warnx("%s: %s", (char *) arg, line);
		xfree(line);
	}

	pclose(fd);

	xfree(cmd);

	xfree(arg);
	LEAVE_THREAD();
	return (NULL);
}

/* ARGSUSED */
void *
save_thread(void *arg)
{
	struct msg	*save;
	struct file	*file;
	FILE		*fd;
	int		 flag;
	unsigned int	 n, t;

	arg = NULL; /* stop gcc complaining */

	for (;;) {
		log_debug("sleeping for %d seconds", conf.mail_time);

		t = conf.mail_time;
		while (t > 0)
			t = sleep(t);
		if (quit)
			break;
		if (conf.mail_cmd == NULL || *conf.mail_cmd == '\0')
			continue;

		LOCK_MUTEX(conf.files_mutex);
		flag = 0;
		TAILQ_FOREACH(file, &conf.files, entry) {
			LOCK_MUTEX(file->saves_mutex);
			if (!TAILQ_EMPTY(&file->saves)) {
				UNLOCK_MUTEX(file->saves_mutex);
				flag = 1;
				break;
			}
			UNLOCK_MUTEX(file->saves_mutex);
		}
		UNLOCK_MUTEX(conf.files_mutex);
		if (!flag)
			continue;

		log_debug("processing saved messages. executing: %s",
		    conf.mail_cmd);

		fd = popen(conf.mail_cmd, "w");
		if (fd == NULL) {
			log_warn("%s", conf.mail_cmd);
			continue;
		}

		LOCK_MUTEX(conf.files_mutex);
		n = 0;
		TAILQ_FOREACH(file, &conf.files, entry) {
			LOCK_MUTEX(file->saves_mutex);

			if (TAILQ_EMPTY(&file->saves)) {
				UNLOCK_MUTEX(file->saves_mutex);
				continue;
			}

			if (fprintf(fd, "Unmatched messages for file %s, "
			    "tag %s:\n\n", file->path, file->tag.name) == -1) {
				UNLOCK_MUTEX(file->saves_mutex);
				break;
			}

			TAILQ_FOREACH(save, &file->saves, entry) {
				if (fwrite(save->str, strlen(save->str), 1,
				    fd) != 1) {
					log_warn("fwrite");
					break;
				}
				if (fputc('\n', fd) == EOF) {
					log_warn("fputc");
					break;
				}
				n++;
			}
			if (fputc('\n', fd) == EOF)
				log_warn("fputc");

			UNLOCK_MUTEX(file->saves_mutex);
			reset_file(file);

		}
		UNLOCK_MUTEX(conf.files_mutex);

		pclose(fd);

		log_debug("processed %u unmatched messages", n);
	}

	return (NULL);
}
