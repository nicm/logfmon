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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logfmon.h"

pthread_mutex_t	save_mutex;

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

                if (pthread_mutex_lock(&save_mutex) != 0)
                        fatalx("pthread_mutex_lock failed");

		flag = 0;
		TAILQ_FOREACH(file, &conf.files, entry) {
			if (!TAILQ_EMPTY(&file->saves)) {
				flag = 1;
				break;
			}
                }
		if (!flag)
			goto done;

		log_debug("processing saved messages. executing: %s",
		    conf.mail_cmd);

                fd = popen(conf.mail_cmd, "w");
                if (fd == NULL) {
                        log_warn(conf.mail_cmd);
			goto done;
                }

                n = 0;
		TAILQ_FOREACH(file, &conf.files, entry) {
                        if (TAILQ_EMPTY(&file->saves))
                                continue;

                        if (fprintf(fd, "Unmatched messages for file %s, "
			    "tag %s:\n\n", file->path, file->tag.name) == -1)
                                break;

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

                        reset_file(file);
                }

                pclose(fd);

                log_debug("processed %d unmatched messages", n);

done:
                if (pthread_mutex_unlock(&save_mutex) != 0)
                        fatalx("pthread_mutex_lock failed");
        }

        return (NULL);
}
