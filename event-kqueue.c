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
#include <sys/event.h>
#include <sys/time.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logfmon.h"

int kq = -1;

void
init_events(void)
{
        struct file	*file;
        struct kevent	*kevlist, *kevptr;
        int		 kevlen;

        if (kq == -1) {
                kq = kqueue();
                if (kq == -1)
                        fatal("kqueue");
        }

        kevlen = count_open_files() * 2;
        if (kevlen == 0)
                return;

        kevlist = xcalloc(kevlen, sizeof (struct kevent));

        kevptr = kevlist;
        TAILQ_FOREACH(file, &conf.files, entry) {
                if (file->fd != NULL) {
			log_debug("init file: tag=%s", file->tag.name);
                        EV_SET(kevptr, fileno(file->fd), EVFILT_VNODE,
			    EV_ADD | EV_CLEAR, NOTE_DELETE | NOTE_RENAME |
			    NOTE_REVOKE, 0, NULL);
                        kevptr++;
                        EV_SET(kevptr, fileno(file->fd), EVFILT_READ,
			    EV_ADD | EV_CLEAR, 0, 0, NULL);
                        kevptr++;
                }
        }

        if (kevent(kq, kevlist, kevlen, NULL, 0, NULL))
                fatal("kevent");

	xfree(kevlist);
}

struct file *
get_event(enum event *event, int timeout)
{
        struct file	*file;
        struct kevent	 kev;
        struct timespec	 ts;
        int		 res;

        *event = EVENT_NONE;

        if (kq == -1)
                return (NULL);

        ts.tv_nsec = 0;
        ts.tv_sec = timeout;

        res = kevent(kq, NULL, 0, &kev, 1, &ts);
        if (res == -1) {
                if (errno == EINTR)
                        return (NULL);
                fatal("kevent");
        }
        if (res == 0) {
                *event = EVENT_TIMEOUT;
                return (NULL);
        }

        file = find_file_by_fd(kev.ident);
        if (file == NULL)
                return (NULL);

        switch (kev.filter) {
        case EVFILT_VNODE:
                *event = EVENT_REOPEN;
                return (file);
        case EVFILT_READ:
                if (kev.data < 0)
                        *event = EVENT_REOPEN;
                else {
                        file->size += kev.data;
                        *event = EVENT_READ;
                }
                return (file);
        }

        return (NULL);
}

void
close_events(void)
{
}
