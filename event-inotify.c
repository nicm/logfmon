/* $Id$ */

/*
 * Copyright (c) 2007 Laurent Pelecq <laurent.pelecq@aful.org>
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
#include <sys/time.h>
#include <sys/ioctl.h>
#ifdef HAVE_INOTIFYTOOLS
#include <inotify.h>
#else
#include <sys/inotify.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <unistd.h>
#include <fcntl.h>

#include "logfmon.h"


static int inotify_fd = -1;

#define EVENT_SIZE(EV)		(sizeof(struct inotify_event) + (EV)->len)

#define EVENT_BUFFER_SIZE	16384

static
void
set_nonblock(int fd)
{
        long flags = 0;
        if (fcntl(fd, F_GETFL, &flags) < 0)
                fatal("cannot read file descriptor attributes");
        flags |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, &flags) < 0)
                log_warnx("non-blocking mode not available");
        else
                log_info("non-blocking mode enabled");
}

/*
 * File event data
 */

#define PENDING_EVENT_READ	0x1
#define PENDING_EVENT_REOPEN	0x2

struct _event_data_t {
	struct file *file;
	unsigned int pending_events;
};
typedef struct _event_data_t event_data_t;

/*
 * Watches
 */

struct _watch_t {
	int wd;
	char *path;
	void *data;
	size_t nref;
	int mask;
	struct _watch_t *parent;
};
typedef struct _watch_t watch_t;

static
int comp_watches_by_wd(const void *a, const void *b) {
	int awd = ((const watch_t*)a)->wd;
	int bwd = ((const watch_t*)b)->wd;
	if (awd < bwd)
		return -1;
	else if (awd > bwd)
		return 1;
	return 0; 
}

static
int comp_watches_by_path(const void *a, const void *b) {
	return strcmp(((const watch_t*)a)->path, ((const watch_t*)b)->path);
}

static watch_t *watches = NULL;
static size_t nwatches = 0;

static
watch_t *
find_watch_by_wd(int wd) {
	watch_t key = { wd, NULL, NULL, 0, 0, NULL };
	return bsearch(&key, watches, nwatches, sizeof(watch_t), comp_watches_by_wd);
}

static
watch_t *
find_watch_by_path(char *path) {
	watch_t key = { -1, path, NULL, 0, 0, NULL };
	size_t nitems = nwatches;
	return lfind(&key, watches, &nitems, sizeof(watch_t), comp_watches_by_path);
}

static
watch_t *
find_watch_by_name(const char *dir_path, const char *name) {
	char *path = 0;
	watch_t *watch = NULL;

	xasprintf(&path, "%s/%s", dir_path, name);
	watch = find_watch_by_path(path);
	xfree(path);
	return watch;
}

static
void
open_watch(watch_t *w)
{
	if (w->wd >= 0)
		inotify_rm_watch(inotify_fd, w->wd);
	w->wd = inotify_add_watch(inotify_fd, w->path, w->mask);
	if (w->wd < 0) {
		close_events();
		fatal("inotify_add_watch");
	}
}

static
watch_t *
push_watch(char *path, int mask, void *data)
{
	watch_t *w = &(watches[nwatches]);
	log_debug("add watch on path: %s", path);
	w->path = path;
	w->wd = -1;
	w->data = data;
	w->nref = 1;
	w->mask = mask;
	w->parent = NULL;
	open_watch(w);
	++nwatches;
	return w;
}

static
void delete_watch(watch_t *w)
{
	if (w->wd >= 0) {
		if (w->nref <= 0)
			fatal("deleting an unused watch");
		--(w->nref);
		if (w->nref == 0) {
			log_debug("remove watch on path: %s", w->path);
			inotify_rm_watch(inotify_fd, w->wd);
			w->wd = -1;
			xfree(w->path);
			w->path = NULL;
			if (w->data) {
				xfree(w->data);
				w->data = NULL;
			}
			if (w->parent)
				delete_watch(w->parent);
		}
	}
}

/*
 *
 */

static
char *safe_dirname(const char *filename) { /* Don't use a static buffer. */
	char *dirname = xstrdup(filename);
	char *sep = strrchr(dirname, '/');
	if (sep)
		*sep = '\0';
	return dirname;
}

static
struct file *find_event(enum event *event)
{
	size_t i;
	for (i = 0; i < nwatches; ++i) {
		watch_t *w = &(watches[i]);
		if (w->data) {
			int new_event = EVENT_NONE;
			event_data_t *data = (event_data_t*)w->data;
			unsigned int pevents = data->pending_events;
			if (pevents & PENDING_EVENT_READ) {
				new_event = EVENT_READ;
				data->pending_events &= (~PENDING_EVENT_READ);
			} else if (pevents & PENDING_EVENT_REOPEN) {
				new_event = EVENT_REOPEN;
				data->pending_events &= (~PENDING_EVENT_REOPEN);
			}
			if (new_event != EVENT_NONE) {
				*event = new_event;
				return data->file;
			}
		}
	}
	return NULL;
}

static
void process_event(struct inotify_event *ev, const char *name)
{
	watch_t *watch = find_watch_by_wd(ev->wd);
	event_data_t *data = NULL;
	unsigned int pevent = 0;
	if (watch) {
		if (ev->mask & IN_MODIFY) {
			data = watch->data;
			pevent = PENDING_EVENT_READ;
		} else if (ev->mask & (IN_CREATE|IN_MOVED_TO)) {
			watch_t *fwatch = find_watch_by_name(watch->path, name);
			log_debug("directory change: %s", watch->path);
			if (fwatch) {
				data = fwatch->data;
				pevent = PENDING_EVENT_REOPEN;
				log_info("file rotated: %s", fwatch->path);
				open_watch(fwatch);
				qsort(watches, nwatches, sizeof(watch_t), comp_watches_by_wd);
			} else
				log_debug("unmonitored file created: %s", name);
		}
		if (data)
			data->pending_events |= pevent;
	}
}

static
void read_pending_events(void)
{
	static char ev_buffer[EVENT_BUFFER_SIZE];
	static size_t end = 0;
	static size_t max_nevents = 0;
	size_t start = 0;
	ssize_t count = 0;
	size_t nevents = 0;

	do {
		count = read(inotify_fd, ev_buffer + end, EVENT_BUFFER_SIZE - end);
		if (count < 0) {
                        switch (errno) {
                        case EINTR:
                                break;
                        case EAGAIN:
                                return;
                        default:
                                fatal("read failed");
                        }
                } else
                        end += count;
        } while (count <= 0);

	for(;;) {
                struct inotify_event *ev = (struct inotify_event*)(ev_buffer + start);
		size_t ev_size = EVENT_SIZE(ev);
		if (start + ev_size > end)
			break;
                else {
                        struct inotify_event ev_aligned;
                        memcpy(&ev_aligned, ev, sizeof(ev_aligned));
                        process_event(&ev_aligned, ev->name);
			start += ev_size;
                        ++nevents;
                }
        }

	if (nevents > max_nevents) {
		max_nevents = nevents;
		log_info("number of events: %zu", max_nevents);
	}

	memmove(ev_buffer, ev_buffer + start, end - start);
	end -= start;
}

void
reinit_events(void)
{
}

void
init_events(void)
{
        struct file	*file = NULL;
	int		nfiles = 0;

	nfiles = count_open_files();

	if (nfiles <= 0 || inotify_fd >= 0)
		return;

	inotify_fd = inotify_init();
	if (inotify_fd < 0)
		fatal("inotify");
	set_nonblock(inotify_fd);
	log_debug("inotify initialized");

	watches = xcalloc(nfiles * 2, sizeof(watch_t));

	nwatches = 0;
        TAILQ_FOREACH(file, &conf.files, entry) {
                if (file->fd != NULL) {
			char *dirname = NULL;
			watch_t *file_watch = NULL;
			watch_t *dir_watch = NULL;
			event_data_t *data = NULL;

			log_debug("init file: tag=%s", file->tag.name);

			data = xmalloc(sizeof(event_data_t));
			data->file = file;
			data->pending_events = 0;
			file_watch = push_watch(xstrdup(file->path), IN_MODIFY, data);

			dirname = safe_dirname(file->path);
			dir_watch = find_watch_by_path(dirname);
			if (dir_watch) {
				log_debug("directory already monitored: %s", dirname);
				++(dir_watch->nref);
				xfree(dirname);
			} else
				dir_watch = push_watch(dirname, IN_CREATE|IN_MOVED_TO, NULL);
			file_watch->parent = dir_watch;
                }
        }
	qsort(watches, nwatches, sizeof(watch_t), comp_watches_by_wd);
}

struct file *
get_event(enum event *event, int timeout)
{
        struct file	*file = NULL;
	fd_set rfds;

        *event = EVENT_NONE;

        if (inotify_fd < 0)
                return (NULL);

	file = find_event(event);
	if (!file) {
		struct timeval	 tv;
		int ret = 0;

		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		FD_ZERO(&rfds);
		FD_SET(inotify_fd, &rfds);

		while (*event == EVENT_NONE) {
			ret = select(inotify_fd + 1, &rfds, NULL, NULL, &tv);
			switch (ret) {
			case -1:
				fatal("inotify select");
				break;
			case 0:
				*event = EVENT_TIMEOUT;
				break;
			default:
				read_pending_events();
				file = find_event(event);
			}
		}
	}

        return file;
}

void
close_events(void)
{
	if (inotify_fd >= 0) {
		size_t i;

		log_debug("deleting all watches");
		for (i = 0; i < nwatches; ++i) {
			watch_t *w = &(watches[i]);
			if (w->parent)
				delete_watch(w);
		}
		xfree(watches);
		watches = NULL;
		nwatches = 0;

		log_debug("closing inotify");
		close(inotify_fd);
		inotify_fd = -1;
	}
}

/*  Local Variables:  */
/*  eval: (c-set-style "bsd")  */
/*  End:  */
