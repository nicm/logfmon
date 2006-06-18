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
#include <sys/stat.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logfmon.h"

void	free_file(struct file *);

struct file *
add_file(char *path, char *tag)
{
        struct file	*file;
        FILE		*fd;

        file = xmalloc(sizeof (struct file));
	memset(file, 0, sizeof (struct file));

        TAILQ_INIT(&file->saves);
	INIT_MUTEX(file->saves_mutex);

        TAILQ_INIT(&file->contexts);

        if (find_file_by_path(path) != NULL) {
                xfree(file);
                log_warnx("%s: duplicate file", path);
                return (NULL);
        }

        if (find_file_by_tag(tag) != NULL) {
                xfree(file);
                log_warnx("%s: duplicate tag", tag);
                return (NULL);
        }
	strlcpy(file->tag.name, tag, sizeof file->tag.name);

        fd = fopen(path, "r");
        if (fd == NULL) {
                xfree(file);
                log_warn("%s", path);
                return (NULL);
        }
        fclose(fd);
	file->path = xstrdup(path);

	log_debug("added file: path=%s, tag=%s", path, tag);
	LOCK_MUTEX(conf.files_mutex);
	TAILQ_INSERT_TAIL(&conf.files, file, entry);
	UNLOCK_MUTEX(conf.files_mutex);
        return (file);
}

void
free_file(struct file *file)
{
	reset_file(file);
	free_contexts(file);
	DESTROY_MUTEX(file->saves_mutex);
	xfree(file->path);
	xfree(file);
}

void
free_files(void)
{
        struct file 	*file;

        close_files();

	LOCK_MUTEX(conf.files_mutex);
	while (!TAILQ_EMPTY(&conf.files)) {
		file = TAILQ_FIRST(&conf.files);
		TAILQ_REMOVE(&conf.files, file, entry);
		free_file(file);
	}
	UNLOCK_MUTEX(conf.files_mutex);
}

void
reset_file(struct file *file)
{
	struct msg	*save;

	LOCK_MUTEX(file->saves_mutex);
	while (!TAILQ_EMPTY(&file->saves)) {
		save = TAILQ_FIRST(&file->saves);
		TAILQ_REMOVE(&file->saves, save, entry);
		xfree(save->str);
		xfree(save);
	}
	UNLOCK_MUTEX(file->saves_mutex);
}

unsigned int
count_open_files(void)
{
        struct file 	*file;
        unsigned int	 n;

        n = 0;
	TAILQ_FOREACH(file, &conf.files, entry) {
		if (file->fd != NULL)
			n++;
	}

	return (n);
}

void
open_files(void)
{
        struct file	*file;
	struct stat	 st;

        TAILQ_FOREACH(file, &conf.files, entry) {
                if (file->fd == NULL) {
                        file->fd = fopen(file->path, "r");
                        if (file->fd == NULL)
                                log_warn("%s", file->path);
                        else {
				if (fstat(fileno(file->fd), &st) < 0) {
					log_warn("%s", file->path);
					fclose(file->fd);
					file->fd = NULL;
				} else {
					file->timer = 0;
					file->size = st.st_size;
					if (file->offset == 0)
						continue;
					if (fseeko(file->fd, file->offset,
					    SEEK_SET) != 0)
						log_warn("fseeko");

					file->buf = NULL;
				}
                        }
                }
        }
}

unsigned int
reopen_files(unsigned int *failed)
{
        struct file 	*file;
        unsigned int	 opened;

        if (failed != NULL)
                *failed = 0;
        opened = 0;

        TAILQ_FOREACH(file, &conf.files, entry) {
                if (file->fd == NULL) {
			if (file->buf != NULL) {
				xfree(file->buf);
				file->buf = NULL;
			}

                        if (file->timer != 0 && file->timer > time(NULL)) {
                                if (failed != NULL)
                                        (*failed)++;
                                continue;
                        }

			file->fd = fopen(file->path, "r");
			if (file->fd == NULL) {
				if (failed != NULL)
					(*failed)++;
			} else {
				file->timer = 0;
				file->size = 0;
				file->offset = 0;
				opened++;
			}
                }
        }

        return (opened);
}

void
close_files(void)
{
        struct file	*file;

        TAILQ_FOREACH(file, &conf.files, entry) {
                if (file->fd != NULL) {
                        fclose(file->fd);
                        file->fd = NULL;

			if (file->buf) {
				xfree(file->buf);
				file->buf = NULL;
			}
                }
        }
}

struct file *
find_file_by_tag(char *tag)
{
        struct file	*file;

        TAILQ_FOREACH(file, &conf.files, entry) {
                if (strcmp(file->tag.name, tag) == 0)
                        return (file);
        }

        return (NULL);
}

struct file *
find_file_by_path(char *path)
{
        struct file	*file;

        TAILQ_FOREACH(file, &conf.files, entry) {
		if (strcmp(file->path, path) == 0) {
                        return (file);
		}
        }

        return (NULL);
}

struct file *
find_file_by_fd(int fd)
{
        struct file	*file;

        TAILQ_FOREACH(file, &conf.files, entry) {
                if (file->fd != NULL && fileno(file->fd) == fd)
                        return (file);
        }

        return (NULL);
}

struct file *
find_file_mismatch(void)
{
        struct file	*file;

        TAILQ_FOREACH(file, &conf.files, entry) {
		if (file->fd != NULL && file->size != file->offset)
			return (file);
        }

        return (NULL);
}
