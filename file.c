/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicm__@ntlworld.com>
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

#include "logfmon.h"

void	free_file(struct file *);

struct file *
add_file(char *path, char *tag)
{
        struct file	*file;
        FILE		*fd;

        file = xmalloc(sizeof (struct file));
	bzero(file, sizeof (struct file));

        TAILQ_INIT(&file->saves);
        TAILQ_INIT(&file->contexts);

        if (find_file_by_path(path) != NULL) {
                free(file);
                log_warnx("%s: duplicate file", path);
                return (NULL);
        }
        if (find_file_by_tag(tag) != NULL) {
                free(file);
                log_warnx("%s: duplicate tag", tag);
                return (NULL);
        }

	if (strlen(tag) > sizeof file->tag.name) {
		free(file);
		log_warnx("%s: tag too long", tag);
		return (NULL);
	}
	strncpy(file->tag.name, tag, sizeof file->tag.name);

        fd = fopen(path, "r");
        if (fd == NULL) {
                free(file);
                log_warn(path);
                return (NULL);
        }
        fclose(fd);
	file->path = xstrdup(path);

	log_debug("added file: path=%s, tag=%s", path, tag);
	TAILQ_INSERT_HEAD(&conf.files, file, entry);
        return (file);
}

void
free_file(struct file *file)
{
	reset_file(file);
	free_contexts(file);

	free(file->path);
	free(file);
}

void
free_files(void)
{
        struct file 	*file;

        close_files();

	while (!TAILQ_EMPTY(&conf.files)) {
		file = TAILQ_FIRST(&conf.files);
		TAILQ_REMOVE(&conf.files, file, entry);
		free_file(file);
	}
}

void
reset_file(struct file *file)
{
	struct msg	*save;

	while (!TAILQ_EMPTY(&file->saves)) {
		save = TAILQ_FIRST(&file->saves);
		TAILQ_REMOVE(&file->saves, save, entry);
		free(save->str);
		free(save);
	}
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

        TAILQ_FOREACH(file, &conf.files, entry) {
                if (file->fd == NULL) {
                        file->fd = fopen(file->path, "r");
                        if (file->fd == NULL)
                                log_warn(file->path);
                        else {
                                file->timer = 0;
                                if (file->offset == 0)
                                        continue;
				if (fseeko(file->fd, file->offset,
				    SEEK_SET) != 0)
                                        log_warn("fseeko");
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
                if (file->fd == NULL)
                {
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
                if (strcmp(file->path, path) == 0)
                        return (file);
        }

        return (NULL);
}

struct file *
find_file_by_fd(int fd)
{
        struct file	*file;

        TAILQ_FOREACH(file, &conf.files, entry) {
                if (file->fd != NULL && fileno(file->fd) == fd)
                        return file;
        }

        return (NULL);
}
