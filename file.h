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

#ifndef FILE_H
#define FILE_H

#include "save.h"

struct file
{
  char *path;
  char *tag;

  FILE *fd;

  char *buffer;
  size_t length;

  struct context *contexts;

  struct save *saves;

  struct file *next;
};

extern struct file *files;

int add_file(char *, char *);
void clear_files(void);
int count_open_files(void);
int count_closed_files(void);
int open_files(void);
void close_files(void);
struct file *find_file_by_tag(char *);
struct file *find_file_by_path(char *);
struct file *find_file_by_fn(int);
void check_files(void);

#endif
