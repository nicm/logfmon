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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "logfmon.h"
#include "file.h"
#include "xmalloc.h"
#include "log.h"
#include "save.h"
#include "context.h"

struct file *files;

int add_file(char *path, char *tag)
{
  struct file *file, *new;
  FILE *fd;

  new = (struct file *) xmalloc(sizeof(struct file));

  new->next = NULL;

  new->fd = NULL;

  new->buffer = NULL;
  new->length = 0;

  new->saves = NULL;
  new->contexts = NULL;

  if(find_file_by_path(path) != NULL)
  {
    free(new);

    error("%s: duplicate file", path);

    return 1;
  }

  fd = fopen(path, "r");
  if(fd == NULL)
  {
    free(new);

    error("%s: %s", path, strerror(errno));

    return 1;
  }
  fclose(fd);

  new->path = (char *) xmalloc(strlen(path) + 1);
  strcpy(new->path, path);

  if(find_file_by_tag(tag) != NULL)
  {
    free(new);
    free(new->path);

    error("%s: duplicate tag", tag);

    return 1;
  }
   
  new->tag = (char *) xmalloc(strlen(tag) + 1);
  strcpy(new->tag, tag);

  if(debug)
    info("file=%s, tag=%s", new->path, new->tag);

  if(files == NULL)
    files = new;
  else
  {
    file = files;
    while(file->next != NULL)
      file = file->next;
    file->next = new;
  }  

  return 0;
}

void clear_files(void)
{
  struct file *file, *last;

  close_files();

  if(files == NULL)
    return;

  file = files;
  while(file != NULL)
  {
    last = file;

    file = file->next;

    clear_contexts(file->contexts);
    clear_saves(file->saves);

    free(last->buffer);
    free(last->path);
    free(last->tag);
    free(last);
  }

  files = NULL;
}

int count_open_files(void)
{
  struct file *file;
  int num;

  if(files == NULL)
    return 0;

  num = 0;
  file = files;
  while(file != NULL)
  {
    if(file->fd != NULL)
      num++;
    file = file->next;
  }

  return num;
}

int count_closed_files(void)
{
  struct file *file;
  int num;

  if(files == NULL)
    return 0;

  num = 0;
  file = files;
  while(file != NULL)
  {
    if(file->fd == NULL)
      num++;
    file = file->next;
  }

  return num;
}

int open_files(void)
{
  struct file *file;
  int num;

  if(files == NULL)
    return 0;

  num = 0;
  file = files;
  while(file != NULL)
  {
    if(file->fd == NULL)
    {
      file->fd = fopen(file->path, "r");
      if(file->fd == NULL)
	error("%s: %s", file->path, strerror(errno));
      else
	num++;
    }
    
    file = file->next;
  }

  return num;
}

void close_files(void)
{
  struct file *file;

  if(files == NULL)
    return;

  file = files;
  while(file != NULL)
  {
    if(file->fd != NULL)
    {
      fclose(file->fd);

      file->fd = NULL;
      file->length = 0;
    }
    
    file = file->next;
  }
}

struct file *find_file_by_tag(char *tag)
{
  struct file *file;

  if(files == NULL)
    return NULL;

  file = files;
  while(file != NULL)
  {
    if(strcmp(file->tag, tag) == 0)
      return file;

    file = file->next;
  }

  return NULL;
}

struct file *find_file_by_path(char *path)
{
  struct file *file;

  if(files == NULL)
    return NULL;

  file = files;
  while(file != NULL)
  {
    if(strcmp(file->path, path) == 0)
      return file;

    file = file->next;
  }

  return NULL;
}

struct file *find_file_by_fn(int fn)
{
  struct file *file;

  if(files == NULL)
    return NULL;

  file = files;
  while(file != NULL)
  {
    if(file->fd != NULL && fileno(file->fd) == fn)
      return file;

    file = file->next;
  }

  return NULL;
}
