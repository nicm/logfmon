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

struct files files = { NULL, NULL };

int add_file(char *path, char *tag)
{
  struct file *file;
  FILE *fd;

  file = (struct file *) xmalloc(sizeof(struct file));

  file->fd = NULL;

  file->buffer = NULL;
  file->length = 0;

  file->size = 0;
  file->offset = 0;

  file->timer = 0;

  init_messages(&file->saves);
  init_contexts(&file->contexts);

  if(find_file_by_path(path) != NULL)
  {
    free(file);

    error("%s: duplicate file", path);

    return 1;
  }

  fd = fopen(path, "r");
  if(fd == NULL)
  {
    free(file);

    error("%s: %s", path, strerror(errno));

    return 1;
  }
  fclose(fd);

  file->path = (char *) xmalloc(strlen(path) + 1);
  strcpy(file->path, path);

  if(find_file_by_tag(tag) != NULL)
  {
    free(file);
    free(file->path);

    error("%s: duplicate tag", tag);

    return 1;
  }
   
  file->tag = (char *) xmalloc(strlen(tag) + 1);
  strcpy(file->tag, tag);

  if(debug)
    info("file=%s, tag=%s", file->path, file->tag);

  if(files.head == NULL)
  {
    file->next = file->last = NULL;
    files.head = files.tail = file;
  }
  else
  {
    files.head->last = file;
    file->next = files.head;
    file->last = NULL;
    files.head = file;
  }  

  return 0;
}

void clear_files(void)
{
  struct file *file, *last;

  if(files.head == NULL)
    return;

  close_files();

  file = files.head;
  while(file != NULL)
  {
    last = file;
    file = file->next;

    clear_contexts(&last->contexts);
    clear_messages(&last->saves);

    free(last->buffer);
    free(last->path);
    free(last->tag);
    free(last);
  }

  files.head = files.tail = NULL;
}

int count_files(void)
{
  struct file *file;
  int num;

  if(files.head == NULL)
    return 0;

  num = 0;
  for(file = files.head; file != NULL; file = file->next)
    num++;

  return num;
}

int count_open_files(void)
{
  struct file *file;
  int num;

  if(files.head == NULL)
    return 0;

  num = 0;
  for(file = files.head; file != NULL; file = file->next)
  {
    if(file->fd != NULL)
      num++;
  }

  return num;
}

int count_closed_files(void)
{
  struct file *file;
  int num;

  if(files.head == NULL)
    return 0;

  num = 0;
  for(file = files.head; file != NULL; file = file->next)
  {
    if(file->fd == NULL)
      num++;
  }

  return num;
}

void open_files(void)
{ 
  struct file *file;

  if(files.head == NULL)
    return;
  
  for(file = files.head; file != NULL; file = file->next)
  {
    if(file->fd == NULL)
    {
      file->fd = fopen(file->path, "r");
      if(file->fd == NULL)
	error("%s: %s", file->path, strerror(errno));
      else
      {
	file->timer = 0;
	if(file->offset > 0)
	{
	  if(fseek(file->fd, (long) file->offset, SEEK_SET) != 0)
	    error("fsetpos: %s", strerror(errno));
	}
      }
    }
  }
  
  return;
}

int reopen_files(int *failed)
{ 
  struct file *file;
  int num;

  if(failed != NULL)
    *failed = 0;

  if(files.head == NULL)
    return 0;

  num = 0;
  for(file = files.head; file != NULL; file = file->next)
  {
    if(file->fd == NULL)
    {
      if(file->timer != 0 && file->timer > time(NULL))
      {
	if(failed != NULL)
	  (*failed)++;
	continue;
      }

      file->fd = fopen(file->path, "r");
      if(file->fd == NULL)
      {
	if(failed != NULL)
	  (*failed)++;
	error("%s: %s", file->path, strerror(errno));
      }
      else
      {
	file->timer = 0;
	file->size = 0;
	file->offset = 0;
	num++;
      }
    }
  }
  
  return num;
}
  
void close_files(void)
{
  struct file *file;

  if(files.head == NULL)
    return;

  for(file = files.head; file != NULL; file = file->next)
  {
    if(file->fd != NULL)
    {
      fclose(file->fd);

      file->fd = NULL;
      file->length = 0;
    }
  }
}

struct file *find_file_by_tag(char *tag)
{
  struct file *file;

  if(files.head == NULL)
    return NULL;

  for(file = files.head; file != NULL; file = file->next)
  {
    if(strcmp(file->tag, tag) == 0)
      return file;
  }

  return NULL;
}

struct file *find_file_by_path(char *path)
{
  struct file *file;

  if(files.head == NULL)
    return NULL;

  for(file = files.head; file != NULL; file = file->next)
  {
    if(strcmp(file->path, path) == 0)
      return file;
  }

  return NULL;
}

struct file *find_file_by_fd(int fd)
{
  struct file *file;

  if(files.head == NULL)
    return NULL;

  for(file = files.head; file != NULL; file = file->next)
  {
    if(file->fd != NULL && fileno(file->fd) == fd)
      return file;
  }

  return NULL;
}

void check_files(void)
{
  struct file *file;

  if(files.head == NULL)
    return;

  for(file = files.head; file != NULL; file = file->next)
    check_contexts(&file->contexts);
}
