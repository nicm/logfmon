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
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include "logfmon.h"
#include "xmalloc.h"
#include "tags.h"
#include "file.h"
#include "log.h"

void init_tags(struct tags *tags)
{
  tags->head = tags->tail = NULL;
}

int add_tag(struct tags *tags, char *name)
{
  struct tag *tag;

  tag = (struct tag *) xmalloc(sizeof(struct tag));

  tag->name = xstrdup(name);

  if(tags->head == NULL)
  {
    tag->next = tag->last = NULL;
    tags->head = tags->tail = tag;
  }
  else
  {
    tags->head->last = tag;
    tag->next = tags->head;
    tag->last = NULL;
    tags->head = tag;
  }  

  return 0;
}

int check_tags(struct tags *tags)
{
  struct tag *tag;

  if(tags->head == NULL)
    return 0;

  for(tag = tags->head; tag != NULL; tag = tag->next)
  {
    if(!find_file_by_tag(tag->name))
    {
      error("%s: tag does not match a file", tag->name);
      return 1;
    }
  }
  
  return 0;
}

void clear_tags(struct tags *tags)
{
  struct tag *tag, *last;

  if(tags->head == NULL)
    return;

  tag = tags->head;
  while(tag != NULL)
  {
    last = tag;
    tag = tag->next;

    free(last->name);
    free(last);
  }

  tags->head = tags->tail = NULL;
}

struct tag *find_tag(struct tags *tags, char *name)
{
  struct tag *tag;

  if(tags->head == NULL)
    return NULL;

  for(tag = tags->head; tag != NULL; tag = tag->next)
  {
    if(strcmp(tag->name, name) == 0)
      return tag;
  }

  return NULL;
}
