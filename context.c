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
#include <pthread.h>
#include <syslog.h>
#include <errno.h>

#include "logfmon.h"
#include "xmalloc.h"
#include "log.h"
#include "context.h"

struct context *add_context(struct context *contexts, char *key)
{
  struct context *context, *new;

  new = (struct context *) xmalloc(sizeof(struct context));

  new->next = NULL;

  new->key = (char *) xmalloc(strlen(key) + 1);
  strcpy(new->key, key);

  if(contexts == NULL)
    contexts = new;
  else
  {
    context = contexts;
    while(context->next != NULL)
      context = context->next;
    context->next = new;
  }  

  return contexts;
}

struct context *clear_contexts(struct context *contexts)
{
  struct context *context, *last;

  if(contexts == NULL)
    return NULL;

  context = contexts;
  while(context != NULL)
  {
    last = context;

    context = context->next;

    free(last->key);
    free(last);
  }

  return NULL;
}

void attach_msg(struct context *contexts, struct contextmsg *msg)
{
}
