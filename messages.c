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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "logfmon.h"
#include "messages.h"
#include "xmalloc.h"

void init_messages(struct messages *messages)
{
  messages->head = messages->tail = NULL;
}

int add_message(struct messages *messages, char *msg)
{
  struct message *message;

  message = (struct message *) xmalloc(sizeof(struct message));

  message->msg = xstrdup(msg);

  if(messages->head == NULL)
  {
    message->next = message->last = NULL;
    messages->head = messages->tail = message;
  }
  else
  {
    messages->head->last = message;
    message->next = messages->head;
    message->last = NULL;
    messages->head = message;
  }

  return 0;
}

int count_messages(struct messages *messages)
{
  struct message *message;
  int num;

  if(messages->head == NULL)
    return 0;

  num = 0;
  for(message = messages->head; message != NULL; message = message->next)
    num++;

  return num;
}

void clear_messages(struct messages *messages)
{
  struct message *message, *last;

  if(messages->head == NULL)
    return;

  message = messages->head;
  while(message != NULL)
  {
    last = message;
    message = message->next;

    free(last->msg);
    free(last);
  }

  messages->head = messages->tail = NULL;
}
