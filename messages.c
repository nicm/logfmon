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
#include "messages.h"
#include "log.h"

void init_messages(struct messages *messages)
{
  messages->head = messages->tail = NULL;

  if((errno = pthread_mutex_init(&(messages->mutex), NULL)) != 0)
    die("pthread_mutex_init: %s", strerror(errno));
}

int add_message(struct messages *messages, char *msg)
{
  struct message *message;

  message = (struct message *) xmalloc(sizeof(struct message));

  message->msg = (char *) xmalloc(strlen(msg) + 1);
  strcpy(message->msg, msg);

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

  pthread_mutex_lock(&(messages->mutex));

  if(messages->head == NULL)
  {
    pthread_mutex_unlock(&(messages->mutex));
    return 0;
  }

  num = 0;
  for(message = messages->head; message != NULL; message = message->next)
    num++;

  pthread_mutex_unlock(&(messages->mutex));

  return num;
}

void clear_messages(struct messages *messages)
{
  struct message *message, *last;

  pthread_mutex_lock(&(messages->mutex));

  if(messages->head == NULL)
  {
    pthread_mutex_unlock(&(messages->mutex));
    return;
  }

  message = messages->head;
  while(message != NULL)
  {
    last = message;
    message = message->next;

    free(last->msg);
    free(last);
  }

  messages->head = messages->tail = NULL;

  pthread_mutex_unlock(&(messages->mutex));
}
