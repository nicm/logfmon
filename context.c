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
#include <time.h>
#include <pthread.h>

#include "logfmon.h"
#include "xmalloc.h"
#include "log.h"
#include "context.h"
#include "rules.h"
#include "threads.h"

void init_contexts(struct contexts *contexts)
{
  contexts->head = contexts->tail = NULL;
}

int add_context(struct contexts *contexts, char *key, struct rule *rule)
{
  struct context *context;

  context = (struct context *) xmalloc(sizeof(struct context));

  init_messages(&context->messages);

  context->rule = rule;
  context->expiry = time(NULL) + rule->params.expiry;

  context->key = (char *) xmalloc(strlen(key) + 1);
  strcpy(context->key, key);

  if(contexts->head == NULL)
  {
    context->next = context->last = NULL;
    contexts->head = contexts->tail = context;
  }
  else
  {
    contexts->head->last = context;
    context->next = contexts->head;
    context->last = NULL;
    contexts->head = context;
  }  

  return 0;
}

void delete_context(struct contexts *contexts, struct context *context)
{
  if(contexts->head == NULL)
    return;

  if(context == contexts->head)
  {
    contexts->head = context->next;
    if(contexts->head != NULL)
      contexts->head->last = NULL;
  }
  if(context == contexts->tail)
  {
    contexts->tail = context->last;
    if(contexts->tail != NULL)
      contexts->tail->next = NULL;
  }

  if(context->next != NULL)
    context->next->last = context->last;
  if(context->last != NULL)
    context->last->next = context->next;

  clear_messages(&context->messages);
  
  free(context->key);
  free(context);
}

void clear_contexts(struct contexts *contexts)
{
  struct context *context, *last;

  if(contexts->head == NULL)
    return;

  context = contexts->head;
  while(context != NULL)
  {
    last = context;
    context = context->next;

    clear_messages(&last->messages);
  
    free(last->key);
    free(last);
  }

  contexts->head = contexts->tail = NULL;
}

struct context *find_context_by_key(struct contexts *contexts, char *key)
{
  struct context *context;

  if(contexts->head == NULL)
    return NULL;

  for(context = contexts->head; context != NULL; context = context->next)
  {
    if(strcmp(context->key, key) == 0)
      return context;
  }

  return NULL;
}

void check_contexts(struct contexts *contexts)
{
  struct context *context, *last;
  time_t now;

  if(contexts->head == NULL)
    return;

  now = time(NULL);
  
  context = contexts->head;
  while(context != NULL)
  {
    last = context;
    context = context->next;

    if(now >= last->expiry)
    {
      if(debug)
	info("context %s expired", last->key);
      if(last->rule != NULL && last->rule->params.cmd != NULL)
	pipe_context(last, last->rule->params.cmd);
      delete_context(contexts, last);
    }
  }

  return;
}

int pipe_context(struct context *context, char *cmd)
{
  FILE *fd;
  struct message *message;
  pthread_t thread;

  if(cmd == NULL || *cmd == '\0')
  {
    error("empty pipe command");
    return 1;
  }

  fd = popen(cmd, "w");
  if(fd == NULL)
    {
      error("%s: %s", cmd, strerror(errno));
      return 1;
    }
  for(message = context->messages.tail; message != NULL; message = message->last)
    fprintf(fd, "%s\n", message->msg);

  if(pthread_create(&thread, NULL, pclose_thread, fd) != 0)
    die("pthread_create: %s", strerror(errno));

  return 0;
}
