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
#include <time.h>

#include "logfmon.h"
#include "xmalloc.h"
#include "log.h"
#include "context.h"
#include "rules.h"

struct context *add_context(struct context *contexts, char *key, struct rule *rule)
{
  struct context *context, *new;

  new = (struct context *) xmalloc(sizeof(struct context));

  new->next = NULL;

  new->cmsgs = NULL;
  new->rule = rule;

  new->expiry = time(NULL) + rule->params.expiry;

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

struct context *delete_context(struct context *contexts, char *key)
{
  struct context *context, *last;

  if(contexts == NULL)
    return NULL;

  if(strcmp(contexts->key, key) == 0)
  {
    context = contexts;
    contexts = contexts->next;
  }
  else
  {
    last = contexts;
    context = contexts->next;
    while(context != NULL)
    {
      if(strcmp(context->key, key) == 0)
	break;

      last = context;
    }

    last->next = context->next;
  }

  clear_msgs(context->cmsgs);
  
  free(context->key);
  free(context);

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

    clear_msgs(last->cmsgs);
  
    free(last->key);
    free(last);
  }

  return NULL;
}

struct context *find_context(struct context *contexts, char *key)
{
  struct context *context;

  if(contexts == NULL)
    return NULL;

  context = contexts;
  while(context != NULL)
  {
    if(strcmp(context->key, key) == 0)
      return context;

    context = context->next;
  }

  return NULL;
}

struct contextmsg *add_msg(struct contextmsg *cmsgs, char *msg)
{
  struct contextmsg *cmsg, *new;

  new = (struct contextmsg *) xmalloc(sizeof(struct contextmsg));

  new->next = NULL;

  new->msg = (char *) xmalloc(strlen(msg) + 1);
  strcpy(new->msg, msg);

  if(cmsgs == NULL)
    cmsgs = new;
  else
  {
    cmsg = cmsgs;
    while(cmsg->next != NULL)
      cmsg = cmsg->next;
    cmsg->next = new;
  }  

  return cmsgs;
}

struct contextmsg *clear_msgs(struct contextmsg *cmsgs)
{
  struct contextmsg *cmsg, *last;

  if(cmsgs == NULL)
    return NULL;

  cmsg = cmsgs;
  while(cmsg != NULL)
  {
    last = cmsg;

    cmsg = cmsg->next;

    free(last->msg);
    free(last);
  }

  return NULL;
}

struct context *check_contexts(struct context *contexts)
{
  struct context *context, *last;
  time_t now;

  if(contexts == NULL)
    return NULL;

  now = time(NULL);
  context = contexts;
  while(context != NULL)
  {
    last = context;

    context = context->next;

    if(now >= last->expiry)
    {
      if(debug)
	info("context %s expired", last->key);
      if(last->rule != NULL && last->rule->params.cmd != NULL)
      {
	if(pipe_context(last->rule->params.cmd, last))
	  error("%s: %s", last->rule->params.cmd, strerror(errno));
      }
      contexts = delete_context(contexts, last->key);
    }
  }

  return contexts;
}

int pipe_context(char *cmd, struct context *context)
{
  FILE *fd;
  struct contextmsg *cmsg;

  fd = popen(cmd, "w");
  if(fd == NULL)
    return 1;
  cmsg = context->cmsgs;
  while(cmsg != NULL)
  {
    fprintf(fd, "%s\n", cmsg->msg);
    
    cmsg = cmsg->next;
  }
  pclose(fd);
  
  return 0;
}
