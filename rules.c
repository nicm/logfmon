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

#include "logfmon.h"
#include "rules.h"
#include "xmalloc.h"
#include "log.h"
#include "file.h"

struct rules rules = { NULL, NULL };

struct rule *add_rule(int action, char *tag, char *re)
{
  struct rule *rule;

  rule = (struct rule *) xmalloc(sizeof(struct rule));

  rule->action = action;

  rule->params.cmd = NULL;
  rule->params.key = NULL;
  rule->params.expiry = 0;

  rule->params.ent_max = 0;
  rule->params.ent_cmd = NULL;

  if(tag != NULL)
  {
    if(find_file_by_tag(tag) == NULL)
    {
      free(rule);

      error("%s: unknown tag", tag);

      return NULL;
    }

    rule->tag = (char *) xmalloc(strlen(tag) + 1);
    strcpy(rule->tag, tag);
  }
  else
    rule->tag = NULL;

  rule->re = (regex_t *) xmalloc(sizeof(regex_t));

  if(regcomp(rule->re, re, 0) != 0)
  {
    free(rule->re);
    free(rule->tag);
    free(rule);

    error("%s: bad regexp", re);

    return NULL;
  }

  if(debug)
    info("match=%s, action=%d, tag=%s", re, rule->action, rule->tag);
  
  if(rules.head == NULL)
  {
    rule->next = rule->last = NULL;
    rules.head = rules.tail = rule;
  }
  else
  {
    rules.head->last = rule;
    rule->next = rules.head;
    rule->last = NULL;
    rules.head = rule;
  }  

  return rule;
}

void clear_rules(void)
{
  struct rule *rule, *last;

  if(rules.head == NULL)
    return;

  rule = rules.head;
  while(rule != NULL)
  {
    last = rule;
    rule = rule->next;

    regfree(last->re);

    free(last->re);
    free(last->tag);
    free(last->params.cmd);
    free(last->params.key);
    free(last);
  }

  rules.head = rules.tail = NULL;
}

