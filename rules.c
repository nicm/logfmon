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
#include <stdlib.h>
#include <string.h>

#include "file.h"
#include "log.h"
#include "logfmon.h"
#include "rules.h"
#include "tags.h"
#include "xmalloc.h"

struct rules rules = { NULL, NULL };

struct rule *add_rule(int action, struct tags *tags, char *re, char *not_re)
{
  struct rule *rule;

  rule = (struct rule *) xmalloc(sizeof(struct rule));

  rule->action = action;

  rule->params.cmd = NULL;
  rule->params.key = NULL;
  rule->params.expiry = 0;

  rule->params.ent_max = 0;
  rule->params.ent_cmd = NULL;

  if(tags == NULL)
  {
    rule->tags = xmalloc(sizeof(struct tags));
    init_tags(rule->tags);
  }
  else
    rule->tags = tags;

  if(check_tags(rule->tags))
  {
    free(rule);
    return NULL;
  }

  rule->re = (regex_t *) xmalloc(sizeof(regex_t));

  if(regcomp(rule->re, re, 0) != 0)
  {
    free(rule->re);
    free(rule);

    error("%s: bad regexp", re);

    return NULL;
  }

  if(not_re != NULL)
  {
    rule->not_re = (regex_t *) xmalloc(sizeof(regex_t));

    if(regcomp(rule->not_re, not_re, 0) != 0)
    {
      free(rule->not_re);
      free(rule->re);
      free(rule);

      error("%s: bad regexp", not_re);

      return NULL;
    }
  }
  else
    rule->not_re = NULL;

  if(debug)
    info("match=%s, action=%d", re, rule->action);

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

    clear_tags(last->tags);
    free(last->tags);

    regfree(last->re);
    free(last->re);

    if(last->not_re != NULL)
    {
      regfree(last->not_re);
      free(last->not_re);
    }

    free(last->params.cmd);
    free(last->params.key);
    free(last);
  }

  rules.head = rules.tail = NULL;
}
