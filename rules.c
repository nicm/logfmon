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

struct rule *rules;

int add_rule(int action, char *param, char *re, char *tag)
{
  struct rule *rule, *new;

  new = (struct rule *) xmalloc(sizeof(struct rule));

  new->next = NULL;

  new->action = action;

  if(param != NULL)
  {
    new->param = (char *) xmalloc(strlen(param) + 1);
    strcpy(new->param, param);
  }
  else
    new->param = NULL;

  if(tag != NULL)
  {
    if(find_file_by_tag(tag) == NULL)
    {
      free(new->param);
      free(new);

      error("%s: unknown tag", tag);

      return 1;
    }

    new->tag = (char *) xmalloc(strlen(tag) + 1);
    strcpy(new->tag, tag);
  }
  else
    new->tag = NULL;

  new->re = (regex_t *) xmalloc(sizeof(regex_t));

  if(regcomp(new->re, re, 0) != 0)
  {
    free(new->re);
    free(new->param);
    free(new->tag);
    free(new);

    error("%s: bad regexp", re);

    return 1;
  }

  if(debug)
    info("match=%s, action=%d, param=%s, tag=%s", re, new->action, new->param, new->tag);

  if(rules == NULL)
    rules = new;
  else
  {
    rule = rules;
    while(rule->next != NULL)
      rule = rule->next;
    rule->next = new;
  }  

  return 0;
}

void clear_rules(void)
{
  struct rule *rule, *last;

  if(rules == NULL)
    return;

  rule = rules;
  while(rule != NULL)
  {
    last = rule;

    rule = rule->next;

    regfree(last->re);
    free(last->re);
    free(last->param);
    free(last->tag);
    free(last);
  }

  rules = NULL;
}

