/* $Id$ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "logfmon.h"
#include "rules.h"
#include "xmalloc.h"
#include "log.h"
#include "file.h"

struct rule *rules;

int add_rule(char *cmd, char *re, char *tag)
{
  struct rule *rule, *new;

  new = (struct rule *) xmalloc(sizeof(struct rule));

  new->next = NULL;

  if(cmd != NULL)
  {
    new->cmd = (char *) xmalloc(strlen(cmd) + 1);
    strcpy(new->cmd, cmd);
  }
  else
    new->cmd = NULL;

  if(tag != NULL)
  {
    if(find_file_by_tag(tag) == NULL)
    {
      free(new->cmd);
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
    free(new->cmd);
    free(new->tag);
    free(new);

    error("%s: bad regexp", re);

    return 1;
  }

  if(debug)
    info("match=%s, command=%s, tag=%s", re, new->cmd, new->tag);

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
    free(last->cmd);
    free(last->tag);
    free(last);
  }

  rules = NULL;
}

