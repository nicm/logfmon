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

#ifndef RULES_H
#define RULES_H

#include <sys/types.h>

#include <regex.h>

#include "tags.h"

enum action
{
  ACTION_IGNORE,
  ACTION_EXEC,
  ACTION_PIPE,
  ACTION_OPEN,
  ACTION_APPEND,
  ACTION_CLOSE
};

struct rule
{
  struct tags *tags;

  regex_t *re;
  regex_t *not_re;

  enum action action;
  struct
  {
    char *cmd;
    char *key;
    time_t expiry;

    int ent_max;
    char *ent_cmd;
  } params;

  struct rule *next;
  struct rule *last;
};

struct rules
{
  struct rule *head;
  struct rule *tail;
};

extern struct rules rules;

struct rule *add_rule(enum action, struct tags *, char *, char *);
void clear_rules(void);

#endif
