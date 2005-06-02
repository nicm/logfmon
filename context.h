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

#ifndef CONTEXT_H
#define CONTEXT_H

#include <sys/types.h>

#include <time.h>
#include <regex.h>

#include "messages.h"
#include "rules.h"

struct context
{
        char *key;

        time_t expiry;

        struct rule *rule;

        struct messages messages;

        struct context *next;
        struct context *last;
};

struct contexts
{
        struct context *head;
        struct context *tail;
};

void init_contexts(struct contexts *);
int add_context(struct contexts *, char *, struct rule *);
void delete_context(struct contexts *, struct context *);
void clear_contexts(struct contexts *);
struct context *find_context_by_key(struct contexts *, char *);
void check_contexts(struct contexts *);
int pipe_context(struct context *, char *);

#endif
