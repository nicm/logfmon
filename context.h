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

#include <time.h>

struct context
{
  char *key;

  time_t expiry;

  struct contextmsg *cmsgs;
  
  struct context *next;
};

struct contextmsg
{
  char *msg;

  struct contextmsg *next;
};

struct context *add_context(struct context *, char *, time_t);
struct context *delete_context(struct context *, char *);
struct context *clear_contexts(struct context *);
struct context *find_context(struct context *, char *);
struct context *check_contexts(struct context *);
struct contextmsg *add_msg(struct contextmsg *, char *);
struct contextmsg *clear_msgs(struct contextmsg *);

#endif
