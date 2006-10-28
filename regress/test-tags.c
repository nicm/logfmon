/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <sys/types.h>
#include <sys/queue.h>

#include <stdlib.h>
#include <string.h>

#include "logfmon.h"

extern void	copy_tags(struct tags *, struct tags *);

void		t_make_tags(struct tags *);
int		t_check_tags(struct tags *);

void
t_make_tags(struct tags *tags)
{
	int		 i;
	struct tag	*tag;

	for (i = 0; i < 100; i++) {
		tag = xcalloc(1, sizeof *tag);
		xsnprintf(tag->name, sizeof tag->name, "tag%d", i);
		TAILQ_INSERT_TAIL(tags, tag, entry);
	}
}

int
t_check_tags(struct tags *tags)
{
	int		 i;
	struct tag	*tag;
	char		 name[MAXTAGLEN];

	i = 0;
	TAILQ_FOREACH(tag, tags, entry) {
		xsnprintf(name, sizeof name, "tag%d", i);
		if (strcmp(name, tag->name) != 0)
			return (1);
		i++;
	}
	if (i != 100)
		return (1);

	return (0);
}

int
main(void)
{
	struct tags	 src;
	struct rule	 rule;
	int		 i;
	char		 name[MAXTAGLEN];

	memset(&src, 0, sizeof src);
	memset(&rule, 0, sizeof rule);

	TAILQ_INIT(&src);
	TAILQ_INIT(&rule.tags);	

	t_make_tags(&src);
	if (t_check_tags(&src) != 0)
		exit(1);

	copy_tags(&src, &rule.tags);
	if (t_check_tags(&rule.tags) != 0)
		exit(2);	
	
	for (i = 0; i < 100; i++) {
		xsnprintf(name, sizeof name, "tag%d", i);
		if (!has_tag(&rule, name))
			exit(3);
	}

	if (has_tag(&rule, "missing"))
		exit(4);

	free_tags(&src);
	if (!TAILQ_EMPTY(&src))
		exit(5);
	
	exit(0);
}
