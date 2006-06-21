/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <regex.h>
#include <string.h>
#include <stdlib.h>

#include "logfmon.h"

void	copy_tags(struct tags *, struct tags *);
void	free_rule(struct rule *);

struct rule *
add_rule(enum action action, struct tags *tags, char *re, char *not_re)
{
        struct rule	*rule;

        rule = xmalloc(sizeof (struct rule));
	memset(rule, 0, sizeof (struct rule));

	copy_tags(tags, &rule->tags);

        rule->action = action;

	if (re != NULL) {
		rule->re = xmalloc(sizeof (regex_t));
		if (regcomp(rule->re, re, REG_EXTENDED) != 0) {
			free_rule(rule);
			log_warnx("%s: bad regexp", re);
			return (NULL);
		}
	}
	if (not_re != NULL) {
                rule->not_re = xmalloc(sizeof (regex_t));
                if (regcomp(rule->not_re, not_re, REG_EXTENDED) != 0) {
			free_rule(rule);
                        log_warnx("%s: bad regexp", not_re);
                        return (NULL);
                }
        }

	log_debug("added rule: re=%s, not_re=%s, action=%s",
	    re, not_re != NULL ? not_re : "<none>", actions[action]);
	TAILQ_INSERT_TAIL(&conf.rules, rule, entry);
        return (rule);
}

void
free_rule(struct rule *rule)
{
	free_tags(&rule->tags);

	if (rule->re != NULL) {
		regfree(rule->re);
		xfree(rule->re);
	}
	if (rule->not_re != NULL) {
		regfree(rule->not_re);
		xfree(rule->not_re);
	}

	if (rule->params.str != NULL)
		xfree(rule->params.str);
	if (rule->params.key != NULL)
		xfree(rule->params.key);

	xfree(rule);
}

void
free_rules(void)
{
        struct rule	*rule;

	while (!TAILQ_EMPTY(&conf.rules)) {
		rule = TAILQ_FIRST(&conf.rules);
		TAILQ_REMOVE(&conf.rules, rule, entry);
		free_rule(rule);
	}
}

int
has_tag(struct rule *rule, char *name)
{
	struct tag	*tag;

	/* empty tags list means any tag matches */
	if (TAILQ_EMPTY(&rule->tags.tags))
		return (1);

	TAILQ_FOREACH(tag, &rule->tags.tags, entry) {
		if (strcmp(name, tag->name) == 0)
			return (1);
	}

	return (0);
}

void
copy_tags(struct tags *src, struct tags *dst)
{
	struct tag	*t_src, *t_dst;

	TAILQ_INIT(&dst->tags);
	TAILQ_FOREACH(t_src, &src->tags, entry) {
		t_dst = xmalloc(sizeof (struct tag));
		strlcpy(t_dst->name, t_src->name, sizeof t_dst->name);
	}
}

void
free_tags(struct tags *tags)
{
	struct tag	*tag;

	while (!TAILQ_EMPTY(&tags->tags)) {
		tag = TAILQ_FIRST(&tags->tags);
		TAILQ_REMOVE(&tags->tags, tag, entry);
		xfree(tag);
	}
}

