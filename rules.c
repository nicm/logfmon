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

#ifdef NO_QUEUE_H
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#include <regex.h>
#include <string.h>
#include <stdlib.h>

#include "logfmon.h"

void	free_rule(struct rule *);

struct rule *
add_rule(enum action action, struct tags *tags, char *re, char *not_re)
{
        struct rule	*rule;
	struct tag	*tag;

        rule = xmalloc(sizeof (struct rule));
	memset(rule, 0, sizeof (struct rule));

	TAILQ_INIT(&rule->tags);
	TAILQ_FOREACH(tag, &tags->tags, entry) {
		TAILQ_INSERT_TAIL(&rule->tags, tag, entry);
	}
	xfree(tags);

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
	struct tag	*tag;

	while (!TAILQ_EMPTY(&rule->tags)) {
		tag = TAILQ_FIRST(&rule->tags);
		TAILQ_REMOVE(&rule->tags, tag, entry);
		xfree(tag);
	}

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
	if (TAILQ_EMPTY(&rule->tags))
		return (1);

	TAILQ_FOREACH(tag, &rule->tags, entry) {
		if (strcmp(name, tag->name) == 0)
			return (1);
	}

	return (0);
}
