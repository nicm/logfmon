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

#include <sys/queue.h>

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
	bzero(rule, sizeof (struct rule));

	TAILQ_INIT(&rule->tags);
	TAILQ_FOREACH(tag, &tags->tags, entry) {
		TAILQ_INSERT_HEAD(&rule->tags, tag, entry);
	}
	free(tags);

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

	log_debug("added rule: re=%s, not_re=%s, action=%d",
	    re, not_re, action);
	TAILQ_INSERT_HEAD(&conf.rules, rule, entry);
        return (rule);
}

void
free_rule(struct rule *rule)
{
	struct tag	*tag;

	while (!TAILQ_EMPTY(&rule->tags)) {
		tag = TAILQ_FIRST(&rule->tags);
		TAILQ_REMOVE(&rule->tags, tag, entry);
		free(tag);
	}

	if (rule->re != NULL) {
		regfree(rule->re);
		free(rule->re);
	}
	if (rule->not_re != NULL) {
		regfree(rule->not_re);
		free(rule->not_re);
	}

	if (rule->params.cmd != NULL)
		free(rule->params.cmd);
	if (rule->params.key != NULL)
		free(rule->params.key);

	free(rule);
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

	TAILQ_FOREACH(tag, &rule->tags, entry) {
		if (strcmp(name, tag->name) == 0)
			return (1);
	}

	return (0);
}
