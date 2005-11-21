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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "logfmon.h"

void	free_context(struct context *);

struct context *
add_context(struct file *file, char *key, struct rule *rule)
{
        struct context	*context;

        context = xmalloc(sizeof (struct context));

	TAILQ_INIT(&context->msgs);

        context->rule = rule;
        context->expiry = time(NULL) + rule->params.expiry;
        context->key = xstrdup(key);

	log_debug("added context: key=%s", key);
	TAILQ_INSERT_HEAD(&file->contexts, context, entry);
        return (context);
}

void
free_context(struct context *context)
{
	reset_context(context);

	free(context->key);
	free(context);
}

void
free_contexts(struct file *file)
{
        struct context	*context;

	while (!TAILQ_EMPTY(&file->contexts)) {
		context = TAILQ_FIRST(&file->contexts);
		TAILQ_REMOVE(&file->contexts, context, entry);
		free_context(context);
	}
}

void
reset_context(struct context *context)
{
	struct msg	*msg;

	while (!TAILQ_EMPTY(&context->msgs)) {
		msg = TAILQ_FIRST(&context->msgs);
		TAILQ_REMOVE(&context->msgs, msg, entry);
		free(msg->str);
		free(msg);
	}
}

void
delete_context(struct file *file, struct context *context)
{
	log_debug("removed context: key=%s", context->key);
	TAILQ_REMOVE(&file->contexts, context, entry);
	free_context(context);

}

struct context *
find_context_by_key(struct file *file, char *key)
{
        struct context	*context;

	TAILQ_FOREACH(context, &file->contexts, entry) {
                if (strcmp(context->key, key) == 0)
                        return (context);
        }

        return (NULL);
}

unsigned int
count_msgs(struct context *context)
{
        struct msg 	*msg;
        unsigned int	 n;

        n = 0;
	TAILQ_FOREACH(msg, &context->msgs, entry)
		n++;

	return (n);
}

void
expire_contexts(struct file *file)
{
        struct context		*context;
	TAILQ_HEAD(, context)	 exp_contexts;
        time_t		 	 now;

        now = time(NULL);
	TAILQ_INIT(&exp_contexts);

	TAILQ_FOREACH(context, &file->contexts, entry) {
                if (now >= context->expiry) {
			log_debug("expired context: key=%s", context->key);
                        if (context->rule != NULL &&
			    context->rule->params.cmd != NULL)
                                pipe_context(context,
				    context->rule->params.cmd);
			TAILQ_INSERT_HEAD(&exp_contexts, context,
			    exp_entry);
                }
        }

	while (!TAILQ_EMPTY(&exp_contexts)) {
		context = TAILQ_FIRST(&exp_contexts);
		TAILQ_REMOVE(&exp_contexts, context, exp_entry);
		delete_context(file, context);
	}
}

int
pipe_context(struct context *context, char *cmd)
{
        FILE		*fd;
        struct msg	*msg;
        pthread_t	 thread;
	char		*s;

        if (cmd == NULL || *cmd == '\0') {
                log_warnx("empty pipe command");
                return (1);
        }

        s = repl_one(cmd, context->key);

        fd = popen(s, "w");
        if (fd == NULL) {
                log_warn(s);
                free(s);
                return (1);
        }
	TAILQ_FOREACH(msg, &context->msgs, entry) {
                if (fwrite(msg->str, strlen(msg->str), 1, fd) != 1) {
			log_warn("fwrite");
                        break;
		}
                if (fputc('\n', fd) == EOF) {
			log_warn("fputc");
                        break;
		}
        }

        if (pthread_create(&thread, NULL, pclose_thread, fd) != 0)
                fatalx("pthread_create failed");

        free(s);

        return 0;
}
