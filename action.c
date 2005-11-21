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

#include <stdlib.h>
#include <string.h>

#include "logfmon.h"

void
act_ignore(struct file *file, char *t)
{
	log_debug("matched: (%s) %s -- ignoring", file->tag.name, t);
}

void
act_exec(struct file *file, char *t, struct rule *rule, regmatch_t match[])
{
        char		*s;
        pthread_t	 thread;

        s = repl_matches(t, rule->params.cmd, match);

	log_debug("matched: (%s) %s -- executing: %s", file->tag.name, t, s);

        if (s == NULL || *s == '\0') {
                log_warnx("empty command for exec");
                free(s);
        } else {
                if (pthread_create(&thread, NULL, exec_thread, s) != 0)
                        fatalx("pthread_create failed");
        }
}

void
act_pipe(struct file *file, char *t, struct rule *rule, regmatch_t match[],
    char *line)
{
        char		*s;
        pthread_t	 thread;
        FILE		*fd;

        if (rule->params.cmd == NULL || *(rule->params.cmd) == '\0')
                return;

        s = repl_matches(t, rule->params.cmd, match);

	log_debug("matched: (%s) %s -- piping: %s", file->tag.name, t, s);

        if (s == NULL || *s == '\0') {
                log_warnx("empty command for pipe");
                free(s);
        } else {
                fd = popen(s, "w");
                if (fd == NULL)
                        log_warn(s);
                else {
                        if (fwrite(line, strlen(line), 1, fd) == 1)
                                fputc('\n', fd);

                        if (pthread_create(&thread, NULL, pclose_thread,
			    fd) != 0)
                                fatalx("pthread_create failed");

                        free(s);
                }
        }
}

void
act_open(struct file *file, char *t, struct rule *rule, regmatch_t match[])
{
        char	*s;

        if (rule->params.key == NULL || *(rule->params.key) == '\0')
                return;

        s = repl_matches(t, rule->params.key, match);

	log_debug("matched: (%s) %s -- opening: '%s'", file->tag.name, t, s);

        if (find_context_by_key(file, s) != NULL) {
		log_debug("ignoring open; found existing context %s", s);
                free(s);
                return;
        }

	if (add_context(file, s, rule) == NULL)
		log_warnx("error adding context");

        free(s);
}

void
act_appnd(struct file *file, char *t, struct rule *rule, regmatch_t match[],
    char *line)
{
        struct context	*context;
	struct msg	*msg;
        char		*s;

        if (rule->params.key == NULL || *(rule->params.key) == '\0')
                return;

        s = repl_matches(t, rule->params.key, match);

	log_debug("matched: (%s) %s -- appending: '%s'", file->tag.name, t, s);

        context = find_context_by_key(file, s);
        if (context == NULL) {
		log_debug("missing context %s for append", s);
                free(s);
                return;
        }
        free(s);

	msg = xmalloc(sizeof (struct msg));
	msg->str = xstrdup(line);
	TAILQ_INSERT_TAIL(&context->msgs, msg, entry);

        if (context->rule->params.ent_max == 0)
                return;

        if (count_msgs(context) >= context->rule->params.ent_max) {
		log_debug("context %s reached limit of %d entries",
		    context->key, context->rule->params.ent_max);

                if (context->rule->params.ent_cmd != NULL)
                        pipe_context(context,
                            context->rule->params.ent_cmd);

                delete_context(file, context);
        }
}

void
act_close(struct file *file, char *t, struct rule *rule, regmatch_t match[])
{
        char		*s;
        struct context	*context;

        if (rule->params.key == NULL || *(rule->params.key) == '\0')
                return;

        s = repl_matches(t, rule->params.key, match);

	log_debug("matched: (%s) %s -- closing: '%s'", file->tag.name, t, s);

        context = find_context_by_key(file, s);
        if (context == NULL) {
		log_debug("missing context %s for close", s);
                free(s);
                return;
        }
        free(s);

        if (rule->params.cmd != NULL && *(rule->params.cmd) != '\0') {
                s = repl_matches(t, rule->params.cmd, match);
                pipe_context(context, s);
                free(s);
        }

        delete_context(file, context);
}
