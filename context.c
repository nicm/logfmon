/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicholas.marriott@gmail.com>
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
add_context(struct file *file, char *key, struct rule *rule, char *entry,
    regmatch_t match[10])
{
	struct context	*context;

	context = xmalloc(sizeof (struct context));

	TAILQ_INIT(&context->msgs);

	context->rule = rule;
	context->expiry = time(NULL) + rule->params.exp_time;
	context->key = xstrdup(key);

	context->line = xstrdup(entry);
	memcpy(&context->match, match, sizeof context->match);

	log_debug("added context: key=%s", key);
	TAILQ_INSERT_TAIL(&file->contexts, context, entry);
	return (context);
}

void
free_context(struct context *context)
{
	reset_context(context);

	xfree(context->line);
	xfree(context->key);
	xfree(context);
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
		xfree(msg->str);
		xfree(msg);
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
	struct msg	*msg;
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
	time_t			 now;

	now = time(NULL);
	TAILQ_INIT(&exp_contexts);

	TAILQ_FOREACH(context, &file->contexts, entry) {
		if (now >= context->expiry) {
			log_debug("expired context: key=%s", context->key);
			act_context(context, context->rule->params.exp_act,
			    context->rule->params.exp_str, 1);
			TAILQ_INSERT_HEAD(&exp_contexts, context, exp_entry);
		}
	}

	while (!TAILQ_EMPTY(&exp_contexts)) {
		context = TAILQ_FIRST(&exp_contexts);
		TAILQ_REMOVE(&exp_contexts, context, exp_entry);
		delete_context(file, context);
	}
}

void
act_context(struct context *context, enum action act, char *str, int repl)
{
	if (repl)
		str = repl_matches(context->line, str, context->match);

	log_debug("acting on context: action=%s, target=%s",
	    actions[act], str);
	switch (act) {
	case ACT_IGNORE:
		break;
	case ACT_EXEC:
		exec_context(str);
		break;
	case ACT_PIPE:
		pipe_context(context, str);
		break;
	case ACT_WRITE:
		write_context(context, str, 0);
		break;
	case ACT_WRITEAPPEND:
		write_context(context, str, 1);
		break;
	case ACT_OPEN:
	case ACT_APPEND:
	case ACT_CLOSE:
		log_warnx("action invalid here: %s", actions[act]);
		break;
	default:
		log_warnx("unknown action: %d\n", act);
		break;
	}

	if (repl && str != NULL)
		xfree(str);
}

void
pipe_context(struct context *context, char *cmd)
{
	FILE		*fd;
	struct msg	*msg;
	pthread_t	 thread;

	if (cmd == NULL || *cmd == '\0') {
		log_warnx("empty pipe command");
		return;
	}

	fd = popen(cmd, "w");
	if (fd == NULL) {
		log_warn("%s", cmd);
		return;
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

	CREATE_THREAD(&thread, pclose_thread, fd);
}

void
exec_context(char *cmd)
{
	pthread_t	 thread;

	if (cmd == NULL || *cmd == '\0') {
		log_warnx("empty exec command");
		return;
	}

	CREATE_THREAD(&thread, exec_thread, xstrdup(cmd));
}

void
write_context(struct context *context, char *path, int append)
{
	FILE		*fd;
	struct msg	*msg;

	if (path == NULL || *path == '\0') {
		log_warnx("empty write path");
		return;
	}

	fd = fopen(path, append ? "a" : "w");
	if (fd == NULL) {
		log_warn("%s", path);
		return;
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

	fclose(fd);
}
