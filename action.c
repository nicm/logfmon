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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef __GLIBC__
#include <stdint.h>
#endif

#include "logfmon.h"

const char *actions[] = { "ignore", "exec", "pipe", "open", "append", 
			  "close", "write", "write-append", NULL };

#define ENSURE_SIZE(buf, len, req) do {					\
	while (len <= (req)) {						\
		if (len > SIZE_MAX / 2)					\
			fatalx("size too large");			\
		len *= 2;						\
		buf = xrealloc(buf, 1, len);				\
	}								\
} while(0)

char *
repl_one(char *src, char *rpl)
{
        char	*buf;
        size_t	 len, pos = 0;

	if (src == NULL || *src == '\0')
		return (NULL);

        len = strlen(src) + 512;
        buf = xmalloc(len);

        while (*src != '\0') {
                if (src[0] == '$' && src[1] == '1') {
			ENSURE_SIZE(buf, len, pos + strlen(rpl));
			strlcpy(buf + pos, rpl, len - pos);
			pos += strlen(rpl);
			src += 2;
			continue;
                }

		ENSURE_SIZE(buf, len, pos + 1);
		*(buf + pos++) = *src++;
        }

	ENSURE_SIZE(buf, len, pos + 1);
        *(buf + pos) = '\0';

        return (buf);
}

char *
repl_matches(char *line, char *src, regmatch_t *match)
{
        char	*buf, *mptr;
        size_t	 len, mlen, pos = 0;
        int	 num;

	if (src == NULL || *src == '\0')
		return (NULL);

        len = strlen(src) + 512;
        buf = xmalloc(len);

        while (*src != '\0') {
                if (src[0] == '$' && isdigit((unsigned char) src[1]) &&
		    !isdigit((unsigned char) src[2])) {
			src++; /* skip $ */
			num = *src - '0';
			mlen = match[num].rm_eo - match[num].rm_so;
			if (mlen > 0) {
				ENSURE_SIZE(buf, len, pos + mlen);
				mptr = line + match[num].rm_so;
				strncpy(buf + pos, mptr, mlen);
				pos += mlen;
				src++; /* skip num */
			} else { /* bad match, copy $ */
				ENSURE_SIZE(buf, len, pos + 1);
				*(buf + pos++) = '$';
			}
			continue;
                }

		ENSURE_SIZE(buf, len, pos + 1);
		*(buf + pos++) = *src++;
        }

	ENSURE_SIZE(buf, len, pos + 1);
	*(buf + pos) = '\0';

        return (buf);
}

void
act_ignore(struct file *file, char *t)
{
	log_debug("matched: (%s) %s -- ignoring", file->tag.name, t);
}

void
act_exec(struct file *file, char *t, struct rule *rule, regmatch_t match[])
{
        char		*cmd;
        pthread_t	 thread;

        cmd = repl_matches(t, rule->params.str, match);
        if (cmd == NULL || *cmd == '\0') {
                log_warnx("empty exec command");
		if (cmd != NULL)
			xfree(cmd);
		return;
	}

	log_debug("matched: (%s) %s -- executing: %s", file->tag.name, t, cmd);

	CREATE_THREAD(&thread, exec_thread, cmd);
}

void
act_pipe(struct file *file, char *t, struct rule *rule, regmatch_t match[],
    char *line)
{
        char		*cmd;
        pthread_t	 thread;
        FILE		*fd;

        cmd = repl_matches(t, rule->params.str, match);
        if (cmd == NULL || *cmd == '\0') {
                log_warnx("empty pipe command");
                if (cmd != NULL)
			xfree(cmd);
		return;
	}

	log_debug("matched: (%s) %s -- piping: %s", file->tag.name, t, cmd);

	fd = popen(cmd, "w");
	if (fd == NULL)
		log_warn("%s", cmd);
	else {
		if (fwrite(line, strlen(line), 1, fd) == 1)
			fputc('\n', fd);
		
		CREATE_THREAD(&thread, pclose_thread, fd);
		
		xfree(cmd);
        }
}

void
act_open(struct file *file, char *t, struct rule *rule, regmatch_t match[])
{
        char	*key;

        key = repl_matches(t, rule->params.key, match);
	if (key == NULL || *key == '\0') {
		log_warnx("empty open key");
		if (key != NULL)
			xfree(key);
		return;
	}

	log_debug("matched: (%s) %s -- opening: '%s'", file->tag.name, t, key);

        if (find_context_by_key(file, key) != NULL) {
		log_debug("ignoring open; found existing context %s", key);
                xfree(key);
                return;
        }

	if (add_context(file, key, rule) == NULL)
		log_warnx("error adding context");

        xfree(key);
}

void
act_appd(struct file *file, char *t, struct rule *rule, regmatch_t match[],
    char *line)
{
        struct context	*context;
	struct msg	*msg;
        char		*key;

        key = repl_matches(t, rule->params.key, match);
	if (key == NULL || *key == '\0') {
		log_warnx("empty append key");
		if (key != NULL)
			xfree(key);
		return;
	}

	log_debug("matched: (%s) %s -- appending: '%s'", file->tag.name, t, 
	    key);

        context = find_context_by_key(file, key);
        if (context == NULL) {
		log_debug("missing context %s for append", key);
                xfree(key);
                return;
        }
        xfree(key);

	msg = xmalloc(sizeof (struct msg));
	msg->str = xstrdup(line);
	TAILQ_INSERT_TAIL(&context->msgs, msg, entry);

        if (context->rule->params.ent_max == 0)
                return;

        if (count_msgs(context) >= context->rule->params.ent_max) {
		log_debug("context %s reached limit of %u entries",
		    context->key, context->rule->params.ent_max);
		
		act_context(context, context->rule->params.ent_act,
		    context->rule->params.ent_str);
                delete_context(file, context);
        }
}

void
act_close(struct file *file, char *t, struct rule *rule, regmatch_t match[])
{
        struct context	*context;
        char		*key, *str;

        key = repl_matches(t, rule->params.key, match);
	if (key == NULL || *key == '\0') {
		log_warnx("empty close key");
		if (key != NULL)
			xfree(key);
		return;
	}

	log_debug("matched: (%s) %s -- closing: '%s'", file->tag.name, t, key);

        context = find_context_by_key(file, key);
        if (context == NULL) {
		log_debug("missing context %s for close", key);
                xfree(key);
                return;
        }
	xfree(key);

	if (rule->params.close_str != NULL)
                str = repl_matches(t, rule->params.close_str, match);
	else
		str = NULL;
	act_context(context, rule->params.close_act, str);
	if (str != NULL)
                xfree(str);

        delete_context(file, context);
}

void
act_write(struct file *file, char *t, struct rule *rule, regmatch_t match[],
    char *line, int append)
{
        char		*path;
        FILE		*fd;

        path = repl_matches(t, rule->params.str, match);
        if (path == NULL || *path == '\0') {
                log_warnx("empty write path");
                if (path != NULL)
			xfree(path);
		return;
	}
	
	log_debug("matched: (%s) %s -- writing: %s", file->tag.name, t, path);

	fd = fopen(path, append ? "a" : "w");
	if (fd == NULL)
		log_warn("%s", path);
	else {
		if (fwrite(line, strlen(line), 1, fd) == 1)
			fputc('\n', fd);
		
		fclose(fd);
		
		xfree(path);
	}
}
