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
#include <stdlib.h>
#include <string.h>

#include "logfmon.h"

#define ENSURE_SIZE(buf, len, req) do {					\
	while (len <= (req)) {						\
		len *= 2;						\
		buf = xrealloc(buf, len);				\
	}								\
} while(0)

char *
repl_one(char *src, char *rpl)
{
        char	*buf;
        size_t	 len, pos = 0;

        len = strlen(src) + 512;
        buf = xmalloc(len);

        while (*src != '\0') {
                if (src[0] == '$' && src[1] == '1') {
			ENSURE_SIZE(buf, len, pos + strlen(rpl));
			strlcpy(buf + pos, rpl, len - pos);
			pos += strlen(rpl);
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

        len = strlen(src) + 512;
        buf = xmalloc(len);

        while (*src != '\0') {
                if (src[0] == '$' && isdigit((unsigned char) src[1]) &&
		    !isdigit((unsigned char) src[2])) {
			src++; /* skip $ */
			num = *src - '0';
			mlen = (size_t) (match[num].rm_eo - match[num].rm_so);
			if (mlen > 0) {
				ENSURE_SIZE(buf, len, pos + mlen);
				mptr = line + (size_t) match[num].rm_so;
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
        char		*cmd;
        pthread_t	 thread;
        FILE		*fd;

        if (rule->params.cmd == NULL || *(rule->params.cmd) == '\0')
                return;

        cmd = repl_matches(t, rule->params.cmd, match);

	log_debug("matched: (%s) %s -- piping: %s", file->tag.name, t, cmd);

        if (cmd == NULL || *cmd == '\0') {
                log_warnx("empty command for pipe");
                free(cmd);
        } else {
                fd = popen(cmd, "w");
                if (fd == NULL)
                        log_warn("%s", cmd);
                else {
                        if (fwrite(line, strlen(line), 1, fd) == 1)
                                fputc('\n', fd);

                        if (pthread_create(&thread, NULL, pclose_thread,
			    fd) != 0)
                                fatalx("pthread_create failed");

                        free(cmd);
                }
        }
}

void
act_open(struct file *file, char *t, struct rule *rule, regmatch_t match[])
{
        char	*key;

        if (rule->params.key == NULL || *(rule->params.key) == '\0')
                return;

        key = repl_matches(t, rule->params.key, match);

	log_debug("matched: (%s) %s -- opening: '%s'", file->tag.name, t, key);

        if (find_context_by_key(file, key) != NULL) {
		log_debug("ignoring open; found existing context %s", key);
                free(key);
                return;
        }

	if (add_context(file, key, rule) == NULL)
		log_warnx("error adding context");

        free(key);
}

void
act_appd(struct file *file, char *t, struct rule *rule, regmatch_t match[],
    char *line)
{
        struct context	*context;
	struct msg	*msg;
        char		*key;

        if (rule->params.key == NULL || *(rule->params.key) == '\0')
                return;

        key = repl_matches(t, rule->params.key, match);

	log_debug("matched: (%s) %s -- appending: '%s'",
	    file->tag.name, t, key);

        context = find_context_by_key(file, key);
        if (context == NULL) {
		log_debug("missing context %s for append", key);
                free(key);
                return;
        }
        free(key);

	msg = xmalloc(sizeof (struct msg));
	msg->str = xstrdup(line);
	TAILQ_INSERT_TAIL(&context->msgs, msg, entry);

        if (context->rule->params.ent_max == 0)
                return;

        if (count_msgs(context) >= context->rule->params.ent_max) {
		log_debug("context %s reached limit of %u entries",
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
        char		*cmd;
        struct context	*context;

        if (rule->params.key == NULL || *(rule->params.key) == '\0')
                return;

        cmd = repl_matches(t, rule->params.key, match);

	log_debug("matched: (%s) %s -- closing: '%s'", file->tag.name, t, cmd);

        context = find_context_by_key(file, cmd);
        if (context == NULL) {
		log_debug("missing context %s for close", cmd);
                free(cmd);
                return;
        }
        free(cmd);

        if (rule->params.cmd != NULL && *(rule->params.cmd) != '\0') {
                cmd = repl_matches(t, rule->params.cmd, match);
                pipe_context(context, cmd);
                free(cmd);
        }

        delete_context(file, context);
}
