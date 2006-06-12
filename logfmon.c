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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/queue.h>

#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logfmon.h"

#ifdef DEBUG
char	*malloc_options = "AFGJX";
#endif

extern FILE		*yyin;
extern int 		 yyparse(void);

volatile sig_atomic_t	 reload;
volatile sig_atomic_t	 quit;
struct conf		 conf;

int			 reload_conf(void);
int			 load_conf(void);
void			 sighandler(int);
int			 parse_line(char *, struct file *);
void			 usage(void);

void
sighandler(int sig)
{
        switch (sig) {
        case SIGTERM:
                quit = 1;
                break;
        case SIGHUP:
                reload = 1;
                break;
        }
}

int
load_conf(void)
{
        yyin = fopen(conf.conf_file, "r");
        if (yyin == NULL)
                return (1);

        yyparse();

        fclose(yyin);

        return (0);
}

int
reload_conf(void)
{
	log_info("reloading configuration");

	save_cache();

	free_rules();
	free_files(); /* closes too */

	if (load_conf() != 0)
		fatal(conf.conf_file);

	load_cache();

	open_files();
	close_events();
	init_events();

	return (0);
}

int
parse_line(char *line, struct file *file)
{
        char		*t;
        struct rule	*rule;
        regmatch_t	 match[10];
	struct msg	*save;

	if (strlen(line) < 17) {
		log_warnx("invalid log message: %s", line);
		return (1);
	}

	/* replace ctrl chars with _ */
	for (t = line; *t != '\0'; t++) {
		if (*t < 32)
			*t = '_';
	}

	/* skip the hostname and any subsequent spaces and return immediately
	   for blank log messages */
        t = strchr(line + 16, ' ');
        if (t == NULL)
                return (0);
	t++;
        if (*t == '\0')
                return (0);

        TAILQ_FOREACH(rule, &conf.rules, entry) {
		if (!has_tag(rule, file->tag.name))
                        continue;

                if (regexec(rule->re, t, 10, match, 0) != 0)
                        continue;
                if (rule->not_re != NULL &&
		    regexec(rule->not_re, t, 0, NULL, 0) == 0)
			continue;

		/* perform action and return */
                switch (rule->action) {
                case ACT_IGNORE:
                        act_ignore(file, t);
			return (0);
                case ACT_EXEC:
                        act_exec(file, t, rule, match);
			return (0);
                case ACT_PIPE:
                        act_pipe(file, t, rule, match, line);
			return (0);
                case ACT_OPEN:
                        act_open(file, t, rule, match);
			continue; /* falls-through to following rules */
                case ACT_APPEND:
                        act_appd(file, t, rule, match, line);
			continue; /* falls-through to following rules */
                case ACT_CLOSE:
                        act_close(file, t, rule, match);
			continue; /* falls-through to following rules */
                }

		/* NOTREACHED */ /* shut lint up */
		log_warnx("unknown action: %d", rule->action);
		return (1);
        }

	/* no matching rule found */
	log_debug("unmatched: (%s) %s", file->tag.name, t);

        if (conf.mail_cmd != NULL && *conf.mail_cmd != '\0') {
		/* append the line to the saves list */
		LOCK_MUTEX(file->saves_mutex);
		save = xmalloc(sizeof (struct msg));
		save->str = xstrdup(line);
		TAILQ_INSERT_TAIL(&file->saves, save, entry);
		UNLOCK_MUTEX(file->saves_mutex);
        }

	return (0);
}

__dead void
usage(void)
{
	printf("usage: %s [-dv] [-f conffile] [-c cachefile] [-p pidfile]\n",
	    __progname);
        exit(1);
}

int
main(int argc, char **argv)
{
        int		 opt, timeout, dirty, error;
	unsigned int	 failed;
        pthread_t	 thread;
        time_t		 expiretime, cachetime;
        enum event	 event;
        struct file	*file;
        FILE		*fd;
	char		*line;

	bzero(&conf, sizeof conf);
	TAILQ_INIT(&conf.rules);
	TAILQ_INIT(&conf.files);

	log_init(1);

        while ((opt = getopt(argc, argv, "c:df:p:v")) != EOF) {
                switch (opt) {
                case 'c':
                        conf.cache_file = xstrdup(optarg);
                        break;
                case 'd':
                        conf.debug = 1;
                        break;
                case 'f':
                        conf.conf_file = xstrdup(optarg);
                        break;
                case 'p':
                        conf.pid_file = xstrdup(optarg);
                        break;
		case 'v':
			printf("%s " BUILD "\n", __progname);
			exit(1);
                case '?':
                default:
                        usage();
                }
        }

	conf.mail_time = MAILTIME;
	conf.mail_cmd = NULL;

	if (conf.conf_file == NULL)
                conf.conf_file = xstrdup(CONFFILE);

        if (load_conf() != 0) {
                log_warn("%s", conf.conf_file);
		exit(1);
        }

        if (conf.mail_cmd == NULL)
                conf.mail_cmd = xstrdup(MAILCMD);
        if (conf.cache_file == NULL)
                conf.cache_file = xstrdup(CACHEFILE);
        if (conf.pid_file == NULL)
                conf.pid_file = xstrdup(PIDFILE);

        if (TAILQ_EMPTY(&conf.files)) {
                log_warnx("no files specified");
		exit(1);
	}

	log_init(conf.debug);

        if (!conf.debug) {
                if (daemon(0, 0) != 0)
                        fatal("daemon");
        }
        if (setpriority(PRIO_PROCESS, getpid(), 1) != 0)
		fatal("setpriority");

        if (conf.gid != 0) {
                if (geteuid() != 0)
                        fatalx("need root privileges to set group");
                else {
                        if (setgroups(1, &conf.gid) != 0 ||
                            setegid(conf.gid) != 0 || setgid(conf.gid) != 0)
                                fatalx("failed to drop group privileges");
                }
        }
        if (conf.uid != 0) {
                if (geteuid() != 0)
                        fatalx("need root privileges to set user");
                else {
                        if (setuid(conf.uid) != 0 || seteuid(conf.uid) != 0)
                                fatalx("failed to drop user privileges");
                }
        }

        log_info("started");

        load_cache();

        reload = 0;
        quit = 0;

	INIT_MUTEX(conf.files_mutex);
        if (pthread_create(&thread, NULL, save_thread, NULL) != 0)
                fatalx("pthread_create failed");

        if (!conf.debug) {
                if (signal(SIGINT, SIG_IGN) == SIG_ERR)
                        fatalx("signal");
                if (signal(SIGQUIT, SIG_IGN) == SIG_ERR)
                        fatalx("signal");
        }
        if (signal(SIGHUP, sighandler) == SIG_ERR)
                fatalx("signal");
        if (signal(SIGTERM, sighandler) == SIG_ERR)
                fatalx("signal");

        if (conf.pid_file != NULL && *conf.pid_file != '\0') {
                fd = fopen(conf.pid_file, "w");
                if (fd == NULL)
                        log_warn("%s", conf.pid_file);
                else {
                        if (fprintf(fd, "%ld\n", (long) getpid()) == -1)
                                log_warnx("error writing pid");
                        fclose(fd);
                }
        }

        open_files();
        init_events();

        dirty = 0;
        failed = 0;
        expiretime = time(NULL);
	cachetime = time(NULL);

	while (!quit) {
		/* reload config after signal */
                if (reload) {
			reload_conf();
			reload = 0;
                        dirty = 0;
		}

		/* if the check timeout has run out, check for closed files
		   and save the cache if required */
                if ((time(NULL) - expiretime) > EXPIRETIMEOUT) {
			LOCK_MUTEX(conf.files_mutex);
			TAILQ_FOREACH(file, &conf.files, entry)
				expire_contexts(file);
			UNLOCK_MUTEX(conf.files_mutex);
			expiretime = time(NULL);
		}
		if (dirty && (time(NULL) - cachetime) > CACHETIMEOUT) {
			save_cache();
			dirty = 0;
			cachetime = time(NULL);
		}

		/* attempt to reopen closed files */
                if (reopen_files(&failed) > 0) {
			/* if any files successfully reopened, reset the
			   event array */
			close_events();
                        init_events();
		}
		timeout = DEFAULTTIMEOUT;
		/* if any reopens failed, use alternative timeout */
                if (failed > 0)
                        timeout = REOPENTIMEOUT;

		file = find_file_mismatch();
		if (file == NULL) {
			/* get an event */
			file = get_event(&event, timeout);
		} else {
			/* force read event */
			event = EVENT_READ;
			log_debug("file mismatch: size=%lld offset=%lld",
			    file->size, file->offset);
		}

                switch (event) {
                case EVENT_NONE:
                case EVENT_TIMEOUT:
                        break;
                case EVENT_REOPEN:
			log_debug("reopen: tag=%s", file->tag.name);
                        fclose(file->fd);
			file->fd = NULL;
                        break;
                case EVENT_READ:
			log_debug("read: tag=%s", file->tag.name);
			while ((line = getln(file->fd, &error)) != NULL) {
				if (parse_line(line, file) != 0)
					exit(1);
				xfree(line);
				file->offset = ftello(file->fd);
				if (file->size < file->offset)
					file->size = file->offset;
				log_debug("new size=%lld, new offset=%lld",
				    file->size, file->offset);
                        }
                        if (error == 1) {
                                fclose(file->fd);
                                file->fd = NULL;
                        }
                        dirty = 1;
                        break;
                }
        }

	close_events();
        close_files();
        if (conf.pid_file != NULL && *conf.pid_file != '\0')
                unlink(conf.pid_file);

	DESTROY_MUTEX(conf.files_mutex);

        log_info("terminated");

	return (0);
}
