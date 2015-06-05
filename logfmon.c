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
 
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "logfmon.h"

#ifdef NO_PROGNAME
const char	*__progname = "logfmon";
#endif

volatile sig_atomic_t	 reload;
volatile sig_atomic_t	 quit;
struct conf		 conf;

int			 reload_conf(void);
void			 sighandler(int);
int			 read_lines(struct file *);
char			*read_line(struct file *, int *);
int			 parse_line(char *, struct file *);
void			 usage(void);
void			 do_stdin(void);

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
reload_conf(void)
{
	log_info("reloading configuration");

	save_cache();

	free_rules();
	free_files(); /* closes too */

	if (parse_conf(conf.conf_file) != 0)
		log_fatal(conf.conf_file);

	load_cache();

	open_files();
	reinit_events();

	return (0);
}

int
read_lines(struct file *file)
{
	char	*line;
	int	 error;

	while ((line = read_line(file, &error)) != NULL) {
		if (parse_line(line, file) != 0)
			exit(1);
		xfree(line);		
	}
	if (!error)
		file->offset = ftello(file->fd);
	
	return (error);
}

char *
read_line(struct file *file, int *error)
{
	char	*buf;
	size_t	 len;
	int	 eol;

	buf = getln(file->fd, error, &eol, &len); 
	if (buf == NULL)
		return (NULL);

	if (file->buf == NULL) {
		/* no previous buffer and a complete read. return the line */
		if (eol)
			return (buf);
		/* no previous buffer and partial read. save this as buffer */
		file->buf = buf;
		file->buflen = len;
		file->bufused = len;
		return (NULL);
	}
	
	/* there is an existing buffer, so expand it to fit if necessary.  add
	   an extra byte on to the length in case the data is finished and we
	   need to add a \0 */
	ENSURE_SIZE(file->buf, file->buflen, file->bufused + len + 1);

	/* append our data, if any, and free the old buffer */
	if (len != 0) {
		memcpy(file->buf + file->bufused, buf, len);
		file->bufused += len;
	}
	xfree(buf);
	
	/* if the new data didn't include an EOL, it cannot be returned yet */
	if (!eol)
		return (NULL);

	/* the buffer holds a complete line, so return it. note that the
	   various getln functions should never return /more/ than a line
	   (ie any data after a \n) so we do not need to worry about leftover 
	   data in the buffer */
	file->buf[file->bufused] = '\0';
	buf = file->buf;
	file->buf = NULL;
	return (buf);
}

int
parse_line(char *line, struct file *file)
{
	char		*entry, *s;
	struct rule	*rule;
	regmatch_t	 match[10];
	struct msg	*save;
	size_t		 mlen;

	/* ignore blank lines */
	if (*line == '\0')
		return (0);
	
	/* replace ctrl chars with _ */
	for (s = line; *s != '\0'; s++) {
		if (*s < 32)
			*s = '_';
	}

	/* extract the part we want from the log line */
	if (regexec(&conf.entry_re, line, 2, match, 0) != 0) {
		log_warnx("invalid log message: %s", line);
		return (0);
	}
	mlen = match[1].rm_eo - match[1].rm_so;
	if (mlen == 0) {
		log_warnx("invalid log message: %s", line);
		return (0);
	}
	entry = xmalloc(mlen + 1);
	memcpy(entry, line + match[1].rm_so, mlen);
	entry[mlen] = '\0';
	if (conf.debug > 1)
		log_debug("found entry: %s", entry);

	TAILQ_FOREACH(rule, &conf.rules, entry) {
		if (!has_tag(rule, file->tag.name))
			continue;

		if (regexec(rule->re, entry, 10, match, 0) != 0)
			continue;
		if (rule->not_re != NULL &&
		    regexec(rule->not_re, entry, 0, NULL, 0) == 0)
			continue;

		/* perform action and return */
		switch (rule->action) {
		case ACT_IGNORE:
			act_ignore(file, entry);
			goto done;
		case ACT_EXEC:
			act_exec(file, entry, rule, match);
			goto done;
		case ACT_PIPE:
			act_pipe(file, entry, rule, match, line);
			goto done;
		case ACT_OPEN:
			act_open(file, entry, rule, match);
			continue; /* falls-through to following rules */
		case ACT_APPEND:
			act_appd(file, entry, rule, match, line);
			continue; /* falls-through to following rules */
		case ACT_CLOSE:
			act_close(file, entry, rule, match);
			continue; /* falls-through to following rules */
		case ACT_CLEAR:
			act_clear(file, entry, rule, match);
			continue; /* falls-through to following rules */
		case ACT_WRITE:
			act_write(file, entry, rule, match, line, 0);
			goto done;
		case ACT_WRITEAPPEND:
			act_write(file, entry, rule, match, line, 1);
			goto done;
		}

		/* NOTREACHED */ /* shut lint up */
		log_warnx("unknown action: %d", rule->action);
		goto error;
	}

	/* no matching rule found */
	log_debug("unmatched: (%s) %s", file->tag.name, entry);

	if (conf.mail_cmd != NULL && *conf.mail_cmd != '\0') {
		/* append the line to the saves list */
		LOCK_MUTEX(file->saves_mutex);
		save = xmalloc(sizeof (struct msg));
		save->str = xstrdup(line);
		TAILQ_INSERT_TAIL(&file->saves, save, entry);
		UNLOCK_MUTEX(file->saves_mutex);
	}

done:
	xfree(entry);
	return (0);

error:
	xfree(entry);
	return (1);
}

__dead void
usage(void)
{
	printf("usage: %s [-dsv] [-f conffile] [-c cachefile] [-p pidfile]\n",
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
	off_t		 size;
	u_int		 i, n;

	memset(&conf, 0, sizeof conf);
	TAILQ_INIT(&conf.rules);
	TAILQ_INIT(&conf.files);

	while ((opt = getopt(argc, argv, "c:df:p:sv")) != EOF) {
		switch (opt) {
		case 'c':
			conf.cache_file = xstrdup(optarg);
			break;
		case 'd':
			conf.debug++;
			break;
		case 'f':
			conf.conf_file = xstrdup(optarg);
			break;
		case 'p':
			conf.pid_file = xstrdup(optarg);
			break;
		case 's':
			conf.use_stdin = 1;
			break;
		case 'v':
			printf("%s " BUILD "\n", __progname);
			exit(1);
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

	if (conf.debug)
		log_open(stderr, LOG_DAEMON, conf.debug);
	else
		log_open(NULL, LOG_DAEMON, conf.debug);

	conf.thr_limit = THREADLIMIT;
	INIT_MUTEX(conf.thr_mutex);
	if (pthread_cond_init(&conf.thr_cond, NULL) != 0) 
		log_fatalx("pthread_cond_init failed");

	if (regcomp(&conf.entry_re, LOGREGEXP, REG_EXTENDED) != 0)
		log_fatalx("invalid log regexp: " LOGREGEXP);

	conf.mail_time = MAILTIME;
	conf.mail_cmd = NULL;

	if (conf.conf_file == NULL)
		conf.conf_file = xstrdup(CONFFILE);
	INIT_MUTEX(conf.files_mutex);

	if (parse_conf(conf.conf_file) != 0) {
		log_warn("%s", conf.conf_file);
		exit(1);
	}

	if (conf.mail_cmd == NULL)
		conf.mail_cmd = xstrdup(MAILCMD);
	if (conf.cache_file == NULL)
		conf.cache_file = xstrdup(CACHEFILE);
	if (conf.pid_file == NULL)
		conf.pid_file = xstrdup(PIDFILE);

	if (!conf.use_stdin && TAILQ_EMPTY(&conf.files)) {
		log_warnx("no files specified");
		exit(1);
	}

	if (!conf.debug && !conf.use_stdin && daemon(0, 0) != 0)
		log_fatal("daemon");

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

	if (setpriority(PRIO_PROCESS, getpid(), 1) != 0)
		log_fatal("setpriority");

	if (conf.gid != 0) {
		if (geteuid() != 0)
			log_fatalx("need root privileges to set group");
		else {
			if (setgroups(1, &conf.gid) != 0 ||
			    setegid(conf.gid) != 0 || setgid(conf.gid) != 0)
				log_fatalx("failed to drop group privileges");
		}
	}
	if (conf.uid != 0) {
		if (geteuid() != 0)
			log_fatalx("need root privileges to set user");
		else {
			if (setuid(conf.uid) != 0 || seteuid(conf.uid) != 0)
				log_fatalx("failed to drop user privileges");
		}
	}

	log_info("started");

	reload = 0;
	quit = 0;

	if (pthread_create(&thread, NULL, save_thread, NULL) != 0)
		log_fatalx("pthread_create failed");

	if (!conf.debug && !conf.use_stdin) {
		if (signal(SIGINT, SIG_IGN) == SIG_ERR)
			log_fatalx("signal");
		if (signal(SIGQUIT, SIG_IGN) == SIG_ERR)
			log_fatalx("signal");
	}
	if (signal(SIGHUP, sighandler) == SIG_ERR)
		log_fatalx("signal");
	if (signal(SIGTERM, sighandler) == SIG_ERR)
		log_fatalx("signal");

	/* special-case stdin */
	if (conf.use_stdin) {
		do_stdin();
		goto out;
	}
 
	load_cache();
	open_files();

	/* read as much of files as possible before entering main loop. this
	   deals with the anything added since last cache write and gets up to
	   date on new files */
	TAILQ_FOREACH(file, &conf.files, entry) {
		if (file->fd == NULL || file_size(file, &size) != 0) 
			continue;

		if (file->offset < size) {
			log_debug("mismatch: tag=%s", file->tag.name);
			if ((error = read_lines(file)) != 0) {
				if (error == EINTR || error == EAGAIN)
					continue;
				fclose(file->fd);
				file->fd = NULL;
			} else
				log_debug("new offset=%lld", file->offset);
		}
	}
	log_debug("initial parse complete");
	save_cache();

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
			reinit_events();
		}
		timeout = DEFAULTTIMEOUT;
		/* if any reopens failed, use alternative timeout */
		if (failed > 0)
			timeout = REOPENTIMEOUT;

		/* get an event */
		file = get_event(&event, timeout);
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
			if (read_lines(file) != 0) {
				fclose(file->fd);
				file->fd = NULL;
			} else
				log_debug("new offset=%lld", file->offset);
			dirty = 1;
			break;
		}
	}

	close_events();

out:
	/* free files. this will wait on files_mutex for the save thread to
	   finish if it is going */
	free_files();	
	DESTROY_MUTEX(conf.files_mutex);

	/* wait some time for all threads to exit */
	LOCK_MUTEX(conf.thr_mutex);
	n = conf.thr_count * 5;
	log_debug("waiting %u seconds for %d threads", n, conf.thr_count);
	for (i = 0; i < n; i++) {
		if (conf.thr_count == 0)
			break;
		UNLOCK_MUTEX(conf.thr_mutex);
		sleep(1);
		LOCK_MUTEX(conf.thr_mutex);
	}
	UNLOCK_MUTEX(conf.thr_mutex);

	if (conf.pid_file != NULL && *conf.pid_file != '\0')
		unlink(conf.pid_file);

	log_info("terminated");

	return (0);
}

void
do_stdin(void)
{
	struct file	*stdin_file;
	int		 flags, error;
	char		*line;
	time_t		 expiretime;
	struct pollfd	 pfd;

	setlinebuf(stdin);
	if ((flags = fcntl(fileno(stdin), F_GETFL)) < 0)
		log_fatal("fcntl");
	flags |= O_NONBLOCK;
	if (fcntl(fileno(stdin), F_SETFL, flags) < 0)
		log_fatal("fcntl");

restart:
	stdin_file = xcalloc(1, sizeof *stdin_file);

	TAILQ_INIT(&stdin_file->saves);
	INIT_MUTEX(stdin_file->saves_mutex);

	TAILQ_INIT(&stdin_file->contexts);

	strlcpy(stdin_file->tag.name, "stdin", sizeof stdin_file->tag.name);
	stdin_file->fd = stdin;
	stdin_file->path = xstrdup("stdin");

	LOCK_MUTEX(conf.files_mutex);
	TAILQ_INSERT_TAIL(&conf.files, stdin_file, entry);
	UNLOCK_MUTEX(conf.files_mutex);

	expiretime = time(NULL);	
	while (!quit) {
		if (reload) {
			stdin_file->fd = NULL;
			reload_conf();
			reload = 0;
			goto restart;
		}

		pfd.fd = fileno(stdin);
		pfd.events = POLLIN;
		if ((error = poll(&pfd, 1, EXPIRETIMEOUT * 1000)) < 0) {
			if (error == EINTR)
				continue;
			log_fatal("poll");
		}

		/* expire contexts before reading lines */
		if ((time(NULL) - expiretime) > EXPIRETIMEOUT) {
			LOCK_MUTEX(conf.files_mutex);
			expire_contexts(stdin_file);
			UNLOCK_MUTEX(conf.files_mutex);
			expiretime = time(NULL);
		}


		line = read_line(stdin_file, &error);
		if (error == EINTR || error == EAGAIN)
			continue;

		if (line != NULL) {
			if (parse_line(line, stdin_file) != 0)
				exit(1);
			xfree(line);
		} else {
			/* warn about errors, but not about EOF */
			if (error != 0) {
				log_warnx("error from stdin. exiting");
				exit(1);
			}
			log_debug("EOF from stdin");
			break;
		}		
	}
}
