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

#ifndef LOGFMON_H
#define LOGFMON_H

#include <sys/types.h>

#ifdef NO_QUEUE_H
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#include <signal.h>
#include <regex.h>
#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>

#define MAXTAGLEN	32

#define MAILTIME	900
#define MAILCMD		"/usr/bin/mail root"

#define CONFFILE	"/etc/logfmon.conf"
#define CACHEFILE	"/var/db/logfmon.cache"
#define PIDFILE		"/var/run/logfmon.pid"

#define EXPIRETIMEOUT	10	/* context expiry check time */
#define CACHETIMEOUT	10	/* cache save check time */
#define DEFAULTTIMEOUT	5	/* default event timeout */
#define REOPENTIMEOUT	2	/* event timeout if waiting to reopen files */

#ifndef __dead
#define __dead
#endif

#ifndef TAILQ_FIRST
#define TAILQ_FIRST(head) (head)->tqh_first
#endif
#ifndef TAILQ_END
#define TAILQ_END(head) NULL
#endif
#ifndef TAILQ_NEXT
#define TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)
#endif
#ifndef TAILQ_FOREACH
#define TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST(head);					\
	     (var) != TAILQ_END(head);				 	\
	     (var) = TAILQ_NEXT(var, field))
#endif
#ifndef TAILQ_EMPTY
#define TAILQ_EMPTY(head) (TAILQ_FIRST(head) == TAILQ_END(head))
#endif

#define INIT_MUTEX(mutex) do {						\
	if (pthread_mutex_init(&(mutex), NULL) != 0) {		 	\
		log_warnx("pthread_mutex_init failed: %s:%d",		\
		__FILE__, __LINE__);		 			\
		exit(1);						\
	}							 	\
} while (0)

#define DESTROY_MUTEX(mutex) do {					\
	int	mtx_error;					 	\
	while ((mtx_error = pthread_mutex_destroy(&(mutex))) != 0) { 	\
		if (mtx_error == EBUSY)				 	\
			continue;				 	\
		log_warnx("pthread_mutex_destroy failed: %s:%d", 	\
		__FILE__, __LINE__);		 		 	\
		exit(1);					 	\
	}							 	\
} while (0)

#define LOCK_MUTEX(mutex) do {						\
	if (pthread_mutex_lock(&(mutex)) != 0) {			\
		log_warnx("pthread_mutex_lock failed: %s:%d",		\
		__FILE__, __LINE__);		 			\
		exit(1);						\
	}								\
} while (0)

#define UNLOCK_MUTEX(mutex) do {                        		\
	if (pthread_mutex_unlock(&(mutex)) != 0) {			\
		log_warnx("pthread_mutex_unlock failed: %s:%d",		\
		__FILE__, __LINE__);		 			\
		exit(1);					 	\
	}							 	\
} while (0)

extern char			*__progname;

extern volatile sig_atomic_t	 reload;
extern volatile sig_atomic_t	 quit;

/* Event types */
enum event {
        EVENT_NONE,
        EVENT_TIMEOUT,
        EVENT_REOPEN,
        EVENT_READ
};

/* Tag entry */
struct tag {
        char			 name[MAXTAGLEN];

	TAILQ_ENTRY(tag)	 entry;
};

/* Tag list */
struct tags {
	TAILQ_HEAD(, tag)	 tags;
};

/* Message entry */
struct msg {
        char			*str;

        TAILQ_ENTRY(msg)	 entry;
};

/* Context entry */
struct context {
        char			*key;
        time_t			 expiry;

        struct rule		*rule;
	TAILQ_HEAD(, msg)	 msgs;

	TAILQ_ENTRY(context)	 entry;
	TAILQ_ENTRY(context)	 exp_entry;
};

/* Rule actions */
enum action {
        ACT_IGNORE,
        ACT_EXEC,
        ACT_PIPE,
        ACT_OPEN,
        ACT_APPEND,
        ACT_CLOSE
};

/* Rule entry */
struct rule {
	TAILQ_HEAD(, tag)	 tags;

        regex_t			*re;
        regex_t			*not_re;

        enum action	 	 action;

        struct
        {
                char		*cmd;
                char		*key;
                time_t		 expiry;

                unsigned int	 ent_max;
                char		*ent_cmd;
        } params;

        TAILQ_ENTRY(rule)	 entry;
};

/* File entry */
struct file {
        time_t		 	 timer;

        char			*path;
	struct tag		 tag;

        FILE			*fd;

        off_t		 	 size;
        off_t		 	 offset;

        TAILQ_HEAD(, context)	 contexts;
	TAILQ_HEAD(, msg)	 saves;
	pthread_mutex_t		 saves_mutex;

	TAILQ_ENTRY(file)	 entry;
};

/* Configuration settings */
struct conf {
	int 			 debug;

	char 			*mail_cmd;
	unsigned int 		 mail_time;

	uid_t 			 uid;
	gid_t			 gid;

	char			*conf_file;
	char			*cache_file;
	char			*pid_file;

	TAILQ_HEAD(, rule)	 rules;
	TAILQ_HEAD(, file)	 files;

	/* Files list mutex. Since entries only can be added and deleted in the
	   main thread, for iterating this mutex only needs to be held in the
	   save thread. */
	pthread_mutex_t		 files_mutex;
};
extern struct conf		 conf;

#ifdef NO_STRLCPY
/* strlcpy.c */
size_t	 strlcpy(char *, const char *, size_t);
#endif

#ifdef NO_DAEMON
/* daemon.c */
int	 daemon(int, int);
#endif

#ifdef NO_ASPRINTF
/* asprintf.c */
int	asprintf(char **, const char *, ...);
int	vasprintf(char **, const char *, va_list);
#endif

/* action.c */
char	*repl_one(char *, char *);
char	*repl_matches(char *, char *, regmatch_t *);
void	 act_ignore(struct file *, char *);
void	 act_exec(struct file *, char *, struct rule *, regmatch_t []);
void	 act_pipe(struct file *, char *, struct rule *, regmatch_t [], char *);
void	 act_open(struct file *, char *, struct rule *, regmatch_t []);
void	 act_appd(struct file *, char *, struct rule *, regmatch_t [], char *);
void	 act_close(struct file *, char *, struct rule *, regmatch_t []);

/* cache.c */
int		 save_cache(void);
int		 load_cache(void);

/* context.c */
struct context	*add_context(struct file *, char *, struct rule *);
void		 free_contexts(struct file *);
void		 reset_context(struct context *);
void		 delete_context(struct file *, struct context *);
struct context	*find_context_by_key(struct file *, char *);
void		 expire_contexts(struct file *);
void		 pipe_context(struct context *, char *);
unsigned int	 count_msgs(struct context *);

/* event.c */
void		 init_events(void);
void		 close_events(void);
struct file 	*get_event(enum event *, int timeout);

/* file.c */
struct file	*add_file(char *, char *);
void		 free_files(void);
void		 reset_file(struct file *);
unsigned int	 count_open_files(void);
void		 open_files(void);
unsigned int	 reopen_files(unsigned int *);
void		 close_files(void);
struct file 	*find_file_by_tag(char *);
struct file 	*find_file_by_path(char *);
struct file 	*find_file_by_fd(int);
struct file	*find_file_mismatch(void);

/* getln.c */
char		*getln(FILE *, int *);

/* log.c */
void		 log_init(int);
void    	 vlog(int, const char *, va_list);
void		 log_warn(const char *, ...);
void		 log_warnx(const char *, ...);
void		 log_info(const char *, ...);
void		 log_debug(const char *, ...);
__dead void	 fatal(const char *);
__dead void	 fatalx(const char *);

/* rules.c */
struct rule	*add_rule(enum action, struct tags *, char *, char *);
void		 free_rules(void);
int		 has_tag(struct rule *, char *);

/* threads.c */
void		*pclose_thread(void *);
void		*exec_thread(void *);
void		*save_thread(void *);

/* xmalloc.c */
char		*xstrdup(const char *);
void		*xcalloc(size_t, size_t);
void		*xmalloc(size_t);
void		*xrealloc(void *, size_t, size_t);
void		 xfree(void *);
int		 xasprintf(char **, const char *, ...);

#endif
