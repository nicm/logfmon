/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicm__@ntlworld.com>
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

#include <signal.h>

#include <sys/types.h>

#define CONFFILE  "/etc/logfmon.conf"
#define CACHEFILE "/etc/logfmon.cache"
#define PIDFILE "/var/run/logfmon.pid"

#define CHECKTIMEOUT 10
#define DEFAULTTIMEOUT 5
#define REOPENTIMEOUT 2

int debug;

volatile sig_atomic_t reload_conf;
volatile sig_atomic_t exit_now;

extern char *mail_cmd;
extern int mail_time;

extern uid_t uid;
extern gid_t gid;

extern char *conf_file;
extern char *cache_file;
extern char *pid_file;

extern int now_daemon;

extern char *__progname;

char *repl_one(char *, char *);

#endif
