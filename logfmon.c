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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h> 
#include <signal.h>
#include <grp.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/resource.h>

#include "logfmon.h"
#include "xmalloc.h"
#include "rules.h"
#include "save.h"
#include "log.h"
#include "file.h"
#include "context.h"
#include "event.h"
#include "tags.h"
#include "cache.h"
#include "threads.h"

extern FILE *yyin;
extern int yyparse(void);

volatile sig_atomic_t reload_conf;
volatile sig_atomic_t exit_now;

char *mail_cmd;
unsigned int mail_time;

uid_t uid;
gid_t gid;

char *conf_file;
char *cache_file;
char *pid_file;

int now_daemon;

int load_conf(void);
void sighandler(int);
char *repl_matches(char *, char *, regmatch_t *);
void parse_line(char *, struct file *);
void usage(void);

void sighandler(int sig)
{
  switch(sig)
  {
    case SIGTERM:
      exit_now = 1;
      break;	
    case SIGHUP:
      reload_conf = 1;
      break;
  }
}

int load_conf(void)
{
  yyin = fopen(conf_file, "r");
  if(yyin == NULL)
    return 1;

  yyparse();

  fclose(yyin);

  return 0;
}

char *repl_one(char *src, char *repl)
{
  char *buf;
  size_t len, pos, rlen;

  len = strlen(src) + 512;
  buf = xmalloc(len);
  pos = 0;

  rlen = strlen(repl);

  while(*src != '\0')
  {
    if(*src != '$' || *(src + 1) != '1')
    {
      *(buf + pos) = *src++;
      
      pos++;
      while(len <= pos)
      {
	len *= 2;
	buf = xrealloc(buf, len);
      }
      
      continue;
    }

    src += 2;

    while(len <= pos + rlen)
    {
      len *= 2;
      buf = xrealloc(buf, len);
    }

    strcpy(buf + pos, repl);
    pos += rlen;
  }

  *(buf + pos) = '\0';
  
  return buf;  
}

char *repl_matches(char *line, char *src, regmatch_t *matches)
{
  char *buf;
  size_t len, mlen, pos;
  int num;

  len = strlen(src) + 512;
  buf = xmalloc(len);
  pos = 0;
    
  while(*src != '\0')
  {
    if(*src != '$' || !isdigit(*(src + 1)) || isdigit(*(src + 2)))
    {
      *(buf + pos) = *src++;
      
      pos++;
      while(len <= pos)
      {
	len *= 2;
	buf = xrealloc(buf, len);
      }

      continue;
    }

    num = atoi(++src);
    mlen = matches[num].rm_eo - matches[num].rm_so;

    if(mlen > 0)
    {
      while(len <= pos + mlen)
      {
	len *= 2;
	buf = xrealloc(buf, len);
      }
      
      strncpy(buf + pos, line + matches[num].rm_so, mlen);
      pos += mlen;
      
      src++;
    }
    else
    {
      *(buf + pos) = '$';
      
      pos++;
      while(len <= pos)
      {
	len *= 2;
	buf = xrealloc(buf, len);
      }
    }
  }
  *(buf + pos) = '\0';

  return buf;
}

void parse_line(char *line, struct file *file)
{
  char *str, *test;
  regmatch_t matches[10];
  pthread_t thread;
  struct rule *rule;
  struct context *context;
  FILE *fd;

  if(strlen(line) < 17)
    return;

  test = line + 16;
  while(*test != ' ' && *test != '\0')
    test++;
  if(*test == '\0')
    return;
  test++;
  if(*test == '\0')
    return;

  for(rule = rules.tail; rule != NULL; rule = rule->last)
  {
    if(rule->tags->head != NULL && !find_tag(rule->tags, file->tag))
      continue;

    if(regexec(rule->re, test, 10, matches, 0) != 0)
      continue;

    if(rule->not_re != NULL)
    {
      if(regexec(rule->not_re, test, 0, NULL, 0) == 0)
	continue;
    }

    switch(rule->action)
    {
      case ACTION_IGNORE:
	if(debug)
	  info("matched: (%s) %s -- ignoring", file->tag, test);
      	return;
      case ACTION_EXEC:
	str = repl_matches(test, rule->params.cmd, matches);
	
	if(debug)
	  info("matched: (%s) %s -- executing: %s", file->tag, test, str);
   
	if(str == NULL || *str == '\0')
	{
	  error("empty command for exec");
	  free(str);
	}
	else
	{
	  if(pthread_create(&thread, NULL, exec_thread, str) != 0)
	    die("pthread_create failed");
	}

	return;
      case ACTION_PIPE:
	if(rule->params.cmd == NULL || *(rule->params.cmd) == '\0')
	  return;

	str = repl_matches(test, rule->params.cmd, matches);

	if(debug)
	  info("matched: (%s) %s -- piping: %s", file->tag, test, str);

	if(str == NULL || *str == '\0')
	{
	  error("empty command for pipe");
	  free(str);
	}
	else
	{
	  fd = popen(str, "w");
	  if(fd == NULL)
	    error("%s: %s", str, strerror(errno));
	  else
	  {
	    fwrite(line, strlen(line), 1, fd);
	    fputc('\n', fd);
	    
	    if(pthread_create(&thread, NULL, pclose_thread, fd) != 0)
	      die("pthread_create failed");

	    free(str);
	  }
	}
	
	return;
      case ACTION_OPEN:
	if(rule->params.key == NULL || *(rule->params.key) == '\0')
	  return;

	str = repl_matches(test, rule->params.key, matches);

	if(debug)
	  info("matched: (%s) %s -- opening: '%s'", file->tag, test, str);
 
	if(find_context_by_key(&file->contexts, str) != NULL)
	{
	  if(debug)
	    info("ignoring open; found existing context %s", str);
	  free(str);
	  continue;
	}

	add_context(&file->contexts, str, rule);

	free(str);

	continue;
      case ACTION_APPEND:
	if(rule->params.key == NULL || *(rule->params.key) == '\0')
	  return;

	str = repl_matches(test, rule->params.key, matches);

	if(debug)
	  info("matched: (%s) %s -- appending: '%s'", file->tag, test, str);

	context = find_context_by_key(&file->contexts, str);
	if(context == NULL)
	{
	  if(debug)
	    info("missing context %s for append", str);
	  free(str);
	  continue;
	}
	free(str);

	add_message(&context->messages, line);

	if(context->rule->params.ent_max == 0)
	  continue;

	if(count_messages(&context->messages) >= context->rule->params.ent_max)
	{
	  if(debug)
	    info("context %s reached limit of %d entries", context->key, context->rule->params.ent_max);
	  
	  if(context->rule->params.ent_cmd != NULL)
	    pipe_context(context, context->rule->params.ent_cmd);
	  
	  delete_context(&file->contexts, context);
	}

	continue;
      case ACTION_CLOSE:
	if(rule->params.key == NULL || *(rule->params.key) == '\0')
	  return;
	
	str = repl_matches(test, rule->params.key, matches);

	if(debug)
	  info("matched: (%s) %s -- closing: '%s'", file->tag, test, str);
	
	context = find_context_by_key(&file->contexts, str);
	if(context == NULL)
	{
	  if(debug)
	    info("missing context %s for close", str);
	  free(str);
	  continue;
	}
	free(str);

	if(rule->params.cmd != NULL && *(rule->params.cmd) != '\0')
	{
	  str = repl_matches(test, rule->params.cmd, matches);
	  
	  pipe_context(context, str);
	  
	  free(str);
	}
	
	delete_context(&file->contexts, context);
	
	continue;
    }
  }

  if(debug)
    info("unmatched: (%s) %s", file->tag, test);
 
  if(mail_cmd != NULL && *mail_cmd != '\0')
  {
    if(pthread_mutex_lock(&save_mutex) != 0)
      die("pthread_mutex_lock failed");

    add_message(&file->saves, line);

    if(pthread_mutex_unlock(&save_mutex) != 0)
      die("pthread_mutex_unlock failed");
  }
}

void usage(void)
{
  printf("usage: %s [-d] [-f conffile] [-c cachefile] [-p pidfile]\n", __progname);

  exit(1);
}

int main(int argc, char **argv)
{
  int opt;
  pthread_t thread;

  time_t now, prev;

  int timeout, failed, dirty;
  enum event event;
  ssize_t len;
  size_t last, pos;

  struct file *file;

  FILE *fd;
 
  now_daemon = 0;

  pid_file = NULL;
  conf_file = NULL;
  cache_file = NULL;

  debug = 0;

  while((opt = getopt(argc, argv, "c:df:p:")) != EOF)
  {
    switch(opt)
    {
      case 'c':
	cache_file = xstrdup(optarg);
	break;
      case 'd':
	debug = 1;
	break;
      case 'f':
	conf_file = xstrdup(optarg);
	break;
      case 'p':
	pid_file = xstrdup(optarg);
	break;
      case '?':
      default:
	usage();
    }
  }

  mail_time = MAILTIME;
  mail_cmd = NULL;

  rules.head = rules.tail = NULL;
  files.head = files.tail = NULL;

  uid = 0;
  gid = 0;

  if(conf_file == NULL)
    conf_file = xstrdup(CONFFILE);

  if(load_conf() != 0)
  {
    error("%s: %s", conf_file, strerror(errno));
    return 1;
  }

  if(mail_cmd == NULL)
    mail_cmd = xstrdup(MAILCMD);
  
  if(cache_file == NULL)
    cache_file = xstrdup(CACHEFILE);

  if(pid_file == NULL)
    pid_file = xstrdup(PIDFILE);

  if(files.head == NULL)
    die("no files specified");

  /*if(rules == NULL)
    die("no rules found");*/

  setpriority(PRIO_PROCESS, getpid(), 1);

  if(!debug)
  {
    if(daemon(0, 0) != 0)
      die("daemon: %s", strerror(errno));
  }

  if(gid != 0)
  {
    if(geteuid() != 0)
      error("need root privileges to set group");
    else
    {
      if(setgroups(1, &gid) != 0 || setegid(gid) != 0 || setgid(gid) != 0)
	die("failed to drop group privileges");
    }
  }

  if(uid != 0)
  {
    if(geteuid() != 0)
      error("need root privileges to set user");
    else
    {
      if(setuid(uid) != 0 || seteuid(uid) != 0)
	die("failed to drop user privileges");
    }
  }

  now_daemon = 1;
  info("started");

  load_cache();

  reload_conf = 0;
  exit_now = 0;

  if(pthread_mutex_init(&save_mutex, NULL) != 0)
    die("pthread_mutex_init failed");

  if(pthread_create(&thread, NULL, save_thread, NULL) != 0)
    die("pthread_create failed");

  if(!debug)
  {
    if(signal(SIGINT, SIG_IGN) == SIG_ERR)
      die("signal: %s", strerror(errno));
    if(signal(SIGQUIT, SIG_IGN) == SIG_ERR)
      die("signal: %s", strerror(errno));
  }

  if(signal(SIGHUP, sighandler) == SIG_ERR)
    die("signal: %s", strerror(errno));
  if(signal(SIGTERM, sighandler) == SIG_ERR)
    die("signal: %s", strerror(errno));

  /*signal(SIGCHLD, SIG_IGN);*/

  if(pid_file != NULL && *pid_file != '\0')
  {
    fd = fopen(pid_file, "w");
    if(fd == NULL)
      error("%s: %s", pid_file, strerror(errno));
    else
    {
      fprintf(fd, "%ld\n", (long) getpid());
      fclose(fd);
    }
  }

  prev = time(NULL) + CHECKTIMEOUT;

  open_files();
  init_events();

  dirty = 0;
  failed = 0;
  len = 0;

  while(!exit_now)
  {
    if(reload_conf)
    {
      info("reloading configuration");

      save_cache();

      if(pthread_mutex_lock(&save_mutex) != 0)
	die("pthread_mutex_lock failed");

      clear_rules();
      clear_files(); /* closes too */
      
      if(load_conf() != 0)
	die("%s: %s", conf_file, strerror(errno));

      if(pthread_mutex_unlock(&save_mutex) != 0)
	die("pthread_mutex_unlock failed");

      load_cache();
      open_files();
      init_events();

      reload_conf = 0;

      dirty = 0;
    }

    if(reopen_files(&failed) > 0)
      init_events();

    if(failed > 0)
      timeout = REOPENTIMEOUT;
    else
      timeout = DEFAULTTIMEOUT;
   
    file = get_event(&event,timeout);

    now = time(NULL);
    if(now >= prev)
    {
      check_files();
      if(dirty)
      {
	save_cache();
	dirty = 0;
      }
      prev = now + CHECKTIMEOUT;
    }

    if(file == NULL)
      continue;

    switch(event)
    {
      case EVENT_NONE:
      case EVENT_TIMEOUT:
	break;
      case EVENT_REOPEN:
	fclose(file->fd);
	file->fd = NULL;
	file->timer = time(NULL) + REOPENTIMEOUT;

	dirty = 1;
	break;
      case EVENT_READ:
	for(;;)
	{
	  file->buffer = xrealloc(file->buffer, file->length + 256);
	  
	  len = read(fileno(file->fd), file->buffer + file->length, 255);
	  if(len == 0 || len == -1)
	    break;
	  file->length += len;
	  if(len < 255)
	    break;
	  
	  if(file->length > 256*1024)
	    break;
	}

	if(len == -1)
	{
	  fclose(file->fd);
	  file->fd = NULL;	  
	}

	last = 0;
	for(pos = 0; pos < file->length; pos++)
	{
	  if(*(file->buffer + pos) == '\0')
	    *(file->buffer + pos) = '_';
	  
	  if(*(file->buffer + pos) == '\n')
	  {
	    *(file->buffer + pos) = '\0';
	    parse_line(file->buffer + last, file);
	    last = pos + 1;
	  }
	}

	memmove(file->buffer, file->buffer + last, file->length - last);
	file->length -= last;

	file->offset += last;

	dirty = 1;
	break;
    }
  }
  
  close_files();
  if(pid_file != NULL && *pid_file != '\0')
    unlink(pid_file);

  /* let's be tidy; easier to check for leaks too */
  clear_rules();
  clear_files();

  if(conf_file != NULL)
    free(conf_file);
  if(cache_file != NULL)
    free(cache_file);
  if(pid_file != NULL)
    free(pid_file);
  if(mail_cmd != NULL)
    free(mail_cmd);

  pthread_mutex_destroy(&save_mutex);

  info("terminated");

  return 0;
}
