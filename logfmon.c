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
#include <getopt.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h> 
#include <signal.h>
#include <grp.h>

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

extern FILE *yyin;
extern int yyparse(void);

char *mail_cmd;
int mail_time;

uid_t uid;
gid_t gid;

char *conf_file;

int now_daemon;

int load_conf(void);
void sighandler(int);
char *repl_matches(char *, char *, regmatch_t *);
void parse_line(char *, struct file *);
void usage(void);
void *exec_thread(void *);
void *pipe_thread(void *);
struct kevent *make_kev_list(int *);

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

void *pipe_thread(void *arg)
{
  struct pipeargs *args;
  FILE *fd;

  args = (struct pipeargs *) arg;

  fd = popen(args->cmd, "w");
  if(fd == NULL)
    error("%s: %s", args->cmd, strerror(errno));
  else
  {
    fprintf(fd, "%s\n", args->line);
    pclose(fd);
  }

  free(args->line);
  free(args->cmd);

  free(args);

  return NULL;
}

void *exec_thread(void *arg)
{
  system((char *) arg);

  free(arg);

  return NULL;
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
    if(*src != '$')
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

    src++;
    if(*src == '\0')
    {
      *(buf + pos) = '$';

      pos++;
      while(len <= pos)
      {
	len *= 2;
	buf = xrealloc(buf, len);
      }

      continue;
    }

    if(*src >= '0' && *src <= '9')
    {
      num = *src++ - '0';
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
      }
      else
      {
	while(len <= pos + 2)
	{
	  len *= 2;
	  buf = xrealloc(buf, len);
	}
	*(buf + pos) = '$';
	pos++;
	*(buf + pos) = num + '0';
	pos++;
      }
    }
    else
    {
      while(len <= pos + 2)
      {
	len *= 2;
	buf = xrealloc(buf, len);
      }
      *(buf + pos) = '$';
      pos++;
      *(buf + pos) = *src++;
      pos++;
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
  int match;
  struct pipeargs *args;

  if(strlen(line) < 17)
    return;

  test = line + 16;
  while(*test != ' ' && *test != '\0')
    test++;
  if(*test != ' ')
    return;
  test++;
  if(*test == '\0')
    return;

  for(rule = rules.tail; rule != NULL; rule = rule->last)
  {
    if(rule->tags->head == NULL || !find_tag(rule->tags, file->tag))
      continue;

    match = regexec(rule->re, test, 10, matches, 0);
    if(match != 0)
      continue;

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
	  if(str != NULL)
	    free(str);
	}
	else
	{
	  if(pthread_create(&thread, NULL, exec_thread, str) != 0)
	    die("pthread_create: %s", strerror(errno));
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
	  if(str != NULL)
	    free(str);
	}
	else
	{
	  args = xmalloc(sizeof(struct pipeargs));
	  
	  args->cmd = str;
	  args->line = xmalloc(strlen(line) + 1);
	  strcpy(args->line, line);
	  
	  if(pthread_create(&thread, NULL, pipe_thread, args) != 0)
	    die("pthread_create: %s", strerror(errno));
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
      pthread_mutex_lock(&save_mutex);
      add_message(&file->saves, line);
      pthread_mutex_unlock(&save_mutex);
    }
}

void usage(void)
{
  printf("usage: %s [-d] [-f file]\n", __progname);

  exit(1);
}

int main(int argc, char **argv)
{
  int opt;
  pthread_t thread;

  time_t now, prev;

  int event, timeout, failed;
  ssize_t len;
  size_t last, pos;

  struct file *file;
 
  now_daemon = 0;
  
  conf_file = CONFFILE;

  debug = 0;

  while((opt = getopt(argc, argv, "df:")) != EOF)
  {
    switch(opt)
    {
      case 'd':
	debug = 1;
	break;
      case 'f':
	conf_file = xmalloc(strlen(optarg) + 1);
	strcpy(conf_file, optarg);
	break;
      case '?':
      default:
	usage();
    }
  }

  rules.head = rules.tail = NULL;
  files.head = files.tail = NULL;

  mail_time = 900;
  mail_cmd = NULL;

  uid = 0;
  gid = 0;

  if(load_conf() != 0)
  {
    error("%s: %s", conf_file, strerror(errno));
    return 1;
  }

  if(mail_cmd == NULL)
    mail_cmd = "/usr/bin/mail root";
  
  if(files.head == NULL)
    die("no files specified");

  /*if(rules == NULL)
    die("no rules found");*/

  setpriority(PRIO_PROCESS, getpid(), 1);

  if(!debug)
  {
    if(daemon(1, 0) != 0)
      die("daemon: %s", strerror(errno));
  }

  if(gid != 0)
  {
    if(geteuid())
      error("need root privileges to set group");
    else
    {
      if(setgroups(1, &gid) != 0 || setegid(gid) != 0 || setgid(gid) != 0)
	die("failed to drop group privileges");
    }
  }

  if(uid != 0)
  {
    if(geteuid())
      error("need root privileges to set user");
    else
    {
      if(setuid(uid) != 0 || seteuid(uid) != 0)
	die("failed to drop user privileges %s", strerror(errno));
    }
  }
  
  now_daemon = 1;
  info("started");

  pthread_mutex_init(&save_mutex, NULL);

  if(pthread_create(&thread, NULL, save_thread, NULL) != 0)
    die("pthread_create: %s", strerror(errno));

  if(!debug)
  {
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
  }

  signal(SIGHUP, sighandler);
  signal(SIGTERM, sighandler);

  /*signal(SIGCHLD, SIG_IGN);*/

  reload_conf = 0;
  exit_now = 0;

  prev = time(NULL) + CHECKTIMEOUT;

  while(!exit_now)
  {
    if(reload_conf)
    {
      info("reloading configuration");

      pthread_mutex_lock(&save_mutex);

      clear_rules();
      clear_files(); /* closes too */
      
      if(load_conf() != 0)
      {
	error("%s: %s", conf_file, strerror(errno));
	error("exited");
	
	exit(1);
      }

      pthread_mutex_unlock(&save_mutex);

      reload_conf = 0;
    }

    if(open_files(&failed) > 0)
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
      prev = now + CHECKTIMEOUT;
    }

    if(file == NULL)
      continue;

    switch(event)
    {
      case EVENT_REOPEN:
	fclose(file->fd);
	file->fd = NULL;
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

	break;
    }
  }
  
  close_files();

  return 0;
}
