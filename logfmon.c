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

#include <sys/types.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "logfmon.h"
#include "xmalloc.h"
#include "rules.h"
#include "save.h"
#include "log.h"
#include "file.h"
#include "context.h"

extern FILE *yyin;
extern int yyparse(void);

char *mail_cmd;
int mail_time;

char *conf_file;

int now_daemon;

int load_conf(void);
void sighandler(int);
char *repl_matches(char *, char *, regmatch_t *);
void parse_line(char *, struct file *);
void usage(void);
void *exec_thread(void *);
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

  FILE *fd;
  struct contextmsg *cmsg;

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

  for(rule = rules; rule != NULL; rule = rule->next)
  {
    if(rule->tag != NULL && strcmp(rule->tag, file->tag) != 0)
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
	if(rule->params.cmd == NULL || *(rule->params.cmd) == '\0')
	  return;

	str = repl_matches(test, rule->params.cmd, matches);
	
	if(debug)
	  info("matched: (%s) %s -- executing: %s", file->tag, test, str);      
    
	if(pthread_create(&thread, NULL, exec_thread, str) != 0)
	  die("pthread_create: %s", strerror(errno));
    
	return;
      case ACTION_OPEN:
	if(rule->params.key == NULL || *(rule->params.key) == '\0')
	  return;

	str = repl_matches(test, rule->params.key, matches);

	if(find_context(file->contexts, str) != NULL)
	{
	  info("removing duplicate context %s", str);
	  file->contexts = delete_context(file->contexts, str);
	}

	if(debug)
	  info("matched: (%s) %s -- opening: %s", file->tag, test, str);      

	file->contexts = add_context(file->contexts, str, rule->params.expiry);

	free(str);

	continue;
      case ACTION_APPEND:
	if(rule->params.key == NULL || *(rule->params.key) == '\0')
	  return;

	str = repl_matches(test, rule->params.key, matches);

	context = find_context(file->contexts, str);
	if(context == NULL)
	{
	  info("missing context %s for append", str);
	  free(str);
	  continue;
	}

	if(debug)
	  info("matched: (%s) %s -- appending: %s", file->tag, test, str);

	context->cmsgs = add_msg(context->cmsgs, line);

	free(str);

	continue;
      case ACTION_CLOSE:
	if(rule->params.key == NULL || *(rule->params.key) == '\0')
	  return;
	
	str = repl_matches(test, rule->params.key, matches);

	context = find_context(file->contexts, str);
	free(str);
	if(context == NULL)
	{
	  info("missing context %s for close", str);
	  continue;
	}

	if(debug)
	  info("matched: (%s) %s -- closing: %s", file->tag, test, str);

	if(rule->params.cmd == NULL)
	  continue;

	str = repl_matches(test, rule->params.cmd, matches);

	fd = popen(str, "w");
	if(fd == NULL)
	{
	  error("%s: %s", str, strerror(errno));
	  free(str);
	  continue;
	}
	cmsg = context->cmsgs;
	while(cmsg != NULL)
	{
	  fprintf(fd, "%s\n", cmsg->msg);
	  
	  cmsg = cmsg->next;
	}
	pclose(fd);
	
	free(str);

	file->contexts = delete_context(file->contexts, context->key);
	
	continue;
    }
  }

  if(debug)
    info("unmatched: (%s) %s", file->tag, test);
    
  file->saves = add_save(file->saves, line);
}

struct kevent *make_kev_list(int *kevlen)
{
  struct file *file;
  struct kevent *kevlist, *kevptr;
  
  *kevlen = count_open_files() * 2;
  if(*kevlen == 0)
    return NULL;

  kevlist = xmalloc(sizeof(struct kevent) * *kevlen);

  kevptr = kevlist;
  file = files;
  while(file != NULL)
  {
    if(file->fd != NULL)
    {
      EV_SET(kevptr, fileno(file->fd), EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_RENAME | NOTE_DELETE, 0, NULL);
      kevptr++;
      EV_SET(kevptr, fileno(file->fd), EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
      kevptr++;
    }

    file = file->next;
  }

  return kevlist;
}

void usage(void)
{
  printf("usage: %s [-d] [-f file]\n", __progname);

  exit(1);

  /* NOTREACHED */
}

int main(int argc, char **argv)
{
  int opt;
  pthread_t thread;

  int rc;
  ssize_t len;
  size_t last, pos;

  struct file *file;

  int kq;  
  struct timespec ts;
  struct kevent kev;
  struct kevent *kevlist;
  int kevlen;
  
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
	conf_file = malloc(strlen(optarg) + 1);
	strcpy(conf_file, optarg);
	break;
      case '?':
      default:
	usage();
    }
  }

  rules = NULL;
  files = NULL;

  mail_time = 900;
  mail_cmd = NULL;

  if(load_conf() != 0)
  {
    error("%s: %s", conf_file, strerror(errno));
    return 1;
  }

  if(mail_cmd == NULL)
    mail_cmd = "/usr/bin/mail root";
  
  if(files == NULL)
    die("no files specified");

  /*if(rules == NULL)
    die("no rules found");*/

  setpriority(PRIO_PROCESS, getpid(), 1);

  if(!debug)
  {
    if(daemon(1, 0) != 0)
      die("daemon: %s", strerror(errno));
  }

  now_daemon = 1;
  info("started");

  pthread_mutex_init(save_mutex, NULL);

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

  kq = kqueue();
  if(kq == -1)
    die("kqueue: %s", strerror(errno));

  while(!exit_now)
  {
    if(reload_conf)
    {
      info("reloading configuration");

      pthread_mutex_lock(save_mutex);

      clear_rules();
      clear_files(); /* closes too */
      
      if(load_conf() != 0)
      {
	error("%s: %s", conf_file, strerror(errno));
	error("exited");
	
	exit(1);
      }

      pthread_mutex_unlock(save_mutex);

      reload_conf = 0;
    }

    if(open_files() > 0)
    {
      kevlist = make_kev_list(&kevlen);
      if(kevent(kq, kevlist, kevlen, NULL, 0, NULL))
      {
	error("kevent: %s", strerror(errno));
	error("exited");
	
	exit(1);
      }
      free(kevlist);
    }

    if(count_closed_files() > 0)
    {
      ts.tv_nsec = 0;
      ts.tv_sec = 3;

      rc = kevent(kq, NULL, 0, &kev, 1, &ts);
    }
    else
      rc = kevent(kq, NULL, 0, &kev, 1, NULL);

    if(rc == -1)
    {
      if(errno == EINTR) /* && !debug) */
	continue;
      
      error("kevent: %s", strerror(errno));
      error("exited");
      
      exit(1);
    }

    if(rc == 0)
      continue;

    file = find_file_by_fn(kev.ident);
    if(file == NULL)
      continue;

    switch(kev.filter)
    {
      case EVFILT_VNODE:
	fclose(file->fd);
	file->fd = NULL;
	break;
      case EVFILT_READ:
	if(kev.data < 0)
	{
	  fclose(file->fd);
	  file->fd = NULL;
	  break;
	}
	
	for(;;)
	{
	  file->buffer = xrealloc(file->buffer, file->length + 256);

	  len = read(fileno(file->fd), file->buffer + file->length, 255);
	  if(len == -1 || len == 0)
	    break;
	  file->length += len;
	  if(len < 255)
	    break;
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
      default:
	error("unexpected result from kevent");
	error("exited");
	    
	exit(1);
    }
  }
  
  close_files();

  return 0;
}
