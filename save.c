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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <errno.h>

#include "logfmon.h"
#include "save.h"
#include "xmalloc.h"
#include "log.h"
#include "file.h"

pthread_mutex_t *save_mutex;

struct save *add_save(struct save *saves, char *msg)
{
  struct save *save, *new;

  new = (struct save *) xmalloc(sizeof(struct save));

  new->next = NULL;

  new->msg = (char *) xmalloc(strlen(msg) + 1);
  strcpy(new->msg, msg);

  pthread_mutex_lock(save_mutex);
  if(saves == NULL)
    saves = new;
  else
  {
    save = saves;
    while(save->next != NULL)
      save = save->next;
    save->next = new;
  }  
  pthread_mutex_unlock(save_mutex);

  return saves;
}

struct save *clear_saves(struct save *saves)
{
  struct save *save, *last;

  if(saves == NULL)
    return NULL;

  save = saves;
  while(save != NULL)
  {
    last = save;

    save = save->next;

    free(last->msg);
    free(last);
  }

  return NULL;
}

void *save_thread(void *arg)
{
  int num;
  struct save *save;
  struct file *file;
  FILE *fd;

  arg = NULL;

  for(;;)
  {
    if(debug)
      info("sleeping for %d seconds", mail_time);

    sleep(mail_time);

    if(exit_now)
      break;

    pthread_mutex_lock(save_mutex);
    
    num = 0;
    file = files;
    while(file != NULL)
    {
      if(file->saves != NULL)
	num++;

      file = file->next;
    }
    
    if(num > 0)
    {
      if(debug)
	info("processing saved messages. executing: %s", mail_cmd);
      fd = popen(mail_cmd, "w");
      if(fd == NULL)
	error("%s: %s", mail_cmd, strerror(errno));
      else
      {
	num = 0;

	file = files;
	while(file != NULL)
	{
	  if(file->saves != NULL)
	  {
	    fprintf(fd, "Unmatched messages for file %s, tag %s:\n\n", file->path, file->tag);

	    save = file->saves;
	    while(save != NULL)
	    {
	      fprintf(fd, "%s\n", save->msg);
	      save = save->next;
	      num++;
	    }

	    fprintf(fd,"\n");

	    file->saves = clear_saves(file->saves);
	  }

	  file = file->next;
	}
	if(debug)
	  info("processed %d unmatched messages", num);
	pclose(fd);
      }
    }

    pthread_mutex_unlock(save_mutex);
  }

  return NULL;
}
