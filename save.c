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
#include <errno.h>

#include "logfmon.h"
#include "save.h"
#include "xmalloc.h"
#include "log.h"
#include "file.h"

pthread_mutex_t save_mutex;

void *save_thread(void *arg)
{
  struct message *save;
  struct file *file;
  FILE *fd;
  int msgs;

  arg = NULL;

  for(;;)
  {
    if(debug)
      info("sleeping for %d seconds", mail_time);

    sleep(mail_time);

    if(exit_now)
      break;

    for(file = files.head; file != NULL; file = file->next)
    {
      if(file->saves.head != NULL)
	break;
    }
    
    if(file == NULL)
      continue;

    if(debug)
      info("processing saved messages. executing: %s", mail_cmd);

    pthread_mutex_lock(&save_mutex);

    fd = popen(mail_cmd, "w");
    if(fd == NULL)
    {
      error("%s: %s", mail_cmd, strerror(errno));
      continue;
    }

    msgs = 0;

    for(file = files.tail; file != NULL; file = file->last)
    {
      if(file->saves.head != NULL)
      {
	fprintf(fd, "Unmatched messages for file %s, tag %s:\n\n", file->path, file->tag);

	for(save = file->saves.tail; save != NULL; save = save->last)
	{
	  fprintf(fd, "%s\n", save->msg);
	  msgs++;
	}

	fprintf(fd,"\n");

	clear_messages(&file->saves);
      }
    }
    pclose(fd);

    pthread_mutex_unlock(&save_mutex);
	
    if(debug)
      info("processed %d unmatched messages", msgs);
  }

  return NULL;
}
