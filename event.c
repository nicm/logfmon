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
#include <errno.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include "logfmon.h"
#include "save.h"
#include "xmalloc.h"
#include "log.h"
#include "file.h"
#include "event.h"

int kq = -1;

void init_events(void)
{
  struct file *file;
  struct kevent *kevlist, *kevptr;
  int kevlen;
  
  if(kq == -1)
  {
    kq = kqueue();
    if(kq == -1)
      die("kqueue: %s", strerror(errno));
  }
  
  kevlen = count_open_files() * 2;
  if(kevlen == 0)
    return;

  kevlist = xmalloc(sizeof(struct kevent) * kevlen);

  kevptr = kevlist;
  for(file = files.head; file != NULL; file = file->next)
  {
    if(file->fd != NULL)
    {
      EV_SET(kevptr, fileno(file->fd), EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_RENAME | NOTE_DELETE, 0, NULL);
      kevptr++;
      EV_SET(kevptr, fileno(file->fd), EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
      kevptr++;
    }
  }

  if(kevent(kq, kevlist, kevlen, NULL, 0, NULL))
    die("kevent: %s", strerror(errno));

  free(kevlist);
}

struct file *get_event(int *event, int timeout)
{
  struct file *file;
  struct kevent kev;
  struct timespec ts;
  int rc;

  *event = EVENT_NONE;

  if(kq == -1)
    return NULL;

  ts.tv_nsec = 0;
  ts.tv_sec = timeout;
  
  rc = kevent(kq, NULL, 0, &kev, 1, &ts);

  if(rc == -1)
  {
    if(errno == EINTR) /* && !debug) */
      return NULL;
    
    die("kevent: %s", strerror(errno));
  }

  if(rc == 0)
  {
    *event = EVENT_TIMEOUT;
    return NULL;
  }

  file = find_file_by_fd(kev.ident);
  if(file == NULL)
    return NULL;

  switch(kev.filter)
  {
    case EVFILT_VNODE:
      *event = EVENT_REOPEN;
      return file;
    case EVFILT_READ:
      if(kev.data < 0)
	*event = EVENT_REOPEN;
      else
	*event = EVENT_READ;
      return file;
  }

  return NULL;
}
