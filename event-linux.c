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
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include "logfmon.h"
#include "save.h"
#include "xmalloc.h"
#include "log.h"
#include "file.h"
#include "event.h"

int ep = -1;

void *sigaction(int sig, siginfo_t *siginfo, void *ctxt)
{
}

void init_events(void)
{
  struct file *file;
  struct epoll_event epev;
  int eplen;
  struct sigaction sigact;

  eplen = count_open_files();
 
  if(ep == -1)
  {
    ep = epoll_create(eplen > 0 ? eplen : 5);
    if(ep == -1)
      die("epoll_create: %s", strerror(errno));

    sigact.sa_sigaction = sigaction;
    sigact.sa_mask = 0;
    sigact.sa_flags = SA_SIGINFO;
    if(sigaction(SIGIO, &sigact, NULL) == -1) 
      die("sigaction: %s", strerror(errno));
  }
  
  if(eplen == 0)
    return;
  
  epev.events = EPOLLIN | EPOLLPRI;

  for(file = files.head; file != NULL; file = file->next)
  {
    if(file->fd != NULL)
    {
      if(fcntl(fileno(file->fd), F_NOTIFY, DN_DELETE | DN_RENAME) == -1)
	die("fcntl: %s", strerror(errno));

      if(fcntl(fileno(file->fd), F_SETSIG, SIGIO) == -1)
	die("fcntl: %s", strerror(errno));

      epev.data.fd = fileno(file->fd);
      if(epoll_ctl(ep, EPOLL_CTL_ADD, fileno(file->fd), &epev) == -1)
	die("epoll_ctl: %s", strerror(errno));	
    }
  }
}

struct file *get_event(int *event, int timeout)
{
  struct file *file;
  struct epoll_event epev;
  int rc;

  *event = EVENT_NONE;

  if(ep == -1)
    return NULL;

  rc = epoll_wait(ep, &epev, 1, timeout * 1000);

  if(rc == -1)
  {
    if(errno == EINTR)
      return NULL;
    
    die("epoll_wait: %s", strerror(errno));
  }

  if(rc == 0)
  {
    *event = EVENT_TIMEOUT;
    return NULL;
  }

  file = find_file_by_fn(epev.data.fd);
  if(file == NULL)
    return NULL;

  *event = EVENT_READ;
  
  return file;
}
