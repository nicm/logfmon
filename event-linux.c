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
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>

#include "logfmon.h"
#include "save.h"
#include "xmalloc.h"
#include "log.h"
#include "file.h"
#include "event.h"

/*
 * Okay, this is a bit of a hack since, as far as I can tell:
 *
 * a) Linux doesn't support notification when a file is renamed or
 *    deleted. fcntl with F_NOTIFY only works on directories, which
 *    is useless.
 *
 * b) Linux doesn't support any useful form of notification when a file
 *    is appended to:
 *
 *    - select() & poll() return immediately when a file is at EOF.
 *    - epoll is poorly documented, not well supported by distros as
 *      yet (both a 2.6 kernel and a patched glibc is needed), and
 *      refuses to work for me altogether on files.
 *    - aio_* is not what I am looking for at all, and it would be 
 *      a real pain to make it do what I want.
 *    - F_SETSIG also looks lannoying to implement, and I'm not sure
 *      it would do the right thing either.
 *
 * So, we are left with a very sucky manual poll with stat()
 * which is, well, crap and I'm not very happy about at all.  
 *
 */

struct file *evfile = NULL;

void init_events(void)
{
  struct file *file;

  evfile = files.head;
}

struct file *get_event(int *event, int timeout)
{
  struct stat sb;
  int num;

  num = 0;

  for(;;)
  {
    *event = EVENT_NONE;

    if(usleep(100000L) == -1)
    {
      if(errno == EINTR)
	return NULL;

      die("usleep: %s", strerror(errno));
    }

    num++;
    if(num > ((double) timeout) / 0.1)
    {
      *event = EVENT_TIMEOUT;
      return NULL;
    }
    
    if(evfile == NULL)
      evfile = files.head;
    
    for(; evfile != NULL; evfile = evfile->next)
    {
      if(evfile->fd != NULL)
      {
	if(stat(evfile->path, &sb) == -1)
	{
	  *event = EVENT_REOPEN;
	  return evfile;
	}

	if(sb.st_size < evfile->size)
	{
	  *event = EVENT_REOPEN;
	  return evfile;
	}

	if(sb.st_size > evfile->size)
	{
	  evfile->size = sb.st_size;

	  *event = EVENT_READ;
	  return evfile;
	}
      }
    }
  }
}

