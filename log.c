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

#include <err.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>

#include "logfmon.h"
#include "log.h"

void vlog(int, char *, va_list);

void die(char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vlog(LOG_ERR, fmt, ap);
  va_end(ap);

  if(now_daemon)
    error("exited");
  
  exit(1);
}

void error(char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vlog(LOG_ERR, fmt, ap);
  va_end(ap);
}

void info(char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vlog(LOG_INFO, fmt, ap);
  va_end(ap);
}

void vlog(int pri, char *fmt, va_list ap)
{
  if(debug || !now_daemon)
    vwarnx(fmt, ap);
  else
    vsyslog(LOG_DAEMON | pri, fmt, ap);
}
