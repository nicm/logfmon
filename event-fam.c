/* $Id$ */

/*
 * Copyright (c) 2006 Laurent Pelecq <laurent.pelecq@soleil.org>
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

#include <sys/types.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <fam.h>

#include "logfmon.h"

static FAMConnection fc;

/* File monitor */
struct _file_mon_t {
  struct file *file;
  FAMRequest fr;
  struct _file_mon_t *next;
};
typedef struct _file_mon_t file_mon_t;

static file_mon_t *fmon_list = NULL; /* Current file monitor list. */

static
file_mon_t *
new_file_monitor(struct file *file)
{
  file_mon_t *fmon = (file_mon_t*)xcalloc(1, sizeof(file_mon_t));
  fmon->file = file;
  if (FAMMonitorFile(&fc, file->path, &(fmon->fr), fmon) < 0) {
    log_warn("FAMMonitorFile(\"%s\")", fmon->file->path);
    xfree(fmon);
    fmon = NULL;
  } else
    log_debug("%s: monitoring", file->path);
  return fmon;
}

static
void
delete_file_monitor(file_mon_t *fmon)
{
  if (fmon) {
    log_debug("%s: cancelling monitoring", fmon->file->path);
    if (FAMCancelMonitor(&fc, &(fmon->fr)) < 0)
      log_warnx("%s: failed to cancel monitoring", fmon->file->path);
    xfree(fmon);
  }
}

static
void
add_file_monitor(struct file *file)
{
  file_mon_t *fmon = new_file_monitor(file);

  if (fmon) {
    fmon->next = fmon_list;
    fmon_list = fmon;
  }
}

static
void
log_event(FAMEvent *fe, void (*log_msg)(const char *, ...))
{
  switch (fe->code) {
  case FAMExists:
    log_msg("%s: found", fe->filename);
    break;
  case FAMEndExist:
    log_msg("%s: end of listing", fe->filename);
    break;
  case FAMChanged:
    log_msg("%s: changed", fe->filename);
    break;
  case FAMDeleted:
    log_msg("%s: deleted", fe->filename);
    break;
  case FAMStartExecuting:
    log_msg("%s: started executing", fe->filename);
    break;
  case FAMStopExecuting:
    log_msg("%s: stopped executing", fe->filename);
    break;
  case FAMCreated:
    log_msg("%s: created", fe->filename);
    break;
  case FAMMoved:
    log_msg("%s: moved", fe->filename);
    break;
  default:
    log_warnx("%s: unknown event %d", fe->filename, fe->code);
  }
}

static
struct file *
find_change(FAMEvent *fe, enum event *event)
{
  struct file *res = ((file_mon_t*)(fe->userdata))->file;

  switch (fe->code) {
  case FAMChanged:
    *event = EVENT_READ;
    log_event(fe, log_debug);
    break;
  case FAMCreated:
    *event = EVENT_REOPEN;
    log_event(fe, log_debug);
    break;
  default:
    log_event(fe, log_info);
  }
  return res;
}

static
int
wait_for_event(int timeout)
{
  struct timeval tv_timeout;
  fd_set rfds;
  int n = -1;

  FD_ZERO(&rfds);
  FD_SET(fc.fd, &rfds);

  tv_timeout.tv_sec = timeout;
  tv_timeout.tv_usec = 0;

  do {
    n = select(fc.fd + 1, &rfds, NULL, NULL, &tv_timeout);
  } while (n < 0 && errno == EINTR);

  if (n < 0)
    log_warn("select");

  return n;
}

void
close_events()
{
  while (fmon_list) {
    file_mon_t *fmon = fmon_list;
    fmon_list = fmon->next;
    delete_file_monitor(fmon);
  }

  FAMClose(&fc);
}

void
init_events()
{
  struct file *file = NULL;

  if (FAMOpen(&fc) < 0)
    log_fatal("FAMOpen");

  TAILQ_FOREACH(file, &conf.files, entry) {
    if (file->fd != NULL) {
      log_debug("init file: tag=%s", file->tag.name);
      add_file_monitor(file);
    }
  }

}

struct file *
get_event(enum event *event, int timeout)
{
    struct file *file = NULL;

    *event = EVENT_NONE;
    while (*event == EVENT_NONE) {
      if (FAMPending(&fc)) {
	  FAMEvent fe;
	  if (FAMNextEvent(&fc, &fe) >= 0) {
	    file = find_change(&fe, event);
	  } else
	    log_warnx("FAMNextEvent failed");
      } else {
	int n = wait_for_event(timeout);
	if (n == 0)
	  *event = EVENT_TIMEOUT;
	else if (n < 0)
	  return NULL;
      }
    }

    return file;
}

void
reinit_events(void)
{
        close_events();
        init_events();
}
