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

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cache.h"
#include "file.h"
#include "log.h"
#include "logfmon.h"
#include "xmalloc.h"

int save_cache(void)
{
  struct file *file;
  FILE *fd;
  char *name;

  if(cache_file == NULL || *cache_file == '\0')
    return 0;

  if(debug)
    info("saving cache");

  name = xmalloc(strlen(cache_file) + 5);
  if(sprintf(name, "%s.new", cache_file) < 0)
  {
    error("sprintf: %s", strerror(errno));
    free(name);
    return 1;
  }

  fd = fopen(name, "w+");
  if(fd == NULL)
  {
    error("%s: %s", name, strerror(errno));
    free(name);
    return 1;
  }

  for(file = files.head; file != NULL; file = file->next)
    fprintf(fd, "%d %s %lld %lld\n", (int) strlen(file->path), file->path, (long long) file->size, (long long) file->offset);

  fclose(fd);

  if(rename(name, cache_file) == -1)
  {
    error("rename: %s", strerror(errno));
    unlink(name);
    free(name);
    return 1;
  }

  free(name);

  return 0;
}

int load_cache(void)
{
  struct file *file;
  struct stat sb;
  FILE *fd;
  char *path, format[24];
  int length;
  off_t size;
  off_t offset;
  int result;

  if(cache_file == NULL || *cache_file == '\0')
    return 0;

  if(debug)
    info("loading cache");

  fd = fopen(cache_file, "r");
  if(fd == NULL)
  {
    /* info is probably correct */
    info("%s: %s", cache_file, strerror(errno));
    return 1;
  }

  path = NULL;
  size = 0;
  offset = 0;

  while(!feof(fd))
  {
    if(fscanf(fd, "%d ", &length) < 1)
      break;

    free(path);
    path = malloc((size_t) length + 1); /* not xmalloc */
    if(path == NULL)
    {
      error("malloc: %s (cache: length = %d)", strerror(errno), length);
      goto error;
    }

    result = snprintf(format, sizeof(format), "%%%dc %%lld %%lld", length);
    if(result < 0 || result > (int) sizeof(format))
    {
      error("cannot load entire cache file; possibly corrupted");
      goto error;
    }
    if(fscanf(fd, format, path, &size, &offset) < 3)
    {
      error("cannot load entire cache file; possibly corrupted");
      goto error;
    }
    path[length] = '\0';

    file = find_file_by_path(path);
    if(file != NULL)
    {
      file->offset = 0;
      if(stat(path, &sb) == -1)
	error("%s: %s", path, strerror(errno));
      else
      {
	if(sb.st_size >= size)
	{
	  file->offset = offset;
	  /* this is correct: size is updated incrementally */
	  file->size = offset;
	}
      }
      if(debug)
	info("file %s, was %lld/%lld now %lld/%lld", path, offset, size, file->offset, file->size);
    }
  }

  free(path);
  fclose(fd);

  return 0;

 error:
  free(path);
  fclose(fd);

  return 1;
}
