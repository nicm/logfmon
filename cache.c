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
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "logfmon.h"
#include "xmalloc.h"
#include "cache.h"
#include "file.h"
#include "log.h"

int save_cache(void)
{
  struct file *file;
  FILE *fd;

  if(cache_file == NULL || *cache_file == '\0')
    return 0;

  if(debug)
    info("saving cache");

  fd = fopen(cache_file,"w+");
  if(fd == NULL)
  {
    error("%s: %s", cache_file, strerror(errno));
    return 1;
  }
   
  for(file = files.head; file != NULL; file = file->next)
    fprintf(fd, "%d %s %lld %lld\n", strlen(file->path), file->path, file->size, file->offset);

  fclose(fd);

  return 0;
}

int load_cache(void)
{
  struct file *file;
  struct stat sb;
  FILE *fd;
  char *path, format[32];
  int length;
  long long size;
  long long offset;

  if(cache_file == NULL || *cache_file == '\0')
    return 0;

  if(debug)
    info("loading cache");

  fd = fopen(cache_file,"r");
  if(fd == NULL)
  {
    info("%s: %s", cache_file, strerror(errno));
    return 1;
  }
  
  path = NULL;
  size = 0;
  offset = 0;

  while(!feof(fd))
  {
    fscanf(fd, "%d ", &length);
    if(path != NULL)
      free(path);
    path = xmalloc(length + 1);
    sprintf(format, "%%%dc %%lld %%lld", length);
    if(fscanf(fd, format, path, &size, &offset) < 3)
      break;
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
	  file->size = offset; /* this is correct: size is updated incrementally */
	  file->offset = offset;
	}
      }
      if(debug)
	info("file %s, was %lld/%lld now %lld/%lld", path, offset, size, file->offset, file->size);
    }
  }

  if(path != NULL)
    free(path);

  fclose(fd);

  return 0;
}
