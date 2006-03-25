/* $Id$ */

/*
 * Copyright (c) 2004 Nicholas Marriott <nicm@users.sourceforge.net>
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

#include <stdlib.h>
#include <string.h>

#include "logfmon.h"

char *
xstrdup(char *s)
{
	size_t	len;

	len = strlen(s) + 1;
        return (strncpy(xmalloc(len), s, len));
}

void *
xcalloc(size_t nmemb, size_t size)
{
        void	*ptr;

        if ((ptr = calloc(nmemb, size)) == NULL)
		fatal("calloc");
        return (ptr);
}

void *
xmalloc(size_t size)
{
        void	*ptr;

        if ((ptr = malloc(size)) == NULL)
		fatal("malloc");
        return (ptr);
}

void *
xrealloc(void *ptr, size_t nmemb, size_t size)
{
	size_t new_size = nmemb * size;

	if (nmemb != 0 && size != 0 && SIZE_T_MAX / nmemb < size)
		fatal("xrealloc: nmemb * size > SIZE_T_MAX");
        if ((ptr = realloc(ptr, new_size)) == NULL)
		fatal("realloc");
        return (ptr);
}
