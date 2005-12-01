/* -*-C-*- */

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

%option yylineno

%{
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "logfmon.h"
#include "y.tab.h"

extern int yylex(void);
%}

%%

\{ {
        int	 	 done = 0, ch;
	unsigned int	 pos = 0;
        char	 	 name[MAXTAGLEN];
	struct tag	*tag;
	struct tags	*tags;

        yylval.tags = xmalloc(sizeof (struct tags));
	tags = yylval.tags;
        TAILQ_INIT(&tags->tags);

        while (!done) {
                switch (ch = input()) {
		case 0:
		case EOF:
			goto badtags;
                case '}':
			done = 1;
			break;
                case ' ':
                        if (pos > 0) {
                                *(name + pos) = '\0';
				tag = xmalloc(sizeof (struct tag));
				strlcpy(tag->name, name, sizeof tag->name);
				TAILQ_INSERT_TAIL(&tags->tags, tag, entry);
                                pos = 0;
                        }
                        break;
                default:
                        if (ch == '-' || ch == '_' ||
			    isalpha((unsigned char) ch) ||
			    isdigit((unsigned char) ch)) {
				/* Tag must begin with a letter */
				if (pos == 0 && !isalpha((unsigned char) ch))
					goto badtags;
                                *(name + pos) = ch;
                                pos++;
				/* Bail if the size has become too long */
                                if (pos >= sizeof name)
					goto badtags;
                        } else
				goto badtags;
                        break;
                }
        }

        if (pos > 0) {
		*(name + pos) = '\0';
		tag = xmalloc(sizeof (struct tag));
		strlcpy(tag->name, name, sizeof tag->name);
		TAILQ_INSERT_TAIL(&yylval.tags->tags, tag, entry);
        }

        if (TAILQ_EMPTY(&yylval.tags->tags))
		goto badtags;

        return (TAGS);

badtags:
	while (!TAILQ_EMPTY(&yylval.tags->tags)) {
		tag = TAILQ_FIRST(&yylval.tags->tags);
		TAILQ_REMOVE(&yylval.tags->tags, tag, entry);
		free(tag);
	}
	free(yylval.tags);
	yylval.tags = NULL;

	return (TAGS);
}
[0-9]+[hms] {
        char	ch;

        ch = *(yytext + strlen(yytext) - 1);
        *(yytext + strlen(yytext) - 1) = '\0';

        yylval.number = atoi(yytext);
        switch (ch) {
        case 'h':
                yylval.number *= 3600;
                break;
        case 'm':
                yylval.number *= 60;
                break;
        }

        return (TIME);
}
[0-9]+ {
        yylval.number = atoi(yytext);
        return (NUMBER);
}
\" {
	int		done = 0, ch;
	size_t		pos = 0, len = 24;

        yylval.string = xmalloc(len + 1);

        while (!done) {
                switch (ch = input()) {
		case 0:
		case EOF:
			goto badstring;
                case '\\':
                        switch (ch = input()) {
			case 0:
			case EOF:
				goto badstring;
                        case 'r':
                                ch = '\r';
                                break;
                        case 'n':
                                ch = '\n';
                                break;
                        case 't':
                                ch = '\t';
                                break;
                        }
                        break;
                case '"':
                        done = 1;
                        continue;
                }

                *(yylval.string + pos) = ch;
                pos++;
                if (pos >= len) {
                        len *= 2;
                        yylval.string = xrealloc(yylval.string, len + 1);
                }
        }

        *(yylval.string + pos) = '\0';

        return (STRING);

badstring:
	free(yylval.string);
	yylval.string = NULL;

	return (STRING);
}
mailcmd return (OPTMAILCMD);
mailtime return (OPTMAILTIME);
cachefile return (OPTCACHEFILE);
pidfile return (OPTPIDFILE);
user return (OPTUSER);
group return (OPTGROUP);
not return (TOKNOT);
in return (TOKIN);
file return (TOKFILE);
tag return (TOKTAG);
set return (TOKSET);
match return (TOKMATCH);
ignore return (TOKIGNORE);
exec return (TOKEXEC);
open return (TOKOPEN);
expire return (TOKEXPIRE);
append return (TOKAPPEND);
close return (TOKCLOSE);
pipe return (TOKPIPE);
when return (TOKWHEN);
\* {
        yylval.tags = xmalloc(sizeof (struct tags));
	TAILQ_INIT(&yylval.tags->tags);

        return (TAGS);
}
[A-Za-z][A-Za-z0-9_-]* {
	struct tag	*tag;

	if (strlen(yytext) > MAXTAGLEN - 1) {
		yylval.tags = NULL;
		return (TAGS);
	}

        yylval.tags = xmalloc(sizeof (struct tags));
	TAILQ_INIT(&yylval.tags->tags);

	tag = xmalloc(sizeof (struct tag));
	strlcpy(tag->name, yytext, sizeof tag->name);
	TAILQ_INSERT_HEAD(&yylval.tags->tags, tag, entry);

        return (TAGS);
}
\#.*\n /* ignore comments */;
\n /* ignore end of line */;
[ \t]+ /* ignore whitespace */;

%%
