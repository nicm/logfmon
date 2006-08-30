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
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "logfmon.h"
#include "y.tab.h"

extern int yylex(void);
extern __dead void yyerror(const char *);
%}

%%

\{ {
        int	 	 done = 0, ch;
	unsigned int	 pos = 0;
        char	 	 name[MAXTAGLEN];
	struct tag	*tag;

        yylval.tags = xmalloc(sizeof (struct tags));
        TAILQ_INIT(yylval.tags);

        while (!done) {
                switch (ch = input()) {
		case 0:
		case EOF:
			yyerror("unterminated tag list");
                case '}':
			done = 1;
			break;
                case ' ':
                        if (pos > 0) {
                                *(name + pos) = '\0';
				tag = xmalloc(sizeof (struct tag));
				strlcpy(tag->name, name, sizeof tag->name);
				TAILQ_INSERT_TAIL(yylval.tags, tag, entry);
                                pos = 0;
                        }
                        break;
                default:
                        if (ch == '-' || ch == '_' ||
			    isalpha((unsigned char) ch) ||
			    isdigit((unsigned char) ch)) {
				/* Tag must begin with a letter */
				if (pos == 0 && !isalpha((unsigned char) ch))
					yyerror("illegal tag first character");
                                *(name + pos) = ch;
                                pos++;
				/* Bail if the size has become too long */
                                if (pos >= sizeof name)
					yyerror("tag too long");
			} else
				yyerror("illegal character in tag");
                        break;
                }
        }

        if (pos > 0) {
		*(name + pos) = '\0';
		tag = xmalloc(sizeof (struct tag));
		strlcpy(tag->name, name, sizeof tag->name);
		TAILQ_INSERT_TAIL(yylval.tags, tag, entry);
        }

        if (TAILQ_EMPTY(yylval.tags))
		yyerror("empty tag list");

        return (TAGS);
}
[0-9]+[HhMmSs] {
	const char	*errstr;
        char	       *cp, ch;

	cp = yytext + strlen(yytext) - 1;
	ch = *cp;
	*cp = '\0';

        yylval.number = strtonum(yytext, 0, INT_MAX, &errstr);
	if (errstr != NULL)
		yyerror("illegal number");
        switch (ch) {
        case 'h':
	case 'H':
		if (yylval.number > INT_MAX / 3600)
			yyerror("time too large");
                yylval.number *= 3600;
                break;
        case 'm':
	case 'M':
		if (yylval.number > INT_MAX / 60)
			yyerror("time too large");
                yylval.number *= 60;
                break;
        }

        return (TIME);
}
[0-9]+ {
	const char	*errstr;

        yylval.number = strtonum(yytext, 0, INT_MAX, &errstr);
	if (errstr != NULL)
		yyerror("illegal number");

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
			yyerror("unterminated string");
                case '\\':
                        switch (ch = input()) {
			case 0:
			case EOF:
				yyerror("unterminated string");
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
		ENSURE_SIZE(yylval.string, len, pos);
        }

        *(yylval.string + pos) = '\0';

        return (STRING);
}
mailcmd return (OPTMAILCMD);
mailtime return (OPTMAILTIME);
cachefile return (OPTCACHEFILE);
pidfile return (OPTPIDFILE);
logregexp return (OPTLOGREGEXP);
maxthreads return (OPTMAXTHREADS);
user return (OPTUSER);
group return (OPTGROUP);
not return (TOKNOT);
in return (TOKIN);
file return (TOKFILE);
tag return (TOKTAG);
set return (TOKSET);
match return (TOKMATCH);
ignore return (TOKIGNORE);
open return (TOKOPEN);
expire return (TOKEXPIRE);
append return (TOKAPPEND);
close return (TOKCLOSE);
clear return (TOKCLEAR);
when return (TOKWHEN);
(auto-append|autoappend) return (TOKAUTOAPPEND);
(exec|pipe|write|write-append) {
	int	i;

	for (i = 0; actions[i] != NULL; i++) {
		if (strcmp(yytext, actions[i]) == 0)
			break;
	}
	if (actions[i] == NULL)
		yyerror("unknown action");
	yylval.action.act = i;
	    
	return (BASICACTION);
}
\* {
        yylval.tags = xmalloc(sizeof (struct tags));
	TAILQ_INIT(yylval.tags);

        return (TAGS);
}
[A-Za-z][A-Za-z0-9_-]* {
	struct tag	*tag;

	if (strlen(yytext) > MAXTAGLEN - 1)
		yyerror("tag too long");

        yylval.tags = xmalloc(sizeof (struct tags));
	TAILQ_INIT(yylval.tags);

	tag = xmalloc(sizeof (struct tag));
	strlcpy(tag->name, yytext, sizeof tag->name);
	TAILQ_INSERT_HEAD(yylval.tags, tag, entry);

        return (TAGS);
}
\#.*\n /* ignore comments */;
\n /* ignore end of line */;
[ \t]+ /* ignore whitespace */;

%%
