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

%option yylineno
%{
#include <stdio.h>
#include <string.h>
#include "xmalloc.h"
#include "y.tab.h"
%}
%%
[0-9]+[hms]             {
                          char ch;

                          ch = *(yytext + strlen(yytext) - 1);
                          *(yytext + strlen(yytext) - 1) = '\0';

                          yylval.number=atoi(yytext);
                          switch(ch)
                          {
                            case 'h':
                              yylval.number *= 3600;
                              break;
                            case 'm':
                              yylval.number *= 60;
                              break;
                          }

                          return TIME;
                        } 
[0-9]+                  {
                          yylval.number=atoi(yytext);
                          return NUMBER;
                        }
\"                      {
                          int ch, pos, len, done;

                          done = 0;
                          len  = 24;
                          pos  = 0;

                          yylval.string = (char *) xmalloc(len + 1);
    
                          while(!done && (ch = input()))
                          {
                            switch(ch)
                            {
                              case '\\':
                                switch(ch = input())
                                {
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
                            if(pos == len)
                            {
                              len *= 2;
                              yylval.string = (char *) xrealloc(yylval.string, len + 1);
                            } 
                          }
                          
                          *(yylval.string + pos) = '\0';             

                          return STRING;
                        }
mailcmd                 return OPTMAILCMD;
mailtime                return OPTMAILTIME;
in			return TOKIN;
file			return TOKFILE;
tag			return TOKTAG;
set                     return TOKSET;
match                   return TOKMATCH;
ignore                  return TOKIGNORE;
exec                    return TOKEXEC;
open                    return TOKOPEN;
expire                  return TOKEXPIRE;
append                  return TOKAPPEND;
close                   return TOKCLOSE;
pipe                    return TOKPIPE;
when                    return TOKWHEN;
\*			return TOKALL;
[A-Za-z0-9_-]+ 		{
                          yylval.string = (char *) xmalloc(strlen(yytext) + 1);
			  strcpy(yylval.string, yytext);

			  return TAG;
			}
\#.*\n                  /* ignore comments */;
\n                      /* ignore end of line */;
[ \t]+                  /* ignore whitespace */;
%%
