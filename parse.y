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

/* Declarations */

%{
#include <stdio.h>
#include <string.h>

#include "logfmon.h"
#include "rules.h"
#include "log.h"
#include "file.h"
 
int yyparse(void);
void yyerror(const char *);
int yywrap(void);
int yylex(void);

void yyerror(const char *str)
{
  die("%s", str);
}
  
int yywrap(void)
{
  return 1;
} 
%}

%token TOKMATCH TOKIGNORE TOKEXEC TOKSET TOKFILE TOKIN TOKTAG TOKALL TOKOPEN TOKAPPEND
%token OPTMAILCMD OPTMAILTIME

%union 
{
  int number;
  char *string;
}

%token <number> NUMBER
%token <string> STRING
%token <string> TAG

%%

/* Rules */

cmds:
     | cmds rule
     | cmds set
     | cmds file
     ;

set: TOKSET OPTMAILCMD STRING
     {
       if(mail_cmd != NULL)
	 free(mail_cmd);
       mail_cmd = $3;
     }
   | TOKSET OPTMAILTIME NUMBER
     {
       mail_time = $3;
     }
   ;

rule: TOKMATCH STRING TOKEXEC STRING
      {
	if(add_rule(ACTION_EXEC, $4, $2, NULL))
	  exit(1);
	free($2);
	free($4);
      }
    | TOKMATCH STRING TOKIGNORE
      {
	if(add_rule(ACTION_IGNORE, NULL, $2, NULL))
	  exit(1);
	free($2);
      }
    | TOKMATCH STRING TOKOPEN STRING
      {
	if(add_rule(ACTION_OPEN, $4, $2, NULL))
	  exit(1);
	free($2);
	free($4);
      }
    | TOKMATCH STRING TOKAPPEND STRING
      {
	if(add_rule(ACTION_APPEND, $4, $2, NULL))
	  exit(1);
	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKEXEC STRING
      {
	if(add_rule(ACTION_EXEC, $6, $4, NULL))
	  exit(1);
	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKIGNORE
      {
	if(add_rule(ACTION_IGNORE, NULL, $4, NULL))
	  exit(1);
	free($4);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKOPEN STRING
      {
	if(add_rule(ACTION_OPEN, $6, $4, NULL))
	  exit(1);
	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKAPPEND STRING
      {
	if(add_rule(ACTION_APPEND, $6, $4, NULL))
	  exit(1);
	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TAG STRING TOKEXEC STRING
      {
	if(add_rule(ACTION_EXEC, $6, $4, $3))
	  exit(1);
	free($3);
	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TAG STRING TOKIGNORE
      {
	if(add_rule(ACTION_IGNORE, NULL, $4, $3))
	  exit(1);
	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKOPEN STRING
      {
	if(add_rule(ACTION_OPEN, $6, $4, $3))
	  exit(1);
	free($3);
	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TAG STRING TOKAPPEND STRING
      {
	if(add_rule(ACTION_APPEND, $6, $4, $3))
	  exit(1);
	free($3);
	free($4);
	free($6);
      }
    ;

file: TOKFILE STRING TOKTAG TAG
      {
	if(add_file($2, $4))
	  exit(1);
	free($2);
	free($4);
      }
    | TOKFILE STRING
      {
	unsigned int num;
	char tag[13];
	for(num = 1; num > 0; num++)
	{
	  snprintf(tag,13,"__%u",num);
	  if(!find_file_by_tag(tag))
	    break;
	}
	if(num > 0)
	{	
   	  if(add_file($2, tag))
	    exit(1);
	}
	else
	  die("%s: unable to find unused tag", $2);
	free($2);
      }
    ;

%%

/* Programs */

