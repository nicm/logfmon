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
#include <stdlib.h>

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

%token TOKMATCH TOKIGNORE TOKEXEC TOKSET TOKFILE TOKIN TOKTAG TOKALL
%token TOKOPEN TOKAPPEND TOKCLOSE TOKPIPE TOKEXPIRE
%token OPTMAILCMD OPTMAILTIME

%union 
{
  int number;
  char *string;
}

%token <number> NUMBER
%token <number> TIME
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
   | TOKSET OPTMAILTIME TIME
     {
       mail_time = $3;
     }
   | TOKSET OPTMAILTIME NUMBER
     {
       mail_time = $3;
     }
   ;

rule: TOKMATCH STRING TOKEXEC STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_EXEC, NULL, $2);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $4;

	free($2);
      }
    | TOKMATCH STRING TOKPIPE STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_PIPE, NULL, $2);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $4;

	free($2);
      }
    | TOKMATCH STRING TOKIGNORE
      {
	struct rule *rule;

	rule = add_rule(ACTION_IGNORE, NULL, $2);

	if(rule == NULL)
	  exit(1);

	free($2);
      }
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE
      {
	struct rule *rule;

	if(*$4 == '\0')
	  die("context key cannot be empty string");

	if($6 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;

	free($2);
      }
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$4 == '\0')
	  die("context key cannot be empty string");

	if($6 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;

	free($2);
      }
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING
      {
	struct rule *rule;

	if(*$4 == '\0')
	  die("context key cannot be empty string");

	if($6 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;
	rule->params.cmd = $8;

	free($2);
      }
    | TOKMATCH STRING TOKAPPEND STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_APPEND, NULL, $2);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;

	free($2);
      }
    | TOKMATCH STRING TOKCLOSE STRING TOKPIPE STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_CLOSE, NULL, $2);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.cmd = $6;

	free($2);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKEXEC STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_EXEC, NULL, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.cmd = $6;
      }
    | TOKMATCH TOKIN TOKALL STRING TOKPIPE STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_PIPE, NULL, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.cmd = $6;
      }
    | TOKMATCH TOKIN TOKALL STRING TOKIGNORE
      {
	struct rule *rule;

	rule = add_rule(ACTION_IGNORE, NULL, $4);

	if(rule == NULL)
	  exit(1);

	free($4);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE
      {
	struct rule *rule;

	if(*$6 == '\0')
	  die("context key cannot be empty string");

	if($8 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	free($4);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$6 == '\0')
	  die("context key cannot be empty string");

	if($8 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	free($4);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING
      {
	struct rule *rule;

	if(*$6 == '\0')
	  die("context key cannot be empty string");

	if($8 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	free($4);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$6 == '\0')
	  die("context key cannot be empty string");

	if($8 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	free($4);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKAPPEND STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_APPEND, NULL, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	
	free($4);
      }
    | TOKMATCH TOKIN TOKALL STRING TOKCLOSE STRING TOKPIPE STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_CLOSE, NULL, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.cmd = $8;

	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKEXEC STRING
      {
	struct rule *rule;

	if(*$3 == '\0')
	  die("tag cannot be empty string");

	rule = add_rule(ACTION_EXEC, $3, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $6;

	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKPIPE STRING
      {
	struct rule *rule;

	if(*$3 == '\0')
	  die("tag cannot be empty string");

	rule = add_rule(ACTION_PIPE, $3, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $6;

	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKIGNORE
      {
	struct rule *rule;

	if(*$3 == '\0')
	  die("tag cannot be empty string");

	rule = add_rule(ACTION_IGNORE, $3, $4);

	if(rule == NULL)
	  exit(1);

	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE
      {
	struct rule *rule;

	if(*$3 == '\0')
	  die("tag cannot be empty string");

	if(*$6 == '\0')
	  die("context key cannot be empty string");

	if($8 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$3 == '\0')
	  die("tag cannot be empty string");

	if(*$6 == '\0')
	  die("context key cannot be empty string");

	if($8 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING
      {
	struct rule *rule;

	if(*$3 == '\0')
	  die("tag cannot be empty string");

	if(*$6 == '\0')
	  die("context key cannot be empty string");

	if($8 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$6 == '\0')
	  die("context key cannot be empty string");

	if($8 == 0)
	  die("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKAPPEND STRING
      {
	struct rule *rule;

	if(*$3 == '\0')
	  die("tag cannot be empty string");

	rule = add_rule(ACTION_APPEND, $3, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;

	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAG STRING TOKCLOSE STRING TOKPIPE STRING
      {
	struct rule *rule;

	if(*$3 == '\0')
	  die("tag cannot be empty string");

	rule = add_rule(ACTION_CLOSE, $3, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.cmd = $8;

	free($3);
	free($4);
      }
    ;

file: TOKFILE STRING TOKTAG TAG
      {
	if(*$2 == '\0')
	  die("path cannot be empty string");

	if(*$4 == '\0')
	  die("tag cannot be empty string");

	if(add_file($2, $4))
	  exit(1);
	free($2);
	free($4);
      }
    | TOKFILE STRING
      {
	unsigned int num;
	char tag[13];

	if(*$2 == '\0')
	  die("path cannot be empty string");

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

