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
#include <pwd.h>
#include <grp.h>
#include <unistd.h>

#include "logfmon.h"
#include "rules.h"
#include "log.h"
#include "file.h"
#include "tags.h"

extern int yylineno; 

int yyparse(void);
void yyerror(const char *);
int yywrap(void);
int yylex(void);

void yyerror(const char *str)
{
  die("%s at line %d", str, yylineno);
}
  
int yywrap(void)
{
  return 1;
} 
%}

%token TOKMATCH TOKIGNORE TOKEXEC TOKSET TOKFILE TOKIN TOKTAG
%token TOKOPEN TOKAPPEND TOKCLOSE TOKPIPE TOKEXPIRE TOKWHEN TOKNOT
%token OPTMAILCMD OPTMAILTIME OPTUSER OPTGROUP OPTCACHEFILE

%union 
{
  int number;
  char *string;
  struct tags *tags;
}

%token <number> NUMBER
%token <number> TIME
%token <string> STRING
%token <tags> TAGS;

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
   | TOKSET OPTCACHEFILE STRING
     {
       if(cache_file == NULL)
	 cache_file = $3;
       else
	 free($3);
     }
   | TOKSET OPTMAILTIME TIME
     {
       if($3 < 10)
	 yyerror("mail time must be at least 10 seconds");

       mail_time = $3;
     }
   | TOKSET OPTMAILTIME NUMBER
     {
       if($3 < 10)
	 yyerror("mail time must be at least 10 seconds");

       mail_time = $3;
     }
   | TOKSET OPTUSER STRING
     {
       struct passwd *pw;

       pw = getpwnam($3);
       if(pw == NULL)
	 die("unknown user %s", $3);

       uid = pw->pw_uid;

       endpwent();
       free($3);
     }
   | TOKSET OPTUSER NUMBER
     {
       struct passwd *pw;

       pw = getpwuid($3);
       if(pw == NULL)
	 die("unknown uid %d", $3);

       uid = pw->pw_uid;

       endpwent();
     }
   | TOKSET OPTGROUP STRING
     {
       struct group *gr;

       gr = getgrnam($3);
       if(gr == NULL)
	 die("unknown group %s", $3);

       gid = gr->gr_gid;

       endgrent();
       free($3);
     }
   | TOKSET OPTGROUP NUMBER
     {
       struct group *gr;

       gr = getgrgid($3);
       if(gr == NULL)
	 die("unknown gid %s", $3);

       gid = gr->gr_gid;

       endgrent();
     }
   ;

rule: /* match, exec */
      TOKMATCH STRING TOKEXEC STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_EXEC, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $4;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKEXEC STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_EXEC, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $6;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKEXEC STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_EXEC, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $6;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKEXEC STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_EXEC, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $8;

	free($4);
	free($6);
      }

      /* match, pipe */
    | TOKMATCH STRING TOKPIPE STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_PIPE, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $4;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKPIPE STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_PIPE, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $6;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_PIPE, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $6;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_PIPE, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.cmd = $8;

	free($4);
	free($6);
      }

      /* match, ignore */
    | TOKMATCH STRING TOKIGNORE
      {
	struct rule *rule;

	rule = add_rule(ACTION_IGNORE, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKIGNORE
      {
	struct rule *rule;

	rule = add_rule(ACTION_IGNORE, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_IGNORE, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_IGNORE, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	free($4);
	free($6);
      }

      /* match, open, ignore, none */
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	free($2);
	free($4);
      }
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;

	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;

	free($4);
	free($6);
      }

      /* match, open, pipe, none */
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;
	rule->params.cmd = $8;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	free($2);
	free($4);
      }
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;
	rule->params.cmd = $8;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;
	rule->params.cmd = $12;

	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;
	rule->params.cmd = $12;

	free($4);
	free($6);
      }

      /* match, open, ignore, ignore */
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	if($9 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;

	rule->params.ent_max = $9;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($11 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	rule->params.ent_max = $11;

	free($2);
	free($4);
      }
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	if($9 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;

	rule->params.ent_max = $9;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($11 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	rule->params.ent_max = $11;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($11 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	rule->params.ent_max = $11;

	free($3);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	if($13 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;

	rule->params.ent_max = $13;

	free($3);
	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($11 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	rule->params.ent_max = $11;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	if($13 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;

	rule->params.ent_max = $13;

	free($4);
	free($6);
      }

      /* match, open, ignore, pipe */
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	if($9 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;

	rule->params.ent_max = $9;
	rule->params.ent_cmd = $11;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($11 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	rule->params.ent_max = $11;
	rule->params.ent_cmd = $13;

	free($2);
	free($4);
      }
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	if($9 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;

	rule->params.ent_max = $9;
	rule->params.ent_cmd = $11;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($11 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	rule->params.ent_max = $11;
	rule->params.ent_cmd = $13;

	free($2);
	free($4);
      }
     | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($11 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	rule->params.ent_max = $11;
	rule->params.ent_cmd = $13;

	free($4);
      }
     | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKIGNORE TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	if($13 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;

	rule->params.ent_max = $13;
	rule->params.ent_cmd = $15;

	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($11 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;

	rule->params.ent_max = $11;
	rule->params.ent_cmd = $13;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKIGNORE TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	if($13 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;

	rule->params.ent_max = $13;
	rule->params.ent_cmd = $15;

	free($4);
	free($6);
      }

      /* match, open, pipe, pipe */
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	if($10 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;
	rule->params.cmd = $8;

	rule->params.ent_max = $10;
	rule->params.ent_cmd = $12;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($12 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	rule->params.ent_max = $12;
	rule->params.ent_cmd = $14;

	free($2);
	free($4);
      }
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	if($10 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;
	rule->params.cmd = $8;

	rule->params.ent_max = $10;
	rule->params.ent_cmd = $12;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($12 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	rule->params.ent_max = $12;
	rule->params.ent_cmd = $14;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($12 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	rule->params.ent_max = $12;
	rule->params.ent_cmd = $14;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	if($14 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;
	rule->params.cmd = $12;

	rule->params.ent_max = $14;
	rule->params.ent_cmd = $16;

	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($12 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	rule->params.ent_max = $12;
	rule->params.ent_cmd = $14;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING TOKWHEN NUMBER TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	if($14 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;
	rule->params.cmd = $12;

	rule->params.ent_max = $14;
	rule->params.ent_cmd = $16;

	free($4);
	free($6);
      }

      /* match, open, pipe, ignore */
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	if($10 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;
	rule->params.cmd = $8;

	rule->params.ent_max = $10;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($12 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	rule->params.ent_max = $12;

	free($2);
	free($4);
      }
    | TOKMATCH STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$4 == '\0')
	  yyerror("context key cannot be empty string");

	if($6 == 0)
	  yyerror("expiry time cannot be zero");

	if($10 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.expiry = $6;
	rule->params.cmd = $8;

	rule->params.ent_max = $10;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($12 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	rule->params.ent_max = $12;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($12 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	rule->params.ent_max = $12;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE TIME TOKPIPE STRING TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	if($14 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;
	rule->params.cmd = $12;

	rule->params.ent_max = $14;

	free($4);
	free($6);
      }
    | TOKMATCH TOKIN TAGS STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$6 == '\0')
	  yyerror("context key cannot be empty string");

	if($8 == 0)
	  yyerror("expiry time cannot be zero");

	if($12 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.expiry = $8;
	rule->params.cmd = $10;

	rule->params.ent_max = $12;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKOPEN STRING TOKEXPIRE NUMBER TOKPIPE STRING TOKWHEN NUMBER TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	if(*$8 == '\0')
	  yyerror("context key cannot be empty string");

	if($10 == 0)
	  yyerror("expiry time cannot be zero");

	if($14 == 0)
	  yyerror("number of entries cannot be zero");

	rule = add_rule(ACTION_OPEN, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.expiry = $10;
	rule->params.cmd = $12;

	rule->params.ent_max = $14;

	free($4);
	free($6);
      }

      /* match, append */
    | TOKMATCH STRING TOKAPPEND STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_APPEND, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKAPPEND STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_APPEND, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKAPPEND STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_APPEND, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKAPPEND STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_APPEND, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;

	free($4);
	free($6);
      }

      /* match, close, ignore */
    | TOKMATCH STRING TOKCLOSE STRING TOKIGNORE
      {
	struct rule *rule;

	rule = add_rule(ACTION_CLOSE, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKCLOSE STRING TOKIGNORE
      {
	struct rule *rule;

	rule = add_rule(ACTION_CLOSE, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKCLOSE STRING TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_CLOSE, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKCLOSE STRING TOKIGNORE
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_CLOSE, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;

	free($4);
	free($6);
      }

      /* match, close, pipe */
    | TOKMATCH STRING TOKCLOSE STRING TOKPIPE STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_CLOSE, NULL, $2, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $4;
	rule->params.cmd = $6;

	free($2);
      }
    | TOKMATCH STRING TOKNOT STRING TOKCLOSE STRING TOKPIPE STRING
      {
	struct rule *rule;

	rule = add_rule(ACTION_CLOSE, NULL, $2, $4);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.cmd = $8;

	free($2);
	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKCLOSE STRING TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_CLOSE, $3, $4, NULL);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $6;
	rule->params.cmd = $8;

	free($4);
      }
    | TOKMATCH TOKIN TAGS STRING TOKNOT STRING TOKCLOSE STRING TOKPIPE STRING
      {
	struct rule *rule;

	if($3 == NULL)
	  yyerror("no tags or illegal tag");

	rule = add_rule(ACTION_CLOSE, $3, $4, $6);

	if(rule == NULL)
	  exit(1);

	rule->params.key = $8;
	rule->params.cmd = $10;

	free($4);
	free($6);
      }
    ;

file: TOKFILE STRING TOKTAG TAGS
      {
	if(*$2 == '\0')
	  yyerror("path cannot be empty string");

	if($4 == NULL)
	  yyerror("no tags or illegal tag");

	if($4->head == NULL)
	  yyerror("at least one tag must be given");

	if($4->head->next != NULL)
	  yyerror("only one tag may be assigned to a file");

	if(add_file($2, $4->head->name))
	  exit(1);

	free($2);

	clear_tags($4);
	free($4);
      }
    | TOKFILE STRING
      {
	unsigned int num;
	char tag[13];

	if(*$2 == '\0')
	  yyerror("path cannot be empty string");

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

