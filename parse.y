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

/* Declarations */

%{
#include <sys/types.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logfmon.h"

extern int yylineno;

int yyparse(void);
void yyerror(const char *);
int yywrap(void);

extern int yylex(void);

__dead void
yyerror(const char *s)
{
        log_warnx("%s: %s at line %d", conf.conf_file, s, yylineno);
	exit(1);
}

int
yywrap(void)
{
        return (1);
}
%}

%token TOKMATCH TOKIGNORE TOKSET TOKFILE TOKIN TOKTAG
%token TOKOPEN TOKAPPEND TOKCLOSE TOKEXPIRE TOKWHEN TOKNOT
%token OPTMAILCMD OPTMAILTIME OPTUSER OPTGROUP OPTCACHEFILE 
%token OPTPIDFILE OPTLOGREGEXP OPTMAXTHREADS

%union
{
        int 	 	 number;
        char 		*string;
        struct tags 	*tags;
	struct {
		enum action	 act;
		char 		*str;
	} action;
}

%token <number> NUMBER
%token <number> TIME
%token <string> STRING
%token <tags> TAGS
%token <action.act> BASICACTION

%type  <number> time
%type  <action> action
%type  <tags> tags
%type  <string> not

%%

/* Rules */

cmds:
     | cmds rule
     | cmds set
     | cmds file

time:
        TIME
      | NUMBER
        {
		$$ = $1;
        }

set: TOKSET OPTMAILCMD STRING
     {
             if (conf.mail_cmd != NULL)
                     xfree(conf.mail_cmd);
             conf.mail_cmd = $3;
     }
   | TOKSET OPTCACHEFILE STRING
     {
             if (conf.cache_file == NULL)
                     conf.cache_file = $3;
             else
                     xfree($3);
     }
   | TOKSET OPTPIDFILE STRING
     {
             if (conf.pid_file == NULL)
                     conf.pid_file = $3;
             else
                     xfree($3);
     } 
   | TOKSET OPTMAILTIME time
     {
             if ($3 < 10)
                     yyerror("mail time must be at least 10 seconds");

             conf.mail_time = $3;
     }
   | TOKSET OPTUSER STRING
     {
             struct passwd *pw;

             pw = getpwnam($3);
             if (pw == NULL) {
                     log_warnx("unknown user: %s", $3);
		     exit(1);
	     }

             conf.uid = pw->pw_uid;

             endpwent();
             xfree($3);
     }
   | TOKSET OPTUSER NUMBER
     {
             struct passwd *pw;

             pw = getpwuid($3);
             if (pw == NULL) {
                     log_warnx("unknown uid: %d", $3);
		     exit(1);
	     }

             conf.uid = pw->pw_uid;

             endpwent();
     }
   | TOKSET OPTGROUP STRING
     {
             struct group *gr;

             gr = getgrnam($3);
             if (gr == NULL) {
                     log_warnx("unknown group: %s", $3);
		     exit(1);
	     }

             conf.gid = gr->gr_gid;

             endgrent();
             xfree($3);
     }
   | TOKSET OPTGROUP NUMBER
     {
             struct group *gr;

             gr = getgrgid($3);
             if (gr == NULL) {
                     log_warnx("unknown gid: %d", $3);
		     exit(1);
	     }

             conf.gid = gr->gr_gid;

             endgrent();
     }
   | TOKSET OPTLOGREGEXP STRING
     {
	     if (regcomp(&conf.entry_re, $3, REG_EXTENDED) != 0) {
		     log_warnx("invalid log regexp: %s", $3);
		     exit(1);
	     }

             xfree($3);
     }
   | TOKSET OPTMAXTHREADS NUMBER
     {
             if ($3 < 10)
                     yyerror("max threads must be at least 10");
             conf.thr_limit = $3;
     }

action: 
        BASICACTION STRING
        {
		$$.act = $1;
		$$.str = $2;
        }
      | TOKIGNORE
        {
		$$.act = ACT_IGNORE;
		$$.str = NULL;
        }

tags:
      TOKIN TAGS
      {
	      if ($2 == NULL)
                      yyerror("no tags or illegal tag");		      

	      $$ = $2;
      }
    | /* empty */ 
      {
	      $$ = xmalloc(sizeof (struct tags));
	      TAILQ_INIT(&$$->tags);
      }

not:
      TOKNOT STRING
      {
	      $$ = $2;
      }
    | /* empty */
      {
	      $$ = NULL;
      }

rule: /* match, action=* */
      TOKMATCH tags STRING not action
      {
              struct rule *rule;
	      
              rule = add_rule($5.act, $2, $3, $4);

              if (rule == NULL)
                      exit(1);

              rule->params.str = $5.str;

              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

    /* match, action=open, expire=* */
    | TOKMATCH tags STRING not TOKOPEN STRING TOKEXPIRE time action
      {
              struct rule *rule;

              if (*$6 == '\0')
                      yyerror("context key cannot be empty string");

              if ($8 == 0)
                      yyerror("expiry time cannot be zero");

              rule = add_rule(ACT_OPEN, $2, $3, $4);

              if (rule == NULL)
                      exit(1);

              rule->params.key = $6;

	      rule->params.exp_act = $9.act;
	      rule->params.exp_str = $9.str;
              rule->params.exp_time = $8;

              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

    /* match, action=open, expire=*, when=* */
    | TOKMATCH tags STRING not TOKOPEN STRING TOKEXPIRE time action 
          TOKWHEN NUMBER action
      {
              struct rule *rule;

              if (*$6 == '\0')
                      yyerror("context key cannot be empty string");

              if ($8 == 0)
                      yyerror("expiry time cannot be zero");

              if ($11 == 0)
                      yyerror("number of entries cannot be zero");

              rule = add_rule(ACT_OPEN, $2, $3, $4);

              if (rule == NULL)
                      exit(1);

              rule->params.key = $6;

	      rule->params.exp_act = $9.act;
	      rule->params.exp_str = $9.str;
              rule->params.exp_time = $8;

              rule->params.ent_max = $11;
	      rule->params.ent_act = $12.act;
	      rule->params.ent_str = $12.str;

              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

      /* match, action=append */
    | TOKMATCH tags STRING not TOKAPPEND STRING
      {
              struct rule *rule;

              if (*$6 == '\0')
                      yyerror("context key cannot be empty string");

              rule = add_rule(ACT_APPEND, $2, $3, $4);

              if (rule == NULL)
                      exit(1);

              rule->params.key = $6;

              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

      /* match, action=close */
    | TOKMATCH tags STRING not TOKCLOSE STRING action
      {
              struct rule *rule;

              if (*$6 == '\0')
                      yyerror("context key cannot be empty string");

              rule = add_rule(ACT_CLOSE, $2, $3, $4);

              if (rule == NULL)
                      exit(1);

              rule->params.key = $6;

	      rule->params.close_act = $7.act;
	      rule->params.close_str = $7.str;

              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

file: TOKFILE STRING TOKTAG TAGS
      {
	      struct tag	*tag;

              if (*$2 == '\0')
                      yyerror("path cannot be empty string");

              if ($4 == NULL)
                      yyerror("no tags or illegal tag");

	      tag = TAILQ_FIRST(&$4->tags);
	      if (tag == NULL)
                      yyerror("at least one tag must be given");
              if (TAILQ_NEXT(tag, entry) != NULL)
                      yyerror("only one tag may be assigned to a file");

              if (add_file($2, tag->name) == NULL)
                      exit(1);

              xfree($2);

              xfree(tag);
              xfree($4);
      }
    | TOKFILE STRING
      {
              unsigned int	n;
              char		name[13];

              if (*$2 == '\0')
                      yyerror("path cannot be empty string");

              for (n = 1; n > 0; n++) {
                      snprintf(name, sizeof name, "__%u", n);
                      if (!find_file_by_tag(name))
                              break;
              }
              if (n > 0) {
                      if (add_file($2, name) == NULL)
                              exit(1);
              } else {
                      log_warnx("%s: unable to find unused tag", $2);
		      exit(1);
	      }
              xfree($2);
      }

%%

/* Programs */
