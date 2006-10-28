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
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "logfmon.h"

extern int yylineno;

int		yyparse(void);
void 		yyerror(const char *, ...);
int 		yywrap(void);
struct macro   *find_macro(char *);

extern int yylex(void);

struct macro {
	char			*name;
	union {
		int	 	 number;
		char		*string;
	} value;
	enum {
		MACRO_NUMBER,
		MACRO_STRING
	} type;

	TAILQ_ENTRY(macro)	entry;
};
TAILQ_HEAD(macros, macro)	macros = TAILQ_HEAD_INITIALIZER(macros);

__dead void
yyerror(const char *fmt, ...)
{
        va_list  ap;
        char    *s;

        xasprintf(&s, "%s: %s at line %d", conf.conf_file, fmt, yylineno);

        va_start(ap, fmt);
        vlog(LOG_CRIT, s, ap);
        va_end(ap);

        exit(1);
}

int
yywrap(void)
{
	struct macro	*macro;

	while (!TAILQ_EMPTY(&macros)) {
		macro = TAILQ_FIRST(&macros);
		TAILQ_REMOVE(&macros, macro, entry);
		xfree(macro->name);
		if (macro->type == MACRO_STRING)
			xfree(macro->value.string);
		xfree(macro);
	}

        return (1);
}

struct macro *
find_macro(char *name)
{
	struct macro	*macro;

	TAILQ_FOREACH(macro, &macros, entry) {
		if (strcmp(macro->name, name) == 0)
			return (macro);
	}

	return (NULL);
}
%}

%token TOKMATCH TOKIGNORE TOKSET TOKFILE TOKIN TOKTAG TOKAUTOAPPEND
%token TOKOPEN TOKAPPEND TOKCLOSE TOKEXPIRE TOKWHEN TOKNOT TOKCLEAR
%token OPTMAILCMD OPTMAILTIME OPTUSER OPTGROUP OPTCACHEFILE 
%token OPTPIDFILE OPTLOGREGEXP OPTMAXTHREADS

%union
{
        int 	 	 number;
        char 		*string;
	int		 flag;
        struct tags 	*tags;
	struct {
		enum action	 act;
		char 		*str;
	} action;
}

%token <number> NUMBER TIME
%token <string> STRING STRMACRO NUMMACRO
%token <tags> TAGS
%token <action.act> BASICACTION

%type  <number> time num
%type  <action> action
%type  <tags> tags
%type  <string> not str
%type  <number> user
%type  <number> group
%type  <flag> autoappend

%%

/* Rules */

cmds: /* empty */
    | cmds rule
    | cmds set
    | cmds file

time: TIME
    | num
      {
	      $$ = $1;
      }

str: STRING
     {
	     $$ = $1;
     }
   | STRMACRO
     {
	     struct macro	*macro;

	     if ((macro = find_macro($1)) == NULL)
		     yyerror("undefined macro: %s", $1);
	     if (macro->type != MACRO_STRING)
		     yyerror("string macro expected: %s", $1);

	     $$ = macro->value.string;
     }

num: NUMBER
     {
	     $$ = $1;
     }
   | NUMMACRO
     {
	     struct macro	*macro;

	     if ((macro = find_macro($1)) == NULL)
		     yyerror("undefined macro: %s", $1);
	     if (macro->type != MACRO_NUMBER)
		     yyerror("number macro expected: %s", $1);

	     $$ = macro->value.number;
     }

user: num
      {
	      struct passwd *pw;
	      
	      pw = getpwuid($1);
	      if (pw == NULL)
		      yyerror("unknown uid %d", $1);
	      
	      $$ = pw->pw_uid;
	      
	      endpwent();
      }
    | str
      {
	      struct passwd *pw;
	     
	      pw = getpwnam($1);
	      if (pw == NULL)
		      yyerror("unknown user \"%s\"", $1);
	      
	      $$ = pw->pw_uid;
	      
	      endpwent();
	      xfree($1);
      }

group: num
       {
	       struct group *gr;

	       gr = getgrgid($1);
	       if (gr == NULL)
		       yyerror("unknown gid %d", $1);

	       $$ = gr->gr_gid;
	       
             endgrent();
       }
     | str
       {
	       struct group *gr;

	       gr = getgrnam($1);
	       if (gr == NULL)
		       yyerror("unknown group \"%s\"", $1);
	       
	       $$ = gr->gr_gid;

	       endgrent();
	       xfree($1);
       }

set: TOKSET OPTMAILCMD str
     {
             if (conf.mail_cmd != NULL)
                     xfree(conf.mail_cmd);
             conf.mail_cmd = $3;
     }
   | TOKSET OPTCACHEFILE str
     {
             if (conf.cache_file == NULL)
                     conf.cache_file = $3;
             else
                     xfree($3);
     }
   | TOKSET OPTPIDFILE str
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
   | TOKSET OPTUSER user
     {
             conf.uid = $3;
     }
   | TOKSET OPTGROUP group
     {
	     conf.gid = $3;
     }
   | TOKSET OPTLOGREGEXP str
     {
	     if (regcomp(&conf.entry_re, $3, REG_EXTENDED) != 0)
		     yyerror("invalid log regexp", $3);

             xfree($3);
     }
   | TOKSET OPTMAXTHREADS num
     {
             if ($3 < 10)
                     yyerror("max threads must be at least 10");
             conf.thr_limit = $3;
     }
   | TOKSET STRMACRO STRING
     {
	     struct macro	*macro;

	     if ((macro = find_macro($2)) == NULL) {
		     macro = xmalloc(sizeof *macro);
		     macro->name = $2;
		     TAILQ_INSERT_HEAD(&macros, macro, entry);
	     }
	     macro->type = MACRO_STRING;
	     macro->value.string = $3;
     }
   | TOKSET NUMMACRO NUMBER
     {
	     struct macro	*macro;

	     if ((macro = find_macro($2)) == NULL) {
		     macro = xmalloc(sizeof *macro);
		     macro->name = $2;
		     TAILQ_INSERT_HEAD(&macros, macro, entry);
	     }
	     macro->type = MACRO_NUMBER;
	     macro->value.number = $3;
     }

action: BASICACTION str
        {
		$$.act = $1;
		$$.str = $2;
        }
      | TOKIGNORE
        {
		$$.act = ACT_IGNORE;
		$$.str = NULL;
        }

tags: TOKIN TAGS
      {
	      if ($2 == NULL)
                      yyerror("no tags or illegal tag");		      

	      $$ = $2;
      }
    | /* empty */ 
      {
	      $$ = xmalloc(sizeof (struct tags));
	      TAILQ_INIT($$);
      }

not: TOKNOT str
     {
	     $$ = $2;
     }
   | /* empty */
     {
	     $$ = NULL;
     }

autoappend: TOKAUTOAPPEND
	    {
		    $$ = 1;
	    }
          | /* empty */
	    {
		    $$ = 0;
	    }	

rule: /* match, action=* */
      TOKMATCH tags str not action
      {
              struct rule *rule;
	      
              rule = add_rule($5.act, $2, $3, $4);
              if (rule == NULL)
                      exit(1);

              rule->params.str = $5.str;

	      free_tags($2);
	      xfree($2);
              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

    /* match, action=open, expire=* */
    | TOKMATCH tags str not TOKOPEN str autoappend TOKEXPIRE time action
      {
              struct rule *rule;

              if (*$6 == '\0')
                      yyerror("context key cannot be empty string");
	      if ($9 == 0)
                      yyerror("expiry time cannot be zero");

              rule = add_rule(ACT_OPEN, $2, $3, $4);
              if (rule == NULL)
                      exit(1);

              rule->params.key = $6;

	      rule->params.exp_act = $10.act;
	      rule->params.exp_str = $10.str;
              rule->params.exp_time = $9;

	      if ($7) {
		      rule = add_rule(ACT_APPEND, $2, $3, $4);
		      if (rule == NULL)
			      exit(1);
	      }

	      free_tags($2);
	      xfree($2);
              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

    /* match, action=open, expire=*, when=* */
    | TOKMATCH tags str not TOKOPEN str autoappend TOKEXPIRE time action 
          TOKWHEN num action
      {
              struct rule 	*rule;

              if (*$6 == '\0')
                      yyerror("context key cannot be empty string");
              if ($9 == 0)
                      yyerror("expiry time cannot be zero");
              if ($12 == 0)
                      yyerror("number of entries cannot be zero");

              rule = add_rule(ACT_OPEN, $2, $3, $4);
              if (rule == NULL)
                      exit(1);

              rule->params.key = $6;

	      rule->params.exp_act = $10.act;
	      rule->params.exp_str = $10.str;
              rule->params.exp_time = $9;

              rule->params.ent_max = $12;
	      rule->params.ent_act = $13.act;
	      rule->params.ent_str = $13.str;

	      if ($7) {
		      rule = add_rule(ACT_APPEND, $2, $3, $4);
		      if (rule == NULL)
			      exit(1);
	      }

	      free_tags($2);
	      xfree($2);
              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

      /* match, action=append */
    | TOKMATCH tags str not TOKAPPEND str
      {
              struct rule 	*rule;

              if (*$6 == '\0')
                      yyerror("context key cannot be empty string");

              rule = add_rule(ACT_APPEND, $2, $3, $4);
              if (rule == NULL)
                      exit(1);

              rule->params.key = $6;

	      free_tags($2);
	      xfree($2);
              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

      /* match, action=close */
    | TOKMATCH tags str not TOKCLOSE str action
      {
              struct rule 	*rule;

              if (*$6 == '\0')
                      yyerror("context key cannot be empty string");

              rule = add_rule(ACT_CLOSE, $2, $3, $4);
              if (rule == NULL)
                      exit(1);

              rule->params.key = $6;

	      rule->params.close_act = $7.act;
	      rule->params.close_str = $7.str;

	      free_tags($2);
	      xfree($2);
              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

      /* match, action=clear */
    | TOKMATCH tags str not TOKCLEAR str action
      {
              struct rule 	*rule;

              if (*$6 == '\0')
                      yyerror("context key cannot be empty string");

              rule = add_rule(ACT_CLEAR, $2, $3, $4);
              if (rule == NULL)
                      exit(1);

              rule->params.key = $6;

	      rule->params.clear_act = $7.act;
	      rule->params.clear_str = $7.str;

	      free_tags($2);
	      xfree($2);
              xfree($3);
	      if ($4 != NULL)
		      xfree($4);
      }

file: TOKFILE str TOKTAG TAGS
      {
	      struct tag	*tag;

              if (*$2 == '\0')
                      yyerror("path cannot be empty string");
              if ($4 == NULL)
                      yyerror("no tags or illegal tag");

	      tag = TAILQ_FIRST($4);
	      if (tag == NULL)
                      yyerror("at least one tag must be given");
              if (TAILQ_NEXT(tag, entry) != NULL)
                      yyerror("only one tag may be assigned to a file");

              if (add_file($2, xstrdup(tag->name)) == NULL)
                      exit(1);

              xfree($2);
	      free_tags($4);
              xfree($4);
      }
    | TOKFILE str
      {
              unsigned int	n;
              char		name[MAXTAGLEN], num[13], *ptr;
	      size_t		len, nlen;

              if (*$2 == '\0')
                      yyerror("path cannot be empty string");

	      if ((ptr = basename($2)) != NULL)
		      strlcpy(name, ptr, sizeof name);
	      else 
		      strlcpy(name, "__", sizeof name);
	      len = strlen(name);

	      if (find_file_by_tag(name)) {
		      for (n = 1; n > 0; n++) {
			      snprintf(num, sizeof num, "%u", n);
			      nlen = strlen(num);
			      
			      if (len + nlen > sizeof name)
				      name[(sizeof name) - nlen - 1] = '\0';
			      else
				      name[len - 1] = '\0';

			      strlcat(name, num, sizeof name);
			      log_debug("testing tag: %s (%u)", name, n);
			      
			      if (!find_file_by_tag(name))
				      break;
		      }
		      if (n == 0)
			      yyerror("unable to find unused tag");
	      }
	      if (add_file($2, name) == NULL)
		      exit(1);
              xfree($2);
      }

%%

/* Programs */
