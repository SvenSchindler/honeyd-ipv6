/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2011 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     CREATE = 258,
     ADD = 259,
     PORT = 260,
     BIND = 261,
     CLONE = 262,
     DOT = 263,
     BLOCK = 264,
     OPEN = 265,
     RESET = 266,
     DEFAULT = 267,
     SET = 268,
     ACTION = 269,
     PERSONALITY = 270,
     PERSONALITY6 = 271,
     RANDOM = 272,
     ANNOTATE = 273,
     NO = 274,
     FINSCAN = 275,
     FRAGMENT = 276,
     DROP = 277,
     OLD = 278,
     NEW = 279,
     COLON = 280,
     PROXY = 281,
     TRANSPARENT = 282,
     UPTIME = 283,
     DROPRATE = 284,
     IN = 285,
     SYN = 286,
     UID = 287,
     GID = 288,
     ROUTE = 289,
     ENTRY = 290,
     LINK = 291,
     NET = 292,
     UNREACH = 293,
     SLASH = 294,
     LATENCY = 295,
     MS = 296,
     LOSS = 297,
     BANDWIDTH = 298,
     SUBSYSTEM = 299,
     OPTION = 300,
     TO = 301,
     SHARED = 302,
     NETWORK = 303,
     SPOOF = 304,
     FROM = 305,
     TEMPLATE = 306,
     OBRACKET = 307,
     CBRACKET = 308,
     RBRACKET = 309,
     LBRACKET = 310,
     TUNNEL = 311,
     TARPIT = 312,
     DYNAMIC = 313,
     USE = 314,
     IF = 315,
     OTHERWISE = 316,
     EQUAL = 317,
     SOURCE = 318,
     OS = 319,
     IP = 320,
     BETWEEN = 321,
     DELETE = 322,
     LIST = 323,
     ETHERNET = 324,
     DHCP = 325,
     ON = 326,
     MAXFDS = 327,
     RESTART = 328,
     DEBUG = 329,
     DASH = 330,
     TIME = 331,
     INTERNAL = 332,
     RANDOMIPVS = 333,
     RANDOMEXCLUDE = 334,
     MANAGED = 335,
     HIH = 336,
     DBFILE = 337,
     SHELLCODEDIR = 338,
     SUBMISSION = 339,
     STRING = 340,
     CMDSTRING = 341,
     IPSTRING = 342,
     IPSSTRING = 343,
     FILENAMESTRING = 344,
     YESNO = 345,
     NUMBER = 346,
     LONG = 347,
     PROTO = 348,
     FLOAT = 349
   };
#endif
/* Tokens.  */
#define CREATE 258
#define ADD 259
#define PORT 260
#define BIND 261
#define CLONE 262
#define DOT 263
#define BLOCK 264
#define OPEN 265
#define RESET 266
#define DEFAULT 267
#define SET 268
#define ACTION 269
#define PERSONALITY 270
#define PERSONALITY6 271
#define RANDOM 272
#define ANNOTATE 273
#define NO 274
#define FINSCAN 275
#define FRAGMENT 276
#define DROP 277
#define OLD 278
#define NEW 279
#define COLON 280
#define PROXY 281
#define TRANSPARENT 282
#define UPTIME 283
#define DROPRATE 284
#define IN 285
#define SYN 286
#define UID 287
#define GID 288
#define ROUTE 289
#define ENTRY 290
#define LINK 291
#define NET 292
#define UNREACH 293
#define SLASH 294
#define LATENCY 295
#define MS 296
#define LOSS 297
#define BANDWIDTH 298
#define SUBSYSTEM 299
#define OPTION 300
#define TO 301
#define SHARED 302
#define NETWORK 303
#define SPOOF 304
#define FROM 305
#define TEMPLATE 306
#define OBRACKET 307
#define CBRACKET 308
#define RBRACKET 309
#define LBRACKET 310
#define TUNNEL 311
#define TARPIT 312
#define DYNAMIC 313
#define USE 314
#define IF 315
#define OTHERWISE 316
#define EQUAL 317
#define SOURCE 318
#define OS 319
#define IP 320
#define BETWEEN 321
#define DELETE 322
#define LIST 323
#define ETHERNET 324
#define DHCP 325
#define ON 326
#define MAXFDS 327
#define RESTART 328
#define DEBUG 329
#define DASH 330
#define TIME 331
#define INTERNAL 332
#define RANDOMIPVS 333
#define RANDOMEXCLUDE 334
#define MANAGED 335
#define HIH 336
#define DBFILE 337
#define SHELLCODEDIR 338
#define SUBMISSION 339
#define STRING 340
#define CMDSTRING 341
#define IPSTRING 342
#define IPSSTRING 343
#define FILENAMESTRING 344
#define YESNO 345
#define NUMBER 346
#define LONG 347
#define PROTO 348
#define FLOAT 349




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 2068 of yacc.c  */
#line 159 "parse.y"

	char *string;
	int number;
	unsigned long long longvalue;
	struct link_drop drop;
	struct addr addr;
	struct action action;
	struct template *tmpl;
	struct personality *pers;
	struct personality6 *pers6;
	struct addrinfo *ai;
	enum fragpolicy fragp;
	float floatp;
	struct condition condition;
	struct tm time;
	struct condition_time timecondition;



/* Line 2068 of yacc.c  */
#line 258 "parse.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


