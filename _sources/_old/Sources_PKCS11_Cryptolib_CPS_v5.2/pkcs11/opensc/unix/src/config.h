/*
* config.h : opensc configuration according to system
*
* Copyright (C) 2010-2016, ASIP Santé
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */
#include <dlfcn.h>
#ifdef __APPLE__
#include <string.h>
#include <pthread.h>
#endif
#include "cps3pkcs11ver.h"

#ifndef ENABLE_PCSC
#define ENABLE_PCSC
#endif

#ifdef __APPLE__
  #define DEFAULT_PCSC_PROVIDER "/System/Library/Frameworks/PCSC.framework/PCSC"
  #define GALSS_PROVIDER        "/Library/Frameworks/galclosx.framework/galclosx"
  #define GALSS_PROVIDER_INFO   "/Library/Frameworks/galinosx.framework/galinosx"
#else
  /* AROC 08/07/2010 : sous Linux, ne plus specifier le chemin d'acces aux librairies */
  #define DEFAULT_PCSC_PROVIDER "libpcsclite.so.1"
  #define GALSS_PROVIDER        "libgalcllux.so"
  #define GALSS_PROVIDER_INFO   "libgalinlux.so"
  /* AROC 08/07/2010 : Fin */
#endif

/* Use iconv libraries and header files */
#define ENABLE_ICONV 1

/* Have OpenCT libraries and header files */
/* #undef ENABLE_OPENCT */

/* Have OpenSSL libraries and header files */
#define ENABLE_OPENSSL 1

/* Define if PC/SC is to be enabled */
/* #undef ENABLE_PCSC */

/* Use readline libraries and header files */
#define ENABLE_READLINE 1

/* Use zlib libraries and header files */
#define ENABLE_ZLIB 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Define to 1 if you have the `getopt_long' function. */
#define HAVE_GETOPT_LONG 1

/* Define to 1 if you have the `getpass' function. */
#define HAVE_GETPASS 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <iconv.h> header file. */
#define HAVE_ICONV_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

#ifdef UNIX_LUX
/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1
#endif

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the `mkdir' function. */
#define HAVE_MKDIR 1

/* Define if you have POSIX threads libraries and header files. */
#define HAVE_PTHREAD 1

/* Define to 1 if you have the <readline/readline.h> header file. */
#define HAVE_READLINE_READLINE_H 1

/* Define to 1 if you have the `setlocale' function. */
#define HAVE_SETLOCALE 1

/* Define to 1 if you have the `setutent' function. */
#define HAVE_SETUTENT 1

/* Define to 1 if `stat' has the bug that it succeeds when given the
   zero-length file name argument. */
/* #undef HAVE_STAT_EMPTY_STRING_BUG */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Define to 1 if you have the `vsyslog' function. */
#define HAVE_VSYSLOG 1

#ifdef __APPLE__
/* Define to 1 if you have the <winscard.h> header file. */
#define HAVE_WINSCARD_H 1
#endif

/* Define to 1 if you have the <zlib.h> header file. */
#define HAVE_ZLIB_H 1

/* Define to 1 if `lstat' dereferences a symlink specified with a trailing
   slash. */
#define LSTAT_FOLLOWS_SLASHED_SYMLINK 1

/* Name of package */
#define PACKAGE "opensc"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define OPENSC_VERSION "0.11.12"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Version number of package */
#ifndef PACKAGE_VERSION
/* CLCO 06/07/2010 : Adaptation ASIP de la version du module PKCS#11 */
#define PACKAGE_VERSION CPS3_PKCS_VER_COMMENT " version : " STR_COMPLETE_VERSION " (OpenSC " OPENSC_VERSION ")"
/* CLCO 06/07/2010 : Fin */
#endif

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

#ifndef lt_dlhandle
# define lt_dlhandle void *
#endif
#ifndef lt_dlerror
#	define lt_dlerror dlerror
#endif
#ifndef lt_dlopen 
#	define lt_dlopen(x) dlopen(x,RTLD_NOW)
#endif
#ifndef lt_dlclose
#	define lt_dlclose(x) dlclose(x)
#endif
#ifndef lt_dlsym
#	define lt_dlsym(x,y) dlsym(x,y)
#endif

/* CLCO 06/07/2010 : Adaptation ASIP de la gestion des traces */
#define getCurrentProcess(pProcessID)  (*(pProcessID)=getpid())
#define getCurrentThread(pThreadID)    (*(pThreadID)=(ULONG)pthread_self())

#ifndef __APPLE__
#define getProcessName() 							 "Unknow process"
#else
#define getProcessName() getprogname()
#endif
/* CLCO 06/07/2010 : Fin */

#ifndef min
#define min(a,b) ((a)>(b)?(b):(a))
#endif

