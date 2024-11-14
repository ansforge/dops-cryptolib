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
#ifndef _OPENSC_WINCONFIG_H
#define _OPENSC_WINCONFIG_H

/* CLCO 08/07/2010 : Suppression des warning de compilation */
#include <direct.h>
#include <io.h>
#include <conio.h>
/* CLCO 08/07/2010 : Fin */
#include <stdio.h>
#include <windows.h>
#include <winscard.h>
#include <sys/timeb.h>
#include <sys/stat.h>
/* CLCO 06/07/2010 : Adaptation ASIP de la version du module PKCS#11 */
#include "cps3pkcs11ver.h"
/* CLCO 06/07/2010 : Fin */

#ifndef strcasecmp
#define strcasecmp stricmp
#endif

#ifndef strncasecmp
#define strncasecmp strnicmp
#endif

#ifndef snprintf
#define snprintf _snprintf
#endif

#ifndef vsnprintf
#define vsnprintf _vsnprintf
#endif

#ifndef isatty
#define isatty _isatty
#endif

#ifndef strnicmp
#define strnicmp _strnicmp
#endif 

#ifndef stricmp
#define stricmp _stricmp
#endif

#ifndef strdup
#define strdup _strdup
#endif

#ifndef fileno
#define fileno _fileno
#endif

#ifndef mkdir
#define mkdir _mkdir
#endif

#ifndef access
#define access _access
#endif

#ifndef unlink
#define unlink _unlink
#endif

#ifndef putenv
#define putenv _putenv
#endif

#ifndef R_OK
#define R_OK  4		/* test whether readable.  */
#define W_OK  2		/* test whether writable.  */
#define X_OK  1		/* test whether execubale. */
#define F_OK  0		/* test whether exist.  */
#endif

#ifndef S_IRUSR 
#define S_IRUSR S_IREAD
#endif

#ifndef S_IWUSR 
#define S_IWUSR S_IWRITE
#endif

#define HAVE_IO_H
#define ENABLE_PCSC
#define HAVE_WINSCARD_H
#define DEFAULT_PCSC_PROVIDER "winscard.dll"
#if defined(_WIN64)
#define GALSS_PROVIDER      "galclw64.dll"
#define GALSS_PROVIDER_INFO "galinw64.dll"
#else
#define GALSS_PROVIDER      "galclw32.dll"
#define GALSS_PROVIDER_INFO "galinw32.dll"
#endif

extern const CHAR REG_SUBKEY[];


#define PATH_MAX _MAX_PATH

/* BPER (@@06122016-1396) : Affichage de la version d'OpenSC - Debut */
#ifndef OPENSC_VERSION
#define OPENSC_VERSION "0.11.12"
#endif
/* BPER (@@06122016-1396) : Affichage de la version d'OpenSC - Fin */

#ifndef PACKAGE_VERSION
/* CLCO 06/07/2010 : Adaptation ASIP de la version du module PKCS#11 */
#define PACKAGE_VERSION CPS_PKCS_VER_COMMENT " version : " STR_COMPLETE_VERSION " (OpenSC " OPENSC_VERSION ")"
/* CLCO 06/07/2010 : Fin */
#endif

#ifndef PACKAGE_NAME
#define PACKAGE_NAME "opensc"
#endif

#ifndef OPENSC_FEATURES
#define OPENSC_FEATURES "N/A"
#endif

#ifndef lt_dlhandle
# define lt_dlhandle void *
#endif

#ifndef lt_dlerror
// Function a la limite de l'inutile sous windows, mais implementer pour comaptibilite
#	define lt_dlerror() strerror(GetLastError())
#endif
#ifndef lt_dlopen 
#	define lt_dlopen(x) LoadLibrary(x)
#endif
#ifndef lt_dlclose
#	define lt_dlclose(x) FreeLibrary((HMODULE)x)
#endif
#ifndef lt_dlsym
#	define lt_dlsym(x,y) GetProcAddress(x,y)
#endif

/* CLCO 06/07/2010 : Adaptation ASIP de la gestion des traces */
#define getCurrentProcess(pProcessID)		(*(pProcessID)=GetCurrentProcessId())
#define getCurrentThread(pThreadID) (*(pThreadID)=GetCurrentThreadId())
#define getProcessName GetCommandLine
/* CLCO 06/07/2010 : Fin */

#endif
