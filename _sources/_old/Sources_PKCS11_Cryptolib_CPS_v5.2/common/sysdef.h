/*
* sysdef.h : System dependencies header file
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

#ifndef __CPS3_SYS_DEFS_H
#define __CPS3_SYS_DEFS_H
#if defined(_WIN32)

#include <windows.h>

#else
typedef void              VOID;
typedef void            * LPVOID;
typedef char              CHAR;
typedef char            * LPSTR;
typedef unsigned char     BYTE;
typedef unsigned char   * LPBYTE;
typedef short             WORD;
typedef short           * LPWORD;
typedef unsigned short    USHORT;
typedef unsigned short  * PUSHORT;
typedef int               INT;
typedef int             * LPINT;
typedef unsigned int      UINT;
typedef unsigned int    * LPUINT;
#ifndef __OBJC__
typedef int               BOOL;
#endif // __OBJC__
typedef BOOL            * LPBOOL;
typedef long              LONG;
typedef long            * LPLONG;
typedef unsigned long     ULONG;
typedef unsigned long   * PULONG;
typedef unsigned long     SIZE_T;

typedef const char          * LPCSTR;
typedef const unsigned char * LPCBYTE;
typedef const void          * LPCVOID;

#define API_ENTRY
#define API_ENTRY_PTR     API_ENTRY *

#ifndef TRUE
#define TRUE              1
#endif // !TRUE

#ifndef FALSE
#define FALSE             0
#endif // !FALSE

#ifndef MAX_PATH
#define MAX_PATH      260
#endif
#endif // ! _WIN32
#endif // __CPS3_UNIX_H


