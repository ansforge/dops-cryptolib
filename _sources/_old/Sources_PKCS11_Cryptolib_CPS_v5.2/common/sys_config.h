/*
* sys_config.h : System configuration dependent functions header
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

#ifndef _SYS_CONFIG_H
#define _SYS_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef _WIN32

#include <windows.h>
#include <shlobj.h>
#include <direct.h>
#include <stdio.h>


DWORD sys_GetDWRegParam(HKEY hKey, LPCSTR subKey, LPCSTR key, LPDWORD pdwValue);

#define GET_DW_REG_PARAM(subKey, keyValue, value)                                                                        \
        do{                                                                                                              \
          DWORD dwValue;                                                                                                 \
          if (sys_GetDWRegParam(HKEY_LOCAL_MACHINE,subKey, keyValue, &dwValue) == ERROR_SUCCESS) {value = (INT)dwValue;} \
          if (sys_GetDWRegParam(HKEY_CURRENT_USER, subKey, keyValue, &dwValue) == ERROR_SUCCESS) {value = (INT)dwValue;} \
        }while(0);

#else // __WIN32

#include "sysdef.h"
 
#endif // ! _WIN32

VOID sys_GetLogPath(LPSTR strConfPath, size_t szSize);
VOID sys_GetConfPath(LPSTR strConfPath, size_t szSize);
VOID sys_GetCachePath(LPSTR strConfPath, size_t szSize);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif //_SYS_CONFIG_H
