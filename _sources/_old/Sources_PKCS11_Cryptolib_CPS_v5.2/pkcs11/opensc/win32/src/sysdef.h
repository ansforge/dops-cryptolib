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

#ifndef __CPS3W32_H
#define __CPS3W32_H

/* partie specifique a windows 32 bits */
#include <windows.h>
#define API_ENTRY __stdcall
#define API_ENTRY_PTR __stdcall*

/* MCUG 09/11/2010 : Fonction de récupération des fichiers de cache à supprimer */
int sc_get_card_cached_files(const char *_path, const char *serialNumber, char ***cached_files, int *size);
/* MCUG 09/11/2010 : FIN */

#endif


