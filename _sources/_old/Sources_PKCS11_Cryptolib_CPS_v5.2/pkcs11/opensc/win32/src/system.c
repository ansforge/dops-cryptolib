/*
* system.c : System dependent functions
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

#include "sysdef.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include <sys/stat.h>
#include <WtsApi32.h>

extern DWORD  _tlsOpaqueValue;
extern BOOL tlsSetThreadContext(VOID);

const CHAR REG_SUBKEY[] = "Software\\ASIP Sante\\PKCS11";
CRITICAL_SECTION pCS;

/* MCUG 09/11/2010 : Fonction de récupération des fichiers de cache à supprimer */
int sc_get_card_cached_files(const char *_path, const char *serialNumber, char ***cached_files, int* size) {

  HANDLE fh;
  WIN32_FIND_DATA File;
  char path[MAX_PATH];
  char file_path[MAX_PATH];
  int n = 0;
  int i = 0;

  // build path of the directory that contains the cached files
  strcpy(path, _path);
  while (_path[n]) n++;
  if (_path[n - 1] != '\\') {
    strcat(path, "\\");
    return 1;
  }
  strcat(path, "*");


  fh = FindFirstFile((LPCSTR)path, &File);
  if (fh != INVALID_HANDLE_VALUE) {

    *size = 0;

    // get the count of concerned files in order to allocation the cached_files pointer
    do {
      // Considers only the cached file that belongs to the given card and avoid removing the EF_DIR file
      if (strstr(File.cFileName, serialNumber) != NULL && strstr(File.cFileName, "2F00") == NULL)
        (*size)++;
    } while (FindNextFile(fh, &File));

    // cached_files allocation 
    *cached_files = (char **)malloc((*size)*sizeof(char*));
    if (*cached_files == NULL) {
      return 1;
    }

    // fills the cached_files pointer with cached_files paths
    fh = FindFirstFile((LPCSTR)path, &File);
    // strip the wildcard * at the end in order to use it to concat file name
    path[strlen(path) - 1] = 0;
    do {
      // Considers only the cached file that belongs to the given card and avoid removing the EF_DIR file
      if (strstr(File.cFileName, serialNumber) != NULL && strstr(File.cFileName, "2F00") == NULL) {
        (*cached_files)[i] = (char *)malloc(sizeof(File.cFileName));
        if ((*cached_files)[i] == NULL) {
          for (int j = i - 1; j > 0; j--) {
            if ((*cached_files)[j] != NULL) { 
              free((*cached_files)[j]); 
            }
          }
          free(*cached_files);
          FindClose(fh); 
          return 1;
        }
        memcpy(file_path, path, MAX_PATH);
        strcat(file_path, File.cFileName);
        memcpy((*cached_files)[i], file_path, MAX_PATH);
        i++;
      }
    } while (FindNextFile(fh, &File));

    FindClose(fh);
  }

  return 0;

}

/* AROC - 16/11/2011 - Lock de l'init : Debut */
extern void *            init_lock;
BOOL WINAPI DllMain(
  __in  HINSTANCE hinstDLL,
  __in  DWORD fdwReason,
  __in  LPVOID lpvReserved
  )
{
  if (fdwReason == DLL_PROCESS_ATTACH) {
    if (init_lock == NULL) {
      InitializeCriticalSection(&pCS);
      init_lock = &pCS;
    }
  }
  if (fdwReason == DLL_PROCESS_DETACH) {
    if (init_lock != NULL) {
      DeleteCriticalSection((LPCRITICAL_SECTION)init_lock);
      init_lock = NULL;
    }
  }
  return TRUE;
}
/* AROC - 16/11/2011 - Lock de l'init : Fin */
/* AROC 08/08/2011 : Fin */