/*
* tls_chainlist.c : Thread Socal Storage module
*
* Copyright (C) 2010-2017, ASIP Santé
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

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "pkcs11-display.h"
#include "tls_chainlist.h"

typedef struct TlsEntry {
  LPVOID pvContext;
  DWORD dwThreadId;
  struct TlsEntry PTR next;
} TlsEntry;

typedef TlsEntry PTR PTlsEntry;

static  PTlsEntry g_pStartList = NULL;

BOOL tls_addToTlsList(DWORD _dwThreadID, LPVOID _pvContext) {

  PTlsEntry pCurrent;

  if (g_pStartList == NULL) {
    /* this is the first entry */
    g_pStartList = (PTlsEntry)calloc(1, sizeof(TlsEntry));
    if (g_pStartList == NULL) {
      return FALSE;
    }
    pCurrent = g_pStartList;
    pCurrent->dwThreadId = _dwThreadID;
    pCurrent->pvContext = _pvContext;
    pCurrent->next = NULL;
#ifdef _DEBUG
    logP11("tls_addToTlsList: _dwThreadID: %lx, _pvContext: 0x%p", _dwThreadID, _pvContext);
#endif
    return TRUE;

  }
  else {
    /* insert this entry at end of list, if not exists */
    PTlsEntry pSave;
    BOOL bFound = FALSE;
    for (pCurrent = g_pStartList; pCurrent != NULL && !bFound; pCurrent = pCurrent->next) {
      pSave = pCurrent;
      if (pCurrent->dwThreadId == _dwThreadID) {
#ifdef _DEBUG
        logP11("tls_addToTlsList: bFound   : _dwThreadID: %lx, _pvContext: 0x%p", _dwThreadID, _pvContext);
#endif
        bFound = TRUE;
      }
    }

    if (!bFound) {
      pSave->next = (PTlsEntry)calloc(1, sizeof(TlsEntry));
      if (pSave->next == NULL) {
        return FALSE;
      }
      pCurrent = pSave->next;
      pCurrent->dwThreadId = _dwThreadID;
      pCurrent->pvContext = _pvContext;
      pCurrent->next = NULL;
#ifdef _DEBUG
      logP11("tls_addToTlsList: _dwThreadID: %lx, _pvContext: %p", _dwThreadID, _pvContext);
#endif // _DEBUG
      return TRUE;
    }
  }

  return FALSE;

}

LPVOID tls_getTlsIndexByThreadId(DWORD dwThreadID) {
  PTlsEntry pCurrent = g_pStartList;
  int found = FALSE;
#ifdef _DEBUG
  logP11("Dans getTlsIndexByThreadId(%d)\n\n", dwThreadID);
#endif // _DEBUG
  while (pCurrent != NULL && !found) {
    if (dwThreadID == pCurrent->dwThreadId) {
      found = TRUE;
    }
    else {
      pCurrent = pCurrent->next;
    }
  }
#ifdef _DEBUG
  logP11("tls_getTlsIndexByThreadId: dwThreadID: %lx, found: %d", dwThreadID, found);
#endif // _DEBUG
  if (pCurrent == (PTlsEntry)NULL) return TLS_INDEX_NONE;
  return pCurrent->pvContext;
}

void tls_deleteTlsEntryByThreadId(DWORD dwThreadID) {
  PTlsEntry pCurrent = g_pStartList, pPrecAttach = NULL;
  int found = FALSE;

#ifdef _DEBUG
  logP11("Dans deleteTlsIndexByThreadId(%d)\n", dwThreadID);
#endif // _DEBUG
  while (pCurrent != NULL && !found) {

    if (dwThreadID == pCurrent->dwThreadId) {
      found = TRUE;
    }
    else {
      pPrecAttach = pCurrent;
      pCurrent = pCurrent->next;
    }
  }

#ifdef _DEBUG
  logP11("tls_deleteTlsEntryByThreadId: dwThreadID: %lx, found: %d", dwThreadID, found);
#endif // _DEBUG
  if (found) {
    if (pPrecAttach == NULL) {
      /* this is the first entry to be deleted */
      g_pStartList = pCurrent->next;
#ifdef DEBUG
      logP11("tls_deleteTlsEntryByThreadId: first entry");
#endif // DEBUG

    }
    else {
      /* this is the next entry to be deleted */
      pPrecAttach->next = pCurrent->next;
#ifdef _DEBUG
      logP11("tls_deleteTlsEntryByThreadId: next entry");
#endif // _DEBUG
    }
  }

  free(pCurrent);

  return;
}



