/*
 * pkcs11-extend.c: PKCS#11 extended functions
 *
 * Copyright (C) 2010-2018, ASIP Santé
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sc-pkcs11.h"

#ifdef _WIN32
#include "sysdef.h"
#endif


CK_RV IC_StartUpdate(CK_SESSION_HANDLE hSession)
{

  CK_ULONG rv = CKR_OK;

  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot    *slot;
  struct sc_card           *card;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  //rv = pool_find(&session_pool, hSession, (void**)&session);
  rv = pool_find(getPoolTable(), hSession, (void**)&session);
  if (rv != CKR_OK) {
    sc_pkcs11_unlock();
    return rv;
  }

  rv = is_session_valid(session);
  if (rv != CKR_OK) {
    sc_pkcs11_unlock();
    return rv;
  }

  slot = session->slot;
  if (slot != NULL) {
    card = slot->card->card;
    if (card != NULL) {
      rv = card->ops->start_exlusivity(card);
    }
  }

  sc_pkcs11_unlock();
  return rv = sc_to_cryptoki_error(rv, slot->reader);;
}

CK_RV IC_EndUpdate(CK_SESSION_HANDLE hSession)
{

  CK_ULONG rv = CKR_OK;

  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot    *slot;
  struct sc_card           *card;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  rv = pool_find(getPoolTable(), hSession, (void**)&session);
  if (rv != CKR_OK) {
    sc_pkcs11_unlock();
    return rv;
  }

  rv = is_session_valid(session);
  if (rv != CKR_OK) {
    sc_pkcs11_unlock();
    return rv;
  }


  slot = session->slot;
  if (slot != NULL) {
    card = slot->card->card;
    if (card != NULL) {
      rv = card->ops->end_exlusivity(card);
    }
  }

  sc_pkcs11_unlock();
  return rv = sc_to_cryptoki_error(rv, slot->reader);;
}

CK_RV IC_KeepAlive(CK_SESSION_HANDLE hSession)
{

  CK_ULONG rv = CKR_OK;
  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot    *slot = NULL;
  struct sc_card           *card;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK) {
    return rv;
  }

  rv = pool_find(getPoolTable(), hSession, (void**)&session);
  if (rv != CKR_OK) {
    sc_pkcs11_unlock();
    return rv;
  }

  slot = session->slot;

  rv = is_session_valid(session);
  if (rv != CKR_OK) {
    sc_pkcs11_unlock();
    return rv;
  }

  card = slot->card->card;
  card->ops->get_status(card);

  sc_pkcs11_unlock();
  return rv = sc_to_cryptoki_error(rv, (slot != 0 ? slot->reader : 0));
}


CK_RV IC_TransmitMessage(CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR       pbMessage,
                         CK_ULONG          szMessage,
                         CK_BYTE_PTR       pbResponse,
                         CK_ULONG_PTR      pszResponse,
                         CK_CHAR           cInsType)
{
  CK_ULONG rv = CKR_OK;

  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot    *slot = NULL;
  struct sc_card           *card;
  size_t                    szResp = (size_t)*pszResponse;
  size_t                    szDumpLen = (size_t)szMessage * 5 + 128;
  char                     *cbDumpBuf = NULL;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK) {
    return rv;
  }

  rv = pool_find(getPoolTable(), hSession, (void**)&session);
  if (rv != CKR_OK) {
    sc_pkcs11_unlock();
    return rv;
  }

  slot = session->slot;

  rv = is_session_valid(session);
  if (rv != CKR_OK) {
    sc_pkcs11_unlock();
    return rv;
  }

  card = slot->card->card;

  cbDumpBuf = (char*)calloc(szDumpLen, sizeof(char));
  if (cbDumpBuf != NULL) {
    sc_hex_dump(slot->card->card->reader->ctx, pbMessage, szMessage, cbDumpBuf, szDumpLen);

    sc_debug(slot->card->card->reader->ctx, "\n%s APDU data [%5u bytes] =====================================\n"
      "%s"
      "======================================================================\n",
      "Outgoing", szDumpLen,
      cbDumpBuf);

    free(cbDumpBuf); cbDumpBuf = NULL;
  }

  rv = card->ops->free_transmit(card, pbMessage, szMessage, pbResponse, &szResp, cInsType);
  *pszResponse = (CK_ULONG)szResp;

  szDumpLen = (size_t)szResp * 5 + 128;
  cbDumpBuf = (char*)calloc(szDumpLen, sizeof(char));
  if (cbDumpBuf != NULL) {
    sc_hex_dump(slot->card->card->reader->ctx, pbResponse, szResp, cbDumpBuf, szDumpLen);

    sc_debug(slot->card->card->reader->ctx, "\n%s APDU data [%5u bytes] =====================================\n"
      "%s"
      "======================================================================\n",
      "Incoming", szDumpLen,
      cbDumpBuf);

    free(cbDumpBuf); cbDumpBuf = NULL;
  }

  sc_pkcs11_unlock();
  return rv = sc_to_cryptoki_error(rv, (slot != 0 ? slot->reader : 0));
}