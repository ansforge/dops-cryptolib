/*
 * pkcs11-session.c: PKCS#11 functions for session management
 *
 * Copyright (C) 2001  Timo Teräs <timo.teras@iki.fi>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sc-pkcs11.h"

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_OpenSession(CK_SLOT_ID            slotID,        /* the slot's ID */
/* CLCO 06/07/2010 : Fin  */
        CK_FLAGS              flags,         /* defined in CK_SESSION_INFO */
        CK_VOID_PTR           pApplication,  /* pointer passed to callback */
        CK_NOTIFY             Notify,        /* notification callback function */
        CK_SESSION_HANDLE_PTR phSession)     /* receives new session handle */
{
  struct sc_pkcs11_slot *slot;
  struct sc_pkcs11_session *session;
  struct sc_context * pcontext; // BPER 1381 Solution C
  int rv;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  /*sc_debug(context, "Opening new session for slot %d\n", slotID);*/

  if (!(flags & CKF_SERIAL_SESSION)) {
    rv = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    goto out;
  }

  /* AROC - 15/11/2011 - Correction Anomalie 8043 - Debut */
  if (flags & ~(CKF_SERIAL_SESSION | CKF_RW_SESSION) || phSession == NULL) {
  /* AROC - 15/11/2011 - Correction Anomalie 8043 - Fin */
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }

  rv = slot_get_token(slotID, &slot, TRUE);
  if (rv != CKR_OK)
    goto out;
  // BPER 1381 - Solution C - Debut
  pcontext = slot->card->card->ctx;
  sc_debug(pcontext, "Opening new pCurSession for slot %d, context handle: %p\n", slotID, pcontext);
  // BPER 1381 - Solution C - Fin

  /* Check that no conflictions sessions exist */
  if (!(flags & CKF_RW_SESSION) && (slot->login_user == CKU_SO)) {
    rv = CKR_SESSION_READ_WRITE_SO_EXISTS;
    goto out;
  }

  session = (struct sc_pkcs11_session*) calloc(1, sizeof(struct sc_pkcs11_session));
  if (session == NULL) {
    rv = CKR_HOST_MEMORY;
    goto out;
  }
    
  session->slot = slot;
  session->notify_callback = Notify;
  session->notify_data = pApplication;
  session->flags = flags;

  /* CLCO 03/08/2010 : tester la validité de la session */
  rv = is_session_valid(session);
  /* Si le handle de session est invalide c'est peut-être que le token n'est pas présent */
  if (rv == CKR_SESSION_HANDLE_INVALID) {
    rv = slot_get_token(slotID, &slot, TRUE);
    if (rv != CKR_OK)
      goto out;
    /* sinon la fonction is_session_valid a indiqué un changement de carte et en a profité pour faire le nettoyage. 
       La création d'une nouvelle session sur une carte potentiellement différente n'est pas un problème. */
    rv = CKR_OK; 
  }
    else if (rv != CKR_OK){
        free(session);
        goto out;
    }
  /* CLCO 03/08/2010 : fin */
  rv = pool_insert(getPoolTable(), session, phSession);
  if (rv != CKR_OK) {
    free(session);
    goto out;
  } else
    slot->nsessions++;

out:  sc_pkcs11_unlock();
  return rv;
}

/* Internal version of C_CloseSession that gets called with
 * the global lock held */
static CK_RV sc_pkcs11_close_session(CK_SESSION_HANDLE hSession, unsigned long thrID)
{
  struct sc_pkcs11_slot *slot;
  struct sc_pkcs11_session *session;
  struct sc_pkcs11_pool *tgt_pool;
  struct sc_context * pContext;
  int rv;

  if (thrID == 0) {
    tgt_pool = getPoolTable();
    pContext = getCurContext();
  }
  else {
    tgt_pool = getPoolTable_ThrID(thrID);
    pContext = getCurContext_finalize(thrID);
  }

  rv = pool_find_and_delete(tgt_pool, hSession, (void**) &session, pContext);
  if (rv != CKR_OK)
    return rv;

  /* If we're the last session using this slot, make sure
   * we log out */
  slot = session->slot;
  slot->nsessions--;
  if (slot->nsessions == 0 && slot->login_user >= 0) {
    slot->login_user = -1;
    slot->card->framework->logout(slot->card, slot->fw_data);
  }

  free(session);
  return CKR_OK;
}

/* Internal version of C_CloseAllSessions that gets called with
 * the global lock held */
CK_RV sc_pkcs11_close_all_sessions(CK_SLOT_ID slotID, struct sc_context * pContext)
{
  struct sc_pkcs11_pool_item *item, *next;
  struct sc_pkcs11_session *pCurSession;
  struct sc_pkcs11_pool    *pSessionPool;

  if (pContext == NULL || pContext->pool_table == NULL){
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  pSessionPool = pContext->pool_table;

  sc_debug(pContext, "C_CloseAllSessions(slot %d).\n", (int) slotID);
  for (item = pSessionPool->head; item != NULL; item = next) {
    pCurSession = (struct sc_pkcs11_session*) item->item;
    next = item->next;
    if (pCurSession->slot->id == (int)slotID) {
      sc_pkcs11_close_session(item->handle, pContext->thr_id_ctx);
    }
  }

  return CKR_OK;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_CloseSession(CK_SESSION_HANDLE hSession) /* the session's handle */
/* CLCO 06/07/2010 : Fin  */
{
  int rv;

  /* BPER 1381 - Solution C */

  rv = sc_pkcs11_lock();
  if (rv == CKR_OK) {
    /* BPER 1381 - Solution C - Début */
    struct sc_context *pcontext;
    struct sc_pkcs11_session *session;

    rv = pool_find(getPoolTable(), hSession, (void**)&session);
    if (rv == CKR_OK) {
      pcontext = session->slot->card->card->ctx;
      sc_debug(pcontext, "C_CloseSession(%lx), context handle: %p\n", (long)hSession, pcontext);
    }
    /* BPER 1381 - Solution C - Fin */
    rv = sc_pkcs11_close_session(hSession, 0);
  }
  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_CloseAllSessions(CK_SLOT_ID slotID) /* the token's slot */
/* CLCO 06/07/2010 : Fin  */
{
  struct sc_pkcs11_slot *slot;
  struct sc_context *pContext;
  int rv;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  rv = slot_get_token(slotID, &slot, FALSE);
  if (rv != CKR_OK)
    goto out;

  pContext = slot->card->card->ctx;
  rv = sc_pkcs11_close_all_sessions(slotID, pContext);

out:  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_GetSessionInfo(CK_SESSION_HANDLE hSession,  /* the session's handle */
/* CLCO 06/07/2010 : Fin  */
           CK_SESSION_INFO_PTR pInfo)   /* receives session information */
{
  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot *slot;
  int rv;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  if (pInfo == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }

  rv = pool_find(getPoolTable(), hSession, (void**) &session);
  if (rv != CKR_OK)
    goto out;

  /* CLCO 26/05/2010 : tester la validité de la session */
  rv = is_session_valid(session);
  if (rv != CKR_OK)
    goto out;
  /* CLCO 26/05/2010 : fin */

  sc_debug(session->slot->card->card->ctx, "C_GetSessionInfo(slot %d).\n", session->slot->id); // BPER 1381 - Solution C
  pInfo->slotID = session->slot->id;
  pInfo->flags = session->flags;
  pInfo->ulDeviceError = 0;

  slot = session->slot;
  if (slot->login_user == CKU_SO) {
    pInfo->state = CKS_RW_SO_FUNCTIONS;
  } else
  if (slot->login_user == CKU_USER
   || (!(slot->token_info.flags & CKF_LOGIN_REQUIRED))) {
    pInfo->state = (session->flags & CKF_RW_SESSION)
      ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
  } else {
    pInfo->state = (session->flags & CKF_RW_SESSION)
      ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
  }

out:  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_GetOperationState(CK_SESSION_HANDLE hSession,             /* the session's handle */
/* CLCO 06/07/2010 : Fin  */
        CK_BYTE_PTR       pOperationState,      /* location receiving state */
        CK_ULONG_PTR      pulOperationStateLen) /* location receiving state length */
{
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_SetOperationState(CK_SESSION_HANDLE hSession,            /* the session's handle */
/* CLCO 06/07/2010 : Fin  */
        CK_BYTE_PTR      pOperationState,      /* the location holding the state */
        CK_ULONG         ulOperationStateLen,  /* location holding state length */
        CK_OBJECT_HANDLE hEncryptionKey,       /* handle of en/decryption key */
        CK_OBJECT_HANDLE hAuthenticationKey)   /* handle of sign/verify key */
{
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_Login(CK_SESSION_HANDLE hSession,  /* the session's handle */
/* CLCO 06/07/2010 : Fin  */
        CK_USER_TYPE      userType,  /* the user type */
        CK_CHAR_PTR       pPin,      /* the user's PIN */
        CK_ULONG          ulPinLen)  /* the length of the PIN */
{
  int rv;
  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot *slot;
  struct sc_pkcs11_pool_item *item;
  struct sc_pkcs11_pool *pSessionPool;
  struct sc_context *pContext = NULL;

  pContext = getCurContext();

  if (pContext == NULL || pContext->pool_table == NULL){
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK) {
    return rv;
  }

  if (userType != CKU_USER && userType != CKU_SO) {
    rv = CKR_USER_TYPE_INVALID;
    goto out;
  }

  pSessionPool = getPoolTable();
  rv = pool_find(pSessionPool, hSession, (void**) &session);
  if (rv != CKR_OK)
    goto out;

  /* CLCO 26/05/2010 : tester la validité de la session */
  rv = is_session_valid(session);
  if (rv != CKR_OK)
    goto out;
  /* CLCO 26/05/2010 : fin */

  /* CLCO 27/07/2010 : ne pas autoriser le login SO si une session read only existe */
  if (userType == CKU_SO) {
    for (item = pSessionPool->head; item != NULL; item = item->next) {
      struct sc_pkcs11_session *cursession=(struct sc_pkcs11_session *)item->item;
      if (!(cursession->flags&CKF_RW_SESSION)) {
        rv = CKR_SESSION_READ_ONLY_EXISTS;
        goto out;
      }
    }
  }
  /* CLCO 27/07/2010 : fin */

  sc_debug(session->slot->card->card->ctx, "Login for pCurSession %d\n", hSession); // BPER 1381 - Solution C

  slot = session->slot;

  if (!(slot->token_info.flags & CKF_USER_PIN_INITIALIZED)) {
    rv = CKR_USER_PIN_NOT_INITIALIZED;
    goto out;
  }

  /* AROC - 14/11/2011 - Correction 8044 : Debut */
  for (item = pSessionPool->head; item != NULL; item = item->next) {
    CK_ULONG testLoggedUser;
    struct sc_pkcs11_session *cursession=NULL;

    if (userType == CKU_USER) testLoggedUser = CKU_SO;
    else testLoggedUser = CKU_USER;

    cursession = (struct sc_pkcs11_session *)item->item;
    if(cursession != NULL && cursession == session) {
      if(cursession->slot->login_user != -1) {
        if(cursession->slot->login_user == testLoggedUser){
          rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
          goto out;
        }
      }
    }
  }
  /* AROC - 14/11/2011 - Correction 8044 : Fin */

  if (slot->login_user >= 0) {
    rv = CKR_USER_ALREADY_LOGGED_IN;
    goto out;
  }

  rv = slot->card->framework->login(slot->card, slot->fw_data,
                                    userType, pPin, ulPinLen);
  if (rv == CKR_OK)
    slot->login_user = userType;

out:  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_Logout(CK_SESSION_HANDLE hSession) /* the session's handle */
/* CLCO 06/07/2010 : Fin  */
{
  int rv;
  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot *slot;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  rv = pool_find(getPoolTable(), hSession, (void**) &session);
  if (rv != CKR_OK)
    goto out;

  /* CLCO 26/05/2010 : tester la validité de la session */
  rv = is_session_valid(session);
  if (rv != CKR_OK)
    goto out;
  /* CLCO 26/05/2010 : fin */

  sc_debug(session->slot->card->card->ctx, "Logout for pCurSession %d\n", hSession); // BPER 1381 - Solution C

  slot = session->slot;

  if (slot->login_user >= 0) {
    slot->login_user = -1;
    rv = slot->card->framework->logout(slot->card, slot->fw_data);
  }
  else
    rv = CKR_USER_NOT_LOGGED_IN;

out:  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_InitPIN(CK_SESSION_HANDLE hSession,
/* CLCO 06/07/2010 : Fin  */
    CK_CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{
  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot *slot;
  int rv;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  rv = pool_find(getPoolTable(), hSession, (void**) &session);
  if (rv != CKR_OK)
    goto out;

  /* CLCO 26/05/2010 : tester la validité de la session */
  rv = is_session_valid(session);
if (rv != CKR_OK)
goto out;
/* CLCO 26/05/2010 : fin */

slot = session->slot;
if (slot->login_user != CKU_SO) {
	rv = CKR_USER_NOT_LOGGED_IN;
}
else
if (slot->card->framework->init_pin == NULL) {
	/* CLCO 21/05/2010 : Gestion du déblocage du code PIN */
	if (slot->card->framework->unblock_pin == NULL) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	else {
		rv = slot->card->framework->unblock_pin(slot->card, slot->fw_data,
			NULL, 0, pPin, ulPinLen);
	}
	/* CLCO 21/05/2010 : fin */
}
else {
	rv = slot->card->framework->init_pin(slot->card, slot,
		pPin, ulPinLen);
}

out:  sc_pkcs11_unlock();
return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_SetPIN(CK_SESSION_HANDLE hSession,
	/* CLCO 06/07/2010 : Fin  */
	CK_CHAR_PTR pOldPin,
	CK_ULONG ulOldLen,
	CK_CHAR_PTR pNewPin,
	CK_ULONG ulNewLen)
{
	int rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(getPoolTable(), hSession, (void**)&session);
	if (rv != CKR_OK)
		goto out;

	/* CLCO 26/05/2010 : tester la validité de la session */
	rv = is_session_valid(session);
	if (rv != CKR_OK)
		goto out;
	/* CLCO 26/05/2010 : fin */

	sc_debug(session->slot->card->card->ctx, "Changing PIN (pCurSession %d)\n", hSession); // BPER 1381 - Solution C
#if 0
	if (!(ses->flags & CKF_RW_SESSION)) {
		rv = CKR_SESSION_READ_ONLY;
		goto out;
	}
#endif

	slot = session->slot;
	rv = slot->card->framework->change_pin(slot->card, slot->fw_data,
		pOldPin, ulOldLen,
		pNewPin, ulNewLen);

out:  sc_pkcs11_unlock();
	return rv;
}


CK_RV IC_StartUpdate(CK_SESSION_HANDLE hSession)
{

	CK_ULONG rv = CKR_OK;

	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot    *slot;
	struct sc_card           *card;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;
	rv = pool_find(getPoolTable(), hSession, (void**)&session);
	//rv = pool_find(&session_pool, hSession, (void**) &session);
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
			if (rv == CKR_OK) {
				card->flags |= SC_CARD_STARTUPDATE;
			}
		}
	}
	
  sc_pkcs11_unlock();
  return rv = sc_to_cryptoki_error(rv, slot->reader);;
}

CK_RV IC_EndUpdate(CK_SESSION_HANDLE hSession )
{

  CK_ULONG rv = CKR_OK;

  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot    *slot;
  struct sc_card           *card;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;
  rv = pool_find(getPoolTable(), hSession, (void**)&session);
  //rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK){
		sc_pkcs11_unlock();
		return rv;
    }
	
  rv = is_session_valid(session);
	if (rv != CKR_OK){
		sc_pkcs11_unlock();
		return rv;
    }
	

  slot = session->slot;
  if (slot !=NULL){
    card = slot->card->card;
	if (card != NULL ){
      rv = card->ops->end_exlusivity(card);
	  card->flags &= ~SC_CARD_STARTUPDATE;
	}
  }

  sc_pkcs11_unlock();
  return rv = sc_to_cryptoki_error(rv, slot->reader);;
}

CK_RV IC_KeepAlive(CK_SESSION_HANDLE hSession )
{

  CK_ULONG rv = CKR_OK;
  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot    *slot=NULL;
  struct sc_card           *card;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK){
	  return rv;
  }
  rv = pool_find(getPoolTable(), hSession, (void**)&session);
  //rv = pool_find(&session_pool, hSession, (void**) &session);
  if (rv != CKR_OK){
	  sc_pkcs11_unlock();
	  return rv;
  }
  
  slot = session->slot;

  rv = is_session_valid(session);
  if (rv != CKR_OK){
    sc_pkcs11_unlock();
    return rv;
  }

  card = slot->card->card;
  card->ops->get_status(card);
  
  sc_pkcs11_unlock();
  return rv =sc_to_cryptoki_error(rv, (slot!=0?slot->reader:0));
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
  struct sc_pkcs11_slot    *slot=NULL;
  struct sc_card           *card;
  size_t                    szResp = (size_t)*pszResponse;
  size_t                    szDumpLen = (size_t)szMessage * 5 + 128;
  char                     *cbDumpBuf = NULL;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK){
		return rv;
    }
  rv = pool_find(getPoolTable(), hSession, (void**)&session);
  //rv = pool_find(&session_pool, hSession, (void**) &session);
  if (rv != CKR_OK){
    sc_pkcs11_unlock();
    return rv;
  }

  slot = session->slot;

  rv = is_session_valid(session);
  if (rv != CKR_OK){
    sc_pkcs11_unlock();
    return rv;
  }

  card = slot->card->card;
  
  cbDumpBuf = (char*)calloc(szDumpLen, sizeof(char));
  if (cbDumpBuf != NULL){
    sc_hex_dump(slot->card->card->reader->ctx , pbMessage, szMessage, cbDumpBuf, szDumpLen);

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
  if (cbDumpBuf != NULL){
    sc_hex_dump(slot->card->card->reader->ctx , pbResponse, szResp, cbDumpBuf, szDumpLen);

	sc_debug(slot->card->card->reader->ctx, "\n%s APDU data [%5u bytes] =====================================\n"
		"%s"
		"======================================================================\n",
		"Incoming", szDumpLen,
		cbDumpBuf);

    free(cbDumpBuf); cbDumpBuf = NULL;
  }

  sc_pkcs11_unlock();
  return rv =sc_to_cryptoki_error(rv, (slot!=0?slot->reader:0));
}
