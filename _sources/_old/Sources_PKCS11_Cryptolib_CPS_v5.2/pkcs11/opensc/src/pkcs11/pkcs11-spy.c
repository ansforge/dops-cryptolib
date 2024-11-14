/*
* Copyright (C) 2003 Mathias Brossard <mathias.brossard@idealx.com>
* Copyright (C) 2010-2016, ASIP Sant�
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307,
* USA
*/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#define CRYPTOKI_EXPORTS
#include "pkcs11-display.h"

/* MCUG & AROC 08/09/2010 : Protection de l'acc�s � la liste qui indique pour chaque thread le nom du fichier de log utilis� */
#include "internal.h"
#include <stdarg.h>

void * gMutexLogFileList = NULL;
/* MCUG & AROC 08/09/2010 : Fin */


#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#include <limits.h>
#endif

#include "sys_config.h"

#if defined(__APPLE__) || defined(UNIX_LUX)
/* BPER - (@@20160629-0001301) - Rendre le repertoire de logs parametrable (traces OpenSC): Debut */
extern char logDirOPSC[256];
/* BPER - (@@20160629-0001301) - Rendre le repertoire de logs parametrable (traces OpenSC): Fin */
#endif

#ifdef __APPLE__
extern int g_sandboxed;
#endif

extern CK_RV mutex_create(void **mutex);
extern CK_RV mutex_lock(void *p);
extern CK_RV mutex_unlock(void *p);
extern CK_RV mutex_destroy(void *p);

#define __PASTE(x,y)      x##y

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
extern CK_FUNCTION_LIST pkcs11_function_list;
/* CLCO 06/07/2010 : Fin  */

/* Declare all spy_* Cryptoki function */

/* Spy Module Function List */
static CK_FUNCTION_LIST_PTR pkcs11_spy = NULL;
/* Real Module Function List */
static CK_FUNCTION_LIST_PTR po = NULL;
/* Dynamic Module Handle */

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
unsigned long traces_enabled = 0;


/* MCUG 07/09/2010 : Optimisation de la la lecture du r�pertoire des log */
char logDirP11[256] = { 0 };
/* MCUG 01/09/2010 : Fin */

/* MCUG & AROC 08/09/2010 : Protection de l'acc�s � la liste qui indique pour chaque thread le nom du fichier de log utilis� */
extern struct sc_context * getCurContext(void);
/* BPER (@@22072016-1381) gestion multithread: extern sc_context_t *context;*/
/* MCUG & AROC 08/09/2010 : Fin */

FILE * get_spy_out_by_thread_force_open(void)
{
  FILE * pTraceFile = NULL;
  char traceFileName[512] = { 0 };
  unsigned long threadID, processID;

  if (!is_traces_enabled())
    return NULL;

  getCurrentProcess(&processID);
  getCurrentThread(&threadID);

  /* MCUG 07/09/2010 : Optimisation de la la lecture du r�pertoire des log */
  if (logDirP11[0] == 0) {
    sys_GetLogPath(logDirP11, sizeof(logDirP11));
  }
  /* MCUG 07/09/2010 : Fin */

  sprintf(traceFileName, "%scps3p11_%lx_%lx.log", logDirP11, processID, threadID);
  pTraceFile = fopen(traceFileName, "a");
  return pTraceFile;
}



/* Inits the spy. If successfull, po != NULL */
static CK_RV init_spy(void)
{
  //  const char *traces;
  int rv = CKR_OK;

#if defined(__APPLE__) || defined(UNIX_LUX)
  char filePath[256] = "";
  scconf_context * opt_conf = NULL;
  scconf_block * opt_block = NULL;
#endif
  /* Allocates and initializes the pkcs11_spy structure */
  pkcs11_spy = (CK_FUNCTION_LIST_PTR)malloc(sizeof(CK_FUNCTION_LIST));
  if (pkcs11_spy) {
    /* with our own pkcs11.h we need to maintain this ourself */
    pkcs11_spy->version.major = 2;
    pkcs11_spy->version.minor = 11;
    pkcs11_spy->C_Initialize = C_Initialize;
    pkcs11_spy->C_Finalize = C_Finalize;
    pkcs11_spy->C_GetInfo = C_GetInfo;
    pkcs11_spy->C_GetFunctionList = C_GetFunctionList;
    pkcs11_spy->C_GetSlotList = C_GetSlotList;
    pkcs11_spy->C_GetSlotInfo = C_GetSlotInfo;
    pkcs11_spy->C_GetTokenInfo = C_GetTokenInfo;
    pkcs11_spy->C_GetMechanismList = C_GetMechanismList;
    pkcs11_spy->C_GetMechanismInfo = C_GetMechanismInfo;
    pkcs11_spy->C_InitToken = C_InitToken;
    pkcs11_spy->C_InitPIN = C_InitPIN;
    pkcs11_spy->C_SetPIN = C_SetPIN;
    pkcs11_spy->C_OpenSession = C_OpenSession;
    pkcs11_spy->C_CloseSession = C_CloseSession;
    pkcs11_spy->C_CloseAllSessions = C_CloseAllSessions;
    pkcs11_spy->C_GetSessionInfo = C_GetSessionInfo;
    pkcs11_spy->C_GetOperationState = C_GetOperationState;
    pkcs11_spy->C_SetOperationState = C_SetOperationState;
    pkcs11_spy->C_Login = C_Login;
    pkcs11_spy->C_Logout = C_Logout;
    pkcs11_spy->C_CreateObject = C_CreateObject;
    pkcs11_spy->C_CopyObject = C_CopyObject;
    pkcs11_spy->C_DestroyObject = C_DestroyObject;
    pkcs11_spy->C_GetObjectSize = C_GetObjectSize;
    pkcs11_spy->C_GetAttributeValue = C_GetAttributeValue;
    pkcs11_spy->C_SetAttributeValue = C_SetAttributeValue;
    pkcs11_spy->C_FindObjectsInit = C_FindObjectsInit;
    pkcs11_spy->C_FindObjects = C_FindObjects;
    pkcs11_spy->C_FindObjectsFinal = C_FindObjectsFinal;
    pkcs11_spy->C_EncryptInit = C_EncryptInit;
    pkcs11_spy->C_Encrypt = C_Encrypt;
    pkcs11_spy->C_EncryptUpdate = C_EncryptUpdate;
    pkcs11_spy->C_EncryptFinal = C_EncryptFinal;
    pkcs11_spy->C_DecryptInit = C_DecryptInit;
    pkcs11_spy->C_Decrypt = C_Decrypt;
    pkcs11_spy->C_DecryptUpdate = C_DecryptUpdate;
    pkcs11_spy->C_DecryptFinal = C_DecryptFinal;
    pkcs11_spy->C_DigestInit = C_DigestInit;
    pkcs11_spy->C_Digest = C_Digest;
    pkcs11_spy->C_DigestUpdate = C_DigestUpdate;
    pkcs11_spy->C_DigestKey = C_DigestKey;
    pkcs11_spy->C_DigestFinal = C_DigestFinal;
    pkcs11_spy->C_SignInit = C_SignInit;
    pkcs11_spy->C_Sign = C_Sign;
    pkcs11_spy->C_SignUpdate = C_SignUpdate;
    pkcs11_spy->C_SignFinal = C_SignFinal;
    pkcs11_spy->C_SignRecoverInit = C_SignRecoverInit;
    pkcs11_spy->C_SignRecover = C_SignRecover;
    pkcs11_spy->C_VerifyInit = C_VerifyInit;
    pkcs11_spy->C_Verify = C_Verify;
    pkcs11_spy->C_VerifyUpdate = C_VerifyUpdate;
    pkcs11_spy->C_VerifyFinal = C_VerifyFinal;
    pkcs11_spy->C_VerifyRecoverInit = C_VerifyRecoverInit;
    pkcs11_spy->C_VerifyRecover = C_VerifyRecover;
    pkcs11_spy->C_DigestEncryptUpdate = C_DigestEncryptUpdate;
    pkcs11_spy->C_DecryptDigestUpdate = C_DecryptDigestUpdate;
    pkcs11_spy->C_SignEncryptUpdate = C_SignEncryptUpdate;
    pkcs11_spy->C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
    pkcs11_spy->C_GenerateKey = C_GenerateKey;
    pkcs11_spy->C_GenerateKeyPair = C_GenerateKeyPair;
    pkcs11_spy->C_WrapKey = C_WrapKey;
    pkcs11_spy->C_UnwrapKey = C_UnwrapKey;
    pkcs11_spy->C_DeriveKey = C_DeriveKey;
    pkcs11_spy->C_SeedRandom = C_SeedRandom;
    pkcs11_spy->C_GenerateRandom = C_GenerateRandom;
    pkcs11_spy->C_GetFunctionStatus = C_GetFunctionStatus;
    pkcs11_spy->C_CancelFunction = C_CancelFunction;
    pkcs11_spy->C_WaitForSlotEvent = C_WaitForSlotEvent;
    pkcs11_spy->C_StartUpdate = C_StartUpdate;
    pkcs11_spy->C_EndUpdate = C_EndUpdate;
    pkcs11_spy->C_TransmitMessage = C_TransmitMessage;
    pkcs11_spy->C_KeepAlive = C_KeepAlive;
  }
  else {
    return CKR_HOST_MEMORY;
  }


#if defined (_WIN32)
  GET_DW_REG_PARAM(REG_SUBKEY, "traces", traces_enabled);
  
#elif defined(__APPLE__) || defined(UNIX_LUX)
  
#if defined(__APPLE__)
  g_sandboxed =  getenv("APP_SANDBOX_CONTAINER_ID") == NULL ? 0 : 1;
#endif
  sys_GetConfPath(filePath, 256);
  strcat(filePath, "cps3_pkcs11.conf");
  opt_conf = scconf_new(filePath);
  if (opt_conf != NULL) {
    scconf_parse(opt_conf);
    opt_block = (scconf_block*)scconf_find_block(opt_conf, NULL, "traces");
    if (opt_block != NULL) {
	    /* BPER - (@@20160629-0001301) - Rendre le repertoire de logs parametrable (traces P11): Debut */
      const char* pLogDir = NULL;
      pLogDir = scconf_get_str(opt_block, "path", 0);
      if(pLogDir != NULL){
        strcpy(logDirP11,pLogDir);
        if (logDirP11[strlen(logDirP11) - 1] != '/'){
          strcat(logDirP11, "/");
        }
        strcpy(logDirOPSC, logDirP11);
      }
      /* BPER - (@@20160629-0001301) - Rendre le repertoire de logs parametrable : Fin */
      traces_enabled = scconf_get_bool(opt_block, "active", 0);
    }
    scconf_free(opt_conf);
  }
#endif // defined(__APPLE__) || defined(UNIX_LUX)


  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  if (traces_enabled) {
    logP11("*************** Traces PKCS#11 CPS3 *****************");
    logP11("Process = %s", getProcessName());
  }

  po = &pkcs11_function_list;
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
int is_traces_enabled(void) {
  return (int)traces_enabled;
}
/* CLCO 06/07/2010 : Fin  */

static void enter(const char *function)
{
  static int count = 0;

  if (!is_traces_enabled()) {
    return;
  }

  logP11("%d: %s", count++, function);

}

static CK_RV retne(CK_RV rv)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return rv;
  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("Returned:  %ld %s\n", (unsigned long)rv, lookup_enum(RV_T, rv));
  /* MCUG 01/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
  return rv;
}

static void spy_dump_string_in(const char *name, CK_VOID_PTR data, CK_ULONG size)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[in] %s", name);
  /* MCUG 01/09/2010 : Fin */

  /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
  print_generic(0, data, size, NULL);
  /* MCUG 06/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

static void spy_dump_sensitive_string_in(const char *name, CK_ULONG size)
{
  char *mask = NULL;
  
  if (!is_traces_enabled())
    return;
  
  mask = calloc(size, sizeof(const char));

  if (mask == NULL)
    return;

  memset((void*)mask, '*', size);
  logP11("[in] %s", name);

  print_generic(0, (CK_VOID_PTR)mask, size, NULL);
  free(mask);
}


static void spy_dump_string_out(const char *name, CK_VOID_PTR data, CK_ULONG size)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;
  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[out] %s ", name);
  /* MCUG 01/09/2010 : Fin */

  /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
  print_generic(0, data, size, NULL);
  /* MCUG 06/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

static void spy_dump_ulong_in(const char *name, CK_ULONG value)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[in] %s = 0x%lx", name, value);
  /* MCUG 01/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

static void spy_dump_ulong_out(const char *name, CK_ULONG value)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[out] %s = 0x%lx", name, value);
  /* MCUG 01/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

static void spy_dump_desc_out(const char *name)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[out] %s: ", name);
  /* MCUG 01/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

static void spy_dump_array_out(const char *name, CK_ULONG size)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[out] %s[%ld]: ", name, size);
  /* MCUG 01/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

static void spy_attribute_req_in(const char *name, CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulCount)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[in] %s[%ld]: ", name, ulCount);
  /* MCUG 01/09/2010 : Fin */

  /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
  print_attribute_list_req(pTemplate, ulCount);
  /* MCUG 06/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

static void spy_attribute_list_in(const char *name, CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulCount)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[in] %s[%ld]: ", name, ulCount);
  /* MCUG 01/09/2010 : Fin */

  /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
  print_attribute_list(pTemplate, ulCount);
  /* MCUG 06/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

static void spy_attribute_list_out(const char *name, CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulCount)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[out] %s[%ld]: ", name, ulCount);
  /* MCUG 01/09/2010 : Fin */

  /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
  print_attribute_list(pTemplate, ulCount);
  /* MCUG 06/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

static void print_ptr_in(const char *name, CK_VOID_PTR ptr)
{
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[in] %s = %p", name, ptr);
  /* MCUG 01/09/2010 : Fin */

  /* CLCO 06/07/2010 : Fin  */
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
static void spy_dump_user_type(CK_USER_TYPE userType)
{
  if (!is_traces_enabled())
    return;
  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("[in] userType = %s",
    /* MCUG 01/09/2010 : Fin */

    lookup_enum(USR_T, userType));
}

static void spy_dump_mech_info_type(CK_MECHANISM_TYPE type)
{
  const char *name;
  if (!is_traces_enabled())
    return;
  name = lookup_enum(MEC_T, type);

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  if (name) {
    logP11("%30s ", name);
  }
  else {
    logP11(" Unknown Mechanism (%08lx)  ", type);
  }
  /* MCUG 01/09/2010 : Fin */
}

static void spy_dump_mech_type(CK_MECHANISM_TYPE type)
{
  const char *name;
  if (!is_traces_enabled())
    return;
  name = lookup_enum(MEC_T, type);

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  if (name) {
    logP11("pMechanism->type=%s", name);
  }
  else {
    logP11("pMechanism->type=Unknown Mechanism (%08lx)  ", type);
  }
  /* MCUG 01/09/2010 : Fin */

}

static void spy_dump_open_session_in(CK_VOID_PTR  pApplication, CK_NOTIFY  Notify)
{
  if (!is_traces_enabled())
    return;

  /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
  logP11("pApplication=%p", pApplication);
  logP11("Notify=%p", (void *)Notify);
  /* MCUG 01/09/2010 : Fin */
}

static void spy_dump_object(CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG_PTR  pulObjectCount)
{
  CK_ULONG i;
  if (!is_traces_enabled())
    return;
  if (pulObjectCount) {

    /* MCUG 01/09/2010 : Adaptation des traces PKCS#11 */
    for (i = 0; i < *pulObjectCount; i++) {
      logP11("Object %ld Matches", phObject[i]);
    }
    /* MCUG 01/09/2010 : Fin */
  }
}
/* CLCO 06/07/2010 : Fin  */

int lockLog(void)
{
  int r;
  if (gMutexLogFileList != NULL) {
    r = mutex_lock(gMutexLogFileList);
    if (r != SC_SUCCESS)
      return r;
  }
  return 0;
}

void unlockLog(void)
{
  int r;
  if (gMutexLogFileList != NULL) {
    r = (int)mutex_unlock(gMutexLogFileList);
    if (r != SC_SUCCESS) {
      // BPER 1381 - Solution C - D�but
      struct sc_context *rctx = getCurContext();
      if (rctx != NULL)
#if defined(__APPLE__)
        _sc_error(rctx, "unable to release lock\n");
#else
        sc_error(rctx, "unable to release lock\n");
#endif
      // BPER 1381 - Solution C - Fin
    }
  }
}
/* MCUG 01/09/2010 : Ajout d'une fonction permettant de log avec pour prefixe la date */
int logP11(const char *format, ...)
{
  va_list arg;
  int done;
  FILE * pTraceFile = NULL;
  char traceFileName[512] = { 0 };
  unsigned long threadID, processID;

  
  if (!is_traces_enabled()) {
    return 0;
  }

  getCurrentProcess(&processID);
  getCurrentThread(&threadID);

  
  /* MCUG & AROC 08/09/2010 : Protection de l'acc�s � la liste qui indique pour chaque thread le nom du fichier de log utilis� */
  lockLog();
  /* MCUG 07/09/2010 : Optimisation de la la lecture du r�pertoire des log */
  if (logDirP11[0] == 0) {
    sys_GetLogPath(logDirP11, sizeof(logDirP11));
  }
  /* MCUG 07/09/2010 : Fin */

  sprintf(traceFileName, "%scps3p11_%lx_%lx.log", logDirP11, processID, threadID);
  pTraceFile = fopen(traceFileName, "a");
  if (pTraceFile == NULL) {
    /* AROC (@@20130115) - Il faut lib�rer l'acc�s en cas d'erreur - Debut */
    unlockLog();
    /* AROC (@@20130115) - Fin */
    return 1;
  }


  fprintf(pTraceFile, "\n");
  sc_add_time_to_log(pTraceFile);
  va_start(arg, format);
  done = vfprintf(pTraceFile, format, arg);
  va_end(arg);

  fflush(pTraceFile);
  fclose(pTraceFile);

  unlockLog();
  /* MCUG & AROC 08/09/2010 : Fin */
  return done;
}
/* MCUG 01/09/2010 : Fin */



CK_RV C_GetFunctionList
(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  /* MCUG & AROC 08/09/2010 : Protection de l'acc�s � la liste qui indique pour chaque thread le nom du fichier de log utilis� */
  if (gMutexLogFileList == NULL)
    mutex_create(&gMutexLogFileList);
  /* MCUG & AROC 08/09/2010 : Fin */

  if (po == NULL) {
    CK_RV rv = init_spy();
    if (rv != CKR_OK)
      return rv;
  }

  enter("C_GetFunctionList");
  *ppFunctionList = pkcs11_spy;
  return retne(CKR_OK);
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
  CK_RV rv;

  if (po == NULL) {
    rv = init_spy();
    if (rv != CKR_OK)
      return rv;
  }
  /* MCUG & AROC 08/09/2010 : Protection de l'acc�s � la liste qui indique pour chaque thread le nom du fichier de log utilis� */
  if (gMutexLogFileList == NULL)
    mutex_create(&gMutexLogFileList);
  /* MCUG & AROC 08/09/2010 : Fin */

  enter("C_Initialize");
  print_ptr_in("pInitArgs", pInitArgs);
  rv = po->C_Initialize(pInitArgs);
  return retne(rv);
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
  CK_RV rv;
  enter("C_Finalize");
  rv = po->C_Finalize(pReserved);
  retne(rv);

  /* MCUG & AROC 08/09/2010 : Protection de l'acc�s � la liste qui indique pour chaque thread le nom du fichier de log utilis� */
  if (gMutexLogFileList != NULL) {
    mutex_destroy(gMutexLogFileList);
    gMutexLogFileList = NULL;
  }
  /* MCUG & AROC 08/09/2010 : Fin */

  return rv;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
  CK_RV rv;
  enter("C_GetInfo");
  rv = po->C_GetInfo(pInfo);
  if (rv == CKR_OK) {
    spy_dump_desc_out("pInfo");
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */

    /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
    print_ck_info(pInfo);
    /* MCUG 06/09/2010 : Fin */

    /* CLCO 06/07/2010 : Fin  */
  }
  return retne(rv);
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
  CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR pulCount)
{
  CK_RV rv;
  enter("C_GetSlotList");
  spy_dump_ulong_in("tokenPresent", tokenPresent);
  rv = po->C_GetSlotList(tokenPresent, pSlotList, pulCount);
  if (rv == CKR_OK) {
    spy_dump_desc_out("pSlotList");
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */

    /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
    print_slot_list(pSlotList, *pulCount);
    /* MCUG 06/09/2010 : Fin */

    /* CLCO 06/07/2010 : Fin  */
    spy_dump_ulong_out("*pulCount", *pulCount);
  }
  return retne(rv);
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
  CK_SLOT_INFO_PTR pInfo)
{
  CK_RV rv;
  enter("C_GetSlotInfo");
  spy_dump_ulong_in("slotID", slotID);
  rv = po->C_GetSlotInfo(slotID, pInfo);
  if (rv == CKR_OK) {
    spy_dump_desc_out("pInfo");
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */

    /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
    print_slot_info(pInfo);
    /* MCUG 06/09/2010 : Fin */

    /* CLCO 06/07/2010 : Fin  */
  }
  return retne(rv);
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID,
  CK_TOKEN_INFO_PTR pInfo)
{
  CK_RV rv;
  enter("C_GetTokenInfo");
  spy_dump_ulong_in("slotID", slotID);
  rv = po->C_GetTokenInfo(slotID, pInfo);
  if (rv == CKR_OK) {
    spy_dump_desc_out("pInfo");
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */

    /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
    print_token_info(pInfo);
    /* MCUG 06/09/2010 : Fin */

    /* CLCO 06/07/2010 : Fin  */
  }
  return retne(rv);
}

CK_RV C_GetMechanismList(CK_SLOT_ID  slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR  pulCount)
{
  CK_RV rv;
  enter("C_GetMechanismList");
  spy_dump_ulong_in("slotID", slotID);
  rv = po->C_GetMechanismList(slotID, pMechanismList, pulCount);
  if (rv == CKR_OK) {
    spy_dump_array_out("pMechanismList", *pulCount);
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */

    /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
    print_mech_list(pMechanismList, *pulCount);
    /* MCUG 06/09/2010 : Fin */

    /* CLCO 06/07/2010 : Fin  */
  }
  return retne(rv);
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID  slotID,
  CK_MECHANISM_TYPE type,
  CK_MECHANISM_INFO_PTR pInfo)
{
  CK_RV rv;
  enter("C_GetMechanismInfo");
  spy_dump_ulong_in("slotID", slotID);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_info_type(type);
  /* CLCO 06/07/2010 : Fin  */
  rv = po->C_GetMechanismInfo(slotID, type, pInfo);
  if (rv == CKR_OK) {
    spy_dump_desc_out("pInfo");
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */

    /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
    print_mech_info(type, pInfo);
    /* MCUG 06/09/2010 : Fin */

    /* CLCO 06/07/2010 : Fin  */
  }
  return retne(rv);
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_UTF8CHAR_PTR pLabel)
{
  CK_RV rv;
  enter("C_InitToken");
  spy_dump_ulong_in("slotID", slotID);
  /* MCUG 16/09/2010 : Masquage PIN & PUK des traces PKCS#11 */
  spy_dump_sensitive_string_in("pPin[ulPinLen]", ulPinLen);
  /* MCUG 16/09/2010 : Fin */
  spy_dump_string_in("pLabel[32]", pLabel, 32);
  rv = po->C_InitToken(slotID, pPin, ulPinLen, pLabel);
  return retne(rv);
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG  ulPinLen)
{
  CK_RV rv;
  enter("C_InitPIN");
  spy_dump_ulong_in("hSession", hSession);
  /* MCUG 16/09/2010 : Masquage PIN & PUK des traces PKCS#11 */
  spy_dump_sensitive_string_in("pPin[ulPinLen]", ulPinLen);
  /* MCUG 16/09/2010 : Fin */
  rv = po->C_InitPIN(hSession, pPin, ulPinLen);
  return retne(rv);
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pOldPin,
  CK_ULONG  ulOldLen,
  CK_UTF8CHAR_PTR pNewPin,
  CK_ULONG  ulNewLen)
{
  CK_RV rv;
  enter("C_SetPIN");
  spy_dump_ulong_in("hSession", hSession);
  /* MCUG 16/09/2010 : Masquage PIN & PUK des traces PKCS#11 */
  spy_dump_sensitive_string_in("pOldPin[ulOldLen]", ulOldLen);
  spy_dump_sensitive_string_in("pNewPin[ulNewLen]", ulNewLen);
  /* MCUG 16/09/2010 : Fin */
  rv = po->C_SetPIN(hSession, pOldPin, ulOldLen,
    pNewPin, ulNewLen);
  return retne(rv);
}

CK_RV C_OpenSession(CK_SLOT_ID  slotID,
  CK_FLAGS  flags,
  CK_VOID_PTR  pApplication,
  CK_NOTIFY  Notify,
  CK_SESSION_HANDLE_PTR phSession)
{
  CK_RV rv;
  enter("C_OpenSession");
  spy_dump_ulong_in("slotID", slotID);
  spy_dump_ulong_in("flags", flags);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_open_session_in(pApplication, Notify);
  /* CLCO 06/07/2010 : Fin  */
  rv = po->C_OpenSession(slotID, flags, pApplication,
    Notify, phSession);
  /* BPER 16/11/2011 correction du trap si le dernier parametre est NULL */
  if (rv == CKR_OK)
    spy_dump_ulong_out("*phSession", *phSession);
  /* BPER 16/11/2011 Fin */
  return retne(rv);
}


CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  enter("C_CloseSession");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_CloseSession(hSession);
  return retne(rv);
}


CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
  CK_RV rv;
  enter("C_CloseAllSessions");
  spy_dump_ulong_in("slotID", slotID);
  rv = po->C_CloseAllSessions(slotID);
  return retne(rv);
}


CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo)
{
  CK_RV rv;
  enter("C_GetSessionInfo");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_GetSessionInfo(hSession, pInfo);
  if (rv == CKR_OK) {
    spy_dump_desc_out("pInfo");
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */

    /* MCUG 06/09/2010 : Adaptation des traces PKCS#11 */
    print_session_info(pInfo);
    /* MCUG 06/09/2010 : Fin */

    /* CLCO 06/07/2010 : Fin  */
  }
  return retne(rv);
}


CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG_PTR pulOperationStateLen)
{
  CK_RV rv;
  enter("C_GetOperationState");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_GetOperationState(hSession, pOperationState,
    pulOperationStateLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pOperationState[*pulOperationStateLen]",
      pOperationState, *pulOperationStateLen);
  }
  return retne(rv);
}


CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG  ulOperationStateLen,
  CK_OBJECT_HANDLE hEncryptionKey,
  CK_OBJECT_HANDLE hAuthenticationKey)
{
  CK_RV rv;
  enter("SetOperationState");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pOperationState[ulOperationStateLen]",
    pOperationState, ulOperationStateLen);
  spy_dump_ulong_in("hEncryptionKey", hEncryptionKey);
  spy_dump_ulong_in("hAuthenticationKey", hAuthenticationKey);
  rv = po->C_SetOperationState(hSession, pOperationState,
    ulOperationStateLen,
    hEncryptionKey,
    hAuthenticationKey);
  return retne(rv);
}


CK_RV C_Login(CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG  ulPinLen)
{
  CK_RV rv;
  enter("C_Login");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_user_type(userType);
  /* CLCO 06/07/2010 : Fin  */
  /* MCUG 16/09/2010 : Masquage PIN & PUK des traces PKCS#11 */
  spy_dump_sensitive_string_in("pPin[ulPinLen]", ulPinLen);
  /* MCUG 16/09/2010 : Fin */
  rv = po->C_Login(hSession, userType, pPin, ulPinLen);
  return retne(rv);
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  enter("C_Logout");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_Logout(hSession);
  return retne(rv);
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulCount,
  CK_OBJECT_HANDLE_PTR phObject)
{
  CK_RV rv;
  enter("C_CreateObject");
  spy_dump_ulong_in("hSession", hSession);
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_CreateObject(hSession, pTemplate, ulCount, phObject);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("*phObject", *phObject);
  }
  return retne(rv);
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject)
{
  CK_RV rv;
  enter("C_CopyObject");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hObject", hObject);
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("*phNewObject", *phNewObject);
  }
  return retne(rv);
}


CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject)
{
  CK_RV rv;
  enter("C_DestroyObject");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hObject", hObject);
  rv = po->C_DestroyObject(hSession, hObject);
  return retne(rv);
}


CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ULONG_PTR pulSize)
{
  CK_RV rv;
  enter("C_GetObjectSize");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hObject", hObject);
  rv = po->C_GetObjectSize(hSession, hObject, pulSize);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("*pulSize", *pulSize);
  }
  return retne(rv);
}


CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulCount)
{
  CK_RV rv;
  enter("C_GetAttributeValue");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hObject", hObject);
  spy_attribute_req_in("pTemplate", pTemplate, ulCount);
  /* PKCS#11 says:
  * ``Note that the error codes CKR_ATTRIBUTE_SENSITIVE,
  *   CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL do not denote
  *   true errors for C_GetAttributeValue.''
  * That's why we ignore these error codes, because we want to display
  * all other attributes anyway (they may have been returned correctly) */
  rv = po->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
  if (rv == CKR_OK || rv == CKR_ATTRIBUTE_SENSITIVE ||
    rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_BUFFER_TOO_SMALL) {
    spy_attribute_list_out("pTemplate", pTemplate, ulCount);
  }
  return retne(rv);
}


CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulCount)
{
  CK_RV rv;
  enter("C_SetAttributeValue");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hObject", hObject);
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
  return retne(rv);
}


CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulCount)
{
  CK_RV rv;
  enter("C_FindObjectsInit");
  spy_dump_ulong_in("hSession", hSession);
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_FindObjectsInit(hSession, pTemplate, ulCount);
  return retne(rv);
}


CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG  ulMaxObjectCount,
  CK_ULONG_PTR  pulObjectCount)
{
  CK_RV rv;
  enter("C_FindObjects");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("ulMaxObjectCount", ulMaxObjectCount);
  rv = po->C_FindObjects(hSession, phObject, ulMaxObjectCount,
    pulObjectCount);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("ulObjectCount", *pulObjectCount);
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */
    spy_dump_object(phObject, pulObjectCount);
    /* CLCO 06/07/2010 : Fin  */
  }
  return retne(rv);
}


CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  enter("C_FindObjectsFinal");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_FindObjectsFinal(hSession);
  return retne(rv);
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  enter("C_EncryptInit");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_EncryptInit(hSession, pMechanism, hKey);
  return retne(rv);
}


CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG  ulDataLen,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen)
{
  CK_RV rv;
  enter("C_Encrypt");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  rv = po->C_Encrypt(hSession, pData, ulDataLen,
    pEncryptedData, pulEncryptedDataLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pEncryptedData[*pulEncryptedDataLen]",
      pEncryptedData, *pulEncryptedDataLen);
  }
  return retne(rv);
}


CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG  ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen)
{
  CK_RV rv;
  enter("C_EncryptUpdate");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart,
    pulEncryptedPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]",
      pEncryptedPart, *pulEncryptedPartLen);
  }
  return retne(rv);
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastEncryptedPart,
  CK_ULONG_PTR pulLastEncryptedPartLen)
{
  CK_RV rv;
  enter("C_EncryptFinal");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_EncryptFinal(hSession, pLastEncryptedPart,
    pulLastEncryptedPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pLastEncryptedPart[*pulLastEncryptedPartLen]",
      pLastEncryptedPart, *pulLastEncryptedPartLen);
  }
  return retne(rv);
}


CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  enter("C_DecryptInit");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_DecryptInit(hSession, pMechanism, hKey);
  return retne(rv);
}


CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG  ulEncryptedDataLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen)
{
  CK_RV rv;
  enter("C_Decrypt");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pEncryptedData[ulEncryptedDataLen]",
    pEncryptedData, ulEncryptedDataLen);
  rv = po->C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen,
    pData, pulDataLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);
  }
  return retne(rv);
}


CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG  ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen)
{
  CK_RV rv;
  enter("C_DecryptUpdate");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pEncryptedPart[ulEncryptedPartLen]",
    pEncryptedPart, ulEncryptedPartLen);
  rv = po->C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen,
    pPart, pulPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
  }
  return retne(rv);
}


CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastPart,
  CK_ULONG_PTR pulLastPartLen)
{
  CK_RV rv;
  enter("C_DecryptFinal");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_DecryptFinal(hSession, pLastPart, pulLastPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pLastPart[*pulLastPartLen]",
      pLastPart, *pulLastPartLen);
  }
  return retne(rv);
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism)
{
  CK_RV rv;
  enter("C_DigestInit");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  rv = po->C_DigestInit(hSession, pMechanism);
  return retne(rv);
}


CK_RV C_Digest(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG  ulDataLen,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen)
{
  CK_RV rv;
  enter("C_Digest");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  rv = po->C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pDigest[*pulDigestLen]",
      pDigest, *pulDigestLen);
  }
  return retne(rv);
}


CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG  ulPartLen)
{
  CK_RV rv;
  enter("C_DigestUpdate");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_DigestUpdate(hSession, pPart, ulPartLen);
  return retne(rv);
}


CK_RV C_DigestKey(CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  enter("C_DigestKey");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_DigestKey(hSession, hKey);
  return retne(rv);
}


CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen)
{
  CK_RV rv;
  enter("C_DigestFinal");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_DigestFinal(hSession, pDigest, pulDigestLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pDigest[*pulDigestLen]",
      pDigest, *pulDigestLen);
  }
  return retne(rv);
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  enter("C_SignInit");
  spy_dump_ulong_in("hSession", hSession);
  /* BPER (@@20121015) � Test du pointeur de m�canisme NULL */
  if (pMechanism != NULL_PTR)
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */
    spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  /* BPER (@@20121015) � Fin */
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_SignInit(hSession, pMechanism, hKey);
  return retne(rv);
}


CK_RV C_Sign(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG  ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen)
{
  CK_RV rv;
  enter("C_Sign");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  rv = po->C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pSignature[*pulSignatureLen]",
      pSignature, *pulSignatureLen);
  }
  return retne(rv);
}


CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG  ulPartLen)
{
  CK_RV rv;
  enter("C_SignUpdate");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_SignUpdate(hSession, pPart, ulPartLen);
  return retne(rv);
}


CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen)
{
  CK_RV rv;
  enter("C_SignFinal");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_SignFinal(hSession, pSignature, pulSignatureLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pSignature[*pulSignatureLen]",
      pSignature, *pulSignatureLen);
  }
  return retne(rv);
}


CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  enter("C_SignRecoverInit");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_SignRecoverInit(hSession, pMechanism, hKey);
  return retne(rv);
}


CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG  ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen)
{
  CK_RV rv;
  enter("C_SignRecover");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  rv = po->C_SignRecover(hSession, pData, ulDataLen,
    pSignature, pulSignatureLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pSignature[*pulSignatureLen]",
      pSignature, *pulSignatureLen);
  }
  return retne(rv);
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  enter("C_VerifyInit");
  spy_dump_ulong_in("hSession", hSession);
  /* BPER (@@20121015) � Test du pointeur de m�canisme NULL */
  if (pMechanism != NULL_PTR)
    /* CLCO 06/07/2010 : Adaptation ASIP des traces */
    spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  /* BPER (@@20121015) � Fin */
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_VerifyInit(hSession, pMechanism, hKey);
  return retne(rv);
}


CK_RV C_Verify(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG  ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG  ulSignatureLen)
{
  CK_RV rv;
  enter("C_Verify");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  spy_dump_string_in("pSignature[ulSignatureLen]",
    pSignature, ulSignatureLen);
  rv = po->C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
  return retne(rv);
}


CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG  ulPartLen)
{
  CK_RV rv;
  enter("C_VerifyUpdate");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_VerifyUpdate(hSession, pPart, ulPartLen);
  return retne(rv);
}


CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG  ulSignatureLen)
{
  CK_RV rv;
  enter("C_VerifyFinal");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pSignature[ulSignatureLen]",
    pSignature, ulSignatureLen);
  rv = po->C_VerifyFinal(hSession, pSignature, ulSignatureLen);
  return retne(rv);
}


CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  enter("C_VerifyRecoverInit");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_VerifyRecoverInit(hSession, pMechanism, hKey);
  return retne(rv);
}


CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG  ulSignatureLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen)
{
  CK_RV rv;
  enter("C_VerifyRecover");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pSignature[ulSignatureLen]",
    pSignature, ulSignatureLen);
  rv = po->C_VerifyRecover(hSession, pSignature, ulSignatureLen,
    pData, pulDataLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);
  }
  return retne(rv);
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG  ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen)
{
  CK_RV rv;
  enter("C_DigestEncryptUpdate");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_DigestEncryptUpdate(hSession, pPart, ulPartLen,
    pEncryptedPart, pulEncryptedPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]",
      pEncryptedPart, *pulEncryptedPartLen);
  }
  return retne(rv);
}


CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG  ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen)
{
  CK_RV rv;
  enter("C_DecryptDigestUpdate");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pEncryptedPart[ulEncryptedPartLen]",
    pEncryptedPart, ulEncryptedPartLen);
  rv = po->C_DecryptDigestUpdate(hSession, pEncryptedPart,
    ulEncryptedPartLen,
    pPart, pulPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
  }
  return retne(rv);
}


CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG  ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen)
{
  CK_RV rv;
  enter("C_SignEncryptUpdate");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_SignEncryptUpdate(hSession, pPart, ulPartLen,
    pEncryptedPart, pulEncryptedPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]",
      pEncryptedPart, *pulEncryptedPartLen);
  }
  return retne(rv);
}


CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG  ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen)
{
  CK_RV rv;
  enter("C_DecryptVerifyUpdate");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pEncryptedPart[ulEncryptedPartLen]",
    pEncryptedPart, ulEncryptedPartLen);
  rv = po->C_DecryptVerifyUpdate(hSession, pEncryptedPart,
    ulEncryptedPartLen, pPart,
    pulPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
  }
  return retne(rv);
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulCount,
  CK_OBJECT_HANDLE_PTR phKey)
{
  CK_RV rv;
  enter("C_GenerateKey");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_GenerateKey(hSession, pMechanism, pTemplate,
    ulCount, phKey);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("hKey", *phKey);
  }
  return retne(rv);
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_ATTRIBUTE_PTR pPublicKeyTemplate,
  CK_ULONG  ulPublicKeyAttributeCount,
  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
  CK_ULONG  ulPrivateKeyAttributeCount,
  CK_OBJECT_HANDLE_PTR phPublicKey,
  CK_OBJECT_HANDLE_PTR phPrivateKey)
{
  CK_RV rv;
  enter("C_GenerateKeyPair");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  spy_attribute_list_in("pPublicKeyTemplate",
    pPublicKeyTemplate, ulPublicKeyAttributeCount);
  spy_attribute_list_in("pPrivateKeyTemplate",
    pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
  rv = po->C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate,
    ulPublicKeyAttributeCount, pPrivateKeyTemplate,
    ulPrivateKeyAttributeCount, phPublicKey,
    phPrivateKey);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("hPublicKey", *phPublicKey);
    spy_dump_ulong_out("hPrivateKey", *phPrivateKey);
  }
  return retne(rv);
}


CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hWrappingKey,
  CK_OBJECT_HANDLE hKey,
  CK_BYTE_PTR pWrappedKey,
  CK_ULONG_PTR pulWrappedKeyLen)
{
  CK_RV rv;
  enter("C_WrapKey");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  spy_dump_ulong_in("hWrappingKey", hWrappingKey);
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_WrapKey(hSession, pMechanism, hWrappingKey,
    hKey, pWrappedKey, pulWrappedKeyLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pWrappedKey[*pulWrappedKeyLen]",
      pWrappedKey, *pulWrappedKeyLen);
  }
  return retne(rv);
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hUnwrappingKey,
  CK_BYTE_PTR  pWrappedKey,
  CK_ULONG  ulWrappedKeyLen,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey)
{
  CK_RV rv;
  enter("C_UnwrapKey");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  spy_dump_ulong_in("hUnwrappingKey", hUnwrappingKey);
  spy_dump_string_in("pWrappedKey[ulWrappedKeyLen]",
    pWrappedKey, ulWrappedKeyLen);
  spy_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
  rv = po->C_UnwrapKey(hSession, pMechanism, hUnwrappingKey,
    pWrappedKey, ulWrappedKeyLen, pTemplate,
    ulAttributeCount, phKey);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("hKey", *phKey);
  }
  return retne(rv);
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hBaseKey,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG  ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey)
{
  CK_RV rv;
  enter("C_DeriveKey");
  spy_dump_ulong_in("hSession", hSession);
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  spy_dump_mech_type(pMechanism->mechanism);
  /* CLCO 06/07/2010 : Fin  */
  spy_dump_ulong_in("hBaseKey", hBaseKey);
  spy_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
  rv = po->C_DeriveKey(hSession, pMechanism, hBaseKey,
    pTemplate, ulAttributeCount, phKey);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("hKey", *phKey);
  }
  return retne(rv);
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSeed,
  CK_ULONG  ulSeedLen)
{
  CK_RV rv;
  enter("C_SeedRandom");
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pSeed[ulSeedLen]", pSeed, ulSeedLen);
  rv = po->C_SeedRandom(hSession, pSeed, ulSeedLen);
  return retne(rv);
}


CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR RandomData,
  CK_ULONG  ulRandomLen)
{
  CK_RV rv;
  enter("C_GenerateRandom");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_GenerateRandom(hSession, RandomData, ulRandomLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("RandomData[ulRandomLen]",
      RandomData, ulRandomLen);
  }
  return retne(rv);
}


CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  enter("C_GetFunctionStatus");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_GetFunctionStatus(hSession);
  return retne(rv);
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  enter("C_CancelFunction");
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_CancelFunction(hSession);
  return retne(rv);
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
  CK_SLOT_ID_PTR pSlot,
  CK_VOID_PTR pRserved)
{
  CK_RV rv;
  enter("C_WaitForSlotEvent");
  spy_dump_ulong_in("flags", flags);
  rv = po->C_WaitForSlotEvent(flags, pSlot, pRserved);
  return retne(rv);
}

/* AROC 08/04/2013 - Ajout des fonctions pour la gestion de la mise � jour des cartes */

CK_RV C_StartUpdate(CK_SESSION_HANDLE hSession )
{
  CK_ULONG rv;
  enter("C_StartUpdate");
  rv = po->C_StartUpdate(hSession);

  return  retne(rv);
}

CK_RV C_EndUpdate(CK_SESSION_HANDLE hSession )
{
  CK_ULONG rv;
  enter("C_EndUpdate");
	rv = C_Logout(hSession);
  if (rv != CKR_OK) return retne(rv);
  rv = po->C_EndUpdate(hSession);

  return  retne(rv);
}

CK_RV C_KeepAlive(CK_SESSION_HANDLE hSession )
{
  CK_ULONG rv = CKR_OK;
  enter("C_KeppAlive");
#ifdef _WIN32
  rv = po->C_KeepAlive(hSession);
#endif
  return  retne(rv);
}

CK_RV C_TransmitMessage(CK_SESSION_HANDLE hSession, 
                        CK_BYTE_PTR       pbMessage,
                        CK_ULONG          szMessage,
                        CK_BYTE_PTR       pbResponse,
                        CK_ULONG_PTR      pszResponse,
                        CK_CHAR           cInsType)
{
  CK_ULONG rv;
  enter("C_TransmitMessage");
  rv = po->C_TransmitMessage(hSession,pbMessage, szMessage, pbResponse, pszResponse, cInsType);

  return retne(rv);
}
/* AROC 08/04/2013 - Ajout des fonctions pour la gestion de la mise � jour des cartes */

