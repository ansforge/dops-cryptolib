/*
 * pkcs11-global.c: PKCS#11 module level functions and function table
 *
 * Copyright (C) 2002  Timo Teräs <timo.teras@iki.fi>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
 /* CLCO 02/06/2010 : Adaptations ASIP pour personnaliser la librairie */
#include "cps3pkcs11ver.h"
/* CLCO 02/06/2010 : fin */
#include "sc-pkcs11.h"
#include "internal.h"
#ifdef _WIN32
#include "tls_chainlist.h"
#endif

sc_context_t *g_context = NULL;

struct sc_pkcs11_config sc_pkcs11_conf;
/* CLCO 03/08/2010 : gestion du déblocage du WaitForSlotEvent pour Firefox lors de l'arret du programme */
CK_BBOOL unblock_wait_for_slot_event = CK_FALSE;
/* CLCO 03/08/2010 : fin */
#if !defined(_WIN32)
pid_t initialized_pid = (pid_t)-1;
#endif

extern CK_FUNCTION_LIST pkcs11_function_list;
static void *      global_lock = NULL; // BPER 1381 - Solution C: global_lock déclaré ici
#if defined(HAVE_PTHREAD) && defined(PKCS11_THREAD_LOCKING)
#include <pthread.h>

CK_RV mutex_create(void **mutex)
{
  /* CLCO 23/06/2010 : correction sur l'allocation mémoire du mutex */
  pthread_mutex_t *m = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
  /* CLCO 23/06/2010 : fin */
  if (m == NULL)
    return CKR_GENERAL_ERROR;;
  pthread_mutex_init(m, NULL);
  *mutex = m;
  return CKR_OK;
}

CK_RV mutex_lock(void *p)
{
  if (pthread_mutex_lock((pthread_mutex_t *)p) == 0)
    return CKR_OK;
  else
    return CKR_GENERAL_ERROR;
}

CK_RV mutex_unlock(void *p)
{
  if (pthread_mutex_unlock((pthread_mutex_t *)p) == 0)
    return CKR_OK;
  else
    return CKR_GENERAL_ERROR;
}

CK_RV mutex_destroy(void *p)
{
  pthread_mutex_destroy((pthread_mutex_t *)p);
  free(p);
  return CKR_OK;
}

static CK_C_INITIALIZE_ARGS _def_locks = {
  mutex_create, mutex_destroy, mutex_lock, mutex_unlock, 0, NULL };
#elif defined(_WIN32) && defined (PKCS11_THREAD_LOCKING)
CK_RV mutex_create(void **mutex)
{
  CRITICAL_SECTION *m;

  m = (CRITICAL_SECTION *)malloc(sizeof(*m));
  if (m == NULL)
    return CKR_GENERAL_ERROR;
  InitializeCriticalSection(m);
  *mutex = m;
  return CKR_OK;
}

CK_RV mutex_lock(void *p)
{
  EnterCriticalSection((CRITICAL_SECTION *)p);
  return CKR_OK;
}


CK_RV mutex_unlock(void *p)
{
  LeaveCriticalSection((CRITICAL_SECTION *)p);
  return CKR_OK;
}

CK_RV mutex_destroy(void *p)
{
  if (p != global_lock) { // BPER 1381 - Solution C
    DeleteCriticalSection((CRITICAL_SECTION *)p);
    free(p);
  }
  return CKR_OK;
}
static CK_C_INITIALIZE_ARGS _def_locks = {
  mutex_create, mutex_destroy, mutex_lock, mutex_unlock, 0, NULL };
#endif

static CK_C_INITIALIZE_ARGS_PTR  global_locking;

/* AROC - 16/11/2011 - Lock de l'init : Debut */
#if defined(_WIN32)
void *            init_lock = NULL;
#else
pthread_mutex_t   init_lock = PTHREAD_MUTEX_INITIALIZER;
#endif
void sc_pkcs11_lock_init(void);
void sc_pkcs11_unlock_init(void);
/* AROC - 16/11/2011 - Lock de l'init : Fin */
int logP11(const char *format, ...);

#if (defined(HAVE_PTHREAD) || defined(_WIN32)) && defined(PKCS11_THREAD_LOCKING)
#define HAVE_OS_LOCKING
static CK_C_INITIALIZE_ARGS_PTR default_mutex_funcs = &_def_locks;
#else
static CK_C_INITIALIZE_ARGS_PTR default_mutex_funcs = NULL;
#endif

/* wrapper for the locking functions for libopensc */
static int sc_create_mutex(void **m)
{
  if (global_locking == NULL)
    return SC_SUCCESS;
  if (global_locking->CreateMutex(m) == CKR_OK)
    return SC_SUCCESS;
  else
    return SC_ERROR_INTERNAL;
}

static int sc_lock_mutex(void *m)
{
  if (global_locking == NULL)
    return SC_SUCCESS;
  if (global_locking->LockMutex(m) == CKR_OK)
    return SC_SUCCESS;
  else
    return SC_ERROR_INTERNAL;
}

static int sc_unlock_mutex(void *m)
{
  if (global_locking == NULL)
    return SC_SUCCESS;
  if (global_locking->UnlockMutex(m) == CKR_OK)
    return SC_SUCCESS;
  else
    return SC_ERROR_INTERNAL;

}

static int sc_destroy_mutex(void *m)
{
  if (global_locking == NULL)
    return SC_SUCCESS;
  if (global_locking->DestroyMutex(m) == CKR_OK)
    return SC_SUCCESS;
  else
    return SC_ERROR_INTERNAL;
}
static CK_BBOOL g_dataByThread = FALSE; // BPER 1381 - Solution C: Flag global pour le fonctionnement bi-mode

static sc_thread_context_t sc_thread_ctx = {
  0, sc_create_mutex, sc_lock_mutex,
  sc_unlock_mutex, sc_destroy_mutex, NULL
};
#ifdef _WIN32
int tlsSetThreadContext(struct sc_context * pCtx, DWORD dwThreadID)
{
  int set = CKR_DEVICE_ERROR;
  LPVOID _pvContext;

  if (pCtx != NULL) {
    if (tls_addToTlsList(GetCurrentThreadId(), pCtx) == TRUE) {
      set = NO_ERROR;
    }
  }
  else {
    DWORD thrID;
    if (dwThreadID == 0) {
      thrID = GetCurrentThreadId();
    }
    else {
      thrID = dwThreadID;
    }
    _pvContext = tls_getTlsIndexByThreadId(thrID);
    if (_pvContext != TLS_INDEX_NONE) {
      tls_deleteTlsEntryByThreadId(thrID);
    }
  }
  return set;
}

/* BPER 1381 - Solution C: gestion multi-threads - Debut */
void * tlsGetThreadContext(DWORD dwThreadID)
{
  DWORD thrID;
  if (dwThreadID == 0) {
    thrID = GetCurrentThreadId();
  }
  else {
    thrID = dwThreadID;
  }
  LPVOID _pvContext = tls_getTlsIndexByThreadId(thrID);
#ifdef DEBUG
  logP11("tlsGetThreadContext: thrID: %lx, _pvContext: %p", thrID, _pvContext);
#endif
  if (_pvContext == TLS_INDEX_NONE) {
    return NULL;
  }
  
  return _pvContext;
}
#endif

sc_context_t * getCurContext(void)
{
#ifdef _WIN32
  if (g_dataByThread) {
    // le contexte est lu dans la zone thread du thread courant
    return (struct sc_context *)tlsGetThreadContext(0);
  }
#endif
  return g_context;
}

sc_context_t * getCurContext_finalize(ULONG dwThreadID)
{
#ifdef _WIN32
  if (g_dataByThread) {
    // le contexte est lu dans la zone thread du thread spécifié
    return (struct sc_context *)tlsGetThreadContext(dwThreadID);
  }
#endif
  return g_context;
}

void setCurContext(sc_context_t * pctx)
{
#ifdef _WIN32
  if (g_dataByThread) {
    tlsSetThreadContext(pctx, 0);
  }
  else {
    g_context = pctx;
  }
#else
  g_context = pctx;
#endif
}

void setCurContext_finalize(sc_context_t * pctx, ULONG dwThreadID)
{
#ifdef _WIN32
  if (g_dataByThread) {
    tlsSetThreadContext(pctx, dwThreadID);
  }
  else {
    g_context = pctx;
  }
#else
  g_context = pctx;
#endif
}

struct sc_pkcs11_pool * getPoolTable(void)
{
#ifdef _WIN32
  if (g_dataByThread) {
    struct sc_context * ctx = (struct sc_context *)tlsGetThreadContext(0);
    if (ctx != NULL) {
      return ctx->pool_table;
    }
    return NULL;
  }
#endif
  if (g_context != NULL) {
    return g_context->pool_table;
  }
  return NULL;
}

struct sc_pkcs11_pool * getPoolTable_ThrID(unsigned long thrID)
{
#ifdef _WIN32
  if (g_dataByThread) {
    struct sc_context * ctx = (struct sc_context *)tlsGetThreadContext(thrID);
    if (ctx != NULL) {
      return ctx->pool_table;
    }
    return NULL;
  }
#endif
  if (g_context != NULL) {
    return g_context->pool_table;
  }
  return NULL;
}

/* BPER 1381 - Solution C: gestion multi-threads - Fin */
/* CLCO 08/07/2010 : Adaptation ASIP pour la gestion des options d'initialisation : winlogon */
#define WINLOGON_PROCESS "winlogonProcess"
#if defined(__APPLE__)
int g_sandboxed = 0;
#endif
int g_winlogonProcess = FALSE;
int g_connectionReset = FALSE;
#define DATA_BY_THREAD "dataByThread" // BPER 1381 - Solution C: parametre pour C_Initialize
#define CPS_UPDATE "cpsUpdate" // Pour la mise a jour de la carte

CK_BBOOL containsReservedParameter(CK_CHAR_PTR parameterList, CK_CHAR_PTR parameter) {
  CK_CHAR_PTR sc;
  CK_ULONG begin = 0;

  do {
    sc = (CK_CHAR_PTR)strstr((char*)parameterList + begin, ";");
    if (sc != NULL) {
      CK_ULONG end = (CK_ULONG)(sc - (parameterList + begin));
      if (strncmp((char*)parameter, (char*)parameterList + begin, end) == 0)
        return TRUE;
      begin += end + 1;
    }
    else if (strncmp((char*)parameter, (char*)parameterList + begin, strlen((char*)parameter)) == 0)
      return TRUE;
  } while (sc != NULL);
  return FALSE;
}
/* CLCO 08/07/2010 : fin */

#ifdef _WIN32
/* Recupere le nom de client TSE qui se connecte.
  Cette information est passée par le CSP CPS3 */
char * getRemoteMachineParameter(CK_CHAR_PTR parameterList, char * pMachine)
{
  char * pStartMachine = NULL;
  if (parameterList == NULL || pMachine == NULL) {
    return NULL;
  }

  /* rechercher '=' en fin de chaine */
  pStartMachine = strrchr(parameterList, '=');

  if (pStartMachine != NULL) {
    pStartMachine++;
    strcpy(pMachine, pStartMachine);
    return pMachine;
  }
  return NULL;
}
#endif // _WIN32

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_Initialize(CK_VOID_PTR pInitArgs)
/* CLCO 06/07/2010 : Fin  */
{
  unsigned int i;
  CK_BBOOL  cps_udpate_process = CK_FALSE;
  int rc, rv;
  sc_context_param_t ctx_opts;
  struct sc_context * rcontext = NULL;/* BPER 1381 - Solution C: gestion multi-threads */


  /* Handle fork() exception */
#if defined(_WIN32)
  char strRemoteMachine[SC_MAX_MACHINE_LEN] = "";
#else
  pid_t current_pid = getpid();

  if (current_pid != initialized_pid) {
    IC_Finalize(NULL_PTR);
  }
  initialized_pid = current_pid;
#endif



  g_dataByThread = CK_FALSE;
  g_winlogonProcess = FALSE;
  g_connectionReset = FALSE;

  if (pInitArgs && ((CK_C_INITIALIZE_ARGS_PTR)pInitArgs)->pReserved != NULL_PTR) {
#if defined(_WIN32)
	  g_dataByThread = containsReservedParameter((CK_CHAR_PTR)((CK_C_INITIALIZE_ARGS_PTR)pInitArgs)->pReserved, (CK_CHAR_PTR)DATA_BY_THREAD);
	  if (g_dataByThread == CK_TRUE) {
		  // Recupere le nom de la machine on TSE
		  getRemoteMachineParameter(((CK_C_INITIALIZE_ARGS_PTR)pInitArgs)->pReserved, strRemoteMachine);
	  }
#endif // _WIN32
	  g_winlogonProcess = containsReservedParameter((CK_CHAR_PTR)((CK_C_INITIALIZE_ARGS_PTR)pInitArgs)->pReserved, (CK_CHAR_PTR)WINLOGON_PROCESS);
    cps_udpate_process = containsReservedParameter((CK_CHAR_PTR)((CK_C_INITIALIZE_ARGS_PTR)pInitArgs)->pReserved, (CK_CHAR_PTR)CPS_UPDATE);

	  if (cps_udpate_process == CK_TRUE) {
		  g_connectionReset = TRUE;
	  }
  }

  sc_pkcs11_lock_init();

  rcontext = getCurContext();  /* BPER 1381 - gestion multi-threads */

  if (rcontext != NULL) {
#ifdef _WIN32
    if (( g_dataByThread == CK_TRUE ) && (strcmp(rcontext->strRemoteMachine, strRemoteMachine)!= 0) ) {
      sc_error(rcontext, "C_Initialize(): Cryptoki needs to be re-initialized on TSE context\n");
      sc_pkcs11_unlock_init();
      return CKR_ASIP_REINIT_NEEDED;
    }
#endif // _WIN32
    sc_error(rcontext, "C_Initialize(): Cryptoki already initialized\n");
    sc_pkcs11_unlock_init();
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }

  rv = sc_pkcs11_init_lock((CK_C_INITIALIZE_ARGS_PTR)pInitArgs);
  if (rv != CKR_OK) {
    goto out;
  }


  /* set context options */
  memset(&ctx_opts, 0, sizeof(sc_context_param_t));
  ctx_opts.ver = 0;
  ctx_opts.app_name = "opensc-pkcs11";
  ctx_opts.thread_ctx = &sc_thread_ctx;

  rc = sc_context_create(&rcontext, &ctx_opts, cps_udpate_process);
  if (rc != SC_SUCCESS) {
    rv = CKR_DEVICE_ERROR;
    goto out;
  }
  sc_debug(rcontext, "C_Initialize\n");

#ifdef _WIN32
  if (g_dataByThread) {
    strcpy(rcontext->strRemoteMachine, strRemoteMachine);
  }
#endif // _WIN32

  setCurContext(rcontext);

  /* Load configuration */
  load_pkcs11_parameters(&sc_pkcs11_conf, rcontext);

  first_free_slot = 0;

  rcontext->virtual_slots = (struct sc_pkcs11_slot *)calloc(sizeof(struct sc_pkcs11_slot), sc_pkcs11_conf.max_virtual_slots);
  if (rcontext->virtual_slots == NULL) {
    rv = CKR_HOST_MEMORY;
    goto out;
  }

  rcontext->pool_table = (struct sc_pkcs11_pool *)calloc(sizeof(struct sc_pkcs11_pool), 1);
  if (rcontext->virtual_slots == NULL) {
    rv = CKR_HOST_MEMORY;
    goto out;
  }

  rcontext->card_table = (struct sc_pkcs11_card *)calloc(sizeof(struct sc_pkcs11_card), SC_MAX_READERS);
  if (rcontext->virtual_slots == NULL) {
    rv = CKR_HOST_MEMORY;
    goto out;
  }

  pool_initialize(rcontext->pool_table, POOL_TYPE_SESSION);

  for (i = 0; i < sc_pkcs11_conf.max_virtual_slots; i++) {
    slot_initialize(i, &rcontext->virtual_slots[i]);
  }

  for (i = 0; i < SC_MAX_READERS; i++) {
    card_initialize(i, rcontext->virtual_slots, rcontext->card_table);
  }
  /* Detect any card, but do not flag "insert" events */
  __card_detect_all(rcontext, 0);

out:
  if (rcontext != NULL)
    sc_debug(rcontext, "C_Initialize: result = %d\n", rv);

  if (rv != CKR_OK) {
    if (rcontext != NULL) {
      sc_release_context(rcontext);
      rcontext = NULL;
    }
    /* Release and destroy the mutex */
    sc_pkcs11_free_lock();
  }

  /* AROC - 16/11/2011 - Lock de l'init : Debut */
  sc_pkcs11_unlock_init();
  /* AROC - 16/11/2011 - Lock de l'init : Fin */

  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_Finalize(CK_VOID_PTR pReserved)
/* CLCO 06/07/2010 : Fin  */
{
  int i;
  CK_RV rv = CKR_OK;
  unsigned long dwThreadID = 0;
  // asssume we retrieve the current thread sc_context
  CK_BBOOL getCurrentCtx = CK_TRUE;

  struct sc_context *pcontext = getCurContext();

  if (pcontext == NULL) {
    if (pReserved != NULL_PTR) {
      if (g_dataByThread == FALSE) {
          rv = CKR_ARGUMENTS_BAD;
          goto out;
      }
      getCurrentCtx = CK_FALSE;
      dwThreadID = *((PULONG)pReserved);
      pcontext = getCurContext_finalize(dwThreadID);
      if (pcontext == NULL)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    else
    {
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
  }
  else {
    if (pReserved != NULL_PTR) {
      dwThreadID = *((PULONG)pReserved);
#ifdef _DEBUG
      logP11("IC_Finalize: dwThreadID required: 0x%lx, pcontext->thr_id_ctx: 0x%lx", dwThreadID, pcontext->thr_id_ctx);
#endif
      if (dwThreadID != pcontext->thr_id_ctx) {
        getCurrentCtx = CK_FALSE;
        pcontext = getCurContext_finalize(dwThreadID);
        if (pcontext == NULL)
          return CKR_CRYPTOKI_NOT_INITIALIZED;
      }
    }
  }

  if (!g_dataByThread) {
    rv = sc_pkcs11_lock();
    if (rv != CKR_OK)
      return rv;
  }

  sc_debug(pcontext, "Shutting down Cryptoki\n");
  /* CLCO 03/08/2010 : gestion du déblocage du WaitForSlotEvent pour Firefox lors de l'arret du programme */
  unblock_wait_for_slot_event = CK_TRUE;
  /* CLCO 03/08/2010 : fin */
  for (i = 0; i < (int)sc_ctx_get_reader_count(pcontext); i++)
    card_removed(i, dwThreadID);

  sc_release_context(pcontext);
  pcontext = NULL;
  if (getCurrentCtx == CK_FALSE) {
    setCurContext_finalize(pcontext, *((PULONG)pReserved));
  }
  else {
    setCurContext(pcontext);
  }

out:  /* Release and destroy the mutex */
  sc_pkcs11_free_lock();

  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_GetInfo(CK_INFO_PTR pInfo)
/* CLCO 06/07/2010 : Fin  */
{
  CK_RV rv = CKR_OK;
  struct sc_context *pcontext; //BPER 1381 - Solution C
  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  if (pInfo == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }
  pcontext = getCurContext();
  sc_debug(pcontext, "Cryptoki info query\n");

  memset(pInfo, 0, sizeof(CK_INFO));
  pInfo->cryptokiVersion.major = 2;
  pInfo->cryptokiVersion.minor = 20;
  /* CLCO 02/06/2010 : Adaptations ASIP pour personnaliser la librairie */
  strcpy_bp(pInfo->manufacturerID,
    CPS_PKCS_COMPANY_NAME,
    sizeof(pInfo->manufacturerID));
  strcpy_bp(pInfo->libraryDescription,
    GETINFO_PKCS_STR_PRODUCT,
    sizeof(pInfo->libraryDescription));
  pInfo->libraryVersion.major = BINARY_VERSION_MAJOR;
  pInfo->libraryVersion.minor = BINARY_VERSION_MINOR; /* FIXME: use 0.116 for 0.11.6 from autoconf */
  /* CLCO 02/06/2010 : Fin */

out:  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
/* CLCO 06/07/2010 : Fin  */
{
  if (ppFunctionList == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  *ppFunctionList = &pkcs11_function_list;
  return CKR_OK;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_GetSlotList(CK_BBOOL       tokenPresent,  /* only slots with token present */
/* CLCO 06/07/2010 : Fin  */
CK_SLOT_ID_PTR pSlotList,     /* receives the array of slot IDs */
CK_ULONG_PTR   pulCount)      /* receives the number of slots */
{
  CK_SLOT_ID_PTR found = NULL;
  unsigned int i;
  CK_ULONG numMatches;
  sc_pkcs11_slot_t *slot;
  CK_RV rv;
  struct sc_context *pcontext; //BPER 1381 - Solution C

  if ((rv = sc_pkcs11_lock()) != CKR_OK) {
    return rv;
  }

  if (pulCount == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }

  pcontext = getCurContext(); //BPER 1381 - Solution C

  if (
    (found = (CK_SLOT_ID_PTR)malloc(
      sizeof(*found) * sc_pkcs11_conf.max_virtual_slots
      )) == NULL
    ) {
    rv = CKR_HOST_MEMORY;
    goto out;
  }

  sc_debug(pcontext, "Getting slot listing, context handle: %p\n", pcontext);
  /* Slot list can only change in v2.20 */
  /* CLCO 22/06/2010 : ne pas conditionner la détection des lecteurs au passage du paramètre pSlotList==NULL */
  if (sc_pkcs11_conf.plug_and_play) {
    /* CLCO 22/06/2010 : fin */
    sc_ctx_detect_readers(pcontext);
  }
  card_detect_all();

  numMatches = 0;
  for (i = 0; i < sc_pkcs11_conf.max_virtual_slots; i++) {
    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    sc_reader_t *reader;
    /* CLCO 04/06/2010 : fin */
    struct sc_pkcs11_slot * pvirtual_slots = NULL;
    /* BPER 1381 - Solution C gestion multi-threads - Debut */
    if (pcontext != NULL){
      pvirtual_slots = pcontext->virtual_slots;
    }
    if (pvirtual_slots == NULL){
      continue;
    }
    /* BPER 1381 - Solution C gestion multi-threads - Fin */
    slot = &pvirtual_slots[i]; // BPER 1381 - Solution C

    /* CLCO 11/05/2010 : Ignorer les slots virtuels */
    if (strncmp((char*)slot->slot_info.slotDescription, "Virtual slot", 12) == 0)
      continue;
    /* CLCO 11/05/2010 : fin */

    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    reader = sc_ctx_get_reader(pcontext, i);
    if (reader && !reader->detected)
      continue; /* retirer de la liste les lecteurs déconnectés */
    /* CLCO 04/06/2010 : fin */

    if (!tokenPresent || (slot->slot_info.flags & CKF_TOKEN_PRESENT))
      found[numMatches++] = i;
  }

  if (pSlotList == NULL_PTR) {
    sc_debug(pcontext, "was only a size inquiry (%d)\n", numMatches);
    *pulCount = numMatches;
    rv = CKR_OK;
    goto out;
  }

  if (*pulCount < numMatches) {
    sc_debug(pcontext, "buffer was too small (needed %d)\n", numMatches);
    *pulCount = numMatches;
    rv = CKR_BUFFER_TOO_SMALL;
    goto out;
  }

  memcpy(pSlotList, found, numMatches * sizeof(CK_SLOT_ID));
  *pulCount = numMatches;
  rv = CKR_OK;

  sc_debug(pcontext, "returned %d slots\n", numMatches);

out:
  if (found != NULL) {
    free(found);
    found = NULL;
  }
  sc_pkcs11_unlock();
  return rv;
}

static sc_timestamp_t get_current_time(void)
{
#if HAVE_GETTIMEOFDAY
  struct timeval tv;
  struct timezone tz;
  sc_timestamp_t curr;

  if (gettimeofday(&tv, &tz) != 0)
    return 0;

  curr = tv.tv_sec;
  curr *= 1000;
  curr += tv.tv_usec / 1000;
#else
  struct _timeb time_buf;
  sc_timestamp_t curr;

  _ftime(&time_buf);

  curr = time_buf.time;
  curr *= 1000;
  curr += time_buf.millitm;
#endif

  return curr;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
/* CLCO 06/07/2010 : Fin  */
{
  struct sc_pkcs11_slot *slot;
  sc_timestamp_t now;
  CK_RV rv;
  struct sc_context *pContext = NULL;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK) {
    return rv;
  }

  pContext = getCurContext(); //BPER 1381 - Solution C
  if (pInfo == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }

  sc_debug(pContext, "Getting info about slot %d, context handle: %p\n", slotID, pContext);

  /* CLCO 23/06/2010 : détection des lecteurs */
  if (sc_pkcs11_conf.plug_and_play) {
    /* AROC (@@20130212-1027) - Ajout de la fonction de mis à jour de l'état pour un lecteur donné */
    sc_ctx_update_reader_state(pContext, slotID);
  }

  rv = slot_get_slot(slotID, &slot, pContext);
  if (rv == CKR_OK) {
    /* CLCO 22/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    sc_reader_t *reader = sc_ctx_get_reader(pContext, slot->reader);
    if (reader && !reader->detected) {
      rv = CKR_SLOT_ID_INVALID; /* le lecteur demandé est déconnecté */
      card_detect(slot->reader, pContext); // pour faire le ménage sur l'objet carte
      goto out;
    }
    /* CLCO 22/06/2010 : fin */
    now = get_current_time();
    if (now >= pContext->card_table[slot->reader].slot_state_expires || now == 0) {
      /* Update slot status */
      rv = card_detect(slot->reader, pContext);
      /* Don't ask again within the next second */
      pContext->card_table[slot->reader].slot_state_expires = now + 1000;
    }
  }
  if (rv == CKR_TOKEN_NOT_PRESENT || rv == CKR_TOKEN_NOT_RECOGNIZED)
    rv = CKR_OK;

  if (rv == CKR_OK)
    memcpy(pInfo, &slot->slot_info, sizeof(CK_SLOT_INFO));

out:  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
/* CLCO 06/07/2010 : Fin  */
{
  struct sc_pkcs11_slot *slot;
  CK_RV rv;
  struct sc_context *context;
  
  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;
  context = getCurContext();
  if (pInfo == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }

  sc_debug(context, "Getting info about token in slot %d, context handle: %p\n", slotID, context);

  rv = slot_get_token(slotID, &slot, TRUE);
  /* CLCO 15/06/2010 : Gestion de l'état du code PIN et PUK */
  if (rv == CKR_OK) {
    int rc;
    struct pkcs15_slot_data *fw_data = (struct pkcs15_slot_data *) slot->fw_data;
    struct pkcs15_fw_data *fw_data2 = (struct pkcs15_fw_data *) slot->card->fw_data;
    struct sc_pkcs15_card *card = fw_data2->p15_card;
    struct sc_pkcs15_object *auth_object;

    if (fw_data->auth_obj != NULL) {

      /* MCUG 28/09/2010 : Ajout de la mise à jour du pin counter au niveau du getTokenInfo */
      struct sc_pkcs15_pin_info *pin_info = (struct sc_pkcs15_pin_info*) fw_data->auth_obj->data;
      rv = rc = sc_pkcs15_get_pin_counter(card, pin_info);
      if (rc != SC_NO_ERROR) {
        sc_debug(context, "sc_pkcs15_get_pin_counter(1) return %d\n", rc);
        /* AROC - 07/03/2016 - C_GetTokenInfo renvoit les informations de la carte précédente lors d'un appel à la librairie PKCS#11 via RDP 8. (@@20160307-1359) : Debut */
        rv = sc_to_cryptoki_error(rc, slot->reader);
        /* AROC - 07/03/2016 - C_GetTokenInfo renvoit les informations de la carte précédente lors d'un appel à la librairie PKCS#11 via RDP 8. (@@20160307-1359) :  Fin */
        goto out;
      }
      /* MCUG 28/09/2010 : Fin */


      if (pin_info->tries_left >= 0) {
        slot->token_info.flags &= ~(CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED | CKF_USER_PIN_COUNT_LOW);
        if (pin_info->tries_left == 1)
          slot->token_info.flags |= CKF_USER_PIN_FINAL_TRY;
        else if (pin_info->tries_left == 0)
          slot->token_info.flags |= CKF_USER_PIN_LOCKED;
        if (pin_info->tries_max && pin_info->tries_left && pin_info->tries_left < pin_info->tries_max && pin_info->tries_left != 0)
          slot->token_info.flags |= CKF_USER_PIN_COUNT_LOW;
      }
    }

    rc = sc_pkcs15_find_so_pin(card, &auth_object);
    if (rc != SC_ERROR_OBJECT_NOT_FOUND && auth_object != NULL) {

      /* MCUG 28/09/2010 : Ajout de la mise à jour du pin counter au niveau du getTokenInfo */
      struct sc_pkcs15_pin_info *pin_info = (struct sc_pkcs15_pin_info*) auth_object->data;
      rv = rc = sc_pkcs15_get_pin_counter(card, pin_info);
      if (rc != SC_NO_ERROR) {
        sc_debug(context, "sc_pkcs15_get_pin_counter(2) return %d\n", rc);
        /* AROC - 07/03/2016 - Retranscrir l'erreur OpenSC en PKCS#11 (@@20160307-1359) : Debut */
        rv = sc_to_cryptoki_error(rc, slot->reader);
        /* AROC - 07/03/2016 - Retranscrir l'erreur OpenSC en PKCS#11 (@@20160307-1359) : Fin */
        goto out;
      }
      /* MCUG 28/09/2010 : Fin */


      if (pin_info->tries_left >= 0) {
        slot->token_info.flags &= ~(CKF_SO_PIN_FINAL_TRY | CKF_SO_PIN_LOCKED | CKF_SO_PIN_COUNT_LOW);
        if (pin_info->tries_left == 1)
          slot->token_info.flags |= CKF_SO_PIN_FINAL_TRY;
        else if (pin_info->tries_left == 0)
          slot->token_info.flags |= CKF_SO_PIN_LOCKED;
        if (pin_info->tries_max && pin_info->tries_left && pin_info->tries_left < pin_info->tries_max && pin_info->tries_left != 0)
          slot->token_info.flags |= CKF_SO_PIN_COUNT_LOW;
      }
    }
    memcpy(pInfo, &slot->token_info, sizeof(CK_TOKEN_INFO));
  }
  /* CLCO 15/06/2010 : fin */

out:  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_GetMechanismList(CK_SLOT_ID slotID,
  /* CLCO 06/07/2010 : Fin  */
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR pulCount)
{
  struct sc_pkcs11_slot *slot;
  CK_RV rv;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;
  /* AROC - 15/11/2011 - Correction Annomalie 8039 - Debut */
  if (pulCount == NULL_PTR)
  {
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }
  /* AROC - 15/11/2011 - Correction Annomalie 8039 - Fin */

  rv = slot_get_token(slotID, &slot, FALSE);
  if (rv == CKR_OK)
    rv = sc_pkcs11_get_mechanism_list(slot->card, pMechanismList, pulCount);

out:
  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_GetMechanismInfo(CK_SLOT_ID slotID,
  /* CLCO 06/07/2010 : Fin  */
  CK_MECHANISM_TYPE type,
  CK_MECHANISM_INFO_PTR pInfo)
{
  struct sc_pkcs11_slot *slot;
  CK_RV rv;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  if (pInfo == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }
  rv = slot_get_token(slotID, &slot, FALSE);
  if (rv == CKR_OK)
    rv = sc_pkcs11_get_mechanism_info(slot->card, type, pInfo);

out:  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_InitToken(CK_SLOT_ID slotID,
  /* CLCO 06/07/2010 : Fin  */
  CK_CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_CHAR_PTR pLabel)
{
  struct sc_pkcs11_pool_item *item;
  struct sc_pkcs11_session *session;
  struct sc_pkcs11_slot *slot;
  struct sc_context * pContext;
  CK_RV rv;

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  rv = slot_get_token(slotID, &slot, TRUE);
  if (rv != CKR_OK)
    goto out;
  pContext = slot->card->card->ctx;
  /* Make sure there's no open session for this token */
  for (item = pContext->pool_table->head; item; item = item->next) {
    session = (struct sc_pkcs11_session*) item->item;
    if (session->slot == slot) {
      rv = CKR_SESSION_EXISTS;
      goto out;
    }
  }

  if (slot->card->framework->init_token == NULL) {
    rv = CKR_FUNCTION_NOT_SUPPORTED;
    goto out;
  }
  rv = slot->card->framework->init_token(slot->card,
    slot->fw_data, pPin, ulPinLen, pLabel);

  if (rv == CKR_OK) {
    /* Now we should re-bind all tokens so they get the
     * corresponding function vector and flags */
  }

out:  sc_pkcs11_unlock();
  return rv;
}

/* CLCO 06/07/2010 : Adaptation ASIP des traces */
CK_RV IC_WaitForSlotEvent(CK_FLAGS flags,   /* blocking/nonblocking flag */
/* CLCO 06/07/2010 : Fin  */
CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
CK_VOID_PTR pReserved) /* reserved.  Should be NULL_PTR */
{
  sc_reader_t *reader, *readers[SC_MAX_SLOTS * SC_MAX_READERS];
  int slots[SC_MAX_SLOTS * SC_MAX_READERS];
  int i, j, k;
  unsigned int mask;
  CK_RV rv;
  struct sc_context *context = getCurContext();
  
  if (context == NULL) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  /* Firefox 1.5 (NSS 3.10) calls this function (blocking) from a seperate thread,
   * which gives 2 problems:
   * - on Windows/Mac: this waiting thread will log to a NULL context
   *   after the 'main' thread does a C_Finalize() and sets the ctx to NULL.
   * - on Linux, things just hang (at least on Debian 'sid')
   * So we just return CKR_FUNCTION_NOT_SUPPORTED on a blocking call,
   * in which case FF just seems to default to polling in the main thread
   * as earlier NSS versions.
   */
   /* CLCO 04/06/2010 : gestion du waitForSlotEvent en mode bloquant */
  if (!(flags & CKF_DONT_BLOCK))
    return CKR_FUNCTION_NOT_SUPPORTED;
  /* CLCO 04/06/2010 : fin */

  rv = sc_pkcs11_lock();
  if (rv != CKR_OK)
    return rv;

  if (pReserved != NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }

  mask = SC_EVENT_CARD_INSERTED | SC_EVENT_CARD_REMOVED;

  if ((rv = slot_find_changed(pSlot, mask)) == CKR_OK
    || (flags & CKF_DONT_BLOCK))
    goto out;

  for (i = k = 0; i < (int)sc_ctx_get_reader_count(context); i++) {
    reader = sc_ctx_get_reader(context, i);
    if (reader == NULL) {
      rv = CKR_GENERAL_ERROR;
      goto out;
    }
    for (j = 0; j < reader->slot_count; j++, k++) {
      readers[k] = reader;
      slots[k] = j;
    }
  }

  /* CLCO 04/06/2010 : gestion du waitForSlotEvent en mode bloquant */
  sc_pkcs11_unlock();

again:
  /* Check if C_Finalize() has been called in another thread */
  /* CLCO 03/08/2010 : gestion du déblocage du WaitForSlotEvent pour Firefox lors de l'arret du programme */
  if (context == NULL || unblock_wait_for_slot_event) {
    unblock_wait_for_slot_event = CK_FALSE;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  /* CLCO 03/08/2010 : fin */

  if ((rv = sc_pkcs11_lock()) != CKR_OK)
    return rv;

  /* Check if C_Finalize() has been called in another thread */
  /* CLCO 03/08/2010 : gestion du déblocage du WaitForSlotEvent pour Firefox lors de l'arret du programme */
  if (context == NULL || unblock_wait_for_slot_event) {
    unblock_wait_for_slot_event = CK_FALSE;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  /* CLCO 03/08/2010 : fin */

  /* If no changed slot was found (maybe an unsupported card
   * was inserted/removed) then go waiting again */
  if ((rv = slot_find_changed(pSlot, mask)) != CKR_OK) {
    sc_pkcs11_unlock();
    /* Check if C_Finalize() has been called in another thread */
    /* CLCO 03/08/2010 : gestion du déblocage du WaitForSlotEvent pour Firefox lors de l'arret du programme */
    if (context == NULL || unblock_wait_for_slot_event) {
      unblock_wait_for_slot_event = CK_FALSE;
      return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    /* CLCO 03/08/2010 : fin */
    /* comme on va reboucler, il faut attendre un peu pour rendre la main aux autres threads */
    msleep(1000);
    goto again;
  }
  /* CLCO 04/06/2010 : fin */

out:  sc_pkcs11_unlock();
  return rv;
}

/*
 * Locking functions
 */

CK_RV
sc_pkcs11_init_lock(CK_C_INITIALIZE_ARGS_PTR args)
{
  int rv = CKR_OK;

  int applock = 0;
  int oslock = 0;
  if (global_lock)
    return CKR_OK;

  /* No CK_C_INITIALIZE_ARGS pointer, no locking */
  if (!args)
    return CKR_OK;

  /* AROC (@@201212014-opti) - vérifier qu'il ne manque pas des pointeurs - Debut */
  if (!(args->CreateMutex && args->DestroyMutex && args->LockMutex && args->UnlockMutex) &&
    !(!args->CreateMutex && !args->DestroyMutex && !args->LockMutex && !args->UnlockMutex)) {
    return CKR_ARGUMENTS_BAD;
  }
  /* AROC (@@201212014-opti) - vérifier qu'il ne manque pas des pointeurs - Fin */

  
  /* If the app tells us OS locking is okay,
   * use that. Otherwise use the supplied functions.
   */
  global_locking = NULL;
  if (args->CreateMutex && args->DestroyMutex &&
    args->LockMutex   && args->UnlockMutex) {
    applock = 1;
  }
  if ((args->flags & CKF_OS_LOCKING_OK)) {
    oslock = 1;
  }

  /* Based on PKCS#11 v2.11 11.4 */
  if (applock && oslock) {
    /* Shall be used in threaded environment, prefer app provided locking */
    global_locking = args;
  }
  else if (!applock && oslock) {
    /* Shall be used in threaded environment, must use operating system locking */
    global_locking = default_mutex_funcs;
  }
  else if (applock && !oslock) {
    /* Shall be used in threaded envirnoment, must use app provided locking */
    global_locking = args;
  }
  else if (!applock && !oslock) {
    /* Shall not be used in threaded environment, use operating system locking */
    global_locking = default_mutex_funcs;
  }

  if (global_locking != NULL) {
    /* create mutex */
    rv = global_locking->CreateMutex(&global_lock);
  }

  return rv;
}

static unsigned long cntApiLock = 0UL; // BPER 1381 - Solution C
CK_RV sc_pkcs11_lock(void)
{
  struct sc_context *pcontext = getCurContext();
  if (pcontext == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (!global_lock)
    return CKR_OK;
  if (global_locking) {
    while (global_locking->LockMutex(global_lock) != CKR_OK)
      ;
    cntApiLock++;
  }

  return CKR_OK;
}
/* AROC - 16/11/2011 - Lock de l'init : Debut */
void sc_pkcs11_lock_init(void)
{
#ifdef WIN32
  if (!init_lock) return;
  mutex_lock(init_lock);
#else
  mutex_lock((void *)&init_lock);
#endif
}

void sc_pkcs11_unlock_init(void)
{
#ifdef WIN32
  if (!init_lock) return;
  mutex_unlock((void *)init_lock);
#else
  mutex_unlock((void *)&init_lock);
#endif
}
/* AROC - 16/11/2011 - Lock de l'init : Fin */
static void
__sc_pkcs11_unlock(void *lock)
{
  if (!lock)
    return;
  if (global_locking) {
    cntApiLock--;
    while (global_locking->UnlockMutex(lock) != CKR_OK)
      ;
  }
}

void sc_pkcs11_unlock(void)
{
  __sc_pkcs11_unlock(global_lock);
}

/*
 * Free the lock - note the lock must be held when
 * you come here
 */
void sc_pkcs11_free_lock(void)
{
  void  *tempLock;

  if (!(tempLock = global_lock))
    return;

  /* Clear the global lock pointer - once we've
   * unlocked the mutex it's as good as gone */
  if (!g_dataByThread)
    global_lock = NULL;

  /* Now unlock. On SMP machines the synchronization
   * primitives should take care of flushing out
   * all changed data to RAM */
  if (!g_dataByThread)
    __sc_pkcs11_unlock(tempLock);

  if (global_locking) {
    if (cntApiLock == 0) {
      global_locking->DestroyMutex(tempLock);
    }
  }
  if (!g_dataByThread)
    global_locking = NULL;
}

CK_FUNCTION_LIST pkcs11_function_list = {
  { 2, 11 }, /* Note: NSS/Firefox ignores this version number and uses C_GetInfo() */
  /* CLCO 06/07/2010 : Adaptation ASIP des traces */
  IC_Initialize,
  IC_Finalize,
  IC_GetInfo,
  IC_GetFunctionList,
  IC_GetSlotList,
  IC_GetSlotInfo,
  IC_GetTokenInfo,
  IC_GetMechanismList,
  IC_GetMechanismInfo,
  IC_InitToken,
  IC_InitPIN,
  IC_SetPIN,
  IC_OpenSession,
  IC_CloseSession,
  IC_CloseAllSessions,
  IC_GetSessionInfo,
  IC_GetOperationState,
  IC_SetOperationState,
  IC_Login,
  IC_Logout,
  IC_CreateObject,
  IC_CopyObject,
  IC_DestroyObject,
  IC_GetObjectSize,
  IC_GetAttributeValue,
  IC_SetAttributeValue,
  IC_FindObjectsInit,
  IC_FindObjects,
  IC_FindObjectsFinal,
  IC_EncryptInit,
  IC_Encrypt,
  IC_EncryptUpdate,
  IC_EncryptFinal,
  IC_DecryptInit,
  IC_Decrypt,
  IC_DecryptUpdate,
  IC_DecryptFinal,
  IC_DigestInit,
  IC_Digest,
  IC_DigestUpdate,
  IC_DigestKey,
  IC_DigestFinal,
  IC_SignInit,
  IC_Sign,
  IC_SignUpdate,
  IC_SignFinal,
  IC_SignRecoverInit,
  IC_SignRecover,
  IC_VerifyInit,
  IC_Verify,
  IC_VerifyUpdate,
  IC_VerifyFinal,
  IC_VerifyRecoverInit,
  IC_VerifyRecover,
  IC_DigestEncryptUpdate,
  IC_DecryptDigestUpdate,
  IC_SignEncryptUpdate,
  IC_DecryptVerifyUpdate,
  IC_GenerateKey,
  IC_GenerateKeyPair,
  IC_WrapKey,
  IC_UnwrapKey,
  IC_DeriveKey,
  IC_SeedRandom,
  IC_GenerateRandom,
  IC_GetFunctionStatus,
  IC_CancelFunction,
  IC_WaitForSlotEvent,
  /* Ajout des fonctions pour la gestion de la mise Ã  jour des cartes */
  IC_StartUpdate,
  IC_EndUpdate,
  IC_TransmitMessage,
  IC_KeepAlive
  /* Ajout des fonctions pour la gestion de la mise Ã  jour des cartes */
  /* CLCO 06/07/2010 : Fin  */
};
