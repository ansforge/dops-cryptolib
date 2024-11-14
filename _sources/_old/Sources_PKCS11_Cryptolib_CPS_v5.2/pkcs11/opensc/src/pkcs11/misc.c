/*
 * misc.c: Miscellaneous PKCS#11 library helper functions
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

#include <stdlib.h>
#include <string.h>
#include "sc-pkcs11.h"

#ifndef _WIN32
#include "sysdef.h"
#endif // _WIN32

#define DUMP_TEMPLATE_MAX  32


void strcpy_bp(u8 *dst, const char *src, size_t dstsize)
{
  size_t c;

  if (!dst || !src || !dstsize)
    return;

  memset((char *)dst, ' ', dstsize);

  c = strlen(src) > dstsize ? dstsize : strlen(src);

  memcpy((char *)dst, src, c);
}

CK_RV sc_to_cryptoki_error(int rc, int reader)
{
  sc_context_t *pcontext = getCurContext(); // BPER 1381 - Solution C
  switch (rc) {
  case SC_SUCCESS:
  case SC_ERROR_CARD_UNRESPONSIVE:
    return CKR_OK;
  case SC_ERROR_NOT_SUPPORTED:
    return CKR_FUNCTION_NOT_SUPPORTED;
  case SC_ERROR_OUT_OF_MEMORY:
    return CKR_HOST_MEMORY;
  case SC_ERROR_PIN_CODE_INCORRECT:
    return CKR_PIN_INCORRECT;
  case SC_ERROR_AUTH_METHOD_BLOCKED:
    return CKR_PIN_LOCKED;
  case SC_ERROR_BUFFER_TOO_SMALL:
    return CKR_BUFFER_TOO_SMALL;
  case SC_ERROR_CARD_NOT_PRESENT:
    card_removed(reader, 0);
    return CKR_TOKEN_NOT_PRESENT;
  case SC_ERROR_INVALID_CARD:
    return CKR_TOKEN_NOT_RECOGNIZED;
  case SC_ERROR_WRONG_LENGTH:
    return CKR_DATA_LEN_RANGE;
  case SC_ERROR_INVALID_PIN_LENGTH:
    return CKR_PIN_LEN_RANGE;
  case SC_ERROR_KEYPAD_CANCELLED:
  case SC_ERROR_KEYPAD_TIMEOUT:
    return CKR_FUNCTION_CANCELED;
  case SC_ERROR_CARD_RESET:
  case SC_ERROR_CARD_REMOVED:
    card_removed(reader, 0);
    return CKR_TOKEN_NOT_PRESENT;/* AROC - 07/03/2016 - Retranscrir l'erreur OpenSC en PKCS#11 (@@20160307-1359) : Debut */
  case SC_ERROR_SECURITY_STATUS_NOT_SATISFIED:
    return CKR_USER_NOT_LOGGED_IN;
  case SC_ERROR_KEYPAD_PIN_MISMATCH:
    return CKR_PIN_INVALID;
  case SC_ERROR_INVALID_ARGUMENTS:
    return CKR_ARGUMENTS_BAD;
  case SC_ERROR_INVALID_DATA:
  case SC_ERROR_INCORRECT_PARAMETERS:
    return CKR_DATA_INVALID;
  case SC_ERROR_NOT_ALLOWED:
    return CKR_KEY_TYPE_INCONSISTENT;
  }
  sc_debug(pcontext, "opensc error: %s (%d)\n", sc_strerror(rc), rc);
  return CKR_GENERAL_ERROR;
}

/* Pool */
CK_RV pool_initialize(struct sc_pkcs11_pool *pool, int type)
{
  pool->type = type;
  pool->next_free_handle = 1;
  pool->num_items = 0;
  pool->head = pool->tail = NULL;

  return CKR_OK;
}

CK_RV pool_insert(struct sc_pkcs11_pool *pool, void *item_ptr, CK_ULONG_PTR pHandle)
{
  struct sc_pkcs11_pool_item *item;
  int handle = pool->next_free_handle++;

  item = (struct sc_pkcs11_pool_item*) malloc(sizeof(struct sc_pkcs11_pool_item));

  if (pHandle != NULL)
    *pHandle = handle;

  item->handle = handle;
  item->item = item_ptr;
  item->next = NULL;
  item->prev = pool->tail;

  if (pool->head != NULL && pool->tail != NULL) {
    pool->tail->next = item;
    pool->tail = item;
  }
  else
    pool->head = pool->tail = item;

  return CKR_OK;
}

CK_RV pool_find(struct sc_pkcs11_pool *pool, CK_ULONG handle, void **item_ptr)
{
  struct sc_pkcs11_pool_item *item;
  if (pool == NULL) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  for (item = pool->head; item != NULL; item = item->next) {
    if (item->handle == handle) {
      *item_ptr = item->item;
      return CKR_OK;
    }
  }

  return (pool->type == POOL_TYPE_OBJECT) ? CKR_OBJECT_HANDLE_INVALID
    : CKR_SESSION_HANDLE_INVALID;
}

// BPER 1381 - Solution C: paramètre contexte supplémentaire
CK_RV pool_find_and_delete(struct sc_pkcs11_pool *pool, CK_ULONG handle, void **item_ptr, struct sc_context * pcontext)
{
  struct sc_pkcs11_pool_item *item;
  //struct sc_context *pcontext = getCurContext(); // BPER 1381 - Solution C

  if (pcontext == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  for (item = pool->head; item != NULL; item = item->next) {
    if (handle == 0 || item->handle == handle) {
      if (item->prev) item->prev->next = item->next;
      if (item->next) item->next->prev = item->prev;
      if (pool->head == item) pool->head = item->next;
      if (pool->tail == item) pool->tail = item->prev;

      *item_ptr = item->item;
      free(item);

      return CKR_OK;
    }
  }

  return (pool->type == POOL_TYPE_OBJECT) ? CKR_OBJECT_HANDLE_INVALID
    : CKR_SESSION_HANDLE_INVALID;
}

/* Session manipulation */
CK_RV session_start_operation(struct sc_pkcs11_session *session,
  int type,
  sc_pkcs11_mechanism_type_t *mech,
struct sc_pkcs11_operation **operation)
{
  sc_pkcs11_operation_t *op;
  struct sc_context *pcontext = session->slot->card->card->ctx; // BPER 1381 - Solution C

  if (pcontext == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (type < 0 || type >= SC_PKCS11_OPERATION_MAX)
    return CKR_ARGUMENTS_BAD;

  if (session->operation[type] != NULL)
    return CKR_OPERATION_ACTIVE;

  if (!(op = sc_pkcs11_new_operation(session, mech)))
    return CKR_HOST_MEMORY;

  session->operation[type] = op;
  if (operation)
    *operation = op;

  return CKR_OK;
}

CK_RV session_get_operation(struct sc_pkcs11_session *session, int type,
  sc_pkcs11_operation_t **operation)
{
  sc_pkcs11_operation_t *op;

  if (type < 0 || type >= SC_PKCS11_OPERATION_MAX)
    return CKR_ARGUMENTS_BAD;

  if (!(op = session->operation[type]))
    return CKR_OPERATION_NOT_INITIALIZED;

  if (operation)
    *operation = op;

  return CKR_OK;
}

CK_RV session_stop_operation(struct sc_pkcs11_session *session, int type)
{
  if (type < 0 || type >= SC_PKCS11_OPERATION_MAX)
    return CKR_ARGUMENTS_BAD;

  if (session->operation[type] == NULL)
    return CKR_OPERATION_NOT_INITIALIZED;

  sc_pkcs11_release_operation(&session->operation[type]);
  return CKR_OK;
}

/* CLCO 26/05/2010 : Ajout d'une fonction permettant de tester la validité de la session */
CK_RV is_session_valid(struct sc_pkcs11_session *session)
{
  struct sc_context *pcontext = session->slot->card->card->ctx; // BPER 1381 - Solution C
  int reader = session->slot->reader;
  int rc;
  /* On SmartCard Logon bypass card detection */
  if (g_winlogonProcess == TRUE) {
    return CKR_OK;
  }

  rc = sc_detect_card_presence(sc_ctx_get_reader(pcontext, reader), 0);
  if (rc < 0) {
    sc_debug(pcontext, "Card detection failed for reader %d: %s\n",
      reader, sc_strerror(rc));
    /* BPER (@@080416-1055) - detection du reboot d'un TLA et invalidation de la session Cryptoki */
    if (rc == SC_ERROR_CARD_UNRESPONSIVE) {
      return CKR_SESSION_HANDLE_INVALID;
    }
    /* BPER (@@080416-1055) - Fin */
    return CKR_DEVICE_ERROR;
  }
  if (rc == 0) {
    sc_debug(pcontext, "%d: Card absent\n", reader);
    card_removed(reader, 0); // Release all resources 
    return CKR_SESSION_HANDLE_INVALID;
  }

  // If the card was changed, disconnect the current one 
  if (rc & SC_SLOT_CARD_CHANGED) {
    sc_debug(pcontext, "%d: Card changed\n", reader);
    /* The following should never happen - but if it
     * does we'll be stuck in an endless loop.
     * So better be fussy. */
    card_removed(reader, 0);
    return CKR_SESSION_HANDLE_INVALID;
  }

  /* JTAU 16/11/2010 : Vérification de l'état de la carte*/
  if (session->slot->card->card->ops->is_valid != NULL) {
    int r = (session->slot->card->card->ops->is_valid)(session->slot->card->card);
    if (r != SC_NO_ERROR)
      return CKR_ASIP_BAD_EF_ACTUA;
  }
  /* JTAU 16/11/2010 : fin*/

  return CKR_OK;
}
/* CLCO 26/05/2010 : fin */

void load_pkcs11_parameters(struct sc_pkcs11_config *conf, sc_context_t *ctx)
{
  scconf_block *conf_block = NULL;

  /* Set defaults */
  conf->plug_and_play = 1;
  conf->max_virtual_slots = 16;
  conf->slots_per_card = 4;
  conf->hide_empty_tokens = 1;
  conf->lock_login = 1;
  /* AROC - (@@20120801-bug) - Ne pas mettre le pin en cache */
  conf->cache_pins = 1;
  /* AROC - (@@20120801-bug) */

  conf->soft_keygen_allowed = 0;


  conf_block = sc_get_conf_block(ctx, "pkcs11", NULL, 1);
  if (!conf_block)
    return;

  /* contains the defaults, if there is a "pkcs11" config block */
  conf->plug_and_play = scconf_get_bool(conf_block, "plug_and_play", conf->plug_and_play);
  conf->max_virtual_slots = scconf_get_int(conf_block, "max_virtual_slots", conf->max_virtual_slots);
  /*XXX: rename the option in 0.12+ */
  conf->slots_per_card = scconf_get_int(conf_block, "num_slots", conf->slots_per_card);
  conf->slots_per_card = scconf_get_int(conf_block, "slots_per_card", conf->slots_per_card);
  conf->hide_empty_tokens = scconf_get_bool(conf_block, "hide_empty_tokens", conf->hide_empty_tokens);
  conf->lock_login = scconf_get_bool(conf_block, "lock_login", conf->lock_login);
  /* AROC - (@@20120801-bug) - Ne pas prendre en compte la conf du pin en cache */
  conf->cache_pins = scconf_get_bool(conf_block, "cache_pins", conf->cache_pins);
  /* AROC - (@@20120801-bug) */
  conf->soft_keygen_allowed = scconf_get_bool(conf_block, "soft_keygen_allowed", conf->soft_keygen_allowed);
}
