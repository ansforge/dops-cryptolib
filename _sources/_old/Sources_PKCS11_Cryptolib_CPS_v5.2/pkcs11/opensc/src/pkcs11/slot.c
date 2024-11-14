/*
 * slot.c: smart card and slot related management functions
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

#include <string.h>
#include <stdlib.h>
#include "sc-pkcs11.h"

#define HYPHENS_TRUNCATE "..."

static struct sc_pkcs11_framework_ops *frameworks[] = {
  &framework_pkcs15,
  NULL
};

unsigned int first_free_slot = 0;

static void init_slot_info(CK_SLOT_INFO_PTR pInfo)
{
  strcpy_bp(pInfo->slotDescription, "Virtual slot", 64);
  /* CLCO 26/05/2010 : Adaptation ASIP du slotInfo */
  strcpy_bp(pInfo->manufacturerID, "", 32);
  /* CLCO 26/05/2010 : fin */
  pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 0;
}

CK_RV card_initialize(int reader, struct sc_pkcs11_slot * pvirtual_slots, struct sc_pkcs11_card * pcard_table)
{
  struct sc_pkcs11_card *card = pcard_table + reader;
  unsigned int avail;
  unsigned int i;

  if (reader < 0 || reader >= SC_MAX_READERS) {
    return CKR_FUNCTION_FAILED;
  }

  memset(card, 0, sizeof(struct sc_pkcs11_card));
  card->reader = reader;

  /* Always allocate a fixed slot range to one reader/card.
   * Some applications get confused if readers pop up in
   * different slots. */
  avail = sc_pkcs11_conf.slots_per_card;

  if (first_free_slot + avail > sc_pkcs11_conf.max_virtual_slots) {
    avail = sc_pkcs11_conf.max_virtual_slots - first_free_slot;
  }
  card->first_slot = first_free_slot;
  card->max_slots = avail;
  card->num_slots = 0;

  for (i = 0; i < card->max_slots; i++) {
    struct sc_pkcs11_slot *slot = pvirtual_slots + card->first_slot + i;
    slot->reader = reader;
  }

  first_free_slot += card->max_slots;
  return CKR_OK;
}

/// slot_set_description
int slot_set_description(CK_SLOT_INFO_PTR pSlotInfo, char * i_pc_readerNamePCSC)
{
  char * l_pc_readerNamePCSCEnd;
  char * l_pc_readerNamePCSCWrk;

  // If not allowed exit
  if ((pSlotInfo == NULL) || (i_pc_readerNamePCSC == NULL)) {
    return -1;
  }

  // Point to the beginning of buffer
  l_pc_readerNamePCSCWrk = (char*)pSlotInfo->slotDescription;
  // Fill slot description with blanks
  memset(l_pc_readerNamePCSCWrk, 0x20, sizeof(pSlotInfo->slotDescription));
  

  // If PCSC reader name is not too big
  if (strlen(i_pc_readerNamePCSC) <= 64) {
    memcpy(l_pc_readerNamePCSCWrk, i_pc_readerNamePCSC, strlen(i_pc_readerNamePCSC));
    // If PCSC reader name is upper than 64
  }
  else {
    // 1 - Copy first 30 caracters		
    memcpy(l_pc_readerNamePCSCWrk, i_pc_readerNamePCSC, 30);
    // 2 - Append "..." to end
    memcpy(l_pc_readerNamePCSCWrk + 30, HYPHENS_TRUNCATE, strlen(HYPHENS_TRUNCATE));
    // 3 - Copy last 30 caracters
    // Jump to last 30 caracters
    l_pc_readerNamePCSCEnd = i_pc_readerNamePCSC + strlen(i_pc_readerNamePCSC) - 31;
    // And concat from position
    memcpy(l_pc_readerNamePCSCWrk + 30 + strlen(HYPHENS_TRUNCATE), l_pc_readerNamePCSCEnd, strlen(l_pc_readerNamePCSCEnd));
  }

  return 0;
}

CK_RV card_detect(int reader, struct sc_context * context)
{
  int rc, rv, i;
  struct sc_pkcs11_slot * pvirtual_slots;
  struct sc_pkcs11_card * pCard;
  rv = CKR_OK;

  /* BPER 1381 Solution C: gestion multi-threads - Debut */
  if (context == NULL || context->card_table == NULL || context->virtual_slots == NULL) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  pCard = &context->card_table[reader];
  pvirtual_slots = context->virtual_slots;

  sc_debug(context, "Reader id(%d): Detecting smart card\n", reader);

  for (i = pCard->max_slots; i--; ) {
    struct sc_pkcs11_slot *slot;
    sc_reader_t *rdr = sc_ctx_get_reader(context, (unsigned int)reader);

    if (rdr == NULL) {
      if (sc_ctx_detect_readers(context) != SC_SUCCESS) {
        return CKR_DEVICE_ERROR;
      }
      rdr = sc_ctx_get_reader(context, (unsigned int)reader);
      if (rdr == NULL) {
        return CKR_DEVICE_ERROR;
      }
    }
    /* gestion de la déconnexion/reconnexion des lecteurs */
    if (!rdr->detected ) {
      if (sc_ctx_detect_readers(context) != SC_SUCCESS) {
        if (pCard->card != NULL) {
          card_removed(reader, 0); /* faire le ménage dans le slot déconnecté */
        }
        return CKR_DEVICE_ERROR;
      }
      else {
        rdr = sc_ctx_get_reader(context, (unsigned int)reader);
      }
    }

    slot = pvirtual_slots + pCard->first_slot + i;
    ///
    slot_set_description(&(slot->slot_info), rdr->name);
    slot->reader = reader;
    if (!rdr->detected) {
      return CKR_DEVICE_ERROR; /* il est inutile de tenter de détecter une carte sur un lecteur déconnecté */
    }
  }

  /* Check if someone inserted a card */
  rc = sc_detect_card_presence(sc_ctx_get_reader(context, reader), 0);
  if (rc < 0) {
    sc_debug(context, "Card detection failed for reader %d: %s\n", reader, sc_strerror(rc));
    card_removed(reader, 0); /* Release all resources */
    return sc_to_cryptoki_error(rc, reader);
  }
  if (rc == 0) {
    sc_debug(context, "Reader id(%d): Card absent\n", reader);
    card_removed(reader, 0); /* Release all resources */
    return CKR_TOKEN_NOT_PRESENT;
  }

  /* If the card was changed, disconnect the current one */
  if ((rc & SC_SLOT_CARD_CHANGED) && (pCard->card != NULL)) {
    sc_debug(context, "Reader id(%d): Card changed\n", reader);
    card_removed(reader, 0);
  }

  /* Detect the card if it's not known already */
  if (pCard->card == NULL) {
    sc_debug(context, "Reader id(%d): Connecting to smart card\n", reader);
    rc = sc_connect_card(sc_ctx_get_reader(context, reader), 0, &pCard->card);
    if (rc != SC_SUCCESS)
      return sc_to_cryptoki_error(rc, reader);
  }

  /* Detect the framework */
  if (pCard->framework == NULL) {
    sc_debug(context, "Reader id(%d): Detecting Framework\n", reader);

    for (i = 0; frameworks[i]; i++) {
      if (frameworks[i]->bind == NULL)
        continue;
      rv = frameworks[i]->bind(pCard);
      if (rv == CKR_OK)
        break;
    }

    if (frameworks[i] == NULL)
      return CKR_TOKEN_NOT_RECOGNIZED;

    /* Initialize framework */
    sc_debug(context, "Reader id(%d): Detected framework %d. Creating tokens.\n", reader, i);
    rv = frameworks[i]->create_tokens(pCard);
    if (rv != CKR_OK)
      return rv;

    pCard->framework = frameworks[i];
  }

  sc_debug(context, "Reader id(%d): Detection ended\n", reader);
  return rv;
}

CK_RV __card_detect_all(struct sc_context *pContext, int report_events)
{
  int i;
  struct sc_pkcs11_slot * pvirtual_slots;

  if (pContext == NULL_PTR || pContext->virtual_slots == NULL) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  pvirtual_slots = pContext->virtual_slots;

  for (i = 0; i < (int)sc_ctx_get_reader_count(pContext); i++) {
    card_detect(i, pContext);
  }
  if (!report_events) {
    CK_SLOT_ID id;

    for (id = 0; id < sc_pkcs11_conf.max_virtual_slots; id++)
      pvirtual_slots[id].events = 0;
  }

  return CKR_OK;
}

CK_RV card_detect_all(void)
{
  struct sc_context *pctx = getCurContext(); //BPER 1381 - Solution C
  return __card_detect_all(pctx, 1);
}

CK_RV card_removed(int reader, unsigned long dwThreadID)
{
  struct sc_context *context; //BPER 1381 - Solution C
  unsigned int i;
  struct sc_pkcs11_card *card;
  if (dwThreadID == 0) {
    context = getCurContext(); // BPER 1381 - Solution C
  }
  else {
    context = getCurContext_finalize(dwThreadID); // BPER 1381 - Solution C
  }

  sc_debug(context, "Reader id(%d): smart card removed\n", reader);

  for (i = 0; i < sc_pkcs11_conf.max_virtual_slots; i++) {
    if (context->virtual_slots[i].card &&
      context->virtual_slots[i].card->reader == reader)
      slot_token_removed(i, context);
  }

  /* beware - do not clean the entire sc_pkcs11_card struct;
   * fields such as first_slot and max_slots are initialized
   * _once_ and need to be left untouched across card removal/
   * insertion */
  card = &context->card_table[reader];
  if (card->framework) {
    card->framework->unbind(card);
  }
  card->framework = NULL;
  card->fw_data = NULL;

  if (card->card)
    sc_disconnect_card(card->card, 0);
  card->card = NULL;

  return CKR_OK;
}

CK_RV slot_initialize(int id, struct sc_pkcs11_slot *slot)
{
  memset(slot, 0, sizeof(*slot));
  slot->id = id;
  slot->login_user = -1;
  init_slot_info(&slot->slot_info);
  pool_initialize(&slot->object_pool, POOL_TYPE_OBJECT);

  return CKR_OK;
}

CK_RV slot_allocate(struct sc_pkcs11_slot **slot, struct sc_pkcs11_card *card)
{
  unsigned int i, first, last;
  struct sc_context *pcontext;
  struct sc_pkcs11_slot * pvirtual_slots;

  if (card == NULL || card->card == NULL ||
    card->card->ctx == NULL || card->card->ctx->virtual_slots == NULL) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  /* BPER 1381 gestion multi-threads - Debut */
  pcontext = card->card->ctx;
  sc_debug(pcontext, "slot_allocate, context handle: %p\n", pcontext);
  pvirtual_slots = pcontext->virtual_slots;
  /* BPER 1381 gestion multi-threads - Fin */

  if (card->num_slots >= card->max_slots) {
    return CKR_FUNCTION_FAILED;
  }

  first = card->first_slot;
  last = first + card->max_slots;

  for (i = first; i < last; i++) {
    if (!pvirtual_slots[i].card) {
      sc_debug(pcontext, "Allocated slot %d\n", i);
      pvirtual_slots[i].card = card;
      pvirtual_slots[i].events = SC_EVENT_CARD_INSERTED;
      *slot = &pvirtual_slots[i];
      sc_debug(pcontext, "Allocated slot %d, 0x%08x\n", i, *slot);
      card->num_slots++;
      return CKR_OK;
    }
  }
  return CKR_FUNCTION_FAILED;
}

CK_RV slot_get_slot(int id, struct sc_pkcs11_slot **slot, sc_context_t *pcontext)
{
  if (pcontext == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  sc_debug(pcontext, "slot_get_slot: id=%d, rdr_count=%d\n", id, pcontext->reader_count);

  if (id < 0 || id >= (int)pcontext->reader_count) {
    return CKR_SLOT_ID_INVALID;
  }

  if (pcontext->virtual_slots == NULL) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  *slot = &pcontext->virtual_slots[id];
  return CKR_OK;
}

CK_RV slot_get_token(int id, struct sc_pkcs11_slot **slot, int bCardPresence)
{
  int rv;
  struct sc_context *pcontext = getCurContext();

  rv = slot_get_slot(id, slot, pcontext);
  if (rv != CKR_OK) {
    return rv;
  }

  if (bCardPresence == TRUE) {
    rv = card_detect((*slot)->reader, pcontext);
    if (rv != CKR_OK) {
      return rv;
    }
  }
  if (!((*slot)->slot_info.flags & CKF_TOKEN_PRESENT))
  {
    sc_debug(pcontext, "card detected, but slot not presenting token");
    return CKR_TOKEN_NOT_PRESENT;
  }
  return CKR_OK;
}

CK_RV slot_token_removed(int id, struct sc_context *pcontext)
{
  int rv, token_was_present;
  struct sc_pkcs11_slot *slot;
  struct sc_pkcs11_object *object;
  CK_SLOT_INFO saved_slot_info;
  int reader;

  if (pcontext == NULL || pcontext->virtual_slots == NULL) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  rv = slot_get_slot(id, &slot, pcontext);
  if (rv != CKR_OK) {
    return rv;
  }

  token_was_present = (slot->slot_info.flags & CKF_TOKEN_PRESENT);

  /* Terminate active sessions */
  sc_pkcs11_close_all_sessions(id, pcontext);

  /* Object pool */
  while (pool_find_and_delete(&slot->object_pool, 0, (void**)&object, pcontext) == CKR_OK) {
    if (object->ops->release)
      object->ops->release(object);
  }

  /* Release framework stuff */
  if (slot->card != NULL) {
    if (slot->fw_data != NULL){
      if (slot->card->framework != NULL && slot->card->framework->release_token != NULL) {
        slot->card->framework->release_token(slot->card, slot->fw_data);
      }
      free(slot->fw_data);
    }
    slot->card->num_slots--;
  }
  
  /* Zap everything else. Restore the slot_info afterwards (it contains the reader
   * name, for instance) but clear its flags */
  saved_slot_info = slot->slot_info;
  reader = slot->reader;
  memset(slot, 0, sizeof(*slot));
  /* CLCO 01/09/2010 : il faut concerver l'id du slot */
  slot->id = id;
  /* CLCO 01/09/2010 : fin */
  slot->slot_info = saved_slot_info;
  slot->slot_info.flags = 0;
  slot->login_user = -1;
  slot->reader = reader;
  pool_initialize(&slot->object_pool, POOL_TYPE_OBJECT);

  if (token_was_present)
    slot->events = SC_EVENT_CARD_REMOVED;

  return CKR_OK;
}

CK_RV slot_find_changed(CK_SLOT_ID_PTR idp, int mask)
{
  sc_pkcs11_slot_t *slot;
  CK_SLOT_ID id;
  sc_context_t *pcontext;
  struct sc_pkcs11_slot * pvirtual_slots;

  pcontext = getCurContext();
  if (pcontext == NULL || pcontext->virtual_slots == NULL) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  pvirtual_slots = pcontext->virtual_slots;

  card_detect_all();
  for (id = 0; id < sc_pkcs11_conf.max_virtual_slots; id++) {
    slot = &pvirtual_slots[id];
    if ((slot->events & SC_EVENT_CARD_INSERTED) && !(slot->slot_info.flags & CKF_TOKEN_PRESENT)) {
      slot->events &= ~SC_EVENT_CARD_INSERTED;
    }
    if (slot->events & mask) {
      slot->events &= ~mask;
      *idp = id;
      return CKR_OK;
    }
  }
  return CKR_NO_EVENT;
}
