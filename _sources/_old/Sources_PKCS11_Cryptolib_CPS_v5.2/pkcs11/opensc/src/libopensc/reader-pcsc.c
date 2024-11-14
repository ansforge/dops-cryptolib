/*
 * reader-pcsc.c: Reader driver for PC/SC interface
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "internal.h"
#ifdef ENABLE_PCSC
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#ifdef __APPLE__
#include <sys/utsname.h>
#endif


#include "internal-winscard.h"

/* AROC 25/03/2011 : Ne pas tenir compte des lecteurs PSS remontés par le drivers Galss sous MAC */
#if defined(__APPLE__)
const char PSS_READERNAME[] = "PSS SmartCard Reader";
#endif
/* AROC 25/03/2011 : Fin */

extern int g_winlogonProcess;

/* Some windows specific kludge */
#undef SCARD_PROTOCOL_ANY
#define SCARD_PROTOCOL_ANY (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
/* Error printing */
#define PCSC_ERROR(ctx, desc, rv) sc_error(ctx, desc ": 0x%08x\n", rv);

/* Utility for handling big endian IOCTL codes. */
#define dw2i_be(a, x) ((((((a[x] << 8) + a[x+1]) << 8) + a[x+2]) << 8) + a[x+3])

#define GET_PRIV_DATA(r) ((struct pcsc_private_data *) (r)->drv_data)
#define GET_SLOT_DATA(r) ((struct pcsc_slot_data *) (r)->drv_data)


struct pcsc_global_private_data {
  SCARDCONTEXT pcsc_ctx;
  int enable_pinpad;
  int connect_exclusive;
  int connect_reset;
  int transaction_reset;
  const char *provider_library;
  lt_dlhandle dlhandle;
  SCardEstablishContext_t SCardEstablishContext;
  SCardReleaseContext_t SCardReleaseContext;
  SCardConnect_t SCardConnect;
  SCardReconnect_t SCardReconnect;
  SCardDisconnect_t SCardDisconnect;
  SCardBeginTransaction_t SCardBeginTransaction;
  SCardEndTransaction_t SCardEndTransaction;
  SCardStatus_t SCardStatus;
  SCardGetStatusChange_t SCardGetStatusChange;
  SCardControlOLD_t SCardControlOLD;
  SCardControl_t SCardControl;
  SCardTransmit_t SCardTransmit;
  SCardListReaders_t SCardListReaders;
#if defined (WIN32) || (__APPLE__)
  SCardIsValidContext_t SCardIsValidContext;
#endif
#ifdef __APPLE__
  int isYosemite;
#endif
};

struct pcsc_private_data {
  char *reader_name;
  struct pcsc_global_private_data *gpriv;
};

struct pcsc_slot_data {
  SCARDHANDLE pcsc_card;
  SCARD_READERSTATE_A reader_state;
  DWORD verify_ioctl;
  DWORD verify_ioctl_start;
  DWORD verify_ioctl_finish;

  DWORD modify_ioctl;
  DWORD modify_ioctl_start;
  DWORD modify_ioctl_finish;
  int locked;
};

static int pcsc_detect_card_presence(sc_reader_t *reader, sc_slot_info_t *slot);

static int pcsc_ret_to_error(DWORD rv)
{
  switch (rv) {
  case SCARD_W_REMOVED_CARD:
    return SC_ERROR_CARD_REMOVED;
  case SCARD_E_NOT_TRANSACTED:
    return SC_ERROR_TRANSMIT_FAILED;
  case SCARD_W_UNRESPONSIVE_CARD:
    return SC_ERROR_CARD_UNRESPONSIVE;
  case SCARD_W_UNPOWERED_CARD:
    return SC_ERROR_CARD_UNRESPONSIVE;
  case SCARD_E_SHARING_VIOLATION:
    return SC_ERROR_READER;
#ifdef SCARD_E_NO_READERS_AVAILABLE /* Older pcsc-lite does not have it */
  case SCARD_E_NO_READERS_AVAILABLE:
    return SC_ERROR_NO_READERS_FOUND;
#endif
  case SCARD_E_NO_SERVICE:
    /* If the service is (auto)started, there could be readers later */
    return SC_ERROR_NO_READERS_FOUND;
  default:
    return SC_ERROR_UNKNOWN;
  }
}

static unsigned int pcsc_proto_to_opensc(DWORD proto)
{
  switch (proto) {
  case SCARD_PROTOCOL_T0:
    return SC_PROTO_T0;
  case SCARD_PROTOCOL_T1:
    return SC_PROTO_T1;
  case SCARD_PROTOCOL_RAW:
    return SC_PROTO_RAW;
  default:
    return 0;
  }
}

static DWORD opensc_proto_to_pcsc(unsigned int proto)
{
  switch (proto) {
  case SC_PROTO_T0:
    return SCARD_PROTOCOL_T0;
  case SC_PROTO_T1:
    return SCARD_PROTOCOL_T1;
  case SC_PROTO_RAW:
    return SCARD_PROTOCOL_RAW;
  default:
    return 0;
  }
}

#ifdef __APPLE__
int isYosemite(sc_context_t *ctx)
{
  struct utsname _utsname;
  char * pStr;
  char major[10] = { 0 };
  int nMajor;

  uname(&_utsname);

  sc_debug(ctx, "OS Version : %s\n", _utsname.release);

  pStr = strchr(_utsname.release, '.');
  if (pStr == NULL)
    return 0;

  strncpy(major, _utsname.release, pStr - _utsname.release);


  nMajor = atoi(major);

  if (nMajor == 14) {
    sc_debug(ctx, "At least Yosemite !!");
    return 1;
  }

  return 0;
}
#endif

static int pcsc_internal_transmit(sc_reader_t *reader, sc_slot_info_t *slot,
  const u8 *sendbuf, size_t sendsize,
  u8 *recvbuf, size_t *recvsize,
  unsigned long control)
{
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
  SCARD_IO_REQUEST sSendPci, sRecvPci;
  DWORD dwSendLength, dwRecvLength;
  DWORD rv;
  SCARDHANDLE card;
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

  SC_FUNC_CALLED(reader->ctx, 3);
  assert(pslot != NULL);
  card = pslot->pcsc_card;

  sSendPci.dwProtocol = opensc_proto_to_pcsc(slot->active_protocol);
  sSendPci.cbPciLength = sizeof(sSendPci);
  sRecvPci.dwProtocol = opensc_proto_to_pcsc(slot->active_protocol);
  sRecvPci.cbPciLength = sizeof(sRecvPci);

  dwSendLength = (DWORD)sendsize;
  dwRecvLength = (DWORD)*recvsize;

  if (!control) {
    rv = priv->gpriv->SCardTransmit(card, &sSendPci, sendbuf, dwSendLength,
      &sRecvPci, recvbuf, &dwRecvLength);
  }
  else {
    if (priv->gpriv->SCardControlOLD != NULL) {
      rv = priv->gpriv->SCardControlOLD(card, sendbuf, dwSendLength,
        recvbuf, &dwRecvLength);
    }
    else {
      rv = priv->gpriv->SCardControl(card, (DWORD)control, sendbuf, dwSendLength,
        recvbuf, dwRecvLength, &dwRecvLength);
    }
  }

  if (rv != SCARD_S_SUCCESS) {
    switch (rv) {
    case SCARD_W_REMOVED_CARD:
      return SC_ERROR_CARD_REMOVED;
    case SCARD_E_NOT_TRANSACTED:
      if (!(pcsc_detect_card_presence(reader, slot) & SC_SLOT_CARD_PRESENT))
        return SC_ERROR_CARD_REMOVED;
      return SC_ERROR_TRANSMIT_FAILED;
    default:
      /* Windows' PC/SC returns 0x8010002f (??) if a card is removed */
      if (pcsc_detect_card_presence(reader, slot) != 1)
        return SC_ERROR_CARD_REMOVED;
      PCSC_ERROR(reader->ctx, "SCardTransmit failed", rv);
      return SC_ERROR_TRANSMIT_FAILED;
    }
  }
  if (!control && dwRecvLength < 2)
    return SC_ERROR_UNKNOWN_DATA_RECEIVED;
  *recvsize = dwRecvLength;

  return SC_SUCCESS;
}

static int pcsc_transmit(sc_reader_t *reader, sc_slot_info_t *slot,
  sc_apdu_t *apdu)
{
  size_t       ssize = 0;
  size_t       rsize = 0;
  size_t       rbuflen = 0;
  u8           *sbuf = NULL;
  u8           *rbuf = NULL;
  int          r;

  /* we always use a at least 258 byte size big return buffer
   * to mimic the behaviour of the old implementation (some readers
   * seems to require a larger than necessary return buffer).
   * The buffer for the returned data needs to be at least 2 bytes
   * larger than the expected data length to store SW1 and SW2. */
  rsize = rbuflen = apdu->resplen <= 256 ? 258 : apdu->resplen + 2;
  rbuf = malloc(rbuflen);
  if (rbuf == NULL) {
    r = SC_ERROR_MEMORY_FAILURE;
    goto out;
  }
  /* encode and log the APDU */
  r = sc_apdu_get_octets(reader->ctx, apdu, &sbuf, &ssize, slot->active_protocol);
  if (r != SC_SUCCESS)
    goto out;
  if (reader->ctx->debug >= 6)
    sc_apdu_log(reader->ctx, apdu, slot->active_protocol);

  r = pcsc_internal_transmit(reader, slot, sbuf, ssize,
    rbuf, &rsize, apdu->control);
  if (r < 0) {
    /* unable to transmit ... most likely a reader problem */
    sc_error(reader->ctx, "unable to transmit");
    goto out;
  }
  /* MCUG 02/09/2010 : Ajout du cryptage de données sensibles sur la log d'apdu */
  if (reader->ctx->debug >= 6)
    sc_apdu_resp_log(reader->ctx, rbuf, rsize);
  /* MCUG 02/09/2010 : Fin */


  /* set response */
  r = sc_apdu_set_resp(reader->ctx, apdu, rbuf, rsize);
out:
  if (sbuf != NULL) {
    sc_mem_clear(sbuf, ssize);
    free(sbuf);
  }
  if (rbuf != NULL) {
    sc_mem_clear(rbuf, rbuflen);
    free(rbuf);
  }

  return r;
}

/* AROC - (@@20160113-1347) - Refonte de la la d�tection d'�venements - Debut */

static int refresh_slot_attributes(sc_reader_t *reader, sc_slot_info_t *slot)
{
  DWORD state, prot, atr_len = SC_MAX_ATR_SIZE;
  unsigned char szReader[200];
  DWORD readers_len = 200;
  DWORD rv;
  //SCARDHANDLE card_handle;
  DWORD active_proto;

  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

  pslot->reader_state.cbAtr = SC_MAX_ATR_SIZE;

  if (pslot->reader_state.szReader == NULL) {
    pslot->reader_state.szReader = priv->reader_name;
    pslot->reader_state.dwCurrentState = SCARD_STATE_UNAWARE;
    pslot->reader_state.dwEventState = SCARD_STATE_UNAWARE;
  }

  if (pslot->pcsc_card == 0) {
    sc_debug(reader->ctx, "Try to connect to reader (%s) with context handle (%p)", priv->reader_name, priv->gpriv->pcsc_ctx);
    rv = priv->gpriv->SCardConnect(priv->gpriv->pcsc_ctx, priv->reader_name, priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY, &pslot->pcsc_card/*card_handle*/, &active_proto);
    if (rv != SCARD_S_SUCCESS)
    {
      PCSC_ERROR(reader->ctx, "SCardConnect failed", rv);
      slot->flags &= ~(SC_SLOT_CARD_PRESENT | SC_SLOT_CARD_CHANGED);
      sc_debug(reader->ctx, "refresh_slot_attributes return state [%d]", slot->flags);
      if ( (rv == SCARD_W_REMOVED_CARD) || (rv == SCARD_W_UNRESPONSIVE_CARD) || (rv == SCARD_E_NO_SMARTCARD)) {
        return 0;
      }
      else {
        PCSC_ERROR(reader->ctx, "SCardConnect failed", rv);
        return pcsc_ret_to_error(rv);
      }
    }
    slot->active_protocol = pcsc_proto_to_opensc(active_proto);
    //pslot->pcsc_card = card_handle;
  }
  //card_handle = pslot->pcsc_card;
  active_proto = slot->active_protocol;
  sc_debug(reader->ctx, "Calling SCardStatus ...");

  rv = priv->gpriv->SCardStatus(pslot->pcsc_card, (LPSTR)szReader, &readers_len, &state, &prot, pslot->reader_state.rgbAtr, (LPDWORD)&pslot->reader_state.cbAtr);
  if (rv == SCARD_E_INVALID_HANDLE || rv == ERROR_INVALID_HANDLE || rv == SCARD_W_REMOVED_CARD || rv == SCARD_W_RESET_CARD || rv == SCARD_W_UNPOWERED_CARD )
  {
    DWORD rc;
    sc_debug(reader->ctx, "SCardStatus failed (0x%08X)... try to reconnect", rv);
#ifdef WIN32
    if (rv != SCARD_W_RESET_CARD) {
#endif
      pslot->reader_state.dwEventState |= SCARD_STATE_CHANGED;
#ifdef WIN32
    }
#endif
    rc = priv->gpriv->SCardReconnect(pslot->pcsc_card, SCARD_SHARE_SHARED, active_proto, SCARD_LEAVE_CARD, &active_proto);
    if (rc != SCARD_S_SUCCESS)
    {
      PCSC_ERROR(reader->ctx, "SCardReconnect failed", rv);
      slot->flags &= ~(SC_SLOT_CARD_PRESENT | SC_SLOT_CARD_CHANGED);
      sc_debug(reader->ctx, "refresh_slot_attributes return state [%d]", slot->flags);
      return 0;
    }
    else {
      sc_debug(reader->ctx, "SCardReconnect OK");
    }
    slot->active_protocol = pcsc_proto_to_opensc(active_proto);
    //pslot->pcsc_card = card_handle;
    atr_len = SC_MAX_ATR_SIZE;
    readers_len = 200;
    rv = priv->gpriv->SCardStatus(pslot->pcsc_card, (LPSTR)szReader, &readers_len, &state, &prot, pslot->reader_state.rgbAtr, (LPDWORD)&pslot->reader_state.cbAtr);
  }

  if (rv == SCARD_S_SUCCESS)
  {
    sc_debug(reader->ctx, "SCardStatus returned state : 0x%08X", state);
    slot->flags = 0;
    if (pslot->reader_state.szReader == NULL)
      pslot->reader_state.szReader = priv->reader_name;
    /* Mettre � jour l'atr */
    if (pslot->reader_state.cbAtr != 0) {
      pslot->reader_state.dwEventState |= SCARD_STATE_PRESENT;
      slot->atr_len = pslot->reader_state.cbAtr;
      if (slot->atr_len > SC_MAX_ATR_SIZE) {
        slot->atr_len = SC_MAX_ATR_SIZE;
      }
      memcpy(slot->atr, pslot->reader_state.rgbAtr, slot->atr_len);
    }

#ifdef WIN32
    switch (state) {
    case SCARD_PRESENT:
    case SCARD_SWALLOWED:
    case SCARD_NEGOTIABLE:
      pslot->reader_state.dwEventState |= SCARD_STATE_PRESENT;
      slot->flags = SC_SLOT_CARD_PRESENT;
      break;
    case SCARD_POWERED:
    case SCARD_SPECIFIC:
      pslot->reader_state.dwEventState |= (SCARD_STATE_PRESENT | SCARD_STATE_INUSE);
      slot->flags = SC_SLOT_CARD_PRESENT;
      break;
    case SCARD_ABSENT:
    default:
      pslot->reader_state.dwEventState |= SCARD_STATE_EMPTY;
      slot->flags = 0;
      break;
    }
#else
    if (((state & SCARD_PRESENT) == SCARD_PRESENT) ||
      ((state & SCARD_SWALLOWED) == SCARD_SWALLOWED))
    {
      pslot->reader_state.dwEventState |= SCARD_STATE_PRESENT;
      slot->flags = SC_SLOT_CARD_PRESENT;
    }
    if ((state & SCARD_POWERED) == SCARD_POWERED)
    {
      pslot->reader_state.dwEventState |= (SCARD_STATE_PRESENT | SCARD_STATE_INUSE);
      slot->flags = SC_SLOT_CARD_PRESENT;
    }
    if ((state & SCARD_ABSENT) == SCARD_ABSENT)
    {
      pslot->reader_state.dwEventState |= SCARD_STATE_EMPTY;
      slot->flags = 0;
    }

#endif
    sc_debug(reader->ctx, "Translate state 0x%08x to 0x%08X", state, slot->flags);
    if (pslot->reader_state.dwEventState != pslot->reader_state.dwCurrentState) {
      sc_debug(reader->ctx, "dwCurrentState 0x%08x vs dwEventState 0x%08X", pslot->reader_state.dwCurrentState, pslot->reader_state.dwEventState);
      pslot->reader_state.dwCurrentState = pslot->reader_state.dwEventState;
      slot->flags |= SC_SLOT_CARD_CHANGED;
    }
  }
  else
  {
    pslot->reader_state.dwCurrentState = SCARD_STATE_EMPTY;
    slot->flags &= ~(SC_SLOT_CARD_PRESENT | SC_SLOT_CARD_CHANGED);
    PCSC_ERROR(reader->ctx, "SCardStatus failed", rv);
  }
  sc_debug(reader->ctx, "refresh_slot_attributes return state [%d]", slot->flags);
  return 0;
}

/* AROC -(@@20160113-1347) - Refonte de la la d�tection d'�venements */

static int pcsc_detect_card_presence(sc_reader_t *reader, sc_slot_info_t *slot)
{
  int rv;
  /* AROC - (@@20141016-1192) - Exploiter la fonction SCardBeginTransaction sous Yosemite afin pour detecter les evenements cartes : Debut */
#if defined(__APPLE__)
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
#endif
  if ((rv = refresh_slot_attributes(reader, slot)) < 0)
    return rv;
#if defined(__APPLE__)

  if (priv->gpriv->isYosemite == 1){
    sc_debug(reader->ctx, "pcsc_detect_card_presence( pslot->pcsc_card : 0x%08x,pslot->locked : 0x%08x", pslot->pcsc_card, pslot->locked);
    if (pslot->pcsc_card != 0 && pslot->locked != 1) {
      int rc;
      sc_debug(reader->ctx, "On Yosemite use SCardBeginTransaction to detect a card activity");
      rc = priv->gpriv->SCardBeginTransaction(pslot->pcsc_card);
      sc_debug(reader->ctx, "SCardBeginTransaction returned : 0x%x",rc);

      if (rc == SCARD_E_NO_SMARTCARD){
        slot->flags = SC_SLOT_CARD_CHANGED;
        sc_debug(reader->ctx, "On Yosemite use SCardBeginTransaction a card activity as been detected");
      }
      else{
        priv->gpriv->SCardEndTransaction(pslot->pcsc_card, SCARD_LEAVE_CARD);
      }
    }
  }
#endif
  /* AROC - (@@20141016-1192) - Exploiter la fonction SCardBeginTransaction sous Yosemite afin pour detecter les evenements cartes : Fin */
  return slot->flags;
}

/* Wait for an event to occur.
 * This function ignores the list of slots, because with
 * pcsc we have a 1:1 mapping of readers and slots anyway
 */
static int pcsc_wait_for_event(sc_reader_t **readers,
  sc_slot_info_t **slots,
  size_t nslots,
  unsigned int event_mask,
  int *reader,
  unsigned int *event, int timeout)
{
  struct pcsc_private_data *priv = GET_PRIV_DATA(readers[0]);
  sc_context_t *ctx;
  SCARDCONTEXT pcsc_ctx;
  DWORD ret;
  SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];
  unsigned long on_bits, off_bits;
  time_t end_time, now, delta;
  size_t i;

  /* Prevent buffer overflow */
  if (nslots >= SC_MAX_READERS)
    return SC_ERROR_INVALID_ARGUMENTS;

  on_bits = off_bits = 0;
  if (event_mask & SC_EVENT_CARD_INSERTED) {
    event_mask &= ~SC_EVENT_CARD_INSERTED;
    on_bits |= SCARD_STATE_PRESENT;
  }
  if (event_mask & SC_EVENT_CARD_REMOVED) {
    event_mask &= ~SC_EVENT_CARD_REMOVED;
    off_bits |= SCARD_STATE_PRESENT;
  }
  if (event_mask != 0)
    return SC_ERROR_INVALID_ARGUMENTS;

  /* Find out the current status */
  ctx = readers[0]->ctx;
  pcsc_ctx = priv->gpriv->pcsc_ctx;
  for (i = 0; i < nslots; i++) {
    struct pcsc_private_data *priv2 = GET_PRIV_DATA(readers[i]);

    rgReaderStates[i].szReader = priv2->reader_name;
    rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
    rgReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;

    /* Can we handle readers from different PCSC contexts? */
    if (priv2->gpriv->pcsc_ctx != pcsc_ctx)
      return SC_ERROR_INVALID_ARGUMENTS;
  }

  ret = priv->gpriv->SCardGetStatusChange(pcsc_ctx, 0, rgReaderStates, (DWORD)nslots);
  if (ret != SCARD_S_SUCCESS) {
    PCSC_ERROR(ctx, "SCardGetStatusChange(1) failed", ret);
    return pcsc_ret_to_error(ret);
  }

  time(&now);
  end_time = now + (timeout + 999) / 1000;

  /* Wait for a status change and return if it's a card insert/removal
   */
  for (; ; ) {
    SCARD_READERSTATE_A *rsp;

    /* Scan the current state of all readers to see if they
     * match any of the events we're polling for */
    *event = 0;
    for (i = 0, rsp = rgReaderStates; i < nslots; i++, rsp++) {
      unsigned long state, prev_state;

      prev_state = rsp->dwCurrentState;
      state = rsp->dwEventState;
      if ((state & on_bits & SCARD_STATE_PRESENT) &&
        (prev_state & SCARD_STATE_EMPTY))
        *event |= SC_EVENT_CARD_INSERTED;
      if ((~state & off_bits & SCARD_STATE_PRESENT) &&
        (prev_state & SCARD_STATE_PRESENT))
        *event |= SC_EVENT_CARD_REMOVED;
      if (*event) {
        *reader = (int)i;
        return SC_SUCCESS;
      }

      /* No match - copy the state so pcscd knows
       * what to watch out for */
      rsp->dwCurrentState = rsp->dwEventState;
    }

    /* Set the timeout if caller wants to time out */
    if (timeout == 0)
      return SC_ERROR_EVENT_TIMEOUT;
    if (timeout > 0) {
      time(&now);
      if (now >= end_time)
        return SC_ERROR_EVENT_TIMEOUT;
      delta = end_time - now;
    }
    else {
      delta = 3600;
    }

    /* CLCO 04/06/2010 : suppression warning compilation */
    ret = priv->gpriv->SCardGetStatusChange(pcsc_ctx, (DWORD)(1000 * delta),
      rgReaderStates, (DWORD)nslots);
    /* CLCO 04/06/2010 : fin */
    if (ret == SCARD_E_TIMEOUT) {
      if (timeout < 0)
        continue;
      return SC_ERROR_EVENT_TIMEOUT;
    }
    if (ret != SCARD_S_SUCCESS) {
      PCSC_ERROR(ctx, "SCardGetStatusChange(2) failed", ret);
      return pcsc_ret_to_error(ret);
    }
  }
}

static int pcsc_reconnect(sc_reader_t * reader, sc_slot_info_t * slot, int reset)
{
  DWORD active_proto, protocol;
  DWORD rv;
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
  int r;

  sc_debug(reader->ctx, "Reconnecting to the card...");

  r = refresh_slot_attributes(reader, slot);
  if (r)
    return r;
  if (!(slot->flags & SC_SLOT_CARD_PRESENT))
    return SC_ERROR_CARD_NOT_PRESENT;

  /* reconnect always unlocks transaction */
  pslot->locked = 0;

  rv = priv->gpriv->SCardReconnect(pslot->pcsc_card,
    priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
    SCARD_PROTOCOL_ANY, reset ? SCARD_UNPOWER_CARD : SCARD_LEAVE_CARD, &active_proto);

  /* Check for protocol difference */
  if (rv == SCARD_S_SUCCESS && _sc_check_forced_protocol
    (reader->ctx, slot->atr, slot->atr_len,
      (unsigned int *)&protocol)) {
    protocol = opensc_proto_to_pcsc(protocol);
    if (pcsc_proto_to_opensc(active_proto) != protocol) {
      rv = priv->gpriv->SCardReconnect(pslot->pcsc_card,
        priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
        protocol, SCARD_UNPOWER_CARD, &active_proto);
    }
  }

  if (rv != SCARD_S_SUCCESS) {
    PCSC_ERROR(reader->ctx, "SCardReconnect failed", rv);
    return rv;
  }

  slot->active_protocol = pcsc_proto_to_opensc(active_proto);
  return rv;
}

static int pcsc_connect(sc_reader_t *reader, sc_slot_info_t *slot)
{
  int r = 0;
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

#ifdef _PINPAD_READER
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
  SCARDHANDLE card_handle = (SCARDHANDLE)NULL;
  u8 feature_buf[256], rbuf[SC_MAX_APDU_BUFFER_SIZE];
  DWORD active_proto, protocol;
  DWORD rv;
  size_t rcount;
  DWORD i, feature_len, display_ioctl = 0;
  PCSC_TLV_STRUCTURE *pcsc_tlv;
#endif

  r = refresh_slot_attributes(reader, slot);
  if (r)
    return r;
  if (!(slot->flags & SC_SLOT_CARD_PRESENT))
    return SC_ERROR_CARD_NOT_PRESENT;

  pslot->locked = 0;
  return SC_SUCCESS;

#ifdef _PINPAD_READER
  /* Always connect with whatever protocol possible */
  rv = priv->gpriv->SCardConnect(priv->gpriv->pcsc_ctx, priv->reader_name,
    priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
    SCARD_PROTOCOL_ANY, &card_handle, &active_proto);
  if (rv != SCARD_S_SUCCESS) {
    PCSC_ERROR(reader->ctx, "SCardConnect failed", rv);
    return pcsc_ret_to_error(rv);
  }
  slot->active_protocol = pcsc_proto_to_opensc(active_proto);
  pslot->pcsc_card = card_handle;

  /* after connect reader is not locked yet */
  pslot->locked = 0;
  sc_debug(reader->ctx, "After connect protocol = %d", slot->active_protocol);

  /* If we need a specific protocol, reconnect if needed */
  if (_sc_check_forced_protocol(reader->ctx, slot->atr, slot->atr_len, (unsigned int *)&protocol)) {
    /* If current protocol differs from the protocol we want to force */
    if (slot->active_protocol != protocol) {
      sc_debug(reader->ctx, "Protocol difference, forcing protocol (%d)", protocol);
      /* Reconnect with a reset. pcsc_reconnect figures out the right forced protocol */
      rv = pcsc_reconnect(reader, slot, 1);
      if (rv != SCARD_S_SUCCESS) {
        PCSC_ERROR(reader->ctx, "SCardReconnect (to force protocol) failed", rv);
        return pcsc_ret_to_error(rv);
      }
      sc_debug(reader->ctx, "Proto after reconnect = %d", slot->active_protocol);
    }
  }

  /* check for pinpad support */
  if (priv->gpriv->SCardControl != NULL) {
    sc_debug(reader->ctx, "Requesting reader features ... ");

    rv = priv->gpriv->SCardControl(pslot->pcsc_card, CM_IOCTL_GET_FEATURE_REQUEST, NULL,
      0, feature_buf, sizeof(feature_buf), &feature_len);
    if (rv != SCARD_S_SUCCESS) {
      sc_debug(reader->ctx, "SCardControl failed %08x", rv);
    }
    else {
      if ((feature_len % sizeof(PCSC_TLV_STRUCTURE)) != 0) {
        sc_debug(reader->ctx, "Inconsistent TLV from reader!");
      }
      else {
        char *log_disabled = "but it's disabled in configuration file";
        /* get the number of elements instead of the complete size */
        feature_len /= sizeof(PCSC_TLV_STRUCTURE);

        pcsc_tlv = (PCSC_TLV_STRUCTURE *)feature_buf;
        for (i = 0; i < feature_len; i++) {
          if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_DIRECT) {
            pslot->verify_ioctl = ntohl(pcsc_tlv[i].value);
          }
          else if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_START) {
            pslot->verify_ioctl_start = ntohl(pcsc_tlv[i].value);
          }
          else if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_FINISH) {
            pslot->verify_ioctl_finish = ntohl(pcsc_tlv[i].value);
          }
          else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_DIRECT) {
            pslot->modify_ioctl = ntohl(pcsc_tlv[i].value);
          }
          else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_START) {
            pslot->modify_ioctl_start = ntohl(pcsc_tlv[i].value);
          }
          else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_FINISH) {
            pslot->modify_ioctl_finish = ntohl(pcsc_tlv[i].value);
          }
          else if (pcsc_tlv[i].tag == FEATURE_IFD_PIN_PROPERTIES) {
            display_ioctl = ntohl(pcsc_tlv[i].value);
          }
          else {
            sc_debug(reader->ctx, "Reader feature %02x is not supported", pcsc_tlv[i].tag);
          }
        }

        /* Set slot capabilities based on detected IOCTLs */
        if (pslot->verify_ioctl || (pslot->verify_ioctl_start && pslot->verify_ioctl_finish)) {
          char *log_text = "Reader supports pinpad PIN verification";
          if (priv->gpriv->enable_pinpad) {
            sc_debug(reader->ctx, log_text);
            slot->capabilities |= SC_SLOT_CAP_PIN_PAD;
          }
          else {
            sc_debug(reader->ctx, "%s %s", log_text, log_disabled);
          }
        }

        if (pslot->modify_ioctl || (pslot->modify_ioctl_start && pslot->modify_ioctl_finish)) {
          char *log_text = "Reader supports pinpad PIN modification";
          if (priv->gpriv->enable_pinpad) {
            sc_debug(reader->ctx, log_text);
            slot->capabilities |= SC_SLOT_CAP_PIN_PAD;
          }
          else {
            sc_debug(reader->ctx, "%s %s", log_text, log_disabled);
          }
        }

        if (display_ioctl) {
          rcount = sizeof(rbuf);
          r = pcsc_internal_transmit(reader, slot, NULL, 0, rbuf, &rcount, display_ioctl);
          if (r == SC_SUCCESS) {
            if (rcount != sizeof(PIN_PROPERTIES_STRUCTURE)) {
              PIN_PROPERTIES_STRUCTURE *caps = (PIN_PROPERTIES_STRUCTURE *)rbuf;
              if (caps->wLcdLayout > 0) {
                sc_debug(reader->ctx, "Reader has a display: %04X", caps->wLcdLayout);
                slot->capabilities |= SC_SLOT_CAP_DISPLAY;
              }
              else
                sc_debug(reader->ctx, "Reader does not have a display.");
            }
            else {
              sc_debug(reader->ctx, "Returned PIN properties structure has bad length (%d)", rcount);
            }
          }
        }
      }
    }
  }
  return SC_SUCCESS;
#endif // PINPAD_READER
}

static int pcsc_disconnect(sc_reader_t * reader, sc_slot_info_t * slot)
{
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

  priv->gpriv->SCardDisconnect(pslot->pcsc_card, priv->gpriv->connect_reset ?
    SCARD_RESET_CARD : SCARD_LEAVE_CARD);
  memset(pslot, 0, sizeof(*pslot));
  slot->flags = 0;
  return SC_SUCCESS;
}

static int pcsc_lock(sc_reader_t *reader, sc_slot_info_t *slot)
{
  DWORD rv;
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

  SC_FUNC_CALLED(reader->ctx, 3);
  assert(pslot != NULL);

  rv = priv->gpriv->SCardBeginTransaction(pslot->pcsc_card);
  switch (rv) {
  case SCARD_E_INVALID_HANDLE:
  case SCARD_E_READER_UNAVAILABLE:
  case SCARD_E_SERVICE_STOPPED: /* AROC (@@20121106) � Prise en compte de l'arret de winscard en context smartcard logon */
#if defined (WIN32)
  case ERROR_INVALID_HANDLE:    /* BPER (@@201308005-1075) � Sous Windows, prise en compte de l'arret de winscard en context RDP */
#endif // WIN32
    rv = pcsc_connect(reader, slot);
    if (rv != SCARD_S_SUCCESS) {
      PCSC_ERROR(reader->ctx, "SCardConnect failed", rv);
      return pcsc_ret_to_error(rv);
    }
    /* Try de Lock again */
    rv = priv->gpriv->SCardBeginTransaction(pslot->pcsc_card);
    if (rv != SCARD_S_SUCCESS) {
      PCSC_ERROR(reader->ctx, "SCardBeginTransaction failed", rv);
      return SC_ERROR_READER_REATTACHED;
    }
    pslot->locked = 1;
    return SC_SUCCESS;
    /* AROC : 08/08/2011 - Debut :  EFFECTUER UNE RECONNECTION SUR CES ERREURS */
  case SCARD_W_REMOVED_CARD:
  case SCARD_E_INVALID_VALUE:
    /* AROC : 08/08/2011 - Fin */
  case SCARD_W_RESET_CARD:
    /* try to reconnect if the card was reset by some other application */
    rv = pcsc_reconnect(reader, slot, 0);
    if (rv != SCARD_S_SUCCESS) {
      PCSC_ERROR(reader->ctx, "SCardReconnect failed", rv);
      return pcsc_ret_to_error(rv);
    }
    /* return failure so that upper layers will be notified and try to lock again */
    /* AROC - (@@20130924-0001097) - Debut */
#if defined (WIN32)
      /* Try de Lock again */
    rv = priv->gpriv->SCardBeginTransaction(pslot->pcsc_card);
    if (rv != SCARD_S_SUCCESS) {
      PCSC_ERROR(reader->ctx, "SCardBeginTransaction failed", rv);
      return SC_ERROR_CARD_RESET;
    }
#else
    return SC_ERROR_CARD_RESET;
#endif //
    /* AROC - (@@20130924-0001097) - Fin*/
  case SCARD_S_SUCCESS:
    pslot->locked = 1;
    return SC_SUCCESS;
  default:
    PCSC_ERROR(reader->ctx, "SCardBeginTransaction failed", rv);
    return pcsc_ret_to_error(rv);
  }
}

static int pcsc_unlock(sc_reader_t *reader, sc_slot_info_t *slot)
{
  DWORD rv;
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

  SC_FUNC_CALLED(reader->ctx, 3);
  assert(pslot != NULL);

  rv = priv->gpriv->SCardEndTransaction(pslot->pcsc_card, priv->gpriv->transaction_reset ?
    SCARD_RESET_CARD : SCARD_LEAVE_CARD);
  pslot->locked = 0;
  if (rv != SCARD_S_SUCCESS) {
    PCSC_ERROR(reader->ctx, "SCardEndTransaction failed", rv);
    return pcsc_ret_to_error(rv);
  }
  return SC_SUCCESS;
}

static int pcsc_release(sc_reader_t *reader)
{
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

  free(priv->reader_name);
  free(priv);
  if (reader->slot[0].drv_data != NULL) {
    free(reader->slot[0].drv_data);
    reader->slot[0].drv_data = NULL;
  }
  return SC_SUCCESS;
}

static int pcsc_reset(sc_reader_t *reader, sc_slot_info_t *slot)
{
  int r;
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
  int old_locked = pslot->locked;

  r = pcsc_reconnect(reader, slot, 1);
  if (r != SCARD_S_SUCCESS)
    return pcsc_ret_to_error(r);

  /* pcsc_reconnect unlocks card... try to lock it again if it was locked */
  if (old_locked)
    r = pcsc_lock(reader, slot);

  return r;
}

static struct sc_reader_operations pcsc_ops;

static struct sc_reader_driver pcsc_drv = {
  "PC/SC reader",
  "pcsc",
  &pcsc_ops,
  0, 0, NULL
};

static int pcsc_init(sc_context_t *ctx, void **reader_data, int connect_reset)
{
  struct pcsc_global_private_data *gpriv;
  scconf_block *conf_block = NULL;
  int ret = SC_ERROR_INTERNAL;

  *reader_data = NULL;

  gpriv = (struct pcsc_global_private_data *) calloc(1, sizeof(struct pcsc_global_private_data));
  if (gpriv == NULL) {
    ret = SC_ERROR_OUT_OF_MEMORY;
    goto out;
  }

  /* Defaults */
  gpriv->connect_exclusive = 0;
  gpriv->transaction_reset = 0;
  gpriv->enable_pinpad = 0;
  gpriv->provider_library = DEFAULT_PCSC_PROVIDER;
  gpriv->pcsc_ctx = -1;

  conf_block = sc_get_conf_block(ctx, "reader_driver", "pcsc", 1);
  if (conf_block) {
    gpriv->connect_exclusive =
      scconf_get_bool(conf_block, "connect_exclusive", gpriv->connect_exclusive);
    gpriv->transaction_reset =
      scconf_get_bool(conf_block, "transaction_reset", gpriv->transaction_reset);
    gpriv->enable_pinpad =
      scconf_get_bool(conf_block, "enable_pinpad", gpriv->enable_pinpad);
    gpriv->provider_library =
      scconf_get_str(conf_block, "provider_library", gpriv->provider_library);
  }

  gpriv->connect_reset = connect_reset;

  gpriv->dlhandle = lt_dlopen(gpriv->provider_library);
  if (gpriv->dlhandle == NULL) {
    ret = SC_ERROR_CANNOT_LOAD_MODULE;
    goto out;
  }
  sc_debug(ctx, "Library handle being acquired: %x", gpriv->dlhandle);
  gpriv->SCardEstablishContext = (SCardEstablishContext_t)lt_dlsym(gpriv->dlhandle, "SCardEstablishContext");
#if defined (WIN32) || (__APPLE__)
  gpriv->SCardIsValidContext = (SCardIsValidContext_t)lt_dlsym(gpriv->dlhandle, "SCardIsValidContext");
#endif
  gpriv->SCardReleaseContext = (SCardReleaseContext_t)lt_dlsym(gpriv->dlhandle, "SCardReleaseContext");
  gpriv->SCardConnect = (SCardConnect_t)lt_dlsym(gpriv->dlhandle, "SCardConnect");
  gpriv->SCardReconnect = (SCardReconnect_t)lt_dlsym(gpriv->dlhandle, "SCardReconnect");
  gpriv->SCardDisconnect = (SCardDisconnect_t)lt_dlsym(gpriv->dlhandle, "SCardDisconnect");
  gpriv->SCardBeginTransaction = (SCardBeginTransaction_t)lt_dlsym(gpriv->dlhandle, "SCardBeginTransaction");
  gpriv->SCardEndTransaction = (SCardEndTransaction_t)lt_dlsym(gpriv->dlhandle, "SCardEndTransaction");
  gpriv->SCardStatus = (SCardStatus_t)lt_dlsym(gpriv->dlhandle, "SCardStatus");
  gpriv->SCardGetStatusChange = (SCardGetStatusChange_t)lt_dlsym(gpriv->dlhandle, "SCardGetStatusChange");
  gpriv->SCardTransmit = (SCardTransmit_t)lt_dlsym(gpriv->dlhandle, "SCardTransmit");
  gpriv->SCardListReaders = (SCardListReaders_t)lt_dlsym(gpriv->dlhandle, "SCardListReaders");

  if (gpriv->SCardConnect == NULL)
    gpriv->SCardConnect = (SCardConnect_t)lt_dlsym(gpriv->dlhandle, "SCardConnectA");
  if (gpriv->SCardStatus == NULL)
    gpriv->SCardStatus = (SCardStatus_t)lt_dlsym(gpriv->dlhandle, "SCardStatusA");
  if (gpriv->SCardGetStatusChange == NULL)
    gpriv->SCardGetStatusChange = (SCardGetStatusChange_t)lt_dlsym(gpriv->dlhandle, "SCardGetStatusChangeA");
  if (gpriv->SCardListReaders == NULL)
    gpriv->SCardListReaders = (SCardListReaders_t)lt_dlsym(gpriv->dlhandle, "SCardListReadersA");

  /* If we have SCardGetAttrib it is correct API */
  if (lt_dlsym(gpriv->dlhandle, "SCardGetAttrib") != NULL) {
#ifdef __APPLE__
    gpriv->SCardControl = (SCardControl_t)lt_dlsym(gpriv->dlhandle, "SCardControl132");
#endif
#ifdef PINPAD_READER
    if (gpriv->SCardControl == NULL) {
      gpriv->SCardControl = (SCardControl_t)lt_dlsym(gpriv->dlhandle, "SCardControl");
    }
#endif // PINPAD_READER
  }
  else {
    gpriv->SCardControlOLD = (SCardControlOLD_t)lt_dlsym(gpriv->dlhandle, "SCardControl");
  }

  if (
    gpriv->SCardReleaseContext == NULL ||
#if defined (WIN32) || (__APPLE__)
    gpriv->SCardIsValidContext == NULL ||
#endif
    gpriv->SCardConnect == NULL ||
    gpriv->SCardReconnect == NULL ||
    gpriv->SCardDisconnect == NULL ||
    gpriv->SCardBeginTransaction == NULL ||
    gpriv->SCardEndTransaction == NULL ||
    gpriv->SCardStatus == NULL ||
    gpriv->SCardGetStatusChange == NULL ||
#ifdef PINPAD_READER
    (gpriv->SCardControl == NULL && gpriv->SCardControlOLD == NULL) ||
#endif // PINPAD_READER
    gpriv->SCardTransmit == NULL ||
    gpriv->SCardListReaders == NULL
    ) {
    ret = SC_ERROR_CANNOT_LOAD_MODULE;
    goto out;
  }

  *reader_data = gpriv;
#ifdef __APPLE__
  gpriv->isYosemite = isYosemite(ctx);
#endif
  gpriv = NULL;
  ret = SC_SUCCESS;
  
out:
  if (gpriv != NULL) {
    if (gpriv->dlhandle != NULL)
      lt_dlclose(gpriv->dlhandle);
    free(gpriv);
  }

  return ret;
}

static int pcsc_finish(sc_context_t *ctx, void *prv_data)
{
  struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) prv_data;

  if (gpriv) {
    if (gpriv->pcsc_ctx != -1)
      gpriv->SCardReleaseContext(gpriv->pcsc_ctx);
    sc_debug(ctx, "Library handle to dispose: %x", gpriv->dlhandle);
    if (gpriv->dlhandle != NULL
      /* BPER (@@20150422-XXXX) - Ne pas liberer la lib Winscard en SmartCard Logon TSE (2012) */
#ifdef _WIN32
      && !g_winlogonProcess
#endif
      /* BPER (@@20150422-XXXX) - Ne pas liberer la lib Winscard en SmartCard Logon TSE (2012) - Fin */
      )
#ifndef __APPLE__
      lt_dlclose(gpriv->dlhandle);
#else
      ;
#endif
    free(gpriv);
  }

  return SC_SUCCESS;
}

static int pcsc_detect_readers(sc_context_t *ctx, void *prv_data)
{
  struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) prv_data;
  DWORD rv;
  DWORD reader_buf_size = 0;
  char *reader_buf = NULL, *reader_name;
  int ret = SC_ERROR_INTERNAL;
  /* CLCO 04/06/2010 : gestion de la déconnexion des lecteurs */
  unsigned int i, j;
  /* Utilisé pour mémoriser les lecteurs déconnectés depuis la dernière détection */
  sc_reader_t * deconnected_reader_list[256] = { 0 };
  /* CLCO 04/06/2010 : fin */
  sc_reader_t *reader = NULL;
  struct pcsc_private_data *priv = NULL;
  sc_slot_info_t *slot = NULL;
  struct pcsc_slot_data *pslot = NULL;


  SC_FUNC_CALLED(ctx, 3);

  if (!gpriv) {
    ret = SC_ERROR_NO_READERS_FOUND;
    goto out;
  }

  sc_debug(ctx, "Probing pcsc readers");

  /* CLCO 04/06/2010 : gestion de la déconnexion des lecteurs */
  /* Balayer la liste des lecteurs déjà identifiés */
  j = 0;
  for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
    sc_reader_t *reader2 = sc_ctx_get_reader(ctx, i);
    if (reader2 == NULL) {
      ret = SC_ERROR_INTERNAL;
      goto err1;
    }
    if (reader2->ops == &pcsc_ops) {
      if (!reader2->detected)
        deconnected_reader_list[j++] = reader2; /* Mémoriser les lecteurs déjà déconnectés */
      reader2->detected = 0; /* cela servira à détecter les nouveaux lecteurs déconnectés */
    }
  }
  /* CLCO 04/06/2010 : fin */

  do {
    if (gpriv->pcsc_ctx == -1) {
      /*
       * Cannot call SCardListReaders with -1
       * context as in Windows ERROR_INVALID_HANDLE
       * is returned instead of SCARD_E_INVALID_HANDLE
       */
      rv = SCARD_E_INVALID_HANDLE;
    }
#if defined (WIN32) || (__APPLE__)
    /* BPER (@@20141016-1195) - Ne pas lister les lecteurs si le service est indisponible */
    else if (gpriv->SCardIsValidContext(gpriv->pcsc_ctx) != SCARD_S_SUCCESS )
    {
      gpriv->pcsc_ctx = -1;
      rv = SCARD_E_INVALID_HANDLE;
    }
    /* BPER (@@20141016-1195) - Fin */
#endif
    else {
#ifdef __APPLE__
      /* Sous macOS il faut retablir une connexion afin de detecter le lecteurs connectes */
      if (sc_ctx_get_reader_count(ctx) == 0){
        SCardReleaseContext(gpriv->pcsc_ctx);
        SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &gpriv->pcsc_ctx);
      }
#endif // __APPLE__
      sc_debug(ctx, "SCardListReaders pcsc_ctx =0x%p, reader_buf_size=%d, ", gpriv->pcsc_ctx, reader_buf_size);
      rv = gpriv->SCardListReaders(gpriv->pcsc_ctx, NULL, NULL,
        (LPDWORD)&reader_buf_size);
    }
    if (rv != SCARD_S_SUCCESS) {
      /* AROC - (@@20121106) - Prise en compte de l'arret de winscard en context smartcard logon : Debut */
      if (rv != SCARD_E_INVALID_HANDLE && rv != SCARD_E_SERVICE_STOPPED
#ifdef _WIN32
        /* BPER (@@201308005-1075) � Sous Windows, prise en compte de l'arret de winscard en context RDP */
        && (rv != ERROR_INVALID_HANDLE)
        /* BPER (@@201308005-1075) � Fin */
#endif
        ) {
        /* AROC - (@@20121106) - Prise en compte de l'arret de winscard en context smartcard logon : Fin */
        PCSC_ERROR(ctx, "SCardListReaders failed (1)", rv);
        ret = pcsc_ret_to_error(rv);
        goto out;
      }

      sc_debug(ctx, "Establish pcsc context");

      rv = gpriv->SCardEstablishContext(SCARD_SCOPE_USER,
        NULL, NULL, &gpriv->pcsc_ctx);
      if (rv != SCARD_S_SUCCESS) {
        PCSC_ERROR(ctx, "SCardEstablishContext failed(2)", rv);
        ret = pcsc_ret_to_error(rv);
        goto out;
      }

      rv = SCARD_E_INVALID_HANDLE;
    }
  } while (rv != SCARD_S_SUCCESS);

  reader_buf = (char *)malloc(sizeof(char) * reader_buf_size);
  if (!reader_buf) {
    ret = SC_ERROR_OUT_OF_MEMORY;
    goto out;
  }
  rv = gpriv->SCardListReaders(gpriv->pcsc_ctx, NULL, reader_buf,
    (LPDWORD)&reader_buf_size);
  if (rv != SCARD_S_SUCCESS) {
    PCSC_ERROR(ctx, "SCardListReaders failed(2)", rv);
    ret = pcsc_ret_to_error(rv);
    goto out;
  }

  for (reader_name = reader_buf; *reader_name != '\x0'; reader_name += strlen(reader_name) + 1) {
    unsigned int i;
    int found = 0;
    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    int reconnected = 0;
    /* CLCO 04/06/2010 : fin */
    reader = NULL;
    priv = NULL;
    slot = NULL;
    pslot = NULL;

    /* AROC 25/03/2011 : Ne pas tenir compte des lecteurs PSS remontés par le drivers Galss sous MAC */
#if defined(__APPLE__)
    sc_debug(ctx, "Probing %s ", reader_name);
    if (!strncmp(reader_name, PSS_READERNAME, strlen(PSS_READERNAME))) {
      sc_debug(ctx, "Bypassing %s ", reader_name);
      continue;
    }
#endif
    /* AROC 25/03/2011 : Fin */

    for (i = 0; i < sc_ctx_get_reader_count(ctx) && !found; i++) {
      sc_reader_t *reader2 = sc_ctx_get_reader(ctx, i);
      if (reader2 == NULL) {
        ret = SC_ERROR_INTERNAL;
        goto err1;
      }
      if (reader2->ops == &pcsc_ops && !strcmp(reader2->name, reader_name)) {
        found = 1;
        /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
        reader2->detected = 1; /* le lecteur est donc bien connecté */
        /* rechercher dans la liste des lecteurs déconnectés pour savoir s'il s'agit d'une reconnexion */
        for (j = 0; deconnected_reader_list[j]; j++) {
          if (deconnected_reader_list[j] == reader2) {
            /* c'est un lecteur reconnecté, on le mémorise pour la suite des traitements */
            reconnected = 1;
            reader = reader2;
            break;
          }
        }
        /* CLCO 04/06/2010 : fin */
      }
    }

    /* Reader already available, skip */
    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    if (found && !reconnected) { /* s'il s'agit d'un lecteur reconnecté, il faut faire le ménage */
    /* CLCO 04/06/2010 : fin */
      continue;
    }

    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    if (!reconnected) {
      sc_debug(ctx, "Found new pcsc reader '%s'", reader_name);
      if ((reader = (sc_reader_t *)calloc(1, sizeof(sc_reader_t))) == NULL) {
        ret = SC_ERROR_OUT_OF_MEMORY;
        goto err1;
      }
    }
    else {
      /* il s'agit d'un lecteur reconnecté, il faut faire le ménage */
      sc_debug(ctx, "Found reconnected pcsc reader '%s'", reader_name);
      ret = pcsc_release(reader);
      if (ret)
        goto err1;
    }
    /* CLCO 04/06/2010 : fin */
    if ((priv = (struct pcsc_private_data *) malloc(sizeof(struct pcsc_private_data))) == NULL) {
      ret = SC_ERROR_OUT_OF_MEMORY;
      goto err1;
    }
    if ((pslot = (struct pcsc_slot_data *) malloc(sizeof(struct pcsc_slot_data))) == NULL) {
      ret = SC_ERROR_OUT_OF_MEMORY;
      goto err1;
    }

    reader->drv_data = priv;
    reader->ops = &pcsc_ops;
    reader->driver = &pcsc_drv;
    reader->slot_count = 1;
    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    reader->detected = 1; /* le lecteur est détecté forcément */
    /* CLCO 04/06/2010 : fin */
    if ((reader->name = strdup(reader_name)) == NULL) {
      ret = SC_ERROR_OUT_OF_MEMORY;
      goto err1;
    }
    priv->gpriv = gpriv;
    if ((priv->reader_name = strdup(reader_name)) == NULL) {
      ret = SC_ERROR_OUT_OF_MEMORY;
      goto err1;
    }
    slot = &reader->slot[0];
    memset(slot, 0, sizeof(*slot));
    slot->drv_data = pslot;
    memset(pslot, 0, sizeof(*pslot));
    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    if (!reconnected && _sc_add_reader(ctx, reader)) { /* on ajoute pas un lecteur reconnecté */
    /* CLCO 04/06/2010 : fin */
      ret = SC_SUCCESS;  /* silent ignore */
      goto err1;
    }
    refresh_slot_attributes(reader, slot);

    continue;

  err1:
    if (priv != NULL) {
      if (priv->reader_name)
        free(priv->reader_name);
      free(priv);
    }
    if (reader != NULL) {
      if (reader->name)
        free(reader->name);
      free(reader);
    }
    if (pslot != NULL)
      free(pslot);

    goto out;
  }

  ret = SC_SUCCESS;

out:

  if (reader_buf != NULL)
    free(reader_buf);

  SC_FUNC_RETURN(ctx, 3, ret);
}

void pcsc_get_status(struct sc_reader * reader, struct sc_slot_info *slot)
{
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
  LONG rv;
  SCARDHANDLE card;
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

  SC_FUNC_CALLED(reader->ctx, 3);
  assert(pslot != NULL);
  card = pslot->pcsc_card;

  SC_FUNC_CALLED(reader->ctx, 3);
  rv = priv->gpriv->SCardStatus(card,NULL,NULL,NULL,NULL,NULL,NULL);
  if (rv != SCARD_S_SUCCESS)
	  PCSC_ERROR(reader->ctx, "SCardStatus failed but no error raised", rv);

}
 /* AROC 08/04/2013 - Ajout de la fonction de tramsmission de donn�es de mani�re transparente */
static int pcsc_free_transmit (struct sc_reader * reader, struct sc_slot_info *slot,
                               const u8 * data, size_t   data_len,
                               u8 * out,  size_t * out_len, unsigned char ins_type)
{
  struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
  SCARD_IO_REQUEST sSendPci, sRecvPci;
  DWORD dwSendLength, dwRecvLength;
  LONG rv;
  SCARDHANDLE card;
  struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

  SC_FUNC_CALLED(reader->ctx, 3);
  assert(pslot != NULL);
  card = pslot->pcsc_card;

  sSendPci.dwProtocol = SCARD_PROTOCOL_T0;
  sSendPci.cbPciLength = sizeof(sSendPci);
  sRecvPci.dwProtocol = SCARD_PROTOCOL_T0;
  sRecvPci.cbPciLength = sizeof(sRecvPci);

  dwSendLength = (DWORD)data_len;
  dwRecvLength = (DWORD)*out_len;

  rv = priv->gpriv->SCardTransmit(card, &sSendPci, data, dwSendLength, &sRecvPci, out, &dwRecvLength);
  if (rv != SCARD_S_SUCCESS) {
    switch (rv) {
    case SCARD_W_REMOVED_CARD:
      return SC_ERROR_CARD_REMOVED;
    case SCARD_E_NOT_TRANSACTED:
      if (!(pcsc_detect_card_presence(reader, slot) & SC_SLOT_CARD_PRESENT))
        return SC_ERROR_CARD_REMOVED;
      return SC_ERROR_TRANSMIT_FAILED;
    default:
      /* Windows' PC/SC returns 0x8010002f (??) if a card is removed */
      if (pcsc_detect_card_presence(reader, slot) != 1)
        return SC_ERROR_CARD_REMOVED;
      PCSC_ERROR(reader->ctx, "SCardTransmit failed", rv);
      return SC_ERROR_TRANSMIT_FAILED;
    }
  }
  *out_len = dwRecvLength;

  return SC_SUCCESS;
}

struct sc_reader_driver * sc_get_pcsc_driver(void)
{
  pcsc_ops.init = pcsc_init;
  pcsc_ops.finish = pcsc_finish;
  pcsc_ops.detect_readers = pcsc_detect_readers;
  pcsc_ops.transmit = pcsc_transmit;
  pcsc_ops.detect_card_presence = pcsc_detect_card_presence;
  pcsc_ops.lock = pcsc_lock;
  pcsc_ops.unlock = pcsc_unlock;
  pcsc_ops.release = pcsc_release;
  pcsc_ops.connect = pcsc_connect;
  pcsc_ops.disconnect = pcsc_disconnect;
  pcsc_ops.perform_verify = NULL/*pcsc_pin_cmd*/;
  pcsc_ops.wait_for_event = pcsc_wait_for_event;
  pcsc_ops.reset = pcsc_reset;
  /* - Ajout de la fonction de tramsmission de donn�es de mani�re transparente */
  pcsc_ops.free_transmit = pcsc_free_transmit;
  pcsc_ops.get_status = pcsc_get_status;

  return &pcsc_drv;
}

#endif   /* HAVE_PCSC */

