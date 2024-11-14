/*
 * sec.c: Cryptography and security (ISO7816-8) functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "internal.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <assert.h>

int sc_decipher(sc_card_t *card,
    const u8 * crgram, size_t crgram_len, u8 * out, size_t outlen)
{
  int r;

  assert(card != NULL && crgram != NULL && out != NULL);
  SC_FUNC_CALLED(card->ctx, 2);
  if (card->ops->decipher == NULL)
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
  r = card->ops->decipher(card, crgram, crgram_len, out, outlen);
        SC_FUNC_RETURN(card->ctx, 2, r);
}

int sc_compute_signature(sc_card_t *card,
       const u8 * data, size_t datalen,
       u8 * out, size_t outlen)
{
  int r;

  assert(card != NULL);
  SC_FUNC_CALLED(card->ctx, 2);
  if (card->ops->compute_signature == NULL)
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
  r = card->ops->compute_signature(card, data, datalen, out, outlen);
        SC_FUNC_RETURN(card->ctx, 2, r);
}

/*
CLCO 12/04/2010 : Gestion IAS - Ajout de l'opÃ©ration de hashing faite par la carte pour la signature numÃ©rique.
*/
int sc_compute_hash(sc_card_t *card,
  const u8 * data, size_t datalen,
  const u8 * remainingdata, size_t remainingdatalen, size_t msglen)
{
  int r;

  assert(card != NULL);
  SC_FUNC_CALLED(card->ctx, 2);
  if (card->ops->compute_hash == NULL)
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
  r = card->ops->compute_hash(card, data, datalen, remainingdata, remainingdatalen, msglen);
  SC_FUNC_RETURN(card->ctx, 2, r);
}
/*
CLCO 12/04/2010 : Fin.
*/

int sc_internal_authenticate(sc_card_t *card,
    const u8 * data, size_t datalen,
    u8 * out, size_t outlen)
{
  int r;

  assert(card != NULL);
  SC_FUNC_CALLED(card->ctx, 2);
  if (card->ops->internal_authenticate == NULL)
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
  r = card->ops->internal_authenticate(card, data, datalen, out, outlen);
  SC_FUNC_RETURN(card->ctx, 2, r);
} 

int sc_set_security_env(sc_card_t *card,
      const sc_security_env_t *env,
      int se_num)
{
  int r;

  assert(card != NULL);
  SC_FUNC_CALLED(card->ctx, 2);
  if (card->ops->set_security_env == NULL)
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
  r = card->ops->set_security_env(card, env, se_num);
        SC_FUNC_RETURN(card->ctx, 2, r);
}


/* CLCO 03/06/2010 : Ajout d'une fonction pour la récupération du nombre d'essais restant pour un code PIN */
int sc_get_pin_counter(sc_card_t *card, sc_pin_counter_t *pin_counter)
{
  int r;

  assert(card != NULL);
  SC_FUNC_CALLED(card->ctx, 2);
  if (card->ops->get_pin_counter == NULL)
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
  r = card->ops->get_pin_counter(card, pin_counter);
  SC_FUNC_RETURN(card->ctx, 2, r);
}
/* CLCO 03/06/2010 : Fin */

int sc_logout(sc_card_t *card)
{
  if (card->ops->logout == NULL)
    return SC_ERROR_NOT_SUPPORTED;
  return card->ops->logout(card);
}

/*
 * This is the new style pin command, which takes care of all PIN
 * operations.
 * If a PIN was given by the application, the card driver should
 * send this PIN to the card. If no PIN was given, the driver should
 * ask the reader to obtain the pin(s) via the pin pad
 */
int sc_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
    int *tries_left)
{
  int r;

  assert(card != NULL);
  SC_FUNC_CALLED(card->ctx, 2);
  if (card->ops->pin_cmd) {
    r = card->ops->pin_cmd(card, data, tries_left);
  } else if (!(data->flags & SC_PIN_CMD_USE_PINPAD)) {
    /* Card driver doesn't support new style pin_cmd, fall
     * back to old interface */

    r = SC_ERROR_NOT_SUPPORTED;
    switch (data->cmd) {
    case SC_PIN_CMD_VERIFY:
      if (card->ops->verify != NULL)
        r = card->ops->verify(card,
          data->pin_type,
          data->pin_reference,
          data->pin1.data,
          (size_t) data->pin1.len,
          tries_left);
      break;
    case SC_PIN_CMD_CHANGE:
      if (card->ops->change_reference_data != NULL)
        r = card->ops->change_reference_data(card,
          data->pin_type,
          data->pin_reference,
          data->pin1.data,
          (size_t) data->pin1.len,
          data->pin2.data,
          (size_t) data->pin2.len,
          tries_left);
      break;
    case SC_PIN_CMD_UNBLOCK:
      if (card->ops->reset_retry_counter != NULL)
        r = card->ops->reset_retry_counter(card,
          data->pin_type,
          data->pin_reference,
          data->pin1.data,
          (size_t) data->pin1.len,
          data->pin2.data,
          (size_t) data->pin2.len);
      break;
    }
    if (r == SC_ERROR_NOT_SUPPORTED)
      sc_error(card->ctx, "unsupported PIN operation (%d)",
          data->cmd);
  } else {
    sc_error(card->ctx, "Use of pin pad not supported by card driver");
    r = SC_ERROR_NOT_SUPPORTED;
  }
  /* AROC (@@20140625-1175) - Lorsque le nombre de tentavie déblocage a ete atteint, il n'est plus possible de se logger ne SO : Debut */
  if (r == SC_ERROR_NOT_ALLOWED) r = SC_ERROR_AUTH_METHOD_BLOCKED;
  /* AROC (@@20140625-1175) - Lorsque le nombre de tentavie déblocage a ete atteint, il n'est plus possible de se logger ne SO : Fin */
  SC_FUNC_RETURN(card->ctx, 2, r);
}

/*
 * This function will copy a PIN, convert and pad it as required
 *
 * Note about the SC_PIN_ENCODING_GLP encoding:
 * PIN buffers are allways 16 nibbles (8 bytes) and look like this:
 *   0x2 + len + pin_in_BCD + paddingnibbles
 * in which the paddingnibble = 0xF
 * E.g. if PIN = 12345, then sbuf = {0x24, 0x12, 0x34, 0x5F, 0xFF, 0xFF, 0xFF, 0xFF}
 * E.g. if PIN = 123456789012, then sbuf = {0x2C, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xFF}
 * Reference: Global Platform - Card Specification - version 2.0.1' - April 7, 2000
 */
int sc_build_pin(u8 *buf, size_t buflen, struct sc_pin_cmd_pin *pin, int pad)
{
  size_t i = 0, j, pin_len = pin->len;

  if (pin->max_length && pin_len > pin->max_length)
    return SC_ERROR_INVALID_ARGUMENTS;

  if (pin->encoding == SC_PIN_ENCODING_GLP) {
    while (pin_len > 0 && pin->data[pin_len - 1] == 0xFF)
      pin_len--;
    if (pin_len > 12)
      return SC_ERROR_INVALID_ARGUMENTS;
    for (i = 0; i < pin_len; i++) {
      if (pin->data[i] < '0' || pin->data[i] > '9')
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    buf[0] = (u8)(0x20 | pin_len);
    buf++;
    buflen--;
  }

  /* PIN given by application, encode if required */
  if (pin->encoding == SC_PIN_ENCODING_ASCII) {
    if (pin_len > buflen)
      return SC_ERROR_BUFFER_TOO_SMALL;
    memcpy(buf, pin->data, pin_len);
    i = pin_len;
  } else if (pin->encoding == SC_PIN_ENCODING_BCD || pin->encoding == SC_PIN_ENCODING_GLP) {
    if (pin_len > 2 * buflen)
      return SC_ERROR_BUFFER_TOO_SMALL;
    for (i = j = 0; j < pin_len; j++) {
      buf[i] <<= 4;
      buf[i] |= pin->data[j] & 0xf;
      if (j & 1)
        i++;
    }
    if (j & 1) {
      buf[i] <<= 4;
      buf[i] |= pin->pad_char & 0xf;
      i++;
    }
  }

  /* Pad to maximum PIN length if requested */
  if (pad || pin->encoding == SC_PIN_ENCODING_GLP) {
    size_t pad_length = pin->pad_length;
    u8     pad_char   = pin->encoding == SC_PIN_ENCODING_GLP ? 0xFF : pin->pad_char;

    if (pin->encoding == SC_PIN_ENCODING_BCD)
      pad_length >>= 1;
    if (pin->encoding == SC_PIN_ENCODING_GLP)
      pad_length = 8;

    if (pad_length > buflen)
      return SC_ERROR_BUFFER_TOO_SMALL;

    if (pad_length && i < pad_length) {
      memset(buf + i, pad_char, pad_length - i);
      i = pad_length;
    }
  }

  return (int)i;
}
