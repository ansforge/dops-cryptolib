/*
 * pkcs15-prkey.c: PKCS #15 private key functions
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
#include "pkcs15.h"
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

static const struct sc_asn1_entry c_asn1_com_key_attr[] = {
  { "iD",     SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
  { "usage",   SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
  { "native",   SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, NULL, NULL },
  { "accessFlags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
  { "keyReference",SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_com_prkey_attr[] = {
  /* FIXME */
{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_rsakey_attr[] = {
  { "value",     SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
  { "modulusLength", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
  { "keyInfo",     SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_prk_rsa_attr[] = {
  { "privateRSAKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_prkey[] = {
  { "privateRSAKey", SC_ASN1_PKCS15_OBJECT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

int sc_pkcs15_decode_prkdf_entry(struct sc_pkcs15_card *p15card,
struct sc_pkcs15_object *obj,
  const u8 ** buf, size_t *buflen)
{
  sc_context_t *ctx = p15card->card->ctx;
  struct sc_pkcs15_prkey_info info;
  int r;
  size_t usage_len = sizeof(info.usage);
  size_t af_len = sizeof(info.access_flags);
  struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_prkey_attr[1];
  struct sc_asn1_entry asn1_rsakey_attr[4], asn1_prk_rsa_attr[2];
  struct sc_asn1_entry asn1_prkey[4];
  struct sc_asn1_pkcs15_object rsa_prkey_obj = { obj, asn1_com_key_attr,
                   asn1_com_prkey_attr, asn1_prk_rsa_attr };

  sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);

  sc_copy_asn1_entry(c_asn1_prk_rsa_attr, asn1_prk_rsa_attr);
  sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);

  sc_copy_asn1_entry(c_asn1_com_prkey_attr, asn1_com_prkey_attr);
  sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

  sc_format_asn1_entry(asn1_prkey + 0, &rsa_prkey_obj, NULL, 0);

  sc_format_asn1_entry(asn1_prk_rsa_attr + 0, asn1_rsakey_attr, NULL, 0);

  sc_format_asn1_entry(asn1_rsakey_attr + 0, &info.path, NULL, 0);
  sc_format_asn1_entry(asn1_rsakey_attr + 1, &info.modulus_length, NULL, 0);

  sc_format_asn1_entry(asn1_com_key_attr + 0, &info.id, NULL, 0);
  sc_format_asn1_entry(asn1_com_key_attr + 1, &info.usage, &usage_len, 0);
  sc_format_asn1_entry(asn1_com_key_attr + 2, &info.native, NULL, 0);
  sc_format_asn1_entry(asn1_com_key_attr + 3, &info.access_flags, &af_len, 0);
  sc_format_asn1_entry(asn1_com_key_attr + 4, &info.key_reference, NULL, 0);

  /* Fill in defaults */
  memset(&info, 0, sizeof(info));
  info.key_reference = -1;
  info.native = 1;

  r = sc_asn1_decode_choice(ctx, asn1_prkey, *buf, *buflen, buf, buflen);
  if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
    return r;
  SC_TEST_RET(ctx, r, "ASN.1 decoding failed");
  if (asn1_prkey[0].flags & SC_ASN1_PRESENT) {
    obj->type = SC_PKCS15_TYPE_PRKEY_RSA;
  }
  else {
    sc_error(ctx, "Neither RSA or DSA or GOSTR3410 key in PrKDF entry.\n");
    SC_FUNC_RETURN(ctx, 0, SC_ERROR_INVALID_ASN1_OBJECT);
  }
  r = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &info.path);
  if (r < 0) {
    if (info.params)
      free(info.params);
    return r;
  }

  /* OpenSC 0.11.4 and older encoded "keyReference" as a negative
     value. Fixed in 0.11.5 we need to add a hack, so old cards
     continue to work. */
  if (p15card->flags & SC_PKCS15_CARD_FLAG_FIX_INTEGERS) {
    if (info.key_reference < -1) {
      info.key_reference += 256;
    }
  }

  obj->data = malloc(sizeof(info));
  if (obj->data == NULL) {
    if (info.params)
      free(info.params);
    SC_FUNC_RETURN(ctx, 0, SC_ERROR_OUT_OF_MEMORY);
  }
  memcpy(obj->data, &info, sizeof(info));

  return 0;
}

void sc_pkcs15_free_prkey_info(sc_pkcs15_prkey_info_t *key)
{
  if (key->subject)
    free(key->subject);
  if (key->params)
    free(key->params);
  free(key);
}
