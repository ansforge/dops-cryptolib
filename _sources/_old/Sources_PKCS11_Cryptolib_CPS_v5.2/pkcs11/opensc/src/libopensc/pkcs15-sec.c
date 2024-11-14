/*
 * pkcs15-sec.c: PKCS#15 cryptography functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyrigth (C) 2007        Nils Larsch <nils@larsch.net>
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "sysdef.h"

#define SIGN_SHA1_LEN               0x14
#define SIGN_SHA256_LEN             0x20

/* verify whether the input data length is that of a known hash */
static int sc_is_allowed_hash_length(size_t inlen) {
  if (inlen == SIGN_SHA1_LEN || inlen == SIGN_SHA256_LEN ) {
    return 1;
  }
  return 0;
}

static int select_key_file(struct sc_pkcs15_card *p15card,
         const struct sc_pkcs15_prkey_info *prkey,
         sc_security_env_t *senv)
{
  sc_path_t path, file_id;
  int r;

  if (prkey->path.len < 2)
    return SC_ERROR_INVALID_ARGUMENTS;
  /* For pkcs15-emulated cards, the file_app may be NULL,
     in that case we allways assume an absolute path */
  if (prkey->path.len == 2 && p15card->file_app != NULL) {
    /* Path is relative to app. DF */
    path = p15card->file_app->path;
    file_id = prkey->path;
    sc_append_path(&path, &file_id);
  } else {
    path = prkey->path;
    memcpy(file_id.value, prkey->path.value + prkey->path.len - 2, 2);
    file_id.len = 2;
    file_id.type = SC_PATH_TYPE_FILE_ID;
    file_id.index = 0;
    file_id.count = 0;
  }
  senv->file_ref = file_id;
  senv->flags |= SC_SEC_ENV_FILE_REF_PRESENT;
  r = sc_select_file(p15card->card, &path, NULL);
  SC_TEST_RET(p15card->card->ctx, r, "sc_select_file() failed");

  return 0;
}
 
int sc_pkcs15_decipher(struct sc_pkcs15_card *p15card,
           const struct sc_pkcs15_object *obj,
           unsigned long flags,
           const u8 * in, size_t inlen, u8 *out, size_t outlen)
{
  int r;
  sc_algorithm_info_t *alg_info;
  sc_security_env_t senv;
  sc_context_t *ctx = p15card->card->ctx;
  const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;
  unsigned long pad_flags = 0, sec_flags = 0;

  SC_FUNC_CALLED(ctx, 1);
  /* If the key is extractable, the caller should extract the
   * key and do the crypto himself */
  if (!prkey->native)
    return SC_ERROR_EXTRACTABLE_KEY;

  if (!(prkey->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP))) {
    sc_error(ctx, "This key cannot be used for decryption\n");
    return SC_ERROR_NOT_ALLOWED;
  }

  alg_info = _sc_card_find_rsa_alg(p15card->card, (int)prkey->modulus_length);
  if (alg_info == NULL) {
    sc_error(ctx, "Card does not support RSA with key length %d\n", prkey->modulus_length);
    return SC_ERROR_NOT_SUPPORTED;
  }
  senv.algorithm = SC_ALGORITHM_RSA;

  r = sc_get_encoding_flags(ctx, flags, alg_info->flags, &pad_flags, &sec_flags);
  if (r != SC_SUCCESS)
    return r;

  senv.algorithm_flags = sec_flags;
  senv.operation       = SC_SEC_OPERATION_DECIPHER;
  senv.flags           = 0;
  /* optional keyReference attribute (the default value is -1) */
  if (prkey->key_reference >= 0) {
    senv.key_ref_len = 1;
    senv.key_ref[0] = prkey->key_reference & 0xFF;
    senv.flags |= SC_SEC_ENV_KEY_REF_PRESENT;
  }
  senv.flags |= SC_SEC_ENV_ALG_PRESENT;

  r = sc_lock(p15card->card);
  SC_TEST_RET(ctx, r, "sc_lock() failed");

  if (prkey->path.len != 0)
  {
    r = select_key_file(p15card, prkey, &senv);
    if (r < 0) {
      sc_unlock(p15card->card);
      SC_TEST_RET(ctx,r,"Unable to select private key file");
    }
  }

  /* CLCO 07/04/2010 : identifiant d'algo */
  senv.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
  if (flags == SC_ALGORITHM_RSA_PAD_PKCS1) {
    senv.algorithm_ref = 0x1A; /* RSA PKCS#1 V2.1 */
  }
  
  r = sc_set_security_env(p15card->card, &senv, 0);
  if (r < 0) {
    sc_unlock(p15card->card);
    SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
  }
  r = sc_decipher(p15card->card, in, inlen, out, outlen);
  sc_unlock(p15card->card);
  SC_TEST_RET(ctx, r, "sc_decipher() failed");

  /* Strip any padding */
  if (pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
    r = sc_pkcs1_strip_02_padding(out, (size_t)r, out, (size_t *) &r);
    SC_TEST_RET(ctx, r, "Invalid PKCS#1 padding");
  }

  return r;
}

static int sc_is_cps4_auth_operation(const struct sc_pkcs15_card* p15card, const struct sc_pkcs15_prkey_info* prkey)
{
    if (p15card) {
        SC_FUNC_CALLED(p15card->card->ctx, 4);
        if (prkey && prkey->usage & SC_SEC_OPERATION_SIGN &&
            (prkey->key_reference & 0xFF) == CPS4_AUTH_PRIV_KEY_ID &&
            strcmp(p15card->card->name, "NXP") == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

int sc_pkcs15_compute_signature(struct sc_pkcs15_card* p15card,
  const struct sc_pkcs15_object* obj,
  unsigned long flags, const u8* in, size_t inlen,
  u8* out, size_t outlen)
{
  int r;
  sc_security_env_t senv;
  sc_context_t* ctx = p15card->card->ctx;
  sc_algorithm_info_t* alg_info;
  const struct sc_pkcs15_prkey_info* prkey = (const struct sc_pkcs15_prkey_info*)obj->data;
  u8 buf[512], * tmp;
  size_t modlen = prkey->modulus_length / 8;
  unsigned long pad_flags = 0, sec_flags = 0;


  SC_FUNC_CALLED(ctx, 1);

  /* some strange cards/setups need decrypt to sign ... */
  if (p15card->flags & SC_PKCS15_CARD_FLAG_SIGN_WITH_DECRYPT) {
    size_t tmplen = sizeof(buf);
    if (flags & SC_ALGORITHM_RSA_RAW) {
      return sc_pkcs15_decipher(p15card, obj, flags,
        in, inlen, out, outlen);
    }
    if (modlen > tmplen) {
      sc_error(ctx, "Buffer too small, needs recompile!\n");
      return SC_ERROR_NOT_ALLOWED;
    }
    r = sc_pkcs1_encode(ctx, flags, in, inlen, buf, &tmplen, modlen, NULL);

    /* no padding needed - already done */
    flags &= ~SC_ALGORITHM_RSA_PADS;
    /* instead use raw rsa */
    flags |= SC_ALGORITHM_RSA_RAW;

    SC_TEST_RET(ctx, r, "Unable to add padding");
    r = sc_pkcs15_decipher(p15card, obj, flags, buf, modlen,
      out, outlen);
    return r;
  }

  /* If the key is extractable, the caller should extract the
   * key and do the crypto himself */
  if (!prkey->native)
    return SC_ERROR_EXTRACTABLE_KEY;

  if (!(prkey->usage & (SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER |
    SC_PKCS15_PRKEY_USAGE_NONREPUDIATION))) {
    sc_error(ctx, "This key cannot be used for signing\n");
    return SC_ERROR_NOT_ALLOWED;
  }

  alg_info = _sc_card_find_rsa_alg(p15card->card, (int)prkey->modulus_length);
  if (alg_info == NULL) {
    sc_error(ctx, "Card does not support RSA with key length %d\n", prkey->modulus_length);
    return SC_ERROR_NOT_SUPPORTED;
  }
  senv.algorithm = SC_ALGORITHM_RSA;

  /* Probably never happens, but better make sure */
  if (inlen > sizeof(buf) || outlen < modlen)
    return SC_ERROR_BUFFER_TOO_SMALL;
  memcpy(buf, in, inlen);
  tmp = buf;

  /* flags: the requested algo
   * algo_info->flags: what is supported by the card
   * senv.algorithm_flags: what the card will have to do */

   /* If the card doesn't support the requested algorithm, see if we
    * can strip the input so a more restrictive algo can be used */
  if ((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) &&
    !(alg_info->flags & (SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_HASH_NONE))) {
    unsigned int algo;
    size_t tmplen = sizeof(buf);
    r = sc_pkcs1_strip_digest_info_prefix(&algo, tmp, inlen, tmp, &tmplen);
    if (r != SC_SUCCESS || algo == SC_ALGORITHM_RSA_HASH_NONE) {
      sc_mem_clear(buf, sizeof(buf));
      return SC_ERROR_INVALID_DATA;
    }
    flags &= ~SC_ALGORITHM_RSA_HASH_NONE;
    flags |= algo;
    inlen = tmplen;
  }
  sc_debug(ctx, "getting prkey->usage: 0x%02x", prkey->usage);
  /* For CPS signature private Key... */
  if (prkey->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION ) {
    /* And for CKM_RSA_PKS algorthim... */
    if (flags & (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) {

      /* if length is not that of SHA1 or SHA256 hash, check for DigestInfo presence and validity */
      if (inlen != 0 && !sc_is_allowed_hash_length(inlen)) {
        unsigned int algo;
        size_t tmplen = sizeof(buf);

        /* If DigestInfo present and valid, try to strip it */
        r = sc_pkcs1_strip_digest_info_prefix(&algo, tmp, inlen, tmp, &tmplen);
        if (r != SC_SUCCESS || algo == SC_ALGORITHM_RSA_HASH_NONE) {
          sc_mem_clear(buf, sizeof(buf));
          return SC_ERROR_INVALID_DATA;
        }

        sc_debug(ctx, "DigestInfo removed. Resulting data length = %lu\n", tmplen);
        inlen = tmplen;
      }
    }
  }

  r = sc_get_encoding_flags(ctx, flags, alg_info->flags, &pad_flags, &sec_flags);
  if (r != SC_SUCCESS) {
    sc_mem_clear(buf, sizeof(buf));
    return r;
  }
  senv.algorithm_flags = sec_flags;

  /* Pour la carte CPS il faut forcer le padding pour la méthode de déchiffrement */
  if (sc_is_cps4_auth_operation(p15card, prkey)) {
    if (flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
      pad_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
    }
  }

  /* add the padding bytes (if necessary) */
  if (pad_flags != 0) {
    size_t tmplen = sizeof(buf);
    r = sc_pkcs1_encode(ctx, pad_flags, tmp, inlen, tmp, &tmplen, modlen, NULL);
    SC_TEST_RET(ctx, r, "Unable to add padding");
    inlen = tmplen;
  }
  else if ((flags & SC_ALGORITHM_RSA_PADS) == SC_ALGORITHM_RSA_PAD_NONE) {
    /* Add zero-padding if input is shorter than the modulus */
    if (inlen < modlen) {
      if (modlen > sizeof(buf))
        return SC_ERROR_BUFFER_TOO_SMALL;
      memmove(tmp + modlen - inlen, tmp, inlen);
      memset(tmp, 0, modlen - inlen);
    }
  }


  senv.flags = 0;
  senv.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
  senv.flags |= SC_SEC_ENV_ALG_PRESENT;
  if (IS_CARD_TYPE_CPS3(p15card->card->type)) {
    if (prkey->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) { // Sign Key
      senv.operation = SC_SEC_OPERATION_SIGN;
      if (((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA1)) && (inlen == 0)) ||
        ((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) && (inlen == SIGN_SHA1_LEN))) {
        senv.algorithm_ref = 0x12;
      }
      else if (((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA256)) && (inlen == 0)) ||
        ((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) && (inlen == SIGN_SHA256_LEN))) {
        senv.algorithm_ref = 0x42;
      }
      else {
        sc_error(ctx, "This key cannot be used for signing (bad data)");
        return SC_ERROR_NOT_ALLOWED;
      }
    }
    else if ((prkey->usage & SC_PKCS15_PRKEY_USAGE_SIGN) && (flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE))) { // Auth Key
      senv.algorithm_ref = 0x02;
      senv.operation = SC_SEC_OPERATION_AUTHENTICATE;
    }
    else {
      sc_error(ctx, "This key cannot be used for signing (unknown key)");
      return SC_ERROR_NOT_ALLOWED;
    }
  }
  else {
    senv.operation = SC_SEC_OPERATION_SIGN;
    if (((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA1)) && (inlen == SIGN_SHA1_LEN)) ||
      ((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) && (inlen == SIGN_SHA1_LEN))) {
      senv.algorithm_ref = CPSV4_ALG_RSA_SHA_PKCS1;
    }
    else if (((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA256)) && (inlen == SIGN_SHA256_LEN)) ||
      ((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) && (inlen == SIGN_SHA256_LEN))) {
      senv.algorithm_ref = CPSV4_ALG_RSA_SHA_256_PKCS1;
    }
    else if (((flags == (SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_SHA1)) && (inlen == SIGN_SHA1_LEN)) ||
      ((flags == (SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_NONE)) && (inlen == SIGN_SHA1_LEN))) {
      senv.algorithm_ref = CPSV4_ALG_RSA_SHA_PKCS1_PSS;
    }
    else if (((flags == (SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_SHA256)) && (inlen == SIGN_SHA256_LEN)) ||
      ((flags == (SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_NONE)) && (inlen == SIGN_SHA256_LEN))) {
      senv.algorithm_ref = CPSV4_ALG_RSA_SHA_256_PKCS1_PSS;
    }
    else if ((prkey->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) != SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) {
      senv.operation = SC_SEC_OPERATION_AUTHENTICATE;
    }
  }


    /* optional keyReference attribute (the default value is -1) */
    if (prkey->key_reference >= 0) {
      senv.key_ref_len = 1;
      senv.key_ref[0] = prkey->key_reference & 0xFF;
      senv.flags |= SC_SEC_ENV_KEY_REF_PRESENT;
    }

    r = sc_lock(p15card->card);
    SC_TEST_RET(ctx, r, "sc_lock() failed");

    if (prkey->path.len != 0) {
      r = select_key_file(p15card, prkey, &senv);
      if (r < 0) {
        sc_unlock(p15card->card);
        SC_TEST_RET(ctx,r,"Unable to select private key file");
      }
    }


    r = sc_set_security_env(p15card->card, &senv, 0);
    if (r < 0) {
      sc_unlock(p15card->card);
      SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
    }

  if ((prkey->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) || (sc_is_cps4_auth_operation(p15card, prkey) && flags & SC_ALGORITHM_RSA_PAD_PSS)) {
    r = sc_compute_signature(p15card->card, tmp, inlen, out, outlen);
  }
  else if ((prkey->usage & SC_PKCS15_PRKEY_USAGE_SIGN) && (senv.operation == SC_SEC_OPERATION_AUTHENTICATE)) {
    r = sc_internal_authenticate(p15card->card, tmp, inlen, out, outlen);
}
  else {
    r = SC_ERROR_NOT_ALLOWED;
  }
  sc_mem_clear(buf, sizeof(buf));
  sc_unlock(p15card->card);
  SC_TEST_RET(ctx, r, "sc_compute_signature() failed");

    return r;
}

int sc_pkcs15_compute_hash(struct sc_pkcs15_card *p15card,
  unsigned long flags, const u8 *in, size_t inlen,
  const u8 *remainingmsg, size_t remainingmsglen, size_t msglen)
{
  int r;
  sc_security_env_t senv;
  sc_context_t *ctx = p15card->card->ctx;
  u8 buf[512], *tmp;
  u8 buf2[512], *tmp2;

  SC_FUNC_CALLED(ctx, 1);

  memcpy(buf, in, inlen);
  tmp = buf;
  memcpy(buf2, remainingmsg, remainingmsglen);
  tmp2 = buf2;

  senv.operation = SC_SEC_OPERATION_HASH;
  senv.flags = 0;
  /* CLCO 01/04/2010 : identifiant d'algo */
  senv.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
  if (flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA1)) {
    senv.algorithm_ref = 0x10; /* SHA-1 */
  }
  else if (flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA256)) {
    senv.algorithm_ref = 0x40; /* SHA-256 */
  }

  r = sc_lock(p15card->card);
  SC_TEST_RET(ctx, r, "sc_lock() failed");

  r = sc_set_security_env(p15card->card, &senv, 0);
  if (r < 0) {
    sc_unlock(p15card->card);
    SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
  }

  r = sc_compute_hash(p15card->card, tmp, inlen, tmp2, remainingmsglen, msglen);
  sc_mem_clear(buf, sizeof(buf));
  sc_mem_clear(buf2, sizeof(buf2));
  sc_unlock(p15card->card);
  SC_TEST_RET(ctx, r, "sc_compute_hash_signature() failed");

  return r;
}
