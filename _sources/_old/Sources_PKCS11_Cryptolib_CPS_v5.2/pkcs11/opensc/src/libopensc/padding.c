/*
 * padding.c: miscellaneous padding functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003 - 2007  Nils Larsch <larsch@trustcenter.de>
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
#include <string.h>
#include <stdlib.h>
#ifdef ENABLE_OPENSSL
#include "openssl/ossl_typ.h"
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/rand.h"
#endif
#include "pkcs11/pkcs11.h"

static EVP_MD* mgf1_flag2md(sc_context_t* ctx, unsigned long mgf1);
static EVP_MD* hash_flag2md(sc_context_t* ctx, unsigned long hash);

 /*
  * Prefixes for pkcs-v1 signatures
  */
static const u8 hdr_md5[] = {
  0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
static const u8 hdr_sha1[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
  0x05, 0x00, 0x04, 0x14
};
static const u8 hdr_sha256[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const u8 hdr_sha384[] = {
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
static const u8 hdr_sha512[] = {
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};
static const u8 hdr_sha224[] = {
  0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};
static const u8 hdr_ripemd160[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01,
  0x05, 0x00, 0x04, 0x14
};


static const struct digest_info_prefix {
  unsigned int  algorithm;
  const u8 *  hdr;
  size_t    hdr_len;
  size_t    hash_len;
} digest_info_prefix[] = {
      { SC_ALGORITHM_RSA_HASH_NONE,     NULL,           0,                      0      },
      {  SC_ALGORITHM_RSA_HASH_MD5,  hdr_md5,  sizeof(hdr_md5),  16  },
      { SC_ALGORITHM_RSA_HASH_SHA1,  hdr_sha1,  sizeof(hdr_sha1),  20  },
      { SC_ALGORITHM_RSA_HASH_SHA256,  hdr_sha256,  sizeof(hdr_sha256),  32  },
      { SC_ALGORITHM_RSA_HASH_SHA384,  hdr_sha384,  sizeof(hdr_sha384),  48  },
      { SC_ALGORITHM_RSA_HASH_SHA512,  hdr_sha512,  sizeof(hdr_sha512),  64  },
      { SC_ALGORITHM_RSA_HASH_SHA224,  hdr_sha224,  sizeof(hdr_sha224),  28  },
      { SC_ALGORITHM_RSA_HASH_RIPEMD160,hdr_ripemd160,  sizeof(hdr_ripemd160),  20  },
      { SC_ALGORITHM_RSA_HASH_MD5_SHA1,  NULL,    0,      36  },
      {  0,        NULL,    0,      0  }
};

static inline EVP_MD* sc_evp_md(void* unused, const char* algorithm)
{
  return (EVP_MD*)EVP_get_digestbyname(algorithm);
}

static inline void sc_evp_md_free(EVP_MD* md)
{
  return;
}

/* add/remove pkcs1 BT01 padding */
static int sc_pkcs1_add_01_padding(const u8 *in, size_t in_len,
  u8 *out, size_t *out_len, size_t mod_length)
{
  size_t i;

  if (*out_len < mod_length)
    return SC_ERROR_BUFFER_TOO_SMALL;
  if (in_len + 11 > mod_length)
    return SC_ERROR_INVALID_ARGUMENTS;
  i = mod_length - in_len;
  memmove(out + i, in, in_len);
  *out++ = 0x00;
  *out++ = 0x01;

  memset(out, 0xFF, i - 3);
  out += i - 3;
  *out = 0x00;

  *out_len = mod_length;
  return SC_SUCCESS;
}

/* remove pkcs1 BT02 padding (adding BT02 padding is currently not
 * needed/implemented) */
int sc_pkcs1_strip_02_padding(const u8 *data, size_t len, u8 *out,
  size_t *out_len)
{
  unsigned int  n = 0;

  if (data == NULL || len < 3)
    return SC_ERROR_INTERNAL;
  /* skip leading zero byte */
  if (*data == 0) {
    data++;
    len--;
  }
  if (data[0] != 0x02)
    return SC_ERROR_WRONG_PADDING;
  /* skip over padding bytes */
  for (n = 1; n < len && data[n]; n++)
    ;
  /* Must be at least 8 pad bytes */
  if (n >= len || n < 9)
    return SC_ERROR_WRONG_PADDING;
  n++;
  if (out == NULL)
    /* just check the padding */
    return SC_SUCCESS;
  /* Now move decrypted contents to head of buffer */
  if (*out_len < len - n)
    return SC_ERROR_INTERNAL;
  memmove(out, data + n, len - n);
  return (int)(len - n);
}

/* add/remove DigestInfo prefix */
static int sc_pkcs1_add_digest_info_prefix(unsigned int algorithm,
  const u8 *in, size_t in_len, u8 *out, size_t *out_len)
{
  int i;

  for (i = 0; digest_info_prefix[i].algorithm != 0; i++) {
    if (algorithm == digest_info_prefix[i].algorithm) {
      const u8 *hdr = digest_info_prefix[i].hdr;
      size_t    hdr_len = digest_info_prefix[i].hdr_len,
        hash_len = digest_info_prefix[i].hash_len;
      if (in_len != hash_len ||
        *out_len < (hdr_len + hash_len))
        return SC_ERROR_INTERNAL;
      memmove(out + hdr_len, in, hash_len);
      memmove(out, hdr, hdr_len);
      *out_len = hdr_len + hash_len;
      return SC_SUCCESS;
    }
  }

  return SC_ERROR_INTERNAL;
}

int sc_pkcs1_strip_digest_info_prefix(unsigned int *algorithm,
  const u8 *in_dat, size_t in_len, u8 *out_dat, size_t *out_len)
{
  int i;

  for (i = 0; digest_info_prefix[i].algorithm != 0; i++) {
    size_t    hdr_len = digest_info_prefix[i].hdr_len,
      hash_len = digest_info_prefix[i].hash_len;
    const u8 *hdr = digest_info_prefix[i].hdr;

    if (in_len == (hdr_len + hash_len) &&
      !memcmp(in_dat, hdr, hdr_len)) {
      if (algorithm)
        *algorithm = digest_info_prefix[i].algorithm;
      if (out_dat == NULL)
        /* just check the DigestInfo prefix */
        return SC_SUCCESS;
      if (*out_len < hash_len)
        return SC_ERROR_INTERNAL;
      memmove(out_dat, in_dat + hdr_len, hash_len);
      *out_len = hash_len;
      return SC_SUCCESS;
    }
  }
  return SC_ERROR_INTERNAL;
}

static int hash_len2algo(size_t hash_len)
{
  switch (hash_len) {
  case SHA_DIGEST_LENGTH:
    return SC_ALGORITHM_RSA_HASH_SHA1;
  case SHA224_DIGEST_LENGTH:
    return SC_ALGORITHM_RSA_HASH_SHA224;
  case SHA256_DIGEST_LENGTH:
    return SC_ALGORITHM_RSA_HASH_SHA256;
  case SHA384_DIGEST_LENGTH:
    return SC_ALGORITHM_RSA_HASH_SHA384;
  case SHA512_DIGEST_LENGTH:
    return SC_ALGORITHM_RSA_HASH_SHA512;
  }
  /* Should never happen -- the mechanism and data should be already
   * verified to match one of the above. If not, we will fail later
   */
  return SC_ALGORITHM_RSA_HASH_NONE;
}

/* large enough up to RSA 4096 */
#define PSS_MAX_SALT_SIZE 512

/* add PKCS#1 v2.0 PSS padding */
static int sc_pkcs1_add_pss_padding(sc_context_t* scctx, unsigned int hash, unsigned int mgf1_hash,
  const u8* in, size_t in_len, u8* out, size_t* out_len, size_t mod_bits, size_t sLen)
{
  /* hLen = sLen in our case */
  int rv = SC_ERROR_INTERNAL, j, hlen;
  size_t dblen, plen, round, mgf_rounds, i;
  int mgf1_hlen;
  EVP_MD* md = NULL, * mgf1_md = NULL;
  EVP_MD_CTX* ctx = NULL;
  u8 buf[8];
  u8 salt[PSS_MAX_SALT_SIZE], mask[EVP_MAX_MD_SIZE];
  size_t mod_length = (mod_bits + 7) / 8;

  if (*out_len < mod_length)
    return SC_ERROR_BUFFER_TOO_SMALL;

  md = hash_flag2md(scctx, hash);
  if (md == NULL)
    return SC_ERROR_NOT_SUPPORTED;
  hlen = EVP_MD_size(md);
  dblen = mod_length - hlen - 1; /* emLen - hLen - 1 */
  plen = mod_length - sLen - hlen - 1;
  if (in_len != (unsigned)hlen) {
    sc_evp_md_free(md);
    return SC_ERROR_INVALID_ARGUMENTS;
  }
  if (sLen + (unsigned)hlen + 2 > mod_length) {
    /* RSA key too small for chosen hash (1296 bits or higher needed for
     * signing SHA-512 hashes) */
    sc_evp_md_free(md);
    return SC_ERROR_NOT_SUPPORTED;
  }
  if (sLen > PSS_MAX_SALT_SIZE) {
    sc_evp_md_free(md);
    return SC_ERROR_INVALID_ARGUMENTS;
  }
  if (RAND_bytes(salt, (unsigned)sLen) != 1) {
    sc_evp_md_free(md);
    return SC_ERROR_INTERNAL;
  }

  /* Hash M' to create H */
  if (!(ctx = EVP_MD_CTX_create()))
    goto done;
  memset(buf, 0x00, 8);
  if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
    EVP_DigestUpdate(ctx, buf, 8) != 1 ||
    EVP_DigestUpdate(ctx, in, hlen) != 1 || /* mHash */
    EVP_DigestUpdate(ctx, salt, sLen) != 1) {
    goto done;
  }

  /* Construct padding2, salt, H, and BC in the output block */
  /* DB = PS || 0x01 || salt */
  memset(out, 0x00, plen - 1); /* emLen - sLen - hLen - 2 */
  out[plen - 1] = 0x01;
  memcpy(out + plen, salt, sLen);
  if (EVP_DigestFinal_ex(ctx, out + dblen, NULL) != 1) { /* H */
    goto done;
  }
  out[dblen + hlen] = 0xBC;
  /* EM = DB* || H || 0xbc
   *  *the first part is masked later */

   /* Construct the DB mask block by block and XOR it in. */
  mgf1_md = mgf1_flag2md(scctx, mgf1_hash);
  if (mgf1_md == NULL)
    return SC_ERROR_NOT_SUPPORTED;
  mgf1_hlen = EVP_MD_size(mgf1_md);

  mgf_rounds = (dblen + mgf1_hlen - 1) / mgf1_hlen; /* round up */
  for (round = 0; round < mgf_rounds; ++round) {
    buf[0] = (u8)((round & 0xFF000000U) >> 24);
    buf[1] = (u8)((round & 0x00FF0000U) >> 16);
    buf[2] = (u8)((round & 0x0000FF00U) >> 8);
    buf[3] = (u8)((round & 0x000000FFU));
    if (EVP_DigestInit_ex(ctx, mgf1_md, NULL) != 1 ||
      EVP_DigestUpdate(ctx, out + dblen, hlen) != 1 || /* H (Z parameter of MGF1) */
      EVP_DigestUpdate(ctx, buf, 4) != 1 || /* C */
      EVP_DigestFinal_ex(ctx, mask, NULL) != 1) {
      goto done;
    }
    /* this is no longer part of the MGF1, but actually
     * XORing mask with DB to create maskedDB inplace */
    for (i = round * mgf1_hlen, j = 0; i < dblen && j < mgf1_hlen; ++i, ++j) {
      out[i] ^= mask[j];
    }
  }

  /* Set leftmost N bits in leftmost octet in maskedDB to zero
   * to make sure the result is smaller than the modulus ( +1)
   */
  out[0] &= (0xff >> (8 * mod_length - mod_bits + 1));

  *out_len = mod_length;
  rv = SC_SUCCESS;

done:
  OPENSSL_cleanse(salt, sizeof(salt));
  OPENSSL_cleanse(mask, sizeof(mask));
  sc_evp_md_free(md);
  sc_evp_md_free(mgf1_md);
  if (ctx) {
    EVP_MD_CTX_destroy(ctx);
  }
  return rv;
}

/* general PKCS#1 encoding function */
int sc_pkcs1_encode(sc_context_t *ctx, unsigned long flags,
  const u8 *in, size_t in_len, u8 *out, size_t *out_len, size_t mod_len, void* pMechanism)
{
  int    i;
  size_t tmp_len = *out_len;
  const u8    *tmp = in;
  unsigned int hash_algo, pad_algo;
#ifdef ENABLE_OPENSSL
  size_t sLen;
  EVP_MD* md = NULL;
  unsigned int mgf1_hash;
  size_t mod_bits = mod_len * 1024;
#endif

  hash_algo = flags & (SC_ALGORITHM_RSA_HASHES | SC_ALGORITHM_RSA_HASH_NONE);
  pad_algo = flags & SC_ALGORITHM_RSA_PADS;

  if (hash_algo != SC_ALGORITHM_RSA_HASH_NONE) {
    i = sc_pkcs1_add_digest_info_prefix(hash_algo, in, in_len,
      out, &tmp_len);
    if (i != SC_SUCCESS) {
      sc_error(ctx, "Unable to add digest info 0x%x\n",
        hash_algo);
      return i;
    }
    tmp = out;
  }
  else
    tmp_len = in_len;

  switch (pad_algo) {
  case SC_ALGORITHM_RSA_PAD_NONE:
    /* padding done by card => nothing to do */
    if (out != tmp)
      memcpy(out, tmp, tmp_len);
    *out_len = tmp_len;
    return SC_SUCCESS;
  case SC_ALGORITHM_RSA_PAD_PKCS1:
    /* add pkcs1 bt01 padding */
    return sc_pkcs1_add_01_padding(tmp, tmp_len, out, out_len,mod_len);

  case SC_ALGORITHM_RSA_PAD_PSS:
#ifdef ENABLE_OPENSSL
    mgf1_hash = flags & SC_ALGORITHM_MGF1_HASHES;
    if (hash_algo == SC_ALGORITHM_RSA_HASH_NONE) {
      /* this is generic RSA_PKCS1_PSS mechanism with hash
       * already done outside of the module. The parameters
       * were already checked so we need to adjust the hash
       * algorithm to do the padding with the correct hash
       * function.
       */
      hash_algo = hash_len2algo(tmp_len);
    }
    /* sLen is by default same as hash length */
    if (!(md = hash_flag2md(ctx, hash_algo)))
      return SC_ERROR_NOT_SUPPORTED;
    sLen = EVP_MD_size(md);
    sc_evp_md_free(md);
    /* if application provide sLen, use it */
    if (pMechanism != NULL) {
      CK_MECHANISM* mech = (CK_MECHANISM*)pMechanism;
      CK_RSA_PKCS_PSS_PARAMS* pss_params;
      if (mech->pParameter && sizeof(CK_RSA_PKCS_PSS_PARAMS) == mech->ulParameterLen) {
        pss_params = mech->pParameter;
        sLen = pss_params->sLen;
      }
    }
   return sc_pkcs1_add_pss_padding(ctx, hash_algo, mgf1_hash, tmp, tmp_len, out, out_len, mod_bits, sLen);
#else
    return SC_ERROR_NOT_SUPPORTED;
#endif
  default:
    /* currently only pkcs1 padding is supported */
    sc_error(ctx, "Unsupported padding algorithm 0x%x\n", pad_algo);
    return SC_ERROR_NOT_SUPPORTED;
  }
}

int sc_get_encoding_flags(sc_context_t *ctx,
  unsigned long iflags, unsigned long caps,
  unsigned long *pflags, unsigned long *sflags)
{
  size_t i;

  if (pflags == NULL || sflags == NULL)
    return SC_ERROR_INVALID_ARGUMENTS;

  for (i = 0; digest_info_prefix[i].algorithm != 0; i++) {
    if (iflags & digest_info_prefix[i].algorithm) {
      if (digest_info_prefix[i].algorithm != SC_ALGORITHM_RSA_HASH_NONE &&
        caps & digest_info_prefix[i].algorithm)
        *sflags |= digest_info_prefix[i].algorithm;
      else
        *pflags |= digest_info_prefix[i].algorithm;
      break;
    }
  }

  if (iflags & SC_ALGORITHM_RSA_PAD_PKCS1) {
    if (caps & SC_ALGORITHM_RSA_PAD_PKCS1)
      *sflags |= SC_ALGORITHM_RSA_PAD_PKCS1;
    else
      *pflags |= SC_ALGORITHM_RSA_PAD_PKCS1;
  }
  else if (iflags & SC_ALGORITHM_RSA_PAD_PSS && (caps & SC_ALGORITHM_RSA_PAD_PSS))
  {
    *sflags |= SC_ALGORITHM_RSA_PAD_PSS;
    *sflags |= iflags & SC_ALGORITHM_MGF1_HASHES;
   // *pflags = iflags & ~(iflags & (SC_ALGORITHM_MGF1_HASHES | SC_ALGORITHM_RSA_PAD_PSS));
    *pflags = 0;
  }
  else if ((iflags & SC_ALGORITHM_RSA_PADS) == SC_ALGORITHM_RSA_PAD_NONE) {
    if (!(caps & SC_ALGORITHM_RSA_RAW)) {
      sc_error(ctx, "raw RSA is not supported");
      return SC_ERROR_NOT_SUPPORTED;
    }
    *sflags |= SC_ALGORITHM_RSA_RAW;
    /* in case of raw RSA there is nothing to pad */
    *pflags = 0;
  }
  else {
    sc_error(ctx, "unsupported algorithm");
    return SC_ERROR_NOT_SUPPORTED;
  }

  return SC_SUCCESS;
}



static EVP_MD* hash_flag2md(sc_context_t* ctx, unsigned long hash)
{
  switch (hash & SC_ALGORITHM_RSA_HASHES) {
  case SC_ALGORITHM_RSA_HASH_SHA1:
    return sc_evp_md(ctx, "SHA1");
  case SC_ALGORITHM_RSA_HASH_SHA224:
    return sc_evp_md(ctx, "SHA224");
  case SC_ALGORITHM_RSA_HASH_SHA256:
    return sc_evp_md(ctx, "SHA256");
  case SC_ALGORITHM_RSA_HASH_SHA384:
    return sc_evp_md(ctx, "SHA384");
  case SC_ALGORITHM_RSA_HASH_SHA512:
    return sc_evp_md(ctx, "SHA512");
  default:
    return NULL;
  }
}

static EVP_MD* mgf1_flag2md(sc_context_t* ctx, unsigned long mgf1)
{
  switch (mgf1 & SC_ALGORITHM_MGF1_HASHES) {
  case SC_ALGORITHM_MGF1_SHA1:
    return sc_evp_md(ctx, "SHA1");
  case SC_ALGORITHM_MGF1_SHA224:
    return sc_evp_md(ctx, "SHA224");
  case SC_ALGORITHM_MGF1_SHA256:
    return sc_evp_md(ctx, "SHA256");
  case SC_ALGORITHM_MGF1_SHA384:
    return sc_evp_md(ctx, "SHA384");
  case SC_ALGORITHM_MGF1_SHA512:
    return sc_evp_md(ctx, "SHA512");
  default:
    return NULL;
  }
}