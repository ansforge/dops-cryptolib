/*
 * OpenSSL helper functions, e.g. for implementing MD5 support
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
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
 *
 */

#include <string.h>
#include "sc-pkcs11.h"

#ifdef ENABLE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/conf.h>
#include <openssl/opensslconf.h> /* for OPENSSL_NO_EC */
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif /* OPENSSL_NO_EC */
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */

static const unsigned char sha1_bin[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
  0x00, 0x04, 0x14
};

static const unsigned char sha224_bin[] = {
  0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};

static const unsigned char sha256_bin[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
  0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static CK_RV  sc_pkcs11_openssl_md_init(sc_pkcs11_operation_t *);
static CK_RV  sc_pkcs11_openssl_md_update(sc_pkcs11_operation_t *, CK_BYTE_PTR, CK_ULONG);
static CK_RV	sc_pkcs11_openssl_md_final(sc_pkcs11_operation_t *,
/* CLCO 20/05/2010 : modification pour gestion IAS, indiquer que le hash doit être partiel */
/* CK_BYTE_PTR, CK_ULONG_PTR);*/
   CK_BYTE_PTR, CK_ULONG_PTR, CK_CHAR);
/* CLCO 20/05/2010 : fin */
static int fips_rsa_verify(int dtype, const unsigned char* x, unsigned int y, unsigned char* sigbuf, unsigned int siglen, EVP_MD_SVCTX* sv);

static void  sc_pkcs11_openssl_md_release(sc_pkcs11_operation_t *);

static sc_pkcs11_mechanism_type_t openssl_sha1_mech = {
  CKM_SHA_1,
  { 0, 0, CKF_DIGEST }, 0,
  sizeof(struct sc_pkcs11_operation),
  sc_pkcs11_openssl_md_release,
  sc_pkcs11_openssl_md_init,
  sc_pkcs11_openssl_md_update,
  sc_pkcs11_openssl_md_final
};

#if OPENSSL_VERSION_NUMBER >= 0x00908000L
static sc_pkcs11_mechanism_type_t openssl_sha256_mech = {
  CKM_SHA256,
  { 0, 0, CKF_DIGEST }, 0,
  sizeof(struct sc_pkcs11_operation),
  sc_pkcs11_openssl_md_release,
  sc_pkcs11_openssl_md_init,
  sc_pkcs11_openssl_md_update,
  sc_pkcs11_openssl_md_final
};
#endif
/* CLCO 03/08/2010 : Désactivation des algorithmes non souhaités par l'ASIP */
/*static sc_pkcs11_mechanism_type_t openssl_sha384_mech = {
  CKM_SHA384,
  { 0, 0, CKF_DIGEST }, 0,
  sizeof(struct sc_pkcs11_operation),
  sc_pkcs11_openssl_md_release,
  sc_pkcs11_openssl_md_init,
  sc_pkcs11_openssl_md_update,
  sc_pkcs11_openssl_md_final
};

static sc_pkcs11_mechanism_type_t openssl_sha512_mech = {
  CKM_SHA512,
  { 0, 0, CKF_DIGEST }, 0,
  sizeof(struct sc_pkcs11_operation),
  sc_pkcs11_openssl_md_release,
  sc_pkcs11_openssl_md_init,
  sc_pkcs11_openssl_md_update,
  sc_pkcs11_openssl_md_final
};
#endif
*/
void
sc_pkcs11_register_openssl_mechanisms(struct sc_pkcs11_card *card)
{

  openssl_sha1_mech.mech_data = EVP_sha1();
  sc_pkcs11_register_mechanism(card, &openssl_sha1_mech);
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
  openssl_sha256_mech.mech_data = EVP_sha256();
  sc_pkcs11_register_mechanism(card, &openssl_sha256_mech);
  /* CLCO 03/08/2010 : Désactivation des algorithmes non souhaités par l'ASIP */
  /*openssl_sha384_mech.mech_data = EVP_sha384();
  sc_pkcs11_register_mechanism(card, &openssl_sha384_mech);
  openssl_sha512_mech.mech_data = EVP_sha512();
  sc_pkcs11_register_mechanism(card, &openssl_sha512_mech);*/
  /* CLCO 03/08/2010 : Fin */
#endif
}


/*
 * Handle OpenSSL digest functions
 */
#define DIGEST_CTX(op) \
  ((EVP_MD_CTX *) (op)->priv_data)

static CK_RV sc_pkcs11_openssl_md_init(sc_pkcs11_operation_t *op)
{
  sc_pkcs11_mechanism_type_t *mt;
  EVP_MD_CTX  *md_ctx;
  EVP_MD    *md;

  if (!op || !(mt = op->type) || !(md = (EVP_MD *)mt->mech_data))
    return CKR_ARGUMENTS_BAD;

  if (!(md_ctx = (EVP_MD_CTX *)calloc(1, sizeof(*md_ctx))))
    return CKR_HOST_MEMORY;
  EVP_DigestInit(md_ctx, md);
  op->priv_data = md_ctx;
  return CKR_OK;
}

static CK_RV sc_pkcs11_openssl_md_update(sc_pkcs11_operation_t *op,
  CK_BYTE_PTR pData, CK_ULONG pDataLen)
{
  EVP_DigestUpdate(DIGEST_CTX(op), pData, pDataLen);
  return CKR_OK;
}

/* CLCO 20/05/2010 : modification pour gestion IAS, indiquer que le hash doit être partiel */
#ifndef HOST_l2c
#define HOST_l2c(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff),	\
			 *((c)++)=(unsigned char)(((l)    )&0xff),	\
			 l)
#endif
#define HASH_MAKE_STRING(c,s)   do {	\
	unsigned long ll;		\
	ll=(c)->h0; HOST_l2c(ll,(s));	\
	ll=(c)->h1; HOST_l2c(ll,(s));	\
	ll=(c)->h2; HOST_l2c(ll,(s));	\
	ll=(c)->h3; HOST_l2c(ll,(s));	\
	ll=(c)->h4; HOST_l2c(ll,(s));	\
	} while (0)
#define	HASH256_MAKE_STRING(c,s)	do {	\
	unsigned long ll;		\
	unsigned int  xn;		\
	switch ((c)->md_len)		\
	{   case SHA224_DIGEST_LENGTH:	\
		for (xn=0;xn<SHA224_DIGEST_LENGTH/4;xn++)	\
		{   ll=(c)->h[xn]; HOST_l2c(ll,(s));   }	\
		break;			\
	    case SHA256_DIGEST_LENGTH:	\
		for (xn=0;xn<SHA256_DIGEST_LENGTH/4;xn++)	\
		{   ll=(c)->h[xn]; HOST_l2c(ll,(s));   }	\
		break;			\
	    default:			\
		if ((c)->md_len > SHA256_DIGEST_LENGTH)	\
		    return 0;				\
		for (xn=0;xn<(c)->md_len/4;xn++)		\
		{   ll=(c)->h[xn]; HOST_l2c(ll,(s));   }	\
		break;			\
	}				\
	} while (0)
/* CLCO 20/05/2010 : fin */


static CK_RV sc_pkcs11_openssl_md_final(sc_pkcs11_operation_t *op,
/* CLCO 20/05/2010 : modification pour gestion IAS, indiquer que le hash doit être partiel */
/*  CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) */
  CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen, CK_CHAR partial)
/* CLCO 20/05/2010 : fin */
{
  EVP_MD_CTX  *md_ctx = DIGEST_CTX(op);
  unsigned int	len = (unsigned int)(*pulDigestLen);

  if (*pulDigestLen < (CK_ULONG)EVP_MD_CTX_size(md_ctx)) {
    *pulDigestLen = EVP_MD_CTX_size(md_ctx);
    return CKR_BUFFER_TOO_SMALL;
  }
  /* CLCO 20/05/2010 : modification pour gestion IAS, indiquer que le hash doit être partiel */
  if (partial) {
    /* Récupérer depuis les données du contexte de l'algo de hashing les valeurs du hash partiel */
    if (op->type->mech == CKM_SHA_1) {
      CK_BYTE buff[SHA_DIGEST_LENGTH];
      CK_BYTE_PTR pTemp = pDigest;
      SHA_CTX *sha_ctx = (SHA_CTX *)md_ctx->md_data;

      HASH_MAKE_STRING(sha_ctx, pTemp);

      EVP_DigestFinal(md_ctx, buff, &len);
    }
    else if (op->type->mech == CKM_SHA256) {
      CK_BYTE buff[SHA256_DIGEST_LENGTH];
      CK_BYTE_PTR pTemp = pDigest;
      SHA256_CTX *sha_ctx = (SHA256_CTX *)md_ctx->md_data;

      HASH256_MAKE_STRING(sha_ctx, pTemp);

      EVP_DigestFinal(md_ctx, buff, &len);
    }
    else {
      EVP_DigestFinal(md_ctx, pDigest, &len);
    }
  }
  else {
    EVP_DigestFinal(md_ctx, pDigest, &len);
  }
  /* CLCO 20/05/2010 : fin */
  *pulDigestLen = len;

  return CKR_OK;
}

static void sc_pkcs11_openssl_md_release(sc_pkcs11_operation_t *op)
{
  EVP_MD_CTX  *md_ctx = DIGEST_CTX(op);

  if (md_ctx)
    free(md_ctx);
  op->priv_data = NULL;
}

static int do_convert_bignum(sc_pkcs15_bignum_t *dst, BIGNUM *src)
{
  if (src == 0)
    return 0;
  dst->len = BN_num_bytes(src);
  dst->data = (u8 *)malloc(dst->len);
  if (dst->data == NULL)
    return 0;
  BN_bn2bin(src, dst->data);
  return 1;
}

CK_RV sc_pkcs11_gen_keypair_soft(struct sc_context *context /* BPER 1381 Solution C */,
  CK_KEY_TYPE keytype, CK_ULONG keybits,
struct sc_pkcs15_prkey *privkey,
struct sc_pkcs15_pubkey *pubkey)
{
  switch (keytype) {
  case CKK_RSA: {
    RSA  *rsa;
    BIO  *err;
    struct sc_pkcs15_prkey_rsa  *sc_priv = &privkey->u.rsa;
    struct sc_pkcs15_pubkey_rsa *sc_pub = &pubkey->u.rsa;

    err = BIO_new(BIO_s_mem());
    rsa = RSA_generate_key(keybits, 0x10001, NULL, err);
    BIO_free(err);
    if (rsa == NULL) {
      sc_debug(context, "RSA_generate_key() failed\n");
      return CKR_FUNCTION_FAILED;
    }

    privkey->algorithm = pubkey->algorithm = SC_ALGORITHM_RSA;

    if (!do_convert_bignum(&sc_priv->modulus, rsa->n)
      || !do_convert_bignum(&sc_priv->exponent, rsa->e)
      || !do_convert_bignum(&sc_priv->d, rsa->d)
      || !do_convert_bignum(&sc_priv->p, rsa->p)
      || !do_convert_bignum(&sc_priv->q, rsa->q)) {
      sc_debug(context, "do_convert_bignum() failed\n");
      RSA_free(rsa);
      return CKR_FUNCTION_FAILED;
    }
    if (rsa->iqmp && rsa->dmp1 && rsa->dmq1) {
      do_convert_bignum(&sc_priv->iqmp, rsa->iqmp);
      do_convert_bignum(&sc_priv->dmp1, rsa->dmp1);
      do_convert_bignum(&sc_priv->dmq1, rsa->dmq1);
    }

    if (!do_convert_bignum(&sc_pub->modulus, rsa->n)
      || !do_convert_bignum(&sc_pub->exponent, rsa->e)) {
      sc_debug(context, "do_convert_bignum() failed\n");
      RSA_free(rsa);
      return CKR_FUNCTION_FAILED;
    }

    RSA_free(rsa);

    break;
  }
  default:
    return CKR_MECHANISM_PARAM_INVALID;
  }

  return CKR_OK;
}

/* CPS4 perform RSA PSS signature verification suitable for OpenSSL v0.9.x */
static CK_RV sc_pkcs11_rsa_pss_verify(struct sc_context* pcontext,EVP_MD_CTX* md_ctx, CK_MECHANISM mech, const sc_pkcs11_operation_t* md, EVP_PKEY* pkey,
    unsigned char* data, int data_len,
    unsigned char* signat, int signat_len) {
    /*assume verification is ok*/
    CK_RSA_PKCS_PSS_PARAMS* rsaPkcsPssParams;
    CK_RV rv=CKR_OK;
    int res;
    int salt_flag = 0;
    int saltlen;
    int dtype;
    EVP_MD_SVCTX* psv;

    if (md_ctx == NULL || md == NULL || pkey == NULL || signat == NULL) {
        return CKR_FUNCTION_FAILED;
    }
    rsaPkcsPssParams = (CK_RSA_PKCS_PSS_PARAMS*)mech.pParameter;
    if (rsaPkcsPssParams == NULL) {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    SC_FUNC_CALLED(pcontext, 3);
    sc_debug(pcontext, "with paramters: md_ctx=%p, md=%p, pkey=%p",md_ctx, md, pkey);
    
    saltlen = rsaPkcsPssParams->sLen;
    if (md_ctx->digest->md_size == saltlen) salt_flag = EVP_MD_CTX_FLAG_PSS_MDLEN;
    dtype = (mech.mechanism == CKM_SHA1_RSA_PKCS_PSS) ? NID_sha1 : NID_sha256;
    psv = OPENSSL_malloc(sizeof(EVP_MD_SVCTX));
    if (psv == NULL) {
        return CKR_HOST_MEMORY;
    }
    psv->key = (RSA*)(pkey->pkey.rsa);
    M_EVP_MD_CTX_set_flags(md_ctx, EVP_MD_CTX_FLAG_PAD_PSS | (salt_flag << 16));
    psv->mctx = md_ctx;
    res = fips_rsa_verify(dtype, data, data_len, signat, signat_len, psv);
    if (!res) {
        sc_debug(pcontext, "fips_rsa_verify failed: res=%d", res);
        rv = CKR_SIGNATURE_INVALID;
    }
    OPENSSL_cleanse(psv, sizeof(EVP_MD_SVCTX));
    OPENSSL_free(psv);
    return rv;
}

/* If no hash function was used, finish with RSA_public_decrypt().
 * If a hash function was used, we can make a big shortcut by
 *   finishing with EVP_VerifyFinal().
 */
CK_RV sc_pkcs11_verify_data(struct sc_context *pcontext /* BPER 1381 Solution C */, const unsigned char *pubkey, int pubkey_len,
  const unsigned char *pubkey_params, int pubkey_params_len,
  CK_MECHANISM mech, sc_pkcs11_operation_t *md,
  unsigned char *data, int data_len,
  unsigned char *signat, int signat_len)
{
  int res;
  CK_RV rv = CKR_GENERAL_ERROR;
  EVP_PKEY *pkey;

  if (mech.mechanism == CKM_GOSTR3410)
  {
    (void)pubkey_params, (void)pubkey_params_len; /* no warning */
    return CKR_FUNCTION_NOT_SUPPORTED;
  }

  pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &pubkey, pubkey_len);
  if (pkey == NULL)
    return CKR_GENERAL_ERROR;

  if (md != NULL) {
    EVP_MD_CTX *md_ctx = DIGEST_CTX(md);

    if (mech.mechanism == CKM_SHA1_RSA_PKCS_PSS || mech.mechanism == CKM_SHA256_RSA_PKCS_PSS) {
        return sc_pkcs11_rsa_pss_verify(pcontext,md_ctx,mech,md,pkey,data,data_len,signat,signat_len);
    }

    res = EVP_VerifyFinal(md_ctx, signat, signat_len, pkey);
    EVP_PKEY_free(pkey);
    if (res == 1)
      return CKR_OK;
    else if (res == 0)
      return CKR_SIGNATURE_INVALID;
    else {
      sc_debug(pcontext, "EVP_VerifyFinal() returned %d\n", res); // BPER 1381 - Solution C
      return CKR_GENERAL_ERROR;
    }
  }
  else {
    RSA *rsa;
    unsigned char *rsa_out = NULL, pad;
    int rsa_outlen = 0;

    switch (mech.mechanism) {
    case CKM_RSA_PKCS:
      pad = RSA_PKCS1_PADDING;
      break;
    case CKM_RSA_X_509:
      pad = RSA_NO_PADDING;
      break;
    default:
      return CKR_ARGUMENTS_BAD;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (rsa == NULL)
      return CKR_DEVICE_MEMORY;

    rsa_out = (unsigned char *)malloc(RSA_size(rsa));
    if (rsa_out == NULL) {
      free(rsa);
      return CKR_DEVICE_MEMORY;
    }

    rsa_outlen = RSA_public_decrypt(signat_len, signat, rsa_out, rsa, pad);
    RSA_free(rsa);
    if (rsa_outlen <= 0) {
      free(rsa_out);
      sc_debug(pcontext, "RSA_public_decrypt() returned %d\n", rsa_outlen); // BPER 1381 - Solution C
      return CKR_GENERAL_ERROR;
    }

    if (rsa_outlen == data_len && memcmp(rsa_out, data, data_len) == 0)
      rv = CKR_OK;
    else
      rv = CKR_SIGNATURE_INVALID;

    free(rsa_out);
  }

  return rv;
}

static const unsigned char* fips_digestinfo_encoding(int nid, unsigned int* len)
{
    switch (nid)
    {

    case NID_sha1:
        *len = sizeof(sha1_bin);
        return sha1_bin;

    case NID_sha256:
        *len = sizeof(sha256_bin);
        return sha256_bin;

    default:
        return NULL;

    }
}

static const unsigned char* fips_digestinfo_nn_encoding(int nid, unsigned int* len)
{
    switch (nid)
    {

    case NID_sha1:
        *len = sizeof(sha1_bin);
        return sha1_bin;

    case NID_sha256:
        *len = sizeof(sha256_bin);
        return sha256_bin;

    default:
        return NULL;

    }
}

static int fips_rsa_verify(int dtype,
    const unsigned char* x, unsigned int y,
    unsigned char* sigbuf, unsigned int siglen,
    EVP_MD_SVCTX* sv)
{
    int i, ret = 0;
    unsigned int dlen, diglen;
    int pad_mode = sv->mctx->flags & EVP_MD_CTX_FLAG_PAD_MASK;
    int rsa_pad_mode = 0;
    unsigned char* s;
    const unsigned char* der;
    unsigned char dig[EVP_MAX_MD_SIZE];
    RSA* rsa = (RSA*)sv->key;

    if (siglen != (unsigned int)RSA_size(sv->key)) {
        RSAerr(RSA_F_FIPS_RSA_VERIFY, RSA_R_WRONG_SIGNATURE_LENGTH);
        return (0);
    }

    ret = EVP_DigestFinal_ex(sv->mctx, dig, &diglen);

    if ((rsa->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_verify) {
        return rsa->meth->rsa_verify(dtype, dig, diglen, sigbuf, siglen, rsa);
    }

    s = OPENSSL_malloc((unsigned int)siglen);
    if (s == NULL) {
        RSAerr(RSA_F_FIPS_RSA_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (pad_mode == EVP_MD_CTX_FLAG_PAD_X931)
        rsa_pad_mode = RSA_X931_PADDING;
    else if (pad_mode == EVP_MD_CTX_FLAG_PAD_PKCS1)
        rsa_pad_mode = RSA_PKCS1_PADDING;
    else if (pad_mode == EVP_MD_CTX_FLAG_PAD_PSS)
        rsa_pad_mode = RSA_NO_PADDING;

    /* NB: call underlying method directly to avoid FIPS blocking */
    i = rsa->meth->rsa_pub_dec((int)siglen, sigbuf, s, rsa, rsa_pad_mode);

    if (i <= 0)
        goto err;

    if (pad_mode == EVP_MD_CTX_FLAG_PAD_X931) {
        int hash_id;
        if (i != (int)(diglen + 1)) {
            RSAerr(RSA_F_FIPS_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }
        hash_id = RSA_X931_hash_id(M_EVP_MD_CTX_type(sv->mctx));
        if (hash_id == -1) {
            RSAerr(RSA_F_FIPS_RSA_VERIFY, RSA_R_UNKNOWN_ALGORITHM_TYPE);
            goto err;
        }
        if (s[diglen] != (unsigned char)hash_id) {
            RSAerr(RSA_F_FIPS_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }
        if (memcmp(s, dig, diglen)) {
            RSAerr(RSA_F_FIPS_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }
        ret = 1;
    }
    else if (pad_mode == EVP_MD_CTX_FLAG_PAD_PKCS1) {

        der = fips_digestinfo_encoding(dtype, &dlen);

        if (!der) {
            RSAerr(RSA_F_FIPS_RSA_VERIFY, RSA_R_UNKNOWN_ALGORITHM_TYPE);
            return (0);
        }

        /*
         * Compare, DigestInfo length, DigestInfo header and finally digest
         * value itself
         */

         /* If length mismatch try alternate encoding */
        if (i != (int)(dlen + diglen))
            der = fips_digestinfo_nn_encoding(dtype, &dlen);

        if ((i != (int)(dlen + diglen)) || memcmp(der, s, dlen)
            || memcmp(s + dlen, dig, diglen)) {
            RSAerr(RSA_F_FIPS_RSA_VERIFY, RSA_R_BAD_SIGNATURE);
            goto err;
        }
        ret = 1;

    }
    else if (pad_mode == EVP_MD_CTX_FLAG_PAD_PSS) {
        int saltlen;
        saltlen = M_EVP_MD_CTX_FLAG_PSS_SALT(sv->mctx);
        if (saltlen == EVP_MD_CTX_FLAG_PSS_MDLEN)
            saltlen = -1;
        else if (saltlen == EVP_MD_CTX_FLAG_PSS_MREC)
            saltlen = -2;
        ret = RSA_verify_PKCS1_PSS(rsa, dig, M_EVP_MD_CTX_md(sv->mctx),
            s, saltlen);
        if (ret < 0)
            ret = 0;
    }
err:
    if (s != NULL) {
        OPENSSL_cleanse(s, siglen);
        OPENSSL_free(s);
    }
    return (ret);
}

CK_RV sc_pkcs11_encrypt_data(struct sc_context* pcontext /* BPER 1381 Solution C */, const unsigned char* pubkey, int pubkey_len,
    CK_MECHANISM_TYPE mech, sc_pkcs11_operation_t* md,
    unsigned char* data, int data_len,
    unsigned char* p_encrypt, CK_ULONG_PTR p_enc_len)
{
    CK_RV rv = CKR_OK;
    EVP_PKEY* pkey;
    RSA* rsa;
    unsigned char* rsa_out = NULL, pad;
    int rsa_outlen = 0;

    if (p_encrypt == NULL || p_enc_len == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (mech) {
    case CKM_RSA_PKCS:
        pad = RSA_PKCS1_PADDING;
        break;
    case CKM_RSA_X_509:
        pad = RSA_NO_PADDING;
        break;
    default:
        sc_debug(pcontext, "RSA encryption invalid mechanism: %d", mech);
        return CKR_MECHANISM_INVALID;
    }

    pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &pubkey, pubkey_len);
    if (pkey == NULL)
        return CKR_GENERAL_ERROR;

    rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (rsa == NULL)
        return CKR_DEVICE_MEMORY;

    rsa_out = (unsigned char*)malloc(RSA_size(rsa));
    if (rsa_out == NULL) {
        free(rsa);
        return CKR_DEVICE_MEMORY;
    }

    rsa_outlen = RSA_public_encrypt(data_len, data, rsa_out, rsa, pad);

    if (rsa_outlen <= 0) {
        sc_debug(pcontext, "RSA encryption failed: %d", rsa_outlen);
        free(rsa);
        return CKR_FUNCTION_FAILED;
    }

    *p_enc_len = rsa_outlen;
    memcpy(p_encrypt, rsa_out, rsa_outlen);
    free(rsa_out);
    free(rsa);

    return rv;
}

/* Tests whether the current mechanism is an
 * Openssl bult-in one.
 */
int is_openssl_mecha(sc_pkcs11_mechanism_type_t * pCurMecha)
{
  return (pCurMecha == &openssl_sha1_mech
#if OPENSSL_VERSION_NUMBER >= 0x00908000L    
    || pCurMecha == &openssl_sha256_mech);
#else
    );
#endif
}
#endif
