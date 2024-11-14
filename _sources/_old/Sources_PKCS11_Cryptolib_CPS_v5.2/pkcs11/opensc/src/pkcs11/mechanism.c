/*
 * Generic handling of PKCS11 mechanisms
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

#include <stdlib.h>
#include <string.h>
#include <openssl/opensslv.h>
#include "sc-pkcs11.h"

 /* Also used for verification data */
struct hash_signature_info {
  CK_MECHANISM_TYPE  mech;
  CK_MECHANISM_TYPE  hash_mech;
  CK_MECHANISM_TYPE  sign_mech;
  sc_pkcs11_mechanism_type_t *hash_type;
  sc_pkcs11_mechanism_type_t *sign_type;
};

/* Also used for verification and decryption data */
struct signature_data {
  struct sc_pkcs11_object *key;
  struct hash_signature_info *info;
  sc_pkcs11_operation_t *  md;
  CK_BYTE      buffer[4096 / 8];
  unsigned int    buffer_len;
  /*
  CLCO 12/04/2010 : Gestion IAS - Ajout des données pour l'opération de hashing faite par la carte lors de la signature numérique.
  */
  CK_BYTE			remaining_msg[64];
  unsigned int		remaining_msg_len;
  size_t				msg_len;
  /*
  CLCO 12/04/2010 : Fin.
  */
};

/*
 * Register a mechanism
 */
CK_RV
sc_pkcs11_register_mechanism(struct sc_pkcs11_card *p11card, sc_pkcs11_mechanism_type_t *mt)
{
  sc_pkcs11_mechanism_type_t ** mechlist;
  sc_pkcs11_mechanism_type_t *curmt;
  unsigned int n;

  mechlist = p11card->mechanisms;

  if (mt == NULL)
    return CKR_HOST_MEMORY;

  for (n = 0; n < p11card->nmechanisms; n++) {
    curmt = p11card->mechanisms[n];
    if (curmt != NULL && curmt->mech == mt->mech)
      return CKR_OK;
  }

  mechlist[p11card->nmechanisms++] = mt;
  mechlist[p11card->nmechanisms] = NULL;
  return CKR_OK;
}

/*
 * Look up a mechanism
 */
sc_pkcs11_mechanism_type_t *
sc_pkcs11_find_mechanism(struct sc_pkcs11_card *p11card, CK_MECHANISM_TYPE mech, int flags)
{
  sc_pkcs11_mechanism_type_t *mt;
  unsigned int n;

  for (n = 0; n < p11card->nmechanisms; n++) {
    mt = p11card->mechanisms[n];
    if (mt && mt->mech == mech && ((mt->mech_info.flags & flags) == flags))
      return mt;
  }
  return NULL;
}

#define TEST_PARAM(p11card, pMecha)  if ((pMech)->pParameter == NULL || (pMech)->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS)) SC_FUNC_RETURN((p11card)->card->ctx, 4, CKR_MECHANISM_PARAM_INVALID);

/*
 * Look up a mechanism parameter
 */
CK_RV
sc_pkcs11_check_parameter(struct sc_pkcs11_card* p11card, CK_MECHANISM_PTR pMech, int flags)
{
    CK_RV rv = CKR_OK;
    CK_RSA_PKCS_PSS_PARAMS* rsaPkcsPssParams;
    if (pMech->mechanism == CKM_RSA_PKCS_PSS) {
        TEST_PARAM(p11card, pMech)
        rsaPkcsPssParams = (CK_RSA_PKCS_PSS_PARAMS*)pMech->pParameter;
        if (rsaPkcsPssParams->hashAlg != CKM_SHA_1 && rsaPkcsPssParams->hashAlg != CKM_SHA256) {
            rv = CKR_MECHANISM_PARAM_INVALID;
        }
    }
    else if (pMech->mechanism == CKM_SHA1_RSA_PKCS_PSS) {
        TEST_PARAM(p11card, pMech)
        rsaPkcsPssParams = (CK_RSA_PKCS_PSS_PARAMS*)pMech->pParameter;
        if (rsaPkcsPssParams->hashAlg != CKM_SHA_1) {
            rv = CKR_MECHANISM_PARAM_INVALID;
        }
    }
    else if (pMech->mechanism == CKM_SHA256_RSA_PKCS_PSS) {
        TEST_PARAM(p11card, pMech)
        rsaPkcsPssParams = (CK_RSA_PKCS_PSS_PARAMS*)pMech->pParameter;
        if (rsaPkcsPssParams->hashAlg != CKM_SHA256) {
            rv = CKR_MECHANISM_PARAM_INVALID;
        }
    }
    if (rv) SC_FUNC_RETURN(p11card->card->ctx, 4, rv);
    return rv;
}

/* CLCO 25/05/2010 : libérer la liste des mécanismes associées à cette carte pour éviter les doublons en cas de réintroduction */
/*
 * unregister all mechanisms
 */
CK_RV
sc_pkcs11_unregister_all_mechanisms(struct sc_pkcs11_card *p11card)
{
  unsigned int i;
  if (p11card != NULL){
    for ( i = 0; i < p11card->nmechanisms; i++) {
      sc_pkcs11_mechanism_type_t* pCurMeca = p11card->mechanisms[i];
      if (pCurMeca != NULL && !is_openssl_mecha(pCurMeca)){
        if (pCurMeca->mech_data != NULL) {
          free((void*)pCurMeca->mech_data);
          pCurMeca->mech_data = NULL;
        }
        free(pCurMeca);
        p11card->mechanisms[i] = NULL;
      }
    }
    p11card->nmechanisms = 0;
  }
  return CKR_OK;
}
/* CLCO 25/05/2010 : fin */

/*
 * Query mechanisms.
 * All of this is greatly simplified by having the framework
 * register all supported mechanisms at initialization
 * time.
 */
CK_RV
sc_pkcs11_get_mechanism_list(struct sc_pkcs11_card *p11card,
  CK_MECHANISM_TYPE_PTR pList,
  CK_ULONG_PTR pulCount)
{
  sc_pkcs11_mechanism_type_t *mt;
  unsigned int n, count = 0;
  int rv;

  for (n = 0; n < p11card->nmechanisms; n++) {
    if (!(mt = p11card->mechanisms[n]))
      continue;
    if (count < *pulCount && pList)
      pList[count] = mt->mech;
    count++;
  }

  rv = CKR_OK;
  if (pList && count > *pulCount)
    rv = CKR_BUFFER_TOO_SMALL;
  *pulCount = count;
  return rv;
}

CK_RV
sc_pkcs11_get_mechanism_info(struct sc_pkcs11_card *p11card,
  CK_MECHANISM_TYPE mechanism,
  CK_MECHANISM_INFO_PTR pInfo)
{
  sc_pkcs11_mechanism_type_t *mt;

  if (!(mt = sc_pkcs11_find_mechanism(p11card, mechanism, 0)))
    return CKR_MECHANISM_INVALID;
  memcpy(pInfo, &mt->mech_info, sizeof(*pInfo));
  return CKR_OK;
}

/*
 * Create/destroy operation handle
 */
sc_pkcs11_operation_t *
sc_pkcs11_new_operation(sc_pkcs11_session_t *session,
  sc_pkcs11_mechanism_type_t *type)
{
  sc_pkcs11_operation_t *res;

  res = (sc_pkcs11_operation_t *)calloc(1, type->obj_size);
  if (res) {
    res->session = session;
    res->type = type;
  }
  return res;
}

void
sc_pkcs11_release_operation(sc_pkcs11_operation_t **ptr)
{
  sc_pkcs11_operation_t *operation = *ptr;

  if (!operation)
    return;
  if (operation->type && operation->type->release)
    operation->type->release(operation);
  memset(operation, 0, sizeof(*operation));
  free(operation);
  *ptr = NULL;
}

CK_RV
sc_pkcs11_md_init(struct sc_pkcs11_session *session,
  CK_MECHANISM_PTR pMechanism)
{
  struct sc_pkcs11_card *p11card;
  sc_pkcs11_operation_t *operation;
  sc_pkcs11_mechanism_type_t *mt;
  int rv;

  if (!session || !session->slot
    || !(p11card = session->slot->card))
    return CKR_ARGUMENTS_BAD;

  /* See if we support this mechanism type */
  mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_DIGEST);
  if (mt == NULL)
    return CKR_MECHANISM_INVALID;

  rv = session_start_operation(session, SC_PKCS11_OPERATION_DIGEST, mt, &operation);
  if (rv != CKR_OK)
    return rv;

  memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));

  rv = mt->md_init(operation);
  if (rv == CKR_OK) {
    operation->already_feed_once = CK_FALSE;
  }

  if (rv != CKR_OK)
    session_stop_operation(session, SC_PKCS11_OPERATION_DIGEST);

  return rv;
}

CK_RV
sc_pkcs11_md_update(struct sc_pkcs11_session *session,
  CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BBOOL single_part)
{
  sc_pkcs11_operation_t *op;
  int rv;

  rv = session_get_operation(session, SC_PKCS11_OPERATION_DIGEST, &op);
  if (rv != CKR_OK)
    goto done;

  if (single_part == CK_TRUE) {
    /* si on est en single part, on ne provisionne les données qu'une seule fois */
    if (op->already_feed_once == CK_FALSE) {
      rv = op->type->md_update(op, pData, ulDataLen);
      if (rv == CKR_OK) {
        op->already_feed_once = CK_TRUE;
      }
    }
  }
  else {
    rv = op->type->md_update(op, pData, ulDataLen);
  }

done:
  if (rv != CKR_OK)
    session_stop_operation(session, SC_PKCS11_OPERATION_DIGEST);

  return rv;
}

CK_RV
sc_pkcs11_md_final(struct sc_pkcs11_session *session,
  CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
  sc_pkcs11_operation_t *op;
  int rv;

  rv = session_get_operation(session, SC_PKCS11_OPERATION_DIGEST, &op);
  if (rv != CKR_OK)
    return rv;

  /* This is a request for the digest length */
  if (pData == NULL)
    *pulDataLen = 0;


  /* CLCO 20/05/2010 : modification pour gestion IAS, indiquer que le hash doit être partiel */
  rv = op->type->md_final(op, pData, pulDataLen, 0);
  /* CLCO 20/05/2010 : fin */

  if (rv == CKR_BUFFER_TOO_SMALL)
    return pData == NULL ? CKR_OK : rv;

  session_stop_operation(session, SC_PKCS11_OPERATION_DIGEST);
  return rv;
}

/*
 * Initialize a signing context. When we get here, we know
 * the key object is capable of signing _something_
 */
CK_RV
sc_pkcs11_sign_init(struct sc_pkcs11_session *session,
  CK_MECHANISM_PTR pMechanism,
struct sc_pkcs11_object *key,
  CK_MECHANISM_TYPE key_type)
{
  struct sc_pkcs11_card *p11card;
  sc_pkcs11_operation_t *operation;
  sc_pkcs11_mechanism_type_t *mt;
  int rv;

  if (!session || !session->slot
    || !(p11card = session->slot->card))
    return CKR_ARGUMENTS_BAD;

  /* See if we support this mechanism type */
  mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_SIGN);
  if (mt == NULL)
    return CKR_MECHANISM_INVALID;

  rv = sc_pkcs11_check_parameter(p11card, pMechanism, 0);
  if (rv != CKR_OK)
      return rv;

  /* See if compatible with key type */
  if (mt->key_type != key_type)
    return CKR_KEY_TYPE_INCONSISTENT;

  rv = session_start_operation(session, SC_PKCS11_OPERATION_SIGN, mt, &operation);
  if (rv != CKR_OK)
    return rv;

  memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));
  rv = mt->sign_init(operation, key);

  if (rv != CKR_OK)
    session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

  return rv;
}

CK_RV
sc_pkcs11_sign_update(struct sc_pkcs11_session *session,
  CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
  sc_pkcs11_operation_t *op;
  int rv;

  rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
  if (rv != CKR_OK)
    return rv;

  if (op->type->sign_update == NULL) {
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto done;
  }

  rv = op->type->sign_update(op, pData, ulDataLen);

done:
  if (rv != CKR_OK)
    session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

  return rv;
}

CK_RV
sc_pkcs11_sign_final(struct sc_pkcs11_session *session,
  CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
  sc_pkcs11_operation_t *op;
  int rv;

  rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
  if (rv != CKR_OK)
    return rv;

  /* Bail out for signature mechanisms that don't do hashing */
  if (op->type->sign_final == NULL) {
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto done;
  }

  rv = op->type->sign_final(op, pSignature, pulSignatureLen);

done:
  if (rv != CKR_BUFFER_TOO_SMALL && pSignature != NULL)
    session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

  return rv;
}

CK_RV
sc_pkcs11_sign_size(struct sc_pkcs11_session *session, CK_ULONG_PTR pLength)
{
  sc_pkcs11_operation_t *op;
  int rv;

  rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
  if (rv != CKR_OK)
    return rv;

  /* Bail out for signature mechanisms that don't do hashing */
  if (op->type->sign_size == NULL) {
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto done;
  }

  rv = op->type->sign_size(op, pLength);

done:
  if (rv != CKR_OK)
    session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

  return rv;
}

/*
 * Initialize a signature operation
 */
static CK_RV
sc_pkcs11_signature_init(sc_pkcs11_operation_t *operation,
struct sc_pkcs11_object *key)
{
  struct hash_signature_info *info;
  struct signature_data *data;
  int rv;

  if (!(data = (struct signature_data *) calloc(1, sizeof(*data))))
    return CKR_HOST_MEMORY;

  data->info = NULL;
  data->key = key;

  /* If this is a signature with hash operation, set up the
   * hash operation */
  info = (struct hash_signature_info *) operation->type->mech_data;
  if (info != NULL) {
    /* Initialize hash operation */
    data->md = sc_pkcs11_new_operation(operation->session,
      info->hash_type);
    if (data->md == NULL)
      rv = CKR_HOST_MEMORY;
    else
      rv = info->hash_type->md_init(data->md);
    if (rv != CKR_OK) {
      sc_pkcs11_release_operation(&data->md);
      free(data);
      return rv;
    }
    data->info = info;
  }

  operation->priv_data = data;
  return CKR_OK;
}

static CK_RV
sc_pkcs11_signature_update(sc_pkcs11_operation_t *operation,
  CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
  struct signature_data *data;

  data = (struct signature_data *) operation->priv_data;
  if (data->md) {
    sc_pkcs11_operation_t  *md = data->md;

    /*
    CLCO 12/04/2010 : Gestion IAS - Ajout des données pour l'opération de hashing faite par la carte lors de la signature numérique.
    */
    CK_ULONG ulPartLenToHash = ulPartLen;
    if (strcmp(operation->session->slot->card->card->driver->name, "IAS") == 0) { /* Faire une fonction générique pour tester si carte IAS */
      int rv = 0;
      /* la taille du dernier bloc à hasher doit être < ou = à 64 octets */
      unsigned int new_remaining_msg_len = (data->remaining_msg_len + ulPartLen) % 64;
      if (new_remaining_msg_len == 0) {
        /* il y a dans ce cas un bloc de 64 octets */
        new_remaining_msg_len = 64;
      }
      if (data->remaining_msg_len != 0 &&
        (data->remaining_msg_len + ulPartLen - new_remaining_msg_len) >= 64) {
        /* il y avait déjà un précédent bloc en attente de hashing */
        rv = md->type->md_update(md, data->remaining_msg, data->remaining_msg_len);
        if (rv)
          return rv;
        data->msg_len += data->remaining_msg_len;
        /* raz des données à hasher */
        data->remaining_msg_len = 0;
      }
      /* Mettre à jour la longueur des données à hasher */
      ulPartLenToHash = ulPartLen>new_remaining_msg_len ? ulPartLen - new_remaining_msg_len : 0;

      /* Mémoriser les données du dernier bloc */
      memcpy(data->remaining_msg + data->remaining_msg_len, pPart + ulPartLenToHash,
        new_remaining_msg_len - data->remaining_msg_len);
      data->remaining_msg_len = new_remaining_msg_len;
      data->msg_len += ulPartLenToHash;
      /* S'il n'y a pas assez de données on ne hash rien */
      if (ulPartLenToHash == 0)
        return rv;
    }

    return md->type->md_update(md, pPart, ulPartLenToHash);
    /*
    CLCO 12/04/2010 : Fin.
    */


  }

  /* This signature mechanism operates on the raw data */
  if (data->buffer_len + ulPartLen > sizeof(data->buffer))
    return CKR_DATA_LEN_RANGE;
  memcpy(data->buffer + data->buffer_len, pPart, ulPartLen);
  data->buffer_len += ulPartLen;
  return CKR_OK;
}

static CK_RV
sc_pkcs11_signature_final(sc_pkcs11_operation_t *operation,
  CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
  struct signature_data *data;
  struct sc_pkcs11_object *key;
  int rv;

  data = (struct signature_data *) operation->priv_data;

  if (data->md) {
    sc_pkcs11_operation_t  *md = data->md;
    CK_ULONG len = sizeof(data->buffer);

    /* CLCO 20/05/2010 : modification pour gestion IAS, indiquer que le hash doit être partiel */
    rv = md->type->md_final(md, data->buffer, &len, data->remaining_msg_len ? 1 : 0);
    /* CLCO 20/05/2010 : fin */


    if (rv == CKR_BUFFER_TOO_SMALL)
      rv = CKR_FUNCTION_FAILED;
    if (rv != CKR_OK)
      return rv;
    data->buffer_len = len;
  }

  key = data->key;
  return key->ops->sign(operation->session,
    key, &operation->mechanism,
    data->buffer, data->buffer_len,
    pSignature, pulSignatureLen);
}

static CK_RV
sc_pkcs11_signature_size(sc_pkcs11_operation_t *operation, CK_ULONG_PTR pLength)
{
  struct sc_pkcs11_object *key;
  CK_ATTRIBUTE attr = { CKA_MODULUS_BITS, pLength, sizeof(*pLength) };
  CK_KEY_TYPE key_type;
  CK_ATTRIBUTE attr_key_type = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
  CK_RV rv;

  key = ((struct signature_data *) operation->priv_data)->key;
  rv = key->ops->get_attribute(operation->session, key, &attr);

  /* convert bits to bytes */
  if (rv == CKR_OK)
    *pLength = (*pLength + 7) / 8;

  if (rv == CKR_OK) {
    rv = key->ops->get_attribute(operation->session, key, &attr_key_type);
  }

  return rv;
}

static void
sc_pkcs11_signature_release(sc_pkcs11_operation_t *operation)
{
  struct signature_data *data;

  data = (struct signature_data *) operation->priv_data;
  if (data) {
    sc_pkcs11_release_operation(&data->md);
    memset(data, 0, sizeof(*data));
    free(data);
  }
}

#ifdef ENABLE_OPENSSL
/*
 * Initialize a verify context. When we get here, we know
 * the key object is capable of verifying _something_
 */
CK_RV
sc_pkcs11_verif_init(struct sc_pkcs11_session *session,
  CK_MECHANISM_PTR pMechanism,
struct sc_pkcs11_object *key,
  CK_MECHANISM_TYPE key_type)
{
  struct sc_pkcs11_card *p11card;
  sc_pkcs11_operation_t *operation;
  sc_pkcs11_mechanism_type_t *mt;
  int rv;

  if (!session || !session->slot
    || !(p11card = session->slot->card))
    return CKR_ARGUMENTS_BAD;

  /* See if we support this mechanism type */
  mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_VERIFY);
  if (mt == NULL)
    return CKR_MECHANISM_INVALID;

  /* See if compatible with key type */
  if (mt->key_type != key_type)
    return CKR_KEY_TYPE_INCONSISTENT;

  rv = session_start_operation(session, SC_PKCS11_OPERATION_VERIFY, mt, &operation);
  if (rv != CKR_OK)
    return rv;

  memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));
  rv = mt->verif_init(operation, key);

  if (rv != CKR_OK)
    session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);

  return rv;

}

CK_RV
sc_pkcs11_verif_update(struct sc_pkcs11_session *session,
  CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
  sc_pkcs11_operation_t *op;
  int rv;

  rv = session_get_operation(session, SC_PKCS11_OPERATION_VERIFY, &op);
  if (rv != CKR_OK)
    return rv;

  if (op->type->verif_update == NULL) {
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto done;
  }

  rv = op->type->verif_update(op, pData, ulDataLen);

done:
  if (rv != CKR_OK)
    session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);

  return rv;
}

CK_RV
sc_pkcs11_verif_final(struct sc_pkcs11_session *session,
  CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
  sc_pkcs11_operation_t *op;
  int rv;

  rv = session_get_operation(session, SC_PKCS11_OPERATION_VERIFY, &op);
  if (rv != CKR_OK)
    return rv;

  if (op->type->verif_final == NULL) {
    rv = CKR_KEY_TYPE_INCONSISTENT;
    goto done;
  }

  rv = op->type->verif_final(op, pSignature, ulSignatureLen);

done:
  session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);
  return rv;
}

/*
 * Initialize a signature operation
 */
static CK_RV
sc_pkcs11_verify_init(sc_pkcs11_operation_t *operation,
struct sc_pkcs11_object *key)
{
  struct hash_signature_info *info;
  struct signature_data *data;
  int rv;

  if (!(data = (struct signature_data *) calloc(1, sizeof(*data))))
    return CKR_HOST_MEMORY;

  data->info = NULL;
  data->key = key;

  /* If this is a verify with hash operation, set up the
   * hash operation */
  info = (struct hash_signature_info *) operation->type->mech_data;
  if (info != NULL) {
    /* Initialize hash operation */
    data->md = sc_pkcs11_new_operation(operation->session,
      info->hash_type);
    if (data->md == NULL)
      rv = CKR_HOST_MEMORY;
    else
      rv = info->hash_type->md_init(data->md);
    if (rv != CKR_OK) {
      sc_pkcs11_release_operation(&data->md);
      free(data);
      return rv;
    }
    data->info = info;
  }

  operation->priv_data = data;
  return CKR_OK;
}

static CK_RV
sc_pkcs11_verify_update(sc_pkcs11_operation_t *operation,
  CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
  struct signature_data *data;

  data = (struct signature_data *) operation->priv_data;
  if (data->md) {
    sc_pkcs11_operation_t  *md = data->md;

    return md->type->md_update(md, pPart, ulPartLen);
  }

  /* This verification mechanism operates on the raw data */
  if (data->buffer_len + ulPartLen > sizeof(data->buffer))
    return CKR_DATA_LEN_RANGE;
  memcpy(data->buffer + data->buffer_len, pPart, ulPartLen);
  data->buffer_len += ulPartLen;
  return CKR_OK;
}

static CK_RV
sc_pkcs11_verify_final(sc_pkcs11_operation_t *operation,
  CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
  struct signature_data *data;
  struct sc_pkcs11_object *key;
  unsigned char *pubkey_value;
  CK_ULONG modulus_bits;
  CK_KEY_TYPE key_type;
  CK_BYTE params[9 /* GOST_PARAMS_OID_SIZE */] = { 0 };
  CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
  CK_ATTRIBUTE attr_key_type = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
  /* BPER (@@20121015) – Gestion du code retour CKR_SIGNATURE_LEN_RANGE */
  CK_ATTRIBUTE attr_modulus_bits = { CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits) };
  /* BPER (@@20121015) – Fin */
  struct sc_context *pcontext = operation->session->slot->card->card->ctx; // BPER 1381 - Solution C
  int rv;

  data = (struct signature_data *) operation->priv_data;

  if (pSignature == NULL)
    return CKR_ARGUMENTS_BAD;

  key = data->key;
  /* BPER (@@20121015) – Gestion du code retour CKR_SIGNATURE_LEN_RANGE */
  rv = key->ops->get_attribute(operation->session, key, &attr_modulus_bits);
  if (rv != CKR_OK)
    return rv;

  if (modulus_bits / 8UL != ulSignatureLen) {
    return CKR_SIGNATURE_LEN_RANGE;
  }
  /* BPER (@@20121015) – Fin */

  rv = key->ops->get_attribute(operation->session, key, &attr);
  if (rv != CKR_OK)
    return rv;
  pubkey_value = (unsigned char *)malloc(attr.ulValueLen);
  attr.pValue = pubkey_value;
  rv = key->ops->get_attribute(operation->session, key, &attr);
  if (rv != CKR_OK)
    goto done;

  rv = key->ops->get_attribute(operation->session, key, &attr_key_type);
 
  rv = sc_pkcs11_verify_data(pcontext, pubkey_value, attr.ulValueLen,
    params, sizeof(params),
    operation->mechanism, data->md,
    data->buffer, data->buffer_len, pSignature, ulSignatureLen);

done:
  free(pubkey_value);

  return rv;
}
#endif

/*
 * Initialize a decryption context. When we get here, we know
 * the key object is capable of decrypting _something_
 */
CK_RV
sc_pkcs11_decr_init(struct sc_pkcs11_session *session,
  CK_MECHANISM_PTR pMechanism,
struct sc_pkcs11_object *key,
  CK_MECHANISM_TYPE key_type)
{
  struct sc_pkcs11_card *p11card;
  sc_pkcs11_operation_t *operation;
  sc_pkcs11_mechanism_type_t *mt;
  CK_RV rv;

  if (!session || !session->slot
    || !(p11card = session->slot->card))
    return CKR_ARGUMENTS_BAD;

  /* See if we support this mechanism type */
  mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_DECRYPT);
  if (mt == NULL)
    return CKR_MECHANISM_INVALID;

  /* See if compatible with key type */
  if (mt->key_type != key_type)
    return CKR_KEY_TYPE_INCONSISTENT;

  rv = session_start_operation(session, SC_PKCS11_OPERATION_DECRYPT, mt, &operation);
  if (rv != CKR_OK)
    return rv;

  memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));
  rv = mt->decrypt_init(operation, key);

  if (rv != CKR_OK)
    session_stop_operation(session, SC_PKCS11_OPERATION_DECRYPT);

  return rv;
}

CK_RV
sc_pkcs11_decr(struct sc_pkcs11_session *session,
  CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
  CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
  sc_pkcs11_operation_t *op;
  int rv;

  rv = session_get_operation(session, SC_PKCS11_OPERATION_DECRYPT, &op);
  if (rv != CKR_OK)
    return rv;

  rv = op->type->decrypt(op, pEncryptedData, ulEncryptedDataLen,
    pData, pulDataLen);

  /* BPER (@@20240612-1716) - correction du bug de l'opération non terminée sur erreur de déchiffrement */
  if (rv != CKR_BUFFER_TOO_SMALL && !(rv == CKR_OK && pData == NULL))
    session_stop_operation(session, SC_PKCS11_OPERATION_DECRYPT);
  /* BPER (@@20240612-1716) - correction du bug de l'opération non terminée sur erreur de déchiffrement - Fin */

  return rv;
}

/*
 * Initialize a signature operation
 */
static CK_RV
sc_pkcs11_decrypt_init(sc_pkcs11_operation_t *operation,
struct sc_pkcs11_object *key)
{
  struct signature_data *data;

  if (!(data = (struct signature_data *) calloc(1, sizeof(*data))))
    return CKR_HOST_MEMORY;

  data->key = key;

  operation->priv_data = data;
  return CKR_OK;
}

static CK_RV
sc_pkcs11_decrypt(sc_pkcs11_operation_t *operation,
  CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
  CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
  struct signature_data *data;
  struct sc_pkcs11_object *key;

  data = (struct signature_data*) operation->priv_data;

  key = data->key;
  return key->ops->decrypt(operation->session,
    key, &operation->mechanism,
    pEncryptedData, ulEncryptedDataLen,
    pData, pulDataLen);
}

static struct signature_data* new_operation_data()
{
    struct signature_data* operation_data = calloc(1, sizeof(struct signature_data));
    return operation_data;
}

static CK_RV
sc_pkcs11_encrypt_init(sc_pkcs11_operation_t *operation, struct sc_pkcs11_object *key)
{
	struct signature_data *data;
	CK_RV rv;

	if (!(data = new_operation_data()))
		return CKR_HOST_MEMORY;

	data->key = key;
    data->info = NULL;

    if (key->ops->encrypt == NULL) {
        /* If encrypt function does not exist 
           this not a public key */
        return CKR_KEY_TYPE_INCONSISTENT;
    }

	if (key->ops->can_do) {
		rv = key->ops->can_do(operation->session, key, operation->type->mech, CKF_ENCRYPT);
		if ((rv == CKR_OK) || (rv == CKR_FUNCTION_NOT_SUPPORTED)) {
			/* Mechanism recognized and can be performed by pkcs#15 card or algorithm references not supported */
		} else {
			/* Mechanism cannot be performed by pkcs#15 card, or some general error. */
			free(data);
			SC_FUNC_RETURN(operation->session->slot->card->card->ctx, 0, (int)rv);
		}
	}

	operation->priv_data = data;

	/* The last parameter is NULL - this is call to INIT code in underlying functions */
	return key->ops->encrypt(operation->session, key, &operation->mechanism, NULL, 0, NULL, NULL);
}


static CK_RV
sc_pkcs11_encrypt(sc_pkcs11_operation_t* operation,
  CK_BYTE_PTR pData, CK_ULONG ulDataLen,
  CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
  struct signature_data* data;
  struct sc_pkcs11_object* key;
  CK_RV rv;
  CK_ULONG ulEncryptedDataLen, ulLastEncryptedPartLen;

  /* PKCS#11: If pBuf is not NULL_PTR, then *pulBufLen must contain the size in bytes.. */
  if (pEncryptedData && !pulEncryptedDataLen)
    return CKR_ARGUMENTS_BAD;

  ulEncryptedDataLen = pulEncryptedDataLen ? *pulEncryptedDataLen : 0;
  ulLastEncryptedPartLen = ulEncryptedDataLen;

  data = (struct signature_data*)operation->priv_data;

  key = data->key;

  /* Encrypt (Update) */
  rv = key->ops->encrypt(operation->session, key, &operation->mechanism,
    pData, ulDataLen, pEncryptedData, &ulEncryptedDataLen);

  if (pulEncryptedDataLen)
    *pulEncryptedDataLen = ulEncryptedDataLen;

  if (rv != CKR_OK)
    return rv;

  /* recalculate buffer space */
  if (ulEncryptedDataLen <= ulLastEncryptedPartLen)
    ulLastEncryptedPartLen -= ulEncryptedDataLen;
  else
    ulLastEncryptedPartLen = 0;
  /* EncryptFinalize 
  rv = key->ops->encrypt(operation->session, key, &operation->mechanism,
    NULL, 0, pEncryptedData + ulEncryptedDataLen, &ulLastEncryptedPartLen);

  if (pulEncryptedDataLen)
    *pulEncryptedDataLen = ulEncryptedDataLen + ulLastEncryptedPartLen;*/
  return rv;
}


/*
 * Initialize a encrypting context. When we get here, we know
 * the key object is capable of encrypt _something_
 */
CK_RV
sc_pkcs11_encr_init(struct sc_pkcs11_session* session,
  CK_MECHANISM_PTR pMechanism,
  struct sc_pkcs11_object* key,
  CK_KEY_TYPE key_type)
{
  struct sc_pkcs11_card* p11card;
  sc_pkcs11_operation_t* operation;
  sc_pkcs11_mechanism_type_t* mt;
  CK_RV rv;

  if (!session || !session->slot || !(p11card = session->slot->card))
    return CKR_ARGUMENTS_BAD;

  /* See if we support this mechanism type */
  mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_ENCRYPT);
  if (mt == NULL)
    return CKR_MECHANISM_INVALID;

  /* See if compatible with key type */
  if (mt->key_type != key_type)
    return CKR_KEY_TYPE_INCONSISTENT;

  rv = session_start_operation(session, SC_PKCS11_OPERATION_ENCRYPT, mt, &operation);
  if (rv != CKR_OK)
    return rv;

  memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));

  rv = mt->encrypt_init(operation, key);
  if (rv != CKR_OK)
    goto out;

  ///* Validate the mechanism parameters */
  //if (key->ops->init_params) {
  //  rv = key->ops->init_params(operation->session, &operation->mechanism);
  //  if (rv != CKR_OK)
  //    goto out;
  //}
  return rv;
out:
  session_stop_operation(session, SC_PKCS11_OPERATION_ENCRYPT);
  return rv;
}

CK_RV
sc_pkcs11_encr(struct sc_pkcs11_session* session,
  CK_BYTE_PTR pData, CK_ULONG ulDataLen,
  CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
  sc_pkcs11_operation_t* op;
  CK_RV rv;

  rv = session_get_operation(session, SC_PKCS11_OPERATION_ENCRYPT, &op);
  if (rv != CKR_OK)
    return rv;

  rv = sc_pkcs11_encrypt(op, pData, ulDataLen,
    pEncryptedData, pulEncryptedDataLen);

  /* application is requesting buffer size ? */
  if (pEncryptedData == NULL) {
    /* do not terminate session for CKR_OK */
    return CKR_OK;
  }
  else if (rv == CKR_BUFFER_TOO_SMALL) {
    return CKR_BUFFER_TOO_SMALL;
  }

  session_stop_operation(session, SC_PKCS11_OPERATION_ENCRYPT);
  return rv;
}



/*
 * Create new mechanism type for a mechanism supported by
 * the card
 */
sc_pkcs11_mechanism_type_t *
sc_pkcs11_new_fw_mechanism(CK_MECHANISM_TYPE mech,
  CK_MECHANISM_INFO_PTR pInfo,
  CK_KEY_TYPE key_type,
  void *priv_data)
{
  sc_pkcs11_mechanism_type_t *mt;

  mt = (sc_pkcs11_mechanism_type_t *)calloc(1, sizeof(*mt));
  if (mt == NULL)
    return mt;
  mt->mech = mech;
  mt->mech_info = *pInfo;
  mt->key_type = key_type;
  mt->mech_data = priv_data;
  mt->obj_size = sizeof(sc_pkcs11_operation_t);

  mt->release = sc_pkcs11_signature_release;

  if (pInfo->flags & CKF_SIGN) {
    mt->sign_init = sc_pkcs11_signature_init;
    mt->sign_update = sc_pkcs11_signature_update;
    mt->sign_final = sc_pkcs11_signature_final;
    mt->sign_size = sc_pkcs11_signature_size;
#ifdef ENABLE_OPENSSL
    mt->verif_init = sc_pkcs11_verify_init;
    mt->verif_update = sc_pkcs11_verify_update;
    mt->verif_final = sc_pkcs11_verify_final;
#endif
  }
  if (pInfo->flags & CKF_UNWRAP) {
    /* ... */
  }
  if (pInfo->flags & CKF_DECRYPT) {
    mt->decrypt_init = sc_pkcs11_decrypt_init;
    mt->decrypt = sc_pkcs11_decrypt;
  }
  if (pInfo->flags & CKF_ENCRYPT) {
    mt->encrypt_init = sc_pkcs11_encrypt_init;
    mt->encrypt = sc_pkcs11_encrypt;
    //mt->encrypt_update = sc_pkcs11_encr_update;
    //mt->encrypt_final = sc_pkcs11_encr_final;
  }
  return mt;
}

/*
 * Register generic mechanisms
 */
CK_RV
sc_pkcs11_register_generic_mechanisms(struct sc_pkcs11_card *p11card)
{
#ifdef ENABLE_OPENSSL
  sc_pkcs11_register_openssl_mechanisms(p11card);
#endif

  return CKR_OK;
}

/*
 * Register a sign+hash algorithm derived from an algorithm supported
 * by the token + a software hash mechanism
 */
CK_RV
sc_pkcs11_register_sign_and_hash_mechanism(struct sc_pkcs11_card *p11card,
  CK_MECHANISM_TYPE mech,
  CK_MECHANISM_TYPE hash_mech,
  sc_pkcs11_mechanism_type_t *sign_type)
{
  sc_pkcs11_mechanism_type_t *hash_type, *new_type;
  struct hash_signature_info *info;
  CK_MECHANISM_INFO mech_info = sign_type->mech_info;

  if (!(hash_type = sc_pkcs11_find_mechanism(p11card, hash_mech, CKF_DIGEST)))
    return CKR_MECHANISM_INVALID;

  /* These hash-based mechs can only be used for sign/verify */
  mech_info.flags &= (CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER);

  info = (struct hash_signature_info *) calloc(1, sizeof(*info));
  info->mech = mech;
  info->sign_type = sign_type;
  info->hash_type = hash_type;
  info->sign_mech = sign_type->mech;
  info->hash_mech = hash_mech;

  new_type = sc_pkcs11_new_fw_mechanism(mech, &mech_info,
    sign_type->key_type, info);
  if (new_type)
    sc_pkcs11_register_mechanism(p11card, new_type);
  return CKR_OK;
}
