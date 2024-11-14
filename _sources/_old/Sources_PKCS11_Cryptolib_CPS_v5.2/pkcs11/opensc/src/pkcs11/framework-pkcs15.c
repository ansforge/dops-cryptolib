/*
 * framework-pkcs15.c: PKCS#15 framework and related objects
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


#ifndef HACK_DISABLED
const int hack_enabled = 1;
#else
const int hack_enabled = 0;
#endif // HACK_DISABLED

#define slot_data(p)    ((struct pkcs15_slot_data *) (p))
#define slot_data_auth(p)  (slot_data(p)->auth_obj)
#define slot_data_pin_info(p)  (((p) && slot_data_auth(p))? \
    (struct sc_pkcs15_pin_info *) slot_data_auth(p)->data : NULL)

#define check_attribute_buffer(attr,size)  \
  if (attr->pValue == NULL_PTR) {         \
    attr->ulValueLen = size;        \
    return CKR_OK;                  \
  }                                       \
  if (attr->ulValueLen < size) {    \
    attr->ulValueLen = size;  \
    return CKR_BUFFER_TOO_SMALL;    \
  }                                       \
  attr->ulValueLen = size;


struct pkcs15_any_object {
  struct sc_pkcs11_object    base;
  unsigned int      refcount;
  size_t        size;
  struct sc_pkcs15_object *  p15_object;
  struct pkcs15_pubkey_object *  related_pubkey;
  struct pkcs15_cert_object *  related_cert;
  struct pkcs15_prkey_object *  related_privkey;
};

struct pkcs15_cert_object {
  struct pkcs15_any_object  base;

  struct sc_pkcs15_cert_info *  cert_info;
  struct sc_pkcs15_cert *    cert_data;
};
#define cert_flags    base.base.flags
#define cert_p15obj    base.p15_object
#define cert_pubkey    base.related_pubkey
#define cert_issuer    base.related_cert
#define cert_prvkey    base.related_privkey

struct pkcs15_prkey_object {
  struct pkcs15_any_object  base;

  struct sc_pkcs15_prkey_info *  prv_info;
};
#define prv_flags    base.base.flags
#define prv_p15obj    base.p15_object
#define prv_pubkey    base.related_pubkey
#define prv_next    base.related_privkey

struct pkcs15_pubkey_object {
  struct pkcs15_any_object  base;

  struct sc_pkcs15_pubkey_info *  pub_info;  /* NULL for key extracted from cert */
  struct sc_pkcs15_pubkey *  pub_data;
};
#define pub_flags    base.base.flags
#define pub_p15obj    base.p15_object
#define pub_genfrom    base.related_cert

#define __p15_type(obj)    (((obj) && (obj)->p15_object)? ((obj)->p15_object->type) : (unsigned int)-1)
#define is_privkey(obj)    (__p15_type(obj) == SC_PKCS15_TYPE_PRKEY_RSA)
#define is_pubkey(obj)    (__p15_type(obj) == SC_PKCS15_TYPE_PUBKEY_RSA)

#define is_cert(obj)    (__p15_type(obj) == SC_PKCS15_TYPE_CERT_X509)

struct pkcs15_data_object {
  struct pkcs15_any_object  base;

  struct sc_pkcs15_data_info *info;
  struct sc_pkcs15_data *value;
};
#define data_flags    base.base.flags
#define data_p15obj    base.p15_object
#define is_data(obj) (__p15_type(obj) == SC_PKCS15_TYPE_DATA_OBJECT)

extern struct sc_pkcs11_object_ops pkcs15_cert_ops;
extern struct sc_pkcs11_object_ops pkcs15_prkey_ops;
extern struct sc_pkcs11_object_ops pkcs15_pubkey_ops;
extern struct sc_pkcs11_object_ops pkcs15_dobj_ops;

static int  __pkcs15_release_object(struct pkcs15_any_object *);
static int  register_mechanisms(struct sc_pkcs11_card *p11card);
static CK_RV  get_public_exponent(struct sc_pkcs15_pubkey *,
          CK_ATTRIBUTE_PTR);
static CK_RV  get_modulus(struct sc_pkcs15_pubkey *,
          CK_ATTRIBUTE_PTR);
static CK_RV  get_modulus_bits(struct sc_pkcs15_pubkey *,
          CK_ATTRIBUTE_PTR);
static CK_RV  get_usage_bit(unsigned int usage, CK_ATTRIBUTE_PTR attr);
static CK_RV  asn1_sequence_wrapper(const u8 *, size_t, CK_ATTRIBUTE_PTR);
static void  cache_pin(void *, int, const sc_path_t *, const void *, size_t);
static int  revalidate_pin(struct pkcs15_slot_data *data,
        struct sc_pkcs11_session *ses);
static int  lock_card(struct pkcs15_fw_data *);
static int  unlock_card(struct pkcs15_fw_data *);
static int  reselect_app_df(sc_pkcs15_card_t *p15card);

/* PKCS#15 Framework */

static CK_RV pkcs15_bind(struct sc_pkcs11_card *p11card)
{
  struct pkcs15_fw_data *fw_data;
  struct sc_context *context;
  int rc;

  // BPER 1381 - Solution C
  if (p11card->card != (struct sc_card *)NULL){
    context = p11card->card->ctx;
  }else{
    context = getCurContext();
  }
  
  if (!(fw_data = (struct pkcs15_fw_data *) calloc(1, sizeof(*fw_data))))
    return CKR_HOST_MEMORY;
  p11card->fw_data = fw_data;

  rc = sc_pkcs15_bind(p11card->card, &fw_data->p15_card);
  sc_debug(context, "Binding to PKCS#15, rc=%d\n", rc);
  if (rc < 0)
    return sc_to_cryptoki_error(rc, p11card->reader);
  return register_mechanisms(p11card);
}

static CK_RV pkcs15_unbind(struct sc_pkcs11_card *p11card)
{
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
  unsigned int i;
  int rc;
  
  /* CLCO 25/05/2010 : libérer la liste des mécanismes associées à cette carte pour éviter les doublons en cas de réintroduction */
  rc = sc_pkcs11_unregister_all_mechanisms(p11card);
  if (rc)
    return sc_to_cryptoki_error(rc, p11card->reader);
  /* CLCO 25/05/2010 : fin */

  for (i = 0; i < fw_data->num_objects; i++) {
    struct pkcs15_any_object *obj = fw_data->objects[i];

    /* use object specific release method if existing */
    if (obj->base.ops && obj->base.ops->release)
      obj->base.ops->release(obj);
    else
      __pkcs15_release_object(obj);
  }

  unlock_card(fw_data);

  rc = sc_pkcs15_unbind(fw_data->p15_card);
  return sc_to_cryptoki_error(rc, p11card->reader);
}

static void pkcs15_init_token_info(struct sc_pkcs15_card *card, CK_TOKEN_INFO_PTR pToken)
{
   strcpy_bp(pToken->manufacturerID, card->manufacturer_id, 32);
   
    /* JTAU 12/11/2010 : Adaptation ASIP : le model doit avoir une valeur spécifique pour les cartes CPS */
    if(card->card->ops->get_model != NULL)    
        card->card->ops->get_model(card->card, pToken->model);              
  else if (card->flags & SC_PKCS15_CARD_FLAG_EMULATED)
    strcpy_bp(pToken->model, "PKCS#15 emulated", 16);
  else
    strcpy_bp(pToken->model, "PKCS#15", 16);

  /* Take the last 16 chars of the serial number (if the are more
   * than 16).
   * _Assuming_ that the serial number is a Big Endian counter, this
   * will assure that the serial within each type of card will be
   * unique in pkcs11 (at least for the first 8^16 cards :-) */
  if (card->serial_number != NULL) {
    int sn_start = (int)(strlen(card->serial_number) - 16);

    if (sn_start < 0)
      sn_start = 0;
    strcpy_bp(pToken->serialNumber,
      card->serial_number + sn_start,
      16);
  }

  pToken->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
  pToken->ulSessionCount = 0; /* FIXME */
  pToken->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
  pToken->ulRwSessionCount = 0; /* FIXME */
  pToken->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pToken->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pToken->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pToken->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pToken->hardwareVersion.major = 0;
  pToken->hardwareVersion.minor = 0;
  pToken->firmwareVersion.major = 0;
  pToken->firmwareVersion.minor = 0;
}

static int
__pkcs15_create_object(struct pkcs15_fw_data *fw_data,
           struct pkcs15_any_object **result,
           struct sc_pkcs15_object *p15_object,
           struct sc_pkcs11_object_ops *ops,
           size_t size)
{
  struct pkcs15_any_object *obj;

  if (fw_data->num_objects >= MAX_OBJECTS)
    return SC_ERROR_TOO_MANY_OBJECTS;

  if (!(obj = (struct pkcs15_any_object *) calloc(1, size)))
    return SC_ERROR_OUT_OF_MEMORY;

  fw_data->objects[fw_data->num_objects++] = obj;

  obj->base.ops = ops;
  obj->p15_object = p15_object;
  obj->refcount = 1;
  obj->size = size;

  *result = obj;
  return 0;
}


static int
__pkcs15_release_object(struct pkcs15_any_object *obj)
{
  if (--(obj->refcount) != 0)
    return obj->refcount;
  
  sc_mem_clear(obj, obj->size);
  free(obj);

  return 0;
}

static int public_key_created(struct pkcs15_fw_data *fw_data,
            const unsigned int num_objects,
            const u8 *id, 
            const size_t size_id,
            struct pkcs15_any_object **obj2)
{
  int found = 0;
  unsigned int ii=0;

  while(ii<num_objects && !found) {
    if (!fw_data->objects[ii]->p15_object) {
      ii++;
      continue;
    }
    if ((fw_data->objects[ii]->p15_object->type != SC_PKCS15_TYPE_PUBKEY) && 
        (fw_data->objects[ii]->p15_object->type != SC_PKCS15_TYPE_PUBKEY_RSA) &&
        (fw_data->objects[ii]->p15_object->type != SC_PKCS15_TYPE_PUBKEY_DSA) 
      ){

      ii++;
      continue;
    }
    /* XXX this is somewhat dirty as this assumes that the first 
     * member of the is the pkcs15 id */
    if (memcmp(fw_data->objects[ii]->p15_object->data, id, size_id) == 0) {
      *obj2 = (struct pkcs15_any_object *) fw_data->objects[ii];
      found=1;
    } else
      ii++;
  }
  
  if (found)
    return SC_SUCCESS;
  else 
    return SC_ERROR_OBJECT_NOT_FOUND;      
}

static int
__pkcs15_create_cert_object(struct pkcs15_fw_data *fw_data,
  struct sc_pkcs15_object *cert, struct pkcs15_any_object **cert_object)
{
  struct sc_pkcs15_cert_info *p15_info;
  struct sc_pkcs15_cert *p15_cert;
  struct pkcs15_cert_object *object;
  struct pkcs15_pubkey_object *obj2;
  int rv;

  p15_info = (struct sc_pkcs15_cert_info *) cert->data;
  if ( ((cert->flags & SC_PKCS15_CO_FLAG_PRIVATE) == SC_PKCS15_CO_FLAG_PRIVATE) ||     /* is the cert private? */
       ((cert->flags & SC_PKCS15_CO_FLAG_OBJECT_SEEN) == SC_PKCS15_CO_FLAG_OBJECT_SEEN))  /* On demand*/
    p15_cert = NULL;     /* will read cert when needed */
  else {
    rv = sc_pkcs15_read_certificate(fw_data->p15_card, p15_info, &p15_cert);
    if (rv < 0) {
      return rv;
    }
  }
  /* Certificate object */
  rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
          cert, &pkcs15_cert_ops,
          sizeof(struct pkcs15_cert_object));
  if (rv < 0)
    return rv;

  object->cert_info = p15_info;
  object->cert_data = p15_cert;

  /* Corresponding public key */
  rv = public_key_created(fw_data, fw_data->num_objects, p15_info->id.value, p15_info->id.len, (struct pkcs15_any_object **) &obj2);
  
  if (rv != SC_SUCCESS)
    rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &obj2,
              NULL, &pkcs15_pubkey_ops,
              sizeof(struct pkcs15_pubkey_object));
  if (rv < 0)
    return rv;  
  
  if (p15_cert) {
    obj2->pub_data = (sc_pkcs15_pubkey_t *)calloc(1, sizeof(sc_pkcs15_pubkey_t));
    if (!obj2->pub_data)
      return SC_ERROR_OUT_OF_MEMORY;
    memcpy(obj2->pub_data, &p15_cert->key, sizeof(sc_pkcs15_pubkey_t));
    /* invalidate public data of the cert object so that sc_pkcs15_cert_free
     * does not free the public key data as well (something like
     * sc_pkcs15_pubkey_dup would have been nice here) -- Nils
     */
    memset(&p15_cert->key, 0, sizeof(sc_pkcs15_pubkey_t));
  } else
    obj2->pub_data = NULL; /* will copy from cert when cert is read */

  obj2->pub_genfrom = object;
  object->cert_pubkey = obj2;

  if (cert_object != NULL)
    *cert_object = (struct pkcs15_any_object *) object;

  return 0;
}

static int
__pkcs15_create_pubkey_object(struct pkcs15_fw_data *fw_data,
  struct sc_pkcs15_object *pubkey, struct pkcs15_any_object **pubkey_object)
{
  struct pkcs15_pubkey_object *object;
  struct sc_pkcs15_pubkey *p15_key;
  int rv;

  /* Read public key from card */
  /* Attempt to read pubkey from card or file. 
   * During initialization process, the key may have been created
   * and saved as a file before the certificate has been created. 
   */  
  if (pubkey->flags & SC_PKCS15_CO_FLAG_PRIVATE)     /* is the key private? */
    p15_key = NULL;     /* will read key when needed */
  else {    
    if ((rv = sc_pkcs15_read_pubkey(fw_data->p15_card, pubkey, &p15_key)) < 0)
      p15_key = NULL; 
  }

  /* Public key object */
  rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
          pubkey, &pkcs15_pubkey_ops,
          sizeof(struct pkcs15_pubkey_object));
  if (rv >= 0) {
    object->pub_info = (struct sc_pkcs15_pubkey_info *) pubkey->data;
    object->pub_data = p15_key;
    if (p15_key && object->pub_info->modulus_length == 0 
        && p15_key->algorithm == SC_ALGORITHM_RSA) {
      object->pub_info->modulus_length = 
        8 * p15_key->u.rsa.modulus.len;
    }
  }

  if (pubkey_object != NULL)
    *pubkey_object = (struct pkcs15_any_object *) object;

  return rv;
}

static int
__pkcs15_create_prkey_object(struct pkcs15_fw_data *fw_data,
  struct sc_pkcs15_object *prkey, struct pkcs15_any_object **prkey_object)
{
  struct pkcs15_prkey_object *object;
  int rv;

  rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
          prkey, &pkcs15_prkey_ops,
          sizeof(struct pkcs15_prkey_object));
  if (rv >= 0)
    object->prv_info = (struct sc_pkcs15_prkey_info *) prkey->data;

  if (prkey_object != NULL)
    *prkey_object = (struct pkcs15_any_object *) object;

  return 0;
}

static int
__pkcs15_create_data_object(struct pkcs15_fw_data *fw_data,
        struct sc_pkcs15_object *object, struct pkcs15_any_object **data_object)
{
  struct pkcs15_data_object *dobj = NULL;
  int rv;

  rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &dobj,
      object, &pkcs15_dobj_ops,
      sizeof(struct pkcs15_data_object));
  if (rv >= 0)   {
      dobj->info = (struct sc_pkcs15_data_info *) object->data;
      dobj->value = NULL;
  }
  
  if (data_object != NULL)
    *data_object = (struct pkcs15_any_object *) dobj;
  
  return 0;
}


static int
pkcs15_create_pkcs11_objects(struct pkcs15_fw_data *fw_data,
           int p15_type, const char *name,
           int (*create)(struct pkcs15_fw_data *,
                  struct sc_pkcs15_object *,
                  struct pkcs15_any_object **any_object))
{
  struct sc_pkcs15_object *p15_object[MAX_OBJECTS];
  sc_context_t* rcontext = fw_data->p15_card->card->ctx;
  int i, count, rv;

  rv = count = sc_pkcs15_get_objects(fw_data->p15_card, p15_type, p15_object, MAX_OBJECTS);

  if (rv >= 0) {
    sc_debug(rcontext, "Found %d %s%s\n", count,
        name, (count == 1)? "" : "s");
  }

  for (i = 0; rv >= 0 && i < count; i++) {
    rv = create(fw_data, p15_object[i], NULL);
  }

  return count;
}

static void
__pkcs15_prkey_bind_related(struct pkcs15_fw_data *fw_data, struct pkcs15_prkey_object *pk)
{
  sc_pkcs15_id_t *id = &pk->prv_info->id;
  struct sc_context* context = fw_data->p15_card->card->ctx;
  unsigned int i;

  sc_debug(context, "Object is a private key and has id %s",
           sc_pkcs15_print_id(id));

  for (i = 0; i < fw_data->num_objects; i++) {
    struct pkcs15_any_object *obj = fw_data->objects[i];

    if (obj->base.flags & SC_PKCS11_OBJECT_HIDDEN)
      continue;
    if (is_privkey(obj) && obj != (struct pkcs15_any_object *) pk) {
      /* merge private keys with the same ID and
       * different usage bits */
      struct pkcs15_prkey_object *other, **pp;

      other = (struct pkcs15_prkey_object *) obj;
      if (sc_pkcs15_compare_id(&other->prv_info->id, id)) {
        obj->base.flags |= SC_PKCS11_OBJECT_HIDDEN;
        for (pp = &pk->prv_next; *pp; pp = &(*pp)->prv_next)
          ;
        *pp = (struct pkcs15_prkey_object *) obj;
      }
    } else
    if (is_pubkey(obj) && !pk->prv_pubkey) {
      struct pkcs15_pubkey_object *pubkey;
      
      pubkey = (struct pkcs15_pubkey_object *) obj;
      if (sc_pkcs15_compare_id(&pubkey->pub_info->id, id)) {
        sc_debug(context, "Associating object %d as public key", i);
        pk->prv_pubkey = pubkey;
        if (pk->prv_info->modulus_length == 0)
          pk->prv_info->modulus_length = pubkey->pub_info->modulus_length;
      }
    }
  }
}

static void
__pkcs15_cert_bind_related(struct pkcs15_fw_data *fw_data, struct pkcs15_cert_object *cert)
{
  struct sc_pkcs15_cert *c1 = cert->cert_data;
  sc_pkcs15_id_t *id = &cert->cert_info->id;
  struct sc_context* context = fw_data->p15_card->card->ctx;
  unsigned int i;

  sc_debug(context, "Object is a certificate and has id %s",
           sc_pkcs15_print_id(id));

  /* Loop over all objects to see if we find the certificate of
   * the issuer and the associated private key */
  for (i = 0; i < fw_data->num_objects; i++) {
    struct pkcs15_any_object *obj = fw_data->objects[i];

    if (is_cert(obj) && obj != (struct pkcs15_any_object *) cert) {
      struct pkcs15_cert_object *cert2;
      struct sc_pkcs15_cert *c2;

      cert2 = (struct pkcs15_cert_object *) obj;
      c2 = cert2->cert_data;

      if (!c1 || !c2 || !c1->issuer_len || !c2->subject_len)
        continue;
      if (c1->issuer_len == c2->subject_len
       && !memcmp(c1->issuer, c2->subject, c1->issuer_len)) {
        sc_debug(context, "Associating object %d (id %s) as issuer",
                 i, sc_pkcs15_print_id(&cert2->cert_info->id));
        cert->cert_issuer = (struct pkcs15_cert_object *) obj;
        return;
      }
    } else
    if (is_privkey(obj) && !cert->cert_prvkey) {
      struct pkcs15_prkey_object *pk;

      pk = (struct pkcs15_prkey_object *) obj;
      if (sc_pkcs15_compare_id(&pk->prv_info->id, id)) {
        sc_debug(context, "Associating object %d as private key", i);
        cert->cert_prvkey = pk;
      }
    }
  }
}

static void
pkcs15_bind_related_objects(struct pkcs15_fw_data *fw_data)
{
  struct sc_context* context = fw_data->p15_card->card->ctx;
  unsigned int i;

  /* Loop over all private keys and attached related certificate
   * and/or public key
   */
  for (i = 0; i < fw_data->num_objects; i++) {
    struct pkcs15_any_object *obj = fw_data->objects[i];

    if (obj->base.flags & SC_PKCS11_OBJECT_HIDDEN)
      continue;

    sc_debug(context, "Looking for objects related to object %d", i);

    if (is_privkey(obj)) {
      __pkcs15_prkey_bind_related(fw_data, (struct pkcs15_prkey_object *) obj);
    } else if (is_cert(obj)) {
      __pkcs15_cert_bind_related(fw_data, (struct pkcs15_cert_object *) obj);
    }
  }
}

/* We deferred reading of the cert until needed, as it may be
 * a private object, so we must wait till login to read
 */

static int 
check_cert_data_read(struct pkcs15_fw_data *fw_data,
         struct pkcs15_cert_object *cert)
{
  int rv;
  struct pkcs15_pubkey_object *obj2;

  if (!cert)
    return SC_ERROR_OBJECT_NOT_FOUND;

  if (cert->cert_data) 
    return 0;
  rv = sc_pkcs15_read_certificate(fw_data->p15_card, cert->cert_info, &cert->cert_data);
  if (rv < 0)
    return rv;

  /* update the related public key object */
  obj2 = cert->cert_pubkey;

  obj2->pub_data = (sc_pkcs15_pubkey_t *)calloc(1, sizeof(sc_pkcs15_pubkey_t));
  if (!obj2->pub_data)
    return SC_ERROR_OUT_OF_MEMORY;
  memcpy(obj2->pub_data, &cert->cert_data->key, sizeof(sc_pkcs15_pubkey_t));
  /* invalidate public data of the cert object so that sc_pkcs15_cert_free
   * does not free the public key data as well (something like
   * sc_pkcs15_pubkey_dup would have been nice here) -- Nils
   */
  memset(&cert->cert_data->key, 0, sizeof(sc_pkcs15_pubkey_t));

  /* now that we have the cert and pub key, lets see if we can bind anything else */
  
  pkcs15_bind_related_objects(fw_data);

  return 0;
}

static int
pool_is_present(struct sc_pkcs11_pool *pool, struct pkcs15_any_object *obj)
{
  struct sc_pkcs11_pool_item *item;

  for (item = pool->head; item != NULL; item = item->next) {
    if (obj == (struct pkcs15_any_object *) item->item)
      return 1;
  }

  return 0;
}

static void
pkcs15_add_object(struct sc_pkcs11_slot *slot,
      struct pkcs15_any_object *obj,
      CK_OBJECT_HANDLE_PTR pHandle)
{
  unsigned int i;
  sc_context_t* context = slot->card->card->ctx;
  struct pkcs15_fw_data *card_fw_data;

  if (obj == NULL
   || (obj->base.flags & (SC_PKCS11_OBJECT_HIDDEN | SC_PKCS11_OBJECT_RECURS)))
    return;

  if (pool_is_present(&slot->object_pool, obj))
    return;

  pool_insert(&slot->object_pool, obj, pHandle);
  obj->base.flags |= SC_PKCS11_OBJECT_SEEN;
  obj->refcount++;

  if (obj->p15_object && (obj->p15_object->user_consent > 0) ) {
    sc_debug(context, "User consent object detected, marking slot as user_consent!\n");
    ((struct pkcs15_slot_data *)slot->fw_data)->user_consent = 1;
  }

  /* Add related objects
   * XXX prevent infinite recursion when a card specifies two certificates
   * referring to each other.
   */
  obj->base.flags |= SC_PKCS11_OBJECT_RECURS;

  switch (__p15_type(obj)) {
  case SC_PKCS15_TYPE_PRKEY_RSA:
    pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_pubkey, NULL);
    card_fw_data = (struct pkcs15_fw_data *) slot->card->fw_data;
    for (i = 0; i < card_fw_data->num_objects; i++) {
      struct pkcs15_any_object *obj2 = card_fw_data->objects[i];
      struct pkcs15_cert_object *cert;

      if (!is_cert(obj2))
        continue;

      cert = (struct pkcs15_cert_object*) obj2;

      if ((struct pkcs15_any_object*)(cert->cert_prvkey) != obj)
        continue;

      pkcs15_add_object(slot, obj2, NULL);
    }
    break;
  case SC_PKCS15_TYPE_CERT_X509:
    pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_pubkey, NULL);
    pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_cert, NULL);
    break;
  }

  obj->base.flags &= ~SC_PKCS11_OBJECT_RECURS;
}

static void pkcs15_init_slot(struct sc_pkcs15_card *card,
    struct sc_pkcs11_slot *slot,
    struct sc_pkcs15_object *auth)
{
  struct pkcs15_slot_data *fw_data;
  struct sc_pkcs15_pin_info *pin_info = NULL;
  sc_context_t* context = slot->card->card->ctx;
  char tmp[64];

  pkcs15_init_token_info(card, &slot->token_info);
  slot->token_info.flags |= CKF_TOKEN_INITIALIZED;
  if (auth != NULL)
    slot->token_info.flags |= CKF_USER_PIN_INITIALIZED;
  if (card->card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) {
    slot->token_info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
    sc_pkcs11_conf.cache_pins = 0;
  }
  if (card->card->caps & SC_CARD_CAP_RNG)
    slot->token_info.flags |= CKF_RNG;
  slot->fw_data = fw_data = (struct pkcs15_slot_data *) calloc(1, sizeof(*fw_data));
  fw_data->auth_obj = auth;

  if (auth != NULL) {
    pin_info = (struct sc_pkcs15_pin_info*) auth->data;

    snprintf(tmp, sizeof(tmp), "%s", card->label);
    slot->token_info.flags |= CKF_LOGIN_REQUIRED;
    /* CLCO 01/06/2010 : Gestion de l'état du code PIN */
    if (pin_info->tries_left >= 0) {
      if (pin_info->tries_left == 1)
        slot->token_info.flags |= CKF_USER_PIN_FINAL_TRY;
      else if (pin_info->tries_left == 0)
        slot->token_info.flags |= CKF_USER_PIN_LOCKED;
      if (pin_info->tries_max && pin_info->tries_left && pin_info->tries_left < pin_info->tries_max && pin_info->tries_left != 0)
        slot->token_info.flags |= CKF_USER_PIN_COUNT_LOW;
    }
  } else
    snprintf(tmp, sizeof(tmp), "%s", card->label);
  strcpy_bp(slot->token_info.label, tmp, 32);

  if (pin_info && pin_info->magic == SC_PKCS15_PIN_MAGIC) {
    slot->token_info.ulMaxPinLen = (unsigned long)pin_info->max_length;
    slot->token_info.ulMinPinLen = (unsigned long)pin_info->min_length;
  } else {
    /* choose reasonable defaults */
    slot->token_info.ulMaxPinLen = 8;
    slot->token_info.ulMinPinLen = 4;
  }

  sc_debug(context, "Initialized token '%s'\n", tmp);
}

static CK_RV pkcs15_create_slot(struct sc_pkcs11_card *p11card,
    struct sc_pkcs15_object *auth,
    struct sc_pkcs11_slot **out)
{
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
  struct sc_pkcs11_slot *slot;
  int rv;

  rv = slot_allocate(&slot, p11card);
  if (rv != CKR_OK)
    return rv;

  /* There's a token in this slot */
  slot->slot_info.flags |= CKF_TOKEN_PRESENT;

  /* Fill in the slot/token info from pkcs15 data */
  pkcs15_init_slot(fw_data->p15_card, slot, auth);

  *out = slot;
  return CKR_OK;
}

static CK_RV pkcs15_create_tokens(struct sc_pkcs11_card *p11card)
{
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
  struct sc_pkcs15_object *auths[MAX_OBJECTS];
  struct sc_pkcs11_slot *slot = NULL;
  sc_context_t * context = p11card->card->ctx; // BPER 1381 Solution C
  int i, rv, reader = p11card->reader;
  int auth_count = 0;
  int found_auth_count = 0;
  unsigned int j;

  sc_debug(context, "pkcs15_create_tokens: p11card=%p, card=%p\n", p11card, p11card->card);

  rv = sc_pkcs15_get_objects(fw_data->p15_card,
          SC_PKCS15_TYPE_AUTH_PIN,
          auths,
          SC_PKCS15_MAX_PINS);
  if (rv < 0)
    return sc_to_cryptoki_error(rv, reader);
  sc_debug(context, "Found %d authentication objects\n", rv);
  auth_count = rv;

  if (!context->processing_update) {
    rv = pkcs15_create_pkcs11_objects(fw_data,
          SC_PKCS15_TYPE_PRKEY_RSA,
          "private key",
          __pkcs15_create_prkey_object);
     if (rv < 0)
       return sc_to_cryptoki_error(rv, reader);

     rv = pkcs15_create_pkcs11_objects(fw_data,
          SC_PKCS15_TYPE_PUBKEY_RSA,
          "public key",
          __pkcs15_create_pubkey_object);
     if (rv < 0)
       return sc_to_cryptoki_error(rv, reader);

    rv = pkcs15_create_pkcs11_objects(fw_data,
          SC_PKCS15_TYPE_CERT_X509,
          "certificate",
          __pkcs15_create_cert_object);
    if (rv < 0)
      return sc_to_cryptoki_error(rv, reader);

    rv = pkcs15_create_pkcs11_objects(fw_data,
          SC_PKCS15_TYPE_DATA_OBJECT,
          "data object",
          __pkcs15_create_data_object);
    if (rv < 0)
      return sc_to_cryptoki_error(rv, reader);

    /* Match up related keys and certificates */
    pkcs15_bind_related_objects(fw_data);
  }
  /* CLCO 06/05/2010 : Dans le cas du sans contact, il n'y a pas de code PIN */
  if ((hack_enabled) && (auth_count != 0))
  /* CLCO 06/05/2010 : fin */
    auth_count = 1;

  for (i = 0; i < auth_count; i++) {
    struct sc_pkcs15_pin_info *pin_info = NULL;

    pin_info = (struct sc_pkcs15_pin_info*) auths[i]->data;

    /* Ignore any non-authentication PINs */
    if ((pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN) != 0)
      continue;

    /* Ignore unblocking pins for hacked module */
    if (hack_enabled && (pin_info->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN) != 0)
      continue;

    found_auth_count++;

    rv = pkcs15_create_slot(p11card, auths[i], &slot);
    if (rv != CKR_OK)
      return CKR_OK; /* no more slots available for this card */

    /* Add all objects related to this pin */
    for (j=0; j < fw_data->num_objects; j++) {
      struct pkcs15_any_object *obj = fw_data->objects[j];

      /* "Fake" objects we've generated */
      if (__p15_type(obj) == (unsigned int)-1)
        continue;
      /* Some objects have an auth_id even though they are
       * not private. Just ignore those... */
      if ((obj->p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE) != SC_PKCS15_CO_FLAG_PRIVATE)
        continue;
      if (!sc_pkcs15_compare_id(&pin_info->auth_id, &obj->p15_object->auth_id))
        continue;

      if (is_privkey(obj)) {
        sc_debug(context, "Adding private key %d to PIN %d\n", j, i);
        pkcs15_add_object(slot, obj, NULL);
      }
      else if (is_data(obj)) {
        sc_debug(context, "Adding data object %d to PIN %d\n", j, i);
        pkcs15_add_object(slot, obj, NULL);
      }
      else if (is_cert(obj)) {
        sc_debug(context, "Adding cert object %d to PIN %d\n", j, i);
        pkcs15_add_object(slot, obj, NULL);
      }
    }
  }

  auth_count = found_auth_count;

  /* Add all public objects to a virtual slot without pin protection.
   * If there's only 1 pin and the hide_empty_tokens option is set,
   * add the public objects to the slot that corresponds to that pin.
   */
  if (!(auth_count == 1 && (sc_pkcs11_conf.hide_empty_tokens || (fw_data->p15_card->flags & SC_PKCS15_CARD_FLAG_EMULATED))))
    slot = NULL;

  /* Add all the remaining objects */
  for (j = 0; j < fw_data->num_objects; j++) {
    struct pkcs15_any_object *obj = fw_data->objects[j];
    /* We only have one pin and only the things related to it. */
    if (!hack_enabled)
      break;

    if (!(obj->base.flags & SC_PKCS11_OBJECT_SEEN)) {
      sc_debug(context, "Object %d was not seen previously\n", j);
      if (!slot) {
        rv = pkcs15_create_slot(p11card, NULL, &slot);
        if (rv != CKR_OK)
          return CKR_OK; /* no more slots available for this card */
      }
      pkcs15_add_object(slot, obj, NULL);
    }
  }

  /* Create read/write slots */
  while (slot_allocate(&slot, p11card) == CKR_OK) {
    if (!sc_pkcs11_conf.hide_empty_tokens && !(fw_data->p15_card->flags & SC_PKCS15_CARD_FLAG_EMULATED)) {
      slot->slot_info.flags |= CKF_TOKEN_PRESENT;
      pkcs15_init_token_info(fw_data->p15_card, &slot->token_info);
      strcpy_bp(slot->token_info.label, fw_data->p15_card->label, 32);
      slot->token_info.flags |= CKF_TOKEN_INITIALIZED;
    }
  }

  sc_debug(context, "All tokens created\n");
  return CKR_OK;
}

static CK_RV pkcs15_release_token(struct sc_pkcs11_card *p11card, void *fw_token)
{
  unlock_card((struct pkcs15_fw_data *) p11card->fw_data);
  return CKR_OK;
}

static CK_RV pkcs15_login(struct sc_pkcs11_card *p11card,
        void *fw_token,
        CK_USER_TYPE userType,
        CK_CHAR_PTR pPin,
        CK_ULONG ulPinLen)
{
  int rc;
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
  struct sc_pkcs15_card *card = fw_data->p15_card;
  struct sc_pkcs15_object *auth_object;
  struct sc_pkcs15_pin_info *pin;
  struct sc_context* context = p11card->card->ctx; // BPER 1381 - Solution C

  switch (userType) {
  case CKU_USER:
    auth_object = slot_data_auth(fw_token);
    if (auth_object == NULL)
      return CKR_USER_PIN_NOT_INITIALIZED;
    break;
  case CKU_SO:
    /* A card with no SO PIN is treated as if no SO login
     * is required */
    rc = sc_pkcs15_find_so_pin(card, &auth_object);

    /* If there's no SO PIN on the card, silently
     * accept any PIN, and lock the card if required */
    if (rc == SC_ERROR_OBJECT_NOT_FOUND
     && sc_pkcs11_conf.lock_login)
      rc = lock_card(fw_data);
    if (rc < 0)
      return sc_to_cryptoki_error(rc, p11card->reader);
    break;
  default:
    return CKR_USER_TYPE_INVALID;
  }
  pin = (struct sc_pkcs15_pin_info *) auth_object->data;

  if (p11card->card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) {
    /* pPin should be NULL in case of a pin pad reader, but
     * some apps (e.g. older Netscapes) don't know about it.
     * So we don't require that pPin == NULL, but set it to
     * NULL ourselves. This way, you can supply an empty (if
     * possible) or fake PIN if an application asks a PIN).
     */
    /* But we want to be able to specify a PIN on the command
     * line (e.g. for the test scripts). So we don't do anything
     * here - this gives the user the choice of entering
     * an empty pin (which makes us use the pin pad) or
     * a valid pin (which is processed normally). --okir */
    if (ulPinLen == 0)
      pPin = NULL;
  } else {
    /*
     * If PIN is out of range,
     * it cannot be correct.
     */
    if (ulPinLen < pin->min_length ||
        ulPinLen > pin->max_length)
      return CKR_PIN_INCORRECT;
  }

  /* By default, we make the reader resource manager keep other
   * processes from accessing the card while we're logged in.
   * Otherwise an attacker could perform some crypto operation
   * after we've authenticated with the card */
  if (sc_pkcs11_conf.lock_login && (rc = lock_card(fw_data)) < 0)
    return sc_to_cryptoki_error(rc, p11card->reader);

  rc = sc_pkcs15_verify_pin(card, pin, pPin, ulPinLen);
  sc_debug(context, "PIN verification returned %d\n", rc);
  
  if (rc >= 0)
    cache_pin(fw_token, userType, &pin->path, pPin, ulPinLen);

  return sc_to_cryptoki_error(rc, p11card->reader);
}

static CK_RV pkcs15_logout(struct sc_pkcs11_card *p11card, void *fw_token)
{
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
  int rc = 0;

  cache_pin(fw_token, CKU_SO, NULL, NULL, 0);
  cache_pin(fw_token, CKU_USER, NULL, NULL, 0);

  sc_logout(fw_data->p15_card->card);

  if (sc_pkcs11_conf.lock_login)
    rc = unlock_card(fw_data);
  return sc_to_cryptoki_error(rc, p11card->reader);
}

static CK_RV pkcs15_change_pin(struct sc_pkcs11_card *p11card,
        void *fw_token,
        CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
        CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
  int rc;
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
  struct sc_pkcs15_pin_info *pin;
  struct sc_context* context = p11card->card->ctx; // BPER 1381 - Solution C

  if (!(pin = slot_data_pin_info(fw_token)))
    return CKR_USER_PIN_NOT_INITIALIZED;

  if (p11card->card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) {
    /* pPin should be NULL in case of a pin pad reader, but
     * some apps (e.g. older Netscapes) don't know about it.
     * So we don't require that pPin == NULL, but set it to
     * NULL ourselves. This way, you can supply an empty (if
     * possible) or fake PIN if an application asks a PIN).
     */
    pOldPin = pNewPin = NULL;
    ulOldLen = ulNewLen = 0;
  } else
  if (ulNewLen < pin->min_length ||
      ulNewLen > pin->max_length)
    return CKR_PIN_LEN_RANGE;

  rc = sc_pkcs15_change_pin(fw_data->p15_card, pin, pOldPin, ulOldLen,
        pNewPin, ulNewLen);
  sc_debug(context, "PIN change returned %d\n", rc);

  if (rc >= 0)
    cache_pin(fw_token, CKU_USER, &pin->path, pNewPin, ulNewLen);
  return sc_to_cryptoki_error(rc, p11card->reader);
}

/* CLCO 21/05/2010 : Ajout dans le framework PKCS#15 d'une fonction de déblocage du code PIN */
static CK_RV pkcs15_unblock_pin(struct sc_pkcs11_card *p11card,
        void *fw_token,
        CK_CHAR_PTR pPuk, CK_ULONG ulPukLen,
        CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
  int rc;
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
  struct sc_pkcs15_pin_info *pin;
  struct sc_context* context = p11card->card->ctx; // BPER 1381 - Solution C

  if (!(pin = slot_data_pin_info(fw_token)))
    return CKR_USER_PIN_NOT_INITIALIZED;

  if (p11card->card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) {
    /* pPin should be NULL in case of a pin pad reader, but
     * some apps (e.g. older Netscapes) don't know about it.
     * So we don't require that pPin == NULL, but set it to
     * NULL ourselves. This way, you can supply an empty (if
     * possible) or fake PIN if an application asks a PIN).
     */
    pPuk = pNewPin = NULL;
    ulPukLen = ulNewLen = 0;
  } else
  if (ulNewLen < pin->min_length ||
      ulNewLen > pin->max_length)
    return CKR_PIN_LEN_RANGE;

  rc = sc_pkcs15_unblock_pin(fw_data->p15_card, pin, pPuk, ulPukLen,
        pNewPin, ulNewLen);
  sc_debug(context, "PIN unblock returned %d\n", rc);

  if (rc >= 0)
    cache_pin(fw_token, CKU_USER, &pin->path, pNewPin, ulNewLen);
  return sc_to_cryptoki_error(rc, p11card->reader);
}
/* CLCO 21/05/2010 : fin */

static CK_RV pkcs15_get_random(struct sc_pkcs11_card *p11card,
        CK_BYTE_PTR p, CK_ULONG len)
{
  int rc;
        struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
        struct sc_card *card = fw_data->p15_card->card;

  rc = sc_get_challenge(card, p, (size_t)len);
  return sc_to_cryptoki_error(rc, p11card->reader);
}

struct sc_pkcs11_framework_ops framework_pkcs15 = {
  pkcs15_bind,
  pkcs15_unbind,
  pkcs15_create_tokens,
  pkcs15_release_token,
  pkcs15_login,
  pkcs15_logout,
  pkcs15_change_pin,
  pkcs15_unblock_pin,
  NULL,      /* init_token */
  NULL,      /* init_pin */
  NULL,      /* create_object */
  NULL,      /* gen_keypair*/
  NULL,      /* seed_random */
  pkcs15_get_random
};

/* CLCO 25/05/2010 : Ajout d'une fonction de modification de la valeur de l'objet qui ne nécessite pas de profil de carte */
int
sc_pkcs15_update_file(sc_card_t *card,
           sc_file_t *file, void *data, unsigned int datalen)
{
  struct sc_file  *info = NULL;
  void    *copy = NULL;
  int    r, need_to_zap = 0;
  char    pbuf[SC_MAX_PATH_STRING_SIZE];

  r = sc_path_print(pbuf, sizeof(pbuf), &file->path);
  if (r != SC_SUCCESS)
    pbuf[0] = '\0';
  sc_debug(card->ctx, "called, path=%s, %u bytes\n", pbuf, datalen);

  sc_ctx_suppress_errors_on(card->ctx);
  if ((r = sc_select_file(card, &file->path, &info)) < 0) {
    return r;
  } else {
    sc_ctx_suppress_errors_off(card->ctx);
    need_to_zap = 1;
  }

  if (info->size < datalen) {
    r = sc_path_print(pbuf, sizeof(pbuf), &file->path);
    if (r != SC_SUCCESS)
      pbuf[0] = '\0';

    sc_error(card->ctx,
      "File %s too small (require %u, have %u) - "
      "please increase size in profile", pbuf,
      datalen, info->size);
    sc_file_free(info);
    return SC_ERROR_TOO_MANY_OBJECTS;
  } else if (info->size > datalen && need_to_zap) {
    /* zero out the rest of the file - we may have shrunk
     * the file contents */
    copy = calloc(1, info->size);
    if (copy == NULL) {
      sc_file_free(info);
      return SC_ERROR_OUT_OF_MEMORY;
    }
    memcpy(copy, data, datalen);
    datalen = (unsigned int)info->size;
    data = copy;
  }

  if (r >= 0 && datalen) {
    r = sc_update_binary(card, 0, (const u8 *) data, datalen, 0);
  }
  
  if (copy)
    free(copy);
  sc_file_free(info);
  return r;
}
/* CLCO 25/05/2010 : fin */

static CK_RV pkcs15_set_attrib(struct sc_pkcs11_session *session,
                               struct sc_pkcs15_object *p15_object,
/* CLCO 25/05/2010 : Ajout du path du fichier à modifier */
                 sc_path_t path,  
/* CLCO 25/05/2010 : fin */
                               CK_ATTRIBUTE_PTR attr)
{
/* CLCO 25/05/2010 : modification de la valeur de l'objet uniquement dans ce cas */
  struct sc_pkcs11_card *p11card = session->slot->card;
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
  int rc = 0;
  CK_RV rv = CKR_OK;

  rc = sc_lock(p11card->card);
  if (rc < 0)
    return sc_to_cryptoki_error(rc, p11card->reader);


  switch(attr->type) {
  case CKA_VALUE:
    {
    sc_file_t *file = sc_file_new();
    file->path=path;
    rc = sc_pkcs15_update_file(fw_data->p15_card->card, file,
                                     attr->pValue, attr->ulValueLen);

    if (rc>0)
      rc = SC_SUCCESS;
    }
    break;
  default:
    rv = CKR_ATTRIBUTE_READ_ONLY;
    goto set_attr_done;
  }

  rv = sc_to_cryptoki_error(rc, p11card->reader);

set_attr_done:
  sc_unlock(p11card->card);
  
  return rv;
}

/*
 * PKCS#15 Certificate Object
 */

static void pkcs15_cert_release(void *obj)
{
  struct pkcs15_cert_object *cert = (struct pkcs15_cert_object *) obj;
  struct sc_pkcs15_cert      *cert_data = cert->cert_data;

  if (__pkcs15_release_object((struct pkcs15_any_object *) obj) == 0) {
    if (cert_data) /* may never have been read */
      sc_pkcs15_free_certificate(cert_data);
  }
}

static CK_RV pkcs15_cert_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
  struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
/* CLCO 25/05/2010 : Ajout du path du fichier à modifier */
  return pkcs15_set_attrib(session, cert->base.p15_object, cert->cert_info->path, attr);
/* CLCO 25/05/2010 : fin */
}

static CK_RV pkcs15_cert_get_attribute(struct sc_pkcs11_session *session,
        void *object,
        CK_ATTRIBUTE_PTR attr)
{
  struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) session->slot->card->fw_data;
  size_t len;

  switch (attr->type) {
  case CKA_CLASS:
    check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
    *(CK_OBJECT_CLASS*)attr->pValue = CKO_CERTIFICATE;
    break;
  case CKA_TOKEN:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue = TRUE;
    break;
  case CKA_PRIVATE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue =
      (cert->base.p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
    break;
  case CKA_MODIFIABLE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue = FALSE;
    break;
  case CKA_LABEL:
    len = strlen(cert->cert_p15obj->label);
    check_attribute_buffer(attr, (unsigned long)len);
    memcpy(attr->pValue, cert->cert_p15obj->label, len);
    break;
  case CKA_CERTIFICATE_TYPE:
    check_attribute_buffer(attr, sizeof(CK_CERTIFICATE_TYPE));
    *(CK_CERTIFICATE_TYPE*)attr->pValue = CKC_X_509;
    break;
  case CKA_ID:
    /* Not sure why CA certs should be reported with an
     * ID of 00. --okir 20030413 */
    if (cert->cert_info->authority) {
      check_attribute_buffer(attr, 1);
      *(unsigned char*)attr->pValue = 0;
    } else {
      check_attribute_buffer(attr, (unsigned long)cert->cert_info->id.len);
      memcpy(attr->pValue, cert->cert_info->id.value, cert->cert_info->id.len);
    }
    break;
  case CKA_TRUSTED:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue = cert->cert_info->authority ? TRUE : FALSE;
    break;
  case CKA_VALUE:
    if (check_cert_data_read(fw_data, cert) != 0) {
      attr->ulValueLen = 0;
      return CKR_OK;
    }
    check_attribute_buffer(attr, (unsigned long)cert->cert_data->data_len);
    memcpy(attr->pValue, cert->cert_data->data, cert->cert_data->data_len);
    break;
  case CKA_SERIAL_NUMBER:
    if (check_cert_data_read(fw_data, cert) != 0) {
      attr->ulValueLen = 0;
      return CKR_OK;
    }
    check_attribute_buffer(attr, (unsigned long)cert->cert_data->serial_len);
    memcpy(attr->pValue, cert->cert_data->serial, cert->cert_data->serial_len);
    break;
  case CKA_SUBJECT:
    if (check_cert_data_read(fw_data, cert) != 0) {
      attr->ulValueLen = 0;
      return CKR_OK;
    }
    return asn1_sequence_wrapper(cert->cert_data->subject,
                                 cert->cert_data->subject_len, attr);
  case CKA_ISSUER:
    if (check_cert_data_read(fw_data, cert) != 0) {
      attr->ulValueLen = 0;
      return CKR_OK;
    }
    return asn1_sequence_wrapper(cert->cert_data->issuer,
         cert->cert_data->issuer_len, attr);
  default:
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

static int
pkcs15_cert_cmp_attribute(struct sc_pkcs11_session *session,
        void *object,
        CK_ATTRIBUTE_PTR attr)
{
  struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) session->slot->card->fw_data;
  u8  *data;
  size_t  len;

  switch (attr->type) {
  /* Check the issuer. Some pkcs11 callers (i.e. netscape) will pass
   * in the ASN.1 encoded SEQUENCE OF SET ... while OpenSC just
   * keeps the SET in the issuer field. */
  case CKA_ISSUER:
    if (check_cert_data_read(fw_data, cert) != 0)
      break;
    if (cert->cert_data->issuer_len == 0)
      break;
    data = (u8 *) attr->pValue;
    len = attr->ulValueLen;
    /* SEQUENCE is tag 0x30, SET is 0x31
     * I know this code is icky, but hey... this is netscape
     * we're dealing with :-) */
    if (cert->cert_data->issuer[0] == 0x31
     && data[0] == 0x30 && len >= 2) {
      /* skip the length byte(s) */
      len = (data[1] & 0x80)? (data[1] & 0x7F) : 0;
      if (attr->ulValueLen < len + 2)
        break;
      data += len + 2;
      len = attr->ulValueLen - len - 2;
    }
    if (len == cert->cert_data->issuer_len
     && !memcmp(cert->cert_data->issuer, data, len))
      return 1;
    break;
  default:
    return sc_pkcs11_any_cmp_attribute(session, object, attr);
  }
  return 0;
}

struct sc_pkcs11_object_ops pkcs15_cert_ops = {
  pkcs15_cert_release,
  pkcs15_cert_set_attribute,
  pkcs15_cert_get_attribute,
  pkcs15_cert_cmp_attribute,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

/*
 * PKCS#15 Private Key Object
 */
static void pkcs15_prkey_release(void *object)
{
  __pkcs15_release_object((struct pkcs15_any_object *) object);
}

static CK_RV pkcs15_prkey_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
  struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
/* CLCO 25/05/2010 : Ajout du path du fichier à modifier */
  return pkcs15_set_attrib(session, prkey->base.p15_object, prkey->prv_info->path, attr);
/* CLCO 25/05/2010 : fin */
}

static CK_RV pkcs15_prkey_get_attribute(struct sc_pkcs11_session *session,
        void *object,
        CK_ATTRIBUTE_PTR attr)
{
  struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) session->slot->card->fw_data;
  struct sc_pkcs15_pubkey *key = NULL;
  unsigned int usage;
  size_t len;

  /* PKCS#11 requires us to supply CKA_MODULUS for private keys,
   * although that is not generally available from a smart card
   * (the key is supposed to be safely locked away after all).
   *
   * To work around this, we hope that we either have an associated
   * public key, or we try to find a certificate with the
   * corresponding public key.
   *
   * Note: We do the same thing for CKA_PUBLIC_EXPONENT as some
   *       applications assume they can get that from the private
   *       key, something PKCS#11 doesn't guarantee.
   */
  if ((attr->type == CKA_MODULUS) || (attr->type == CKA_PUBLIC_EXPONENT)) {
    /* First see if we have a associated public key */
    if (prkey->prv_pubkey)
      key = prkey->prv_pubkey->pub_data;
    else {
      /* Try to find a certificate with the public key */
      unsigned int i;

      for (i = 0; i < fw_data->num_objects; i++) {
        struct pkcs15_any_object *obj = fw_data->objects[i];
        struct pkcs15_cert_object *cert;

        if (!is_cert(obj))
          continue;

        cert = (struct pkcs15_cert_object*) obj;

        if (cert->cert_prvkey != prkey)
          continue;

        if (check_cert_data_read(fw_data, cert) == 0)
          key = cert->cert_pubkey->pub_data;
      }
    }
  }

  switch (attr->type) {
  case CKA_CLASS:
    check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
    *(CK_OBJECT_CLASS*)attr->pValue = CKO_PRIVATE_KEY;
    break;
  case CKA_TOKEN:
  case CKA_LOCAL:
  case CKA_SENSITIVE:
  case CKA_ALWAYS_SENSITIVE:
  case CKA_NEVER_EXTRACTABLE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue = TRUE;
    break;
  case CKA_PRIVATE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue = (prkey->prv_p15obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
    break;
  case CKA_MODIFIABLE:
  case CKA_EXTRACTABLE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue = FALSE;
    break;
  case CKA_LABEL:
    len = strlen(prkey->prv_p15obj->label);
    check_attribute_buffer(attr, (unsigned long)len);
    memcpy(attr->pValue, prkey->prv_p15obj->label, len);
    break;
  case CKA_KEY_TYPE:
    check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
    *(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
    break;
  case CKA_ID:
    check_attribute_buffer(attr, (unsigned long)prkey->prv_info->id.len);
    memcpy(attr->pValue, prkey->prv_info->id.value, prkey->prv_info->id.len);
    break;
  case CKA_KEY_GEN_MECHANISM:
    check_attribute_buffer(attr, sizeof(CK_MECHANISM_TYPE));
    *(CK_MECHANISM_TYPE*)attr->pValue = CK_UNAVAILABLE_INFORMATION;
    break;
  case CKA_ENCRYPT:
  case CKA_DECRYPT:
  case CKA_SIGN:
  case CKA_SIGN_RECOVER:
  case CKA_WRAP:
  case CKA_UNWRAP:
  case CKA_VERIFY:
  case CKA_VERIFY_RECOVER:
  case CKA_DERIVE:
    /* Combine the usage bits of all split keys */
    for (usage = 0; prkey; prkey = prkey->prv_next)
      usage |= prkey->prv_info->usage;
    return get_usage_bit(usage, attr);
  case CKA_MODULUS:
    return get_modulus(key, attr);
  /* XXX: this should be removed sometimes as a private key has no
   * CKA_MODULUS_BITS attribute, but unfortunately other parts depend
   * on this -- Nils */
  case CKA_MODULUS_BITS:
    check_attribute_buffer(attr, sizeof(CK_ULONG));
    *(CK_ULONG *) attr->pValue = (CK_ULONG)prkey->prv_info->modulus_length;
    return CKR_OK;
  case CKA_PUBLIC_EXPONENT:
    return get_public_exponent(key, attr);
  case CKA_PRIVATE_EXPONENT:
  case CKA_PRIME_1:
  case CKA_PRIME_2:
  case CKA_EXPONENT_1:
  case CKA_EXPONENT_2:
  case CKA_COEFFICIENT:
    return CKR_ATTRIBUTE_SENSITIVE;
  case CKA_SUBJECT:
  case CKA_START_DATE:
  case CKA_END_DATE:
    attr->ulValueLen = 0;
    return CKR_OK;
  default:
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

/*
CLCO 12/04/2010 : Gestion IAS - Ajout des structures utilisées pour l'opération de hashing faite par la carte lors de la signature numérique.
*/
/* Also used for verification data */
struct hash_signature_info {
	CK_MECHANISM_TYPE	mech;
	CK_MECHANISM_TYPE	hash_mech;
	CK_MECHANISM_TYPE	sign_mech;
	sc_pkcs11_mechanism_type_t *hash_type;
	sc_pkcs11_mechanism_type_t *sign_type;
};

/* Also used for verification and decryption data */
struct signature_data {
	struct sc_pkcs11_object *key;
	struct hash_signature_info *info;
	sc_pkcs11_operation_t *	md;
	CK_BYTE			buffer[4096/8];
	unsigned int		buffer_len;
	CK_BYTE			remaining_msg[64];
	unsigned int		remaining_msg_len;
	size_t				msg_len;
};

/*
CLCO 12/04/2010 : Fin.
*/
static CK_RV pkcs15_prkey_sign(struct sc_pkcs11_session *ses, void *obj,
      CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pData,
      CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
      CK_ULONG_PTR pulDataLen)
{

  /*
  CLCO 12/04/2010 : Gestion IAS - Ajout des structures utilisÃ©es pour l'opÃ©ration de hashing faite par la carte lors de la signature numÃ©rique.
  */
  struct signature_data *sign_data;
  /*
  CLCO 12/04/2010 : Fin.
  */
  struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object *) obj;
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) ses->slot->card->fw_data;
  struct pkcs15_slot_data *data = slot_data(ses->slot->fw_data);
  struct sc_context *context = ses->slot->card->card->ctx; // BPER 1381 - Solution C: recuperation du contexte depuis la session Cryptoki
  int rv, flags = 0;

  sc_debug(context, "Initiating signing operation, mechanism 0x%x.\n",
        pMechanism->mechanism);

  /* See which of the alternative keys supports signing */
  while (prkey
   && !(prkey->prv_info->usage
       & (SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_SIGNRECOVER|
         SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)))
    prkey = prkey->prv_next;

  if (prkey == NULL)
    return CKR_KEY_FUNCTION_NOT_PERMITTED;

  switch (pMechanism->mechanism) {
  case CKM_RSA_PKCS:
    flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
    break;
  case CKM_MD5_RSA_PKCS:
    flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_MD5;
    break;
  case CKM_SHA1_RSA_PKCS:
    flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA1;
    break;
  case CKM_SHA256_RSA_PKCS:
    flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA256;
    break;
  case CKM_SHA384_RSA_PKCS:
    flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA384;
    break;
  case CKM_SHA512_RSA_PKCS:
    flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA512;
    break;
  case CKM_RIPEMD160_RSA_PKCS:
    flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_RIPEMD160;
    break;
  case CKM_RSA_X_509:
    flags = SC_ALGORITHM_RSA_RAW;
    break;
  case CKM_RSA_PKCS_PSS:
      flags = SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_NONE;
      break;
  case CKM_SHA1_RSA_PKCS_PSS:
    flags = SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_SHA1;
    break;
  case CKM_SHA256_RSA_PKCS_PSS:
    flags = SC_ALGORITHM_RSA_PAD_PSS | SC_ALGORITHM_RSA_HASH_SHA256;
    break;
  default:
    return CKR_MECHANISM_INVALID;
  }

  rv = sc_lock(ses->slot->card->card);
  if (rv < 0)
    return sc_to_cryptoki_error(rv, ses->slot->card->reader);

  if (!sc_pkcs11_conf.lock_login) {
    rv = reselect_app_df(fw_data->p15_card);
    if (rv < 0) {
      sc_unlock(ses->slot->card->card);
      return sc_to_cryptoki_error(rv, ses->slot->card->reader);
    }
  }

  /*
  CLCO 12/04/2010 : Gestion IAS - Appel de l'opÃ©ration de hashing faite par la carte lors de la signature numÃ©rique.
  */
  if ((strcmp(ses->slot->card->card->driver->name, "IAS") == 0) &&
    ((flags&SC_ALGORITHM_RSA_HASH_NONE) != SC_ALGORITHM_RSA_HASH_NONE) &&
    ((flags&SC_ALGORITHM_RSA_RAW) != SC_ALGORITHM_RSA_RAW)) {
    sign_data = (struct signature_data *) ses->operation[SC_PKCS11_OPERATION_SIGN]->priv_data;
    /* tester s'il y a eu au moins un bloc hashÃ© par openssl */
    if (sign_data->msg_len == 0)
      ulDataLen = 0; /* sinon on ne tient pas compte du hash final */

    sc_debug(context, "Now computing hash of signature for %d bytes. %d bytes already hashed.\n", sign_data->remaining_msg_len, sign_data->msg_len);
    rv = sc_pkcs15_compute_hash(fw_data->p15_card,
      flags,
      pData,
      ulDataLen,
      sign_data->remaining_msg, sign_data->remaining_msg_len,
      sign_data->msg_len);
    if (rv != CKR_OK) {
      sc_unlock(ses->slot->card->card);
      return rv;
    }
    /* Indiquer pour les traitements Ã  suivre de la signature que les donnÃ©es Ã  signer ne sont plus Ã  traiter.
    Cela permettra en particulier de faire la diffÃ©rence entre de la signature et de l'authentification.
    */
    ulDataLen = 0;
  }
  /*
  CLCO 12/04/2010 : Fin.
  */

  sc_debug(context, "Selected flags %X. Now computing signature for %d bytes. %d bytes reserved.\n", flags, ulDataLen, *pulDataLen);
  rv = sc_pkcs15_compute_signature(fw_data->p15_card,
           prkey->prv_p15obj,
           flags,
           pData,
           ulDataLen,
           pSignature,
           *pulDataLen);

  /* Do we have to try a re-login and then try to sign again? */
  if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
    rv = revalidate_pin(data, ses);
    if (rv == 0) {
      rv = sc_pkcs15_compute_signature(fw_data->p15_card,
        prkey->prv_p15obj, flags, pData, ulDataLen,
        pSignature, *pulDataLen);
    /* CLCO 18/05/2010 : si la revalidation du pin a échoué, il faut remettre le code erreur initial */
    } else {
      rv=SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
    }
    /* CLCO 18/05/2010 : fin */
  }

  sc_unlock(ses->slot->card->card);
  
  sc_debug(context, "Sign complete. Result %d.\n", rv);

  if (rv > 0) {
    *pulDataLen = rv;
    return CKR_OK;
  }

  return sc_to_cryptoki_error(rv, ses->slot->card->reader);
}

static CK_RV
pkcs15_prkey_decrypt(struct sc_pkcs11_session *ses, void *obj,
    CK_MECHANISM_PTR pMechanism,
    CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) ses->slot->card->fw_data;
  struct pkcs15_prkey_object *prkey;
  struct pkcs15_slot_data *data = slot_data(ses->slot->fw_data);
  struct sc_context *context = ses->slot->card->card->ctx; // BPER 1381 - Solution C: recuperation du contexte depuis la session Cryptoki
  u8  decrypted[256];
  int  buff_too_small, rv, flags = 0;

  sc_debug(context, "Initiating unwrap/decryption.\n");

  /* See which of the alternative keys supports unwrap/decrypt */
  prkey = (struct pkcs15_prkey_object *) obj;
  while (prkey
   && !(prkey->prv_info->usage
       & (SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP)))
    prkey = prkey->prv_next;

  if (prkey == NULL)
    return CKR_KEY_FUNCTION_NOT_PERMITTED;

  /* Select the proper padding mechanism */
  switch (pMechanism->mechanism) {
  case CKM_RSA_PKCS:
    flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
    break;
  case CKM_RSA_X_509:
    flags |= SC_ALGORITHM_RSA_RAW;
    break;
  default:
    return CKR_MECHANISM_INVALID;
  }

  rv = sc_lock(ses->slot->card->card);
  if (rv < 0)
    return sc_to_cryptoki_error(rv, ses->slot->card->reader);

  if (!sc_pkcs11_conf.lock_login) {
    rv = reselect_app_df(fw_data->p15_card);
    if (rv < 0) {
      sc_unlock(ses->slot->card->card);
      return sc_to_cryptoki_error(rv, ses->slot->card->reader);
    }
  }

  rv = sc_pkcs15_decipher(fw_data->p15_card, prkey->prv_p15obj,
         flags, pEncryptedData, ulEncryptedDataLen,
         decrypted, sizeof(decrypted));

  /* Do we have to try a re-login and then try to decrypt again? */
  if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
    rv = revalidate_pin(data, ses);
    if (rv == 0)
      rv = sc_pkcs15_decipher(fw_data->p15_card, prkey->prv_p15obj,
            flags, pEncryptedData, ulEncryptedDataLen,
            decrypted, sizeof(decrypted));
  }
  sc_unlock(ses->slot->card->card);

  sc_debug(context, "Key unwrap/decryption complete. Result %d.\n", rv);

  if (rv < 0)
    return sc_to_cryptoki_error(rv, ses->slot->card->reader);

  buff_too_small = (*pulDataLen < (CK_ULONG)rv);
  *pulDataLen = rv;
  if (pData == NULL_PTR)
    return CKR_OK;
  if (buff_too_small)
    return CKR_BUFFER_TOO_SMALL;
  memcpy(pData, decrypted, *pulDataLen);

  return CKR_OK;
}

static CK_RV
pkcs15_prkey_unwrap(struct sc_pkcs11_session *ses, void *obj,
    CK_MECHANISM_PTR pMechanism,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
    void **result)
{
  u8 unwrapped_key[256];
  CK_ULONG key_len = sizeof(unwrapped_key);
  int   r;

  r = pkcs15_prkey_decrypt(ses, obj, pMechanism, pData, ulDataLen,
      unwrapped_key, &key_len);

  if (r < 0)
    return sc_to_cryptoki_error(r, ses->slot->card->reader);
  return sc_pkcs11_create_secret_key(ses,
      unwrapped_key, key_len,
      pTemplate, ulAttributeCount,
      (struct sc_pkcs11_object **) result);
}

struct sc_pkcs11_object_ops pkcs15_prkey_ops = {
  pkcs15_prkey_release,
  pkcs15_prkey_set_attribute,
  pkcs15_prkey_get_attribute,
  sc_pkcs11_any_cmp_attribute,
  NULL,
  NULL,
  pkcs15_prkey_sign,
  pkcs15_prkey_unwrap,
  pkcs15_prkey_decrypt
};

/*
 * PKCS#15 RSA Public Key Object
 */
static void pkcs15_pubkey_release(void *object)
{
  struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
  struct sc_pkcs15_pubkey *key_data = pubkey->pub_data;

  if (__pkcs15_release_object((struct pkcs15_any_object *) object) == 0) {
    if (key_data) 
      sc_pkcs15_free_pubkey(key_data);
  }
}

static CK_RV pkcs15_pubkey_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
  struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
/* CLCO 25/05/2010 : Ajout du path du fichier à modifier */
  return pkcs15_set_attrib(session, pubkey->base.p15_object, pubkey->pub_info->path, attr);
/* CLCO 25/05/2010 : fin */
}

static CK_RV pkcs15_pubkey_get_attribute(struct sc_pkcs11_session *session,
        void *object,
        CK_ATTRIBUTE_PTR attr)
{
  struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
  struct pkcs15_cert_object *cert = pubkey->pub_genfrom;
  struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) session->slot->card->fw_data;
  size_t len;

  /* We may need to get these from cert */
  switch (attr->type) {
    case CKA_MODULUS:
    case CKA_MODULUS_BITS:
    case CKA_VALUE:
    case CKA_PUBLIC_EXPONENT:
      if (pubkey->pub_data == NULL) 
        /* FIXME: check the return value? */
        check_cert_data_read(fw_data, cert);
      break;
  }

  switch (attr->type) {
  case CKA_CLASS:
    check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
    *(CK_OBJECT_CLASS*)attr->pValue = CKO_PUBLIC_KEY;
    break;
  case CKA_TOKEN:
  case CKA_LOCAL:
  case CKA_SENSITIVE:
  case CKA_ALWAYS_SENSITIVE:
  case CKA_NEVER_EXTRACTABLE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue = TRUE;
    break;
  case CKA_PRIVATE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    if (pubkey->pub_p15obj) {
      *(CK_BBOOL*)attr->pValue =
        (pubkey->pub_p15obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
    } else if (cert && cert->cert_p15obj) {
      *(CK_BBOOL*)attr->pValue =
        (cert->pub_p15obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
    } else  {
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;
  case CKA_MODIFIABLE:
  case CKA_EXTRACTABLE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue = FALSE;
    break;
  case CKA_LABEL:
    if (pubkey->pub_p15obj) {            
      len = strlen(pubkey->pub_p15obj->label);
      check_attribute_buffer(attr, (unsigned long)len);
      memcpy(attr->pValue, pubkey->pub_p15obj->label, len);
    } else if (cert && cert->cert_p15obj) {            
      len = strlen(cert->cert_p15obj->label) + sizeof("Cle publique - ");
      check_attribute_buffer(attr, (unsigned long)(len));
      strcpy(attr->pValue, "Cle publique - ");
      strcat(attr->pValue, cert->cert_p15obj->label);
    } else {
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;
  case CKA_KEY_TYPE:
    check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
    *(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
    break;
  case CKA_ID:
    if (pubkey->pub_info) {
      check_attribute_buffer(attr, (unsigned long)pubkey->pub_info->id.len);
      memcpy(attr->pValue, pubkey->pub_info->id.value, pubkey->pub_info->id.len);
    } else if (cert && cert->cert_info) {
      check_attribute_buffer(attr, (unsigned long)cert->cert_info->id.len);
      memcpy(attr->pValue, cert->cert_info->id.value, cert->cert_info->id.len);
    } else {
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    break;
  case CKA_KEY_GEN_MECHANISM:
    check_attribute_buffer(attr, sizeof(CK_MECHANISM_TYPE));
    *(CK_MECHANISM_TYPE*)attr->pValue = CK_UNAVAILABLE_INFORMATION;
    break;
  case CKA_ENCRYPT:
  case CKA_DECRYPT:
  case CKA_SIGN:
  case CKA_SIGN_RECOVER:
  case CKA_WRAP:
  case CKA_UNWRAP:
  case CKA_VERIFY:
  case CKA_VERIFY_RECOVER:
  case CKA_DERIVE:
    if (pubkey->pub_info) {
      /* BPER (@@20240612-1716) - set CKA_ENCRYPT & CKA_VERIFY flags for CPS4 cards */
      if (!strcmp(fw_data->p15_card->card->name, "NXP")) {
          if (attr->type == CKA_ENCRYPT || attr->type == CKA_VERIFY) {
              pubkey->pub_info->usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_VERIFY;
          }
      }
      /* BPER (@@20240612-1716) - set CKA_ENCRYPT & CKA_VERIFY flags for CPS4 cards - Fin */
      return get_usage_bit(pubkey->pub_info->usage, attr);
    } else {
      return get_usage_bit(SC_PKCS15_PRKEY_USAGE_ENCRYPT
          |SC_PKCS15_PRKEY_USAGE_VERIFY
          |SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,
          attr);
    }
  case CKA_MODULUS:
    return get_modulus(pubkey->pub_data, attr);
  case CKA_MODULUS_BITS:
    return get_modulus_bits(pubkey->pub_data, attr);
  case CKA_PUBLIC_EXPONENT:
    return get_public_exponent(pubkey->pub_data, attr);
  case CKA_VALUE:
    if (pubkey->pub_data) {
      check_attribute_buffer(attr, (unsigned long)pubkey->pub_data->data.len);
      memcpy(attr->pValue, pubkey->pub_data->data.value,
                pubkey->pub_data->data.len);
    } else if (cert && cert->cert_data) {
      check_attribute_buffer(attr, (unsigned long)cert->cert_data->data_len);
      memcpy(attr->pValue, cert->cert_data->data, cert->cert_data->data_len);
    }
    break;
  default:
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  return CKR_OK;
}

static CK_RV pkcs15_pubkey_can_do(struct sc_pkcs11_session* session, struct sc_pkcs11_object* key,
    CK_MECHANISM_TYPE type, int ck_type) {
    CK_RV rv;
    struct pkcs15_pubkey_object* pubkey = NULL;
    CK_BBOOL is_encrypt = CK_FALSE;
    CK_CHAR pubkey_label[128] = { 0 };
    CK_KEY_TYPE pubkey_key_type;
    CK_ULONG pubkey_label_len = sizeof(pubkey_label);
    CK_ULONG pubkey_key_type_len = sizeof(pubkey_key_type);
    CK_ATTRIBUTE attr_is_encrypt = { CKA_ENCRYPT, &is_encrypt, sizeof(is_encrypt) };
    CK_ATTRIBUTE attr_label = { CKA_LABEL, pubkey_label, pubkey_label_len };
    CK_ATTRIBUTE attr_key_type = { CKA_KEY_TYPE, &pubkey_key_type, pubkey_key_type_len };
    rv = key->ops->get_attribute(session, key, &attr_is_encrypt);
    if (rv != CKR_OK)
        return rv;
    if (!is_encrypt) {
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* check key type, must be RSA */
    rv = key->ops->get_attribute(session, key, &attr_key_type);
    if (rv != CKR_OK)
        return rv;
    if (pubkey_key_type != CKK_RSA) {
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* check key usage, prevent signature key */
    rv = key->ops->get_attribute(session, key, &attr_label);
    if (rv != CKR_OK)
        return rv;
    if (strstr(pubkey_label, "Sign") != NULL) {
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    return CKR_OK;
}

static CK_RV pkcs15_pubkey_encrypt(struct sc_pkcs11_session* session,
    struct sc_pkcs11_object* key,
    CK_MECHANISM_PTR p_mecha, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR p_encrypt, CK_ULONG_PTR p_encrypt_len) {
    CK_RV rv = CKR_OK;
    struct pkcs15_pubkey_object* pubkey = NULL;
    if (p_encrypt_len == NULL) {
        /* encrypt init */
        pubkey = (struct pkcs15_pubkey_object*)key;
    }
    else {
        const unsigned char* _pubkey;
        int _pubkey_len;
        CK_ULONG modulus_bits = 0;
        CK_ATTRIBUTE attr_modulus_bits = { CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits) };
        rv = key->ops->get_attribute(session, key, &attr_modulus_bits);
        if (rv != CKR_OK)
            return rv;

        if (p_encrypt == NULL) {
            /* encrypt: size only */
            *p_encrypt_len = modulus_bits / 8UL;
            return rv;
        }
        if (*p_encrypt_len < modulus_bits / 8UL) {
            return CKR_BUFFER_TOO_SMALL;
        }
        
        pubkey = (struct pkcs15_pubkey_object*)key;
        _pubkey_len = (int)pubkey->pub_data->data.len;
        _pubkey = (const unsigned char*)pubkey->pub_data->data.value;
        sc_debug(session->slot->card->card->ctx, "pub_data, len 0x%x", pubkey->pub_data->data.len);
        sc_debug(session->slot->card->card->ctx, "pub_data, data %p", pubkey->pub_data->data.value);

        rv = sc_pkcs11_encrypt_data(session->slot->card->card->ctx, _pubkey, _pubkey_len,
            p_mecha->mechanism, NULL,
            data, data_len,
            p_encrypt, p_encrypt_len);
        
    }
    return rv;
}

struct sc_pkcs11_object_ops pkcs15_pubkey_ops = {
  pkcs15_pubkey_release,
  pkcs15_pubkey_set_attribute,
  pkcs15_pubkey_get_attribute,
  sc_pkcs11_any_cmp_attribute,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  pkcs15_pubkey_can_do,
  pkcs15_pubkey_encrypt
};


/* PKCS#15 Data Object*/

static void pkcs15_dobj_release(void *object)
{
  __pkcs15_release_object((struct pkcs15_any_object *) object);
}

static CK_RV pkcs15_dobj_set_attribute(struct sc_pkcs11_session *session,
    void *object, CK_ATTRIBUTE_PTR attr)
{
  struct pkcs15_data_object *dobj = (struct pkcs15_data_object*) object;
  
/* CLCO 25/05/2010 : Ajout du path du fichier à modifier */
  return pkcs15_set_attrib(session, dobj->base.p15_object, dobj->info->path, attr);
/* CLCO 25/05/2010 : fin */
}


static int pkcs15_dobj_get_value(struct sc_pkcs11_session *session,
    struct pkcs15_data_object *dobj,
    struct sc_pkcs15_data **out_data)
{
  int rv;
  struct pkcs15_fw_data *fw_data =
    (struct pkcs15_fw_data *) session->slot->card->fw_data;
  struct pkcs15_slot_data *data = slot_data(session->slot->fw_data);
  int reader = session->slot->card->reader;

  if (!out_data)
    return SC_ERROR_INVALID_ARGUMENTS;
  
  rv = sc_pkcs15_read_data_object(fw_data->p15_card, dobj->info, out_data);

  /* Do we have to try a re-login and then try to sign again? */
  if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
    rv = revalidate_pin(data, session);
    if (rv == 0)
      rv = sc_pkcs15_read_data_object(fw_data->p15_card, dobj->info, out_data);
  }

  if (rv < 0)
    return sc_to_cryptoki_error(rv, reader);

  return rv;
}

static CK_RV data_value_to_attr(struct sc_context* context, CK_ATTRIBUTE_PTR attr, struct sc_pkcs15_data *data)
{
  if (!attr || !data)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  sc_debug(context, "data %p\n", data);
  sc_debug(context, "data_len %i\n", data->data_len);

  check_attribute_buffer(attr, (unsigned long)data->data_len);
  memcpy(attr->pValue, data->data, data->data_len);
  return CKR_OK;
}

static CK_RV pkcs15_dobj_get_attribute(struct sc_pkcs11_session *session,
        void *object,
        CK_ATTRIBUTE_PTR attr)
{
  struct pkcs15_data_object *dobj = (struct pkcs15_data_object*) object;
  struct sc_context *context = session->slot->card->card->ctx; // BPER 1381 - Solution C
  size_t len;
  
  switch (attr->type) {
  case CKA_CLASS:
    check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
    *(CK_OBJECT_CLASS*)attr->pValue = CKO_DATA;
    break;
  case CKA_TOKEN:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue = TRUE;
    break;
  case CKA_PRIVATE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue =
      (dobj->base.p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
    break;
  case CKA_MODIFIABLE:
    check_attribute_buffer(attr, sizeof(CK_BBOOL));
    *(CK_BBOOL*)attr->pValue =
      (dobj->base.p15_object->flags & 0x02) != 0;
    break;
  case CKA_LABEL:
    len = strlen(dobj->base.p15_object->label);
    check_attribute_buffer(attr, (unsigned long)len);
    memcpy(attr->pValue, dobj->base.p15_object->label, len);
    break;
  case CKA_APPLICATION:
    len = strlen(dobj->info->app_label);
    check_attribute_buffer(attr, (unsigned long)len);
    memcpy(attr->pValue, dobj->info->app_label, len);
    break;
#if 0
  case CKA_ID:
    check_attribute_buffer(attr, dobj->info->id.len);
    memcpy(attr->pValue, dobj->info->id.value, dobj->info->id.len);
    break;
#endif
  case CKA_OBJECT_ID:
    {
      len = sizeof(dobj->info->app_oid);
      
      check_attribute_buffer(attr, (unsigned long)len);
      memcpy(attr->pValue, dobj->info->app_oid.value, len);
    }
    break;
  case CKA_VALUE:
    {
      CK_RV rv;
      struct sc_pkcs15_data *data = NULL;
            /* BPER (@@20150216-1226) - Lecture superflue des données en requete 'size only' */
            dobj->info->size_only = 0;
            if (attr->pValue == NULL)
                dobj->info->size_only = 1;
            /* BPER (@@20150216-1226) - Lecture superflue des données en requete 'size only' - Fin */
      rv = pkcs15_dobj_get_value(session, dobj, &data);
      if (rv == CKR_OK)
        rv = data_value_to_attr(context, attr, data); // BPER 1381 - Solution C
      if (data) {
        free(data->data);
        free(data);
      }
      if (rv != CKR_OK)
        return rv;
    }
    break;
  default:
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }
  
  return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_dobj_ops = {
  pkcs15_dobj_release,
  pkcs15_dobj_set_attribute,
  pkcs15_dobj_get_attribute,
  sc_pkcs11_any_cmp_attribute,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
};


/*
 * get_attribute helpers
 */
static CK_RV
get_bignum(sc_pkcs15_bignum_t *bn, CK_ATTRIBUTE_PTR attr)
{
  check_attribute_buffer(attr, (unsigned long)bn->len);
  memcpy(attr->pValue, bn->data, bn->len);
  return CKR_OK;
}

static CK_RV
get_bignum_bits(sc_pkcs15_bignum_t *bn, CK_ATTRIBUTE_PTR attr)
{
  CK_ULONG  bits, mask;

  bits = (CK_ULONG)(bn->len * 8);
  for (mask = 0x80; mask; mask >>= 1, bits--) {
    if (bn->data[0] & mask)
      break;
  }
  check_attribute_buffer(attr, sizeof(bits));
  *(CK_ULONG *) attr->pValue = bits;
  return CKR_OK;
}

static CK_RV
get_modulus(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
  if (key == NULL)
    return CKR_ATTRIBUTE_TYPE_INVALID;
  switch (key->algorithm) {
  case SC_ALGORITHM_RSA:
    return get_bignum(&key->u.rsa.modulus, attr);
  }
  return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_modulus_bits(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
  if (key == NULL)
    return CKR_ATTRIBUTE_TYPE_INVALID;
  switch (key->algorithm) {
  case SC_ALGORITHM_RSA:
    return get_bignum_bits(&key->u.rsa.modulus, attr);
  }
  return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_public_exponent(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
  if (key == NULL)
    return CKR_ATTRIBUTE_TYPE_INVALID;
  switch (key->algorithm) {
  case SC_ALGORITHM_RSA:
    return get_bignum(&key->u.rsa.exponent, attr);
  }
  return CKR_ATTRIBUTE_TYPE_INVALID;
}

/*
 * Map pkcs15 usage bits to pkcs11 usage attributes.
 *
 * It's not totally clear to me whether SC_PKCS15_PRKEY_USAGE_NONREPUDIATION should
 * be treated as being equivalent with CKA_SIGN or not...
 */
static CK_RV
get_usage_bit(unsigned int usage, CK_ATTRIBUTE_PTR attr)
{
  static struct {
    CK_ATTRIBUTE_TYPE type;
    unsigned int  flag;
  } flag_mapping[] = {
    { CKA_ENCRYPT,    SC_PKCS15_PRKEY_USAGE_ENCRYPT },
    { CKA_DECRYPT,    SC_PKCS15_PRKEY_USAGE_DECRYPT },
    { CKA_SIGN,    SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_NONREPUDIATION },
    { CKA_SIGN_RECOVER,  SC_PKCS15_PRKEY_USAGE_SIGNRECOVER },
    { CKA_WRAP,    SC_PKCS15_PRKEY_USAGE_WRAP },
    { CKA_UNWRAP,    SC_PKCS15_PRKEY_USAGE_UNWRAP },
    { CKA_VERIFY,    SC_PKCS15_PRKEY_USAGE_VERIFY },
    { CKA_VERIFY_RECOVER,  SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER },
    { CKA_DERIVE,    SC_PKCS15_PRKEY_USAGE_DERIVE },
    { 0, 0 }
  };
  unsigned int mask = 0, j;

  for (j = 0; (mask = flag_mapping[j].flag) != 0; j++) {
    if (flag_mapping[j].type == attr->type)
      break;
  }
  if (mask == 0)
    return CKR_ATTRIBUTE_TYPE_INVALID;

  check_attribute_buffer(attr, sizeof(CK_BBOOL));
  *(CK_BBOOL*)attr->pValue = (usage & mask)? TRUE : FALSE;

  return CKR_OK;
}


static CK_RV
asn1_sequence_wrapper(const u8 *data, size_t len, CK_ATTRIBUTE_PTR attr)
{
  u8    *dest;
  unsigned int  n;
  size_t    len2;
  size_t    lenb = 1;

  len2 = len;
  /* calculate the number of bytes needed for the length */
  if (len > 127) {
    unsigned int i;
    for (i = 0; (len & (0xff << i)) != 0 && (0xff << i) != 0; i++)
      lenb++;
  }
  check_attribute_buffer(attr, (unsigned long)(1 + lenb + len));

  dest = (u8 *) attr->pValue;
  *dest++ = 0x30;  /* SEQUENCE tag */
  if (len <= 127) {
    *dest++ = (u8)len;
  } else {
    for (n = 4; (len & 0xFF000000) == 0; n--)
      len <<= 8;
    *dest++ = 0x80 + n;
    while (n--) {
      *dest++ = (u8)(len >> 24);
      len <<= 8;
    }
  }
  memcpy(dest, data, len2);
  attr->ulValueLen = (unsigned long)((dest - (u8 *) attr->pValue) + len2);
  return CKR_OK;
}

static void
cache_pin(void *p, int user, const sc_path_t *path, const void *pin, size_t len)
{
  struct pkcs15_slot_data *data = (struct pkcs15_slot_data *) p;

  if ((user != CKU_SO && user != CKU_USER) || !sc_pkcs11_conf.cache_pins)
    return;
  /* Don't cache pins related to user_consent objects/slots */
  if (data->user_consent)
    return;

  memset(&data->pin[user], 0, sizeof(data->pin[user]));
  if (len && len <= MAX_CACHE_PIN) {
    memcpy(data->pin[user].value, pin, len);
    data->pin[user].len = (unsigned int)len;
    if (path)
      data->pin[user].path = *path;
  }
}

/* TODO: GUI must indicate pinpad revalidation instead of a plain error.*/
static int
revalidate_pin(struct pkcs15_slot_data *data, struct sc_pkcs11_session *ses)
{
  struct sc_context *context = ses->slot->card->card->ctx; // BPER 1381 Solution C: recuperation du contexte depuis la session Cryptoki
  int rv;
  u8 value[MAX_CACHE_PIN];

  sc_debug(context, "PIN revalidation\n");

  if (!sc_pkcs11_conf.cache_pins
       && !(ses->slot->token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH))
    return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;

  if (sc_pkcs11_conf.cache_pins && data->user_consent)
    return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;

  if (ses->slot->token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
    rv = pkcs15_login(ses->slot->card, ses->slot->fw_data, CKU_USER, NULL, 0);
  }
  else {
    memcpy(value, data->pin[CKU_USER].value, data->pin[CKU_USER].len);
    rv = pkcs15_login(ses->slot->card, ses->slot->fw_data, CKU_USER,
      value, data->pin[CKU_USER].len);
  }

  if (rv != CKR_OK)
    sc_debug(context, "Re-login failed: 0x%0x (%d)\n", rv, rv);

  return rv;
}

/*
 * Mechanism handling
 * FIXME: We should consult the card's algorithm list to
 * find out what operations it supports
 */
static int register_mechanisms(struct sc_pkcs11_card *p11card)
{
  sc_card_t *card = p11card->card;
  sc_algorithm_info_t *alg_info;
  CK_MECHANISM_INFO mech_info;
  sc_pkcs11_mechanism_type_t *mt;
  unsigned int num;
  int rc, flags = 0;

  /* Register generic mechanisms */
  sc_pkcs11_register_generic_mechanisms(p11card);

  mech_info.flags = CKF_HW | CKF_SIGN | CKF_UNWRAP | CKF_DECRYPT;
#ifdef ENABLE_OPENSSL
  mech_info.flags |= CKF_VERIFY;
#endif
  mech_info.ulMinKeySize = ~0;
  mech_info.ulMaxKeySize = 0;

  /* For now, we just OR all the algorithm specific
   * flags, based on the assumption that cards don't
   * support different modes for different key sizes
   */
  num = card->algorithm_count;
  alg_info = card->algorithms;
  while (num--) {
    if (alg_info->algorithm == SC_ALGORITHM_RSA)   {
    if (alg_info->key_length < mech_info.ulMinKeySize)
      mech_info.ulMinKeySize = alg_info->key_length;
    if (alg_info->key_length > mech_info.ulMaxKeySize)
      mech_info.ulMaxKeySize = alg_info->key_length;

    flags |= alg_info->flags;
    }
    alg_info++;
  }

  /* Check if we support raw RSA */
  if (flags & SC_ALGORITHM_RSA_RAW) {
    mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_X_509,
          &mech_info, CKK_RSA, NULL);
    rc = sc_pkcs11_register_mechanism(p11card, mt);
    if (rc != CKR_OK)
      return rc;

    /* If the card supports RAW, it should by all means
     * have registered everything else, too. If it didn't
     * we help it a little
     */
    flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
    /* CLCO 18/05/2010 : conditionner l'ajout des algorithmes de signature avec hash en fonction de la configuration */
    if (!(flags&SC_ALGORITHM_RSA_HASH_NONE))
      flags |= SC_ALGORITHM_RSA_HASHES;
    /* CLCO 18/05/2010 : fin */
  }

  /* Check for PKCS1 */
  if (flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
      /* BPER (@@20240418-1712) add CKF_ENCRYPT for CKR_RSA_PKCS only */
      mech_info.flags |= CKF_ENCRYPT;
      /* BPER (@@20240418-1712) add CKF_ENCRYPT for CKR_RSA_PKCS only - fin */
    mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS,
          &mech_info, CKK_RSA, NULL);
    rc = sc_pkcs11_register_mechanism(p11card, mt);
    if (rc != CKR_OK)
      return rc;

    /* CLCO 18/05/2010 : conditionner l'ajout des algorithmes de signature avec hash en fonction de la configuration */
    if (!(flags&SC_ALGORITHM_RSA_HASH_NONE)) {
      /* if the driver doesn't say what hashes it supports,
       * claim we will do all of them */
      if (!(flags & SC_ALGORITHM_RSA_HASHES))
        flags |= SC_ALGORITHM_RSA_HASHES;
    }
    /* CLCO 18/05/2010 : fin */

    if (flags & SC_ALGORITHM_RSA_HASH_SHA1)
      sc_pkcs11_register_sign_and_hash_mechanism(p11card,
          CKM_SHA1_RSA_PKCS, CKM_SHA_1, mt);
    /* CLCO 18/05/2010 : ajout de l'agorithme RSA with SHA-256 */
    if (flags & SC_ALGORITHM_RSA_HASH_SHA256)
      sc_pkcs11_register_sign_and_hash_mechanism(p11card,
          CKM_SHA256_RSA_PKCS, CKM_SHA256, mt);
    /* CLCO 18/05/2010 : fin */
    if (flags & SC_ALGORITHM_RSA_HASH_MD5)
      sc_pkcs11_register_sign_and_hash_mechanism(p11card,
          CKM_MD5_RSA_PKCS, CKM_MD5, mt);
    if (flags & SC_ALGORITHM_RSA_HASH_RIPEMD160)
      sc_pkcs11_register_sign_and_hash_mechanism(p11card,
          CKM_RIPEMD160_RSA_PKCS, CKM_RIPEMD160, mt);
#if 0
    /* Does this correspond to any defined CKM_XXX value? */
    if (flags & SC_ALGORITHM_RSA_HASH_MD5_SHA1)
      sc_pkcs11_register_sign_and_hash_mechanism(p11card,
          CKM_XXX_RSA_PKCS, CKM_XXX, mt);
#endif
#ifdef ENABLE_OPENSSL
    /* CLCO 25/05/2010 : conditionner la possiblité de générer des clés à la capacité de la carte */
    if (flags & SC_ALGORITHM_ONBOARD_KEY_GEN) {
      mech_info.flags = CKF_GENERATE_KEY_PAIR;
      mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN,
            &mech_info, CKK_RSA, NULL);
      rc = sc_pkcs11_register_mechanism(p11card, mt);
      if (rc != CKR_OK)
        return rc;
    }
    /* Check for PSS */
    if (flags & SC_ALGORITHM_RSA_PAD_PSS) {
      /* add CKM_RSA_PKCS_PSS mechanism */
      mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS_PSS,
            &mech_info, CKK_RSA, NULL);
      rc = sc_pkcs11_register_mechanism(p11card, mt);
      if (rc != CKR_OK)
         return rc;
      /* add CKM_RSA_PKCS_PSS mechanism - Fin */

      if (flags & SC_ALGORITHM_RSA_HASH_SHA1)
        sc_pkcs11_register_sign_and_hash_mechanism(p11card,CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1, mt);
      /* CLCO 18/05/2010 : ajout de l'agorithme RSA with SHA-256 */
      if (flags & SC_ALGORITHM_RSA_HASH_SHA256)
        sc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, mt);
    }
    /* CLCO 25/05/2010 : fin */
#endif
  }
  return CKR_OK;
}

static int lock_card(struct pkcs15_fw_data *fw_data)
{
  struct sc_context *context = fw_data->p15_card->card->ctx; // BPER 1381 - Solution C
  int  rc;

  if ((rc = sc_lock(fw_data->p15_card->card)) < 0)
    sc_debug(context, "Failed to lock card (%d)\n", rc);
  else
    fw_data->locked++;

  return rc;
}

static int unlock_card(struct pkcs15_fw_data *fw_data)
{
  while (fw_data->locked) {
    sc_unlock(fw_data->p15_card->card);
    fw_data->locked--;
  }
  return 0;
}

static int reselect_app_df(sc_pkcs15_card_t *p15card)
{
  int r = SC_SUCCESS;

  if (p15card->file_app != NULL) {
    /* if the application df (of the pkcs15 application) is
     * specified select it */
    sc_path_t *tpath = &p15card->file_app->path;
    sc_debug(p15card->card->ctx, "reselect application df\n");
    r = sc_select_file(p15card->card, tpath, NULL);
  }
  return r;
}


