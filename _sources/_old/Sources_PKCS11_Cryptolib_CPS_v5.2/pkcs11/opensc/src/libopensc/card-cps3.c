/*
 * card-cps3.c : Driver for CPS3 based cards
 *
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
 * Partially based on the ISO7816 driver.
 *
 */

#include "internal.h"
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include "sysdef.h"
#endif
#include "card-cps.h"


static struct sc_card_operations cps3_ops;

static struct sc_card_driver cps3_drv = { "IAS", "cps3", &cps3_ops, NULL, 0, NULL };



/* Known AIDs */
static const u8 cps3_aid_cps3[] = { 0xE8, 0x28, 0xBD, 0x08, 0x0F, 0x80, 0x25, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x10 };
static const u8 cps3_aid_cps3_cl[] = { 0xE8, 0x28, 0xBD, 0x08, 0x0F, 0x80, 0x25, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x20 };



/* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
/* Paths des fichiers situations de la CPS3 */
const char* cps3_sit_paths[] = { "3F000001D120", "3F000001D121", "3F000001D122", "3F000001D123", "3F000001D124", "3F000001D125", "3F000001D126", "3F000001D127", "3F000001D128", "3F000001D129", "3F000001D12A", "3F000001D12B", "3F000001D12C", "3F000001D12D", "3F000001D12E", "3F000001D12F" };
/* MCUG 14/09/2010 : Fin */

#define CARD_CONTACT      0
#define CARD_CONTACT_LESS 1



/*--------------------------------------------------------------------------
     cps3_init

Fonction appelée par OpenSC pour initialiser les champs de l'objet sc_card_t.
La fonction positionne notamment :
                le nom de la carte (IAS)
                le numéro de série EF.SN.ICC
                les algorithmes et taille de clés supportés par la carte
Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte

Codes retour:
SC_SUCCESS
SC_ERROR_INTERNAL

--------------------------------------------------------------------------*/
static int cps3_init(sc_card_t *card)
{
  unsigned long flags;

  struct cps_priv_data *priv = DRVDATA(card);

  if (priv == NULL)
    return SC_ERROR_INTERNAL;

  assert(card != NULL);

  /* Card version detection */
  if (!IS_CARD_TYPE_CPS3(card->type)) {
    return SC_ERROR_INTERNAL;
  }

  SC_FUNC_CALLED(card->ctx, 1);
  card->name = "IAS";
  card->cla = 0x00;
  card->sw1_bytes_available = CPS3_SW1_BYTES_AVAILABLE;
  card->sw1_cps2ter_bytes_available = CPS2TER_SW1_BYTES_AVAILABLE;

  /* Set card capabilities */
  card->caps |= SC_CARD_CAP_RNG;

  /* Set the supported algorithms */
  flags = SC_ALGORITHM_RSA_PAD_PKCS1;

  /* En sans contact, il n'est pas permis de faire de la signature */
  if (!priv->contactless) {
    flags |= SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_HASH_SHA256;
  }
  else {
    flags |= SC_ALGORITHM_RSA_HASH_NONE;
  }
  flags |= SC_ALGORITHM_RSA_RAW;

  /* Only 1024 bit key sizes were tested */
  _sc_card_add_rsa_alg(card, 1024, flags, 0);
  _sc_card_add_rsa_alg(card, 2048, flags, 0);
  _sc_card_add_rsa_alg(card, 512, flags, 0);

  card->max_recv_size = 0xE7;
  //if (use_cache) {
  //  if (card->serialnr.len != 0) {
  //    /* AROC (@@20130801-1071) - Ne pas bloquer la carte quand les données sont lues en cache : Debut */
  //    if (!_cps_read_efsnicc(card)) { return SC_ERROR_INTERNAL; }
  //    /* AROC (@@20130801-1071) - Fin*/
  //  }
  //}
  return SC_SUCCESS;
}

int cps3_check_type(sc_card_t* card)
{
  struct cps_priv_data* priv = NULL;
  int status = SC_SUCCESS;
  int locked = FALSE;
  sc_path_t tpath;
  sc_file_t* tfile = NULL;
  u8* buf_file = NULL;
  int r;

  if (card == NULL) {
    status = SC_ERROR_INVALID_ARGUMENTS;
    goto end;
  }

  if ((status = sc_lock(card)) != SC_SUCCESS) {
    goto end;
  }
  locked = TRUE;

  priv = DRVDATA(card);
  if (priv != NULL) {
    if (priv->cps_type == CPS_UNKNOWN) {

      // Essayer de lire un fichier du mode "en contact"
      sc_format_path("3F0000017001", &tpath);
      r = sc_select_file(card, &tpath, &tfile);
      if (r == 0 && tfile != NULL) {
        ALLOCATE(status, buf_file, tfile->size, card);
        r = sc_read_binary(card, 0, buf_file, 1, 0);
        if (r < 0) {
          priv->cps_type = CPS3_CONTACTLESS;
          if (card->ctx->processing_update) {
            r = 0;
            goto end;
          }
        }
        else {
          priv->cps_type = CPS3_CONTACT;
        }
      }
      else
      {
        status = SC_ERROR_INTERNAL;
        goto end;
      }
    }
    priv->contactless = (priv->cps_type == CPS3_CONTACTLESS);
  }
end:
  if (locked) { sc_unlock(card); };
  if (tfile != NULL) sc_file_free(tfile);
  if (buf_file != NULL) { free(buf_file); }
  return status;
}

/*--------------------------------------------------------------------------
     cps3_match_card

Fonction appelée par OpenSC pour que le driver vérifie s'il supporte la carte qui lui est passée en paramètre.
La fonction : vérifie si le fichier EFSN est présent et correspond à l'émetteur ASIP Santé
              vérifie si la carte présente fonctionne en mode sans contact ou non

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte

Codes retour:
SC_SUCCESS
SC_ERROR_OUT_OF_MEMORY
SC_ERROR_INTERNAL

--------------------------------------------------------------------------*/
static int cps3_match_card(sc_card_t *card)
{
  struct cps_priv_data *priv = NULL;
  INT card_type = -1;

  if (card->atr_len != 0) {
    if (!_is_cps_card(card->atr, card->atr_len, &card_type)) { return FALSE; }
    if (card_type != CPS3_CONTACT && card_type != CPS3_CONTACTLESS) { return FALSE; }
  }

  card->type = card_type == CPS3_CONTACT ? SC_CARD_TYPE_IAS_CPS3 : SC_CARD_TYPE_IAS_CPS3_CL; // pour traiter correctement l'instruction select
  card->sw1_bytes_available = CPS3_SW1_BYTES_AVAILABLE;
  card->sw1_cps2ter_bytes_available = CPS2TER_SW1_BYTES_AVAILABLE;
  
  if (card->ctx->processing_update) {
    return FALSE;
  }

  /* Lire le contenu du fichier EFSN dans le MF */
  if (!_cps_read_efsnicc(card)) { return FALSE; }
  priv = DRVDATA(card);
  if (priv != NULL) {
    priv->cps_type = card_type;
    priv->contactless = (card_type == CPS3_CONTACTLESS);
    priv->bad_actua = 0;
  }
  return TRUE;
}

/*--------------------------------------------------------------------------
     cps3_set_security_env

Fonction appelé par OpenSC pour positionner un environnement de sécurité sur la carte.
Dans le monde CPS3, l'envoi d'un APDU particulier en fonction du type d'opération est effectué pour basculer en mode sécurisé.

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte
env                : Pointeur vers l'envrionnement de sécuité à positionner
se_num             : Pointeur vers le numéro de l'environnement de sécurité passé en paramètre

Codes retour:
SC_SUCCESS
SC_ERROR_NOT_SUPPORTED

--------------------------------------------------------------------------*/
static int cps3_set_security_env(sc_card_t *card,
  const sc_security_env_t *env, int se_num)
{
  sc_apdu_t apdu;
  u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
  u8 *p;
  int r, locked = 0;

  assert(card != NULL && env != NULL);
  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0);
  switch (env->operation) {
  case SC_SEC_OPERATION_DECIPHER:
    apdu.p2 = 0xB8;
    break;
  case SC_SEC_OPERATION_SIGN:
    apdu.p2 = 0xB6;
    break;
  case SC_SEC_OPERATION_AUTHENTICATE:
    apdu.p2 = 0xA4;
    break;
  case SC_SEC_OPERATION_HASH:
    apdu.p2 = 0xAA;
    break;
  default:
    return SC_ERROR_INVALID_ARGUMENTS;
  }
  p = sbuf;
  if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
    *p++ = 0x80;  /* algorithm reference */
    *p++ = 0x01;
    *p++ = env->algorithm_ref & 0xFF;
  }
  if ((env->flags & SC_SEC_ENV_FILE_REF_PRESENT) &&
    (!IS_CARD_TYPE_CPS3(card->type))) { /* non supporté par la CPS3 lors d'une authentification avec la clé technique */
    *p++ = 0x81;
    *p++ = (u8)env->file_ref.len;
    assert(sizeof(sbuf) - (p - sbuf) >= env->file_ref.len);
    memcpy(p, env->file_ref.value, env->file_ref.len);
    p += env->file_ref.len;
  }
  if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
    if (env->flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC)
      *p++ = 0x83;
    else
      *p++ = 0x84;
    *p++ = (u8)env->key_ref_len;
    assert(sizeof(sbuf) - (p - sbuf) >= env->key_ref_len);
    memcpy(p, env->key_ref, env->key_ref_len);
    p += env->key_ref_len;
  }
  r = (int)(p - sbuf);
  apdu.lc = r;
  apdu.datalen = r;
  apdu.data = sbuf;
  if (se_num > 0) {
    r = sc_lock(card);
    SC_TEST_RET(card->ctx, r, "sc_lock() failed");
    locked = 1;
  }
  if (apdu.datalen != 0) {
    r = sc_transmit_apdu(card, &apdu);
    if (r) {
      sc_perror(card->ctx, r, "APDU transmit failed");
      goto err;
    }
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    if (r) {
      sc_perror(card->ctx, r, "Card returned error");
      goto err;
    }
  }
  if (se_num <= 0)
    return 0;
  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF2, se_num);
  r = sc_transmit_apdu(card, &apdu);
  sc_unlock(card);
  SC_TEST_RET(card->ctx, r, "APDU transmit failed");
  return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
  if (locked)
    sc_unlock(card);
  return r;
}

static int cps3_sign(sc_card_t *card, const u8 * data, size_t datalen, u8 * out, size_t outlen, unsigned long opType)
{
  int r = 0;
  sc_apdu_t apdu;
  u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
  u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
  int isPSOCDS = 0;


  assert(card != NULL && data != NULL && out != NULL);
  if (datalen > 255) {
    SC_FUNC_RETURN(card->ctx, 4, SC_ERROR_INVALID_ARGUMENTS);
  }

  SC_FUNC_CALLED(card->ctx, SC_LOG_TYPE_DEBUG);

  if (datalen == 0) {
    isPSOCDS = 1;
  }
  memset(&apdu, 0, sizeof(sc_apdu_t));

  if (opType == SC_SEC_OPERATION_SIGN) {
    /* INS: 0x2A  PERFORM SECURITY OPERATION
    * P1:  0x9E  Resp: Digital Signature
    * P2:  0x9A  Cmd: Input for Digital Signature */
    sc_format_apdu(card, &apdu, (isPSOCDS == 1) ? SC_APDU_CASE_2_SHORT : SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
  }
  else if (SC_SEC_OPERATION_AUTHENTICATE) {
    /* INS: 0x88  INTERNAL AUTHENTICATE for Client/Server authentication
    * P1:  0x00  Référence de l'algorithme spécifiée dans le SE actif
    * P2:  0x00  Référence secrète spécifiée dans le SE actif */
    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x88, 0x00, 0x00);
  }
  else {
    SC_FUNC_RETURN(card->ctx, 4, SC_ERROR_NOT_SUPPORTED);
  }

  if (isPSOCDS == 1) {
    apdu.data = 0;
    apdu.lc = 0;
    apdu.datalen = 0;
  }
  else {
  memcpy(sbuf, data, datalen);
  apdu.data = sbuf;
  apdu.lc = datalen;
  apdu.datalen = datalen;
  }

  apdu.resp = rbuf;
  apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
  apdu.le = SC_MAX_APDU_RESP_SIZE;

  apdu.sensitive = 1;
  r = sc_transmit_apdu(card, &apdu);
  SC_TEST_RET(card->ctx, r, "APDU transmit failed");
  if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
    size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;

    memcpy(out, apdu.resp, len);
    SC_FUNC_RETURN(card->ctx, 4, (int)len);
  }
  SC_FUNC_RETURN(card->ctx, 4, sc_check_sw(card, apdu.sw1, apdu.sw2));
}


static int cps3_internal_authenticate(sc_card_t *card, const u8 * data, size_t datalen, u8 * out, size_t outlen)
{
  return cps3_sign(card, data, datalen, out, outlen, SC_SEC_OPERATION_AUTHENTICATE);
}

/*--------------------------------------------------------------------------
     cps3_compute_signature

Fonction réalisant les opération cryptographiques de signature en mode PSO CDS ou Internal Authenticate

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte
data               : Données à signer / déchiffrer
datalen            : Longueur des données à signer / déchiffrer
out                : Buffer recevant la signature / les données déchiffrées
outlen             : Longueur du buffer recevant la signature / les données déchiffrées

Codes retour:
SC_SUCCESS
SC_ERROR_INVALID_ARGUMENTS
SC_ERROR_NOT_SUPPORTED

--------------------------------------------------------------------------*/
static int cps3_compute_signature(sc_card_t *card, const u8 * data,
  size_t datalen, u8 * out, size_t outlen)
{
  return cps3_sign(card, data, datalen, out, outlen, SC_SEC_OPERATION_SIGN);
}


/*--------------------------------------------------------------------------
     cps3_decipher

Fonction réalisant les opération cryptographiques de déchiffrement en mode PSO

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte
crgram             : Données à déchiffrer
crgram_len         : Longueur des données à déchiffrer
out                : Buffer recevant les données déchiffrées
outlen             : Longueur effective des données déchiffrées

Codes retour:
SC_ERROR_MEMORY_FAILURE
Taille réponse à l'APDU si OK sinon état du SW

--------------------------------------------------------------------------*/
static int cps3_decipher(sc_card_t *card,
  const u8 * crgram, size_t crgram_len,
  u8 * out, size_t outlen)
{
  int       r;
  sc_apdu_t apdu;
  u8        *sbuf = NULL;

  assert(card != NULL && crgram != NULL && out != NULL);
  SC_FUNC_CALLED(card->ctx, 2);

  sbuf = (u8 *)malloc(crgram_len + 1);
  if (sbuf == NULL)
    return SC_ERROR_MEMORY_FAILURE;

  /* INS: 0x2A  PERFORM SECURITY OPERATION
   * P1:  0x80  Resp: Plain value
   * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
  sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x80, 0x86);
  apdu.resp = out;
  apdu.resplen = outlen;
  /* if less than 256 bytes are expected than set Le to 0x00
   * to tell the card the we want everything available (note: we
   * always have Le <= crgram_len) */
  apdu.le = (outlen >= 256 && crgram_len < 256) ? 256 : outlen;
  apdu.sensitive = 1;

  sbuf[0] = 0x81; /* padding indicator byte, 0x81 for RSA */
  memcpy(sbuf + 1, crgram, crgram_len);
  apdu.data = sbuf;
  apdu.lc = crgram_len + 1;
  apdu.datalen = crgram_len + 1;
  if (IS_CARD_TYPE_CPS3(card->type))
    apdu.flags |= SC_APDU_FLAGS_CHAINING;
  r = sc_transmit_apdu(card, &apdu);
  sc_mem_clear(sbuf, crgram_len + 1);
  free(sbuf);
  SC_TEST_RET(card->ctx, r, "APDU transmit failed");
  if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
    SC_FUNC_RETURN(card->ctx, 2, (int)apdu.resplen);
  else
    SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

/*--------------------------------------------------------------------------
     cps3_get_aid_pkcs15

Fonction récupérant l'AID (application identifier) correspondant à l'un des deux modes contact/sans contact

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte
aid                : Buffer recevant l'AID
aid_len            : Longueur effective de l'AID

Codes retour:
SC_SUCCESS
SC_ERROR_INTERNAL

--------------------------------------------------------------------------*/
static int cps3_get_aid_pkcs15(sc_card_t *card, u8 * aid, size_t *aid_len)
{
  struct cps_priv_data *priv = DRVDATA(card);
  if (priv != NULL) {
    if (priv->contactless) {
      *aid_len = sizeof(cps3_aid_cps3_cl);
      memcpy(aid, cps3_aid_cps3_cl, *aid_len);
    }
    else {
      *aid_len = sizeof(cps3_aid_cps3);
      memcpy(aid, cps3_aid_cps3, *aid_len);
    }
  }
  else return SC_ERROR_INTERNAL;

  return SC_SUCCESS;
}

/*--------------------------------------------------------------------------
     cps3_compute_hash

Fonction réalisant les opération cryptographiques de condensat en mode PSO CDS ou Internal Authenticate

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte
data               : Données à condenser
datalen            : Longueur des données à condenser
remainingdata      : les données restant à condenser
remainingdatalen   : Longueur des données restant à condenser
msglen             : Longueur totale des données à condenser

Codes retour:
SC_SUCCESS
SC_ERROR_INVALID_ARGUMENTS
Etat du SW

--------------------------------------------------------------------------*/
static int cps3_compute_hash(sc_card_t *card, const u8 * data,
  size_t datalen, const u8 * remainingdata,
  size_t remainingdatalen, size_t msglen)
{
  int r;
  size_t i;
  sc_apdu_t apdu;
  u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
  //u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
  u8 *p;

  assert(card != NULL && data != NULL && remainingdata != NULL);
  if (remainingdatalen > 64 || remainingdatalen == 0)
    SC_FUNC_RETURN(card->ctx, 4, SC_ERROR_INVALID_ARGUMENTS);

  SC_FUNC_CALLED(card->ctx, SC_LOG_TYPE_DEBUG);

  /* INS: 0x2A  PERFORM SECURITY OPERATION
   * P1:  0x90  Resp: Hash
   * P2:  0xA0  Cmd: Données fournies pour le hash */
  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x90,
    0xA0);

  p = sbuf;
  *p++ = 0x90;
  *p++ = (u8)(datalen == 0 ? datalen : datalen + 8);
  if (datalen != 0)
    memcpy(p, data, datalen);
  p += datalen;
  if (datalen != 0) {
    /* taille du message en bits */
    for (i = 0; i < 3; i++)
      *p++ = 0x00; /* un size_t fait 4 octets, donc même en multipliant par 8 les 3 premiers octets sont à zéro */
    for (i = 0; i < 5; i++) {
      size_t tmp = msglen;
      if (i == 4)
        tmp = (0xFF & tmp) << 3;
      else
        tmp = tmp >> ((4 - i) * 8 - 3);

      *p++ = (u8)0xFF & tmp;
    }
  }
  /* dernier bloc à hasher */
  *p++ = 0x80;
  *p++ = (u8)remainingdatalen;
  memcpy(p, remainingdata, remainingdatalen);
  p += remainingdatalen;
  apdu.le = 0;
  apdu.data = sbuf;
  apdu.resplen = 0;
  apdu.lc = p - sbuf;
  apdu.datalen = apdu.lc;
  /* MCUG 02/09/2010 : Ajout du cryptage de données sensibles sur la log d'apdu */
  apdu.sensitive = 1;
  /* MCUG 02/09/2010 : Fin */

  r = sc_transmit_apdu(card, &apdu);
  SC_TEST_RET(card->ctx, r, "APDU transmit failed");
  SC_FUNC_RETURN(card->ctx, 4, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

/*--------------------------------------------------------------------------
     cps3_get_pin_counter

Fonction testant au moyen d'un APDU le nombre d'essais restant pour la saisie d'un code correct

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte
sc_pin_counter_t   : Pointeur vers l'objet de mémorisation de l'état des codes carte

Codes retour:
SC_SUCCESS
SC_ERROR_INVALID_ARGUMENTS
SC_ERROR_NOT_SUPPORTED
Etat du SW

--------------------------------------------------------------------------*/
static int cps3_get_pin_counter(sc_card_t *card, sc_pin_counter_t *pin_counter)
{
  int r;
  sc_apdu_t apdu;
  u8 sbuf[SC_MAX_APDU_BUFFER_SIZE] = { 0x4D,0x08,0x70,0x06,0xBF,0x81,0x01,0x02,0xA0,0x80 };
  u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
  u8 *p;
  sc_path_t tmppath;

  assert(card != NULL && pin_counter != NULL);

  sc_format_path("3F00", &tmppath);

  r = sc_select_file(card, &tmppath, NULL);
  if (r != SC_SUCCESS) {
    return r;
  }

  /* INS: 0xCB  GET_DATA for SDO
   * P1:  0x3F  Resp: Hash
   * P2:  0xFF  Cmd: Données fournies pour le hash */
  sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xCB, 0x3F, 0xFF);

  p = sbuf;
  *(p + 6) = (u8)pin_counter->pin_reference;
  apdu.data = sbuf;
  apdu.lc = 10;
  apdu.datalen = apdu.lc;
  apdu.resp = rbuf;
  apdu.resplen = sizeof(rbuf);
  apdu.le = 256;
  r = sc_transmit_apdu(card, &apdu);
  SC_TEST_RET(card->ctx, r, "APDU transmit failed");
  if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
    _cps_get_pin_info(card, apdu.resp, apdu.resplen - 2, pin_counter);
    SC_FUNC_RETURN(card->ctx, 2, SC_SUCCESS);
  }
  else {
    SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
  }
}

/*--------------------------------------------------------------------------
     cps3_select_file

Fonction selectionnant au moyen d'un chemin le fichier sur la carte

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte
in_path            : chemin du fichier à récupérer
file_out           : Pointeur vers un objet qui contiendra les informations liées au fichier

Codes retour:
SC_SUCCESS
SC_ERROR_INVALID_ARGUMENTS
SC_ERROR_NOT_SUPPORTED
SC_ERROR_UNKNOWN_DATA_RECEIVED
SC_ERROR_OUT_OF_MEMORY
Etat du SW

--------------------------------------------------------------------------*/
static int cps3_select_file(sc_card_t *card, const sc_path_t *in_path,
  sc_file_t **file_out)
{
  int                     r, pathlen, stripped_len, offset;
  u8                              buf[SC_MAX_APDU_BUFFER_SIZE];
  u8                              pathbuf[SC_MAX_PATH_SIZE], *path;
  sc_context_t    *ctx;
  sc_apdu_t               apdu;
  sc_file_t               *file;

  r = pathlen = stripped_len = offset = 0;
  path = pathbuf;
  file = NULL;

  assert(card != NULL && in_path != NULL);
  ctx = card->ctx;

  if (in_path->len > SC_MAX_PATH_SIZE)
    return SC_ERROR_INVALID_ARGUMENTS;
  memcpy(path, in_path->value, in_path->len);
  pathlen = (int)in_path->len;

  sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
  apdu.p2 = 4; /* First record, return FCI */

  switch (in_path->type) {
  case SC_PATH_TYPE_FILE_ID:
    apdu.p1 = 2;
    if (pathlen != 2)
      return SC_ERROR_INVALID_ARGUMENTS;
    break;
  case SC_PATH_TYPE_DF_NAME:
    apdu.p1 = 4;
    break;
  case SC_PATH_TYPE_PATH:
    apdu.p1 = 9;
    if (!IS_CARD_TYPE_CPS3(card->type)) {
      /* Strip the MF */
      if (pathlen >= 2 && memcmp(path, "\x3f\x00", 2) == 0) {
        if (pathlen == 2) { /* Only 3f00 provided */
          apdu.p1 = 0;
          break;
        }
        path += 2;
        pathlen -= 2;
      }
      /* Optimization based on the normal Portuguese eID usage pattern:
       * paths with len >= 4 shall be stripped - this avoids unnecessary
       * "file not found" errors. Other cards may benefit from this also.
       *
       * This works perfectly for the Portuguese eID card, but if you
       * are adapting this driver to another card, "false positives" may
       * occur depending, of course, on the file structure of the card.
       *
       * Please have this in mind if adapting this driver to another card.
       */
      if (pathlen >= 4) {
        stripped_len = pathlen - 2;
        path += stripped_len;
        pathlen = 2;
      }
      else if (pathlen == 2) {
        apdu.p1 = 0;
      }
    }
    break;
  case SC_PATH_TYPE_FROM_CURRENT:
    apdu.p1 = 9;
    break;
  case SC_PATH_TYPE_PARENT:
    apdu.p1 = 3;
    apdu.p2 = 0x0C;
    pathlen = 0;
    apdu.cse = SC_APDU_CASE_2_SHORT;
    break;
  default:
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_INVALID_ARGUMENTS);
  }

  apdu.lc = pathlen;
  apdu.data = path;
  apdu.datalen = pathlen;

  if (file_out != NULL) {
    apdu.resp = buf;
    apdu.resplen = sizeof(buf);
    apdu.le = 256;
  }
  else {
    apdu.p2 = 0x0C;
    apdu.cse = (apdu.lc == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
  }

  r = sc_transmit_apdu(card, &apdu);
  SC_TEST_RET(card->ctx, r, "APDU transmit failed");
  if (file_out == NULL) {
    if (apdu.sw1 == card->sw1_bytes_available)
      SC_FUNC_RETURN(card->ctx, 2, 0);
    SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
  }

  /* A "file not found" error was received, this can mean two things:
   * 1) the file does not exist
   * 2) the current DF may be incorrect due to the optimization applied
   *    earlier. If the path was previously stripped, select the first DF
   *    and try to re-select the path with the full value.
   */
  if (stripped_len > 0 && apdu.sw1 == 0x6A && apdu.sw2 == 0x82) {
    sc_path_t tpath;

    /* Restore original path value */
    path -= stripped_len;
    pathlen += stripped_len;

    memset(&tpath, 0, sizeof(sc_path_t));
    tpath.type = SC_PATH_TYPE_PATH;
    tpath.len = 2;
    tpath.value[0] = path[0];
    tpath.value[1] = path[1];

    /* Go up in the hierarchy to the correct DF */
    r = cps3_select_file(card, &tpath, NULL);
    SC_TEST_RET(card->ctx, r, "Error selecting parent.");

    /* We're now in the right place, reconstruct the APDU and retry */
    path += 2;
    pathlen -= 2;
    apdu.lc = pathlen;
    apdu.data = path;
    apdu.datalen = pathlen;

    if (file_out != NULL)
      apdu.resplen = sizeof(buf);

    r = sc_transmit_apdu(card, &apdu);
    SC_TEST_RET(card->ctx, r, "APDU transmit failed");
    if (file_out == NULL) {
      if (apdu.sw1 == card->sw1_bytes_available)
        SC_FUNC_RETURN(card->ctx, 2, 0);
      SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
    }
  }

  r = sc_check_sw(card, apdu.sw1, apdu.sw2);
  if (r)
    SC_FUNC_RETURN(card->ctx, 2, r);

  if (apdu.resplen < 2)
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
  switch (apdu.resp[0]) {
  case 0x62:
  case 0x6F:
    file = sc_file_new();
    if (file == NULL)
      SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);
    file->path = *in_path;
    if (card->ops->process_fci == NULL) {
      sc_file_free(file);
      SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
    }
    if ((size_t)apdu.resp[1] + 2 <= apdu.resplen)
      card->ops->process_fci(card, file, apdu.resp + 2, apdu.resp[1]);
    *file_out = file;
    break;
  case 0x00:      /* proprietary coding */
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
  default:
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
  }

  return SC_SUCCESS;
}

// Compute an epoch date from a string representation of a date
/*--------------------------------------------------------------------------
     get_ef_actua_time

Fonction determinant une date en millisecondes d'après sa représentation chaîne

Parametres:
date_value         : Pointeur vers la chaine représentant la date

Codes retour:
la date en millisecondes

--------------------------------------------------------------------------*/
time_t get_ef_actua_time(char *date_value) {

  struct tm tm = { 0 };

  sscanf(date_value, "%4d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
  // fix up to struct tm base values:
  tm.tm_year -= 1900;
  tm.tm_mon -= 1;

  // adjust for 24 hour clock
  if (tm.tm_hour == 24)
    tm.tm_hour = 0;

  return mktime(&tm);

}
/* MCUG 05/11/2010 : Fin */

/* MCUG 05/11/2010 : Gestion de la mise à jour des fichiers de situations */
/*--------------------------------------------------------------------------
     sc_pkcs15_parse_ef_actua

Fonction analysant le fichier EF_ACTUA d'apres l'état du cache fichier

Parametres:
ef_actua_file      : Pointeur vers l'objet contenant les informations du fichier EF_ACTUA
ef_actua_fields    : Pointeur vers l'objet contenant les attributs du fichier EF_ACTUA
buf                : Buffer contenant le fichier lu en cache
blen               : Longueur du fichier lu en cache

Codes retour:
SC_SUCCESS

--------------------------------------------------------------------------*/
int sc_pkcs15_parse_ef_actua(struct sc_pkcs15_ef_actua *ef_actua_file, struct sc_ef_actua_fields ef_actua_fields, const u8 *buf, int blen)
{

  int start_date_length;
  char* start_date_value;
  int end_date_length;
  char* end_date_value;
  int i = 0;
  int j = 0;

  for (i = 0; i < blen; i++) {

    if (buf[i] == ef_actua_fields.actua_template_tag) {
      i++;
      //template_length = (int) buf[i];
      continue;
    }

    if (buf[i] == ef_actua_fields.actua_start_date_tag) {
      i++;
      start_date_length = (int)buf[i];
      j = 0;
      start_date_value = calloc(start_date_length * 2, sizeof(char));
      for (j = 0; j < start_date_length * 2; j++) {
        i++;
        start_date_value[j] = (char)buf[i] >> 4; // bitwise shift to retrieve the left value of the byte 
        start_date_value[j] += 0x30; // to convert it in char
        start_date_value[++j] = (char)buf[i] & 0x0f; // bitwise AND 1 in order to retrieve the right value of the byte
        start_date_value[j] += 0x30; // to convert it in char

      }
      ef_actua_file->actua_start_date = get_ef_actua_time(start_date_value);
      free(start_date_value);
      continue;
    }

    if (buf[i] == ef_actua_fields.actua_end_date_tag) {
      i++;
      end_date_length = (int)buf[i];
      j = 0;
      end_date_value = calloc(end_date_length * 2, sizeof(char));
      for (j = 0; j < end_date_length * 2; j++) {
        i++;
        end_date_value[j] = (char)buf[i] >> 4; // bitwise shift to retrieve the left value of the byte 
        end_date_value[j] += 0x30; // to convert it in char
        end_date_value[++j] = (char)buf[i] & 0x0f; // bitwise AND 1 in order to retrieve the right value of the byte
        end_date_value[j] += 0x30; // to convert it in char
      }
      ef_actua_file->actua_end_date = get_ef_actua_time(end_date_value);
      free(end_date_value);
      continue;
    }
  }

  return SC_SUCCESS;
}

/* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
/*--------------------------------------------------------------------------
     cps3_verify_update

Fonction analysant le fichier EF_ACTUA pour savoir si la carte a été mise a jour

Parametres:
p15card            : Pointeur vers l'objet de la structure P15 de la carte

Codes retour:
SC_SUCCESS
SC_ERROR_INTERNAL
SC_ERROR_OUT_OF_MEMORY

--------------------------------------------------------------------------*/
static int cps3_verify_update(struct sc_pkcs15_card *p15card)
{
  int err = -1;
  /* AROC 24/03/2011 : Portage MAC OS X */
  /*int len = -1;*/
  size_t len = -1;
  /* AROC 24/03/2011 : Fin */
  int isCached = -1; /* file state: not in cache */
  int isOnCard = -1; /* file state: not on card */
  int update = 0; /* update state: not required */
  u8* buf_cached_file = NULL;
  u8* buf_file = NULL;
  struct sc_pkcs15_ef_actua ef_actua_card_file;
  struct sc_pkcs15_ef_actua ef_actua_cached_file;
  sc_file_t *file_actua;
  sc_path_t tmppath;
  sc_file_t *file_actua_cache;
  sc_path_t tmppath_cache;
  int r = SC_SUCCESS;

  struct cps_priv_data *priv = DRVDATA(p15card->card);

  // Pas d'accès au fichier EF_ACTUA en mode sans contact
  if (priv != NULL) {
    if (priv->contactless)
      return 0;
  }
  else return SC_ERROR_INTERNAL;

  // BPER Pas d'accès au fichier EF_ACTUA en mode mise a jour de cartes CPS
  if (p15card->card->ctx->use_cache == 0) {
	  return 0;
  }

  /* Read EF_ACTUA file on cache */
  file_actua_cache = sc_file_new();
  tmppath_cache = file_actua_cache->path;
  sc_format_path(CPS3_EF_ACTUA_PATH, &tmppath_cache);
  isCached = sc_select_cached_file(p15card->card, &tmppath_cache, &file_actua_cache, 1);
  if (isCached == 0) {
    isCached = sc_pkcs15_read_cached_file(p15card, &tmppath_cache, &buf_cached_file, &len);
    if (isCached == 0) {
      sc_pkcs15_parse_ef_actua(&ef_actua_cached_file, cps3_ef_actua_fields, buf_cached_file, (int)len);

      /* If cached file is corrupted, delete it */
      if (ef_actua_cached_file.actua_start_date < 0 || ef_actua_cached_file.actua_end_date < 0) {
        sc_pkcs15_delete_cached_file(p15card);
        isCached = -1;
      }
    }
  }
  sc_file_free(file_actua_cache);

  /* Read EF_ACTUA file on the card */
  file_actua = sc_file_new();
  tmppath = file_actua->path;
  sc_format_path(CPS3_EF_ACTUA_PATH, &tmppath);

  sc_lock(p15card->card);
  err = sc_select_file(p15card->card, &tmppath, &file_actua);
  if (err)
    goto end;
  isOnCard = err;

  if ((len = file_actua->size) == 0) {
    sc_error(p15card->card->ctx, "EF_ACTUA is empty\n");
    priv->bad_actua = 1;
    goto end;
  }
  buf_file = malloc(len);
  if (buf_file == NULL) {
    sc_error(p15card->card->ctx, "Out of memory\n");
    r = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  err = sc_read_binary(p15card->card, 0, buf_file, len, 0);
  if (err < 0) {
    priv->bad_actua = 1;
    goto end;
  }

  sc_pkcs15_parse_ef_actua(&ef_actua_card_file, cps3_ef_actua_fields, buf_file, err);

  /* If the EF_ACTUA file is valid, and EF_ACTUA not in cache save it into the cache */
  if (isCached < 0 && ef_actua_card_file.actua_start_date > -1 && ef_actua_card_file.actua_end_date > -1) {

    // Clean cache just in case some cached files were already there
    sc_pkcs15_delete_cached_file(p15card);

    sc_pkcs15_cache_file(p15card, &tmppath, buf_file, len);
    goto end;
  }
  /* MCUG 13/12/2010 : Prise en compte d'un cas ignorée jusque là */
/* If the EF_ACTUA file is invalid, and EF_ACTUA not in cache => bad_actua */
  else if (isCached < 0 && (ef_actua_card_file.actua_start_date < 0 || ef_actua_card_file.actua_end_date < 0)) {
    priv->bad_actua = 1;
    goto end;
  }
  /* MCUG 13/12/2010 : FIN */

  /* If there is an EF_ACTUA file in the cache we should parse it and compare it with the one from the card */
  if (update == 0 && isCached == 0) {

    /* If the EF_ACTUA file is invalid do not update the cache */
    if (ef_actua_card_file.actua_start_date < 0 || ef_actua_card_file.actua_end_date < 0) {
      sc_error(p15card->card->ctx, "EF_ACTUA is invalid\n");
      priv->bad_actua = 1;
      goto end;
    }

    /* If cached EF_ACTUA differs from the card's EF_ACTUA erase all situations files */
    if (ef_actua_card_file.actua_start_date != ef_actua_cached_file.actua_start_date
      || ef_actua_card_file.actua_end_date != ef_actua_cached_file.actua_end_date)
      update = 1;
  }

  if (update) {

    sc_pkcs15_delete_cached_file(p15card);

    /* If the EF_ACTUA file is valid, save it into the cache */
    if (isCached == 0 && ef_actua_card_file.actua_start_date > -1 && ef_actua_card_file.actua_end_date > -1)
      sc_pkcs15_cache_file(p15card, &tmppath, buf_file, len);
  }

end:

  if (buf_cached_file != NULL) { free(buf_cached_file); }
  buf_cached_file = NULL;
  if (buf_file != NULL) { free(buf_file); }
  buf_file = NULL;
  if (file_actua) { sc_file_free(file_actua); }

  sc_unlock(p15card->card);
  return r;
  /* MCUG 14/09/10 : Fin */

}







/*--------------------------------------------------------------------------
sc_get_driver

Fonction initialisant le driver CPS3. L'initialisation consiste à intialiser le driver
CPS3 avec un driver ISO7816, puis à surcharger certaines des fonctions de ce driver par les
fonctions spécifiques CPS3 définies dans ce fichier.

Parametres:

Codes retour:
La fonction renvoie la structure du driver CPS3 initialisé

--------------------------------------------------------------------------*/
static struct sc_card_driver *sc_get_driver(void)
{
  struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

  /* Use the standard iso operations as default */
  cps3_ops = *iso_drv->ops;
  /* CPS3 specific functions */
  cps3_ops.select_file = cps3_select_file;
  cps3_ops.match_card = cps3_match_card;
  cps3_ops.init = cps3_init;
  cps3_ops.set_security_env = cps3_set_security_env;
  cps3_ops.compute_signature = cps3_compute_signature;
  cps3_ops.compute_hash = cps3_compute_hash;
  cps3_ops.internal_authenticate = cps3_internal_authenticate;
  cps3_ops.decipher = cps3_decipher;
  cps3_ops.get_aid_pkcs15 = cps3_get_aid_pkcs15;
  cps3_ops.get_pin_counter = cps3_get_pin_counter;
  cps3_ops.verify_update = (void*)cps3_verify_update; /* Gestion de la mise à jour des fichiers de situations */
  cps3_ops.is_visible = cps_is_visible; /* Afin de permettre le masquage de certains objets */
  cps3_ops.get_model = cps_get_model; /* Retourne le moodèle de la carte*/
  cps3_ops.is_valid = cps_is_valid; /* Vérifie si la carte est valide*/
  cps3_ops.cps2ter_select_file = cps2ter_select_file;
  cps3_ops.finish = cps_finish;
  /* Ajout des fonctions pour la mise a jour de la carte : Debut */
  cps3_ops.start_exlusivity = cps_start_exlusivity;
  cps3_ops.end_exlusivity = cps_end_exlusivity;
  cps3_ops.free_transmit = cps_free_transmit;
  cps3_ops.get_status = cps_get_status;
  /* Ajout des fonctions pour la mise a jour de la carte : Fin */
  return &cps3_drv;
}

/*--------------------------------------------------------------------------
sc_get_cps3_driver

Fonction appelant la fonction d'initialisation du driver CPS3 définie ci-dessus.

Parametres:

Codes retour:
La fonction renvoie la structure du driver CPS3 initialisé

--------------------------------------------------------------------------*/
struct sc_card_driver* sc_get_cps3_driver(void)
{
  return sc_get_driver();
}
