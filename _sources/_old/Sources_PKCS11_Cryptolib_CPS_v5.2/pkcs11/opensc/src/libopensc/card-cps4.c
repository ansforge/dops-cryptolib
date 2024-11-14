/*
 * card-cps3.c : Driver for CPS4 based cards
 *
 * Copyright (C) 2010-2024, ASIP Santé
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

//#define DRVDATA(card)   ((struct cps4_priv_data *) ((card)->drv_data))

 /* préfix du numéro de série */
#define PREFIX_SN          "8025000001"
#define CPS4_EF_ACTUA_PATH "3F00D010"
#define CPS4_EF_SN         "3F00D003"
/* No more PIN command to transmit */
#define SC_PIN_CMD_NONE    -1
/* Use channel one for all APDUs */
#define CLA_CHANNEL_ISO   0x00
#define CLA_CHANNEL_ONE   0x01
#define CHIPDOC_APP_AID  "\x80\x25\x00\x00\x01\xFF\x01\x00"
#define CHIPDOC_APP_LEN   0x08 

static struct sc_card_operations cps4_ops;
static struct sc_card_operations *iso_ops = NULL;

static struct sc_card_driver cps3_drv = { "NXP", "cps4", &cps4_ops, NULL, 0, NULL};



/* Known AIDs */
static const u8 cps_aid_cps4[] = { 0xE8, 0x28, 0xBD, 0x08, 0x0F, 0x80, 0x25, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x10 };

static int cps4_select_file(sc_card_t* card, const sc_path_t* in_path, sc_file_t** file_out);
static int _do_reselect_cps4_aid(sc_card_t* card);
/*--------------------------------------------------------------------------
     cps4_init

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
static int cps4_init(sc_card_t *card)
{
  unsigned long flags;
  int use_cache = 1;

  struct cps_priv_data *priv = DRVDATA(card);

  if (priv == NULL)
    return SC_ERROR_INTERNAL;


  assert(card != NULL);

  SC_FUNC_CALLED(card->ctx, 1);
  card->name = "NXP";
  //card->sw1_cps2ter_bytes_available = CPS2TER_SW1_BYTES_AVAILABLE;

  /* Card version detection */
  if (card->type != SC_CARD_TYPE_IAS_CPS4) {
    return SC_ERROR_INTERNAL;
  }

  /* Set card capabilities */
  card->caps |= SC_CARD_CAP_RNG;


  if (priv == NULL) {
    return SC_ERROR_INTERNAL;
  }

  /* Set the supported algorithms */
  flags  = SC_ALGORITHM_RSA_PAD_PKCS1;
  flags |= SC_ALGORITHM_RSA_HASH_SHA1;
  flags |= SC_ALGORITHM_RSA_HASH_SHA256;
  flags |= SC_ALGORITHM_RSA_RAW;
  flags |= SC_ALGORITHM_RSA_PAD_PSS;

  _sc_card_add_rsa_alg(card, 2048, flags, 0);
  
  card->max_recv_size = SC_DEFAULT_MAX_RECV_SIZE;
  if (use_cache) {
    int err;
    size_t len;
    u8 *buf;
    char *serial_number;
    sc_file_t *file_sn;
    sc_path_t tmppath;

    /* AROC (@@20130801-1071) - Ne pas bloquer la carte quand les données sont lues en cache : Debut */
    if (card->serialnr.len != 0) {
      return SC_SUCCESS;
    }
    /* AROC 08/11/2011 - Fin */
    sc_lock(card);
    /* AROC (@@20130801-1071) - Fin*/

    file_sn = sc_file_new();
    tmppath = file_sn->path;
    sc_format_path(CPS_EF_SN_PATH, &tmppath);

    err = sc_select_file(card, &tmppath, &file_sn);
    if (err) {
      sc_unlock(card);
      return err/*SC_SUCCESS*/;
    }
    if ((len = file_sn->size) == 0) {
      sc_error(card->ctx, "EF(SN.ICC) is empty\n");
      sc_unlock(card);
      return err;
    }
    buf = malloc(len);
    if (buf == NULL) {
      sc_unlock(card);
      return SC_ERROR_OUT_OF_MEMORY;
    }
    err = sc_read_binary(card, 0, buf, len, 0);
    if (err < 0) {
      sc_unlock(card);
      return err;
    }
    err = sc_pkcs15_parse_efsnicc(card->ctx, &serial_number, buf, (size_t)err);
    if (err == SC_SUCCESS) {
      if (serial_number) {
        size_t offset = 0;
        if (strstr(serial_number, PREFIX_SN)) {
          offset = strlen(PREFIX_SN);
        }
        /* recopier le numéro de série sans le préfix */
        strcpy((char*)card->serialnr.value, serial_number + offset);
        card->serialnr.len = strlen((char*)card->serialnr.value);
      }
    }
    if (serial_number) {
      free(serial_number);
    }
  }
  sc_unlock(card);
  return SC_SUCCESS;
}

static int _cps4_select_app(sc_card_t* card)
{
  sc_path_t chipdoc_path = { 0 };

  /* Resélectionner l'applet ChipDoc depuis le nouveau canal */
  memcpy(chipdoc_path.value, CHIPDOC_APP_AID, CHIPDOC_APP_LEN);
  chipdoc_path.len = CHIPDOC_APP_LEN;
  chipdoc_path.type = SC_PATH_TYPE_DF_NAME;
  return cps4_select_file(card, &chipdoc_path, NULL);
}

/*--------------------------------------------------------------------------
     cps4_match_card

Fonction appelée par OpenSC pour que le driver vérifie s'il supporte la carte qui lui est passée en paramètre.
La fonction : vérifie si le fichier EFSN est présent et correspond à l'émetteur ASIP Santé
              vérifie si la carte présente fonctionne en mode sans contact ou non

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte

Codes retour:
 TRUE si la carte est une CPS v4, sinon FALSE

--------------------------------------------------------------------------*/
static int cps4_match_card(sc_card_t* card)
{
    int r=0;
    struct cps_priv_data* priv = NULL;
    int card_type = -1;

    if (card->atr_len != 0) {
        if (!_is_cps_card(card->atr, card->atr_len, &card_type)) { SC_FUNC_RETURN(card->ctx, SC_LOG_TYPE_DEBUG, r); return r; }
    }

    if (card->cla == CLA_CHANNEL_ISO) {
        card->cla = CLA_CHANNEL_ONE;
    }

    r = _cps4_select_app(card);
    if (r != SC_SUCCESS) {
      r = _do_reselect_cps4_aid(card);
    }
    if (r == SC_SUCCESS) {
      card->type = SC_CARD_TYPE_IAS_CPS4;
      card->sw1_bytes_available = CPS4_SW1_BYTES_AVAILABLE;
      r = _cps_read_efsnicc(card);
      if (r == SC_SUCCESS) {
        priv = DRVDATA(card);
        if (priv != NULL) {
          priv->cps_type = CPS4_CONTACT;
          priv->contactless = 0;
          priv->bad_actua = 0;
        }
      }
    }
    return r;
}



/*--------------------------------------------------------------------------
     cps4_set_security_env

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
static int cps4_set_security_env(sc_card_t *card, const sc_security_env_t *env, int se_num)
{

  sc_apdu_t apdu;
  u8 sbuf[4] = "";
  int r = 0;

  assert(card != NULL && env != NULL);
  /* INS  :   0x22 - MANAGE SECURITY ENVIRONMENT
   * P1-P2: 0x81 0xB6 - Set DST for Digital Signature
   * P1-P2: 0x41 0xB8 - Set DST for Decipher
   */ 
  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x00, 0x00);
  switch (env->operation) {
  case SC_SEC_OPERATION_AUTHENTICATE:
  case SC_SEC_OPERATION_DECIPHER:
    apdu.p1 = 0x41;
    apdu.p2 = 0xB8;
    apdu.datalen = apdu.lc = 0x03; // MSE Decrypt data size 
    sbuf[0] = 0x83; // Decrypt Data Tag
    sbuf[1] = 0x01; // Decrypt Data Tag Size
    sbuf[2] = CPS4_AUTH_PRIV_KEY_ID; // Key Id
    
    break;
  case SC_SEC_OPERATION_SIGN:
    apdu.p1 = 0x81;
    apdu.p2 = 0xB6;
    apdu.datalen = apdu.lc = 0x04; // MSE Sign data size 
    sbuf[0] = 0x91; // Digital Signature Data Tag
    sbuf[1] = 0x02; // Digital Signature Data Size
    sbuf[2] = env->algorithm_ref; // Algorithm Id
    sbuf[3] = env->key_ref[0] | 0x80; // Key Id with MSB for signing hash data
    break;
  default:
    return SC_ERROR_INVALID_ARGUMENTS;
  }

  apdu.data = sbuf;
  if (sc_lock(card) == SC_SUCCESS) {
    r = sc_transmit_apdu(card, &apdu);
    sc_unlock(card);
  }

  SC_TEST_RET(card->ctx, r, "APDU transmit failed");
  return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int cps4_sign(sc_card_t *card, const u8 * data, size_t datalen, u8 * out, size_t outlen, unsigned long opType)
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




/*--------------------------------------------------------------------------
     cps4_compute_signature

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
static int cps4_compute_signature(sc_card_t *card, const u8 * data,
  size_t datalen, u8 * out, size_t outlen)
{
  return cps4_sign(card, data, datalen, out, outlen, SC_SEC_OPERATION_SIGN);
}

extern int sc_pkcs1_strip_02_padding(const u8* data, size_t len, u8* out,
    size_t* out_len);

/*--------------------------------------------------------------------------
     cps4_decipher

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
static int decipher(sc_card_t *card, const u8 * crgram, size_t crgram_len,  u8 * out, size_t outlen, u8 clearPad)
{
  int       r;
  sc_apdu_t apdu;
  u8        *sbuf = NULL;

  assert(card != NULL && crgram != NULL && out != NULL);
  SC_FUNC_CALLED(card->ctx, 2);

  sbuf = (u8 *)malloc(crgram_len /* + 1*/);
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

  /* sbuf[0] = 0x81;  padding indicator byte, 0x81 for RSA */
  memcpy(sbuf /* + 1*/, crgram, crgram_len);
  apdu.data = sbuf;
  apdu.lc = crgram_len /* + 1*/;
  apdu.datalen = crgram_len /* + 1*/;
  if (card->type == SC_CARD_TYPE_IAS_CPS4)
    apdu.flags |= SC_APDU_FLAGS_CHAINING;
  r = sc_transmit_apdu(card, &apdu);
  sc_mem_clear(sbuf, crgram_len /* + 1*/);
  free(sbuf);
  SC_TEST_RET(card->ctx, r, "APDU transmit failed");
  if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
    if (clearPad) {
      size_t unpadded_len = apdu.resplen;
      u8* unpadded_resp = (u8*)malloc(apdu.resplen);
      if (unpadded_resp == NULL) {
        return SC_ERROR_MEMORY_FAILURE;
      }
      r = sc_pkcs1_strip_02_padding(apdu.resp, (int)apdu.resplen, unpadded_resp, &unpadded_len);
      if (r > 0) {
        memcpy(apdu.resp, unpadded_resp, r);
        apdu.resplen = r;
      }
      else {
        free(unpadded_resp);
        return SC_ERROR_DECRYPT_FAILED;
      }
      free(unpadded_resp);
      SC_FUNC_RETURN(card->ctx, 2, (int)apdu.resplen);
    }
    else {
      SC_FUNC_RETURN(card->ctx, 2, (int)apdu.resplen);
    }
  }
  else
    SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
}
static int cps4_decipher(sc_card_t* card, const u8* crgram, size_t crgram_len, u8* out, size_t outlen)
{
  return decipher(card, crgram, crgram_len, out, outlen, TRUE);
}

static int cps4_internal_authenticate(sc_card_t* card, const u8* data, size_t datalen, u8* out, size_t outlen)
{
  return decipher(card, data, datalen, out, outlen, FALSE);
  //return cps4_sign(card, data, datalen, out, outlen, SC_SEC_OPERATION_AUTHENTICATE);
}
/*--------------------------------------------------------------------------
     cps4_get_aid_pkcs15

Fonction récupérant l'AID (application identifier) correspondant à l'un des deux modes contact/sans contact

Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte
aid                : Buffer recevant l'AID
aid_len            : Longueur effective de l'AID

Codes retour:
SC_SUCCESS
SC_ERROR_INTERNAL

--------------------------------------------------------------------------*/
static int cps4_get_aid_pkcs15(sc_card_t *card, u8 * aid, size_t *aid_len)
{
  struct cps_priv_data *priv = DRVDATA(card);
  if (priv != NULL) {
      *aid_len = sizeof(cps_aid_cps4);
      memcpy(aid, cps_aid_cps4, *aid_len);
  }
  else return SC_ERROR_INTERNAL;

  return SC_SUCCESS;
}

/*--------------------------------------------------------------------------
     cps4_compute_hash

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
static int cps4_compute_hash(sc_card_t *card, const u8 * data,
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

static int _do_reselect_cps4_aid(sc_card_t* card)
{
  int          r = SC_NO_ERROR;
  const char CPS4_AID_IDS[] = { 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00 };
  const char CPS4_AID_CPS2T[] = { 0x80, 0x25, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x02 };
  const char CPS4_AID[] = { 0x80, 0x25, 0x00, 0x00, 0x01, 0xFF, 0x01, 0x00 };

  sc_apdu_t select_ids = { SC_APDU_CASE_3_SHORT, 0x01, 0xA4, 0x04, 0x0C, 0x07, 0x00, CPS4_AID_IDS, 0x07, NULL, 0, 0, 0, 0, 0 };
  sc_apdu_t select_cps2ter = { SC_APDU_CASE_3_SHORT, 0x00, 0xA4, 0x04, 0x0C, 0x08, 0x00, CPS4_AID_CPS2T, 0x08, NULL, 0, 0, 0, 0, 0 };
  sc_apdu_t select_cps4 = { SC_APDU_CASE_3_SHORT, 0x01, 0xA4, 0x04, 0x0C, 0x08, 0x00, CPS4_AID, 0x08, NULL, 0, 0, 0, 0, 0 };

  sc_debug(card->ctx, "select IDS");
  r = card->reader->ops->transmit(card->reader, card->slot, &select_ids);
  if (r == SC_NO_ERROR) {
    sc_debug(card->ctx, "select CPS2Ter AID (cla = 0)");
    r = card->reader->ops->transmit(card->reader, card->slot, &select_cps2ter);
    if (r == SC_NO_ERROR) {
      sc_debug(card->ctx, "select CPS4 AID (cla = 1)");
      return card->reader->ops->transmit(card->reader, card->slot, &select_cps4);
    }
  }

  return r;
}

static int _cps4_get_pin_counter(sc_card_t* card, sc_pin_counter_t* pin_counter)
{
  int r;
  sc_apdu_t apdu;

  assert(card != NULL && pin_counter != NULL);

  sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, pin_counter->pin_reference);

  r = sc_transmit_apdu(card, &apdu);
  if (apdu.sw1 == 0x63) {
    pin_counter->tries_left = (apdu.sw2 & 0x0f);
    pin_counter->tries_max = 3;
    SC_FUNC_RETURN(card->ctx, 2, SC_SUCCESS);

  }
  else if (apdu.sw1 == 0x69 && apdu.sw2 == 0x83) {
    sc_debug(card->ctx, "PIN blocked");
    pin_counter->tries_left = 0;
    pin_counter->tries_max = 3;
    SC_FUNC_RETURN(card->ctx, 2, SC_SUCCESS);
  }
  else {
    SC_TEST_RET(card->ctx, r, "APDU transmit failed");
    SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
  }
}
/*--------------------------------------------------------------------------
     cps4_get_pin_counter

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
static int cps4_get_pin_counter(sc_card_t *card, sc_pin_counter_t *pin_counter)
{
int r;
  r = _cps4_get_pin_counter(card, pin_counter);
  if (r == SC_ERROR_BAD_CHANNEL) {
    r = _cps4_select_app(card);
    if (r == SC_SUCCESS) {
      return _cps4_get_pin_counter(card, pin_counter);
    }
  }
  return r;
}

/*--------------------------------------------------------------------------
     cps4_select_file

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
static int cps4_select_file(sc_card_t *card, const sc_path_t *in_path,
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
    if (card->type != SC_CARD_TYPE_IAS_CPS3) {
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
    r = cps4_select_file(card, &tpath, NULL);
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


/*--------------------------------------------------------------------------
     cps4_verify_update

Fonction analysant le fichier EF_ACTUA pour savoir si la carte a été mise a jour

Parametres:
p15card            : Pointeur vers l'objet de la structure P15 de la carte

Codes retour:
SC_SUCCESS
SC_ERROR_INTERNAL
SC_ERROR_OUT_OF_MEMORY

--------------------------------------------------------------------------*/
static int cps4_verify_update(struct sc_pkcs15_card *p15card)
{
  struct cps_priv_data *priv = DRVDATA(p15card->card);

  // Pas d'accès au fichier EF_ACTUA en CPS4 pour le moment
  if (priv != NULL) {
      return SC_SUCCESS;
  }
  else return SC_ERROR_INTERNAL;

}

static int cps4_reset_retry_counter(struct sc_card* card, unsigned int type,
    int ref_qualifier,
    const u8* puk, size_t puklen,
    const u8* newref, size_t newlen) {
    return SC_SUCCESS;

}

static int cps4_build_pin_apdu(sc_card_t* card, sc_apdu_t* apdu, struct sc_pin_cmd_data* data, u8* buf, size_t buf_len)
{
  int r, len = 0, pad = 0, use_pin_pad = 0, ins, p1 = 0, p2 = 0, cse = SC_APDU_CASE_3_SHORT;

  switch (data->pin_type) {
  case SC_AC_CHV:
    break;
  default:
    return SC_ERROR_INVALID_ARGUMENTS;
  }

  if (data->flags & SC_PIN_CMD_NEED_PADDING)
    pad = 1;
  if (data->flags & SC_PIN_CMD_USE_PINPAD)
    use_pin_pad = 1;

  data->pin1.offset = 5;
  p2 = data->pin_reference;

  switch (data->cmd) {
  case SC_PIN_CMD_VERIFY:
    ins = 0x20;
    if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)
      return r;
    len = r;
    break;
  case SC_PIN_CMD_CHANGE:
    ins = 0x24;
    if (data->pin1.len > 0 || data->pin1.data != NULL) {
        // we don't use the old pin in case of CHANGE PIN command
        data->pin1.len = 0;
    }
    if (data->pin1.len != 0 || use_pin_pad) {
      if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)
        return r;
      len += r;
    }
    else {
      /* implicit test */
      p1 = 1;
    }

    data->pin2.offset = data->pin1.offset + len;
    if ((r = sc_build_pin(buf + len, buf_len - len, &data->pin2, pad)) < 0)
      return r;
    len += r;
    break;
  case SC_PIN_CMD_UNBLOCK:
    /* Débloqué le code PIN */
    ins = 0x2C;
    p1 = 0x03;
    p2 |= 0x80;
    len = 0;
    cse = SC_APDU_CASE_1;
    break;
  default:
    return SC_ERROR_NOT_SUPPORTED;
  }

  sc_format_apdu(card, apdu, cse, ins, p1, p2);

  apdu->lc = len;
  apdu->datalen = len;
  apdu->data = buf;
  apdu->resplen = 0;
  apdu->sensitive = 1;

  return 0;
}

static void set_array_pin_cmds(struct sc_pin_cmd_data* data, int _cmds[]) {
    int i = 0;
    switch (data->cmd) {
    case SC_PIN_CMD_CHANGE:
        if (data->pin1.data != NULL) {
            _cmds[i++] = SC_PIN_CMD_VERIFY;
        }
        _cmds[i++] = data->cmd;
        break;
    case SC_PIN_CMD_UNBLOCK:
        _cmds[i++] = data->cmd;
        _cmds[i++] = SC_PIN_CMD_CHANGE;
        break;
    default:
        _cmds[i++] = data->cmd;
        _cmds[i++] = SC_PIN_CMD_NONE;
    }
}

static int cps4_pin_cmd(sc_card_t* card, struct sc_pin_cmd_data* data, int* tries_left) {
    int i, r = SC_SUCCESS;
    sc_apdu_t local_apdu, * apdu;
    int _pin_cmds[2] = { SC_PIN_CMD_NONE };
    u8  sbuf[SC_MAX_APDU_BUFFER_SIZE] = { 0 };

    set_array_pin_cmds(data, _pin_cmds);

    if (tries_left)
        *tries_left = -1;
    
    for (i = 0; i < sizeof(_pin_cmds)/sizeof(int) && _pin_cmds[i] != SC_PIN_CMD_NONE; i++) {
        data->cmd = _pin_cmds[i];
        r = cps4_build_pin_apdu(card, &local_apdu, data, sbuf, sizeof(sbuf));
        if (r < 0)
            return r;
        data->apdu = &local_apdu;
        apdu = data->apdu;
        if (!(data->flags & SC_PIN_CMD_USE_PINPAD)) {
            /* Transmit the APDU to the card */
            r = sc_transmit_apdu(card, apdu);

            /* Clear the buffer - it may contain pins */
            sc_mem_clear(sbuf, sizeof(sbuf));
        }
        else {
            sc_error(card->ctx, "Card reader driver does not support " "PIN entry through reader key pad");
            r = SC_ERROR_NOT_SUPPORTED;
        }

        if (!r) {
            data->apdu = NULL;
            if (apdu->sw1 == 0x63) {
                if ((apdu->sw2 & 0xF0) == 0xC0 && tries_left != NULL)
                    *tries_left = apdu->sw2 & 0x0F;
                if ((apdu->sw2 & 0x0F) == 0) return SC_ERROR_AUTH_METHOD_BLOCKED;
                return SC_ERROR_PIN_CODE_INCORRECT;
            }
            if (apdu->sw1 == 0x69 && apdu->sw2 == 0x83 && tries_left != NULL) {
                *tries_left = 0;
                return SC_ERROR_AUTH_METHOD_BLOCKED;
            }
        }
        else {
            SC_TEST_RET(card->ctx, r, "APDU transmit failed");
        }
    }
    return r;
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

  if (iso_ops == NULL)
    iso_ops = iso_drv->ops;
  /* Use the standard iso operations as default */
  cps4_ops = *iso_drv->ops;
  /* CPS3 specific functions */
  cps4_ops.match_card = cps4_match_card;
  cps4_ops.init = cps4_init;
  cps4_ops.set_security_env = cps4_set_security_env;
  cps4_ops.compute_signature = cps4_compute_signature;
  cps4_ops.compute_hash = cps4_compute_hash;
  cps4_ops.internal_authenticate = cps4_internal_authenticate;
  cps4_ops.decipher = cps4_decipher;
  cps4_ops.get_aid_pkcs15 = cps4_get_aid_pkcs15;
  cps4_ops.get_pin_counter = cps4_get_pin_counter;
  /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
  cps4_ops.verify_update = (void*)cps4_verify_update;
  /* MCUG 14/09/2010 : Fin */
  cps4_ops.reset_retry_counter = cps4_reset_retry_counter;
  /* MCUG 14/09/10 : Afin de permettre le masquage de certains objets */
  cps4_ops.is_visible = cps_is_visible;
  /* MCUG 14/09/2010 : Fin */
  cps4_ops.get_model = cps_get_model;
  cps4_ops.pin_cmd = cps4_pin_cmd;
  /* JTAU 16/11/2010 : Vérifie si la carte est valide*/
  cps4_ops.is_valid = cps_is_valid;
  /* JTAU 16/11/10 : Fin */
  cps4_ops.cps2ter_select_file = cps2ter_select_file;
  cps4_ops.finish = cps_finish;
  /* Ajout des fonctions pour la mise a jour de la carte : Debut */
  cps4_ops.start_exlusivity = cps_start_exlusivity;
  cps4_ops.end_exlusivity = cps_end_exlusivity;
  cps4_ops.free_transmit = cps_free_transmit;
  cps4_ops.get_status = cps_get_status;
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
struct sc_card_driver* sc_get_cps4_driver(void)
{
  return sc_get_driver();
}
