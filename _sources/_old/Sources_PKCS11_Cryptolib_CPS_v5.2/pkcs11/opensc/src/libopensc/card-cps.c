/*
 * card-cps.c : Common driver functions for CPS based cards (CPS3 / CPS4)
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
#if !defined(_WIN32)
#include <stdlib.h>
#include "sysdef.h"
#endif

#include "internal.h"
#include "asn1.h"
#include "card-cps.h"

/* Path du master file de la carte CPS2ter */
#define CPS2TER_MF_FID        "\x3F\x00"

/* Numéro d'émetteur IAS de l'ANS */
static const u8 cps3_fsn[] = { 0x80, 0x25, 0x00, 0x00, 0x01 };

static sc_path_t invisible_objects[] = { {{0x3f,0x00,0xD0,0x10}, 4, 0, 0} /* EF_ACTUA */};

/* couple ATR / masque pour la CPS3 contact */
static const u8 CPS3_C_ATR[] =   { 0x3B, 0xac, 0x00, 0x40, 0x2a, 0x00, 0x12, 0x25, 0x00, 0x64, 0x80, 0x00, 0x03, 0x10, 0x00, 0x90, 0x00 };
static const u8 CPS3_C_MASK[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };
/* couple ATR / masque pour la CPS3 contactless */
static const u8 CPS3_CL_ATR[] = { 0x3b, 0x8f, 0x80, 0x01, 0x00, 0x31, 0xb8, 0x64, 0x04, 0xb0, 0xec, 0xc1, 0x73, 0x94, 0x01, 0x80, 0x82, 0x90, 0x00, 0x0E };
static const u8 CPS3_CL_MASK[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
/* couple ATR / masque pour la CPS4 contact */
static const u8 CPS4_C_ATR[] =  { 0x3B, 0x9B, 0x18, 0x80, 0x01, 0x00, 0x12, 0x25, 0x00, 0x64, 0x80, 0x04, 0x01, 0x00, 0x00, 0x90, 0x44 };
static const u8 CPS4_C_MASK[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
/* couple ATR / masque pour la CPS4 release candidate contact */
static const u8 CPS4RC_C_ATR[] =  { 0x3B, 0x9B, 0x18, 0x80, 0x01, 0x00, 0x12, 0x25, 0x00, 0x64, 0x80, 0x00, 0x04, 0x01, 0x00, 0x90, 0x44 };
static const u8 CPS4RC_C_MASK[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
/* couple ATR / masque pour la CPS4 release candidate contact  T0 only */
static const u8 CPS4TO_C_ATR[]  = { 0x3B, 0xDC, 0x18, 0xFF, 0x00, 0x00, 0x12, 0x25, 0x00, 0x64, 0x80, 0x00, 0x04, 0x01, 0x00, 0x90, 0x00};
static const u8 CPS4TO_C_MASK[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };



const sc_match_atr CPS_ATR_LIST[] = {
  {CPS3_C_ATR , CPS3_C_MASK , sizeof(CPS3_C_ATR),CPS3_CONTACT },
  {CPS3_CL_ATR, CPS3_CL_MASK, sizeof(CPS3_CL_ATR),CPS3_CONTACTLESS},
  {CPS4RC_C_ATR , CPS4RC_C_MASK , sizeof(CPS4RC_C_ATR),CPS4_CONTACT},
  {CPS4_C_ATR , CPS4_C_MASK , sizeof(CPS4_C_ATR),CPS4_CONTACT},
  {CPS4TO_C_ATR , CPS4TO_C_MASK , sizeof(CPS4TO_C_ATR),CPS4_CONTACT},
};



/*--------------------------------------------------------------------------
     _is_cps_card

Detecter une carte CPS

Parametres:
atr            : L'ATR de la carte à tester
szAtr          : Taille de l'ATR de la carte à tester
pType          : Si la carte est de la famille CPS, le type de carte CPS en retour

Codes retour:   
  1 si c'est une carte CPS , sinon 0
--------------------------------------------------------------------------*/
int _is_cps_card(u8* atr, size_t szAtr, int* pType)
{
  size_t i;

  if (szAtr == 0) { return FALSE; }

  for (i = 0; i < (sizeof(CPS_ATR_LIST) / sizeof(sc_match_atr)); i++) {

    if (CPS_ATR_LIST[i].length != szAtr) { continue; }

    if (!memcmp(CPS_ATR_LIST[i].atr, atr, szAtr)) {
      *pType = CPS_ATR_LIST[i].type;
      return TRUE;
    }
  }

  return FALSE;
}

/*--------------------------------------------------------------------------
     cps_get_model

Fonction positionnant le modèle de carte CPS

Parametres:
card            : Pointeur vers l'objet contenant les informations de la carte
model           : Buffer recevant en retour le modèle de carte

Codes retour:         toujours 0

--------------------------------------------------------------------------*/
int cps_get_model(sc_card_t* card, u8* model)
{
  struct cps_priv_data *data = DRVDATA(card);
  if (model != NULL && data != NULL) {
    if (data->cps_type == CPS4_CONTACT) {
      strcpy((char*)model, CPS4_MODEL);
    }
    else {
      strcpy((char*)model, CPS3_MODEL);
    }
  }
  return 0;
}

/*--------------------------------------------------------------------------
     _cps_read_efsnicc

  Fonction qui permet de lire le fichier EF(SN.ICC)
  Mise à jour des informations privé de la carte 

  Parametres:
  card            : Pointeur vers l'objet contenant les informations de la carte

  Codes retour:         
    TRUE si le fichier à été lu correctement, sinon FALSE

--------------------------------------------------------------------------*/
int _cps_read_efsnicc(sc_card_t* card)
{
  sc_path_t tpath;
  sc_file_t* tfile = NULL;
  u8* buf_file = NULL;
  int r = 0;
  struct cps_priv_data* priv = NULL;
  int status = SC_SUCCESS;
  int locked = FALSE;

  if (card == NULL) {
    status= SC_ERROR_INVALID_ARGUMENTS;
    goto end;
  }

  /* vérifier si le fichier efsnicc n'a pas déjà été lu */
  if (card->serialnr.len != 0) { return TRUE;  }

  if ((status = sc_lock(card)) != SC_SUCCESS) {
    goto end;
  }

  locked = TRUE;

  /* Vérifier la présence du fichier EFSN dans le MF */
  sc_format_path(CPS_EF_SN_PATH, &tpath);
  r = sc_select_file(card, &tpath, &tfile);
  if (r == 0 && tfile != NULL)
  {
    if (tfile->size != 12)
    {
      sc_debug(card->ctx, "Bad EFSN file length");
      status = SC_ERROR_INTERNAL;
      goto end;
    }

    /* Lire le contenu du fichier EFSN dans le MF */
    ALLOCATE(status, buf_file, tfile->size, card);
    if (status != SC_SUCCESS) {
      goto end;
    }

    r = sc_read_binary(card, 0, buf_file, tfile->size, 0);
    if (r != tfile->size){
      sc_debug(card->ctx, "unable to read EFSN file");
      status = SC_ERROR_INTERNAL;
      goto end;
    }

    /* Comparer le fichier EFSN avec le numéro d'émetteur de l'ASIP Santé */
    if (memcmp(buf_file + 2, cps3_fsn, sizeof(cps3_fsn)) != 0)
    {
      sc_debug(card->ctx, "EFSN file different from ASIP SN");
      status = SC_ERROR_INTERNAL;
      goto end;
    }
    else
    {
      char* serial_number = NULL;
      int err;
      /* AROC 08/11/2011 - Debut : Memoriser le numero de serie lorsqu'il a ete lu */
      err = sc_pkcs15_parse_efsnicc(card->ctx, &serial_number, buf_file, tfile->size);
      if (err == SC_SUCCESS) {
        if (serial_number) {
          size_t offset = 0;
          if (strstr(serial_number, PREFIX_SN)) {
            offset = strlen(PREFIX_SN);
          }
          /* recopier le numéro de série sans le préfix */
          strcpy((char*)card->serialnr.value, serial_number + offset);
          card->serialnr.len = strlen((char*)card->serialnr.value);
          free(serial_number);
        }
      }
      sc_file_free(tfile);
      tfile = NULL;
      if (buf_file != NULL) { free(buf_file); buf_file = NULL; }

      /* AROC 08/11/2011 - Fin */
      /* AROC 17/01/2012 - Debut - Memoriser l'atr afin qu'il puisse etre positionne dans le context ressource */
      /*  Bien que l'on soit dans le driver carte de la cps3 en volet IAS, cet atr ne sera utiliser que par les apis cps */
      memcpy(card->slot->atr, CPS3_C_ATR, sizeof(CPS3_C_ATR));
      card->slot->atr_len = sizeof(CPS3_C_ATR);
      /* AROC 17/01/2012 - Fin */
      // On détermine tout de suite si on est en mode "sans contact"
      ALLOCATE(status, priv, sizeof(struct cps_priv_data), card);
      if (status != SC_SUCCESS) {
        goto end;
      }

      card->drv_data = priv;
    }
  }
  else {
    sc_debug(card->ctx, "unable to select EFSN file");
    status = SC_ERROR_INTERNAL;
    goto end;
  }
end:
  if (locked) { sc_unlock(card); };
  if (buf_file != NULL) { free(buf_file); }
  if (tfile != NULL) { sc_file_free(tfile); }
  return (status == SC_SUCCESS);
}


 /*--------------------------------------------------------------------------
     cps_is_visible

Fonction vérifiant si le fichier dont on passe le chemin doit etre affiché ou non

Parametres:
path            : Pointeur vers le chemin du fichier sur la carte

Codes retour:
0 si le fichier est caché, 1 sinon

--------------------------------------------------------------------------*/
 int cps_is_visible(const sc_path_t* path)
 {
   int i;
   
   for (i = 0; i < (sizeof(invisible_objects) / sizeof(sc_path_t)); i++) {
     if (!memcmp((const char*)path->value, (const char*)invisible_objects[i].value, invisible_objects[i].len))
       return FALSE;
   }

   return TRUE;
 }

 /*--------------------------------------------------------------------------
     cps_is_valid

Fonction renvoyant le résultat de la mise à jour de la carte

Parametres:
card            : Pointeur vers l'objet contenant les informations de la carte

Codes retour:
SC_NO_ERROR
SC_ERROR_INTERNAL

--------------------------------------------------------------------------*/
 int cps_is_valid(sc_card_t* card)
 {
   struct cps_priv_data* priv = DRVDATA(card);
   if (priv != NULL) {
     if (priv->bad_actua) {
       return SC_ERROR_INTERNAL;
     }
     else return SC_NO_ERROR;
   }
   else return SC_ERROR_INTERNAL;
 }
 /*--------------------------------------------------------------------------
    cps_finish

Fonction pour libérer les drivers CPS

Parametres:
path            : Pointeur vers le chemin du fichier sur la carte

Codes retour:
0 si le fichier est caché, 1 sinon

--------------------------------------------------------------------------*/
 int cps_finish(sc_card_t* card)
 {
   if (card != NULL) {
     if (card->drv_data != NULL) {
       free(card->drv_data);
       card->drv_data = NULL;
     }
   }
   return SC_SUCCESS;
 }


 /*--------------------------------------------------------------------------
      cps_start_exlusivity

 Fonction perttant d'etablir une connexion exclusive avec la carte.

 Parametres:
 card            : Pointeur vers l'objet contenant les informations de la carte

 Codes retour:
 SC_NO_ERROR
 SC_ERROR_INTERNAL

 --------------------------------------------------------------------------*/
 int cps_start_exlusivity(sc_card_t* card)
 {
   int r;

   r = sc_lock(card);
   SC_TEST_RET(card->ctx, r, "sc_lock() failed");
   return SC_SUCCESS;
 }

 /*--------------------------------------------------------------------------
      cps3_end_exlusivity

 Fonction perttant de liberer une connexion exclusive avec la carte.

 Parametres:
 card            : Pointeur vers l'objet contenant les informations de la carte

 Codes retour:
 SC_NO_ERROR
 SC_ERROR_INTERNAL

 --------------------------------------------------------------------------*/
 int cps_end_exlusivity(sc_card_t* card)
 {
   int r;
   r = sc_unlock(card);
   SC_TEST_RET(card->ctx, r, "sc_lock() failed");  return SC_SUCCESS;
 }

 /*--------------------------------------------------------------------------
      cps3_free_transmit

 Fonction perttant de transmettre des données à une carte de manière transparente.

 Parametres:
 card            : Pointeur vers l'objet contenant les informations de la carte
 data            : Les données à envoyer
 data_len        : La taille des données à envoyer
 out             : Le donnees en réponse
 outlen          : Le pointeur sur la taille de la réponse
 ins_type        : Le type d'instruction (0=IN/ 1=IN-OUT)

 Codes retour:
 SC_NO_ERROR
 SC_ERROR_INTERNAL

 --------------------------------------------------------------------------*/
 int cps_free_transmit(sc_card_t* card, const u8* data, size_t data_len, u8* out, size_t* outlen, unsigned char ins_type)
 {
   int r;
   if (card->reader->ops->free_transmit == NULL) r = SC_ERROR_INTERNAL;
   else   r = card->reader->ops->free_transmit(card->reader, card->slot, data, data_len, out, outlen, ins_type);

   return r;
 }
 /*--------------------------------------------------------------------------
      cps3_get_status

 Fonction perttant d'appeler la methode getstatus.

 Parametres:
 card            : Pointeur vers l'objet contenant les informations de la carte

 Codes retour:
 Aucun
 --------------------------------------------------------------------------*/
 void cps_get_status(sc_card_t* card)
 {
   if (card->reader->ops->get_status == NULL) return;
   else   card->reader->ops->get_status(card->reader, card->slot);

 }


 /*--------------------------- CPS2 TER ---------------------------*/


 static const struct sc_card_error cps2ter_errors[] = {
   { 0x6700, SC_ERROR_INCORRECT_PARAMETERS, "Bad extranel length" },

   { 0x6B00, SC_ERROR_INCORRECT_PARAMETERS, "Wrong parameter(s) P1-P2" },
   { 0x6D00, SC_ERROR_INS_NOT_SUPPORTED, "Instruction code not supported or invalid" },
   { 0x6F00, SC_ERROR_NOT_ALLOWED,  "No response possible" },

   { 0x9240, SC_ERROR_OBJECT_NOT_VALID,  "File's header is corrupt" },

   { 0x9402, SC_ERROR_INCORRECT_PARAMETERS, "Bad adress in file or bad file length" },
   { 0x9404, SC_ERROR_FILE_NOT_FOUND,  "File ID not found" },
   { 0x9408, SC_ERROR_INCORRECT_PARAMETERS, "File can not be used for this cmd" },

   { 0x9802, SC_ERROR_INVALID_PIN_REFERENCE, "PIN not activated" },
   { 0x9804, SC_ERROR_PIN_CODE_INCORRECT, "PIN code incorrect" },
   { 0x9808, SC_ERROR_INVALID_PIN_REFERENCE,  "Invalidated PIN" },
   { 0x9810, SC_ERROR_OBJECT_NOT_VALID,  "Invalidated file" },
   { 0x9840, SC_ERROR_INVALID_PIN_REFERENCE,  "PIN locked" },
   /* AROC (@@20120606) - Debut */
   { 0x6E00, SC_ERROR_CLASS_NOT_SUPPORTED,  "Unsupported Class" },
   /* AROC (@@20120606) - Fin */
 };

/*--------------------------------------------------------------------------
cps2ter_check_sw

Analyse les codes retour sw1 et sw2 positionnés sur l'APDU par la carte.
Si ces codes sont 90-00 alors la commande s'est déroulée sans erreur
Sinon la fonction compare les codes avec le tableau cps2ter_errors et renvoie un code
retouretour supporté par OpenSC
Parametres:
card               : Pointeur vers l'objet contenant les informations de la carte
sw1                : flag positionné dans la réponse de la carte
sw2                : flag positionné dans la réponse de la carte

Codes retour:
SC_NO_ERROR
SC_ERROR_INCORRECT_PARAMETERS
SC_ERROR_INS_NOT_SUPPORTED
SC_ERROR_NOT_ALLOWED
SC_ERROR_OBJECT_NOT_VALID
SC_ERROR_FILE_NOT_FOUND
SC_ERROR_INVALID_PIN_REFERENCE
SC_ERROR_PIN_CODE_INCORRECT
SC_ERROR_CARD_CMD_FAILED (si les valeur SW1 et SW2 ne sont pas définies dans le tableau cps2ter_errors


--------------------------------------------------------------------------*/
 static int cps2ter_check_sw(sc_card_t* card, unsigned int sw1, unsigned int sw2)
 {
   const int err_count = sizeof(cps2ter_errors) / sizeof(cps2ter_errors[0]);
   int i;

   /* Handle special cases here */
   if (sw1 == 0x6C) {
     sc_error(card->ctx, "Wrong length; correct length is %d\n", sw2);
     return SC_ERROR_WRONG_LENGTH;
   }
   if ((sw1 == 0x90) || (sw1 == 0x9F))
     return SC_NO_ERROR;
   if (sw1 == 0x63U && (sw2 & ~0x0fU) == 0xc0U) {
     sc_error(card->ctx, "Verification failed (remaining tries: %d)\n",
       (sw2 & 0x0f));
     return SC_ERROR_PIN_CODE_INCORRECT;
   }
   for (i = 0; i < err_count; i++)
     if (cps2ter_errors[i].SWs == ((sw1 << 8) | sw2)) {
       sc_error(card->ctx, "%s\n", cps2ter_errors[i].errorstr);
       return cps2ter_errors[i].errorno;
     }
   sc_error(card->ctx, "Unknown SWs; SW1=%02X, SW2=%02X\n", sw1, sw2);
   return SC_ERROR_CARD_CMD_FAILED;
 }


 /*--------------------------------------------------------------------------
 cps2ter_process_fci

 Fonction analysant la réponse de la carte à une sélection de fichier pour déterminer le
 type de fichier (DF, EF, MF)

 Parametres:
 card               : Pointeur vers l'objet contenant les informations de la carte
 buf                : Buffer contenant la réponse de la carte à la sélection d'un fichier
 buflen             : Longueur du buffer buf

 Codes retour:
 SC_SUCCESS
 SC_ERROR_NOT_SUPPORTED

 --------------------------------------------------------------------------*/
 static int cps2ter_process_fci(sc_card_t* card, sc_file_t* file,
   const u8* buf, size_t buflen)
 {
   sc_context_t* ctx = card->ctx;
   unsigned char byte;
   const char* type;
   int bytes;

   if (ctx->debug >= 3)
     sc_debug(ctx, "processing FCI bytes\n");

   file->id = (buf[2] << 8) | buf[3];

   if (ctx->debug >= 3)
     sc_debug(ctx, "  file identifier: 0x%02X%02X\n", buf[2],
       buf[3]);


   byte = buf[4];


   file->ef_structure = SC_FILE_EF_TRANSPARENT; // Autre possibilités ?

   switch (byte) {
   case 1:
     type = "MF";
     file->type = SC_FILE_TYPE_DF;
     break;
   case 2:
     type = "DF";
     file->type = SC_FILE_TYPE_DF;
     break;
   case 4:
     type = "EF";
     file->type = SC_FILE_TYPE_WORKING_EF;
     break;

   default:
     type = "unknown";
     break;
   }
   if (ctx->debug >= 3) {
     sc_debug(ctx, "  type: %s\n", type);
     sc_debug(ctx, "  EF structure: %d\n",
       byte & 0x07);
   }

   bytes = (buf[0] << 8) + buf[1];
   if (ctx->debug >= 3)
     sc_debug(ctx, "  bytes in file: %d\n", bytes);
   file->size = bytes;

   file->magic = SC_FILE_MAGIC;

   return 0;
 }
 /*--------------------------------------------------------------------------
 cps2ter_internal_select_file

 Fonction réalisant la sélection d'un fichier sur la carte.
 Pour la carte CPS2ter seule la sélection par ID est utilisée.
 La fonction effectue deux envoie d'APDU : SELECT et GET_RESPONSE.
 Le contenu de la réponse n'est pas analysé, ce qui est fait par la méthode appeleante.

 Parametres:
 card               : Pointeur vers l'objet contenant les informations de la carte
 in_path            : Pointeur vers l'objet contenant le path du fichier à sélectionner
 file_out           : Pointeur vers un objet qui contiendra les informations liées au fichier

 Codes retour:
 SC_SUCCESS
 SC_ERROR_NOT_SUPPORTED

 --------------------------------------------------------------------------*/
 static int cps2ter_internal_select_file(sc_card_t* card, const sc_path_t* in_path,
   sc_file_t** file_out, u8** resp, size_t* resplen)
 {
   int             r, pathlen, stripped_len, offset, bypass = 0;
   u8              buf[SC_MAX_APDU_BUFFER_SIZE];
   u8              pathbuf[SC_MAX_PATH_SIZE], * path;

   sc_context_t* ctx;
   sc_file_t* file;
   sc_apdu_t apdu;

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
   apdu.cla = 0xA0;
   apdu.p2 = 0; /* First record, return FCI */


   switch (in_path->type) {
   case SC_PATH_TYPE_FILE_ID:
     apdu.p1 = 0;
     if (pathlen != 2)
       return SC_ERROR_INVALID_ARGUMENTS;
     if ((memcmp(in_path->value, CPS2TER_MF_FID, 2) == 0) && !file_out) {
       /* indiquer que tout s'est bien passé : statusCode = 0x9000*/
       apdu.sw1 = 0x90;
       apdu.sw2 = 0x00;
       r = 0;
       bypass = 1;
       sc_debug(card->ctx, "CPS2ter card - bypass select fid=0x%02x%02x\n",
         in_path->value[0], in_path->value[1]);
     }
     break;
   case SC_PATH_TYPE_DF_NAME:
     apdu.p1 = 4;
     break;
   case SC_PATH_TYPE_CPS2TER:
   case SC_PATH_TYPE_PATH:
     // Dans ce cas on va faire plusieurs select successifs pour parcourir l'arborescence
     if (pathlen > 2)
     {
       sc_path_t temp_path;
       int i = 0;
       for (i = 0; i < pathlen - 2; i = i + 2)
       {

         memset(temp_path.value, 0, SC_MAX_PATH_SIZE);
         memcpy(temp_path.value, in_path->value + i * sizeof(u8), 2);
         temp_path.len = 2;
         temp_path.type = SC_PATH_TYPE_PATH;
         r = cps2ter_internal_select_file(card, &temp_path, NULL, resp, resplen);
         if (r != SC_SUCCESS)
           return r;
         if (*resp != NULL)
           free(*resp);
       }
       memcpy(temp_path.value, in_path->value + i * sizeof(u8), 2);
       return cps2ter_internal_select_file(card, &temp_path, file_out, resp, resplen);


     }
     apdu.p1 = 0;
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
     apdu.cse = (apdu.lc == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
   }

   if (!bypass)
     r = sc_transmit_apdu(card, &apdu);

   SC_TEST_RET(card->ctx, r, "APDU transmit failed");
   if (file_out == NULL) {
     if (apdu.sw1 == CPS2TER_SW1_BYTES_AVAILABLE)
       SC_FUNC_RETURN(card->ctx, 2, 0);
     SC_FUNC_RETURN(card->ctx, 2, cps2ter_check_sw(card, apdu.sw1, apdu.sw2));
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
     r = cps2ter_internal_select_file(card, &tpath, NULL, resp, resplen);
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
       if (apdu.sw1 == CPS2TER_SW1_BYTES_AVAILABLE)
         SC_FUNC_RETURN(card->ctx, 2, 0);
       SC_FUNC_RETURN(card->ctx, 2, cps2ter_check_sw(card, apdu.sw1, apdu.sw2));
     }
   }

   r = cps2ter_check_sw(card, apdu.sw1, apdu.sw2);
   if (r)
     SC_FUNC_RETURN(card->ctx, 2, r);

   if (apdu.resplen < 2)
     SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
   *resp = malloc(apdu.resplen * sizeof(u8));
   if (*resp == NULL)
     return SC_ERROR_OUT_OF_MEMORY;
   memcpy(*resp, apdu.resp, apdu.resplen);
   *resplen = apdu.resplen;

   return SC_SUCCESS;
 }

 /*--------------------------------------------------------------------------
 cps2ter_select_file

 Fonction réalisant la sélection d'un fichier sur la carte.
 Pour la carte CPS2ter seule la sélection par ID est utilisée. La sélection
 du master file (MF) n'est pas réalisée et renvoie toujours SC_SUCCESS.

 Parametres:
 card               : Pointeur vers l'objet contenant les informations de la carte
 in_path            : Pointeur vers l'objet contenant le path du fichier à sélectionner
 file_out           : Pointeur vers un objet qui contiendra les informations liées au fichier

 Codes retour:
 SC_SUCCESS
 SC_ERROR_NOT_SUPPORTED

 --------------------------------------------------------------------------*/
 int cps2ter_select_file(sc_card_t* card, const sc_path_t* in_path, sc_file_t** file_out)
 {
   u8* resp;
   size_t resplen;
   int r;
   sc_file_t* file;

   resp = NULL;
   r = cps2ter_internal_select_file(card, in_path, file_out, &resp, &resplen);
   if (r != SC_SUCCESS) {
     SC_FUNC_RETURN(card->ctx, 2, r);
   }

   // On ne cherche pas à lire les données du fichier
   if (file_out == NULL) {
     SC_FUNC_RETURN(card->ctx, 2, r);
   }

   if (resplen < 2)
     SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);

   switch (resp[0]) {

   case 0x85:
     file = sc_file_new();
     if (file == NULL) {
       free(resp);
       SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);
     }
     file->path = *in_path;

     if ((int)resp[1] + 2 <= (int)resplen) {
       cps2ter_process_fci(card, file, resp + 2, resp[1]);
     }
     *file_out = file;
     if (resp != NULL) {
       free(resp);
     }

     break;
   default:
     if (resp != NULL) {
       free(resp);
     }
     SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
   }
   return SC_SUCCESS;
 }


 void _cps_get_pin_info(sc_card_t* card, u8* pbuff, size_t buffLen, sc_pin_counter_t* pPinCounter)
 {
   struct cps_priv_data* priv = NULL;
   size_t i;
   int maxTries = -1;
   int triesLeft = -1;
   int usageLeft = -1;

   priv = DRVDATA(card);

   for (i = 0; i < buffLen; i++) {
     if (pbuff[i] == 0x9A) //maxTries
     {
       maxTries = pbuff[i + 2]; i += 2; continue;
     }
     if (pbuff[i] == 0x9B) //triesLeft
     {
       triesLeft = pbuff[i + 2]; i += 2; continue;
     }
     if (priv->cps_type == CPS3_CONTACT) {
       if (pbuff[i] == 0x9D) //usageLeft
       {
         if (pbuff[i + 1] == 1) { usageLeft = pbuff[i + 2]; i += 2; continue; }
         if (pbuff[i + 1] == 2) { usageLeft = (pbuff[i + 2] << 8) + pbuff[i + 3]; i += 2; continue; }
       }
     }
   }

   if (priv->cps_type == CPS3_CONTACT && usageLeft != -1)
     pPinCounter->tries_left = usageLeft == 0 ? 0 : triesLeft;
   else
     pPinCounter->tries_left = triesLeft;
   pPinCounter->tries_max = maxTries;


 }
