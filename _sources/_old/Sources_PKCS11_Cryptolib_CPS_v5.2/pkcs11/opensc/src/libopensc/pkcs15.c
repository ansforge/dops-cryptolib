/*
 * pkcs15.c: PKCS #15 general functions
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

#ifndef _WIN32
#include "sysdef.h"
#endif // _WIN32

int cache_action = -1;

extern int g_winlogonProcess;

static const struct sc_asn1_entry c_asn1_twlabel[] = {
  { "twlabel", SC_ASN1_UTF8STRING, SC_ASN1_TAG_UTF8STRING, 0, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_toki[] = {
  { "version",        SC_ASN1_INTEGER,      SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
  { "serialNumber",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
  { "manufacturerID", SC_ASN1_UTF8STRING,   SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
  { "label",      SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL, NULL },
  /* XXX the Taiwanese ID card erroneously uses explicit tagging */
  { "label-tw",       SC_ASN1_STRUCT,       SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
  { "tokenflags",      SC_ASN1_BIT_FIELD,    SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
  { "seInfo",      SC_ASN1_SE_INFO,    SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
  { "recordInfo",      SC_ASN1_STRUCT,       SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
  { "supportedAlgorithms", SC_ASN1_STRUCT,  SC_ASN1_CONS | SC_ASN1_CTX | 2, SC_ASN1_OPTIONAL, NULL, NULL },
  { "issuerId",       SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 3, SC_ASN1_OPTIONAL, NULL, NULL },
  { "holderId",       SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 4, SC_ASN1_OPTIONAL, NULL, NULL },
  { "lastUpdate",     SC_ASN1_GENERALIZEDTIME, SC_ASN1_CTX | 5, SC_ASN1_OPTIONAL, NULL, NULL },
  { "preferredLanguage", SC_ASN1_PRINTABLESTRING, SC_ASN1_TAG_PRINTABLESTRING, SC_ASN1_OPTIONAL, NULL, NULL }, 
  { NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_tokeninfo[] = {
  { "TokenInfo", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

/* CLCO 01/06/2010 : Ajout d'une fonction permettant de parser le fichier EF SN ICC */
#define SC_ASN1_TAG_SERIAL_NUMBER  0x1A
#define SC_ASN1_TAG_SERIAL_NUMBER_CPS4  0x5A

static const struct sc_asn1_entry c_asn1_efsnicc[] = {
  { "PAN", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SERIAL_NUMBER | SC_ASN1_APP, 0, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

typedef struct cps2ter_entry {
  const u8* cps2terName;
  const u8 cps2terPath[6];
  const u8 cps2terPathSize;
}cps2ter_entry;

typedef struct situation_map {
  const u8* cps3Name;
  cps2ter_entry cps2ter;
}situation_map;


#define CLR_FILE(p) if (p != NULL){ sc_file_free(p); p = NULL; }
#define CLR_MEM(p) if (p != NULL){ free(p);  p = NULL; }

int sc_pkcs15_parse_tokeninfo(sc_context_t *ctx,
  sc_pkcs15_tokeninfo_t *ti, const u8 *buf, size_t blen)
{
  int r;
  u8 serial[128];
#if 0
  size_t i;
#endif
  size_t serial_len = sizeof(serial);
  u8 mnfid[SC_PKCS15_MAX_LABEL_SIZE];
  size_t mnfid_len  = sizeof(mnfid);
  u8 label[SC_PKCS15_MAX_LABEL_SIZE];
  size_t label_len = sizeof(label);
  u8 last_update[32];
  size_t lupdate_len = sizeof(last_update) - 1;
  size_t flags_len   = sizeof(ti->flags);
  struct sc_asn1_entry asn1_toki[14], asn1_tokeninfo[3], asn1_twlabel[3];
  u8 preferred_language[3];
  size_t lang_length = sizeof(preferred_language);

  memset(last_update, 0, sizeof(last_update));
  /* CLCO 01/06/2010 : Gestion IAS du numéro de série devant figurer dans le token info */
  memset(serial, 0, sizeof(serial));
  sc_copy_asn1_entry(c_asn1_twlabel, asn1_twlabel);
  sc_copy_asn1_entry(c_asn1_toki, asn1_toki);
  sc_copy_asn1_entry(c_asn1_tokeninfo, asn1_tokeninfo);
  sc_format_asn1_entry(asn1_twlabel, label, &label_len, 0);

  sc_format_asn1_entry(asn1_toki + 0, &ti->version, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 1, serial, &serial_len, 0);
  sc_format_asn1_entry(asn1_toki + 2, mnfid, &mnfid_len, 0);
  sc_format_asn1_entry(asn1_toki + 3, label, &label_len, 0);
  sc_format_asn1_entry(asn1_toki + 4, asn1_twlabel, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 5, &ti->flags, &flags_len, 0);
  sc_format_asn1_entry(asn1_toki + 6, &ti->seInfo, &ti->num_seInfo, 0);
  sc_format_asn1_entry(asn1_toki + 7, NULL, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 8, NULL, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 9, NULL, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 10, NULL, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 11, last_update, &lupdate_len, 0);
  sc_format_asn1_entry(asn1_toki + 12, preferred_language, &lang_length, 0);
  sc_format_asn1_entry(asn1_tokeninfo, asn1_toki, NULL, 0);
  

  r = sc_asn1_decode(ctx, asn1_tokeninfo, buf, blen, NULL, NULL);
  if (r) {
    sc_error(ctx, "ASN.1 parsing of EF(TokenInfo) failed: %s\n",
      sc_strerror(r));
    return r;
  }
  ti->version += 1;
  ti->serial_number = (char *) malloc(serial_len * 2 + 1);
  if (ti->serial_number == NULL){
    return SC_ERROR_OUT_OF_MEMORY;
  }
  ti->serial_number[0] = 0;

#if 0
  /* CLCO 27/05/2010 : conditionner la copie du serial number à sa présence dans le CIAInfo */
  if (asn1_toki[1].flags & SC_ASN1_PRESENT) {
    for (i = 0; i < serial_len; i++) {
      char byte[3];

      sprintf(byte, "%02X", serial[i]);
      strcat(ti->serial_number, byte);
    }
  }
#endif

  if (ti->manufacturer_id == NULL) {
    if (asn1_toki[2].flags & SC_ASN1_PRESENT) {
      ti->manufacturer_id = strdup((char *)mnfid);
    }
    else {
      ti->manufacturer_id = strdup("(unknown)");
    }
    if (ti->manufacturer_id == NULL) {
      return SC_ERROR_OUT_OF_MEMORY;
    }
  }

  if (ti->label == NULL) {
    if (asn1_toki[3].flags & SC_ASN1_PRESENT || asn1_toki[4].flags & SC_ASN1_PRESENT) {
      ti->label = strdup((char *)label);
    }
    else {
      ti->label = strdup("(unknown)");
    }
    if (ti->label == NULL) {
      return SC_ERROR_OUT_OF_MEMORY;
    }
  }
  
  if (asn1_toki[11].flags & SC_ASN1_PRESENT) {
    ti->last_update = strdup((char *)last_update);
    if (ti->last_update == NULL) { 
      return SC_ERROR_OUT_OF_MEMORY; 
    }
  }
  
  if (asn1_toki[12].flags & SC_ASN1_PRESENT) {
    preferred_language[2] = 0;
    ti->preferred_language = strdup((char *)preferred_language);
    if (ti->preferred_language == NULL) {
      return SC_ERROR_OUT_OF_MEMORY;
    }
  }

  return SC_SUCCESS;
}


int sc_pkcs15_parse_efsnicc(sc_context_t *ctx, char **serial_number, const u8 *buf, size_t blen)
{
  int r;
  u8 pan[128];
  size_t i;
  size_t pan_len = sizeof(pan);
  struct sc_asn1_entry asn1_pan[3];

  memset(pan, 0, sizeof(pan));
  sc_copy_asn1_entry(c_asn1_efsnicc, asn1_pan);
  sc_format_asn1_entry(asn1_pan, pan, &pan_len, 0);
  
  r = sc_asn1_decode(ctx, asn1_pan, buf, blen, NULL, NULL);
  if (r) {
    sc_error(ctx, "ASN.1 parsing of EF(SN) failed: %s\n", sc_strerror(r));
    return r;
  }

  /* Remonter tout le SN.ICC dans le cas de la mise à jour de carte CPS */
  if(!ctx->processing_update){
     pan_len = pan_len - 1;
  }
  /* La longueur du numéro de série n'est pas égale à celle du pan.
      Il faut retirer à la fin la formule de Luhn (1 chiffre) et les bits de remplissage 'F'*/
  *serial_number = (char *) malloc((pan_len) * 2 + 1);
  if (*serial_number == NULL) {
    return SC_ERROR_OUT_OF_MEMORY;
  }
  (*serial_number)[0] = 0;
  
  for (i = 0; i < pan_len; i++) {
    char byte[3];

    sprintf(byte, "%02X", pan[i]);
    strcat(*serial_number, byte);
  }
  return SC_SUCCESS;
}


int sc_pkcs15_parse_efsn_cps4(sc_context_t* ctx, char** serial_number, const u8* buf, size_t blen)
{
  int r;
  /* bypass RFU bytes in serial number */
  int start_rfu = 2;
  u8 pan[128];
  size_t i;
  size_t pan_len = sizeof(pan);
  struct sc_asn1_entry asn1_pan[3];

  memset(pan, 0, sizeof(pan));
  sc_copy_asn1_entry(c_asn1_efsnicc, asn1_pan);
  sc_format_asn1_entry(asn1_pan, pan, &pan_len, 0);

  r = sc_asn1_decode(ctx, asn1_pan, buf, blen, NULL, NULL);
  if (r) {
    sc_error(ctx, "ASN.1 parsing of EF(SN) failed: %s\n", sc_strerror(r));
    return r;
  }

  /* La longueur du numéro de série n'est pas égale à celle du pan.
      Il faut retirer à la fin la formule de Luhn (1 chiffre) et les bits de remplissage 'F'*/
  *serial_number = (char*)malloc((pan_len - start_rfu) * 2 + 1);
  if (*serial_number == NULL) {
    return SC_ERROR_OUT_OF_MEMORY;
  }
  (*serial_number)[0] = 0;

  for (i = start_rfu; i < pan_len; i++) {
    char byte[3];

    sprintf(byte, "%02X", pan[i]);
    strcat(*serial_number, byte);
  }
  return SC_SUCCESS;
}

static const struct sc_asn1_entry c_asn1_ddo[] = {
  { "oid",     SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, SC_ASN1_OPTIONAL, NULL, NULL },
  { "odfPath",     SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
  { "tokenInfoPath", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL, NULL },
  { "unusedPath",    SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

static int parse_ddo(struct sc_pkcs15_card *p15card, const u8 * buf, size_t buflen)
{
  struct sc_asn1_entry asn1_ddo[5];
  sc_path_t odf_path, ti_path, us_path;
  int r;

  sc_copy_asn1_entry(c_asn1_ddo, asn1_ddo);
  sc_format_asn1_entry(asn1_ddo + 1, &odf_path, NULL, 0);
  sc_format_asn1_entry(asn1_ddo + 2, &ti_path, NULL, 0);
  sc_format_asn1_entry(asn1_ddo + 3, &us_path, NULL, 0);

  r = sc_asn1_decode(p15card->card->ctx, asn1_ddo, buf, buflen, NULL, NULL);
  if (r) {
    sc_error(p15card->card->ctx, "DDO parsing failed: %s\n", sc_strerror(r));
    return r;
  }

  if (asn1_ddo[1].flags & SC_ASN1_PRESENT) {
    p15card->file_odf = sc_file_new();
    if (p15card->file_odf == NULL) {
      return SC_ERROR_OUT_OF_MEMORY;
    }
    p15card->file_odf->path = odf_path;
  }
  
  if (asn1_ddo[2].flags & SC_ASN1_PRESENT) {
    p15card->file_tokeninfo = sc_file_new();
    if (p15card->file_tokeninfo == NULL) {
      CLR_FILE(p15card->file_odf)
      return SC_ERROR_OUT_OF_MEMORY;
    }
    p15card->file_tokeninfo->path = ti_path;
  }
  
  if (asn1_ddo[3].flags & SC_ASN1_PRESENT) {
    p15card->file_unusedspace = sc_file_new();
    if (p15card->file_unusedspace == NULL) {
      CLR_FILE(p15card->file_odf)
      CLR_FILE(p15card->file_tokeninfo)
      return SC_ERROR_OUT_OF_MEMORY;
    }
    p15card->file_unusedspace->path = us_path;
  }

  return 0;
}

static const struct sc_asn1_entry c_asn1_odf[] = {
  { "privateKeys",   SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, NULL, NULL },
  { "publicKeys",     SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
  { "trustedPublicKeys",   SC_ASN1_STRUCT, SC_ASN1_CTX | 2 | SC_ASN1_CONS, 0, NULL, NULL },
  { "secretKeys",      SC_ASN1_STRUCT, SC_ASN1_CTX | 3 | SC_ASN1_CONS, 0, NULL, NULL },
  { "certificates",   SC_ASN1_STRUCT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, 0, NULL, NULL },
  { "trustedCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 5 | SC_ASN1_CONS, 0, NULL, NULL },
  { "usefulCertificates",  SC_ASN1_STRUCT, SC_ASN1_CTX | 6 | SC_ASN1_CONS, 0, NULL, NULL },
  { "dataObjects",   SC_ASN1_STRUCT, SC_ASN1_CTX | 7 | SC_ASN1_CONS, 0, NULL, NULL },
  { "authObjects",   SC_ASN1_STRUCT, SC_ASN1_CTX | 8 | SC_ASN1_CONS, 0, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

static const unsigned int odf_indexes[] = {
  SC_PKCS15_PRKDF,
  SC_PKCS15_PUKDF,
  SC_PKCS15_PUKDF_TRUSTED,
  SC_PKCS15_SKDF,
  SC_PKCS15_CDF,
  SC_PKCS15_CDF_TRUSTED,
  SC_PKCS15_CDF_USEFUL,
  SC_PKCS15_DODF,
  SC_PKCS15_AODF,
};

static int parse_odf(const u8 * buf, size_t buflen, struct sc_pkcs15_card *card)
{
  const u8 *p = buf;
  size_t left = buflen;
  int r, i, type;
  sc_path_t path;
  struct sc_asn1_entry asn1_obj_or_path[] = {
    { "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path, NULL },
    { NULL, 0, 0, 0, NULL, NULL }
  };
  struct sc_asn1_entry asn1_odf[10];
  
  sc_copy_asn1_entry(c_asn1_odf, asn1_odf);
  for (i = 0; asn1_odf[i].name != NULL; i++) {
    sc_format_asn1_entry(asn1_odf + i, asn1_obj_or_path, NULL, 0);
  }

  while (left > 0) {
    r = sc_asn1_decode_choice(card->card->ctx, asn1_odf, p, left, &p, &left);
    if (r == SC_ERROR_ASN1_END_OF_CONTENTS) {
      break; 
    }
    if (r < 0) { 
      return r; 
    }
    
    type = r;
    r = sc_pkcs15_make_absolute_path(&card->file_app->path, &path);
    if (r < 0) { 
      return r; 
    }
    
    r = sc_pkcs15_add_df(card, odf_indexes[type], &path, NULL);
    if (r) { 
      return r; 
    }
  }
  return 0;
}

struct sc_pkcs15_card * sc_pkcs15_card_new(void)
{
  struct sc_pkcs15_card *p15card;
  
  p15card = (struct sc_pkcs15_card *) calloc(1, sizeof(struct sc_pkcs15_card));
  if (p15card == NULL) {
    return NULL;
  }

  p15card->magic = SC_PKCS15_CARD_MAGIC;
  return p15card;
}

void sc_pkcs15_card_free(struct sc_pkcs15_card *p15card)
{

  if (p15card == NULL) {
    return;
  }
  assert(p15card->magic == SC_PKCS15_CARD_MAGIC);

  while (p15card->unusedspace_list) {
    sc_pkcs15_remove_unusedspace(p15card, p15card->unusedspace_list);
  }
  p15card->unusedspace_read = 0;

  sc_pkcs15_card_clear(p15card);

  free(p15card);
}

void sc_pkcs15_card_clear(sc_pkcs15_card_t *p15card)
{
  if (p15card == NULL) {
    return;
  }

  p15card->version = 0;
  p15card->flags   = 0;
  while (p15card->obj_list != NULL) {
    sc_pkcs15_remove_object(p15card, p15card->obj_list);
  }
  p15card->obj_list = NULL;
  while (p15card->df_list != NULL) {
    sc_pkcs15_remove_df(p15card, p15card->df_list);
  }

  p15card->df_list = NULL;
  CLR_FILE(p15card->file_app);
  CLR_FILE(p15card->file_tokeninfo);
  CLR_FILE(p15card->file_odf);
  CLR_FILE(p15card->file_unusedspace);

  CLR_MEM(p15card->label);
  CLR_MEM(p15card->serial_number);
  CLR_MEM(p15card->manufacturer_id);
  CLR_MEM(p15card->last_update);
  CLR_MEM(p15card->preferred_language);

  if (p15card->seInfo != NULL) {
    size_t i;
    for (i = 0; i < p15card->num_seInfo; i++) {
      CLR_MEM(p15card->seInfo[i]);
    }
    CLR_MEM(p15card->seInfo);
    p15card->num_seInfo = 0;
  }
}

static int sc_pkcs15_bind_internal(sc_pkcs15_card_t *p15card)
{
  unsigned char *buf = NULL;
  int    err = 0, ok = 0;
  size_t len;
  sc_path_t tmppath;
  sc_card_t    *card = p15card->card;
  sc_context_t *ctx  = card->ctx;
  sc_pkcs15_tokeninfo_t tokeninfo;
/* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
  cache_action = p15card->opts.use_cache;
/* MCUG 14/09/2010 : Fin */

  if (ctx->debug > 4)
    sc_debug(ctx, "trying normal pkcs15 processing\n");

  /* Enumerate apps now */
  if (card->app_count < 0) {
    err = sc_enum_apps(card);
    if (err < 0 && err != SC_ERROR_FILE_NOT_FOUND) {
      sc_error(ctx, "unable to enumerate apps: %s\n", sc_strerror(err));
      goto end;
    }
  }
  p15card->file_app = sc_file_new();
  if (p15card->file_app == NULL) {
    err = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  sc_format_path("3F005015", &p15card->file_app->path);
  if (card->app_count > 0) {
    const sc_app_info_t *info;
    
    info = sc_find_pkcs15_app(card);
    if (info != NULL) {
      if (info->path.len)
        p15card->file_app->path = info->path;
      if (info->ddo != NULL)
        parse_ddo(p15card, info->ddo, info->ddo_len);
    }
  }

  /* Check if pkcs15 directory exists */
  sc_ctx_suppress_errors_on(card->ctx);

  /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
    if(card->ops->verify_update != NULL)
      err = card->ops->verify_update (p15card);
  if(err < 0)
    goto end;
  /* MCUG 14/09/2010 : Fin */

  /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
  /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
  err = sc_select_cached_file(card, &p15card->file_app->path, NULL, cache_action);
  /* MCUG 14/09/2010 : Fin */
  /* CLCO 06/07/2010 : Fin  */

  /* If the above test failed on cards without EF(DIR),
   * try to continue read ODF from 3F005031. -aet
   */
  if ((err == SC_ERROR_FILE_NOT_FOUND) &&
      (card->app_count < 1)) {
    sc_format_path("3F00", &p15card->file_app->path);
    err = SC_NO_ERROR;
  }

  sc_ctx_suppress_errors_off(card->ctx);
  if (err < 0)
    goto end;

  if (p15card->file_odf == NULL) {
    /* check if an ODF is present; suppress errors as we
     * don't know yet whether we have a pkcs15 card */
    tmppath = p15card->file_app->path;
    sc_append_path_id(&tmppath, (const u8 *) "\x50\x31", 2);
    sc_ctx_suppress_errors_on(card->ctx);
    /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
    /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
    err = sc_select_cached_file(card, &tmppath, &p15card->file_odf, cache_action);
    /* MCUG 14/09/2010 : Fin */
    /* CLCO 06/07/2010 : Fin  */
    sc_ctx_suppress_errors_off(card->ctx);
    
  } else {
    tmppath = p15card->file_odf->path;
    sc_file_free(p15card->file_odf);
    p15card->file_odf = NULL;
    /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
    /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
    err = sc_select_cached_file(card, &tmppath, &p15card->file_odf, cache_action);
    /* MCUG 14/09/2010 : Fin */
    /* CLCO 06/07/2010 : Fin  */
  }
  if (err != SC_SUCCESS) {
    char pbuf[SC_MAX_PATH_STRING_SIZE];

    int r = sc_path_print(pbuf, sizeof(pbuf), &tmppath);
    if (r != SC_SUCCESS)
      pbuf[0] = '\0';

    sc_debug(ctx, "EF(ODF) not found in '%s'\n", pbuf);
    goto end;
  }

  if ((len = p15card->file_odf->size) == 0) {
    sc_error(card->ctx, "EF(ODF) is empty\n");
    goto end;
  }
  /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
  err = -1; /* file state: not in cache */

  /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
  if (cache_action == USE_CACHE) {
    err = sc_pkcs15_read_cached_file(p15card, &tmppath, &buf, &len);
  }
  /* MCUG 14/09/2010 : Fin */
  if (err) {
    /* CLCO 27/07/2010 : refaire un select du fichier pour plus de sécurité  */
    err = sc_select_cached_file(card, &tmppath, &p15card->file_odf, 0);
    if (err != SC_SUCCESS)
      goto end;
    /* CLCO 27/07/2010 : Fin  */
    buf = malloc(len);
    if(buf == NULL)
      return SC_ERROR_OUT_OF_MEMORY;
    err = sc_read_binary(card, 0, buf, len, 0);
    if (err < 0)
      goto end;
    if (err < 2) {
      err = SC_ERROR_PKCS15_APP_NOT_FOUND;
      goto end;
    }
    len = err;
    /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
    if ((cache_action == USE_CACHE || cache_action == MAJ_CACHE) && buf && len) {
      err = sc_pkcs15_cache_file(p15card, &tmppath, buf, len);
    }
    /* MCUG 14/09/2010 : Fin */
  }
  /* CLCO 06/07/2010 : Fin  */
  if (parse_odf(buf, len, p15card)) {
    err = SC_ERROR_PKCS15_APP_NOT_FOUND;
    sc_error(card->ctx, "Unable to parse ODF\n");
    goto end;
  }
  free(buf);
  buf = NULL;

  if (card->ctx->debug) {
    sc_pkcs15_df_t *df;

    sc_debug(card->ctx, "The following DFs were found:\n");
    for (df = p15card->df_list; df; df = df->next) {
      char pbuf[SC_MAX_PATH_STRING_SIZE];

      int r = sc_path_print(pbuf, sizeof(pbuf), &df->path);
      if (r != SC_SUCCESS)
        pbuf[0] = '\0';

      sc_debug(card->ctx,
        "  DF type %u, path %s, index %u, count %d\n",
        df->type, pbuf, df->path.index, df->path.count);
    }
  }

  if (p15card->file_tokeninfo == NULL) {
    tmppath = p15card->file_app->path;
    sc_append_path_id(&tmppath, (const u8 *) "\x50\x32", 2);
  } else {
    tmppath = p15card->file_tokeninfo->path;
    sc_file_free(p15card->file_tokeninfo);
    p15card->file_tokeninfo = NULL;
  }
  /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
  /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
  err = sc_select_cached_file(card, &tmppath, &p15card->file_tokeninfo, cache_action);
  /* MCUG 14/09/2010 : Fin */
  /* CLCO 06/07/2010 : Fin  */
  if (err)
    goto end;

  if ((len = p15card->file_tokeninfo->size) == 0) {
    sc_error(card->ctx, "EF(TokenInfo) is empty\n");
    goto end;
  }
  /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
  err = -1; /* file state: not in cache */

  /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
  if (cache_action == USE_CACHE) {
    err = sc_pkcs15_read_cached_file(p15card, &tmppath, &buf, &len);
  }
  /* MCUG 14/09/2010 : Fin */

  if (err) {
    /* CLCO 27/07/2010 : refaire un select du fichier pour plus de sécurité  */
    err = sc_select_cached_file(card, &tmppath, &p15card->file_tokeninfo, 0);
    if (err)
      goto end;
    /* CLCO 27/07/2010 : Fin  */
    buf = malloc(len);
    if(buf == NULL)
      return SC_ERROR_OUT_OF_MEMORY;
    err = sc_read_binary(card, 0, buf, len, 0);
    if (err < 0)
      goto end;
    if (err <= 2) {
      err = SC_ERROR_PKCS15_APP_NOT_FOUND;
      goto end;
    }
    len = err;

    /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
    if ((cache_action == USE_CACHE || cache_action == MAJ_CACHE) && buf && len) {
      err = sc_pkcs15_cache_file(p15card, &tmppath, buf, len);
    }
    /* MCUG 14/09/2010 : Fin */
  }
  /* CLCO 06/07/2010 : Fin  */

  memset(&tokeninfo, 0, sizeof(tokeninfo));
  /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
  err = sc_pkcs15_parse_tokeninfo(ctx, &tokeninfo, buf, (size_t)len);
  /* CLCO 06/07/2010 : Fin  */
  if (err != SC_SUCCESS)
    goto end;
  p15card->version         = tokeninfo.version;
  p15card->label           = tokeninfo.label;
  /* CLCO 01/06/2010 : Gestion IAS du numéro de série devant figurer dans le token info */
  if (tokeninfo.serial_number[0]==0) { /* le numéro de série est-il présent dans le fichier CIAInfo ? */
    if ((strcmp(card->driver->name, "IAS")==0) || (strcmp(card->driver->name, "NXP") == 0)) {
      free(tokeninfo.serial_number);
      /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
      /* La lecture du numéro de série a déjà été fait à l'init du driver de la carte */
      p15card->serial_number = malloc(p15card->card->serialnr.len+1);
      if (p15card->serial_number != NULL) {
        strcpy(p15card->serial_number, (char*)p15card->card->serialnr.value);
      }
      else {
        return SC_ERROR_OUT_OF_MEMORY;
      }
      /* CLCO 06/07/2010 : Fin  */
    }
  } else {
    p15card->serial_number   = tokeninfo.serial_number;
  }
  /* CLCO 01/06/2010 : fin */
  p15card->manufacturer_id = tokeninfo.manufacturer_id;
  p15card->last_update     = tokeninfo.last_update;
  p15card->flags           = tokeninfo.flags;
  p15card->preferred_language = tokeninfo.preferred_language;
  p15card->seInfo          = tokeninfo.seInfo;
  p15card->num_seInfo      = tokeninfo.num_seInfo;

  ok = 1;
end:
  if (buf != NULL) { free(buf); }
  if (!ok) {
    sc_pkcs15_card_clear(p15card);
    return err;
  }

  return SC_SUCCESS;
}

int sc_pkcs15_bind(sc_card_t *card, struct sc_pkcs15_card **p15card_out)
{
  struct sc_pkcs15_card *p15card = NULL;
  sc_context_t *ctx;
  scconf_block *conf_block = NULL, **blocks;
  int    i, r, emu_first, enable_emu;

  assert(sc_card_valid(card) && p15card_out != NULL);
  ctx = card->ctx;
  
  SC_FUNC_CALLED(ctx, 1);

  p15card = sc_pkcs15_card_new();
  if (p15card == NULL) {
    return SC_ERROR_OUT_OF_MEMORY;
  }
  p15card->card = card;

  for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
    blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i], "framework", "pkcs15");
    if (blocks && blocks[0] != NULL)
    {
      conf_block = blocks[0];
    }
    free(blocks);
  }

  if (conf_block) {
    // p15card->opts.use_cache = scconf_get_bool(conf_block, "use_caching", 0);
	// BPER Pour la mise a jour des cartes CPS, paramétrer la désactivation du cache
	p15card->opts.use_cache = card->ctx->use_cache;
  }

  r = sc_lock(card);
  if (r) {
    sc_error(ctx, "sc_lock() failed: %s\n", sc_strerror(r));
    sc_pkcs15_card_free(p15card);
    SC_FUNC_RETURN(ctx, 1, r);
  }

  enable_emu = scconf_get_bool(conf_block, "enable_pkcs15_emulation", 1);
  if (enable_emu) {
    emu_first = scconf_get_bool(conf_block, "try_emulation_first", 0);

    if (emu_first || sc_pkcs15_is_emulation_only(card)) {
      r = sc_pkcs15_bind_synthetic(p15card);
      if (r != SC_SUCCESS) {
        r = sc_pkcs15_bind_internal(p15card);
      }
    } else {
      r = sc_pkcs15_bind_internal(p15card);
      if (r != SC_SUCCESS) {
        r = sc_pkcs15_bind_synthetic(p15card);
      }
    }

  } else {
    r = sc_pkcs15_bind_internal(p15card);
  }

  if (r < 0) {
    sc_unlock(card);
    sc_pkcs15_card_free(p15card);
    SC_FUNC_RETURN(ctx, 1, r);
  }

  *p15card_out = p15card;
  sc_unlock(card);
  return SC_SUCCESS;
}

int sc_pkcs15_unbind(struct sc_pkcs15_card *p15card)
{
  assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);
  SC_FUNC_CALLED(p15card->card->ctx, 1);
  if (p15card->dll_handle)
    lt_dlclose(p15card->dll_handle);
  sc_pkcs15_card_free(p15card);
  return 0;
}


int __sc_pkcs15_add_cps2ter_object(sc_pkcs15_card_t* p15card, cps2ter_entry entry)
{
  struct sc_pkcs15_object* obj = NULL;
  struct sc_pkcs15_data_info* info = NULL;
  int r;

  if (p15card == NULL) {
    return SC_ERROR_INVALID_ARGUMENTS;
  }
  obj = calloc(1, sizeof(struct sc_pkcs15_object));
  if (obj == NULL) {
    return SC_ERROR_OUT_OF_MEMORY;
  }

  info = calloc(1, sizeof(struct sc_pkcs15_data_info));
  if (info == NULL) {
    free(obj);
    return SC_ERROR_OUT_OF_MEMORY;
  }

  memcpy(info->path.value, entry.cps2terPath, entry.cps2terPathSize);
  info->path.len = entry.cps2terPathSize;
  info->path.type = SC_PATH_TYPE_CPS2TER;
  info->app_oid.value[0] = -1;
  info->path.count = -1;
  strcpy(info->app_label, "CPS");

  obj->auth_id.len = 1;
  obj->auth_id.value[0] = 1;
  strcpy(obj->label, entry.cps2terName);
  obj->type = SC_PKCS15_TYPE_DATA_OBJECT;
  obj->data = info;
  obj->flags = SC_PKCS15_CO_FLAG_PRIVATE;

  r = sc_pkcs15_encode_dodf_entry(p15card->card->ctx, obj, &obj->der.value, &obj->der.len);
  if (r == SC_SUCCESS) {
    r = sc_pkcs15_add_object(p15card, obj);
  }
  return r;
}

int __sc_pkcs15_add_cps_sit_fat(sc_pkcs15_card_t *p15card)
{
  struct sc_pkcs15_object *obj = NULL;
  struct sc_pkcs15_data_info  *info = NULL;
  int r;

  if (p15card == NULL) {
    return SC_ERROR_INVALID_ARGUMENTS;
  }
  
  obj = calloc(1, sizeof(struct sc_pkcs15_object));
  if (obj == NULL) {
    return SC_ERROR_OUT_OF_MEMORY;
  }

  info = calloc(1, sizeof(struct sc_pkcs15_data_info));
  if (info == NULL) {
    free(obj);
    return SC_ERROR_OUT_OF_MEMORY;
  }

  memcpy(info->path.value, "\x3F\x00\x7F\x01\x40\x00", 6);
  info->path.len = 6;
  info->path.type = SC_PATH_TYPE_CPS2TER;
  info->app_oid.value[0] = -1;
  info->path.count = -1;
  strcpy(info->app_label,"CPS");

  obj->auth_id.len = 1;
  obj->auth_id.value[0] = 1;
  strcpy(obj->label, "CPS_SIT_FACT");
  obj->type = SC_PKCS15_TYPE_DATA_OBJECT;
  obj->data = info;
  obj->flags = SC_PKCS15_CO_FLAG_PRIVATE;

  r = sc_pkcs15_encode_dodf_entry(p15card->card->ctx, obj, &obj->der.value, &obj->der.len);
  if ( r== SC_SUCCESS) {
    r = sc_pkcs15_add_object(p15card, obj);
  }
  return r;
}
#define PREFX_SIT "CPS_ACTIVITY"
situation_map Sits[] = {
  { "CPS_ACTIVITY_01_PS",{"CPS2TER_ACTIVITY_01_PS",{ 0x3F,0x00,0x40, 0X10 },4} },
  { "CPS_ACTIVITY_02_PS",{"CPS2TER_ACTIVITY_02_PS",{ 0x3F,0x00,0x40, 0X11 },4} },
  { "CPS_ACTIVITY_03_PS",{"CPS2TER_ACTIVITY_03_PS",{ 0x3F,0x00,0x40, 0X12 },4} },
  { "CPS_ACTIVITY_04_PS",{"CPS2TER_ACTIVITY_04_PS",{ 0x3F,0x00,0x40, 0X13 },4} },
  { "CPS_ACTIVITY_05_PS",{"CPS2TER_ACTIVITY_05_PS",{ 0x3F,0x00,0x40, 0X14 },4} },
  { "CPS_ACTIVITY_06_PS",{"CPS2TER_ACTIVITY_06_PS",{ 0x3F,0x00,0x40, 0X15 },4} },
  { "CPS_ACTIVITY_07_PS",{"CPS2TER_ACTIVITY_07_PS",{ 0x3F,0x00,0x40, 0X16 },4} },
  { "CPS_ACTIVITY_08_PS",{"CPS2TER_ACTIVITY_08_PS",{ 0x3F,0x00,0x40, 0X17 },4} },
  { "CPS_ACTIVITY_09_PS",{"CPS2TER_ACTIVITY_09_PS",{ 0x3F,0x00,0x40, 0X18 },4} },
  { "CPS_ACTIVITY_10_PS",{"CPS2TER_ACTIVITY_10_PS",{ 0x3F,0x00,0x40, 0X19 },4} },
  { "CPS_ACTIVITY_11_PS",{"CPS2TER_ACTIVITY_11_PS",{ 0x3F,0x00,0x40, 0X1A },4} },
  { "CPS_ACTIVITY_12_PS",{"CPS2TER_ACTIVITY_12_PS",{ 0x3F,0x00,0x40, 0X1B },4} },
  { "CPS_ACTIVITY_13_PS",{"CPS2TER_ACTIVITY_13_PS",{ 0x3F,0x00,0x40, 0X1C },4} },
  { "CPS_ACTIVITY_14_PS",{"CPS2TER_ACTIVITY_14_PS",{ 0x3F,0x00,0x40, 0X1D },4} },
  { "CPS_ACTIVITY_15_PS",{"CPS2TER_ACTIVITY_15_PS",{ 0x3F,0x00,0x40, 0X1E },4} },
  { "CPS_ACTIVITY_16_PS",{"CPS2TER_ACTIVITY_16_PS",{ 0x3F,0x00,0x40, 0X1F },4} },
};

cps2ter_entry sit_fact = { "CPS_SIT_FACT" ,{ 0x3F, 0x00, 0x7F, 0x01, 0x40, 0x00 },6 };


static int __add_cps2ter_sit(sc_pkcs15_card_t* p15card)
{
  sc_pkcs15_object_t* obj;
  int    r = 0;
  int i;
  for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
    if (strstr(obj->label, PREFX_SIT) != NULL) {
      for (i=0; i < 16; i++) {
        if (!strcmp(Sits[i].cps3Name, obj->label)) {
          r = __sc_pkcs15_add_cps2ter_object(p15card, Sits[i].cps2ter);
        }
      }
    }
  }
  return SC_SUCCESS;
}

static int
__sc_pkcs15_search_objects(sc_pkcs15_card_t *p15card,
      unsigned int class_mask, unsigned int type,
      int (*func)(sc_pkcs15_object_t *, void *),
                        void *func_arg,
      sc_pkcs15_object_t **ret, size_t ret_size)
{
  sc_pkcs15_object_t *obj;
  sc_pkcs15_df_t  *df;
  unsigned int  df_mask = 0;
  size_t    match_count = 0;
  int    r = 0;

  if (type)
    class_mask |= SC_PKCS15_TYPE_TO_CLASS(type);

  /* Make sure the class mask we have makes sense */
  if (class_mask == 0
   || (class_mask & ~(SC_PKCS15_SEARCH_CLASS_PRKEY |
          SC_PKCS15_SEARCH_CLASS_PUBKEY |
          SC_PKCS15_SEARCH_CLASS_CERT |
          SC_PKCS15_SEARCH_CLASS_DATA |
          SC_PKCS15_SEARCH_CLASS_AUTH))) {
    return SC_ERROR_INVALID_ARGUMENTS;
  }

  if (class_mask & SC_PKCS15_SEARCH_CLASS_PRKEY)
    df_mask |= (1 << SC_PKCS15_PRKDF);
  if (class_mask & SC_PKCS15_SEARCH_CLASS_PUBKEY)
    df_mask |= (1 << SC_PKCS15_PUKDF)
       | (1 << SC_PKCS15_PUKDF_TRUSTED);
  if (class_mask & SC_PKCS15_SEARCH_CLASS_CERT)
    df_mask |= (1 << SC_PKCS15_CDF)
       | (1 << SC_PKCS15_CDF_TRUSTED)
       | (1 << SC_PKCS15_CDF_USEFUL);
  if (class_mask & SC_PKCS15_SEARCH_CLASS_DATA)
    df_mask |= (1 << SC_PKCS15_DODF);
  if (class_mask & SC_PKCS15_SEARCH_CLASS_AUTH)
    df_mask |= (1 << SC_PKCS15_AODF);

  /* Make sure all the DFs we want to search have been
   * enumerated. */
  for (df = p15card->df_list; df != NULL; df = df->next) {
    if (!(df_mask & (1 << df->type)))
      continue;
    if (df->enumerated || ((df->type == SC_PKCS15_DODF) && (g_winlogonProcess==TRUE)))
      continue;
    /* Enumerate the DF's, so p15card->obj_list is
     * populated. */
    r = sc_pkcs15_parse_df(p15card, df);
    SC_TEST_RET(p15card->card->ctx, r, "DF parsing failed");
    if (df->type == SC_PKCS15_DODF && p15card->card->type == SC_CARD_TYPE_IAS_CPS3) {
      r = __sc_pkcs15_add_cps2ter_object(p15card, sit_fact);
      r = __add_cps2ter_sit(p15card);
      SC_TEST_RET(p15card->card->ctx, r, "Addin CPS Sit Facturation failed");
    }
    df->enumerated = 1;
  }

  /* And now loop over all objects */
  for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
    /* Check object type */
    if (!(class_mask & SC_PKCS15_TYPE_TO_CLASS(obj->type)))
      continue;
    if (type != 0
     && obj->type != type
     && (obj->type & SC_PKCS15_TYPE_CLASS_MASK) != type)
      continue;

    /* Potential candidate, apply search function */
    if (func != NULL && func(obj, func_arg) <= 0)
      continue;
    /* Okay, we have a match. */
    match_count++;
    if (ret_size == 0)
      continue;
    ret[match_count-1] = obj;
    if (ret_size <= match_count)
      break;
  }
  return (int)match_count;
}

int sc_pkcs15_get_objects(struct sc_pkcs15_card *p15card, unsigned int type,
        struct sc_pkcs15_object **ret, size_t ret_size)
{
  return sc_pkcs15_get_objects_cond(p15card, type, NULL, NULL, ret, ret_size);
}

static int compare_obj_id(struct sc_pkcs15_object *obj, const sc_pkcs15_id_t *id)
{
  void *data = obj->data;
  
  switch (obj->type) {
  case SC_PKCS15_TYPE_CERT_X509:
    return sc_pkcs15_compare_id(&((struct sc_pkcs15_cert_info *) data)->id, id);
  case SC_PKCS15_TYPE_PRKEY_RSA:
  case SC_PKCS15_TYPE_PRKEY_DSA:
    return sc_pkcs15_compare_id(&((struct sc_pkcs15_prkey_info *) data)->id, id);
  case SC_PKCS15_TYPE_PUBKEY_RSA:
  case SC_PKCS15_TYPE_PUBKEY_DSA:
    return sc_pkcs15_compare_id(&((struct sc_pkcs15_pubkey_info *) data)->id, id);
  case SC_PKCS15_TYPE_AUTH_PIN:
    return sc_pkcs15_compare_id(&((struct sc_pkcs15_pin_info *) data)->auth_id, id);
  case SC_PKCS15_TYPE_DATA_OBJECT:
    return sc_pkcs15_compare_id(&((struct sc_pkcs15_data_info *) data)->id, id);
  }
  return 0;
}

static int sc_obj_app_oid(struct sc_pkcs15_object *obj, const struct sc_object_id *app_oid)
{
  if (obj->type & SC_PKCS15_TYPE_DATA_OBJECT)
    return sc_compare_oid(&((struct sc_pkcs15_data_info *) obj->data)->app_oid, app_oid);
  return 0;
}

static int compare_obj_usage(sc_pkcs15_object_t *obj, unsigned int mask, unsigned int value)
{
  void    *data = obj->data;
  unsigned int  usage;

  switch (obj->type) {
  case SC_PKCS15_TYPE_PRKEY_RSA:
  case SC_PKCS15_TYPE_PRKEY_DSA:
    usage = ((struct sc_pkcs15_prkey_info *) data)->usage;
    break;
  case SC_PKCS15_TYPE_PUBKEY_RSA:
  case SC_PKCS15_TYPE_PUBKEY_DSA:
    usage = ((struct sc_pkcs15_pubkey_info *) data)->usage;
    break;
  default:
    return 0;
  }
  return (usage & mask & value) != 0;
}

static int compare_obj_flags(sc_pkcs15_object_t *obj, unsigned int mask, unsigned int value)
{
  void    *data = obj->data;
  unsigned int  flags;

  switch (obj->type) {
  case SC_PKCS15_TYPE_AUTH_PIN:
    flags = ((struct sc_pkcs15_pin_info *) data)->flags;
    break;
  default:
    return 0;
  }
  return !((flags ^ value) & mask);
}

static int compare_obj_reference(sc_pkcs15_object_t *obj, int value)
{
  void    *data = obj->data;
  int    reference;

  switch (obj->type) {
  case SC_PKCS15_TYPE_AUTH_PIN:
    reference = ((struct sc_pkcs15_pin_info *) data)->reference;
    break;
  case SC_PKCS15_TYPE_PRKEY_RSA:
  case SC_PKCS15_TYPE_PRKEY_DSA:
    reference = ((struct sc_pkcs15_prkey_info *) data)->key_reference;
    break;
  default:
    return 0;
  }
  return reference == value;
}

static int compare_obj_path(sc_pkcs15_object_t *obj, const sc_path_t *path)
{
  void *data = obj->data;
  
  switch (obj->type) {
  case SC_PKCS15_TYPE_CERT_X509:
    return sc_compare_path(&((struct sc_pkcs15_cert_info *) data)->path, path);
  case SC_PKCS15_TYPE_PRKEY_RSA:
  case SC_PKCS15_TYPE_PRKEY_DSA:
    return sc_compare_path(&((struct sc_pkcs15_prkey_info *) data)->path, path);
  case SC_PKCS15_TYPE_PUBKEY_RSA:
  case SC_PKCS15_TYPE_PUBKEY_DSA:
    return sc_compare_path(&((struct sc_pkcs15_pubkey_info *) data)->path, path);
  case SC_PKCS15_TYPE_AUTH_PIN:
    return sc_compare_path(&((struct sc_pkcs15_pin_info *) data)->path, path);
  case SC_PKCS15_TYPE_DATA_OBJECT:
    return sc_compare_path(&((struct sc_pkcs15_data_info *) data)->path, path);
  }
  return 0;
}

static int compare_obj_data_name(sc_pkcs15_object_t *obj, const char *app_label, const char *label)
{
  struct sc_pkcs15_data_info *cinfo = (struct sc_pkcs15_data_info *) obj->data;

  if (obj->type != SC_PKCS15_TYPE_DATA_OBJECT)
    return 0;
  
  return !strcmp(cinfo->app_label, app_label) &&
    !strcmp(obj->label, label);
}

static int compare_obj_key(struct sc_pkcs15_object *obj, void *arg)
{
  struct sc_pkcs15_search_key *sk = (struct sc_pkcs15_search_key *) arg;

  if (sk->id && !compare_obj_id(obj, sk->id))
    return 0;
  if (sk->app_oid && !sc_obj_app_oid(obj, sk->app_oid))
    return 0;
  if (sk->usage_mask && !compare_obj_usage(obj, sk->usage_mask, sk->usage_value))
    return 0;
  if (sk->flags_mask && !compare_obj_flags(obj, sk->flags_mask, sk->flags_value))
    return 0;
  if (sk->match_reference && !compare_obj_reference(obj, sk->reference))
    return 0;
  if (sk->path && !compare_obj_path(obj, sk->path))
    return 0;
  if (
    sk->app_label && sk->label &&
    !compare_obj_data_name(obj, sk->app_label, sk->label)
  ) {
    return 0;
  }

  return 1;
}

static int find_by_key(struct sc_pkcs15_card *p15card,
           unsigned int type, struct sc_pkcs15_search_key *sk,
           struct sc_pkcs15_object **out)
{
  int r;
  
  r = sc_pkcs15_get_objects_cond(p15card, type, compare_obj_key, sk, out, 1);
  if (r < 0)
    return r;
  if (r == 0)
    return SC_ERROR_OBJECT_NOT_FOUND;
  return 0;
}

int sc_pkcs15_get_objects_cond(struct sc_pkcs15_card *p15card, unsigned int type,
             int (* func)(struct sc_pkcs15_object *, void *),
                               void *func_arg,
             struct sc_pkcs15_object **ret, size_t ret_size)
{
  return __sc_pkcs15_search_objects(p15card, 0, type,
      func, func_arg, ret, ret_size);
}

int sc_pkcs15_find_object_by_id(sc_pkcs15_card_t *p15card,
        unsigned int type, const sc_pkcs15_id_t *id,
        sc_pkcs15_object_t **out)
{
  sc_pkcs15_search_key_t sk;
  int  r;

  memset(&sk, 0, sizeof(sk));
  sk.id = id;

  r = __sc_pkcs15_search_objects(p15card, 0, type,
        compare_obj_key, &sk,
        out, 1);
  if (r < 0)
    return r;
  if (r == 0)
    return SC_ERROR_OBJECT_NOT_FOUND;
  return 0;
}

int sc_pkcs15_find_pin_by_auth_id(struct sc_pkcs15_card *p15card,
           const struct sc_pkcs15_id *id,
           struct sc_pkcs15_object **out)
{
  return sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_AUTH_PIN, id, out);
}

int sc_pkcs15_find_so_pin(struct sc_pkcs15_card *p15card,
      struct sc_pkcs15_object **out)
{
  struct sc_pkcs15_search_key sk;

  memset(&sk, 0, sizeof(sk));
  sk.flags_mask = sk.flags_value = SC_PKCS15_PIN_FLAG_SO_PIN;
  
  return find_by_key(p15card, SC_PKCS15_TYPE_AUTH_PIN, &sk, out);
}

int sc_pkcs15_add_object(struct sc_pkcs15_card *p15card,
       struct sc_pkcs15_object *obj)
{
  struct sc_pkcs15_object *p = p15card->obj_list;

  obj->next = obj->prev = NULL;
  if (p15card->obj_list == NULL) {
    p15card->obj_list = obj;
    return 0;
  }
  while (p->next != NULL)
     p = p->next;
  p->next = obj;
  obj->prev = p;

  return 0;
}

void sc_pkcs15_remove_object(struct sc_pkcs15_card *p15card,
           struct sc_pkcs15_object *obj)
{
  if (obj->prev == NULL)
    p15card->obj_list = obj->next;
  else
    obj->prev->next = obj->next;
  if (obj->next != NULL)
    obj->next->prev = obj->prev;
  sc_pkcs15_free_object(obj);
}

void sc_pkcs15_free_object(struct sc_pkcs15_object *obj)
{
  switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
  case SC_PKCS15_TYPE_PRKEY:
    sc_pkcs15_free_prkey_info((sc_pkcs15_prkey_info_t *)obj->data);
    break;
  case SC_PKCS15_TYPE_PUBKEY:
    sc_pkcs15_free_pubkey_info((sc_pkcs15_pubkey_info_t *)obj->data);
    break;
  case SC_PKCS15_TYPE_CERT:
    sc_pkcs15_free_cert_info((sc_pkcs15_cert_info_t *)obj->data);
    break;
  case SC_PKCS15_TYPE_DATA_OBJECT:
    sc_pkcs15_free_data_info((sc_pkcs15_data_info_t *)obj->data);
    break;
  case SC_PKCS15_TYPE_AUTH:
    sc_pkcs15_free_pin_info((sc_pkcs15_pin_info_t *)obj->data);
    break;
  default:
    free(obj->data);
  }

  if (obj->der.value)
    free(obj->der.value);
  free(obj);
}

int sc_pkcs15_add_df(struct sc_pkcs15_card *p15card,
         unsigned int type, const sc_path_t *path,
         const sc_file_t *file)
{
  struct sc_pkcs15_df *p = p15card->df_list, *newdf;

  /* MCUG 14/09/10 : Afin de permettre le masquage de certains objets */
  if(p15card->card->ops->is_visible == NULL || p15card->card->ops->is_visible(path) == 1)
  {
  /* MCUG 14/09/10 : Fin */

    newdf = (struct sc_pkcs15_df *) calloc(1, sizeof(struct sc_pkcs15_df));
    if (newdf == NULL)
      return SC_ERROR_OUT_OF_MEMORY;
    newdf->path = *path;
    newdf->type = type;
    if (file != NULL) {
      sc_file_dup(&newdf->file, file);
      if (newdf->file == NULL) {
        free(newdf);
        return SC_ERROR_OUT_OF_MEMORY;
      }
        
    }
    if (p15card->df_list == NULL) {
      p15card->df_list = newdf;
      return 0;
    }
    while (p->next != NULL)
      p = p->next;
    p->next = newdf;
    newdf->prev = p;

  /* MCUG 14/09/10 : Afin de permettre le masquage de certains objets */
  }
  /* MCUG 14/09/10 : Fin */

  return 0;
}

void sc_pkcs15_remove_df(struct sc_pkcs15_card *p15card,
       struct sc_pkcs15_df *obj)
{
  if (obj->prev == NULL)
    p15card->df_list = obj->next;
  else
    obj->prev->next = obj->next;
  if (obj->next != NULL)
    obj->next->prev = obj->prev;
  if (obj->file)
    sc_file_free(obj->file);
  free(obj);
}

int sc_pkcs15_parse_df(struct sc_pkcs15_card *p15card,
           struct sc_pkcs15_df *df)
{
  sc_context_t *ctx = p15card->card->ctx;
  u8 *buf;
  const u8 *p;
  size_t bufsize;
  int r;
  struct sc_pkcs15_object *obj = NULL;
  int (* func)(struct sc_pkcs15_card *, struct sc_pkcs15_object *,
         const u8 **nbuf, size_t *nbufsize) = NULL;

  switch (df->type) {
  case SC_PKCS15_PRKDF:
    func = sc_pkcs15_decode_prkdf_entry;
    break;
  case SC_PKCS15_PUKDF:
    func = sc_pkcs15_decode_pukdf_entry;
    break;
  case SC_PKCS15_CDF:
  case SC_PKCS15_CDF_TRUSTED:
  case SC_PKCS15_CDF_USEFUL:
    func = sc_pkcs15_decode_cdf_entry;
    break;
  case SC_PKCS15_DODF:
    func = sc_pkcs15_decode_dodf_entry;
    break;
  case SC_PKCS15_AODF:
    func = sc_pkcs15_decode_aodf_entry;
    break;
  }
  if (func == NULL) {
    sc_error(ctx, "unknown DF type: %d\n", df->type);
    return SC_ERROR_INVALID_ARGUMENTS;
  }
  if (df->file != NULL)
    r = sc_pkcs15_read_file(p15card, &df->path,
        /* BPER (@@20150216-1226) - Paramètre supplémentaire spécifiant que l'on veut les données */
          &buf, &bufsize, NULL, 0);
    /* BPER (@@20150216-1226) - Paramètre supplémentaire spécifiant que l'on veut les données - Fin */
  else
    r = sc_pkcs15_read_file(p15card, &df->path,
        /* BPER (@@20150216-1226) - Paramètre supplémentaire spécifiant que l'on veut les données */
          &buf, &bufsize, &df->file, 0);
    /* BPER (@@20150216-1226) - Paramètre supplémentaire spécifiant que l'on veut les données - Fin */
  if (r < 0)
    return r;

  p = buf;
  while (bufsize && *p != 0x00) {
    const u8 *oldp;
    size_t obj_len;
    
    obj = (struct sc_pkcs15_object *) calloc(1, sizeof(struct sc_pkcs15_object));
    if (obj == NULL) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto ret;
    }
    oldp = p;
    r = func(p15card, obj, &p, &bufsize);
    if (r) {
      free(obj);
      if (r == SC_ERROR_ASN1_END_OF_CONTENTS) {
        r = 0;
        break;
      }
      sc_perror(ctx, r, "Error decoding DF entry");
      goto ret;
    }
    obj_len = p - oldp;

    obj->der.value = (u8 *) malloc(obj_len);
    if (obj->der.value == NULL) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto ret;
    }
    memcpy(obj->der.value, oldp, obj_len);
    obj->der.len = obj_len;

    obj->df = df;
    r = sc_pkcs15_add_object(p15card, obj);
    if (r) {
      if (obj->data)
        free(obj->data);
      free(obj);
      sc_perror(ctx, r, "Error adding object");
      goto ret;
    }
  };
ret:
  free(buf);
  return r;
}

void sc_pkcs15_remove_unusedspace(struct sc_pkcs15_card *p15card,
       sc_pkcs15_unusedspace_t *unusedspace)
{
  if (unusedspace->prev == NULL)
    p15card->unusedspace_list = unusedspace->next;
  else
    unusedspace->prev->next = unusedspace->next;
  if (unusedspace->next != NULL)
    unusedspace->next->prev = unusedspace->prev;
  free(unusedspace);
}

int sc_pkcs15_read_file(struct sc_pkcs15_card *p15card,
      const sc_path_t *in_path,
      u8 **buf, size_t *buflen,
      sc_file_t **file_out
/* BPER (@@20150216-1226) - Paramètre supplémentaire spécifiant que l'on ne veut que la taille */
    , int size_only
/* BPER (@@20150216-1226) - Paramètre supplémentaire spécifiant que l'on ne veut que la taille - Fin*/
            )
{
  sc_file_t *file = NULL;
  u8  *data = NULL;
  size_t  len = 0, offset = 0;
  int  r;

  assert(p15card != NULL && in_path != NULL && buf != NULL);

  if (p15card->card->ctx->debug >= 1) {
    char pbuf[SC_MAX_PATH_STRING_SIZE];

    r = sc_path_print(pbuf, sizeof(pbuf), in_path);
    if (r != SC_SUCCESS)
      pbuf[0] = '\0';

    sc_debug(p15card->card->ctx, "called, path=%s, index=%u, count=%d, size_only=%d\n",
      pbuf, in_path->index, in_path->count, size_only);
  }

  /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
  if(cache_action < 0)
    cache_action = p15card->opts.use_cache;

  r = -1; /* file state: not in cache */
  if (cache_action == USE_CACHE) {
    r = sc_pkcs15_read_cached_file(p15card, in_path, &data, &len);
  }
  /* MCUG 14/09/2010 : Fin */

  if (r) {
    r = sc_lock(p15card->card);
    SC_TEST_RET(p15card->card->ctx, r, "sc_lock() failed");
    r = sc_select_file(p15card->card, in_path, &file);
    if (r)
      goto fail_unlock;
/* BPER (@@20150216-1226) - Paramètre supplémentaire spécifiant que l'on ne veut que la taille */
    if (size_only) {
      *buflen = file->size;
      sc_file_free(file);
      sc_unlock(p15card->card);
      return 0;
    }
/* BPER (@@20150216-1226) - Paramètre supplémentaire spécifiant que l'on ne veut que la taille - Fin */

    /* Handle the case where the ASN.1 Path object specified
     * index and length values */
    if (in_path->count < 0) {
      len = file->size;
      offset = 0;
    } else {
      offset = in_path->index;
      len = in_path->count;
      /* Make sure we're within proper bounds */
      if (offset >= file->size
       || offset + len > file->size) {
        r = SC_ERROR_INVALID_ASN1_OBJECT;
        goto fail_unlock;
      }
    }
    data = (u8 *) malloc(len);
    if (data == NULL) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto fail_unlock;
    }
    if (file->ef_structure == SC_FILE_EF_LINEAR_VARIABLE_TLV) {
      int i;
      size_t l, record_len;
      unsigned char *head;

      head = data;
      for (i=1;  ; i++) {
        l = len - (head - data);
        if (l > 256) { l = 256; }
        p15card->card->ctx->suppress_errors++;
        r = sc_read_record(p15card->card, i, head, l,
            SC_RECORD_BY_REC_NR);
        p15card->card->ctx->suppress_errors--;
        if (r == SC_ERROR_RECORD_NOT_FOUND)
          break;
        if (r < 0) {
          free(data);
          goto fail_unlock;
        }
        if (r < 2)
          break;
        record_len = head[1];
        if (record_len != 0xff) {
          memmove(head,head+2,r-2);
          head += (r-2);
        } else {
          if (r < 4)
            break;
          record_len = head[2] * 256 + head[3];
          memmove(head,head+4,r-4);
          head += (r-4);
        }
      }
      len = head-data;
      r = (int)len;
    } else {
      r = sc_read_binary(p15card->card, (unsigned int)offset, data, len, (in_path->type == SC_PATH_TYPE_CPS2TER) ? CPS2TER_FLAG:0);
      if (r < 0) {
        free(data);
        goto fail_unlock;
      }
      /* sc_read_binary may return less than requested */
      len = r;
    } 
    sc_unlock(p15card->card);

    /* Return of release file */
    if (file_out != NULL)
      *file_out = file;
    else
      sc_file_free(file);

    /* MCUG 14/09/2010 : Gestion de la mise à jour des fichiers de situations */
    if ((cache_action == USE_CACHE || cache_action == MAJ_CACHE) && data && len) {
      r = sc_pkcs15_cache_file(p15card, in_path, data, len);
    }
    /* MCUG 14/09/2010 : Fin */
  }
  *buf = data;
  *buflen = len;
  return 0;

fail_unlock:
  if (file)
    sc_file_free(file);
  sc_unlock(p15card->card);
  return r;
}

int sc_pkcs15_compare_id(const struct sc_pkcs15_id *id1,
       const struct sc_pkcs15_id *id2)
{
  assert(id1 != NULL && id2 != NULL);
  if (id1->len != id2->len)
    return 0;
  return memcmp(id1->value, id2->value, id1->len) == 0;
}

const char *sc_pkcs15_print_id(const struct sc_pkcs15_id *id)
{
  static char buffer[256];

  sc_bin_to_hex(id->value, id->len, buffer, sizeof(buffer), '\0');
  return buffer;
}

int sc_pkcs15_make_absolute_path(const sc_path_t *parent, sc_path_t *child)
{
  /* a 0 length path stays a 0 length path */
  if (child->len == 0)
    return SC_SUCCESS;

  if (sc_compare_path_prefix(sc_get_mf_path(), child))
    return SC_SUCCESS;
  return sc_concatenate_path(child, parent, child);
}
