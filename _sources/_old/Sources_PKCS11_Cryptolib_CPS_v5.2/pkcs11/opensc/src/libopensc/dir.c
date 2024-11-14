/*
 * dir.c: Stuff for handling EF(DIR)
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
#include "asn1.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct app_entry {
  const u8 *aid;
  size_t aid_len;
  const char *desc;
};

static const struct app_entry apps[] = {
  { (const u8 *) "\xA0\x00\x00\x00\x63PKCS-15", 12, "PKCS #15" },
  { (const u8 *) "\xA0\x00\x00\x01\x77PKCS-15", 12, "Belgian eID" },
  /*
  CLCO 12/04/2010 : Ajout de l'identifiant d'application de la carte IAS ECC CPS3.
  */
    { (const u8 *) "\xE8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x10", 13, "ASIP CPS" },
    { (const u8 *) "\xE8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x20", 13, "ASIP CPS CL" },
  /*
  CLCO 12/04/2010 : Fin.
  */
};

static const struct app_entry * find_app_entry(const u8 * aid, size_t aid_len)
{
  size_t i;

  for (i = 0; i < sizeof(apps) / sizeof(apps[0]); i++) {
    if (apps[i].aid_len == aid_len &&
      memcmp(apps[i].aid, aid, aid_len) == 0)
      return &apps[i];
  }
  return NULL;
}

const sc_app_info_t * sc_find_pkcs15_app(sc_card_t *card)
{
  const sc_app_info_t *app = NULL;
  unsigned int i;

  /* CLCO 06/05/2010 : rechercher via le driver carte l'aid PKCS#15 qui correspond à l'ATR */
  if (card->ops->get_aid_pkcs15) {
    u8 aid_pkcs15[SC_MAX_AID_SIZE];
    size_t aid_len = sizeof(aid_pkcs15);
    if (card->ops->get_aid_pkcs15(card, aid_pkcs15, &aid_len) == SC_SUCCESS)
      app = sc_find_app_by_aid(card, aid_pkcs15, aid_len);
  }
  else {
    /* CLCO 06/05/2010 : sinon faire comme prévu par OpenSC initialement */
    i = sizeof(apps) / sizeof(apps[0]);
    while (!app && i--)
      app = sc_find_app_by_aid(card, apps[i].aid, apps[i].aid_len);
  }
  /* CLCO 06/05/2010 : fin */

  return app;
}

static const struct sc_asn1_entry c_asn1_dirrecord[] = {
  { "aid",   SC_ASN1_OCTET_STRING, SC_ASN1_APP | 15, 0, NULL, NULL },
  { "label", SC_ASN1_UTF8STRING,   SC_ASN1_APP | 16, SC_ASN1_OPTIONAL, NULL, NULL },
  { "path",  SC_ASN1_OCTET_STRING, SC_ASN1_APP | 17, SC_ASN1_OPTIONAL, NULL, NULL },
  { "ddo",   SC_ASN1_OCTET_STRING, SC_ASN1_APP | 19 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_dir[] = {
  { "dirRecord", SC_ASN1_STRUCT, SC_ASN1_APP | 1 | SC_ASN1_CONS, 0, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};

static int parse_dir_record(sc_card_t *card, u8 ** buf, size_t *buflen,
  int rec_nr)
{
  struct sc_asn1_entry asn1_dirrecord[5], asn1_dir[2];
  sc_app_info_t *app = NULL;
  const struct app_entry *ae;
  int r;
  u8 aid[128], label[128], path[128];
  u8 ddo[128];
  size_t aid_len = sizeof(aid), label_len = sizeof(label),
    path_len = sizeof(path), ddo_len = sizeof(ddo);

  sc_copy_asn1_entry(c_asn1_dirrecord, asn1_dirrecord);
  sc_copy_asn1_entry(c_asn1_dir, asn1_dir);
  sc_format_asn1_entry(asn1_dir + 0, asn1_dirrecord, NULL, 0);
  sc_format_asn1_entry(asn1_dirrecord + 0, aid, &aid_len, 0);
  sc_format_asn1_entry(asn1_dirrecord + 1, label, &label_len, 0);
  sc_format_asn1_entry(asn1_dirrecord + 2, path, &path_len, 0);
  sc_format_asn1_entry(asn1_dirrecord + 3, ddo, &ddo_len, 0);

  r = sc_asn1_decode(card->ctx, asn1_dir, *buf, *buflen, (const u8 **)buf, buflen);
  if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
    return r;
  if (r) {
    sc_error(card->ctx, "EF(DIR) parsing failed: %s\n",
      sc_strerror(r));
    return r;
  }
  if (aid_len > SC_MAX_AID_SIZE) {
    sc_error(card->ctx, "AID is too long.\n");
    return SC_ERROR_INVALID_ASN1_OBJECT;
  }
  app = (sc_app_info_t *)malloc(sizeof(sc_app_info_t));
  if (app == NULL)
    return SC_ERROR_OUT_OF_MEMORY;

  memcpy(app->aid, aid, aid_len);
  app->aid_len = aid_len;
  if (asn1_dirrecord[1].flags & SC_ASN1_PRESENT)
    app->label = strdup((char *)label);
  else
    app->label = NULL;
  if (asn1_dirrecord[2].flags & SC_ASN1_PRESENT) {
    if (path_len > SC_MAX_PATH_SIZE) {
      sc_error(card->ctx, "Application path is too long.\n");
      free(app);
      return SC_ERROR_INVALID_ASN1_OBJECT;
    }
    memcpy(app->path.value, path, path_len);
    app->path.len = path_len;
    app->path.type = SC_PATH_TYPE_PATH;
  }
  else if (aid_len < sizeof(app->path.value)) {
    memcpy(app->path.value, aid, aid_len);
    app->path.len = aid_len;
    app->path.type = SC_PATH_TYPE_DF_NAME;
  }
  else
    app->path.len = 0;
  if (asn1_dirrecord[3].flags & SC_ASN1_PRESENT) {
    app->ddo = (u8 *)malloc(ddo_len);
    if (app->ddo == NULL) {
      free(app);
      return SC_ERROR_OUT_OF_MEMORY;
    }
    memcpy(app->ddo, ddo, ddo_len);
    app->ddo_len = ddo_len;
  }
  else {
    app->ddo = NULL;
    app->ddo_len = 0;
  }
  ae = find_app_entry(aid, aid_len);
  if (ae != NULL)
    app->desc = ae->desc;
  else
    app->desc = NULL;
  app->rec_nr = rec_nr;
  card->app[card->app_count] = app;
  card->app_count++;

  return 0;
}

int sc_enum_apps(sc_card_t *card)
{
  sc_path_t path;
  int ef_structure;
  size_t file_size;
  int r;
  /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
  int i;
  scconf_block *conf_block = NULL, **blocks;
  struct sc_pkcs15_card *p15card = NULL;


  for (i = 0; card->ctx->conf_blocks[i] != NULL; i++) {
    blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i], "framework", "pkcs15");
    if (blocks && blocks[0] != NULL) {
      conf_block = blocks[0];
    }
    free(blocks);
  }

  p15card = sc_pkcs15_card_new();
  if (p15card == NULL) {
    return SC_ERROR_OUT_OF_MEMORY;
  }
  p15card->card = card;
  // p15card->opts.use_cache = scconf_get_bool(conf_block, "use_caching", 0);
  // BPER Pour la mise a jour des cartes CPS, paramétrer la désactivation du cache
  p15card->opts.use_cache = card->ctx->use_cache;
  /* CLCO 06/07/2010 : Fin  */

  if (card->app_count < 0) {
    card->app_count = 0;
  }
  sc_format_path("3F002F00", &path);
  if (card->ef_dir != NULL) {
    sc_file_free(card->ef_dir);
    card->ef_dir = NULL;
  }
  sc_ctx_suppress_errors_on(card->ctx);
  /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
  r = sc_select_cached_file(card, &path, &card->ef_dir, p15card->opts.use_cache);
  /* CLCO 06/07/2010 : Fin  */
  sc_ctx_suppress_errors_off(card->ctx);
  if (r) {
    return r;
  }
  if (card->ef_dir->type != SC_FILE_TYPE_WORKING_EF) {
    sc_debug(card->ctx, "EF(DIR) is not a working EF.\n");
    sc_file_free(card->ef_dir);
    card->ef_dir = NULL;
    return SC_ERROR_INVALID_CARD;
  }
  ef_structure = card->ef_dir->ef_structure;
  file_size = card->ef_dir->size;
  if (file_size == 0) {
    return 0;
  }
  if (ef_structure == SC_FILE_EF_TRANSPARENT) {
    u8 *buf = NULL, *p;
    size_t bufsize = file_size;

    /* CLCO 06/07/2010 : Gestion du cache des instructions cartes liées au chargement de la structure PKCS#15  */
    r = -1; /* file state: not in cache */
    if (p15card->opts.use_cache) {
      r = sc_pkcs15_read_cached_file(p15card, &path, &buf, &bufsize);
    }
    p = buf;
    if (r) {
      bufsize = file_size;

      buf = (u8 *)malloc(file_size);
      if (buf == NULL) {
        return SC_ERROR_OUT_OF_MEMORY;
      }


      /* AROC - (@@20130927-0001102) - Debut */
      /* Re select the file */
      r = sc_select_cached_file(card, &path, &card->ef_dir, 0);
      sc_ctx_suppress_errors_off(card->ctx);
      if (r) {
        free(buf);
        return r;
      }
      r = sc_read_binary(card, 0, buf, file_size, 0);
      if (r < 0) {
        free(buf);
        SC_TEST_RET(card->ctx, r, "sc_read_binary() failed");
      }
      bufsize = r;
      p = buf;
      if (p15card->opts.use_cache && buf && file_size) {
        r = sc_pkcs15_cache_file(p15card, &path, buf, file_size);
      }
    }

    while (bufsize > 0) {
      if (card->app_count == SC_MAX_CARD_APPS) {
        sc_error(card->ctx, "Too many applications on card");
        break;
      }
      r = parse_dir_record(card, &p, &bufsize, -1);
      if (r) { break; }
    }
    if (buf) {
      free(buf);
    }

  }
  else {  /* record structure */
    u8 buf[256], *p;
    unsigned int rec_nr;
    size_t       rec_size;

    for (rec_nr = 1; ; rec_nr++) {
      sc_ctx_suppress_errors_on(card->ctx);
      r = sc_read_record(card, rec_nr, buf, sizeof(buf), SC_RECORD_BY_REC_NR);
      sc_ctx_suppress_errors_off(card->ctx);
      if (r == SC_ERROR_RECORD_NOT_FOUND) {
        break;
      }
      SC_TEST_RET(card->ctx, r, "read_record() failed");
      if (card->app_count == SC_MAX_CARD_APPS) {
        sc_error(card->ctx, "Too many applications on card");
        break;
      }
      rec_size = r;
      p = buf;
      parse_dir_record(card, &p, &rec_size, (int)rec_nr);
    }
  }
  if (p15card != NULL) {
    p15card->card = NULL;
    sc_pkcs15_card_free(p15card);
  }
  return card->app_count;
}

void sc_free_apps(sc_card_t *card)
{
  int  i;

  for (i = 0; i < card->app_count; i++) {
    if (card->app[i]->label)
      free(card->app[i]->label);
    if (card->app[i]->ddo)
      free(card->app[i]->ddo);
    free(card->app[i]);
  }
  card->app_count = -1;
}

const sc_app_info_t * sc_find_app_by_aid(sc_card_t *card, const u8 *aid, size_t aid_len)
{
  int i;

  assert(card->app_count > 0);
  for (i = 0; i < card->app_count; i++) {
    if (card->app[i]->aid_len == aid_len &&
      memcmp(card->app[i]->aid, aid, aid_len) == 0)
      return card->app[i];
  }
  return NULL;
}

