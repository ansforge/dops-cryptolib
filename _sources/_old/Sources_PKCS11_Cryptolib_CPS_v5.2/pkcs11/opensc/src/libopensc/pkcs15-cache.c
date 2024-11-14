/*
 * pkcs15-cache.c: PKCS #15 file caching functions
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
#include "sysdef.h"
#include "encdec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>

#define SHA256_LENGTH 32

extern int sc_get_card_cached_files(const char *_path, const char *serialNumber, char ***cached_files, int* size);

#define TYPE_FILE_DATA              0x01
#define TYPE_SELECT_DATA            0x02

const char FILE_DATA_FORMAT[]       = "%s%s_%s";
const char SELECT_DATA_FORMAT[]     = "%s%s_s_%s";
const char FILE_DATA_FORMAT_UP[]    = "%s%s_%s_%s";
const char SELECT_DATA_FORMAT_UP[]  = "%s%s_%s_s_%s";

#define CACHE_FORMAT(type) type == TYPE_FILE_DATA ? FILE_DATA_FORMAT : SELECT_DATA_FORMAT
#define CACHE_FORMAT_UP(type) type == TYPE_FILE_DATA ? FILE_DATA_FORMAT_UP : SELECT_DATA_FORMAT_UP




static int gen_cache_file(sc_card_t *card, const sc_path_t *path, char *buf, size_t bufsize, unsigned char type, char * lastUpdate)
{
  char dir[PATH_MAX];
  char pathname[SC_MAX_PATH_SIZE * 2 + 1];
  int  r;
  const u8 *pathptr;
  size_t i, pathlen;
  scconf_block *conf_block = NULL;
  const char * no_cache_file_list;


  if ((path->type != SC_PATH_TYPE_PATH) && (path->type != SC_PATH_TYPE_CPS2TER)) {
    return SC_ERROR_INVALID_ARGUMENTS;
  }

  assert(path->len <= SC_MAX_PATH_SIZE);
  r = sc_get_cache_dir(card->ctx, dir, sizeof(dir));
  if (r) {
    return r;
  }

  pathptr = path->value;
  pathlen = path->len;
  if (pathlen > 2 && memcmp(pathptr, "\x3F\x00", 2) == 0) {
    pathptr += 2;
    pathlen -= 2;
  }

  for (i = 0; i < pathlen; i++) {
    sprintf(pathname + 2 * i, "%02X", pathptr[i]);
  }

  conf_block = sc_get_conf_block(card->ctx, "card_driver", card->driver->short_name, 1);

  no_cache_file_list = scconf_get_str(conf_block, "no_cache_file_list", "");
  if (strstr(no_cache_file_list, pathname)) {
    return SC_ERROR_INVALID_ARGUMENTS;
  }

  if (card->serialnr.len != 0) {
    if (lastUpdate != NULL) {
      r = snprintf(buf, bufsize, CACHE_FORMAT_UP(type), dir, card->serialnr.value, lastUpdate, pathname);
    }
    else {
      r = snprintf(buf, bufsize, CACHE_FORMAT(type), dir, card->serialnr.value, pathname);
    }
    if (r < 0) {
      return SC_ERROR_BUFFER_TOO_SMALL;
    }
  }
  else {
    return SC_ERROR_INVALID_ARGUMENTS;
  }

  return SC_SUCCESS;
}

static int generate_cache_filename(struct sc_pkcs15_card *p15card, const sc_path_t *path, char *buf, size_t bufsize)
{
  return gen_cache_file(p15card->card, path, buf, bufsize, TYPE_FILE_DATA, p15card->last_update);
}


int sc_pkcs15_read_cached_file(struct sc_pkcs15_card *p15card, const sc_path_t *path, u8 **buf, size_t *bufsize)
{
  char fname[PATH_MAX];
  int r;
  FILE *f;
  size_t count, offset, got;
  size_t control_data_len;
  u8 *dec_data = NULL;
  struct stat stbuf;
  u8 *data = NULL;

  r = generate_cache_filename(p15card, path, fname, sizeof(fname));
  if (r != 0) {
    return r;
  }
  r = stat(fname, &stbuf);
  if (r || !stbuf.st_size) {
    return SC_ERROR_FILE_NOT_FOUND;
  }

  control_data_len = strlen(fname);

  if (path->count < 0) {
    count = stbuf.st_size;
    offset = 0;
  }
  else {
    count = path->count + control_data_len;
    offset = path->index;
    if (offset + count > (size_t)stbuf.st_size) {
      return SC_ERROR_FILE_NOT_FOUND; /* cache file bad? */
    }
  }

  data = (u8 *)malloc((size_t)stbuf.st_size);
  if (data == NULL) {
    return SC_ERROR_OUT_OF_MEMORY;
  }

  if (*buf && *bufsize && count - control_data_len - SHA256_LENGTH - strlen(p15card->card->driver->short_name) > *bufsize) {
    free(data);
    return SC_ERROR_BUFFER_TOO_SMALL;
  }

  if (p15card->card->ctx->debug >= 7) {
    sc_debug(p15card->card->ctx, "read cache file %s\n", fname);
  }

  f = fopen(fname, "rb");
  if (f == NULL) {
    free(data);
    return SC_ERROR_FILE_NOT_FOUND;
  }

  if (offset) {
    fseek(f, (long)offset, SEEK_SET);
  }

  got = fread(data, 1, count, f);
  fclose(f);
  if (got != count) {
    free(data);
    return SC_ERROR_BUFFER_TOO_SMALL;
  }

  opensc_decrypt(p15card->card, data, &dec_data, &count, (u8*)fname, (int)control_data_len);
  if (!dec_data) {
    free(data);
    if (p15card->card->ctx->debug >= 7)
      sc_error(p15card->card->ctx, "probably corrupted cache file %s\n", fname);
    return SC_ERROR_FILE_NOT_FOUND;
  }
  else {
    free(data);
    if (*buf) { free(*buf); }
    *buf = dec_data;
  }
  *bufsize = count;
  return 0;
}

int sc_pkcs15_cache_file(struct sc_pkcs15_card *p15card, const sc_path_t *path, const u8 *buf, size_t bufsize)
{
  char fname[PATH_MAX];
  int r;
  FILE *f;
  size_t c;
  u8 *enc_data = NULL;

  size_t control_data_len;

#if !defined(_WIN32)
  mode_t save_mode;
#endif
  r = generate_cache_filename(p15card, path, fname, sizeof(fname));
  if (r != 0) {
    return r;
  }

  control_data_len = strlen(fname);

  if (p15card->card->ctx->debug >= 7) {
    sc_debug(p15card->card->ctx, "set cache file %s\n", fname);
  }

#if !defined(_WIN32)
  save_mode = umask(0);
#endif
  f = fopen(fname, "wb");
#if !defined(_WIN32)
  umask(save_mode);
#endif

  /* If the open failed because the cache directory does
   * not exist, create it and a re-try the fopen() call.
   */
  if (f == NULL && errno == ENOENT) {
    if ((r = sc_make_cache_dir(p15card->card->ctx)) < 0) {
      return r;
    }
#if !defined(_WIN32)
    save_mode = umask(0);
#endif
    f = fopen(fname, "wb");
#if !defined(_WIN32)
    umask(save_mode);
#endif
  }
  if (f == NULL) {
    return 0;
  }

  opensc_encrypt(p15card->card, (u8 *)buf, &enc_data, &bufsize, (u8*)fname, (int)control_data_len);
  if (!enc_data) {
    fclose(f);
    return SC_ERROR_INTERNAL;
  }

  c = fwrite(enc_data, 1, bufsize, f);
  free(enc_data);
  fclose(f);

  if (c != bufsize) {
    sc_error(p15card->card->ctx, "fwrite() wrote only %d bytes", c);
    unlink(fname);
    return SC_ERROR_INTERNAL;
  }
  return 0;
}

static int generate_select_cache_filename(sc_card_t *card, const sc_path_t *path, char *buf, size_t bufsize)
{
   return  gen_cache_file(card, path, buf, bufsize, TYPE_SELECT_DATA, NULL);
}

int sc_pkcs15_read_cached_select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **fileout)
{
  char fname[PATH_MAX];
  int r;
  FILE *f;
  size_t count, offset, got;
  struct stat stbuf;
  u8 *data = NULL;
  sc_file_t *file;
  u8 *dec_data = NULL;
  u8 *p;
  int i;
  size_t control_data_len;

  r = generate_select_cache_filename(card, path, fname, sizeof(fname));
  if (r != 0) {
    return r;
  }

  r = stat(fname, &stbuf);
  if (r || !stbuf.st_size) {
    return SC_ERROR_FILE_NOT_FOUND;
  }

  control_data_len = strlen(fname);

  if (path->count < 0) {
    count = stbuf.st_size;
    offset = 0;
  }
  else {
    count = path->count + control_data_len + SHA256_LENGTH + strlen(card->driver->short_name);
    offset = path->index;
    if (offset + count > (size_t)stbuf.st_size) {
      return SC_ERROR_FILE_NOT_FOUND; /* cache file bad? */
    }
  }
  data = (u8 *)malloc((size_t)stbuf.st_size);
  if (data == NULL) {
    return SC_ERROR_OUT_OF_MEMORY;
  }

  /* CLCO 16/07/2010 : ajout de traces */
  if (card->ctx->debug >= 7)
    sc_debug(card->ctx, "read select cache file %s\n", fname);
  /* CLCO 16/07/2010 : fin */

  f = fopen(fname, "rb");
  if (f == NULL) {
    free(data);
    sc_debug(card->ctx, "file not found %s\n", fname);
    return SC_ERROR_FILE_NOT_FOUND;
  }
  if (offset) {
    fseek(f, (long)offset, SEEK_SET);
  }

  got = fread(data, 1, count, f);
  fclose(f);
  if (got != count) {
    free(data);
    sc_debug(card->ctx, "Buffer too small %s\n", fname);
    return SC_ERROR_BUFFER_TOO_SMALL;
  }
  /* CLCO 26/07/2010 : gestion des données de contrôle du fichier */
  /* AROC 07/03/2011 : la methode systeme encrypt existe sous MACOSX, encrypt devient opensc_encrypt */
  /*                   et donc par convention decrypt devient opensc_decrypt                         */
  opensc_decrypt(card, data,&dec_data, &count, (u8*)fname, (int)control_data_len);
  free(data);
  /* CLCO 26/07/2010 : fin */
  if (!dec_data) {
    sc_error(card->ctx, "corrupted cache file %s\n", fname);
    return SC_ERROR_FILE_NOT_FOUND;
  }
  file = sc_file_new();
  p = dec_data;
  memcpy((u8*)file, p, sizeof(sc_file_t));

  /* CLCO 26/07/2010 : vérifier la validité du cache */
  if (file->magic != SC_FILE_MAGIC) {
    free(dec_data);
    sc_debug(card->ctx, "Bad magic code %s\n", fname);
    return SC_ERROR_FILE_NOT_FOUND;
  }
  /* CLCO 26/07/2010 : fin */

  p += sizeof(sc_file_t);
  for (i = 0; i < SC_MAX_AC_OPS; i++) {
    if (file->acl[i]) {
      struct sc_acl_entry *next;
      file->acl[i] = malloc(sizeof(struct sc_acl_entry));
      memcpy((u8*)file->acl[i], p, sizeof(struct sc_acl_entry));
      p += sizeof(struct sc_acl_entry);
      for (next = file->acl[i]->next; next; next = next->next) {
        next = malloc(sizeof(struct sc_acl_entry));
        memcpy((u8*)next, p, sizeof(struct sc_acl_entry));
        p += sizeof(struct sc_acl_entry);
      }
    }
  }
  if (file->sec_attr) {
    file->sec_attr = malloc(file->sec_attr_len);
    if (file->sec_attr != NULL) {
      memcpy((u8*)file->sec_attr, p, file->sec_attr_len);
      p += file->sec_attr_len;
    }
  }
  if (file->prop_attr) {
    file->prop_attr = malloc(file->prop_attr_len);
    if (file->prop_attr != NULL) {
      memcpy((u8*)file->prop_attr, p, file->prop_attr_len);
      p += file->prop_attr_len;
    }
  }
  if (file->type_attr) {
    file->type_attr = malloc(file->type_attr_len);
    if (file->type_attr != NULL) {
      memcpy((u8*)file->type_attr, p, file->type_attr_len);
      p += file->type_attr_len;
    }
  }
  free(dec_data);
  *fileout = file;
  return 0;
}

int sc_pkcs15_select_cache_file(sc_card_t *card, const sc_path_t *path, sc_file_t *file)
{
  char fname[PATH_MAX];
  int r;
  FILE *f;
  size_t c;
  u8 *enc_data = NULL;
  u8 *buf;
  u8 *p;
  size_t bufsize;
  int i;
  /* CLCO 26/07/2010 : gestion des données de contrôle du fichier */
  size_t control_data_len;
  /* CLCO 26/07/2010 : fin */
  /* AROC 09/03/2011 : Positionner les droits en ecriture et en lecture à l'ensemble des utilisateur*/
#if !defined(_WIN32)
  mode_t save_mode;
#endif

  r = generate_select_cache_filename(card, path, fname, sizeof(fname));
  if (r != 0) {
    return r;
  }

  /* CLCO 26/07/2010 : gestion des données de contrôle du fichier */
  control_data_len = strlen(fname);
  /* CLCO 26/07/2010 : fin */

  /* CLCO 16/07/2010 : ajout de traces */
  if (card->ctx->debug >= 7) {
    sc_debug(card->ctx, "set select cache file %s\n", fname);
  }
  /* CLCO 16/07/2010 : fin */

#if !defined(_WIN32)
  save_mode = umask(0);
#endif
  f = fopen(fname, "wb");
#if !defined(_WIN32)
  umask(save_mode);
#endif
  /* If the open failed because the cache directory does
   * not exist, create it and a re-try the fopen() call.
   */
   /* AROC 13/08/2015 : Ne pas remonter d'erreur si le dossier de cache ne peut �tre cr��(@@20150813-0001199) - Debut */
  if (f == NULL && errno == ENOENT) {
    if ((r = sc_make_cache_dir(card->ctx)) < 0) {
      return 0;
    }
    /* AROC 13/08/2015 : Ne pas remonter d'erreur si le dossier de cache ne peut �tre cr��(@@20150813-0001199) - Fin */
#if !defined(_WIN32)
    save_mode = umask(0);
#endif
    f = fopen(fname, "wb");
#if !defined(_WIN32)
    umask(save_mode);
#endif
  }
  if (f == NULL) {
    return 0;
  }

  bufsize = sizeof(sc_file_t);
  for (i = 0; i < SC_MAX_AC_OPS; i++) {
    if (file->acl[i]) {
      struct sc_acl_entry *next;
      bufsize += sizeof(struct sc_acl_entry);
      for (next = file->acl[i]->next; next; next = next->next) {
        bufsize += sizeof(struct sc_acl_entry);
      }
    }
  }
  if (file->sec_attr)
    bufsize += file->sec_attr_len;
  if (file->prop_attr)
    bufsize += file->prop_attr_len;
  if (file->type_attr)
    bufsize += file->type_attr_len;

  buf = malloc(bufsize);
  p = buf;
  memcpy(p, (u8*)file, sizeof(sc_file_t));
  p += sizeof(sc_file_t);
  for (i = 0; i < SC_MAX_AC_OPS; i++) {
    if (file->acl[i]) {
      struct sc_acl_entry *next;
      memcpy(p, (u8*)file->acl[i], sizeof(struct sc_acl_entry));
      p += sizeof(struct sc_acl_entry);
      for (next = file->acl[i]->next; next; next = next->next) {
        memcpy(p, (u8*)next, sizeof(struct sc_acl_entry));
        p += sizeof(struct sc_acl_entry);
      }
    }
  }
  if (file->sec_attr) {
    memcpy(p, (u8*)file->sec_attr, file->sec_attr_len);
    p += file->sec_attr_len;
  }
  if (file->prop_attr) {
    memcpy(p, (u8*)file->prop_attr, file->prop_attr_len);
    p += file->prop_attr_len;
  }
  if (file->type_attr) {
    memcpy(p, (u8*)file->type_attr, file->type_attr_len);
    p += file->type_attr_len;
  }

  /* CLCO 26/07/2010 : gestion des données de contrôle du fichier */
  opensc_encrypt(card, buf,&enc_data, &bufsize, (u8*)fname, (int)control_data_len);
  /* CLCO 26/07/2010 : fin */
  if (!enc_data) {
    fclose(f);
    free(buf);
    return SC_ERROR_INTERNAL;
  }
  /* CLCO 26/07/2010 : gestion des données de contrôle du fichier */
  c = fwrite(enc_data, 1, bufsize, f);
  /* CLCO 26/07/2010 : fin */
  fclose(f);
  free(enc_data);
  free(buf);
  /* CLCO 26/07/2010 : gestion des données de contrôle du fichier */
  if (c != bufsize/*+control_data_len*/) {
    /* CLCO 26/07/2010 : fin */
    sc_error(card->ctx, "fwrite() wrote only %d bytes", c);
    unlink(fname);
    return SC_ERROR_INTERNAL;
  }
  return 0;
}
/* CLCO 05/07/2010 : fin */


/* MCUG 14/09/2010 : Fonction de suppression d'un fichier de cache */
int sc_pkcs15_delete_cached_file(struct sc_pkcs15_card *p15card)
{
  char dir[PATH_MAX];
  char dirStr[PATH_MAX];
  struct stat stbuf;
  int r;
  char **cached_files = NULL;
  int size;
  int i;

  r = sc_get_cache_dir(p15card->card->ctx, dirStr, sizeof(dir));
  if (r) {
    return r;
  }

  r = sc_get_card_cached_files((const char*)dirStr, (const char*)p15card->card->serialnr.value, &cached_files, &size);
  if (r == 0) {

    // Loop over the cache files and remove them one by one
    for (i = 0; i < size; i++) {
      r = stat(cached_files[i], &stbuf);
      if (r == 0) {
        r = remove(cached_files[i]);
        if (r != 0 && p15card->card->ctx->debug >= 7) {
          sc_debug(p15card->card->ctx, "removed cache file %s failed\n", cached_files[i]);
        }
        else {
          sc_debug(p15card->card->ctx, "removed cache file %s succeed\n", cached_files[i]);
        }
        if (cached_files[i] != NULL) { free(cached_files[i]); }
      }
    }
  }
  if (cached_files != NULL) { free(cached_files); }

  return 0;
}
/* MCUG 14/09/2010 : fin */
