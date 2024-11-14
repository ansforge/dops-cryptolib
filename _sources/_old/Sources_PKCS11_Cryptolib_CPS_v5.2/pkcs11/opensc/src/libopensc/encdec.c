/*
* encded.c : cipher functions
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
*/

#include <stdio.h>
#include "types.h"
#include "opensc.h"
#include <string.h>
#include <openssl/des.h>
#include <openssl/sha.h>

/* AROC 07/03/2011 : la methode systeme encrypt existe sous MACOSX, encrypt devient opensc_encrypt */
/*                   et donc par convention decrypt devient opensc_decrypt                         */
/* AROC - (@@20130927-0001102) - Debut */
#ifdef ENABLE_OPENSSL 
char * get_key(sc_card_t *card, unsigned char *hash) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, card->serialnr.value, card->serialnr.len);
  SHA256_Final(hash, &sha256);
  return (char *)hash;
}
char * get_hash(u8 *data, size_t datalen, unsigned char *hash) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, data, datalen);
  SHA256_Final(hash, &sha256);
  return (char *)hash;
}
#endif
void opensc_encrypt(sc_card_t *card, u8 *Msg, u8 **ppOut, size_t *size, u8 *control_data, int control_data_len)
{
#ifdef ENABLE_OPENSSL 
  u8*    Res;
  u8*    Msg2enc;
  int           n = 0;
  size_t        size2enc;
  DES_cblock      Key2;
  DES_key_schedule schedule;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned char hash_data[SHA256_DIGEST_LENGTH];
  const char   *pDrvName = NULL;
  size_t        szDrvName = 0;

  if (ppOut != NULL) {
    *ppOut = NULL;
  }

  /* insérer en début les données de contrôle pour permettre de détecter un mauvais déchiffrement */
  if (card->driver != NULL && card->driver->short_name != NULL) {
    pDrvName = card->driver->short_name;
    szDrvName = strlen(pDrvName);
  }

  size2enc = *size + control_data_len + SHA256_DIGEST_LENGTH + szDrvName;

  Msg2enc = (u8 *)calloc(size2enc, sizeof(u8));
  if (!Msg2enc) {
    return;
  }

  get_hash(Msg, *size, hash_data);
  memcpy(Msg2enc, control_data, control_data_len);
  memcpy(Msg2enc + control_data_len, pDrvName, szDrvName);
  memcpy(Msg2enc + control_data_len + szDrvName, hash_data, SHA256_DIGEST_LENGTH);
  memcpy(Msg2enc + control_data_len + szDrvName + SHA256_DIGEST_LENGTH, Msg, *size);

  /* Prepare the key for use with DES_cfb64_encrypt */
  memcpy(Key2, get_key(card, hash), 8);
  DES_set_odd_parity(&Key2);
  DES_set_key_checked(&Key2, &schedule);

  Res = (u8 *)calloc(size2enc, sizeof(u8));
  if (!Res) {
    free(Msg2enc);
    return;
  }

  /* Encryption occurs here */
  DES_cfb64_encrypt((u8 *)Msg2enc, (u8 *)Res, (long)size2enc, &schedule, &Key2, &n, DES_ENCRYPT);

  *size = size2enc;
  *ppOut = Res;
  free(Msg2enc);
  return;
#else
  return;
#endif
}

void opensc_decrypt(sc_card_t *card, u8 *Msg, u8 **ppOut, size_t *size, u8 *control_data, int control_data_len)
{
#ifdef ENABLE_OPENSSL 
  u8*           Res = NULL;
  u8*           Msg2dec = NULL;
  int           n = 0;
  size_t        size2dec;
  size_t        sizeres;

  DES_cblock      Key2;
  DES_key_schedule schedule;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned char hash_res[SHA256_DIGEST_LENGTH];
  const char   *pDrvName = NULL;
  size_t        szDrvName = 0;
  
  if (ppOut != NULL) {
    *ppOut = NULL;
  }

  if (card->driver != NULL && card->driver->short_name != NULL) {
    pDrvName = card->driver->short_name;
    szDrvName = strlen(pDrvName);
  }

  if ((int)*size <= control_data_len + szDrvName + SHA256_DIGEST_LENGTH) {
    return;
  }

  size2dec = *size;

  Msg2dec = (u8 *)calloc(size2dec, sizeof(u8));
  if (!Msg2dec) {
    return ;
  }
  /* Prepare the key for use with DES_cfb64_encrypt */
  memcpy(Key2, get_key(card, hash), 8);
  DES_set_odd_parity(&Key2);
  DES_set_key_checked(&Key2, &schedule);

  /* Decryption occurs here */
  DES_cfb64_encrypt((u8 *)Msg, (u8 *)Msg2dec, (long)size2dec, &schedule, &Key2, &n, DES_DECRYPT);

  /* vérifier si les données ne sont pas corrompues */
  if (strncmp((char*)Msg2dec, (char*)control_data, control_data_len)) {
    free(Msg2dec);
    return;
  }
  if (strncmp((char*)Msg2dec + control_data_len, (char*)pDrvName, szDrvName)) {
    free(Msg2dec);
    return;
  }

  sizeres = *size - control_data_len - szDrvName - SHA256_DIGEST_LENGTH;
  Res = (u8 *)calloc(sizeres, sizeof(u8));
  if (!Res) {
    free(Msg2dec);
    return;
  }

  memcpy(Res, Msg2dec + control_data_len + szDrvName + SHA256_DIGEST_LENGTH, sizeres);

  /* vérifier si les données ne sont pas corrompues */
  get_hash(Res, sizeres, hash_res);
  if (memcmp(hash_res, Msg2dec + control_data_len + szDrvName, SHA256_DIGEST_LENGTH)) {
    free(Msg2dec);
    free(Res);
    return;
  }

  free(Msg2dec);
  *size = sizeres;
  *ppOut = Res;
  return;
#else
  return;
#endif
}
/* AROC - (@@20130927-0001102) - Fin */
