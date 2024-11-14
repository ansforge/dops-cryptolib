/*
 * cards.h: Registered card types for sc_card_t->type
 *
 * Copyright (C) 2005  Antti Tapaninen <aet@cc.hut.fi>
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

#ifndef _OPENSC_CARDS_H
#define _OPENSC_CARDS_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  /* Generic card types */
  SC_CARD_TYPE_UNKNOWN = -1,
  SC_CARD_TYPE_GENERIC_BASE = 0,
  SC_CARD_TYPE_GENERIC,

  /* Cards without registered type, yet */
  SC_CARD_TYPE_TEST_BASE = 500,

  /* IAS cards */
  SC_CARD_TYPE_IAS_BASE = 22000,
  SC_CARD_TYPE_IAS_CPS3,
  SC_CARD_TYPE_IAS_CPS3_CL,
  SC_CARD_TYPE_IAS_CPS4,
/*
CLCO 12/04/2010 : Fin.
*/
};

#define IS_CARD_TYPE_CPS3(type) ((type == SC_CARD_TYPE_IAS_CPS3) || (type ==SC_CARD_TYPE_IAS_CPS3_CL))

// CPSv4 Algo id
#define CPSV4_ALG_RSA_SHA_ISO9796        0x09 // Not implemented
#define CPSV4_ALG_RSA_SHA_PKCS1          0x0A
#define CPSV4_ALG_RSA_SHA_PKCS1_PSS      0x15
#define CPSV4_ALG_RSA_SHA_ISO9796_MR     0x1E // Not implemented
#define CPSV4_ALG_RSA_SHA_224_PKCS1      0x27 // Not implemented
#define CPSV4_ALG_RSA_SHA_256_PKCS1      0x28 
#define CPSV4_ALG_RSA_SHA_384_PKCS1      0x29 // Not implemented
#define CPSV4_ALG_RSA_SHA_512_PKCS1      0x2A // Not implemented
#define CPSV4_ALG_RSA_SHA_224_PKCS1_PSS  0x2B // Not implemented
#define CPSV4_ALG_RSA_SHA_256_PKCS1_PSS  0x2C
#define CPSV4_ALG_RSA_SHA_384_PKCS1_PSS  0x2D // Not implemented
#define CPSV4_ALG_RSA_SHA_512_PKCS1_PSS  0x2E // Not implemented

extern sc_card_driver_t* sc_get_cps3_driver(void);
extern sc_card_driver_t* sc_get_cps4_driver(void);

#ifdef __cplusplus
}
#endif

#endif /* _OPENSC_CARDS_H */
