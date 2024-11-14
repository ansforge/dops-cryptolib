/*
 * pkcs11-extend.c: PKCS#11 extended functions
 *
 * Copyright (C) 2010-2018, ASIP Santé
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

#ifndef PKCS11_EXTEND_H
#define PKCS11_EXTEND_H 1

#include "pkcs11.h"
#if defined(__cplusplus)
extern "C" {
#endif

/* System dependencies.  */
#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
  #pragma pack(push, cryptoki, 1)
#endif


  CK_RV IC_StartUpdate(CK_SESSION_HANDLE hSession);
  CK_RV IC_EndUpdate(CK_SESSION_HANDLE hSession);
  CK_RV IC_KeepAlive(CK_SESSION_HANDLE hSession);
  CK_RV IC_TransmitMessage(CK_SESSION_HANDLE hSession,
    unsigned char *pbMessage,
    unsigned long  szMessage,
    unsigned char *pbResponse,
    unsigned long *pszResponse,
    unsigned char  cInsType);

/* System dependencies.  */
#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#pragma pack(pop, cryptoki)
#endif

#if defined(__cplusplus)
}
#endif

#endif  /* PKCS11_EXTEND_H */
