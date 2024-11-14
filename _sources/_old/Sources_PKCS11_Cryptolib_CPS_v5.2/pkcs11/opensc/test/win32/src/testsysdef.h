/*---------------------------------------------------------------------------
 PROJET     : Couche de portabilite multi-systeme
 
 PLATE-FORME: WIN32
 
 MODULE     : CryptoLib CPS3, implementee sous forme de DLL
              Ce fichier est implemente differemment pour chaque 
              plate forme.

 FICHIER    : cps3\win32\src\cpscps.h

 DATE       : 10/06/10
 
 AUTEUR     : ASIP
 
-----------------------------------------------------------------------------
-----------------------------------------------------------------------------
 Modifications:  (nouvelle version, date, auteur, explication)

V1.00 - 2010/06/10 - Claude CONVERT - Version officielle initiale

 ...
-----------------------------------------------------------------------------
---------------------------------------------------------------------------*/

#ifndef __CPS3W32_H
#define __CPS3W32_H

/* partie specifique a windows 32 bits */
#include "stdafx.h"
#include <windows.h>

//#include "win32def.h"
#ifdef _WIN64
static char                    dllNameCPS3[256]="cps3_pkcs11_w64.dll";
#else
static char                    dllNameCPS3[256]="cps3_pkcs11_w32.dll";
#endif
static char                    dllNameCPS2TerPCSC[256]="cps_pkcs11_pcsc_w32.dll";
static char                    dllNameCPS2TerGALSS[256]="cps_pkcs11_w32.dll";

#ifndef STDCALL 
#define STDCALL __stdcall 
#endif 

#endif


