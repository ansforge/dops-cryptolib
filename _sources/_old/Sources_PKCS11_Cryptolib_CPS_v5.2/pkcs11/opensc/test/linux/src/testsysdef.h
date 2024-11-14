/*---------------------------------------------------------------------------
 PROJET     : Couche de portabilite multi-systeme
 
 PLATE-FORME: LINUX
 
 MODULE     : CryptoLib CPS3, implementee sous forme de DLL
              Ce fichier est implemente differemment pour chaque 
              plate forme.

 FICHIER    : cps3\linux\src\cpscps.h

 DATE       : 10/06/10
 
 AUTEUR     : ASIP
 
-----------------------------------------------------------------------------
-----------------------------------------------------------------------------
 Modifications:  (nouvelle version, date, auteur, explication)

V1.00 - 2010/06/10 - Claude CONVERT - Version officielle initiale

 ...
-----------------------------------------------------------------------------
---------------------------------------------------------------------------*/

#ifndef __CPS3LINUX_H
#define __CPS3LINUX_H

/* partie specifique a linux 32 bits */
#ifndef __APPLE__
#else
#include "sysdef.h"
#endif // #ifndef __APPLE__

#include <pthread.h>
#include <unistd.h>
#define SYS_MAX_PATH 256


#ifndef __APPLE__
const char                    dllNameCPS3[256]="libcps3_pkcs11_lux.so";
const char                    dllNameCPS2TerPCSC[256]="libcps_pkcs11_pcsc_lux.so";
const char                    dllNameCPS2TerGALSS[256]="libcps_pkcs11_lux.so";
#else
const char                    dllNameCPS3[256]="/usr/local/lib/libcps3_pkcs11_osx.dylib";
const char                    dllNameCPS2TerPCSC[256]="libcps_pkcs11_pcsc_osx.dylib";
const char                    dllNameCPS2TerGALSS[256]="libcps_pkcs11_osx.dylib";
#endif // #ifndef __APPLE__

#define GetCurrentThreadId() pthread_self()
#ifndef STDCALL 
//#define STDCALL __attribute__((stdcall)) 
#define STDCALL  
#endif 

#ifndef Sleep
#define Sleep(x) usleep(1000*x)
#endif

#ifndef _stricmp
#define _stricmp strcasecmp
#endif

#endif
