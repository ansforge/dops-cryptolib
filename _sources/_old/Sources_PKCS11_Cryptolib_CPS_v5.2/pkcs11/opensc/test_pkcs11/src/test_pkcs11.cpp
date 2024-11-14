
#include "StdAfx.h"
#include "testsysdef.h"
#include <stdio.h>
#include "pkcs11.h"

typedef void* SYS_HANDLE;
#define CK_API      STDCALL
typedef void *      SYS_HANDLE;
#ifdef _WIN64
typedef INT_PTR(CK_API *CK_PFUNCTION)();
#else
typedef int (CK_API *CK_PFUNCTION)();
#endif

void testSignatureBigData(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, char * filePath, size_t block_size);
BOOL IOExistsFile(char * fileName);

SYS_HANDLE               LoadDynLibrary(CK_CHAR_PTR pLibraryName);
CK_PFUNCTION CK_API      GetFunctionPtr(SYS_HANDLE dllInst, CK_CHAR_PTR pFunctionName);

int _tmain(int argc, _TCHAR * argv[])
{
  CK_ULONG i;
  CK_FUNCTION_LIST *pFunctionList = NULL_PTR;
  CK_CHAR dllName[256];
  size_t block_size;

  CK_CHAR pin[8] = { 0 };
  char filePath[260] = { 0 };
  char bs[64] = { 0 };

  for (i = 0; i < (CK_ULONG)argc; i++) {

    if (strcmp(argv[i], "/c") == 0) {
      if (argv[i + 1] != NULL) {
        strcpy((char *)pin, argv[i + 1]);
      }
    }
    if (strcmp(argv[i], "/f") == 0) {
      if (argv[i + 1] != NULL) {
        strcpy((char *)filePath, argv[i + 1]);
      }
    }

    if (strcmp(argv[i], "/bs") == 0) {
      if (argv[i + 1] != NULL) {
        strcpy((char *)bs, argv[i + 1]);
      }
    }
  }

  strcpy((char *)dllName, dllNameCPS3);

  SYS_HANDLE dllInst = (SYS_HANDLE)LoadDynLibrary((CK_CHAR_PTR)dllName);
  if (dllInst == NULL)
  {
    printf("\n!!! La librairie %s n'a pas pu etre chargee !!!\n", dllName);
    return 1;
  }
  printf("\nLa librairie %s a ete chargee\n", dllName);

  CK_C_GetFunctionList pC_GetFunctionList = (CK_C_GetFunctionList)GetFunctionPtr(dllInst, (CK_CHAR_PTR)"C_GetFunctionList");
  if (pC_GetFunctionList == NULL) {
    printf("\n!!! L'entree C_GetFunctionList est introuvable !!!\n");
    return 2;
  }

  CK_RV rv = pC_GetFunctionList(&pFunctionList);
  if (rv != CKR_OK) {
    printf("\n!!! Erreur sur l'appel de C_GetFunctionList rv=0x%08x !!!\n", (unsigned int)rv);
    return (int)rv;
  }

  /*printf("Saisissez votre code porteur (1234 par defaut): ");
  gets( (char *)pin );*/

  if (pin[0] == 0) {
    strcpy((char *)pin, "1234");
  }

  if (bs[0] == 0) {
    block_size = 0xF0000000;
  }
  else {
    block_size = (size_t)atol(bs);
    if (block_size < 1024) {
      block_size = 1024;
    }
  }

 
  if (filePath[0] == 0) {
    printf("Le fichier a signer est requis !\n");
    return 1;
  }


  if (!IOExistsFile(filePath)) {
    printf("Le fichier n'existe pas !\n");
    return 1;
  }

  testSignatureBigData(pFunctionList, pin, filePath, block_size);

  return 0;
}

unsigned char testAll(CK_BYTE_PTR data) {
  return NULL;
}


#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

BOOL IOExistsFile(char * fileName) {
  struct _stati64 bufstat;
  int rc;

  if (fileName == NULL || !strcmp(fileName, ""))
    return FALSE;

  rc = _stati64(fileName, &bufstat);
  if (rc == 0) {
    printf("Taille du fichier : %llu\n", bufstat.st_size);
    return TRUE;
  }
  else {
    printf("\t_stati64():  errno = %d\n", errno);
    if (errno == EACCES) {
      printf("\tEACCES\n");
      return TRUE;
    }
    else if (errno == ENOENT) {
      printf("\tENOENT\n");
    }
    else if (errno == EEXIST) {
      printf("\tEEXIST\n");
    }

  }

  return FALSE;
}