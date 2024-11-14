#include "stdafx.h"
#include <windows.h>
#include <process.h>
#include <winbase.h>
#include <wincrypt.h>
#include <time.h>

#include "testsystem.h"

#include "testsysdef.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>


#include "openssl/pkcs12.h"
#include <openssl/err.h>
#include <openssl/rand.h>


#include "pkcs11.h"

/*************************************************************

  VARIABLES
  
*************************************************************/
#define NO_TRACE      0
#define TRACE_INFO    1
#define TRACE_DEBUG   2
#define TRACE_MAX     3

extern int traceLevel;

/*************************************************************

  FONCTIONS
  
*************************************************************/
#define CK_API      STDCALL
typedef void *      SYS_HANDLE;
#ifdef _WIN64
typedef INT_PTR ( CK_API *CK_PFUNCTION)();
#else
typedef int ( CK_API *CK_PFUNCTION)();
#endif
SYS_HANDLE               LoadDynLibrary( CK_CHAR_PTR pLibraryName);
CK_PFUNCTION CK_API      GetFunctionPtr( SYS_HANDLE dllInst,CK_CHAR_PTR pFunctionName);

/* GetFunctionPtr()
* Retourne l'adresse d'une fonction d'une librairie
*/
CK_PFUNCTION CK_API GetFunctionPtr( SYS_HANDLE dllInst,CK_CHAR_PTR pFunctionName)
{
  return( GetProcAddress( (HINSTANCE)dllInst,(LPCSTR)pFunctionName));
}

/* LoadDynLibrary()
* Chargement dynamique d'une librairie
*/
SYS_HANDLE  LoadDynLibrary( CK_CHAR_PTR pLibraryName)
{
  SYS_HANDLE      lSysHandle;
  FILE        *   ptrFile = NULL;
  DWORD rc32;
  lSysHandle = LoadLibrary( (LPCSTR)pLibraryName);
  
  
  if ( lSysHandle == NULL)
  {
    char szTool[512];
    rc32=GetLastError();
    sprintf( szTool,"%s: rc=%u:", pLibraryName, rc32);
    FormatMessage( FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL,
      rc32,
      MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT),
      szTool+strlen( szTool),
      sizeof( szTool) - strlen( szTool),
      NULL);
    
    if (pLibraryName[0]=='\"') {
      char szLibraryName[512];
      strcpy(szLibraryName,(char *)pLibraryName+1);
      if ( szLibraryName[strlen(szLibraryName)-1] == '\"')
        szLibraryName[strlen(szLibraryName)-1]=0;
      lSysHandle = LoadLibrary( szLibraryName);
      
      if ( lSysHandle == NULL)
      {
        
        char szTool[512];
        rc32=GetLastError();
        sprintf( szTool,"%s: rc=%u:", szLibraryName, rc32);
        FormatMessage( FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
          NULL,
          rc32,
          MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT),
          szTool+strlen( szTool),
          sizeof( szTool) - strlen( szTool),
          NULL);
        
        
        
        
          /* %v1.0.0.F DREN le 07/05/2003: si il y a des doubles \, on les
        retire pour Me (et sans doute Win 98) */
        char *  ptmp=NULL;
        
        if ( (ptmp=strstr( szLibraryName, "\\\\")) != NULL)
        {
          while ( ptmp != NULL)
          {
            *ptmp = '\0';
            strcat( szLibraryName, ptmp+1);
            ptmp=strstr( szLibraryName, "\\\\");
          }
          
          lSysHandle = LoadLibrary( szLibraryName);
          
          
          if ( lSysHandle == NULL)
          {
            char szTool[512];
            rc32=GetLastError();
            sprintf( szTool,"%s: rc=%u:", szLibraryName, rc32);
            FormatMessage( FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
              NULL,
              rc32,
              MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT),
              szTool+strlen( szTool),
              sizeof( szTool) - strlen( szTool),
              NULL);
          }
        }
      }
    }
  }
  return( lSysHandle);
}


DWORD WINAPI threadFunction(LPVOID IpvThreadParam)
{
	int randomNumber;
	BOOL infinite=TRUE;
	CK_RV rv;
  CK_CHAR_PTR pinCode = (CK_CHAR_PTR)IpvThreadParam;
	srand( (unsigned)time( NULL ) );
	randomNumber=(rand()%1000);
	Sleep(randomNumber);
	rv=testAll(pinCode);
	if(rv!=CKR_OK)
		printf( "Erreur du thread %x\n", GetCurrentThreadId() );
	printf( "Fin du thread %x : \n", GetCurrentThreadId() );
	return rv;
}

CK_RV launchThreads(CK_ULONG nbThread, CK_CHAR_PTR pin) {
	CK_RV rv= CKR_OK;	
  HANDLE * hThreads;
	DWORD dwThreadParam=1;
	DWORD dwThreadId;
	CK_ULONG i;
	hThreads=(HANDLE *)malloc(nbThread * sizeof(HANDLE));
	if (hThreads==NULL)
		return CKR_HOST_MEMORY;

	for(i=0;i<nbThread;i++) {
		hThreads[i]=CreateThread(NULL,0, threadFunction,(void *)pin,0,&dwThreadId);
	}
	WaitForMultipleObjects(nbThread,hThreads,TRUE,INFINITE);
	for(i=0;i<nbThread;i++)
	{
		CK_RV thread_rv=CKR_OK;
		GetExitCodeThread(hThreads[i], &thread_rv);
		if (thread_rv!=CKR_OK)
			rv=thread_rv;
		CloseHandle(hThreads[i]);
	}
	free(hThreads);
	return rv;
}

void sys_ExecuteCommand(char * cmd)
{
  char correctCmd[256];
  sprintf(correctCmd, "CMD.EXE /C \"%s\"", cmd);
  WinExec(correctCmd, SW_HIDE);
  Sleep(3000);
}

char * sys_GetAllUsersDir( )
{
  char * pEnv;
  pEnv = getenv("ALLUSERSPROFILE");
  DWORD dwVersion = GetVersion();
  DWORD  dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
  
  if (pEnv == NULL || dwMajorVersion == 5)
  {
    pEnv = "C:\\Documents and Settings\\All Users\\Application Data";
  }
  return pEnv;
}

int sys_renameFile(char * fileName)
{
  char newFileName[128];
  int rc;
  strcpy(newFileName, fileName);
  strcat(newFileName, "_OK");
  rc = remove(newFileName);

  Sleep(600);
  rc = rename(fileName, newFileName);
  if(rc == -1)
  {
    DWORD dwError=GetLastError();
    printf("sys_renameFile > dwError = %d\n", dwError);
  }
  return rc;
}

#include <sys/types.h>
#include <sys/stat.h>

#define OK 0
#define KO 1
#define trace_line printf

int IOReadFile(char * fileName, unsigned char ** ppData, size_t * pulDataLen) {
	struct _stat bufstat;
	FILE * phFile = NULL;
	int rc;

	if(ppData == NULL || pulDataLen == NULL)
		return KO;

	rc = _stat(fileName, &bufstat);

	if(rc == OK) {
		trace_line("%s %ld\n", fileName, bufstat.st_size);

		phFile = fopen(fileName, "rb");

		if(phFile == NULL)
			return KO;

		*ppData = (unsigned char *)malloc(bufstat.st_size * sizeof(unsigned char));

		if(*ppData == NULL) {
			fclose(phFile);
			return KO;
		}
		fread(*ppData, 1, bufstat.st_size, phFile);
		*pulDataLen = bufstat.st_size;
	}
	else {
		rc = errno;
		switch(errno) {
		case ENOENT :
			trace_line("file not exists.\n");
			break;
		case EINVAL :
			trace_line("bad argument.\n");
			break;
		default:;
		}
	}
  if(phFile)
    rc = fclose(phFile);
	return rc;
}

int IOWriteFile(char * fileName, unsigned char * pData, size_t  ulDataLen) {
	
	FILE * phFile = NULL;
	int rc = OK;
	size_t sWritten;

	if(fileName == NULL || pData == NULL || ulDataLen == 0)
		rc = KO;

	if(rc == OK) {
		trace_line("%s %ld\n", fileName, ulDataLen);

		phFile = fopen(fileName, "wb");

		if(phFile == NULL)
			return KO;

		sWritten = fwrite(pData, 1, ulDataLen, phFile);

		if(sWritten != ulDataLen) {
			trace_line("Writing data non correct %lu, %lu\n", sWritten, ulDataLen);
			rc = KO;
		}

		fclose(phFile);
		 
	}

	return rc;
}

/* Sous Visual 2015, redeclarer les prototypes suivants non décorés C++ */
#if _MSC_VER >= 1900
extern "C" int _vsnprintf(char *buffer,
  size_t count,
  const char *format,
  va_list argptr);

extern "C" int vfprintf(FILE *stream,
  const char *format,
  va_list argptr);
#endif
