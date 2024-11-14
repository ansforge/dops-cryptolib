#include "testsysdef.h"
#include "testsystem.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "pkcs11.h"
#include <dlfcn.h>
#include <unistd.h>




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
#define CK_API STDCALL
typedef void *      SYS_HANDLE;
typedef int ( CK_API *CK_PFUNCTION)();

//extern void traceInFile(CK_ULONG level, CK_CHAR_PTR msg);

/* GetFunctionPtr()
* Retourne l'adresse d'une fonction d'une librairie
*/
CK_PFUNCTION CK_API GetFunctionPtr( SYS_HANDLE dllInst,CK_CHAR_PTR pFunctionName)
{
	CK_PFUNCTION CK_API pFunc;
	
	pFunc = (CK_PFUNCTION CK_API)dlsym(dllInst, (char *)pFunctionName);
	
	return pFunc;
}

/* LoadDynLibrary()
* Chargement dynamique d'une librairie
*/
SYS_HANDLE  LoadDynLibrary( CK_CHAR_PTR pLibraryName)
{
	int		dl_flags = 0;
	void *	h;
	
	dl_flags |= RTLD_LAZY;
	dl_flags |= RTLD_LOCAL;
	
	h = dlopen((char *)pLibraryName, dl_flags);
	if (h == NULL) {
	 printf ("\n!!! La librairie %s n'a pas pu etre chargee !!!\n\n",(char *)pLibraryName);
	 CK_CHAR buf[1024]={0};
	 sprintf((char *)buf,"Loading library error : %s",dlerror());
	 //traceInFile(TRACE_INFO, buf);
	}
	 

	return (SYS_HANDLE)h;
}


void *my_thread_process (void * arg)
{
	int randomNumber;
	srand( (unsigned)time( NULL ) );
	CK_CHAR_PTR pin= (CK_CHAR_PTR) arg; 
	while(1)
	{
		if(!testAll(pin))
		{
			break;
		}
		printf( "Erreur du thread %x\n", GetCurrentThreadId() );
		randomNumber=(rand()%1000);
		usleep(randomNumber * 1000);
	}
	printf( "Fin du thread %x : \n", GetCurrentThreadId() );
  pthread_exit (0);
	return 0;
}

CK_RV launchThreads(CK_ULONG nbThread, CK_CHAR_PTR pin) {
	CK_RV rv= CKR_OK;	
  pthread_t * hThreads;
	CK_ULONG i;

	hThreads=(pthread_t *)malloc(nbThread * sizeof(pthread_t));
	if (hThreads==NULL)
		return CKR_HOST_MEMORY;

	for(i=0;i<nbThread;i++) {
		pthread_t th;
		if (pthread_create (&th, NULL, my_thread_process, (void*)pin) < 0)
			 return CKR_FUNCTION_FAILED;
		hThreads[i]=th;
	}
	
	for(i=0;i<nbThread;i++)
	{
		void *ret;
		(void)pthread_join(hThreads[i],	&ret);
	}
	free(hThreads);
	return rv;
}

void sys_ExecuteCommand(char * cmd)
{
  char correctCmd[128];
  strcpy(correctCmd, cmd);
  system(correctCmd);
  usleep(3 * 1000);
}

#include <sys/stat.h>

extern int errno;

#define OK 0
#define KO 1
#define trace_line printf

int IOReadFile(char * fileName, unsigned char ** ppData, size_t * pulDataLen) {
	struct stat bufstat;
	FILE * phFile = NULL;
	int rc;

	if(ppData == NULL || pulDataLen == NULL)
		return KO;

	rc = stat(fileName, &bufstat);

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

int IOWriteFile(char * fileName, unsigned char * ppData, size_t  ulDataLen) {
	
	FILE * phFile = NULL;
	int rc = OK;
	size_t sWritten;

	if(fileName == NULL || ppData == NULL || ulDataLen == 0)
		rc = KO;

	if(rc == OK) {
		trace_line("%s %u\n", fileName, ulDataLen);

		phFile = fopen(fileName, "wb");

		if(phFile == NULL)
			return KO;

		sWritten = fwrite(ppData, 1, ulDataLen, phFile);

		if(sWritten != ulDataLen) {
			trace_line("Writing data non correct %u, %u\n", sWritten, ulDataLen);
			rc = KO;
		}

		fclose(phFile);
		 
	}

	return rc;
}
