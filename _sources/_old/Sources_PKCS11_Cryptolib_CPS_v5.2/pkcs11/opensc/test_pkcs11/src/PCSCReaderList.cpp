// PCSCReaderList.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <winscard.h>
#ifndef UNDER_CE
#include <conio.h>
#else
#define printf_s printf
#endif

#ifdef UNICODE
#define LPSTRING    LPWSTR
#define LPCSTRING   LPCWSTR
#else
#define LPSTRING    LPSTR
#define LPCSTRING   LPCSTR
#endif

void SCard_Dbg_DumpMultiStringA(LPSTR IN pBuffer, DWORD IN nbEntries)
{
  LPSTR szInfo;
  DWORD index;

  if (pBuffer == NULL) return;

  printf_s("\nReader :");
  szInfo = pBuffer;
  for ( index = 0; index < nbEntries; index++ )
  {
      if ( 0 == *szInfo  || strlen(szInfo) > 256)
          break;
      printf_s("\n\t%s", szInfo);
      szInfo += strlen(szInfo) + 1;
  }
}
void SCard_Dbg_DumpMultiStringW(LPWSTR IN pBuffer, DWORD IN nbEntries)
{
  LPWSTR  swzInfo;
  char    Info[256];
  DWORD  index;

  if (pBuffer == NULL) return;

  printf_s("\nReader :");
  swzInfo = pBuffer;
  for ( index = 0; index < nbEntries; index++ )
  {
      if ( 0 == *swzInfo || wcslen(swzInfo)> 256)
          break;
      wcstombs(Info, swzInfo , 256 );
      printf_s("\n\t%s", Info);
      swzInfo += wcslen(swzInfo) + 1;
  }
}
#ifdef UNICODE
#define SCard_DumpMultiString SCard_Dbg_DumpMultiStringW
#else
#define SCard_DumpMultiString SCard_Dbg_DumpMultiStringA
#endif

#define PCSC_CFG_FILE  "lecteurs_pcsc.cfg"

typedef struct READERENTRY{
	unsigned char ReaderName[MAX_PATH];
	unsigned char ResourceName[8+1];
}READERENTRY,*LPREADERENTRY;

LONG GetReadersList(unsigned char ** pstrReaders)
{
  LONG rc=SCARD_S_SUCCESS;
	SCARDCONTEXT context;
	LPSTR pReaders = NULL;
	LPSTR pReadersTmp = NULL;
	DWORD  dwReaders = 0, index = 0;
	LPREADERENTRY pReaderEntry = NULL;

  rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM,NULL,NULL,&context);
  if (rc != SCARD_S_SUCCESS) return rc;

	rc = SCardListReaders(context, NULL, NULL, &dwReaders );
  if (rc != SCARD_S_SUCCESS) { SCardReleaseContext(context); return rc;}

	pReaders = (LPSTR)calloc(dwReaders, sizeof(TCHAR));
	if (pReaders == NULL){ SCardReleaseContext(context); return SCARD_E_NO_MEMORY;}

	rc = SCardListReaders(context, NULL, pReaders, &dwReaders );
  if (rc != SCARD_S_SUCCESS) { SCardReleaseContext(context); return rc;}

	dwReaders = 0;
	pReadersTmp = pReaders;
	while(pReadersTmp[0] != 0){
		pReadersTmp = pReadersTmp + strlen(pReadersTmp) + 1;
		dwReaders+=1;
	}
	
	pReaderEntry = (LPREADERENTRY)calloc(dwReaders, sizeof(READERENTRY));
	if (pReaderEntry == NULL){ free(pReaders); SCardReleaseContext(context); return SCARD_E_NO_MEMORY;}


	pReadersTmp = pReaders;
	while(pReadersTmp[0] != 0){
		strcpy((char*)pReaderEntry[index].ReaderName, pReadersTmp);
		pReadersTmp = pReadersTmp + strlen(pReadersTmp) + 1;
	}

	free(pReaders);
	free(pReaderEntry);
	rc = SCardReleaseContext(context);
	return rc;

}
bool GetCfgFilePath(PCHAR pFilePath, UINT16 szSize)
{
	UINT rc;
	if( (szSize == 0) || (pFilePath == NULL) ) return FALSE;
	rc = GetSystemWindowsDirectory(pFilePath, szSize);
	if ( (rc > szSize) || (rc == 0) ) return FALSE;

	strcat(pFilePath, "\\");
	strcat(pFilePath, PCSC_CFG_FILE);

	return TRUE;
}

void RemoveLineFeed(PCHAR pString)
{
	UINT16 index;
	if (pString == NULL) return;

	for (index = 0; index < strlen(pString); index ++){
		if ( (pString[index] == '\r') || (pString[index] == '\n')) pString[index] = 0x00;
	}
}

void GetCfgReaders(LPREADERENTRY * pCfgReaders)
{
	FILE * pCfgFile = NULL;
	CHAR   cFilePath[MAX_PATH];
	CHAR   lines[50][MAX_PATH];
	UINT16 index1 = 0, index2 = 0, count = 0;

	LPREADERENTRY pEntries = NULL;

	if (pCfgReaders !=NULL)
		*pCfgReaders = (LPREADERENTRY)-1;
	// Get configuration file name.
	if (!GetCfgFilePath(cFilePath, MAX_PATH)) return;


	// Try to open...
	if ( (pCfgFile = fopen( cFilePath, "r+")) != NULL) {
		// Read Lines...
		while(fgets(lines[index1], MAX_PATH, pCfgFile)){
			//Clear Line feeds
			RemoveLineFeed(lines[index1]);
			// Validate lines.
			if ( (lines[index1][0] != 0x00) && 
					 (lines[index1][0] != ';')  && 
					 (lines[index1][8] == '-') ) 
				count++;
			index1++;
		}

		pEntries = (LPREADERENTRY)calloc(count, sizeof(READERENTRY));
		for(index2=0, count=0; index2<index1; index2++){
			if ( (lines[index2][0] == 0x00) || (lines[index2][0] == ';') || (lines[index2][8] != '-') ) 
				continue;
			else {
				strncpy((PCHAR)pEntries[count].ResourceName, lines[index2], 8);
				strcpy((PCHAR)pEntries[count].ReaderName, lines[index2]+9);
				count++;
			}
		}
	}
}

#ifdef __NOTDEF
int _tmain(int argc, _TCHAR* argv[])
{
  LONG          rc;
  SCARDCONTEXT  context;
  SCARDHANDLE   hCard;
  DWORD         dwAP;
  LPSTRING      pAutoAllocReaders = NULL;
  DWORD         szAutoAllocReaders = SCARD_AUTOALLOCATE;
  LPSTRING      pReader;

	//GetReadersList(NULL);
	//GetCfgReaders(NULL);
  rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM,NULL,NULL,&context);
  if (rc != SCARD_S_SUCCESS) return 0;


  rc = SCardListReaders(context, SCARD_DEFAULT_READERS, (LPSTRING)&pAutoAllocReaders, &szAutoAllocReaders );
  if (rc != SCARD_S_SUCCESS && szAutoAllocReaders == 0) { SCardReleaseContext(context); return 0;}


  pReader = pAutoAllocReaders;
  if (pReader == NULL){
    printf_s("\n\tNo reader Connected.");
    goto end;
  }
	for (DWORD index = 0; 0 != *pReader; index++ ){
    SCard_DumpMultiString(pReader, 1);
		rc = SCardConnect(context,pReader,SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwAP);
    if (rc != SCARD_S_SUCCESS) {
      if (rc == SCARD_W_REMOVED_CARD){
        printf_s("\n\tNo card found on the reader.");
       pReader += lstrlen(pReader) + 1; 
       continue;
      }
      printf_s("\n\tTrying to establish a connection : FAILD with error 0x%08x", rc);
      pReader += lstrlen(pReader) + 1; 
      continue;
    }
    printf_s("\n\tCard found on the reader.");
    printf_s("\n\t - Trying to establish a connection : OK");
    
		//printf_s("\n\nAppuyez sur une touche pour continuer(AVANT BEGIN TRANSACTION)...");
    //_getch();

    rc = SCardBeginTransaction(hCard);
    //rc = SCardBeginTransaction(hCard);
    if (rc != SCARD_S_SUCCESS) { 
      printf_s("\nTrying to begining a transaction : FAILD with error 0x%08x", rc);
      _getch();
      pReader += lstrlen(pReader) + 1; 
			SCardDisconnect(hCard, SCARD_LEAVE_CARD);
      continue;
    }
    printf_s("\n\t - Trying to begining a transaction : OK");
		SCardDisconnect(hCard, SCARD_LEAVE_CARD);
		rc = SCardConnect(context,pReader,SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwAP);

		//printf_s("\n\nAppuyez sur une touche pour continuer...");
    //_getch();
    rc = SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
		//printf_s("\nEnd transaction : 0x%08x", rc);
    SCardDisconnect(hCard, SCARD_LEAVE_CARD);
    pReader += lstrlen(pReader) + 1;
  }
	//}while(true);

  SCardReleaseContext(context);
end:
  printf_s("\n\nAppuyez sur une touche pour terminer...");
  _getch();
  return 0;
}

#endif __NOTDEF
#ifndef __NOTDEF
int _tmain(int argc, _TCHAR* argv[])
{
  LONG          rc;
  SCARDCONTEXT  context;
  SCARDHANDLE   hCard;
  DWORD         dwAP;
  LPSTRING      pAutoAllocReaders = NULL;
  DWORD         szAutoAllocReaders = SCARD_AUTOALLOCATE;
  LPSTRING      pReader;
  
  rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM,NULL,NULL,&context);
  if (rc != SCARD_S_SUCCESS) return 0;


  rc = SCardListReaders(context, NULL, (LPSTRING)&pAutoAllocReaders, &szAutoAllocReaders );
  if (rc != SCARD_S_SUCCESS && szAutoAllocReaders == 0) { SCardReleaseContext(context); return 0;}


  pReader = pAutoAllocReaders;
	SCARD_READERSTATE_A readerState;
	readerState.szReader = pReader;
	readerState.dwCurrentState = readerState.dwEventState = SCARD_STATE_UNAWARE;
	do{
    printf_s("\n\nWaiting....");
		rc = SCardGetStatusChangeA(context, INFINITE , &readerState, 1);
		if (rc != SCARD_S_SUCCESS){
			printf_s("\nSCardGetStatusChangeA, error (0x%08x)", rc); 
		}else{
			printf_s("\nPre State, (0x%08x)", readerState.dwCurrentState); 
			printf_s("\nNew State, (0x%08x)", readerState.dwEventState);
			readerState.dwCurrentState = readerState.dwEventState;
		}
	}while(rc == SCARD_S_SUCCESS);

  SCardReleaseContext(context);
  printf_s("\n\nAppuyez sur une touche pour terminer...");
  _getch();
  return 0;
}
#endif
#define CPS3_OpAppMgr "\x00\xA4\x04\x00\x07\xA0\x00\x00\x01\x51\x00\x00\x00"
#define CPS_OpAppCPS2 "\x00\xA4\x04\x00\x0D\xE8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x10\x00"
#ifdef __NOTDEF
int _tmain(int argc, _TCHAR* argv[])
{
 LONG          rc;
  SCARDCONTEXT  context;
  SCARDHANDLE   hCard;
  DWORD         dwAP;
  LPSTRING      pAutoAllocReaders = NULL;
  DWORD         szAutoAllocReaders = SCARD_AUTOALLOCATE;
  LPSTRING      pReader;
  char          ch = 'Y';
  BYTE          bRecvBuffer[256];
  DWORD         cbRecvLength = 0;

  rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM,NULL,NULL,&context);
  if (rc != SCARD_S_SUCCESS) return 0;


  rc = SCardListReaders(context, NULL, (LPSTRING)&pAutoAllocReaders, &szAutoAllocReaders );
  if (rc != SCARD_S_SUCCESS && szAutoAllocReaders == 0) { SCardReleaseContext(context); return 0;}


  pReader = pAutoAllocReaders;
	SCARD_READERSTATE_A readerState;
	readerState.szReader = pReader;
	readerState.dwCurrentState = readerState.dwEventState = SCARD_STATE_UNAWARE;
  do{
    rc = SCardGetStatusChangeA(context, 1 , &readerState, 1);
    if( (readerState.dwEventState & SCARD_STATE_PRESENT) == SCARD_STATE_PRESENT ){
      if (SCardConnect(context,readerState.szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &hCard,&dwAP) != SCARD_S_SUCCESS){
        printf_s("\n\nSCardConnect failed with error %d...", GetLastError());
        goto end2;
      }
      printf_s("\n\nAppuyez sur ENTREE pour selectionner l'Application Manager...");
      ch = _getch();
      rc = SCardBeginTransaction(hCard);
      memset(bRecvBuffer, 0,256); cbRecvLength=256;
      rc = SCardTransmit(hCard, SCARD_PCI_T0, (LPCBYTE)CPS3_OpAppMgr,sizeof(CPS3_OpAppMgr)-1, NULL,(LPBYTE)&bRecvBuffer,&cbRecvLength);
      rc = SCardEndTransaction(hCard, SCARD_LEAVE_CARD);

      /*
      printf_s("\n\nAppuyez sur ENTREE pour selectionner l'AID CPS2...");
      ch = _getch();
      SCardBeginTransaction(hCard);
      SCardTransmit(hCard, SCARD_PCI_T0, CPS_OpAppCPS2,sizeof(CPS3_OpAppMgr), NULL,(LPBYTE)&bRecvBuffer,&cbRecvLength);
      SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
      */

      printf_s("\n\nAppuyez sur la touche \"Q\" touche pour terminer...");
      ch = _getch();ch = toupper( ch );
    }
  }
  while(ch != 'Q');

  SCardDisconnect(hCard,SCARD_LEAVE_CARD);
end2:
  SCardReleaseContext(context);
  //printf_s("\n\nAppuyez sur une touche pour terminer...");
  //_getch();
  return 0;
}
#endif