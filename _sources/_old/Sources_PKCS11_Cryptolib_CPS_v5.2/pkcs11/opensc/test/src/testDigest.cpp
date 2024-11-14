#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "testconstants.h"

#define MAX_DIGEST     128
#define DATA_TO_DIGEST  "document_to_sign"
#define DATA2_TO_DIGEST "VICTOR    1007141750163220748"

extern sTESTS_MSGS     MsgsTbl[];
extern CK_BBOOL isCPS2TerGALSS;
extern CK_BBOOL isCPS2TerPCSC;

extern char *getErrorCodeString(CK_RV error, char * strError);
extern int ConsigneResultatCSV(unsigned short __usTestNumero, unsigned long usRc, unsigned long usExpectedRc, char * libelle);
extern unsigned short getIndexDebutSectionTests(int searchedTestLevel);
extern void testSetMechanism(int testLevel, int keySpec, CK_RV expectedRv, CK_MECHANISM_PTR pMechanism);
extern void checkPrintResult(char * mesgTest, CK_RV rv, int testNumber, sTESTS_MSGS * table);
extern void testSetData(int testLevel, int keySpec, CK_RV expectedRv, CK_BYTE_PTR * ppData, CK_ULONG_PTR pulDataLen);
extern void testFreeData(CK_BYTE_PTR * ppData, CK_ULONG_PTR pulDataLen);
extern void showBytes(unsigned char * byData, size_t sData);

void CPSGES_CondenseMessage_1455_01(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_CHAR_PTR pMessage, CK_ULONG ulMessageLen, int * pTestNumber);
void CPSGES_CondenseMessage_1455_03(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_CHAR_PTR pMessage, CK_ULONG ulMessageLen, int * pTestNumber);
void CPSGES_CondenseMessage_1455_04(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_CHAR_PTR pMessage, CK_ULONG ulMessageLen, int * pTestNumber);
void CPSGES_CondenseMessage_1455_05(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_CHAR_PTR pMessage, CK_ULONG ulMessageLen, int * pTestNumber);

//*******************************************************************
//Effectue les tests de digest
//*******************************************************************
void testDigestManagementFunctions(CK_FUNCTION_LIST *pFunctionList)
{
  int testNumber = getIndexDebutSectionTests(MDIGEST_FUNCTIONS);
  CK_RV rv;
  CK_SESSION_HANDLE sessionRO = 0xFFFFFFFF;
  CK_MECHANISM testDigestMecha;

  CK_BYTE_PTR pDigest;
  CK_ULONG ulDigestLen;

  // C_DigestInit et librairie non initialisée
  rv = (*pFunctionList->C_DigestInit)(sessionRO, &testDigestMecha);

  checkPrintResult("C_DigestInit et librairie non initialis" E_AIGUE "e", rv, testNumber, MsgsTbl);


  // C_Digest et librairie non initialisée
  testNumber++;
  rv = (*pFunctionList->C_Digest)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16, NULL_PTR, &ulDigestLen);

  checkPrintResult("C_Digest et librairie non initialis" E_AIGUE "e", rv, testNumber, MsgsTbl);

  rv = (*pFunctionList->C_Initialize)(NULL);
  if (rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
  {
    CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
    CK_ULONG ulSlotsListSize = MAX_SLOTS;
    //recupération de la liste des slots avec carte
    rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
    if (rv != CKR_OK || ulSlotsListSize == 0) return;

    currentSlotID = tabSlots[0];

    // Handle de session invalide
    testNumber++;
    rv = (*pFunctionList->C_DigestInit)(sessionRO, &testDigestMecha);

    checkPrintResult("C_DigestInit avec handle de session invalide", rv, testNumber, MsgsTbl);



    //ouverture d'une session en lecture seule sur le premier slot
    rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
    if (rv != CKR_OK) {
      (*pFunctionList->C_Finalize)(NULL);
      return;
    }

    // C_DigestInit et paramètres corrects
    testNumber++;
    // Positionner un mécanisme de hash (SHA1)
    testSetMechanism(MDIGEST_FUNCTIONS, SHA1, MsgsTbl[testNumber].usExpectedRc, &testDigestMecha);
    rv = (*pFunctionList->C_DigestInit)(sessionRO, &testDigestMecha);

    checkPrintResult("C_DigestInit et param" E_GRAVE "tres corrects", rv, testNumber, MsgsTbl);

    // C_Digest et paramètres corrects
    testNumber++;
    // Positionner un mécanisme de hash
    testSetMechanism(MDIGEST_FUNCTIONS, 0, MsgsTbl[testNumber].usExpectedRc, &testDigestMecha);
    rv = (*pFunctionList->C_Digest)(sessionRO, (unsigned char *)DATA_TO_DIGEST, strlen(DATA_TO_DIGEST), NULL, &ulDigestLen);

    checkPrintResult("C_Digest et param" E_GRAVE "tres corrects (taille hash)", rv, testNumber, MsgsTbl);

    pDigest = (CK_BYTE_PTR)malloc(ulDigestLen * sizeof(CK_BYTE));
    // C_Digest et paramètres corrects
    testNumber++;
    // Positionner un mécanisme de hash
    //testSetMechanism(MDIGEST_FUNCTIONS, 0, MsgsTbl[testNumber].usExpectedRc, &testDigestMecha);
    rv = (*pFunctionList->C_Digest)(sessionRO, (unsigned char *)DATA_TO_DIGEST, strlen(DATA_TO_DIGEST), pDigest, &ulDigestLen);

    checkPrintResult("C_Digest et param" E_GRAVE "tres corrects (Valeur hash)", rv, testNumber, MsgsTbl);
    showBytes(pDigest, ulDigestLen);

    free(pDigest);

    // C_DigestInit et paramètres corrects
    testNumber++;
    // Positionner un mécanisme de hash (SHA256)
    testSetMechanism(MDIGEST_FUNCTIONS, SHA256, MsgsTbl[testNumber].usExpectedRc, &testDigestMecha);
    if (!isCPS3) {
      // si on n'est pas en CPS3, le mecanisme SHA_256 n est pas supporte
      MsgsTbl[testNumber].usExpectedRc = CKR_MECHANISM_PARAM_INVALID;
    }
    rv = (*pFunctionList->C_DigestInit)(sessionRO, &testDigestMecha);

    checkPrintResult("C_DigestInit et param" E_GRAVE "tres corrects", rv, testNumber, MsgsTbl);

    if (isCPS3) {
      // C_DigestUpdate et paramètres corrects
      testNumber++;
      // Positionner un mécanisme de hash (SHA256)
      rv = (*pFunctionList->C_DigestUpdate)(sessionRO, (CK_BYTE_PTR)DATA2_TO_DIGEST, strlen(DATA2_TO_DIGEST));

      checkPrintResult("C_DigestUpdate et param" E_GRAVE "tres corrects", rv, testNumber, MsgsTbl);

      // C_DigestFinal et paramètres corrects (taille du hash)
      testNumber++;
      rv = (*pFunctionList->C_DigestFinal)(sessionRO, NULL, &ulDigestLen);

      checkPrintResult("C_DigestFinal et param" E_GRAVE "tres corrects (taille condensat)", rv, testNumber, MsgsTbl);

      pDigest = (CK_BYTE_PTR)malloc(ulDigestLen * sizeof(CK_BYTE));

      if (pDigest == NULL_PTR) {
        printf("Host memory error when allocating...\n");
        return;
      }

      // C_Digest et paramètres corrects
      testNumber++;
      rv = (*pFunctionList->C_DigestFinal)(sessionRO, pDigest, &ulDigestLen);

      checkPrintResult("C_DigestFinal et param" E_GRAVE "tres corrects (Valeur du condensat)", rv, testNumber, MsgsTbl);
      showBytes(pDigest, ulDigestLen);

      free(pDigest);
    }

    CPSGES_CondenseMessage_1455_01(pFunctionList, sessionRO, CKM_SHA_1, (CK_CHAR_PTR)DATA_TO_DIGEST, (CK_ULONG)strlen(DATA_TO_DIGEST), &testNumber);
    CPSGES_CondenseMessage_1455_03(pFunctionList, sessionRO, CKM_SHA_1, (CK_CHAR_PTR)DATA_TO_DIGEST, (CK_ULONG)strlen(DATA_TO_DIGEST), &testNumber);
    CPSGES_CondenseMessage_1455_04(pFunctionList, sessionRO, CKM_SHA_1, (CK_CHAR_PTR)DATA_TO_DIGEST, (CK_ULONG)strlen(DATA_TO_DIGEST), &testNumber);
    CPSGES_CondenseMessage_1455_05(pFunctionList, sessionRO, CKM_SHA_1, (CK_CHAR_PTR)DATA_TO_DIGEST, (CK_ULONG)strlen(DATA_TO_DIGEST), &testNumber);

    rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

  }

}

void CPSGES_CondenseMessage_1455_01(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_CHAR_PTR pMessage, CK_ULONG ulMessageLen, int * pTestNumber)
{
  CK_RV rv;
  CK_MECHANISM Meca;
  CK_ULONG ulDigestLen = 0;
  CK_BYTE_PTR  pDigest = NULL;

  if (pMessage == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    return;
  }

  printf("\nCPSGES_CondenseMessage_1455_01: '%s'\n", pMessage);

  Meca.mechanism = mtype;
  (*pTestNumber)++;
  rv = (*pFunctionList->C_DigestInit)(hSession, &Meca);
  checkPrintResult("C_DigestInit et param" E_GRAVE "tres corrects", rv, *pTestNumber, MsgsTbl);
  if (rv != CKR_OK) {
    printf("C_DigestInit failed:  rv = %lx\n", rv);
    return;
  }

  (*pTestNumber)++;
  rv = (*pFunctionList->C_Digest)(hSession, pMessage, ulMessageLen, pDigest, &ulDigestLen);
  checkPrintResult("C_Digest et taille du condensat", rv, *pTestNumber, MsgsTbl);
  if (rv != CKR_OK) {
    printf("C_Digest failed (size query) :  rv = %lx", rv);
    return;
  }

  pDigest = (CK_BYTE_PTR)malloc(ulDigestLen);

  if (pDigest == NULL_PTR) {
    printf("Host memory error when allocating...\n");
    return;
  }

  (*pTestNumber)++;
  rv = (*pFunctionList->C_DigestFinal)(hSession, pDigest, &ulDigestLen);

  checkPrintResult("C_DigestFinal et valeur du condensat", rv, *pTestNumber, MsgsTbl);

  if (rv != CKR_OK) {
    printf("C_DigestFinal failed (actual digest) :  rv = %lx", rv);
    return;
  }

  showBytes(pDigest, ulDigestLen);

  free(pDigest);
}

void CPSGES_CondenseMessage_1455_03(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_CHAR_PTR pMessage, CK_ULONG ulMessageLen, int * pTestNumber)
{
  CK_RV rv;
  CK_MECHANISM Meca;
  CK_BYTE bufCondensat[MAX_DIGEST];
  CK_ULONG LgCondensat = MAX_DIGEST;

  if (pMessage == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    return;
  }

  printf("\nCPSGES_CondenseMessage_1455_03: %s\n", pMessage);

  Meca.mechanism = mtype;
  (*pTestNumber)++;
  rv = (*pFunctionList->C_DigestInit)(hSession, &Meca);
  checkPrintResult("C_DigestInit et param" E_GRAVE "tres corrects", rv, *pTestNumber, MsgsTbl);
  if (rv != CKR_OK) {
    printf("C_DigestInit failed:  rv = %lx\n", rv);
    return;
  }

  (*pTestNumber)++;
  rv = (*pFunctionList->C_DigestUpdate)(hSession, pMessage, ulMessageLen);
  checkPrintResult("C_DigestUpdate et param" E_GRAVE "tres corrects", rv, *pTestNumber, MsgsTbl);
  if (rv != CKR_OK) {
    printf("C_DigestUpdate failed (feeding data) :  rv = %lx", rv);
    return;
  }

  (*pTestNumber)++;
  rv = (*pFunctionList->C_DigestFinal)(hSession, bufCondensat, &LgCondensat);
  checkPrintResult("C_DigestFinal et buffer allou" E_AIGUE, rv, *pTestNumber, MsgsTbl);
  if (rv != CKR_OK) {
    printf("C_DigestFinal failed (with buffer ready) :  rv = %lx", rv);
    return;
  }

  showBytes(bufCondensat, LgCondensat);

}

void CPSGES_CondenseMessage_1455_04(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_CHAR_PTR pMessage, CK_ULONG ulMessageLen, int * pTestNumber)
{
  CK_RV rv;
  CK_MECHANISM Meca;
  CK_BYTE bufCondensat[MAX_DIGEST];
  CK_ULONG LgCondensat = MAX_DIGEST;

  if (pMessage == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    return;
  }

  printf("\nCPSGES_CondenseMessage_1455_04: %s\n", pMessage);

  Meca.mechanism = mtype;
  (*pTestNumber)++;
  rv = (*pFunctionList->C_DigestInit)(hSession, &Meca);
  checkPrintResult("C_DigestInit et param" E_GRAVE "tres corrects", rv, *pTestNumber, MsgsTbl);
  if (rv != CKR_OK) {
    printf("C_DigestInit failed:  rv = %lx\n", rv);
    return;
  }

  (*pTestNumber)++;
  rv = (*pFunctionList->C_Digest)(hSession, pMessage, ulMessageLen, bufCondensat, &LgCondensat);
  checkPrintResult("C_Digest et buffer allou" E_AIGUE, rv, *pTestNumber, MsgsTbl);
  if (rv != CKR_OK) {
    printf("C_Digest failed (with buffer ready) :  rv = %lx", rv);
    return;
  }
  showBytes(bufCondensat, LgCondensat);
}

void CPSGES_CondenseMessage_1455_05(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_CHAR_PTR pMessage, CK_ULONG ulMessageLen, int * pTestNumber)
{
  CK_RV rv;
  CK_MECHANISM Meca;
  CK_BYTE bufCondensat[MAX_DIGEST];
  CK_ULONG LgCondensat;

  if (pMessage == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    return;
  }

  printf("\nCPSGES_CondenseMessage_1455_05: %s\n", pMessage);
  if (mtype == CKM_SHA_1) {
    LgCondensat = (CK_ULONG)(0x14 - 0x02);
  }

  if (mtype == CKM_SHA256) {
    LgCondensat = (CK_ULONG)(0x20 - 0x02);
  }
  Meca.mechanism = mtype;
  (*pTestNumber)++;
  rv = (*pFunctionList->C_DigestInit)(hSession, &Meca);
  checkPrintResult("C_DigestInit et param" E_GRAVE "tres corrects", rv, *pTestNumber, MsgsTbl);
  if (rv != CKR_OK) {
    printf("C_DigestInit failed:  rv = %lx\n", rv);
    return;
  }

  (*pTestNumber)++;
  rv = (*pFunctionList->C_Digest)(hSession, pMessage, ulMessageLen, bufCondensat, &LgCondensat);
  checkPrintResult("C_Digest et buffer de taille insuffisante", rv, *pTestNumber, MsgsTbl);

}