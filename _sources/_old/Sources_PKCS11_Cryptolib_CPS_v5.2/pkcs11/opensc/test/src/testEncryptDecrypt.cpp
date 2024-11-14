#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "testconstants.h"

#define WINLOGON_DECRYPT "winlogonDecrypt"
#define DATA_TO_ENCRYPT "Message chiffre"

extern sTESTS_MSGS     MsgsTbl[];
extern CK_BBOOL isCPS3;


extern unsigned short getIndexDebutSectionTests(int searchedTestLevel);
extern int testGetPkcs11Object(CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, int testLevel, int keySpec, CK_CHAR * pin,CK_OBJECT_HANDLE_PTR phObject, int * pTestNumber);
extern void testSetMechanism(int testLevel, int keySpec, CK_RV expectedRv, CK_MECHANISM_PTR pMechanism);
extern void testChiffrementRSA_Openssl(CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, CK_OBJECT_HANDLE hPubKey, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR * ppEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
extern void checkPrintResult(char * mesgTest, CK_RV rv, int testNumber, sTESTS_MSGS * table);

//*******************************************************************
//Effectue les tests de chiffrement
//*******************************************************************
void testEncryptManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_BYTE_PTR * ppEncryptedData, CK_ULONG_PTR pulEncryptedDataLen, CK_CHAR_PTR pin)
{
  int testNumber = getIndexDebutSectionTests(ENCRYPT_FUNCTIONS);
  CK_RV rv;
  CK_SESSION_HANDLE sessionRO = 0xFFFFFFFF;
  CK_MECHANISM testMecha;
  unsigned long objCount = 0;
  CK_BYTE_PTR pData = (CK_BYTE_PTR)DATA_TO_ENCRYPT;
  const CK_ULONG ulDataLen = (CK_ULONG)strlen((const char *)pData);

  CK_OBJECT_HANDLE hPubKey = 0;

  rv = (*pFunctionList->C_Initialize)(NULL);
  if (rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
  {
    CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
    CK_ULONG ulSlotsListSize = MAX_SLOTS;
    const CK_ULONG dataLen = strlen((const char *)DATA_TO_ENCRYPT);
    //recupération de la liste des slots avec carte
    rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
    if (rv != CKR_OK || ulSlotsListSize == 0) return;

    currentSlotID = tabSlots[0];
    testNumber = getIndexDebutSectionTests(ENCRYPT_FUNCTIONS + 1);
    

    // Handle de session invalide
    rv = (*pFunctionList->C_EncryptInit)(sessionRO, &testMecha, hPubKey);
    checkPrintResult("C_EncryptInit avec handle de session invalide", rv, testNumber, MsgsTbl);


    //ouverture d'une session en lecture seule sur le premier slot
    rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
    if (rv != CKR_OK) {
      (*pFunctionList->C_Finalize)(NULL);
      return;
    }

    // Mauvais handle de clé
    testNumber++;
    CK_OBJECT_HANDLE hNewObject = 0;
    rv = (*pFunctionList->C_EncryptInit)(sessionRO, &testMecha, hNewObject);
    checkPrintResult("C_EncryptInit et mauvais handle de cl" E_AIGUE "", rv, testNumber, MsgsTbl);

    rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, (CK_CHAR_PTR)pin, 4);
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
      (*pFunctionList->C_Finalize)(NULL);
      return;
    }

    testGetPkcs11Object(pFunctionList, sessionRO, ENCRYPT_FUNCTIONS, AT_KEYEXCHANGE, pin, &hPubKey, NULL);

    // Mauvais mécanisme
    testNumber++;
    testSetMechanism(ENCRYPT_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
    rv = (*pFunctionList->C_EncryptInit)(sessionRO, &testMecha, hPubKey);
    checkPrintResult("C_EncryptInit avec mauvais m" E_AIGUE "canisme", rv, testNumber, MsgsTbl);


    testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, pin, &hNewObject, NULL);

    // Type de clé inconsistent avec le mécanisme choisi
    testNumber++;
    testMecha.mechanism = CKM_RSA_PKCS;
    rv = (*pFunctionList->C_EncryptInit)(sessionRO, &testMecha, hNewObject);
    checkPrintResult("C_EncryptInit et type de cl" E_AIGUE " inconsistent avec le m" E_AIGUE "canisme choisi", rv, testNumber, MsgsTbl);



    (*pFunctionList->C_CloseAllSessions)(currentSlotID);

    /***********************************************/
    /*        tests C_Encrypt()                    */
    /***********************************************/

    //ouverture d'une session en lecture ecriture sur le premier slot
    rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
    if (rv != CKR_OK) {
      (*pFunctionList->C_Finalize)(NULL);
      return;
    }

    // Recuperer l'objet clé secrete
    hPubKey = 0;
    testGetPkcs11Object(pFunctionList, sessionRO, ENCRYPT_FUNCTIONS, AT_KEYEXCHANGE, pin, &hPubKey, NULL);

    // C_Encrypt et opération non initialisée
    CK_ULONG ulCipherTextLen;
    CK_CHAR bufCipher[30];
    testNumber++;
    rv = (*pFunctionList->C_Encrypt)(sessionRO, (CK_BYTE_PTR)DATA_TO_ENCRYPT, dataLen, NULL_PTR, &ulCipherTextLen);
    checkPrintResult("C_Encrypt et op" E_AIGUE "ration non initialisee", rv, testNumber, MsgsTbl);

    // Initialisation de chiffrement correct
    testNumber++;
    testMecha.mechanism = CKM_RSA_PKCS;
    rv = (*pFunctionList->C_EncryptInit)(sessionRO, &testMecha, hPubKey);
    checkPrintResult("C_EncryptInit init de chiffrement correct", rv, testNumber, MsgsTbl);

    // Chiffrement et mauvais parametre
    testNumber++;
    rv = (*pFunctionList->C_Encrypt)(sessionRO, (CK_BYTE_PTR)DATA_TO_ENCRYPT, 0, NULL_PTR, NULL_PTR);
    checkPrintResult("C_Encrypt et mauvais parametre", rv, testNumber, MsgsTbl);

    // Chiffrement et taille en sortie insuffisante
    testNumber++;
    ulCipherTextLen = 12;
    rv = (*pFunctionList->C_Encrypt)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16, bufCipher, &ulCipherTextLen);
    checkPrintResult("C_Encrypt et mauvais parametre", rv, testNumber, MsgsTbl);

    // Chiffrement correct
    testNumber++;
    ulCipherTextLen = sizeof(bufCipher);
    rv = (*pFunctionList->C_Encrypt)(sessionRO, (CK_BYTE_PTR)DATA_TO_ENCRYPT, 16, (CK_BYTE_PTR)NULL_PTR, pulEncryptedDataLen);
    if (rv != CKR_OK) {
      (*pFunctionList->C_Finalize)(NULL);
      return;
    }

    *ppEncryptedData = (CK_BYTE_PTR)malloc(*pulEncryptedDataLen);
    if (*ppEncryptedData == NULL_PTR) {
      (*pFunctionList->C_Finalize)(NULL);
      return;
    }

    rv = (*pFunctionList->C_Encrypt)(sessionRO, (CK_BYTE_PTR)DATA_TO_ENCRYPT, 16, (CK_BYTE_PTR)*ppEncryptedData, pulEncryptedDataLen);
    checkPrintResult("C_Encrypt et parametres corrects", rv, testNumber, MsgsTbl);

    (*pFunctionList->C_CloseAllSessions)(currentSlotID);

    (*pFunctionList->C_Finalize)(NULL);
  }
}

//*******************************************************************
//Effectue les tests de déchiffrement
//*******************************************************************
void testDecryptManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BYTE_PTR  pEncryptedData, CK_ULONG ulEncryptedDataLen)
{
  CK_C_INITIALIZE_ARGS pInitArgs;
  int testNumber = getIndexDebutSectionTests(DECRYPT_FUNCTIONS);
  CK_RV rv;
  CK_SESSION_HANDLE sessionRO = 0xFFFFFFFF;
  CK_MECHANISM testMecha;
  CK_BYTE_PTR pData = (CK_BYTE_PTR)DATA_TO_ENCRYPT;

  CK_OBJECT_HANDLE hObject = 0;

  // librairie non initialisée
  rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
  checkPrintResult("C_DecryptInit et librairie non initialis" E_AIGUE "e", rv, testNumber, MsgsTbl);

  if (isCPS3) {
    /**** ACTIVER le winlogonDecrypt à l'initialisation ******/
    pInitArgs.flags = CKF_OS_LOCKING_OK | CKF_LIBRARY_CANT_CREATE_OS_THREADS;
    pInitArgs.LockMutex = NULL_PTR;
    pInitArgs.UnlockMutex = NULL_PTR;
    pInitArgs.CreateMutex = NULL_PTR;
    pInitArgs.DestroyMutex = NULL_PTR;
    pInitArgs.pReserved = (void*)WINLOGON_DECRYPT;

    rv = (*pFunctionList->C_Initialize)(&pInitArgs);
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
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_DecryptInit avec handle de session invalide", rv, testNumber, MsgsTbl);



      //ouverture d'une session en lecture seule sur le premier slot
      rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
      if (rv != CKR_OK) {
        (*pFunctionList->C_Finalize)(NULL);
        return;
      }

      // login utilisateur
      testNumber++;
      rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);
      checkPrintResult("C_Login avec code porter correct", rv, testNumber, MsgsTbl);


      // Mauvais handle de clé
      testNumber++;
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_DecryptInit avec mauvais handle de cl" E_AIGUE "", rv, testNumber, MsgsTbl);


      // Recuperer l'objet clé privée d'authentification (AT_KEYEXCHANGE)
      testGetPkcs11Object(pFunctionList, sessionRO, DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, pin, &hObject, NULL);

      // Mauvais mécanisme
      testNumber++;
      testSetMechanism(DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_DecryptInit et mauvais m" E_AIGUE "canisme", rv, testNumber, MsgsTbl);


      rv = (*pFunctionList->C_Logout)(sessionRO);
      // Utilisateur non logué
      testNumber++;
      testSetMechanism(DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_DecryptInit et utilisateur non logu" E_GRAVE "", rv, testNumber, MsgsTbl);


      rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

      /***********************************************/
      /*        tests C_Decrypt()                    */
      /***********************************************/

      //ouverture d'une session en lecture seule sur le premier slot
      rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
      if (rv != CKR_OK) {
        (*pFunctionList->C_Finalize)(NULL);
        return;
      }

      // Recuperer l'objet clé privée d'authentification (AT_KEYEXCHANGE)
    hObject = 0;
      testGetPkcs11Object(pFunctionList, sessionRO, DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, pin, &hObject, NULL);

      // C_Decrypt et opération non initialisée
      CK_ULONG ulPlainTextLen;
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16, NULL_PTR, &ulPlainTextLen);
      checkPrintResult("C_Decrypt et op" E_AIGUE "ration non initialisee", rv, testNumber, MsgsTbl);


      // C_Decrypt et handle de session invalide
      CK_SESSION_HANDLE sessionRO_Inv = 0xFFFFFFFF;
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO_Inv, (CK_BYTE_PTR)"testtesttesttest", 16, NULL_PTR, &ulPlainTextLen);
      checkPrintResult("C_Decrypt et handle de session invalide", rv, testNumber, MsgsTbl);


      // C_DecryptInit et paramètres corrects
      testNumber++;
      // Positionner un mécanisme correct pour la clé d'authent
      testSetMechanism(DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_DecryptInit et param" E_GRAVE "tres corrects", rv, testNumber, MsgsTbl);


      // C_Decrypt et paramètre d'entrée invalide
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, (CK_BYTE_PTR)NULL_PTR, ulEncryptedDataLen, NULL_PTR, &ulPlainTextLen);
      checkPrintResult("C_Decrypt et param" E_GRAVE "tre d'entr" E_AIGUE "e invalide", rv, testNumber, MsgsTbl);


      // C_Decrypt et buffer de sortie trop petit
      testNumber++;
      CK_BYTE bufPlainText[32];
      ulPlainTextLen = 2;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, pEncryptedData, ulEncryptedDataLen, bufPlainText, &ulPlainTextLen);
      checkPrintResult("C_Decrypt et buffer de sortie trop petit", rv, testNumber, MsgsTbl);


      // C_Decrypt et paramètres corrects (demande de la taille en sortie)
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, pEncryptedData, ulEncryptedDataLen, NULL_PTR, &ulPlainTextLen);
      checkPrintResult("C_Decrypt et parametres corrects, demande de la taille uniquement", rv, testNumber, MsgsTbl);


      // C_Decrypt et paramètres corrects (dechiffrement effectif)
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, pEncryptedData, ulEncryptedDataLen, bufPlainText, &ulPlainTextLen);
      if (rv == CKR_OK) {
        rv = memcmp(pData, bufPlainText, ulPlainTextLen);
        if (rv != 0) {
          rv = CKR_FUNCTION_FAILED;
        }
      }

      checkPrintResult("C_Decrypt et param" E_AIGUE "tres corrects, dechiffrement effectif", rv, testNumber, MsgsTbl);


      (*pFunctionList->C_CloseAllSessions)(currentSlotID);

      rv = (*pFunctionList->C_Finalize)(NULL);

      testNumber++;
      /* 06/04/2018 decrypt sans passer le parametre specifique au C_Initialize */
      rv = (*pFunctionList->C_Initialize)(NULL);
      checkPrintResult("C_Initialize correct avec initArgs NULL.", rv, testNumber, MsgsTbl);

      if (rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
      {
        ulSlotsListSize = MAX_SLOTS;
        //recupération de la liste des slots avec carte
        rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
        if (rv != CKR_OK || ulSlotsListSize == 0) return;

        currentSlotID = tabSlots[0];

        //ouverture d'une session en lecture seule sur le premier slot
        rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
        if (rv != CKR_OK) {
          (*pFunctionList->C_Finalize)(NULL);
          return;
        }

        // login utilisateur
        testNumber++;
        rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);
        checkPrintResult("C_Login avec code porteur correct. initArgs NULL.", rv, testNumber, MsgsTbl);

        // Recuperer l'objet clé privée d'authentification (AT_KEYEXCHANGE)
        testGetPkcs11Object(pFunctionList, sessionRO, DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, pin, &hObject, NULL);

        // C_DecryptInit et paramètres corrects
        testNumber++;
        // Positionner un mécanisme correct pour la clé d'authent
        testSetMechanism(DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
        rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
        checkPrintResult("C_DecryptInit et param" E_GRAVE "tres corrects. initArgs NULL.", rv, testNumber, MsgsTbl);

        // C_Decrypt et paramètres corrects (demande de la taille en sortie)
        testNumber++;
        rv = (*pFunctionList->C_Decrypt)(sessionRO, pEncryptedData, ulEncryptedDataLen, NULL_PTR, &ulPlainTextLen);
        checkPrintResult("C_Decrypt et parametres corrects, demande de la taille uniquement. initArgs NULL.", rv, testNumber, MsgsTbl);

        // C_Decrypt et paramètres corrects (dechiffrement effectif)
        testNumber++;
        rv = (*pFunctionList->C_Decrypt)(sessionRO, pEncryptedData, ulEncryptedDataLen, bufPlainText, &ulPlainTextLen);

        if (rv == CKR_OK) {
          rv = memcmp(pData, bufPlainText, ulPlainTextLen);
          if (rv != 0) {
            rv = CKR_FUNCTION_FAILED;
          }
        }
        checkPrintResult("C_Decrypt et param" E_AIGUE "tres corrects, dechiffrement effectif. initArgs NULL.", rv, testNumber, MsgsTbl);

        (*pFunctionList->C_CloseAllSessions)(currentSlotID);

        rv = (*pFunctionList->C_Finalize)(NULL);
      }

    }
  } else {
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
      testMecha.mechanism = CKM_RC4;
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_DecryptInit avec handle de session invalide", rv, testNumber, MsgsTbl);


      //ouverture d'une session en lecture seule sur le premier slot
      rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
      if (rv != CKR_OK) {
        (*pFunctionList->C_Finalize)(NULL);
        return;
      }

      // login utilisateur
      testNumber++;
      rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);
      checkPrintResult("C_Login avec code porter correct", rv, testNumber, MsgsTbl);

      // Mauvais handle de clé
      testNumber++;
      MsgsTbl[testNumber].usExpectedRc = CKR_KEY_HANDLE_INVALID;
      CK_OBJECT_HANDLE hNewObject = 0;
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hNewObject);
      checkPrintResult("C_DecryptInit et mauvais handle de cl" E_AIGUE "", rv, testNumber, MsgsTbl);

      testGetPkcs11Object(pFunctionList, sessionRO, DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, NULL_PTR, &hObject, NULL);
      // Mauvais mécanisme
      testNumber++;
      testSetMechanism(ENCRYPT_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_DecryptInit avec mauvais m" E_AIGUE "canisme", rv, testNumber, MsgsTbl);

      rv = (*pFunctionList->C_Logout)(sessionRO);
      if (rv != CKR_OK) {
        (*pFunctionList->C_Finalize)(NULL);
        return;
      }
      // Utilisateur non logué
      testNumber++;
      //testGetPkcs11Object(pFunctionList, sessionRO, DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, NULL_PTR, &hObject);
      testMecha.mechanism = CKM_RC4;
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_DecryptInit et utilisateur non logué", rv, testNumber, MsgsTbl);

      rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

      /***********************************************/
      /*        tests C_Decrypt()                    */
      /***********************************************/

      //ouverture d'une session en lecture seule sur le premier slot
      rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
      if (rv != CKR_OK) {
        (*pFunctionList->C_Finalize)(NULL);
        return;
      }

      rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);
      if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        (*pFunctionList->C_Finalize)(NULL);
        return;
      }

      // Recuperer l'objet clé secrete pour le mecanisme RC4
       hObject = 0;
      testGetPkcs11Object(pFunctionList, sessionRO, DECRYPT_FUNCTIONS, AT_KEYEXCHANGE, pin, &hObject, NULL);
      // C_Decrypt et opération non initialisée
      CK_ULONG ulPlainTextLen;
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16, NULL_PTR, &ulPlainTextLen);
      checkPrintResult("C_Decrypt et op" E_AIGUE "ration non initialisee", rv, testNumber, MsgsTbl);


      // C_Decrypt et handle de session invalide
      CK_SESSION_HANDLE sessionRO_Inv = 0xFFFFFFFF;
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO_Inv, (CK_BYTE_PTR)"testtesttesttest", 16, NULL_PTR, &ulPlainTextLen);
      checkPrintResult("C_Decrypt et handle de session invalide", rv, testNumber, MsgsTbl);

      // C_DecryptInit et paramètres corrects
      testNumber++;
      // Positionner un mécanisme correct pour la clé secrete
      testMecha.mechanism = CKM_RC4;
      rv = (*pFunctionList->C_DecryptInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_DecryptInit et param" E_GRAVE "tres corrects", rv, testNumber, MsgsTbl);


      // C_Decrypt et paramètre d'entrée invalide
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, (CK_BYTE_PTR)NULL_PTR, ulEncryptedDataLen, NULL_PTR, NULL_PTR);
      checkPrintResult("C_Decrypt et param" E_GRAVE "tre d'entr" E_AIGUE "e invalide", rv, testNumber, MsgsTbl);


      // C_Decrypt et buffer de sortie trop petit
      testNumber++;
      CK_BYTE bufPlainText[32];
      ulPlainTextLen = 2;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, pEncryptedData, ulEncryptedDataLen, bufPlainText, &ulPlainTextLen);
      checkPrintResult("C_Decrypt et buffer de sortie trop petit", rv, testNumber, MsgsTbl);

      // C_Decrypt et paramètres corrects (demande de la taille en sortie)
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, pEncryptedData, ulEncryptedDataLen, NULL_PTR, &ulPlainTextLen);
      checkPrintResult("C_Decrypt et parametres corrects, demande de la taille uniquement", rv, testNumber, MsgsTbl);


      // C_Decrypt et paramètres corrects (dechiffrement effectif)
      testNumber++;
      rv = (*pFunctionList->C_Decrypt)(sessionRO, pEncryptedData, ulEncryptedDataLen, bufPlainText, &ulPlainTextLen);

      rv = memcmp(pData, bufPlainText, ulPlainTextLen);
      if (rv != 0) {
        rv = CKR_FUNCTION_FAILED;
      }

      checkPrintResult("C_Decrypt et param" E_AIGUE "tres corrects, dechiffrement effectif", rv, testNumber, MsgsTbl);

      (*pFunctionList->C_CloseAllSessions)(currentSlotID);

      rv = (*pFunctionList->C_Finalize)(NULL);

    }


  }
}