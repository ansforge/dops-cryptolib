#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "testconstants.h"

#define DATA_TO_SIGN "Un message a signer"
extern sTESTS_MSGS     MsgsTbl[];

extern CK_BBOOL isCPS2TerGALSS;
extern CK_BBOOL isCPS2TerPCSC;

extern unsigned short getIndexDebutSectionTests(int searchedTestLevel);
extern int testGetPkcs11Object(CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, int testLevel, int keySpec,  CK_CHAR_PTR pin, CK_OBJECT_HANDLE_PTR phObject, int * pTestNumber);
extern void testSetMechanism(int testLevel, int keySpec, CK_RV expectedRv, CK_MECHANISM_PTR pMechanism);
extern void testSetData(int testLevel, int keySpec, CK_RV expectedRv, CK_BYTE_PTR * ppData, CK_ULONG_PTR pulDataLen);
extern void testFreeData(CK_BYTE_PTR * ppData, CK_ULONG_PTR pulDataLen);
extern void checkPrintResult(char * mesgTest, CK_RV rv, int testNumber, sTESTS_MSGS * table);
extern unsigned short BuildFullHash( CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, CK_CHAR_PTR pData, CK_BYTE_PTR * pbyHash, CK_ULONG * pdwFullHashLen, unsigned int dwAlgId,  int useOID);

CK_BYTE_PTR pbySignature2 = NULL_PTR;
CK_ULONG ulSignatureLen2;
CK_BYTE_PTR pbySignature3 = NULL_PTR;
CK_ULONG ulSignatureLen3;


//*******************************************************************
//Effectue les tests de signature
//*******************************************************************
void testSignatureManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BYTE_PTR bufSignature, CK_ULONG_PTR pulBufSignatureLen, CK_BYTE_PTR bufSignature_256, CK_ULONG_PTR pulBufSignature_256Len)
{
	int testNumber = getIndexDebutSectionTests(SIGNATU_FUNCTIONS);
	CK_RV rv;
	CK_SESSION_HANDLE sessionRO = 0xFFFFFFFF;
	CK_MECHANISM testMecha;
  unsigned short keyType = AT_SIGNATURE;
	CK_OBJECT_HANDLE hObject=0, hPubKey;
  CK_BYTE_PTR pData;
  CK_ULONG ulDataLen;
  CK_ULONG ulSignatureLen;
  CK_BYTE bufSignature_AT_SIGN[256];

	// librairie non initialisée
	rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
  checkPrintResult("C_SignInit et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	

  // C_Sign et librairie non initialisée
  testNumber++;
  rv = (*pFunctionList->C_Sign)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16, NULL_PTR, &ulSignatureLen);
  checkPrintResult("C_Sign et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	

  // C_SignUpdate et librairie non initialisée
  testNumber++;
	rv = (*pFunctionList->C_SignUpdate)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16);
  checkPrintResult("C_SignUpdate et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	

  // C_SignFinal et librairie non initialisée
	testNumber++;
  rv = (*pFunctionList->C_SignFinal)(sessionRO, (CK_BYTE_PTR)bufSignature_AT_SIGN, &ulSignatureLen);
  checkPrintResult("C_SignFinal et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	

	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
		CK_ULONG ulSlotsListSize = MAX_SLOTS;
		//recupération de la liste des slots avec carte
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
		if (rv != CKR_OK || ulSlotsListSize == 0) return;

		currentSlotID = tabSlots[0];

		// Handle de session invalide
		testNumber++;
		rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
    checkPrintResult("C_SignInit avec handle de session invalide" ,rv,testNumber,MsgsTbl);
		
		

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    // login utilisateur
    testNumber++;
    if (isContactLess == CK_TRUE) {
      // clé privée d'authent (AT_KEYEXCHANGE) en sans contact
      keyType = AT_KEYEXCHANGE;
      MsgsTbl[testNumber].usExpectedRc = CKR_USER_PIN_NOT_INITIALIZED;
    }
	  rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);
    checkPrintResult("C_Login avec code porteur correct" ,rv,testNumber,MsgsTbl);
		

		// Mauvais handle de clé
    testNumber++;
		rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
    checkPrintResult("C_SignInit avec mauvais handle de cl" E_AIGUE  ,rv,testNumber,MsgsTbl);
		

		// Recuperer l'objet clé privée d'authentification (AT_KEYEXCHANGE)
		testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, pin, &hObject, NULL);

    // Recuperer l'objet clé publique d'authentification (AT_KEYEXCHANGE)
    testGetPkcs11Object(pFunctionList, sessionRO, VERISGN_FUNCTIONS, AT_KEYEXCHANGE, pin, &hPubKey, NULL);

		// Mauvais mécanisme
		testNumber++;
		testSetMechanism(SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_SignInit)(sessionRO,&testMecha, hObject);
    checkPrintResult("C_SignInit et mauvais m" E_AIGUE "canisme" ,rv,testNumber,MsgsTbl);
		
		
		// Type de clé inconsistent avec le mécanisme choisi
		testNumber++;
    if ( isCPS3_Card ) {
		  testSetMechanism(SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		  rv = (*pFunctionList->C_SignInit)(sessionRO,&testMecha, hPubKey);
      checkPrintResult("C_SignInit et type de cl" E_AIGUE " inconsistent avec le m" E_AIGUE "canisme choisi" ,rv,testNumber,MsgsTbl);
		  
    }

		rv = (*pFunctionList->C_Logout)(sessionRO);
		// Utilisateur non logué
		testNumber++;
		testSetMechanism(SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
    if (isContactLess == CK_TRUE) {
      MsgsTbl[testNumber].usExpectedRc = CKR_OK;
    }
		rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
    checkPrintResult("C_SignInit et utilisateur non logu" E_GRAVE  ,rv,testNumber,MsgsTbl);
		

		

		rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

    /***********************************************/
    /*        tests C_Sign()                       */
    /***********************************************/

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    // Recuperer l'objet clé privée d'authentification (AT_KEYEXCHANGE)
    hObject = NULL_PTR;
		testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, pin, &hObject, NULL);

		// C_Sign et opération non initialisée
		testNumber++;
		rv = (*pFunctionList->C_Sign)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16, NULL_PTR, &ulSignatureLen);
    checkPrintResult("C_Sign et op" E_AIGUE "ration non initialisee" ,rv,testNumber,MsgsTbl);
		

		// C_Sign et handle de session invalide
		CK_SESSION_HANDLE sessionRO_Inv = 0xFFFFFFFF;
		testNumber++;
		rv = (*pFunctionList->C_Sign)(sessionRO_Inv, (CK_BYTE_PTR)"testtesttesttest", 16, NULL_PTR, &ulSignatureLen);
    checkPrintResult("C_Sign et handle de session invalide" ,rv,testNumber,MsgsTbl);
		

    // C_SignInit et paramètres corrects
		testNumber++;
    // Positionner un mécanisme correct pour la clé d'authent
    testSetMechanism(SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
    checkPrintResult("C_SignInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
		

    // C_Sign et paramètre d'entrée invalide
		testNumber++;
		rv = (*pFunctionList->C_Sign)(sessionRO, (CK_BYTE_PTR)NULL_PTR, 16, NULL_PTR, NULL_PTR);
    checkPrintResult("C_Sign et param"  E_GRAVE  "tre d'entr" E_AIGUE "e invalide" ,rv,testNumber,MsgsTbl);
		

    // C_SignInit et paramètres corrects
		testNumber++;
    if (!isCPS3) {
      // Positionner un mécanisme correct pour la clé d'authent
      testSetMechanism(SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		  rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_SignInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
      
    }

     // C_Sign et récupération de la taille de signature uniquement (CKR_OK)
		testNumber++;
    CK_BYTE_PTR pDonnee = NULL_PTR;
    CK_ULONG ulDonnee;

    if (!isCPS3) {
      pDonnee = (CK_BYTE_PTR)DATA_TO_SIGN;
      ulDonnee = strlen((const char *)pDonnee);
    }
    else {
      pDonnee = (CK_BYTE_PTR)DATA_TO_SIGN;
      ulDonnee = 0UL;
    }
		rv = (*pFunctionList->C_Sign)(sessionRO, (CK_BYTE_PTR)pDonnee, ulDonnee, NULL_PTR, &ulSignatureLen);
    checkPrintResult("C_Sign et recuperation taille de la signature" ,rv,testNumber,MsgsTbl);
		


    // C_Sign et taille de la signature incorrecte
		testNumber++;
    ulSignatureLen = 0;
    rv = (*pFunctionList->C_Sign)(sessionRO, (CK_BYTE_PTR)pDonnee, ulDonnee, bufSignature, &ulSignatureLen);
    checkPrintResult("C_Sign et taille signature incorrecte" ,rv,testNumber,MsgsTbl);
		

    // C_Sign et taille de la signature correcte, pData à NULL (doit retourner CKR_ARGUMENTS_BAD)
		testNumber++;
    ulSignatureLen = 256;
    pDonnee = NULL_PTR;
    rv = (*pFunctionList->C_Sign)(sessionRO, (CK_BYTE_PTR)pDonnee, 0, bufSignature, &ulSignatureLen);
    checkPrintResult("C_Sign et taille de signature correcte, pData est NULL" ,rv,testNumber,MsgsTbl);
		
    if (!isCPS3) {
      // Re-initialiser l'operation avec les Cryptos CPS2ter
      rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
      if (rv != CKR_OK) {
        (*pFunctionList->C_Finalize)(NULL_PTR);
        return;
      }
    }

    // C_Sign et données en entrée incorrectes (doit retourner CKR_DATA_LEN_RANGE)
		testNumber++;
    // Positionner des données incorrectes
    testSetData(SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &pData, &ulDataLen);
    ulSignatureLen = 256;
    rv = (*pFunctionList->C_Sign)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen, bufSignature, &ulSignatureLen);
    checkPrintResult("C_Sign et taille des donn" E_AIGUE "es d'entree incorrecte" ,rv,testNumber,MsgsTbl);
		
    testFreeData( &pData, &ulDataLen);

    // Il faut reinitialiser une opération de signature
    testNumber++;
    rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
    checkPrintResult("C_SignInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
    
    // C_Sign avec paramètres en entrée corrects pSignature à NULL
		testNumber++;
    // Positionner une taille des données en sortie correcte
    BuildFullHash( pFunctionList, sessionRO, (CK_CHAR_PTR)"document_to_sign", &pData, &ulDataLen, SHA1, CK_TRUE);
		rv = (*pFunctionList->C_Sign)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen, NULL_PTR, pulBufSignatureLen);
    checkPrintResult("C_Sign avec param"  E_GRAVE  "tres en entr" E_AIGUE "e corrects (pSignature " A_ACCENT " NULL, taille signature)" ,rv,testNumber,MsgsTbl);

    // C_Sign avec paramètres en entrée corrects
		testNumber++;
    // Positionner une taille des données en sortie correcte
		rv = (*pFunctionList->C_Sign)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen, bufSignature, pulBufSignatureLen);
    checkPrintResult("C_Sign avec param"  E_GRAVE  "tres en entr" E_AIGUE "e corrects (valeur signature)" ,rv,testNumber,MsgsTbl);
		

    testFreeData( &pData, &ulDataLen);

    rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

    /***********************************************/
    /*        tests C_SignUpdate()                   */
    /***********************************************/

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    // Recuperer l'objet clé privée de signature (AT_SIGNATURE)
    hObject = NULL_PTR;
		testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, keyType, pin, &hObject, NULL);

		// C_SignUpdate et opération non initialisée
		testNumber++;
		rv = (*pFunctionList->C_SignUpdate)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16);
    checkPrintResult("C_SignUpdate et op" E_AIGUE "ration non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
		

		// C_SignUpdate et handle de session invalide
		sessionRO_Inv = 0xFFFFFFFF;
		testNumber++;
		rv = (*pFunctionList->C_SignUpdate)(sessionRO_Inv, (CK_BYTE_PTR)"testtesttesttest", 16);
    checkPrintResult("C_SignUpdate et handle de session invalide" ,rv,testNumber,MsgsTbl);
		

    // C_SignInit et paramètres corrects
		testNumber++;
    // Positionner un mécanisme correct pour la clé de signature
    testSetMechanism(SIGNATU_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
    checkPrintResult("C_SignInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
		

    // C_SignUpdate et paramètre d'entrée invalide (CKR_ARGUMENT_BAD)
		testNumber++;
		rv = (*pFunctionList->C_SignUpdate)(sessionRO, (CK_BYTE_PTR)NULL_PTR, 16);
    checkPrintResult("C_SignUpdate et param" E_GRAVE "tres d'entree invalides" ,rv,testNumber,MsgsTbl);
		
    if (!isCPS3) {
      // Re-initialiser l'operation avec les Cryptos CPS2ter
      rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
      if (rv != CKR_OK) {
        (*pFunctionList->C_Finalize)(NULL_PTR);
        return;
      }
    }

    // C_SignUpdate et parametres en entrée corrects
		testNumber++;
    // Positionner des données correctes
    testSetData(SIGNATU_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &pData, &ulDataLen);
		rv = (*pFunctionList->C_SignUpdate)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen);
    checkPrintResult("C_SignUpdate et parametres d'entr" E_AIGUE "e incorrects" ,rv,testNumber,MsgsTbl);
		

    // C_SignUpdate et parametres en entrée corrects
		testNumber++;
    // Positionner des données incorrectes
		rv = (*pFunctionList->C_SignUpdate)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen);
    checkPrintResult("C_SignUpdate et taille des donn" E_AIGUE "es d'entr" E_AIGUE "e incorrecte" ,rv,testNumber,MsgsTbl);
		

    testFreeData( &pData, &ulDataLen);

    rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

    /***********************************************/
    /*        tests C_SignFinal()                   */
    /***********************************************/

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    // Recuperer l'objet clé privée de signature (AT_SIGNATURE)
    hObject = NULL_PTR;
		testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, keyType, pin, &hObject, NULL);

		// C_SignFinal et opération non initialisée
		testNumber++;
    rv = (*pFunctionList->C_SignFinal)(sessionRO, (CK_BYTE_PTR)bufSignature_AT_SIGN, &ulSignatureLen);
    checkPrintResult("C_SignFinal et op" E_AIGUE "ration non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
		

    // C_SignInit et paramètres corrects
		testNumber++;
    // Positionner un mécanisme correct pour la clé de signature
    testSetMechanism(SIGNATU_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
    checkPrintResult("C_SignInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
		

		// C_SignFinal et handle de session invalide
		sessionRO_Inv = 0xFFFFFFFF;
		testNumber++;
		rv = (*pFunctionList->C_SignFinal)(sessionRO_Inv, (CK_BYTE_PTR)bufSignature_AT_SIGN, &ulSignatureLen);
    
		checkPrintResult("C_SignFinal et handle de session invalide" ,rv,testNumber,MsgsTbl);
    //checkPrintResult("C_SignInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
		

    // C_SignFinal et paramètre d'entrée invalide
		testNumber++;
    rv = (*pFunctionList->C_SignFinal)(sessionRO, (CK_BYTE_PTR)bufSignature_AT_SIGN, NULL_PTR);
		checkPrintResult("C_SignFinal et param" E_GRAVE "tre d'entr" E_AIGUE "e invalide" ,rv,testNumber,MsgsTbl);
		
    if (!isCPS3) {
      // Re-initialiser l'operation avec les Cryptos CPS2ter
      rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
      if (rv != CKR_OK) {
        (*pFunctionList->C_Finalize)(NULL_PTR);
        return;
      }
    }

    // C_SignUpdate et parametres en entrée corrects
		testNumber++;
    // Positionner des données correctes
    testSetData(SIGNATU_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &pData, &ulDataLen);
		rv = (*pFunctionList->C_SignUpdate)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen);
		checkPrintResult("C_SignUpdate avec des donn" E_AIGUE "es d'entr" E_AIGUE "e correctes" ,rv,testNumber,MsgsTbl);
		

    // C_SignFinal et buffer de signature de taille insuffisante
		testNumber++;
    *pulBufSignature_256Len = 250;
    rv = (*pFunctionList->C_SignFinal)(sessionRO, bufSignature_AT_SIGN, pulBufSignature_256Len);
		checkPrintResult("C_SignFinal et buffer de signature de taille insuffisante" ,rv,testNumber,MsgsTbl);
		

    // C_SignFinal et récupération de la taille seulement
		testNumber++;
    *pulBufSignature_256Len = 0;
    rv = (*pFunctionList->C_SignFinal)(sessionRO, NULL_PTR, pulBufSignature_256Len);
		checkPrintResult("C_SignFinal et r" E_AIGUE "cup" E_AIGUE "ration de la taille de la signature" ,rv,testNumber,MsgsTbl);
		

    if (rv == CKR_OK && *pulBufSignature_256Len == sizeof(bufSignature_AT_SIGN)) {
      // C_SignFinal et calcul effectif de la signature
		  testNumber++;
      rv = (*pFunctionList->C_SignFinal)(sessionRO, bufSignature_256, pulBufSignature_256Len);
		  checkPrintResult("C_SignFinal et calcul effectif de la signature" ,rv,testNumber,MsgsTbl);
		  
    }

    (*pFunctionList->C_Finalize)(NULL);


    rv = (*pFunctionList->C_Initialize)(NULL);

    if ((rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) && isContactLess == CK_FALSE)
    {
      CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
      CK_ULONG ulSlotsListSize = MAX_SLOTS;
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
      rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);
      //checkPrintResult("C_Login avec code porteur correct", rv, testNumber, MsgsTbl);

      hObject = NULL_PTR;
      testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, AT_SIGNATURE, pin, &hObject, NULL);

      // C_SignInit et signature de condensat avec AT_SIGNATURE
      testNumber++;
      // Positionner le mécanisme CKM_RSA_PKCS pour la clé de signature
      testSetMechanism(SIGNATU_FUNCTIONS, AT_SIGNATURE | AT_SIGN_HASH, MsgsTbl[testNumber].usExpectedRc, &testMecha);
      rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_SignInit et param" E_GRAVE "tres corrects (CKM_RSA_PKCS et cl" E_AIGUE " de signature)", rv, testNumber, MsgsTbl);

      // C_Sign et taille du hash correcte, pData à NULL
      testNumber++;
      // Creation du condensat SHA1 ...
      BuildFullHash(pFunctionList, sessionRO, (CK_CHAR_PTR)"document_to_sign", &pData, &ulDataLen, SHA1, CK_FALSE);
      rv = (*pFunctionList->C_Sign)(sessionRO, pData, ulDataLen, NULL, &ulSignatureLen2);
      checkPrintResult("C_Sign et taille de signature", rv, testNumber, MsgsTbl);

      pbySignature2 = (CK_BYTE_PTR)malloc(ulSignatureLen2);
      // C_Sign signature effective du hash
      testNumber++;
      rv = (*pFunctionList->C_Sign)(sessionRO, pData, ulDataLen, pbySignature2, &ulSignatureLen2);
      checkPrintResult("C_Sign et signature du condensat effective", rv, testNumber, MsgsTbl);

      // C_SignInit et signature de condensat SHA2 avec AT_SIGNATURE
      testNumber++;
      // Positionner le mécanisme CKM_RSA_PKCS pour la clé de signature
      rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_SignInit et param" E_GRAVE"tres corrects (CKM_RSA_PKCS et cl" E_AIGUE " de signature)", rv, testNumber, MsgsTbl);

      // C_Sign et taille du hash SHA2 correcte, pData à NULL
      testNumber++;
      // Creation du condensat SHA2 ...
      BuildFullHash(pFunctionList, sessionRO, (CK_CHAR_PTR)"document_to_sign", &pData, &ulDataLen, SHA256, CK_FALSE);
      rv = (*pFunctionList->C_Sign)(sessionRO, pData, ulDataLen, NULL, &ulSignatureLen3);
      checkPrintResult("C_Sign et taille de signature", rv, testNumber, MsgsTbl);

      pbySignature3 = (CK_BYTE_PTR)malloc(ulSignatureLen3);

      // C_Sign signature effective du hash SHA2
      testNumber++;
      rv = (*pFunctionList->C_Sign)(sessionRO, pData, ulDataLen, pbySignature3, &ulSignatureLen3);
      checkPrintResult("C_Sign et signature du condensat effective", rv, testNumber, MsgsTbl);

      testFreeData(&pData, &ulDataLen);
      //free(pbySignature2);

      rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

      (*pFunctionList->C_Finalize)(NULL);
    }

    rv = (*pFunctionList->C_Initialize)(NULL);

    if ((rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) && isContactLess == CK_FALSE)
    {
      CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
      CK_ULONG ulSlotsListSize = MAX_SLOTS;
      CK_BYTE_PTR pbySignature4 = NULL_PTR;
      CK_ULONG ulSignatureLen4;
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
      rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);

      hObject = NULL_PTR;
      testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, AT_SIGNATURE, pin, &hObject, NULL);

      // C_SignInit et signature de condensat avec AT_SIGNATURE
      testNumber++;
      // Positionner le mécanisme CKM_RSA_PKCS pour la clé de signature
      testSetMechanism(SIGNATU_FUNCTIONS, AT_SIGNATURE | AT_SIGN_HASH, MsgsTbl[testNumber].usExpectedRc, &testMecha);
      rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_SignInit et param" E_GRAVE"tres corrects (CKM_RSA_PKCS et cl" E_AIGUE " de signature)", rv, testNumber, MsgsTbl);

      // C_Sign et taille du hash SHA2 correcte, pData à NULL
      testNumber++;
      // Creation du condensat SHA2 ...
      BuildFullHash(pFunctionList, sessionRO, (CK_CHAR_PTR)"document_to_sign", &pData, &ulDataLen, SHA256, CK_TRUE);
      rv = (*pFunctionList->C_Sign)(sessionRO, pData, ulDataLen, NULL, &ulSignatureLen4);
      checkPrintResult("C_Sign et taille de signature", rv, testNumber, MsgsTbl);

      pbySignature4 = (CK_BYTE_PTR)malloc(ulSignatureLen4);

      // C_Sign signature effective du hash SHA2
      testNumber++;
      rv = (*pFunctionList->C_Sign)(sessionRO, pData, ulDataLen, pbySignature4, &ulSignatureLen4);
      checkPrintResult("C_Sign et signature du condensat effective", rv, testNumber, MsgsTbl);

      testFreeData(&pData, &ulDataLen);


      rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

    }
    (*pFunctionList->C_Finalize)(NULL);
	}
}

//*******************************************************************
//Effectue les tests de vérification de signature
//*******************************************************************
void testVerificationSignatureManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_BYTE_PTR bufSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR bufSignature_256, CK_ULONG ulBufSignature_256Len)
{
  int testNumber = getIndexDebutSectionTests(VERISGN_FUNCTIONS);
	CK_RV rv;
	CK_SESSION_HANDLE sessionRO = 0xFFFFFFFF;
	CK_MECHANISM testMecha;
  unsigned short keyType = AT_SIGNATURE;

	CK_OBJECT_HANDLE hObject=0;
  CK_BYTE_PTR pData;
  CK_ULONG ulDataLen;
  CK_BYTE bufSignature_AT_SIGN[256];
  CK_ULONG local_ulSignatureLen = sizeof(bufSignature_AT_SIGN);

	// librairie non initialisée
	rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
	checkPrintResult("C_VerifyInit et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	

  // C_Verify et librairie non initialisée
	testNumber++;
	rv = (*pFunctionList->C_Verify)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16, (CK_BYTE_PTR)"toto", ulSignatureLen);
	checkPrintResult("C_Verify et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	

  // C_VerifyUpdate et librairie non initialisée
	testNumber++;
	rv = (*pFunctionList->C_VerifyUpdate)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16);
	checkPrintResult("C_VerifyUpdate et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	
  // C_VerifyFinal et librairie non initialisée
	testNumber++;
  rv = (*pFunctionList->C_VerifyFinal)(sessionRO, (CK_BYTE_PTR)bufSignature_AT_SIGN, local_ulSignatureLen);
	checkPrintResult("C_VerifyFinal et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	

	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
		CK_ULONG ulSlotsListSize = MAX_SLOTS;
    //CK_ULONG ulSignatureLen = 64;

		//recupération de la liste des slots avec carte
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
		if (rv != CKR_OK || ulSlotsListSize == 0) return;

		currentSlotID = tabSlots[0];

		// Handle de session invalide
		testNumber++;
		rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("C_VerifyInit avec handle de session invalide" ,rv,testNumber,MsgsTbl);
		
		

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    // Mauvais handle de clé
    testNumber++;
		rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("C_VerifyInit avec mauvais handle de cl" E_AIGUE "" ,rv,testNumber,MsgsTbl);
		

		// Recuperer l'objet clé publique d'authentification (AT_KEYEXCHANGE)
    testGetPkcs11Object(pFunctionList, sessionRO, VERISGN_FUNCTIONS, AT_KEYEXCHANGE, NULL_PTR, &hObject, NULL);

		// Mauvais mécanisme
		testNumber++;
    testSetMechanism(VERISGN_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_VerifyInit)(sessionRO,&testMecha, hObject);
		checkPrintResult("C_VerifyInit et mauvais m" E_AIGUE "canisme" ,rv,testNumber,MsgsTbl);
		

    // Mauvais paramètre d'entrée
		testNumber++;
    // Trap avec la cryptolib cps2ter
    if ( ! isCPS2TerGALSS && !isCPS2TerPCSC)
    {
    testSetMechanism(VERISGN_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_VerifyInit)(sessionRO,NULL_PTR, hObject);
		checkPrintResult("C_VerifyInit et mauvais param" E_GRAVE "tre d'entr" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
    }

    /* Type de clé inconsistent avec le mécanisme choisi
		testNumber++;
    if ( isCPS3_Card ) {
		  testSetMechanism(VERISGN_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		  rv = (*pFunctionList->C_VerifyInit)(sessionRO,&testMecha, hObject);
		  checkPrintResult("C_VerifyInit et type de cl" E_AIGUE " inconsistent avec le m" E_AIGUE "canisme choisi" ,rv,testNumber,MsgsTbl);
		  
    }*/

    rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

    /***********************************************/
    /*        tests C_Verify()                     */
    /***********************************************/

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    // Recuperer l'objet clé publique d'authentification (AT_KEYEXCHANGE)
    hObject = NULL_PTR;
		testGetPkcs11Object(pFunctionList, sessionRO, VERISGN_FUNCTIONS, AT_KEYEXCHANGE, NULL_PTR, &hObject, NULL);

		// C_Verify et opération non initialisée
		testNumber++;
		rv = (*pFunctionList->C_Verify)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16, (CK_BYTE_PTR)"toto", ulSignatureLen);
		checkPrintResult("C_Verify et op" E_AIGUE "ration non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
		

		// C_Verify et handle de session invalide
		CK_SESSION_HANDLE sessionRO_Inv = 0xFFFFFFFF;
		testNumber++;
		rv = (*pFunctionList->C_Verify)(sessionRO_Inv, (CK_BYTE_PTR)"testtesttesttest", 16, (CK_BYTE_PTR)"toto", ulSignatureLen);
		checkPrintResult("C_Verify et handle de session invalide" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyInit et paramètres corrects
		testNumber++;
    // Positionner un mécanisme correct pour la clé publique d'authentification
    testSetMechanism(VERISGN_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("C_VerifyInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
		

    // C_Verify et paramètre d'entrée invalide
		testNumber++;
		rv = (*pFunctionList->C_Verify)(sessionRO, (CK_BYTE_PTR)NULL_PTR, 16, NULL_PTR, ulSignatureLen);
		checkPrintResult("C_Verify et param"  E_GRAVE  "tre d'entr" E_AIGUE "e invalide" ,rv,testNumber,MsgsTbl);
		

    // C_Verify et taille des données incorrectes
		testNumber++;
    CK_BYTE local_bufSignature[128];
    local_ulSignatureLen = sizeof(local_bufSignature);
    // Positionner des données incorrectes
    testSetData(VERISGN_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &pData, &ulDataLen);
    if (isCPS3)
		rv = (*pFunctionList->C_Verify)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen, local_bufSignature, local_ulSignatureLen);
    else
      rv = (*pFunctionList->C_Verify)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen, bufSignature, ulSignatureLen);
		checkPrintResult("C_Verify et taille des donn" E_AIGUE "es d'entree incorrecte" ,rv,testNumber,MsgsTbl);
		

    testFreeData( &pData, &ulDataLen);

    // Il faut reinitialiser une opération de vérification
    testNumber++;
    rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("C_VerifyInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
    

    // C_Verify et taille de la signature incorrecte
		testNumber++;
    // Positionner des données d'entrée correctes
    testSetData(VERISGN_FUNCTIONS, AT_KEYEXCHANGE, MsgsTbl[testNumber].usExpectedRc, &pData, &ulDataLen);
    // ... mais une taille de la signature incorrecte
    local_ulSignatureLen = 124;
		rv = (*pFunctionList->C_Verify)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen, bufSignature, local_ulSignatureLen);
		checkPrintResult("C_Verify et taille des donn" E_AIGUE "es en sortie insuffisante" ,rv,testNumber,MsgsTbl);
		

    // C_Verify avec paramètres en entrée corrects, arret de l'opération
		testNumber++;
    // Positionner une taille des données en sortie correcte
		rv = (*pFunctionList->C_Verify)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen, bufSignature, ulSignatureLen);
		checkPrintResult("C_Verify avec param" E_GRAVE "tres en entree corrects, arr" E_ACCENT "t de l'op" E_AIGUE "ration" ,rv,testNumber,MsgsTbl);
		

    // Il faut encore une fois reinitialiser une opération de vérification
    testNumber++;
    testFreeData(&pData, &ulDataLen);
    BuildFullHash(pFunctionList, sessionRO, (CK_CHAR_PTR)"document_to_sign", &pData, &ulDataLen, SHA1, CK_TRUE);

    rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("A nouveau, C_VerifyInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
    

    // C_Verify avec paramètres en entrée corrects
		testNumber++;
		rv = (*pFunctionList->C_Verify)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen, bufSignature, ulSignatureLen);
		checkPrintResult("C_Verify avec param" E_GRAVE "tres en entree corrects." ,rv,testNumber,MsgsTbl);
		

    testFreeData( &pData, &ulDataLen);

    rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

    /***********************************************/
    /*        tests C_VerifyUpdate()               */
    /***********************************************/

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    // Recuperer l'objet clé pubique de signature (AT_SIGNATURE)
    hObject = NULL_PTR;
    if (isContactLess == CK_TRUE) {
      // ... d'authentification pour le sans contact
      keyType = AT_KEYEXCHANGE;
    }
		testGetPkcs11Object(pFunctionList, sessionRO, VERISGN_FUNCTIONS, keyType, NULL_PTR, &hObject, NULL);

		// C_VerifyUpdate et opération non initialisée
		testNumber++;
		rv = (*pFunctionList->C_VerifyUpdate)(sessionRO, (CK_BYTE_PTR)"testtesttesttest", 16);
		checkPrintResult("C_VerifyUpdate et op" E_AIGUE "ration non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
		

		// C_VerifyUpdate et handle de session invalide
    testNumber++;
		sessionRO_Inv = 0xFFFFFFFF;
		rv = (*pFunctionList->C_VerifyUpdate)(sessionRO_Inv, (CK_BYTE_PTR)"testtesttesttest", 16);
		checkPrintResult("C_VerifyUpdate et handle de session invalide" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyInit et paramètres corrects
		testNumber++;
    // Positionner un mécanisme correct pour la clé publique de signature
    testSetMechanism(VERISGN_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("C_VerifyInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyUpdate et paramètre d'entrée invalide
		testNumber++;
		rv = (*pFunctionList->C_VerifyUpdate)(sessionRO, (CK_BYTE_PTR)NULL_PTR, 16);
		checkPrintResult("C_VerifyUpdate et param" E_GRAVE "tre d'entr" E_AIGUE "e invalide" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyUpdate et parametres en entrée corrects
		testNumber++;
    // Positionner des données incorrectes
    testSetData(VERISGN_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &pData, &ulDataLen);
		rv = (*pFunctionList->C_VerifyUpdate)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen);
		checkPrintResult("C_VerifyUpdate et param" E_GRAVE "tres en entr" E_AIGUE "e corrects" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyUpdate et parametres en entrée corrects
		testNumber++;
		rv = (*pFunctionList->C_VerifyUpdate)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen);
		checkPrintResult("C_VerifyUpdate et param" E_GRAVE "tres en entr" E_AIGUE "e corrects" ,rv,testNumber,MsgsTbl);
		

    testFreeData( &pData, &ulDataLen);

    rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

    /***********************************************/
    /*        tests C_VerifyFinal()                   */
    /***********************************************/

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

		// Recuperer l'objet clé publique de signature (AT_SIGNATURE)
    hObject = NULL_PTR;
		testGetPkcs11Object(pFunctionList, sessionRO, VERISGN_FUNCTIONS, keyType, NULL_PTR, &hObject, NULL);

		// C_VerifyFinal et opération non initialisée
		testNumber++;
    rv = (*pFunctionList->C_VerifyFinal)(sessionRO, (CK_BYTE_PTR)bufSignature_AT_SIGN, local_ulSignatureLen);
		checkPrintResult("C_VerifyFinal et op" E_AIGUE "ration non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
		

		// C_VerifyFinal et handle de session invalide
    testNumber++;
		sessionRO_Inv = 0xFFFFFFFF;
		rv = (*pFunctionList->C_VerifyFinal)(sessionRO_Inv, (CK_BYTE_PTR)bufSignature_AT_SIGN, local_ulSignatureLen);
		checkPrintResult("C_SignFinal et handle de session invalide" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyInit et paramètres corrects
		testNumber++;
    // Positionner un mécanisme correct pour la clé de signature
    testSetMechanism(VERISGN_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("C_VerifyInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyFinal et paramètre d'entrée invalide
		testNumber++;
    rv = (*pFunctionList->C_VerifyFinal)(sessionRO, (CK_BYTE_PTR)NULL_PTR, local_ulSignatureLen);
		checkPrintResult("C_VerifyFinal et param" E_GRAVE "tre d'entr" E_AIGUE "e invalide" ,rv,testNumber,MsgsTbl);

    // C_VerifyUpdate et parametres en entrée corrects
		testNumber++;
    // Positionner des données correctes
    testSetData(VERISGN_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &pData, &ulDataLen);
		rv = (*pFunctionList->C_VerifyUpdate)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen);
		checkPrintResult("C_VerifyUpdate avec des donn" E_AIGUE "es d'entr" E_AIGUE "e correctes" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyFinal et buffer de signature de taille insuffisante
		testNumber++;
    local_ulSignatureLen = 250;
    rv = (*pFunctionList->C_VerifyFinal)(sessionRO, bufSignature_AT_SIGN, local_ulSignatureLen);
		checkPrintResult("C_VerifyFinal et buffer de signature de taille insuffisante" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyFinal et buffer de signature de taille correcte - arret de l'opération
		testNumber++;
    local_ulSignatureLen = 256;
    rv = (*pFunctionList->C_VerifyFinal)(sessionRO, bufSignature_AT_SIGN, local_ulSignatureLen);
		checkPrintResult("C_VerifyFinal et buffer de signature de taille correcte, arret de l'opération" ,rv,testNumber,MsgsTbl);
		

    // De nouveau, appel C_VerifyInit et paramètres corrects
		testNumber++;
    // Positionner un mécanisme correct pour la clé de signature
    testSetMechanism(VERISGN_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("C_VerifyInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
		

    // De nouveau, appel C_VerifyUpdate et parametres en entrée corrects
		testNumber++;
    // Positionner des données correctes
    testSetData(VERISGN_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &pData, &ulDataLen);
		rv = (*pFunctionList->C_VerifyUpdate)(sessionRO, (CK_BYTE_PTR)pData, ulDataLen);
		checkPrintResult("C_VerifyUpdate avec des donn" E_AIGUE "es d'entr" E_AIGUE "e correctes" ,rv,testNumber,MsgsTbl);
		

    // C_VerifyFinal et buffer contenant la signature à vérifier
		testNumber++;
    rv = (*pFunctionList->C_VerifyFinal)(sessionRO, bufSignature_256, ulBufSignature_256Len);
		checkPrintResult("C_VerifyFinal et buffer contenant la signature " A_ACCENT " v" E_AIGUE "rifier" ,rv,testNumber,MsgsTbl);
		
    (*pFunctionList->C_Finalize)(NULL);

    rv = (*pFunctionList->C_Initialize)(NULL);

    if ((rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) && isContactLess == CK_FALSE)
    {
      CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
      CK_ULONG ulSlotsListSize = MAX_SLOTS;
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

      hObject = NULL_PTR;
      testGetPkcs11Object(pFunctionList, sessionRO, VERISGN_FUNCTIONS, AT_SIGNATURE, NULL, &hObject, NULL);

    // C_VerifyInit et signature de condensat avec AT_SIGNATURE
		testNumber++;
    // Positionner le mécanisme CKM_SHA1_RSA_PKCS pour la clé public de signature
    testSetMechanism(VERISGN_FUNCTIONS, AT_SIGNATURE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("C_VerifyInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);

    // C_Verify du condensat SHA256
		testNumber++;
    // Envoi des données à vérifier ...
    //BuildFullHash(pFunctionList, sessionRO, (CK_CHAR_PTR)"document_to_sign", &pData, &ulDataLen, SHA1);
      pData = (CK_BYTE_PTR)"document_to_sign";
      ulDataLen = strlen("document_to_sign");
    rv = (*pFunctionList->C_Verify)(sessionRO, pData, ulDataLen, pbySignature2, ulSignatureLen2);
		checkPrintResult("C_Verify et condensat SHA_1 a verifier" ,rv,testNumber,MsgsTbl);
		
      // C_VerifyInit et signature de condensat avec AT_SIGNATURE
      testNumber++;
      // Positionner le mécanisme CKM_SHA256_RSA_PKCS pour la clé public de signature
      testMecha.mechanism = CKM_SHA256_RSA_PKCS;
      testMecha.pParameter = NULL;
      rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
      checkPrintResult("C_VerifyInit et param" E_GRAVE"tres corrects", rv, testNumber, MsgsTbl);

      // C_Verify du condensat 
      testNumber++;
      // Envoi des données à vérifier ...
      pData = (CK_BYTE_PTR)"document_to_sign";
      ulDataLen = strlen("document_to_sign");
      rv = (*pFunctionList->C_Verify)(sessionRO, pData, ulDataLen, pbySignature3, ulSignatureLen3);
      checkPrintResult("C_Verify et condensat SHA_256 a verifier", rv, testNumber, MsgsTbl);

      //testFreeData(&pData, &ulDataLen);
    if(pbySignature2)
      free(pbySignature2);
      if (pbySignature3)
        free(pbySignature3);

    rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

  }
    (*pFunctionList->C_Finalize)(NULL);
}
}

/* Define for CPS2ter Cryptolib */
#define CKA_CPS_KEY_TYPE								CKA_VENDOR_DEFINED+1
CK_RV testAuthenSansContact(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_CHAR_PTR pin, CK_SLOT_ID slotId, int * testNumber);
CK_RV testAuthenWithKeys(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_SLOT_ID slotId, int * testNumber);

//*******************************************************************
//Effectue les tests de signature sans contact
//*******************************************************************
void testContactlessSignatureManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin)
{
  int testNumber = getIndexDebutSectionTests(CONTACTLESS_TEST_CPS3);
	CK_RV rv;
	CK_SESSION_HANDLE sessionRO = 0xFFFFFFFF;
	unsigned long objCount = 0;

	CK_OBJECT_HANDLE hObject=0;

  /*printf("Ins" E_AIGUE "rer une carte CPS pour les tests sans contact...");
  getchar();*/
	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
		CK_ULONG ulSlotsListSize = MAX_SLOTS;
    //CK_ULONG ulSignatureLen = 64;

		//recupération de la liste des slots avec carte
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
		if (rv != CKR_OK || ulSlotsListSize == 0) return;

		currentSlotID = tabSlots[0];
		

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
    checkPrintResult("C_OpenSession contactless" ,rv,testNumber,MsgsTbl);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}
    testNumber++;
    testAuthenSansContact(pFunctionList, sessionRO, pin, currentSlotID, &testNumber);
  }
}

CK_RV testAuthenSansContact(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_CHAR_PTR pin, CK_SLOT_ID slotId, int * testNumber) {
  CK_RV rv=CKR_OK;
  CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
  CK_BYTE_PTR pLabelKPriv=(CK_BYTE_PTR)"CPS_PRIV_AUT";
  CK_BYTE_PTR pLabelKPrivTech=(CK_BYTE_PTR)"CPS_PRIV_TECH_AUT";
  unsigned keyTypePriv ='S';
  unsigned keyTypePrivTech ='A';
  //CK_BYTE keyId[]={1,2,3,4};
  
  CK_ATTRIBUTE privKeyTemplate[] = {
    //		{CKA_ID, keyId, sizeof(keyId)},
    {CKA_CLASS,&privKeyClass,sizeof(privKeyClass)},
    {CKA_LABEL,pLabelKPriv,strlen((char *)pLabelKPriv)}
  };
  
  CK_ATTRIBUTE privKeyTechTemplate[] = {
    //		{CKA_ID, keyId, sizeof(keyId)},
    {CKA_CLASS,&privKeyClass,sizeof(privKeyClass)},
    {CKA_LABEL,pLabelKPrivTech,strlen((char *)pLabelKPrivTech)}
  };

  CK_ATTRIBUTE oldPrivKeyTemplate[] = {
    {CKA_CLASS,&privKeyClass,sizeof(privKeyClass)},
	{CKA_CPS_KEY_TYPE,&keyTypePriv,sizeof(keyTypePriv)}
  };

  CK_ATTRIBUTE oldPrivTechKeyTemplate[] = {
    {CKA_CLASS,&privKeyClass,sizeof(privKeyClass)},
	{CKA_CPS_KEY_TYPE,&keyTypePrivTech,sizeof(keyTypePrivTech)}
  };

  CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
  
  CK_ATTRIBUTE pubKeyTemplate[] = {
    {CKA_ID, NULL, 0},
    {CKA_CLASS,&pubKeyClass,sizeof(pubKeyClass)}
  };
  
  
  CK_ULONG keyListSize =1;
  CK_OBJECT_HANDLE hPrivateKey,hPublicKey;
  
  //traceInFile(TRACE_INFO, (CK_CHAR_PTR)"------------- testAuthen");
  
  //CK_BYTE pin[]="1234";
  rv=(*pFunctionList->C_Login)(hSession,CKU_USER,pin,strlen((char *)pin));
  checkPrintResult("C_Login utilisateur CKU_USER" ,rv,*testNumber,MsgsTbl);
		
  if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN && rv!=CKR_USER_PIN_NOT_INITIALIZED)
		goto end_sign;
  
  if (rv==CKR_USER_PIN_NOT_INITIALIZED) { /* c'est de l'authentification avec le sans contact */
	  if(isCPS3) {
      (*testNumber)++;
		  rv=(*pFunctionList->C_FindObjectsInit)(hSession, privKeyTechTemplate, sizeof(privKeyTechTemplate)/sizeof(CK_ATTRIBUTE));
      checkPrintResult("C_FindObjectsInit (CL) recherche cl" E_AIGUE " priv" E_AIGUE "e" ,rv,*testNumber,MsgsTbl);
    }
	  else
		rv=(*pFunctionList->C_FindObjectsInit)(hSession, oldPrivTechKeyTemplate, sizeof(oldPrivTechKeyTemplate)/sizeof(CK_ATTRIBUTE));
  } else {
	  if(isCPS3) {
      (*testNumber)++;
		  rv=(*pFunctionList->C_FindObjectsInit)(hSession, privKeyTemplate, sizeof(privKeyTemplate)/sizeof(CK_ATTRIBUTE)); 
      checkPrintResult("C_FindObjectsInit recherche cl" E_AIGUE " priv" E_AIGUE "e" ,rv,*testNumber,MsgsTbl);
    }
	  else
		rv=(*pFunctionList->C_FindObjectsInit)(hSession, oldPrivTechKeyTemplate, sizeof(oldPrivKeyTemplate)/sizeof(CK_ATTRIBUTE)); 
  }
  if (rv!=CKR_OK) goto end_sign;

  // FindObjects
  (*testNumber)++;
  rv = (*pFunctionList->C_FindObjects)(hSession,&hPrivateKey,1, &keyListSize);
  checkPrintResult("C_FindObjects (CL) recherche cl" E_AIGUE " priv" E_AIGUE "e" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;

  // C_FindObjectsFinal
  (*testNumber)++;
  rv=(*pFunctionList->C_FindObjectsFinal)(hSession);
  checkPrintResult("C_FindObjectsFinal (CL) recherche cl" E_AIGUE " priv" E_AIGUE "e" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;

  // C_GetAttributeValue
  (*testNumber)++;
  rv=(*pFunctionList->C_GetAttributeValue)(hSession,hPrivateKey,&pubKeyTemplate[0],1);
  checkPrintResult("C_GetAttributeValue recherche cl" E_AIGUE " priv" E_AIGUE "e" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK)
		goto end_sign;

  // C_GetAttributeValue
  pubKeyTemplate[0].pValue=malloc(pubKeyTemplate[0].ulValueLen*sizeof(CK_BYTE));
  (*testNumber)++;
  rv=(*pFunctionList->C_GetAttributeValue)(hSession,hPrivateKey,&pubKeyTemplate[0],1);
  checkPrintResult("C_GetAttributeValue recherche cl" E_AIGUE " priv" E_AIGUE "e" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK)	
		goto end_sign;
  
  /* rechercher la clé publique pour vérifier la signature */
  (*testNumber)++;
  rv=(*pFunctionList->C_FindObjectsInit)(hSession, pubKeyTemplate, sizeof(pubKeyTemplate)/sizeof(CK_ATTRIBUTE)); 
  checkPrintResult("C_FindObjectsInit recherche cl" E_AIGUE " publique" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;

  // C_FindObjects
  (*testNumber)++;
  rv = (*pFunctionList->C_FindObjects)(hSession,&hPublicKey, 1,&keyListSize);
  checkPrintResult("C_FindObjects recherche cl" E_AIGUE " publique" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;

  // C_FindObjectsFinal
  (*testNumber)++;
  rv=(*pFunctionList->C_FindObjectsFinal)(hSession);
  checkPrintResult("C_FindObjectsFinal recherche cl" E_AIGUE " publique" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;
  rv = testAuthenWithKeys(pFunctionList, hSession, hPublicKey, hPrivateKey, slotId, testNumber);
  
end_sign:	
  printf("------------- testAuthen: %d", rv);
  return rv;
}

CK_RV testAuthenWithKeys(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey, CK_SLOT_ID slotId, int * testNumber) {
  CK_RV rv=CKR_OK;
  CK_BYTE_PTR pMessageCourt=(CK_BYTE_PTR)"Message court, de 33 octets maxi.";
  CK_BYTE_PTR pMessage=pMessageCourt;
  CK_BYTE_PTR pMessage1=(CK_BYTE_PTR)"Mess";
  CK_BYTE_PTR pMessage2=(CK_BYTE_PTR)"age";
  CK_ULONG ulMessage=strlen((char *)pMessage);
  CK_ULONG ulMessage1=4;
  CK_ULONG ulMessage2=3;
  CK_BYTE_PTR pSignature=NULL;
  CK_ULONG ulSignature=0;
  CK_BYTE_PTR pSignature1=NULL;
  CK_ULONG ulSignature1=0;
  CK_ULONG i;


  CK_MECHANISM mechanism = {
    CKM_SHA1_RSA_PKCS, NULL_PTR,0
  };
  
  CK_MECHANISM mechanism1 = {
    CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR,0
  };
  
  CK_MECHANISM mechanism2 = {
    CKM_RSA_PKCS, NULL_PTR,0
  };
  
  CK_MECHANISM mechanism3 = {
    CKM_RSA_X_509, NULL_PTR,0
  };

  if(!isCPS3) {
	  mechanism1.mechanism = CKM_SHA256_RSA_PKCS;
	  mechanism2.mechanism = CKM_SHA1_RSA_PKCS;
  }
  
  /*Vérifier un mauvais méchanisme pour la signature */
  (*testNumber)++;
  rv=(*pFunctionList->C_SignInit)(hSession,&mechanism1,hPrivateKey);
  checkPrintResult("C_SignInit et mauvais m" E_AIGUE "canisme" ,rv,*testNumber,MsgsTbl);
  if (rv==CKR_OK) { /* c'est inattendu mais la p11 de Gemalto se moque de l'algo */
			/* pour éviter d'avoir l'erreur CKR_OPERATION_ACTIVE au prochain appel */
    (*testNumber)++;
		int rv2=(*pFunctionList->C_Sign)(hSession,pMessage,ulMessage,NULL,&ulSignature);
    checkPrintResult("C_Sign et test specifique Gemalto",rv2, *testNumber, MsgsTbl);
		if (rv2!=CKR_OK) goto end_sign;
		pSignature=(CK_BYTE_PTR)malloc(ulSignature*sizeof(CK_BYTE));

    (*testNumber)++;
		rv=(*pFunctionList->C_Sign)(hSession,pMessage,ulMessage,pSignature,&ulSignature);
    
    checkPrintResult("C_Sign et test specifique Gemalto" ,rv,*testNumber,MsgsTbl);
		if (pSignature!=NULL) {
			free(pSignature); 
			pSignature=NULL;
		}
  }
  if (rv!=CKR_MECHANISM_INVALID && rv!=CKR_OK) goto end_sign;
  
  // C_SignInit cas normal
  (*testNumber)++;
  rv=(*pFunctionList->C_SignInit)(hSession,&mechanism2,hPrivateKey);
  
  checkPrintResult("C_SignInit dans cas normal" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;
  if(isCPS3) {
    (*testNumber)++;
	  rv=(*pFunctionList->C_SignInit)(hSession,&mechanism3,hPrivateKey);
    
    checkPrintResult("C_SignInit et operation active" ,rv,*testNumber,MsgsTbl);
	  if (rv!=CKR_OPERATION_ACTIVE) goto end_sign;
  }

  /*Signature d'un coup */
  (*testNumber)++;
  rv=(*pFunctionList->C_Sign)(hSession,pMessage,ulMessage,NULL,&ulSignature);
  
  checkPrintResult("C_Sign et parametres corrects (taille)" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;
  pSignature=(CK_BYTE_PTR)malloc(ulSignature*sizeof(CK_BYTE));
  (*testNumber)++;
  rv=(*pFunctionList->C_Sign)(hSession,pMessage,ulMessage,pSignature,&ulSignature);
  
  checkPrintResult("C_Sign et parametres corrects (valeur)" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;
  
  /*Signature par morceau avec un message court */
  (*testNumber)++;
  rv=(*pFunctionList->C_SignInit)(hSession,&mechanism2,hPrivateKey);
  checkPrintResult("C_SignInit et parametres corrects" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;

  (*testNumber)++;
  rv=(*pFunctionList->C_SignUpdate)(hSession,pMessage1,ulMessage1);
  checkPrintResult("C_SignUpdate et parametres corrects" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;

  (*testNumber)++;
  rv=(*pFunctionList->C_SignUpdate)(hSession,pMessage2,ulMessage2);
  checkPrintResult("C_SignUpdate et parametres corrects" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;

  (*testNumber)++;
  rv=(*pFunctionList->C_SignFinal)(hSession,NULL,&ulSignature1);
  checkPrintResult("C_SignFinal et parametres corrects (taille)" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;

  (*testNumber)++;
  pSignature1=(CK_BYTE_PTR)malloc(ulSignature1*sizeof(CK_BYTE));
  rv=(*pFunctionList->C_SignFinal)(hSession,pSignature1,&ulSignature1);
  checkPrintResult("C_SignFinal et parametres corrects (valeur)" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;
  
  /* Signature par morceau avec le même message */
  (*testNumber)++;
  rv=(*pFunctionList->C_SignInit)(hSession,&mechanism2,hPrivateKey);
  checkPrintResult("C_SignInit et parametres corrects" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;
  for (i=0;i<ulMessage;i++) {
	  if (i%20==0) {
		  CK_ULONG len=ulMessage-i;
		  if (len>20)
			  len=20;
      (*testNumber)++;
		  rv=(*pFunctionList->C_SignUpdate)(hSession,pMessage+i,len);
      checkPrintResult("C_SignUpdate et parametres corrects" ,rv,*testNumber,MsgsTbl);
      (*testNumber)--;
		  if (rv!=CKR_OK) goto end_sign;
	  }
  }

  (*testNumber)+=2;
  rv=(*pFunctionList->C_SignFinal)(hSession,NULL,&ulSignature1);
  checkPrintResult("C_SignFinal et parametres corrects" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;
  pSignature1=(CK_BYTE_PTR)malloc(ulSignature1*sizeof(CK_BYTE));
  (*testNumber)++;
  rv=(*pFunctionList->C_SignFinal)(hSession,pSignature1,&ulSignature1);
  checkPrintResult("C_SignFinal et parametres corrects" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;
  
  rv=memcmp(pSignature,pSignature1,ulSignature1);
  if(rv!=0) goto end_sign;
  
  /*Vérifier la signature */
  (*testNumber)++;
  rv=(*pFunctionList->C_VerifyInit)(hSession,&mechanism2,hPublicKey);
  checkPrintResult("C_VerifyInit et parametres corrects" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;

  // C_Verify
  (*testNumber)++;
  rv=(*pFunctionList->C_Verify)(hSession,pMessage,ulMessage,pSignature,ulSignature);
  checkPrintResult("C_Verify et parametres corrects" ,rv,*testNumber,MsgsTbl);
  if (rv!=CKR_OK) goto end_sign;
  
  if (pSignature!=NULL) {
    free(pSignature); 
    pSignature=NULL;
  }
  if (pSignature1!=NULL) {
    free(pSignature1);
    pSignature1=NULL;
  }
  return rv;
  
end_sign:	
  if (pSignature!=NULL) free(pSignature);
  if (pSignature1!=NULL) free(pSignature1);
  return rv;
}

//*******************************************************************
//Effectue les tests de signature avec le SHA 256
//*******************************************************************
void testSignatureSHA256ManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BYTE_PTR bufSignature_256, CK_ULONG_PTR pulBufSignature_256Len)
{
  int testNumber = getIndexDebutSectionTests(SIGSHA256_FUNCTIONS);
	CK_RV rv;
	CK_SESSION_HANDLE sessionRO = 0xFFFFFFFF;
	CK_MECHANISM testMecha;
	unsigned long objCount = 0;
  unsigned short keyType = AT_SIGNATURE;
	CK_OBJECT_HANDLE hObject = NULL;
  CK_BYTE_PTR pSignature1 = NULL_PTR;
  CK_ULONG ulSignature1;
  CK_SLOT_ID currentSlotID;

	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		CK_SLOT_ID tabSlots[MAX_SLOTS];
		CK_ULONG ulSlotsListSize = MAX_SLOTS;
		//recupération de la liste des slots avec carte
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
		if (rv != CKR_OK || ulSlotsListSize == 0) return;

		currentSlotID = tabSlots[0];		

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
    
    checkPrintResult("C_OpenSession ouverture de session" ,rv,testNumber,MsgsTbl);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    // login utilisateur
    testNumber++;
    if (isContactLess == CK_TRUE) {
      keyType = AT_KEYEXCHANGE;
      MsgsTbl[testNumber].usExpectedRc = CKR_USER_PIN_NOT_INITIALIZED;
    }
	  rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);
    checkPrintResult("C_Login avec code porteur correct" ,rv,testNumber,MsgsTbl);		
    if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN && rv!=CKR_USER_PIN_NOT_INITIALIZED) goto end_sign;

    /////////// Calcul de la signature SHA_256 /////////////////////

		// Recuperer l'objet clé privée de signature (AT_SIGNATURE)
		testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, keyType, pin, &hObject, NULL);

    // C_SignInit et paramètres corrects
		testNumber++;
    // Positionner un mécanisme correct pour la clé de signature
    testSetMechanism(SIGSHA256_FUNCTIONS, keyType, MsgsTbl[testNumber].usExpectedRc, &testMecha);
    if (!isCPS3 || isContactLess == CK_TRUE) {
      // si on n'est pas en CPS3, le mecanisme n'est pas supporte en CPS2ter
      MsgsTbl[testNumber].usExpectedRc = CKR_MECHANISM_INVALID;
    }
		rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);
		checkPrintResult("C_SignInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
    if (rv!=CKR_OK) goto end_sign;

    char * pMessage = "Sollemnia ita ita ita in regis imitatus renidens ut quemquam gnarus pectore superbiam cum legum cruciatibus excarnificari inpegit gnarus tandem tandem regis sputamine accusatorem intrepidus abiecto pertinacius pectore Stoicum pertinacius superbiam nec nec Cyprii temporum illum intrepidus iniquitati quemquam qui obtrectatorem sputamine quaedam renidens inpegit laceratus poenali id insultans tamquam tamquam interrogantis incusare superbiam torvum sedibus Stoicum alium alium deessent ut pectore nec qui id abiecto et libertatemque mentiretur deessent cum Cyprii quemquam ita regis excarnificari excarnificari multatus cum quaedam poenali praecepit intrepidus cruciatibus veterem tamquam superbiam confessus evisceratus ita caelo sollemnia excarnificari morte flagitaret linguam obtrectatorem flagitaret temporum pectore."; 
    CK_ULONG ulMessage = strlen(pMessage);
    for (int i=0; i<(int)ulMessage; i++) {
      // C_SignUpdate et paramètres corrects
      if (i % 80 == 0) {
         CK_ULONG len=ulMessage-i;
		     if (len>80)
			     len=80;
		    testNumber++;
		    rv = (*pFunctionList->C_SignUpdate)(sessionRO, (CK_CHAR_PTR)(pMessage + i), len);
        
		    checkPrintResult("C_SignUpdate et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
        testNumber--;
        if (rv!=CKR_OK) goto end_sign;
      }
    }

   
     testNumber+=2;
     rv=(*pFunctionList->C_SignFinal)(sessionRO,NULL,&ulSignature1);
     checkPrintResult("C_SignFinal et parametres corrects" ,rv,testNumber,MsgsTbl);
     if (rv!=CKR_OK) goto end_sign;
     pSignature1=(CK_BYTE_PTR)malloc(ulSignature1*sizeof(CK_BYTE));
     testNumber++;
     rv=(*pFunctionList->C_SignFinal)(sessionRO,pSignature1,&ulSignature1);
     checkPrintResult("C_SignFinal et parametres corrects" ,rv,testNumber,MsgsTbl);
     if (rv!=CKR_OK) goto end_sign;

     /////////// Vérification de la signature SHA_256 /////////////////////

     // Recuperer l'objet clé publique de signature (AT_SIGNATURE)
		 testGetPkcs11Object(pFunctionList, sessionRO, VERISGN_FUNCTIONS, AT_SIGNATURE, NULL, &hObject, NULL);
     // C_VerifyInit et paramètres corrects
		 testNumber++;
     // Positionner le mécanisme CKM_SHA256_RSA_PKCS pour la clé de signature
     testSetMechanism(SIGSHA256_FUNCTIONS, AT_SIGNATURE, MsgsTbl[testNumber].usExpectedRc, &testMecha);
		 rv = (*pFunctionList->C_VerifyInit)(sessionRO, &testMecha, hObject);
		 checkPrintResult("C_VerifyInit et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
     if (rv!=CKR_OK) goto end_sign;

     
    ulMessage = strlen(pMessage);
    for (int i=0; i<(int)ulMessage; i++) {
      // C_VerifyUpdate et paramètres corrects
      if (i % 80 == 0) {
         CK_ULONG len=ulMessage-i;
		     if (len>80)
			     len=80;
		    testNumber++;
		    rv = (*pFunctionList->C_VerifyUpdate)(sessionRO, (CK_CHAR_PTR)(pMessage + i), len);
		    checkPrintResult("C_VerifyUpdate et param" E_GRAVE "tres corrects" ,rv,testNumber,MsgsTbl);
        testNumber--;
        if (rv!=CKR_OK) goto end_sign;
      }
    }

   
     testNumber+=2;
     // C_VerifyFinal verification effective de la signature par morceaux
     rv=(*pFunctionList->C_VerifyFinal)(sessionRO, pSignature1, ulSignature1);
     checkPrintResult("C_VerifyFinal et parametres corrects" ,rv,testNumber,MsgsTbl);
     if (rv!=CKR_OK) goto end_sign;
 
  }
end_sign:
  if (pSignature1!=NULL) free(pSignature1);

  rv = (*pFunctionList->C_CloseAllSessions)(currentSlotID);

  (*pFunctionList->C_Finalize)(NULL);
}