#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "testconstants.h"

extern sTESTS_MSGS     MsgsTbl[];
extern CK_BBOOL isCPS2TerGALSS;
extern CK_BBOOL isCPS2TerPCSC;

extern char *getErrorCodeString(CK_RV error, char * strError);
extern int ConsigneResultatCSV(unsigned short __usTestNumero, unsigned long usRc, unsigned long usExpectedRc, char * libelle);
extern unsigned short getIndexDebutSectionTests(int searchedTestLevel);
extern int testGetPkcs11Object(CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, int testLevel, int keySpec,  CK_CHAR_PTR pin, CK_OBJECT_HANDLE_PTR phObject, int * pTestNumber);
extern void testSetMechanism(int testLevel, int keySpec, CK_RV expectedRv, CK_MECHANISM_PTR pMechanism);
extern void testSetData(int testLevel, int keySpec, CK_RV expectedRv, CK_BYTE_PTR * ppData, CK_ULONG_PTR pulDataLen);
extern void checkPrintResult(char * mesgTest, CK_RV rv, int testNumber, sTESTS_MSGS * table);
extern void testFreeData(CK_BYTE_PTR * ppData, CK_ULONG_PTR pulDataLen);

CK_RV testModifyDataObject(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hRWSession, CK_CHAR_PTR pin, int * testNumber);
CK_RV testCpsActivityObject(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hRWSession, CK_CHAR_PTR pin, int * testNumber);
CK_RV testCpsPorteurObject(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hRWSession, CK_CHAR_PTR pin, int * testNumber);
CK_RV testCpsCertificatObject(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hRWSession, CK_CHAR_PTR pin, int * testNumber);


//*******************************************************************
//Effectue les tests sur l'objet CPS_DATA (CPS3)
//*******************************************************************
void testCpsDataObject(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin)
{
  int testNumber = getIndexDebutSectionTests(CPSDATA_TEST_CPS3);
	CK_RV rv;
	CK_SESSION_HANDLE sessionRO = 0xFFFFFFFF;
  CK_SESSION_HANDLE hRWSession = 0xFFFFFFFF;
	//CK_MECHANISM testMecha;
	unsigned long objCount = 0;

	CK_OBJECT_HANDLE hObject=0;

	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED && isContactLess == CK_FALSE)
	{
		CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
		CK_ULONG ulSlotsListSize = MAX_SLOTS;
		//recupération de la liste des slots avec carte
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
		if (rv != CKR_OK || ulSlotsListSize == 0) return;

		currentSlotID = tabSlots[0];
		

		//ouverture d'une session en lecture seule sur le premier slot
		rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    //ouverture d'une session en lecture ecriture sur le premier slot
    rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hRWSession);
    checkPrintResult("C_OpenSession avec session RW" ,rv,testNumber,MsgsTbl);
	
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    testModifyDataObject(pFunctionList, sessionRO, hRWSession, pin, &testNumber);
		
  }

    rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED && isContactLess == CK_FALSE)
	{
		CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
		CK_ULONG ulSlotsListSize = MAX_SLOTS;
		//recupération de la liste des slots avec carte
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
		if (rv != CKR_OK || ulSlotsListSize == 0) return;

		currentSlotID = tabSlots[0];

    //ouverture d'une session en lecture seule sur le premier slot
    rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
    checkPrintResult("C_OpenSession avec session RO" ,rv,testNumber,MsgsTbl);
	
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    testCpsActivityObject(pFunctionList, sessionRO, hRWSession, pin, &testNumber);
    }

    rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED && isContactLess == CK_FALSE)
	{
		CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
		CK_ULONG ulSlotsListSize = MAX_SLOTS;
		//recupération de la liste des slots avec carte
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
		if (rv != CKR_OK || ulSlotsListSize == 0) return;

		currentSlotID = tabSlots[0];

    //ouverture d'une session en lecture seule sur le premier slot
    rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
    checkPrintResult("C_OpenSession avec session RO" ,rv,testNumber,MsgsTbl);
	
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

       testCpsPorteurObject(pFunctionList, sessionRO, hRWSession, pin, &testNumber);
    }

    rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
		CK_ULONG ulSlotsListSize = MAX_SLOTS;
		//recupération de la liste des slots avec carte
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
		if (rv != CKR_OK || ulSlotsListSize == 0) return;

		currentSlotID = tabSlots[0];

    //ouverture d'une session en lecture seule sur le premier slot
    rv = (*pFunctionList->C_OpenSession)(currentSlotID,CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
    checkPrintResult("C_OpenSession avec session RO" ,rv,testNumber,MsgsTbl);
	
		if (rv != CKR_OK) {
			(*pFunctionList->C_Finalize)(NULL);
			return;
		}

    testCpsCertificatObject(pFunctionList, sessionRO, hRWSession, pin, &testNumber);
    }
}

CK_RV testModifyDataObject(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hRWSession, CK_CHAR_PTR pin, int * testNumber) {

  CK_RV rv=CKR_OK;
  CK_CHAR localPin[9];
  CK_BBOOL vrai=TRUE;
  CK_OBJECT_CLASS dataClass=CKO_DATA;
  CK_CHAR dataLabel[]="CPS_DATA";
  CK_ATTRIBUTE dataTemplate[]={	{CKA_CLASS, &dataClass, sizeof(dataClass)},
  {CKA_TOKEN, &vrai, sizeof(vrai)},
  {CKA_MODIFIABLE, &vrai, sizeof(vrai)},
  {CKA_LABEL, dataLabel, strlen((char *)dataLabel)}
  };
  CK_ULONG dataTemplateSize=sizeof(dataTemplate)/sizeof(CK_ATTRIBUTE);
  CK_ATTRIBUTE dataValueTemplate[]={{CKA_VALUE, NULL, 0}};
  CK_ATTRIBUTE dataValueModTemplate[]={{CKA_VALUE, NULL, 0}};
  CK_ULONG dataValueTemplateSize=sizeof(dataValueTemplate)/sizeof(CK_ATTRIBUTE);
  CK_OBJECT_HANDLE hObject=0;
  CK_ULONG i;
  
	/*traceInFile(TRACE_INFO,(CK_CHAR_PTR)"------------- testModifyDataObject :");*/
  // login utilisateur
  (*testNumber)++;
  rv=(*pFunctionList->C_Login)(hSession,CKU_USER,pin,strlen((char *)pin));
  
  checkPrintResult("C_Login avec code porteur correct" ,rv,*testNumber,MsgsTbl);
		
  if (rv == CKR_PIN_INCORRECT) {
    printf("Code pin '%s' incorrect, saisissez le code pin de la carte :", pin);
#ifdef _WIN32
        gets_s((char *)localPin,sizeof(localPin));
#else 
        fgets((char *)localPin, sizeof(localPin), stdin);
#endif

    rv=(*pFunctionList->C_Login)(hSession,CKU_USER,localPin,strlen((char *)localPin));
  }
  if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN && rv!=CKR_USER_PIN_NOT_INITIALIZED) return rv;

  if (rv==CKR_USER_PIN_NOT_INITIALIZED) {
	  rv = CKR_OK; // pas la peine d'aller plus loin, ce n'est pas modifiable en sans contact
		goto end_modify_object;
  }
  (*testNumber)++;
  rv=(*pFunctionList->C_FindObjectsInit)(hSession, dataTemplate, dataTemplateSize);
  
  checkPrintResult("C_FindObjectsInit avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);
	
  if (rv!=CKR_OK) goto end_modify_object;
  while (TRUE) {
    CK_OBJECT_HANDLE objectHandle[]={0,0};
    CK_ULONG i,nbObject=0;

    (*testNumber)++;
    rv=(*pFunctionList->C_FindObjects)(hSession, objectHandle, sizeof(objectHandle)/sizeof(CK_OBJECT_HANDLE), &nbObject);
    
    checkPrintResult("C_FindObjects avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);
	
    if (rv!=CKR_OK) goto end_modify_object;
    
    for (i=0;i<nbObject;i++) {
      hObject=objectHandle[i];
    }
    
    if (nbObject!=sizeof(objectHandle)/sizeof(CK_OBJECT_HANDLE))
      break;
  }

  (*testNumber)++;
  rv=(*pFunctionList->C_FindObjectsFinal)(hSession);
  
  checkPrintResult("C_FindObjectsFinal avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);
	
  if (rv!=CKR_OK) goto end_modify_object;

	if (hObject==0) {
	  rv = CKR_OK; // c'est probablement une carte CPS2ter, rien à modifier donc
		goto end_modify_object;
  }
 
  (*testNumber)++;
  rv=(*pFunctionList->C_GetAttributeValue)(hSession, hObject, dataValueTemplate, dataValueTemplateSize);
  
  checkPrintResult("C_GetAttributeValue r" E_AIGUE "cup" E_AIGUE "ration taille objet" ,rv,*testNumber,MsgsTbl);

  if (rv!=CKR_OK) goto end_modify_object;
  
  (*testNumber)++;
  dataValueTemplate[0].pValue=malloc(dataValueTemplate[0].ulValueLen*sizeof(CK_BYTE));
  rv=(*pFunctionList->C_GetAttributeValue)(hSession, hObject, dataValueTemplate, dataValueTemplateSize);
  
  checkPrintResult("C_GetAttributeValue r" E_AIGUE "cup" E_AIGUE "ration valeur objet" ,rv,*testNumber,MsgsTbl);

  if (rv!=CKR_OK) goto end_modify_object;
  
  dataValueModTemplate[0].pValue=malloc(dataValueTemplate[0].ulValueLen*sizeof(CK_BYTE));
  dataValueModTemplate[0].ulValueLen=dataValueTemplate[0].ulValueLen;
  for (i=0;i<dataValueTemplate[0].ulValueLen;i++) {
	  ((CK_BYTE_PTR)dataValueModTemplate[0].pValue)[i]=((CK_BYTE_PTR)dataValueTemplate[0].pValue)[i]+(CK_BYTE)i;
  }

  (*testNumber)++;
  rv=(*pFunctionList->C_SetAttributeValue)(hRWSession, hObject, dataValueModTemplate, dataValueTemplateSize);
  
  checkPrintResult("C_SetAttributeValue positionner nouvelle valeur objet" ,rv,*testNumber,MsgsTbl);

	if (rv==CKR_SESSION_READ_ONLY) {
		CK_SESSION_INFO sessionInfo;
		(*pFunctionList->C_GetSessionInfo)(hSession, &sessionInfo);
		if (sessionInfo.state&CKS_RO_USER_FUNCTIONS)
			  rv=(*pFunctionList->C_SetAttributeValue)(hRWSession, hObject, dataValueModTemplate, dataValueTemplateSize);
		else
			goto end_modify_object;
	}
  if (rv!=CKR_OK) goto end_modify_object;
  
  // Recuperation valeur objet modifié
  (*testNumber)++;
  rv=(*pFunctionList->C_GetAttributeValue)(hSession, hObject, dataValueTemplate, dataValueTemplateSize);
  
  checkPrintResult("C_GetAttributeValue r" E_GRAVE "cup" E_GRAVE "ration valeur objet" ,rv,*testNumber,MsgsTbl);

  if (rv!=CKR_OK) goto end_modify_object;

	if (memcmp(dataValueTemplate[0].pValue, dataValueModTemplate[0].pValue, dataValueTemplate[0].ulValueLen)!=0) {
	  rv = CKR_DATA_INVALID;
		goto end_modify_object;
  }

end_modify_object:	
	/*traceInFileRet(TRACE_INFO,(CK_CHAR_PTR)"------------- testModifyDataObject", rv);*/
  (*pFunctionList->C_Finalize)(NULL);
  if (dataValueTemplate[0].pValue!=NULL)
    free(dataValueTemplate[0].pValue);
  if (dataValueModTemplate[0].pValue!=NULL)
    free(dataValueModTemplate[0].pValue);
  return rv;
}

CK_RV testCpsActivityObject(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hRWSession, CK_CHAR_PTR pin, int * testNumber) {
  
    CK_RV rv=CKR_OK;
    CK_CHAR localPin[9];
    CK_BBOOL vrai=TRUE;
    CK_OBJECT_CLASS dataClass=CKO_DATA;
    CK_CHAR dataLabel[]="CPS_ACTIVITY_01_PS";
    CK_ATTRIBUTE dataTemplate[]={	{CKA_CLASS, &dataClass, sizeof(dataClass)},
    {CKA_TOKEN, &vrai, sizeof(vrai)},
    {CKA_PRIVATE, &vrai, sizeof(vrai)},
    {CKA_LABEL, dataLabel, strlen((char *)dataLabel)}
    };
    CK_ULONG dataTemplateSize=sizeof(dataTemplate)/sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE dataValueTemplate[]={{CKA_VALUE, NULL, 0}};
    CK_ULONG dataValueTemplateSize=sizeof(dataValueTemplate)/sizeof(CK_ATTRIBUTE);
    CK_OBJECT_HANDLE hObject=0;
    CK_OBJECT_HANDLE objectHandle[]={0,0};
    CK_ULONG nbObject=0;

    /*traceInFile(TRACE_INFO,(CK_CHAR_PTR)"------------- testCpsActivityObject :");*/
    // login utilisateur
    (*testNumber)++;
    rv=(*pFunctionList->C_Login)(hSession,CKU_USER,pin,strlen((char *)pin));

    checkPrintResult("C_Login avec code porteur correct" ,rv,*testNumber,MsgsTbl);

    if (rv == CKR_PIN_INCORRECT) {
        printf("Code pin '%s' incorrect, saisissez le code pin de la carte :", pin);
#ifdef _WIN32
        gets_s((char *)localPin, sizeof(localPin));
#else 
        fgets((char *)localPin, sizeof(localPin), stdin);
#endif
        rv=(*pFunctionList->C_Login)(hSession,CKU_USER,localPin,strlen((char *)localPin));    
    }
    if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN && rv!=CKR_USER_PIN_NOT_INITIALIZED) return rv;

    if (rv==CKR_USER_PIN_NOT_INITIALIZED) {
        rv = CKR_OK; // pas la peine d'aller plus loin, ce n'est pas modifiable en sans contact
        goto end_activity_object;
    }
    (*testNumber)++;
    rv=(*pFunctionList->C_FindObjectsInit)(hSession, dataTemplate, dataTemplateSize);

    checkPrintResult("C_FindObjectsInit avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_activity_object;

    (*testNumber)++;
    rv=(*pFunctionList->C_FindObjects)(hSession, objectHandle, sizeof(objectHandle)/sizeof(CK_OBJECT_HANDLE), &nbObject);

    checkPrintResult("C_FindObjects avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK || nbObject == 0) goto end_activity_object;

    hObject=objectHandle[0];

    (*testNumber)++;
    rv=(*pFunctionList->C_FindObjectsFinal)(hSession);

    checkPrintResult("C_FindObjectsFinal avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_activity_object;

    (*testNumber)++;
    rv=(*pFunctionList->C_GetAttributeValue)(hSession, hObject, dataValueTemplate, dataValueTemplateSize);

    checkPrintResult("C_GetAttributeValue r" E_AIGUE "cup" E_AIGUE "ration taille objet" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_activity_object;

    (*testNumber)++;
    dataValueTemplate[0].pValue=malloc(dataValueTemplate[0].ulValueLen*sizeof(CK_BYTE));
    rv=(*pFunctionList->C_GetAttributeValue)(hSession, hObject, dataValueTemplate, dataValueTemplateSize);

    checkPrintResult("C_GetAttributeValue r" E_AIGUE "cup" E_AIGUE "ration valeur objet" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_activity_object;


end_activity_object:	
    /*traceInFileRet(TRACE_INFO,(CK_CHAR_PTR)"------------- testModifyDataObject", rv);*/
    (*pFunctionList->C_Finalize)(NULL);
    if (dataValueTemplate[0].pValue!=NULL)
        free(dataValueTemplate[0].pValue);
    return rv;
}

CK_RV testCpsPorteurObject(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hRWSession, CK_CHAR_PTR pin, int * testNumber) {
  
    CK_RV rv=CKR_OK;
    CK_BBOOL faux=FALSE;
    CK_BBOOL vrai=TRUE;
    CK_OBJECT_CLASS dataClass=CKO_DATA;
    CK_CHAR dataLabel[]="CPS_NAME_PS";
    CK_ATTRIBUTE dataTemplate[]={	{CKA_CLASS, &dataClass, sizeof(dataClass)},
    {CKA_TOKEN, &vrai, sizeof(vrai)},
    {CKA_PRIVATE, &faux, sizeof(faux)},
    {CKA_LABEL, dataLabel, strlen((char *)dataLabel)}
    };
    CK_ULONG dataTemplateSize=sizeof(dataTemplate)/sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE dataValueTemplate[]={{CKA_VALUE, NULL, 0}};
    CK_ULONG dataValueTemplateSize=sizeof(dataValueTemplate)/sizeof(CK_ATTRIBUTE);
    CK_OBJECT_HANDLE hObject=0;
    CK_OBJECT_HANDLE objectHandle[]={0,0};
    CK_ULONG nbObject=0;

    /*traceInFile(TRACE_INFO,(CK_CHAR_PTR)"------------- testCpsPorteurObject :");*/
  
    (*testNumber)++;
    rv=(*pFunctionList->C_FindObjectsInit)(hSession, dataTemplate, dataTemplateSize);

    checkPrintResult("C_FindObjectsInit avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_cpsporteur_object;

    (*testNumber)++;
    rv=(*pFunctionList->C_FindObjects)(hSession, objectHandle, sizeof(objectHandle)/sizeof(CK_OBJECT_HANDLE), &nbObject);

    checkPrintResult("C_FindObjects avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK || nbObject == 0) goto end_cpsporteur_object;

    hObject=objectHandle[0];

    (*testNumber)++;
    rv=(*pFunctionList->C_FindObjectsFinal)(hSession);

    checkPrintResult("C_FindObjectsFinal avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_cpsporteur_object;

    (*testNumber)++;
    rv=(*pFunctionList->C_GetAttributeValue)(hSession, hObject, dataValueTemplate, dataValueTemplateSize);

    checkPrintResult("C_GetAttributeValue r" E_AIGUE "cup" E_AIGUE "ration taille objet" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_cpsporteur_object;

    (*testNumber)++;
    dataValueTemplate[0].pValue=malloc(dataValueTemplate[0].ulValueLen*sizeof(CK_BYTE));
    rv=(*pFunctionList->C_GetAttributeValue)(hSession, hObject, dataValueTemplate, dataValueTemplateSize);

    checkPrintResult("C_GetAttributeValue r" E_AIGUE "cup" E_AIGUE "ration valeur objet" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_cpsporteur_object;


end_cpsporteur_object:	
    /*traceInFileRet(TRACE_INFO,(CK_CHAR_PTR)"------------- testCpsPorteurObject", rv);*/
    (*pFunctionList->C_Finalize)(NULL);
    if (dataValueTemplate[0].pValue!=NULL)
        free(dataValueTemplate[0].pValue);
    return rv;
}

CK_RV testCpsCertificatObject(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hRWSession, CK_CHAR_PTR pin, int * testNumber) {
  
    CK_RV rv=CKR_OK;
    CK_BBOOL faux=FALSE;
    CK_BBOOL vrai=TRUE;
    CK_OBJECT_CLASS dataClass=CKO_CERTIFICATE;
    CK_CHAR dataLabel[]="Certificat de Signature CPS";
    CK_ATTRIBUTE dataTemplate[]={	{CKA_CLASS, &dataClass, sizeof(dataClass)},
    {CKA_TOKEN, &vrai, sizeof(vrai)},
    {CKA_PRIVATE, &faux, sizeof(faux)},
    {CKA_LABEL, dataLabel, strlen((char *)dataLabel)}
    };
    CK_ULONG dataTemplateSize=sizeof(dataTemplate)/sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE dataValueTemplate[]={{CKA_VALUE, NULL, 0}};
    CK_ULONG dataValueTemplateSize=sizeof(dataValueTemplate)/sizeof(CK_ATTRIBUTE);
    CK_OBJECT_HANDLE hObject=0;
    CK_OBJECT_HANDLE objectHandle[]={0,0};
    CK_ULONG nbObject=0;

    /*traceInFile(TRACE_INFO,(CK_CHAR_PTR)"------------- testCpsPorteurObject :");*/
    if (isContactLess == CK_TRUE) {
      strcpy((char *)dataLabel, "Certificat Technique CPS");
      (*testNumber)+=20;
    }
    else {
      (*testNumber)++;
    }
    rv=(*pFunctionList->C_FindObjectsInit)(hSession, dataTemplate, dataTemplateSize);

    checkPrintResult("C_FindObjectsInit avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_cpscertificat_object;

    (*testNumber)++;
    rv=(*pFunctionList->C_FindObjects)(hSession, objectHandle, sizeof(objectHandle)/sizeof(CK_OBJECT_HANDLE), &nbObject);

    checkPrintResult("C_FindObjects avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK || nbObject == 0) goto end_cpscertificat_object;

    hObject=objectHandle[0];

    (*testNumber)++;
    rv=(*pFunctionList->C_FindObjectsFinal)(hSession);

    checkPrintResult("C_FindObjectsFinal avec param" E_GRAVE "tres corrects" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_cpscertificat_object;

    (*testNumber)++;
    rv=(*pFunctionList->C_GetAttributeValue)(hSession, hObject, dataValueTemplate, dataValueTemplateSize);

    checkPrintResult("C_GetAttributeValue r" E_AIGUE "cup" E_AIGUE "ration taille objet" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_cpscertificat_object;

    (*testNumber)++;
    dataValueTemplate[0].pValue=malloc(dataValueTemplate[0].ulValueLen*sizeof(CK_BYTE));
    rv=(*pFunctionList->C_GetAttributeValue)(hSession, hObject, dataValueTemplate, dataValueTemplateSize);

    checkPrintResult("C_GetAttributeValue r" E_AIGUE "cup" E_AIGUE "ration valeur objet" ,rv,*testNumber,MsgsTbl);

    if (rv!=CKR_OK) goto end_cpscertificat_object;


end_cpscertificat_object:	
    /*traceInFileRet(TRACE_INFO,(CK_CHAR_PTR)"------------- testCpsPorteurObject", rv);*/
    (*pFunctionList->C_Finalize)(NULL);
    if (dataValueTemplate[0].pValue!=NULL)
        free(dataValueTemplate[0].pValue);
    return rv;
}