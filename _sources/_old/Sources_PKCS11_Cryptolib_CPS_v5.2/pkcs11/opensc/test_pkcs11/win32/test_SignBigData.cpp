#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/timeb.h>
#include <time.h>
#include <StdAfx.h>
#include "pkcs11.h"

//#define BLOCK_SIZE 131072
#define MAX_SLOTS 10
#define BLOCK_SIZE 0xF0000
#define AT_SIGNATURE 1
#define AT_KEYEXCHANGE 2
#define MAX_TEMPLATE_SIZE 10
#define AT_KEYEXCHANGE_MODULUS_LENGTH 128

#define CKA_CPS_KEY_TYPE								CKA_VENDOR_DEFINED+1

#define CKR_ASIPTEST_FAILED								0xC0000000
#define ENCRYPT_FUNCTIONS 400
#define ENCRYPT_FUNCTIONS_CPS3 400
#define DECRYPT_FUNCTIONS 500
#define SIGNATU_FUNCTIONS 600
#define VERISGN_FUNCTIONS 700

CK_BBOOL isCPS3 = CK_TRUE;
CK_BBOOL isCPS3_Card = CK_TRUE;

int testGetPkcs11Object(CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, int testLevel, int keySpec, CK_CHAR_PTR szPin, CK_OBJECT_HANDLE_PTR phObject, int * pTestNumber);
void showBytes(unsigned char * byData, size_t sData);


int IOSignFile(char * fileName, 
               CK_FUNCTION_LIST *pFunctionList, 
               CK_SESSION_HANDLE hSessionRO, 
               unsigned char * bufSignature_AT_SIGN, 
               CK_ULONG_PTR pulDataLen,
               size_t block_size) {
    
    FILE * phFile = NULL;
    int rc = 0;
    CK_RV rv;
 
    CK_BYTE_PTR pData;
    // size_t ulDataLen;

    if(rc == 0) {
        int j;
        size_t nRead = 0;
        size_t nReadSave;
        size_t szReadBlock = block_size; // 1MB

        printf("C_SignUpdate par bloc de %d octets.\n", block_size); 
        phFile = fopen(fileName, "rb");


        if(phFile == NULL)
            return 1;

        pData = (unsigned char *)malloc(szReadBlock * sizeof(unsigned char));

        if(pData == NULL) {
            fclose(phFile);
            return 1;
        }
        for(j = 0;  ; j++) {
            nReadSave = nRead;
            nRead = fread(pData, 1, szReadBlock, phFile);

            if(nRead) {

                rv = (*pFunctionList->C_SignUpdate)(hSessionRO, pData, nRead);
                //printf("C_SignUpdate: rv = %x, ", rv);
                if(nReadSave <= 0) {
                    if (nRead < szReadBlock) {
                        //printf("Last block nRead: %lu, %x\n", nRead, pData[0]);
                        break;
                    }
                    else {
                        //printf("First block nRead: %lu, %x\n", nRead, pData[0]);
                    }
                }
                else {

                    if (nRead < szReadBlock) {
                        //printf("Last block(%d) nRead: %lu, %x\n", j+1, nRead, (pData)[0]);
                        break;
                    }
                    else {
                        //printf("Next block(%d) nRead: %lu, %x\n", j+1, nRead, (pData)[0]);
                    }

                }
            }
            else
                break;
        }

        rv = (*pFunctionList->C_SignFinal)(hSessionRO, (CK_BYTE_PTR)bufSignature_AT_SIGN, (CK_ULONG_PTR)pulDataLen);
        //printf("C_SignFinal: rv = %x\n", rv);

        fclose(phFile);

        free( pData );
    }

    return rc;
}


void testSignatureBigData(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, char * filePath, size_t block_size) {

    CK_RV rv;
    CK_SESSION_HANDLE sessionRO = 0xFFFFFFFF;
    CK_MECHANISM testMecha;
    unsigned long objCount = 0;

    CK_OBJECT_HANDLE hObject=0;
    // CK_BYTE_PTR pData;
    // CK_ULONG ulDataLen;
    CK_ULONG ulSignatureLen;
    CK_BYTE bufSignature_AT_SIGN[512];	
   time_t   start, finish;
   double   result, elapsed_time;

    rv = (*pFunctionList->C_Initialize)(NULL);
    if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
        CK_ULONG ulSlotsListSize = MAX_SLOTS;
        //recupération de la liste des slots avec carte
        rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);

        if (rv != CKR_OK || ulSlotsListSize == 0) {
            printf("C_GetSlotList aucune carte trouvee: rv=%lu\n" ,rv);
            (*pFunctionList->C_Finalize)(NULL);
            return;
        }

        currentSlotID = tabSlots[0];


        //ouverture d'une session en lecture seule sur le premier slot
        rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
        if (rv != CKR_OK) {
            printf("C_OpenSession erreur: rv=%lu" ,rv);
            (*pFunctionList->C_Finalize)(NULL);
            return;
        }

        // login utilisateur
        rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);

        if(rv == CKR_PIN_INCORRECT) {
            printf("C_Login le code porteur etait incorrect: rv=%lu\n" ,rv);
            (*pFunctionList->C_Finalize)(NULL);
            return;
        }
        printf("C_Login avec code porteur correct: rv=%lu\n" ,rv);

        // Recuperer l'objet clé privée de signature (AT_SIGNATURE)
        testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, AT_SIGNATURE, pin, &hObject, NULL);

        testMecha.mechanism = CKM_SHA1_RSA_PKCS;

        // Initialisation de signature
        rv = (*pFunctionList->C_SignInit)(sessionRO, &testMecha, hObject);

        if (rv != CKR_OK) {
            printf("C_SignInit erreur: rv=%lu" ,rv);
            (*pFunctionList->C_Finalize)(NULL);
            return;
        }

        printf("C_SignInit avec handle de session valide: rv=%lu\n" ,rv);

        time( &start );
        IOSignFile(filePath, pFunctionList, sessionRO, bufSignature_AT_SIGN, (CK_ULONG_PTR)&ulSignatureLen, block_size);
        time( &finish );

        elapsed_time = difftime( finish, start );
        printf( "\nTemps de signature : %6.0f seconds.\n", elapsed_time );

        showBytes(bufSignature_AT_SIGN, ulSignatureLen);

        if (rv != CKR_OK) {
            (*pFunctionList->C_Finalize)(NULL);
            return;
        }
    }
}

CK_RV getCPS3EncryptPubKey( CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, CK_CHAR_PTR szPin, int testLevel, CK_OBJECT_HANDLE_PTR phObject)
{
  CK_RV rv=CKR_OK;
  //CK_BYTE_PTR pData=(CK_BYTE_PTR)"Message chiffre";
  CK_BYTE_PTR pLabelCertAut=(CK_BYTE_PTR)"Certificat d'Authentification CPS";
  CK_BYTE_PTR pLabelCertTechAut=(CK_BYTE_PTR)"Certificat Technique CPS";
  //CK_ULONG ulDataLen=strlen((char *)pData)+1;
  CK_BYTE_PTR   p;
  
  CK_OBJECT_CLASS publicKeyClass= CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privateKeyClass= CKO_PRIVATE_KEY;
  CK_OBJECT_CLASS certClass= CKO_CERTIFICATE;
  CK_BYTE id[]={4,5,6};
  CK_BYTE idAuth[4]={4,0,0,0};

  
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS,&publicKeyClass,sizeof(publicKeyClass)},
    {CKA_ID,&id,sizeof(id)}
  };
  
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS,&privateKeyClass,sizeof(privateKeyClass)},
    {CKA_ID,&id,sizeof(id)}
  };

  CK_ATTRIBUTE certTemplate[] = {
    {CKA_CLASS,&certClass,sizeof(certClass)},
    {CKA_LABEL,pLabelCertAut,strlen((char *)pLabelCertAut)}
  };
  CK_ATTRIBUTE oldcertTemplate[] = {
    {CKA_CLASS,&certClass,sizeof(certClass)},
    {CKA_ID, &idAuth, sizeof(idAuth)}
  };
  CK_ATTRIBUTE commonTemplate[] = {
    {CKA_ID,NULL,0}
  };
  
  CK_ATTRIBUTE keyTemplate[] = {
    {0,NULL,0}
  };
  
  
  CK_ULONG keyListSize = 5;
  CK_OBJECT_HANDLE_PTR pPubKey = (CK_OBJECT_HANDLE_PTR) malloc(keyListSize *sizeof(CK_OBJECT_HANDLE));
  CK_OBJECT_HANDLE_PTR pPrivKey = (CK_OBJECT_HANDLE_PTR) malloc(keyListSize *sizeof(CK_OBJECT_HANDLE));
  CK_OBJECT_HANDLE_PTR pCertificate = (CK_OBJECT_HANDLE_PTR) malloc(keyListSize *sizeof(CK_OBJECT_HANDLE));
  
  
  /*CK_MECHANISM encryptmechanism = {
    CKM_RSA_PKCS, NULL_PTR,0
  };*/
  
  CK_MECHANISM decryptmechanism = {
    CKM_RSA_PKCS, NULL_PTR,0
  };
  
	//traceInFile(TRACE_INFO,(CK_CHAR_PTR)"------------- testEncryptDecryptRSA :");
  rv=(*pFunctionList->C_Login)(sessionRO, CKU_USER, szPin, strlen((char *)szPin));
  if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN && rv!=CKR_USER_PIN_NOT_INITIALIZED)  
		goto out;
  
  
  /* Récupérer un handle sur la clé public de chiffrement */
  
  if (rv==CKR_USER_PIN_NOT_INITIALIZED) { /* c'est de l'authentification avec le sans contact */
		rv=CKR_OK; /* En attendant une correction sur la structure P15 qui permettrait de tester correctement une erreur P11 */
		goto out;
  } else {
    if(isCPS3)
		rv=(*pFunctionList->C_FindObjectsInit)(sessionRO, certTemplate, sizeof(certTemplate)/sizeof(CK_ATTRIBUTE)); 
    else
    rv=(*pFunctionList->C_FindObjectsInit)(sessionRO, oldcertTemplate, sizeof(oldcertTemplate)/sizeof(CK_ATTRIBUTE)); 
  }
  if (rv!=CKR_OK)
		goto out;
  rv = (*pFunctionList->C_FindObjects)(sessionRO,pCertificate,keyListSize, &keyListSize);
  if ( (rv != CKR_OK) || (keyListSize == 0) )
  {
    rv = CKR_FUNCTION_FAILED; 
		goto out;
  }

  rv=(*pFunctionList->C_FindObjectsFinal)(sessionRO);
  if (rv!=CKR_OK)
		goto out;
  
  rv=(*pFunctionList->C_GetAttributeValue)(sessionRO, pCertificate[0],commonTemplate,sizeof(commonTemplate)/sizeof(CK_ATTRIBUTE));
  if (rv!=CKR_OK)
		goto out;
  commonTemplate[0].pValue=malloc(commonTemplate[0].ulValueLen*sizeof(CK_BYTE));
  rv=(*pFunctionList->C_GetAttributeValue)(sessionRO, pCertificate[0],commonTemplate,sizeof(commonTemplate)/sizeof(CK_ATTRIBUTE));
  if (rv!=CKR_OK)
		goto out;
  
  if (testLevel == ENCRYPT_FUNCTIONS) {
    publicKeyTemplate[1].pValue=commonTemplate[0].pValue;
    publicKeyTemplate[1].ulValueLen=commonTemplate[0].ulValueLen;
  }

  if (testLevel == DECRYPT_FUNCTIONS) {
    privateKeyTemplate[1].pValue=commonTemplate[0].pValue;
    privateKeyTemplate[1].ulValueLen=commonTemplate[0].ulValueLen;
  }

  if (testLevel == ENCRYPT_FUNCTIONS) {
    rv=(*pFunctionList->C_FindObjectsInit)(sessionRO, publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE));
  }
  if (testLevel == DECRYPT_FUNCTIONS) {
    rv=(*pFunctionList->C_FindObjectsInit)(sessionRO, privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE));
  }
  if (rv!=CKR_OK)
		goto out;
  if (testLevel == ENCRYPT_FUNCTIONS) {
    rv = (*pFunctionList->C_FindObjects)(sessionRO, pPubKey, keyListSize, &keyListSize);
  }
  if (testLevel == DECRYPT_FUNCTIONS) {
    rv = (*pFunctionList->C_FindObjects)(sessionRO, pPrivKey, keyListSize, &keyListSize);
  }
  if ( (rv != CKR_OK) || (keyListSize == 0) )
  {
    rv = CKR_FUNCTION_FAILED; 
		goto out;
  }
  if (testLevel == ENCRYPT_FUNCTIONS) {
    *phObject = pPubKey[0];
  }
  if (testLevel == DECRYPT_FUNCTIONS) {
    *phObject = pPrivKey[0];
  }
  rv=(*pFunctionList->C_FindObjectsFinal)(sessionRO);
  if (rv!=CKR_OK)
		goto out;

out:
  if (pPubKey)
		free(pPubKey);
  if (pPrivKey)
    free(pPrivKey);
  if (pCertificate)
		free(pCertificate);
  if(commonTemplate[0].pValue)
    free(commonTemplate[0].pValue);
  if(keyTemplate[0].pValue)
    free(keyTemplate[0].pValue);
  return rv;
}

/* BPER (@@20131017) - Si on passe un pTestNumer non NULL, cette ecrit dans les fichiers de résultats et met à jour du coup ce pTestNumber */
int testGetPkcs11Object(CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, int testLevel, int keySpec, CK_CHAR_PTR szPin, CK_OBJECT_HANDLE_PTR phObject, int * pTestNumber) {

	CK_RV rv;
	// char errorCode[50];
	CK_OBJECT_CLASS dataClass=CKO_DATA;
	CK_BBOOL boole;
	CK_ATTRIBUTE dataTemplate[MAX_TEMPLATE_SIZE]={	{CKA_CLASS, &dataClass, sizeof(dataClass)}};
	size_t sTemplateSize;
	CK_ULONG objCount, keyAlg;
	CK_OBJECT_HANDLE hObject;
	unsigned short keyType;
	CK_ULONG id;

	
	if(testLevel == ENCRYPT_FUNCTIONS)
		dataClass = CKO_SECRET_KEY;
  if(testLevel == SIGNATU_FUNCTIONS) {
		int place = 0;
		dataClass = CKO_PRIVATE_KEY;

		// CKA_CLASS
		dataTemplate[place].type = CKA_CLASS;
		dataTemplate[place].ulValueLen=sizeof(CK_OBJECT_CLASS);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		memcpy(dataTemplate[place].pValue, &dataClass, dataTemplate[place].ulValueLen);

		// CKA_PRIVATE
		place++;
		dataTemplate[place].type = CKA_PRIVATE;
		dataTemplate[place].ulValueLen=sizeof(CK_BBOOL);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		boole = CK_TRUE;
		memcpy(dataTemplate[place].pValue, &boole, dataTemplate[place].ulValueLen);

		// CKA_TOKEN
		place++;
		dataTemplate[place].type = CKA_TOKEN;
		dataTemplate[place].ulValueLen=sizeof(CK_BBOOL);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		boole = CK_TRUE;
		memcpy(dataTemplate[place].pValue, &boole, dataTemplate[place].ulValueLen);

		// CKA_LABEL
		place++;
		if (isCPS3) {
		  dataTemplate[place].type = CKA_LABEL;
		  
		  if(keySpec == AT_KEYEXCHANGE) {
        dataTemplate[place].ulValueLen = strlen("CPS_PRIV_AUT");
        dataTemplate[place].pValue = malloc( dataTemplate[place].ulValueLen );
		    memcpy(dataTemplate[place].pValue, "CPS_PRIV_AUT", dataTemplate[place].ulValueLen);
      }
		  if(keySpec == AT_SIGNATURE) {
       dataTemplate[place].ulValueLen = strlen("CPS_PRIV_SIG");
        dataTemplate[place].pValue = malloc( dataTemplate[place].ulValueLen );
		    memcpy(dataTemplate[place].pValue, "CPS_PRIV_SIG", dataTemplate[place].ulValueLen);
      }
		} else {
      // En CPS2ter, on utilise le CKA_ID pour rechercher les clés privées
	
	  dataTemplate[place].type = CKA_CPS_KEY_TYPE;
      dataTemplate[place].ulValueLen = sizeof(keyType);
	  dataTemplate[place].pValue = &keyType;
      if(keySpec == AT_KEYEXCHANGE) {
		  keyType = 'A';
      }
      if(keySpec == AT_SIGNATURE) {
		  keyType = 'S';
      }
		}
		sTemplateSize = place+1;

    // login
	  rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, szPin, 4);
		//printf("testGetPkcs11Object : C_Login - Code retour : %s\n",getErrorCodeString(rv,errorCode));
	}

  if(testLevel == VERISGN_FUNCTIONS) {
		int place = 0;
		dataClass = CKO_PUBLIC_KEY;

		// CKA_CLASS
		dataTemplate[place].type = CKA_CLASS;
		dataTemplate[place].ulValueLen=sizeof(CK_OBJECT_CLASS);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		memcpy(dataTemplate[place].pValue, &dataClass, dataTemplate[place].ulValueLen);

		// CKA_PRIVATE
		place++;
		dataTemplate[place].type = CKA_PRIVATE;
		dataTemplate[place].ulValueLen=sizeof(CK_BBOOL);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		boole = CK_FALSE;
		memcpy(dataTemplate[place].pValue, &boole, dataTemplate[place].ulValueLen);

		// CKA_TOKEN
		place++;
		dataTemplate[place].type = CKA_TOKEN;
		dataTemplate[place].ulValueLen=sizeof(CK_BBOOL);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		boole = CK_TRUE;
		memcpy(dataTemplate[place].pValue, &boole, dataTemplate[place].ulValueLen);

		// CKA_ID
		place++;
		dataTemplate[place].type = CKA_ID;
		if (isCPS3) {
      if (isCPS3_Card) {
		    if(keySpec == AT_KEYEXCHANGE) {
          dataTemplate[place].ulValueLen = 14;
          dataTemplate[place].pValue = malloc( dataTemplate[place].ulValueLen );
		      memcpy(dataTemplate[place].pValue, "\xe8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x10\x02", dataTemplate[place].ulValueLen);
        }
		    if(keySpec == AT_SIGNATURE) {
         dataTemplate[place].ulValueLen = 14;
          dataTemplate[place].pValue = malloc( dataTemplate[place].ulValueLen );
		      memcpy(dataTemplate[place].pValue, "\xe8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x10\x01", dataTemplate[place].ulValueLen);
        }
      }
      else {
        if(keySpec == AT_KEYEXCHANGE) {
          dataTemplate[place].ulValueLen = 2;
          dataTemplate[place].pValue = malloc( dataTemplate[place].ulValueLen );
		      memcpy(dataTemplate[place].pValue, "\x12\x16", dataTemplate[place].ulValueLen);
        }
		    if(keySpec == AT_SIGNATURE) {
         dataTemplate[place].ulValueLen = 2;
          dataTemplate[place].pValue = malloc( dataTemplate[place].ulValueLen );
		      memcpy(dataTemplate[place].pValue, "\x12\x17", dataTemplate[place].ulValueLen);
        }
      }
		} else {
			
        dataTemplate[place].type = CKA_ID;
        dataTemplate[place].ulValueLen = sizeof(id);
	    dataTemplate[place].pValue = &id;
        if(keySpec == AT_KEYEXCHANGE) {
		  id = 4;
        }
        if(keySpec == AT_SIGNATURE) {
		  id = 1;
        }
      /*dataTemplate[place].ulValueLen = 4;
		  dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
      if(keySpec == AT_KEYEXCHANGE) {  
		    memcpy(dataTemplate[place].pValue, "\x04\x00\x00\x00", dataTemplate[place].ulValueLen);
      }
      if(keySpec == AT_SIGNATURE) {
		    memcpy(dataTemplate[place].pValue, "\x01\x00\x00\x00", dataTemplate[place].ulValueLen);
      }*/
		}
		sTemplateSize = place+1;
	}

  if(testLevel == ENCRYPT_FUNCTIONS || testLevel == DECRYPT_FUNCTIONS) {
    int place = 0;
    CK_BYTE keyByte[24]={0x6D,0x1C,0x31,0x97,0x26,0x76,0x92,0x45,0x9B,0x86,0xCE,0x02,0x61,0x61,0xEF,0x34,0x10,0x75,0xDF,0xCB,0x61,0xE5,0xD9,0x2F};

    if (isCPS3) {
      return getCPS3EncryptPubKey( pFunctionList, sessionRO, szPin, testLevel, phObject);
    }

    // CKA_CLASS
    dataClass = CKO_SECRET_KEY;
		dataTemplate[place].type = CKA_CLASS;
		dataTemplate[place].ulValueLen=sizeof(CK_OBJECT_CLASS);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		memcpy(dataTemplate[place].pValue, &dataClass, dataTemplate[place].ulValueLen);

		// CKA_ENCRYPT
		place++;
		dataTemplate[place].type = CKA_ENCRYPT;
		dataTemplate[place].ulValueLen=sizeof(CK_BBOOL);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		boole = CK_TRUE;
		memcpy(dataTemplate[place].pValue, &boole, dataTemplate[place].ulValueLen);

    // CKA_DECRYPT
		place++;
    dataTemplate[place].type = CKA_DECRYPT;
		dataTemplate[place].ulValueLen=sizeof(CK_BBOOL);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		boole = CK_FALSE;
    if (testLevel == DECRYPT_FUNCTIONS)
      boole = CK_TRUE;
		memcpy(dataTemplate[place].pValue, &boole, dataTemplate[place].ulValueLen);

		// CKA_TOKEN
		place++;
		dataTemplate[place].type = CKA_TOKEN;
		dataTemplate[place].ulValueLen=sizeof(CK_BBOOL);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		boole = CK_FALSE;
		memcpy(dataTemplate[place].pValue, &boole, dataTemplate[place].ulValueLen);

    // CKA_VALUE
		place++;
		dataTemplate[place].type = CKA_VALUE;
    dataTemplate[place].ulValueLen=sizeof(keyByte);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
		memcpy(dataTemplate[place].pValue, keyByte, dataTemplate[place].ulValueLen);

    // CKA_KEY_TYPE
		place++;
		dataTemplate[place].type = CKA_KEY_TYPE;
    dataTemplate[place].ulValueLen=sizeof(CK_ULONG);
		dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
    keyAlg = CKK_RC4;
		memcpy(dataTemplate[place].pValue, &keyAlg, dataTemplate[place].ulValueLen);
    sTemplateSize = place+1;

    if (testLevel == ENCRYPT_FUNCTIONS) {
      // login
	    rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, szPin, 4);
		  //printf("testGetPkcs11Object : C_Login - Code retour : %s\n",getErrorCodeString(rv,errorCode));
    }

    rv = (*pFunctionList->C_CreateObject)(sessionRO,dataTemplate, sTemplateSize, phObject);

    return rv;
  }
  int test;
		//findobjectsinit
		rv = (*pFunctionList->C_FindObjectsInit)(sessionRO,dataTemplate, sTemplateSize);
    if (pTestNumber != NULL_PTR) {
      (*pTestNumber)++;
		  //test=ConsigneResultatCSV(MsgsTbl[*pTestNumber].TestLevel,rv,MsgsTbl[*pTestNumber].usExpectedRc,MsgsTbl[*pTestNumber].Msg);
      printf("%03d : C_FindObjectsInit : %lu\n", rv);
    }

		if(rv == CKR_OK) {
		  // findobjects
		  rv = (*pFunctionList->C_FindObjects)(sessionRO,&hObject,1,&objCount);
      if (pTestNumber != NULL_PTR) {
        (*pTestNumber)++;
        if (rv == CKR_OK)
          if (objCount < 1 ) rv = CKR_ASIPTEST_FAILED;
		   // test=ConsigneResultatCSV(MsgsTbl[*pTestNumber].TestLevel,rv,MsgsTbl[*pTestNumber].usExpectedRc,MsgsTbl[*pTestNumber].Msg);
        printf("%03d : C_FindObjects : %lu\n", rv);
      }
		  *phObject = hObject;
		}

		//findobjectsfinal
		rv = (*pFunctionList->C_FindObjectsFinal)(sessionRO);
    if (pTestNumber != NULL_PTR) {
      (*pTestNumber)++;
      //test=ConsigneResultatCSV(MsgsTbl[*pTestNumber].TestLevel,rv,MsgsTbl[*pTestNumber].usExpectedRc,MsgsTbl[*pTestNumber].Msg);
      printf("%03d : C_FindObjectsFinal : %lu\n", rv);
    }

		return rv;
}


void showBytes(unsigned char * byData, size_t sData)
{
  size_t nLength = sData * 3;
  char *pBuffer = (char *)calloc(nLength, sizeof(char));
  if (pBuffer)
  {
    char *p;
    p = pBuffer;
    for (int i = 0; i < (int)sData; i++)
    {
      sprintf(p, (i == sData - 1) ? "%02X" : "%02X\x20", byData[i]);
      p = p + 3;
    }

    printf("\nSignature (%lu bytes) : %s\n", sData, pBuffer);

    free(pBuffer);
  }
}