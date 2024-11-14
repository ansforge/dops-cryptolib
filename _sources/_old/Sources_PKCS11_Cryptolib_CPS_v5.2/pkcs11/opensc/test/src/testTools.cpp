#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_OPENSSL
#include "openssl/pkcs12.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#endif

#include "pkcs11.h"
#include "testconstants.h"

#define MAX_TEMPLATE_SIZE 10
#define AT_KEYEXCHANGE_MODULUS_LENGTH 128

#define CKA_CPS_KEY_TYPE								CKA_VENDOR_DEFINED+1

#define CPS4_SIGN_KEY_ID 0x10
#define CPS4_AUTH_KEY_ID 0x20

extern sTESTS_MSGS     MsgsTbl[];
extern char *getErrorCodeString(CK_RV error, char * strError);
extern int ConsigneResultatCSV(unsigned short __usTestNumero, unsigned long usRc, unsigned long usExpectedRc, char * libelle);
extern void sys_ExecuteCommand(char * cmd);
#ifdef WIN32
extern char * sys_GetAllUsersDir( void );
#endif
extern int IOReadFile(char * fileName, unsigned char ** ppData, size_t * pulDataLen);
extern int IOWriteFile(char * fileName, unsigned char * ppData, size_t  ulDataLen);

CK_RV getCPS3EncryptPubKey( CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, CK_CHAR_PTR szPin, int testLevel, CK_OBJECT_HANDLE_PTR phObject);

/* BPER (@@20131017) - Si on passe un pTestNumer non NULL, cette fonction ecrit dans les fichiers de résultats et met à jour du coup ce pTestNumber */
int testGetPkcs11Object(CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, int testLevel, int keySpec, CK_CHAR_PTR szPin, CK_OBJECT_HANDLE_PTR phObject, int * pTestNumber) {

	CK_RV rv;
	char errorCode[50];
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
    if (isContactLess == CK_TRUE) {
      boole = CK_FALSE;
    }
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
        if (isContactLess == CK_TRUE) {
          dataTemplate[place].ulValueLen = strlen("CPS_PRIV_TECH_AUT");
          dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
          memcpy(dataTemplate[place].pValue, "CPS_PRIV_TECH_AUT", dataTemplate[place].ulValueLen);
        }
        else {
          dataTemplate[place].ulValueLen = strlen("CPS_PRIV_AUT");
          dataTemplate[place].pValue = malloc(dataTemplate[place].ulValueLen);
          memcpy(dataTemplate[place].pValue, "CPS_PRIV_AUT", dataTemplate[place].ulValueLen);
        }
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
          if (isContactLess == CK_TRUE) {
            memcpy(dataTemplate[place].pValue, "\xe8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x10\x03", dataTemplate[place].ulValueLen);
          }
          else {
            memcpy(dataTemplate[place].pValue, "\xe8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x10\x02", dataTemplate[place].ulValueLen);
			if (isCPS3_Card & TYPE_CPS4) {
				((CK_BYTE_PTR)dataTemplate[place].pValue)[13] = CPS4_AUTH_KEY_ID;
			}
          }
        }
		    if(keySpec == AT_SIGNATURE) {
         dataTemplate[place].ulValueLen = 14;
          dataTemplate[place].pValue = malloc( dataTemplate[place].ulValueLen );
		      memcpy(dataTemplate[place].pValue, "\xe8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x10\x01", dataTemplate[place].ulValueLen);
			  if (isCPS3_Card & TYPE_CPS4) {
				  ((CK_BYTE_PTR)dataTemplate[place].pValue)[13] = CPS4_SIGN_KEY_ID;
			  }
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
		  test=ConsigneResultatCSV(MsgsTbl[*pTestNumber].TestLevel,rv,MsgsTbl[*pTestNumber].usExpectedRc,MsgsTbl[*pTestNumber].Msg);
      printf("%03d : C_FindObjectsInit : %s\n",MsgsTbl[*pTestNumber].TestLevel,test==0?"OK":getErrorCodeString(rv,errorCode));
    }

		if(rv == CKR_OK) {
		  // findobjects
		  rv = (*pFunctionList->C_FindObjects)(sessionRO,&hObject,1,&objCount);
      if (pTestNumber != NULL_PTR) {
        (*pTestNumber)++;
        if (rv == CKR_OK)
          if (objCount < 1 ) rv = CKR_ASIPTEST_FAILED;
		    test=ConsigneResultatCSV(MsgsTbl[*pTestNumber].TestLevel,rv,MsgsTbl[*pTestNumber].usExpectedRc,MsgsTbl[*pTestNumber].Msg);
        printf("%03d : C_FindObjects : %s\n",MsgsTbl[*pTestNumber].TestLevel,test==0?"OK":getErrorCodeString(rv,errorCode));
      }
		  *phObject = hObject;
		}

		//findobjectsfinal
		rv = (*pFunctionList->C_FindObjectsFinal)(sessionRO);
    if (pTestNumber != NULL_PTR) {
      (*pTestNumber)++;
      test=ConsigneResultatCSV(MsgsTbl[*pTestNumber].TestLevel,rv,MsgsTbl[*pTestNumber].usExpectedRc,MsgsTbl[*pTestNumber].Msg);
      printf("%03d : C_FindObjectsFinal : %s\n",MsgsTbl[*pTestNumber].TestLevel,test==0?"OK":getErrorCodeString(rv,errorCode));
    }

		return rv;
}

CK_RV getCPS3EncryptPubKey( CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, CK_CHAR_PTR szPin, int testLevel, CK_OBJECT_HANDLE_PTR phObject)
{
  CK_RV rv=CKR_OK;
  //CK_BYTE_PTR pData=(CK_BYTE_PTR)"Message chiffre";
  CK_BYTE_PTR pLabelCertAut=(CK_BYTE_PTR)"Certificat d'Authentification CPS";
  CK_BYTE_PTR pLabelCertTechAut=(CK_BYTE_PTR)"Certificat Technique CPS";
  //CK_ULONG ulDataLen=strlen((char *)pData)+1;
  //CK_SLOT_ID slotId=-1;
  CK_BYTE_PTR   p;
  
  CK_OBJECT_CLASS publicKeyClass= CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privateKeyClass= CKO_PRIVATE_KEY;
  CK_OBJECT_CLASS certClass= CKO_CERTIFICATE;
  CK_BYTE id[]={4,5,6};
  CK_BYTE idAuth[4]={4,0,0,0};
  //CK_ULONG idCPS2=1000;

  
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

void testSetMechanism(int testLevel, int keySpec, CK_RV expectedRv, CK_MECHANISM_PTR pMechanism) {

	// Les mécanismes utilisés n'ont pas de paramètre
	pMechanism->pParameter = NULL_PTR;
	pMechanism->ulParameterLen = 0;

  if (testLevel == MDIGEST_FUNCTIONS)
  {
    switch(expectedRv) {

			case CKR_OK :
        pMechanism->mechanism = CKM_SHA_1;
        if (keySpec == SHA256)
          pMechanism->mechanism = CKM_SHA256;
				break;
    }
    return;
  }

  if (testLevel == SIGNATU_FUNCTIONS || testLevel == VERISGN_FUNCTIONS || testLevel == DECRYPT_FUNCTIONS || testLevel == ENCRYPT_FUNCTIONS) {

    if((keySpec & AT_KEYEXCHANGE) == AT_KEYEXCHANGE) {

			switch(expectedRv) {

			case CKR_MECHANISM_INVALID :
				pMechanism->mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
				break;

			case CKR_KEY_TYPE_INCONSISTENT :
				pMechanism->mechanism = CKM_SHA1_RSA_PKCS;
				break;

			case CKR_USER_NOT_LOGGED_IN :
			case CKR_OK :
				pMechanism->mechanism = CKM_RSA_PKCS;
				break;
			default:;
			}
		}

    if((keySpec & AT_SIGNATURE) == AT_SIGNATURE) {

			switch(expectedRv) {

			case CKR_MECHANISM_INVALID :
				pMechanism->mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
				break;
			case CKR_KEY_TYPE_INCONSISTENT :
				pMechanism->mechanism = CKM_RSA_PKCS;
				break;

			case CKR_USER_NOT_LOGGED_IN :
			case CKR_OK :
        pMechanism->mechanism = CKM_SHA1_RSA_PKCS;
        if((keySpec & AT_SIGN_HASH) == AT_SIGN_HASH) {
          pMechanism->mechanism = CKM_RSA_PKCS;
        }
				break;
			default:;
			}
		}
	}

  if (testLevel == SIGSHA256_FUNCTIONS) {

    /*if((keySpec & AT_SIGNATURE) == AT_SIGNATURE) {*/

			switch(expectedRv) {

			case CKR_USER_NOT_LOGGED_IN :
			case CKR_OK :
        pMechanism->mechanism = CKM_SHA256_RSA_PKCS;
				break;
			default:;
			}
		/*}*/
  }
}

void testSetData(int testLevel, int keySpec, CK_RV expectedRv, CK_BYTE_PTR * ppData, CK_ULONG_PTR pulDataLen) {

  *pulDataLen = 0;

  	if (testLevel == SIGNATU_FUNCTIONS || testLevel == VERISGN_FUNCTIONS) {

		  if(keySpec == AT_KEYEXCHANGE) {

			  switch(expectedRv) {
        case CKR_DATA_LEN_RANGE :
          *pulDataLen = 513;
          break;

        case CKR_BUFFER_TOO_SMALL :
        case CKR_SIGNATURE_LEN_RANGE :
        case CKR_OK :
          // Positionner une taille de 35 (correspondant au DigestInfo. )
          // dans le cas de la clé d'authentification avec CKM_RSA_PKCS
          *pulDataLen = 35;
          break;

        default:;
        }
      }

      if(keySpec == AT_SIGNATURE) {

			  switch(expectedRv) {
        case CKR_DATA_LEN_RANGE :
          *pulDataLen = 513;
          break;

        case CKR_BUFFER_TOO_SMALL :
        case CKR_OK :
          // Positionner n'importe quelle taille (Voir specs PKCS11. )
          // pour la clé de signature
          *pulDataLen = 1405;
          break;

        default:;
        }
      }
    }

    if (*pulDataLen > 0) {
     *ppData = (CK_BYTE_PTR)malloc( *pulDataLen );

     for (int i=0; i<(int)*pulDataLen; i++)
        (*ppData)[i] = 'A';
    }
}

void testFreeData(CK_BYTE_PTR * ppData, CK_ULONG_PTR pulDataLen) {

  if (ppData) {
    if (*ppData != NULL_PTR) {

      // libération zone mémoire
      free( *ppData );
      *ppData = NULL_PTR;

      // raz de la taille de la zone mémoire
      if (pulDataLen != NULL_PTR) {
         *pulDataLen = 0;
      }
    }
  }
}

void testChiffrementRSA_Openssl(CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, CK_OBJECT_HANDLE hPubKey, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR * ppEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {

  CK_RV rv;
  CK_BYTE_PTR   p;
  RSA * pRsa;
  CK_BYTE_PTR pEncryptedData=NULL;
  CK_ULONG ulEncryptedDataLen=0;

  CK_ATTRIBUTE keyTemplate[] = {
    {0,NULL,0}
  };

  /*chiffrer le message */
  
  /* Initialisation openssl */
#ifdef UNIX_LUX
  //OpenSSL_add_all_ciphers();
#else
  //OpenSSL_add_all_algorithms();
#endif
  ERR_load_crypto_strings ();
  
  pRsa=RSA_new();
  
  /*Récupération des attributs de la clé*/
  /* Récupération du CKA_MODULUS */
  keyTemplate[0].type=CKA_MODULUS;
  rv=(*pFunctionList->C_GetAttributeValue)(sessionRO, hPubKey, keyTemplate,1);
  if (rv!=CKR_OK)
		goto out;
  keyTemplate[0].pValue=malloc(keyTemplate[0].ulValueLen*sizeof(CK_BYTE));
  rv=(*pFunctionList->C_GetAttributeValue)(sessionRO, hPubKey, keyTemplate,1);
  if(rv!=CKR_OK){
    RSA_free(pRsa);
    goto out;
  }

  pRsa->n = BN_bin2bn((CK_CHAR_PTR)keyTemplate[0].pValue,keyTemplate[0].ulValueLen,NULL);

  /* Récupération du CKA_PUBLIC_EXPONENT */
  keyTemplate[0].type=CKA_PUBLIC_EXPONENT;
  rv=(*pFunctionList->C_GetAttributeValue)(sessionRO, hPubKey, keyTemplate,1);
  if (rv!=CKR_OK)
		goto out;
  keyTemplate[0].pValue=malloc(keyTemplate[0].ulValueLen*sizeof(CK_BYTE));
  rv=(*pFunctionList->C_GetAttributeValue)(sessionRO, hPubKey, keyTemplate,1);
  if(rv!=CKR_OK){
    RSA_free(pRsa);
    goto out;
  }
  pRsa->e = BN_bin2bn((CK_CHAR_PTR)keyTemplate[0].pValue,keyTemplate[0].ulValueLen,NULL);

  ulEncryptedDataLen = RSA_size( (RSA *)pRsa);

  pEncryptedData = (CK_BYTE_PTR)calloc(ulEncryptedDataLen, sizeof(CK_BYTE));
  if ( pEncryptedData == NULL_PTR ){ 
    RSA_free(pRsa);
    rv = CKR_HOST_MEMORY;
    goto out;
  }
  
  p = pEncryptedData;

  ulEncryptedDataLen = RSA_public_encrypt(ulDataLen,pData, p, (RSA *)pRsa, RSA_PKCS1_PADDING);
  if( ulEncryptedDataLen == -1 ){
    char buf[256]={0};
    ERR_error_string(ERR_get_error(), buf);
    RSA_free(pRsa);
    rv = CKR_FUNCTION_FAILED; 
    free(pEncryptedData);
    goto out;
  }
  
  *pulEncryptedDataLen = ulEncryptedDataLen;
  *ppEncryptedData = pEncryptedData;
  
  RSA_free(pRsa);

out:
  printf("Fin\n");
}

/*
%--------------------------------------------------------------------------
% BuildFullHash
%
% Rôle : BuildFullHash est utilisée pour construire le hash complet avec le DigestInfo
%
% Paramètres d'entrée :
%			      IN pFunctionList		-  interface des fonctions PKCS11
%           IN sessionRO        -  handle de session Cryptoki
%           IN pData            -  données à condenser
%						OUT pbyHash		      -  Adresse contenant en retour l'adresse du buffer ALLOUE avec le hash complet
%						OUT pdwFullHashLen	-  Adresse du DWORD contenant la taille du hash complet
%						IN  dwAlgId		      -  algorithme de hash utilisé
%  
% Valeur retournée :	TRUE si l'opération s'est bien passée
%						FALSE sinon 
%---------------------------------------------------------------------------
*/
unsigned short BuildFullHash( CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, CK_CHAR_PTR pData, CK_BYTE_PTR * pbyHash, CK_ULONG * pdwFullHashLen, unsigned int dwAlgId, int useOID)
{
  CK_ULONG dwBufferLen, dwHashLen = 0, dwOIDLen = 0;
  const CK_BYTE * pbyOID = NULL;
  CK_BYTE_PTR pMyHash = NULL;
  CK_RV rv;
  CK_MECHANISM testDigestMecha;

  printf("BuildFullHash  0x%08x, 0x%08x\n", pData, pbyHash);

  // C_DigestInit et paramètres corrects
  //testNumber++;
  // Positionner un mécanisme de hash (SHA1)
  testSetMechanism(MDIGEST_FUNCTIONS, dwAlgId, CKR_OK, &testDigestMecha);
  rv = (*pFunctionList->C_DigestInit)(sessionRO, &testDigestMecha);
  if (rv != CKR_OK) goto end_hash;
  //printf("%03d : C_DigestInit et param"E_GRAVE"tres corrects : %s\n",MsgsTbl[testNumber].TestLevel,test==0?"OK":getErrorCodeString(rv,errorCode));

  // HP_HASHSIZE
  rv = (*pFunctionList->C_Digest)(sessionRO, (unsigned char *)pData, strlen((const char *)pData), NULL, &dwHashLen);
  if (rv != CKR_OK) goto end_hash;

  pMyHash = (CK_BYTE_PTR)malloc( dwHashLen);
	
	if(pMyHash == NULL) {
		printf("BuildFullHash (HOST_MEMORY step 1)  0x%08x, 0x%08x, 0x%08x\n", pData, pbyHash, FALSE);
		return FALSE;
	}

  // HP_HASHVAL
  rv = (*pFunctionList->C_Digest)(sessionRO, (unsigned char *)pData, strlen((const char *)pData), pMyHash, &dwHashLen);
  if (rv != CKR_OK) goto end_hash;
  if (useOID) {
  //Mise en forme du digestInfo
  switch(dwAlgId)
  {
  case SHA1:
    pbyOID = &kbyoidSHA1[0];
    dwOIDLen = sizeof(kbyoidSHA1);
    break;
  case SHA256:
    pbyOID = &kbyoidSHA256[0];
    dwOIDLen = sizeof(kbyoidSHA256);
    break;
  default:
   
    printf("BuildFullHash  0x%08x, 0x%08x, 0x%08x\n", pData, pbyHash, FALSE);
    return FALSE;
  }
  }

  *pbyHash = (CK_BYTE_PTR) malloc(dwHashLen + dwOIDLen);
  if(!(*pbyHash))
  {
    printf("BuildFullHash (HOST_MEMORY step 2) 0x%08x, 0x%08x, 0x%08x\n", pData, pbyHash, FALSE);
    if(pMyHash) free (pMyHash);
    return FALSE;
  }

  if(pbyOID && useOID)
    memcpy(*pbyHash, pbyOID, dwOIDLen);
  
  memcpy( (*pbyHash)+dwOIDLen, pMyHash, dwHashLen);

  *pdwFullHashLen = dwHashLen + dwOIDLen;
end_hash:
  if (pMyHash)
    free(pMyHash);
  printf("BuildFullHash 0x%08x, 0x%08x, 0x%08x\n", pData, pbyHash, TRUE);
  return TRUE;
}

void showBytes(unsigned char * byData, size_t sData)
{
   int nLength = sData * 3;
   char *pBuffer = (char *)calloc(nLength, sizeof(char));
   if (pBuffer)
   {
     char *p;
     p = pBuffer;
     for (int i = 0; i < (int)sData; i++)
     {
        sprintf(p, (i == sData-1) ? "%02X" : "%02X ", byData[i]);
        p = p + 3;
     }

     printf("\nArray of bytes (%lu) : %s\n", sData, pBuffer);

     free(pBuffer);
   }
}

void deleteCache( )
{
  char * p = NULL;
  char cachedir [128] =
#ifdef WIN32
    "\\santesocial\\cps\\cache\\*.*";
#elif defined (UNIX_OSX)
    "/Library/Preferences/santesocial/CPS/cache/*";
#else
    "/etc/opt/santesocial/CPS/cache/*";
#endif
  char * cmdDel =
#ifdef WIN32
    "del /Q";
#else
    "rm -f";
#endif
  char cmdFull[128];
#ifdef WIN32
  char cachedirTemp[128];
  p = sys_GetAllUsersDir( );
  strcpy(cachedirTemp, p);
  strcat(cachedirTemp, cachedir);
  p = cachedirTemp;
#else
  p = cachedir;
#endif

  sprintf(cmdFull, "%s %s", cmdDel, p);

  printf("Delete cache command : %s\n", cmdFull);

  sys_ExecuteCommand(cmdFull);
}


int modifyFile(char * dirName, char * serialNumber, char * suffix);

int modifyCache( char * serialNumber , char * suffix)
{
  int rc;
  char * p = NULL;
  char desiredSerialNumber[64];
  char cachedir [128] =
#ifdef WIN32
    "\\santesocial\\cps\\cache\\";
#elif defined (UNIX_OSX)
    "/Library/Preferences/santesocial/CPS/cache/";
#else
    "/etc/opt/santesocial/CPS/cache/";
#endif
#ifdef WIN32
  char cachedirTemp[128];
  p = sys_GetAllUsersDir( );
  strcpy(cachedirTemp, p);
  strcat(cachedirTemp, cachedir);
  p = cachedirTemp;
#else
  p = cachedir;
#endif
  char * pBlank = strchr(serialNumber, 0x20);
  strcpy(desiredSerialNumber, serialNumber);
  if(pBlank)
  {
    size_t cbData = pBlank - serialNumber;
    strncpy(desiredSerialNumber, serialNumber, cbData);
    desiredSerialNumber[cbData] =0;
  }
  rc = modifyFile(p, desiredSerialNumber, suffix);
  return rc;
}

int modifyFile(char * dirName, char * serialNumber, char * suffix)
{
  char absoluteFileName[256];
  /*char * tabCardFiles[] = { "_00015031",
"_00015032","_00017001","_00017002","_00017004","_00017005","_00017006","_00017102","_00017104","_00017105","_00017106","_0001A001","_0001A002","_0001A003","_0001D121","_0001D122","_0001D123","_0001D124","_0001D125","_0001D126","_0001D127","_0001D128","_0001D129","_00025031","_00025032","_2F00","_s_00015031","_s_00015032","_s_00025031","_s_00025032",
"_s_2F00",
NULL
};*/

//  char * tabCardFiles[] = { "_2F00", NULL};

  int index = 0;
  int rc;
  unsigned char * pData;
  size_t ulDataLen;
  /*while (tabCardFiles[index] != NULL)
  {*/
    strcpy(absoluteFileName, dirName);
    strcat(absoluteFileName, serialNumber);
    strcat(absoluteFileName, suffix);
    ulDataLen = 0;
    /* lire le fichier de cache */
    rc = IOReadFile(absoluteFileName, &pData, &ulDataLen);
    if (!rc) {
      if (pData) {
        /* changer deux octets */
        pData[3] = 'A';
        pData[4] = 'B';

        rc = IOWriteFile(absoluteFileName, pData, ulDataLen);
        printf("File %s successfully rewrited\n", absoluteFileName);

        /* liberer la zone mémoire */
        free( pData );
        pData = NULL;
      }
    }
    index++;
  /*}*/
    return rc;
}

#if defined __APPLE__ || defined UNIX_LUX
#include <unistd.h>
int testScenario_1144( CK_FUNCTION_LIST *pFunctionList )
{
	CK_RV rv;
	int i, rc = 0;
	
	printf("VŽrifier qu'un lecteur PSS avec carte CPS est connecte au poste.\nVŽrifier que les traces Cryptolib sont activees\n");
	getchar();
	
	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
		CK_TOKEN_INFO tokenInfo;
		CK_ULONG ulSlotsListSize = MAX_SLOTS;
		
		//recupération de la liste des slots avec carte
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
		if (rv != CKR_OK || ulSlotsListSize == 0) 
		{
			rc = 1;
			goto fin_1144;
		}
		
		currentSlotID = tabSlots[0];
		
		rv = (*pFunctionList->C_GetTokenInfo)(currentSlotID, &tokenInfo);
		if (rv != CKR_OK) {
			rc = 1;
			goto fin_1144;
		}
		
		printf("DŽbrancher le lecteur PSS du poste.\n");
		getchar();
		
		for (i=0; i<25; i++) {
			rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
			if (rv != CKR_OK || ulSlotsListSize != 0) {
				rc = 1;
				goto fin_1144;
			}
			usleep(600);
		}
		
		printf("Rebrancher le lecteur PSS au poste.\n");
		getchar();
		
		ulSlotsListSize = MAX_SLOTS;
		for (i=0; i<25 && ulSlotsListSize == MAX_SLOTS; i++) {
			rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
			if (rv != CKR_OK) {
				rc = 1;
				goto fin_1144;
			}
			usleep(600);
		}
		
		if (ulSlotsListSize != 0) {
			printf("OK. Le lecteur PSS est rebranche.\n"); 
		}

fin_1144:
		(*pFunctionList->C_Finalize)(NULL);
		
	}

	return rc;	
}


#endif
