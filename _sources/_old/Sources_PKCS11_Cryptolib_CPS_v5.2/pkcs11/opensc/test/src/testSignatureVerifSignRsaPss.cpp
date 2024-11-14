#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "testconstants.h"

#define DATA_TO_SIGN "document_to_sign"

/* RSA PSS error types */
#define RSA_PSS_ERR_NO_PARAMETER        1
#define RSA_PSS_ERR_MSM_ALG        2
#define RSA_PSS_ERR_MISMATCH_PARAM_LEN  3

extern sTESTS_MSGS     MsgsTbl[];

extern CK_BBOOL isCPS2TerGALSS;
extern CK_BBOOL isCPS2TerPCSC;

extern unsigned short getIndexDebutSectionTests(int searchedTestLevel);
extern int testGetPkcs11Object(CK_FUNCTION_LIST* pFunctionList, CK_SESSION_HANDLE sessionRO, int testLevel, int keySpec, CK_CHAR_PTR pin, CK_OBJECT_HANDLE_PTR phObject, int* pTestNumber);
extern void testSetMechanism(int testLevel, int keySpec, CK_RV expectedRv, CK_MECHANISM_PTR pMechanism);
extern void testSetData(int testLevel, int keySpec, CK_RV expectedRv, CK_BYTE_PTR* ppData, CK_ULONG_PTR pulDataLen);
extern void testFreeData(CK_BYTE_PTR* ppData, CK_ULONG_PTR pulDataLen);
extern void checkPrintResult(char* mesgTest, CK_RV rv, int testNumber, sTESTS_MSGS* table);
extern void showBytes(unsigned char* byData, size_t sData);
extern unsigned short BuildFullHash(CK_FUNCTION_LIST* pFunctionList, CK_SESSION_HANDLE sessionRO, CK_CHAR_PTR pData, CK_BYTE_PTR* pbyHash, CK_ULONG* pdwFullHashLen, unsigned int dwAlgId, int useOID);

extern CK_BYTE_PTR pbySignature2;
extern CK_ULONG ulSignatureLen2;
extern CK_BYTE_PTR pbySignature3;
extern CK_ULONG ulSignatureLen3;

#define SHA1_HASH_LEN 0x14
#define SHA256_HASH_LEN 0x20

/* signature RSA PSS avec un buffer statique de taille suffisante */
void CPSGES_Sign_RSAPSS(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_OBJECT_HANDLE privateKey, CK_CHAR_PTR message, CK_ULONG messageLen, int errorType, int * pTestNumber, CK_BYTE_PTR pbuf, CK_ULONG_PTR buf_len)
{
    CK_RV rv;
    CK_MECHANISM smech;
    int error = 0;
    CK_BYTE_PTR sign = NULL_PTR;
    CK_ULONG slen = 0;
    const CK_RSA_PKCS_MGF_TYPE ckRsaPssMGF = (mtype == CKM_SHA1_RSA_PKCS_PSS) ? CKG_MGF1_SHA1 : CKG_MGF1_SHA256;

    CK_RSA_PKCS_PSS_PARAMS rsaPkcsPssParams;
    rsaPkcsPssParams.hashAlg = (mtype == CKM_SHA1_RSA_PKCS_PSS) ? CKM_SHA_1 : CKM_SHA256;
    rsaPkcsPssParams.mgf = ckRsaPssMGF;
    rsaPkcsPssParams.sLen = (mtype == CKM_SHA1_RSA_PKCS_PSS) ? SHA1_HASH_LEN : SHA256_HASH_LEN;

    smech.mechanism = mtype;
    smech.pParameter = &rsaPkcsPssParams;
    smech.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);

    char* textMsg = "C_SignInit et param" E_GRAVE "tres corrects";
    if (errorType != 0) {
        textMsg = "C_SignInit et param" E_GRAVE "tres incorrects";
    }
    switch (errorType) {
    case RSA_PSS_ERR_NO_PARAMETER:
        smech.pParameter = NULL;
        break;
    case RSA_PSS_ERR_MISMATCH_PARAM_LEN: {
        smech.ulParameterLen = 124;
        break;
    }
    case RSA_PSS_ERR_MSM_ALG:
        if (mtype == CKM_SHA1_RSA_PKCS_PSS) {
            rsaPkcsPssParams.hashAlg = CKM_SHA256;
        }
        if (mtype == CKM_SHA256_RSA_PKCS_PSS) {
            rsaPkcsPssParams.hashAlg = CKM_SHA_1;
        }
        break;
    default:;
    }

    showBytes(message, messageLen);
#if 0
    _IOWriteFile("data.bin", message, messageLen);
#endif

    (*pTestNumber)++;
    rv = (*pFunctionList->C_SignInit)(hSession, &smech, privateKey);
    checkPrintResult(textMsg, rv, *pTestNumber, MsgsTbl);

    if (rv != CKR_OK) {
        fprintf(stderr, "\nC_SignInit failed: rv = 0x%.8X\n", rv);
        error = 1;
    }
    else {
        (*pTestNumber)++;
        printf("\nC_Sign() with size query.\n");
        rv = (*pFunctionList->C_Sign)(hSession, (CK_BYTE_PTR)message, messageLen, (CK_BYTE_PTR)sign, &slen);
        checkPrintResult("C_Sign et demande de la taille", rv, *pTestNumber, MsgsTbl);

        if (rv != CKR_OK) {
            fprintf(stderr, "\nC_Sign failed: rv = 0x%.8X\n", rv);
            error = 1;
        }
        else {
            (*pTestNumber)++;
            sign = (CK_BYTE_PTR)malloc(slen);

            printf("\nC_Sign() with actual signing.\n");
            rv = (*pFunctionList->C_Sign)(hSession, (CK_BYTE_PTR)message, messageLen, (CK_BYTE_PTR)sign, &slen);
            checkPrintResult("C_Sign et calcul de la signature", rv, *pTestNumber, MsgsTbl);

            if (rv != CKR_OK) {
                fprintf(stderr, "\nC_Sign failed: rv = 0x%.8X\n", rv);
                error = 1;
            }
        }

        if (rv == CKR_OK) {
            fprintf(stdout, "\nMessage was successfully signed with private key!\n");

            showBytes(sign, slen);

            if (sign != NULL_PTR) {
                memcpy(pbuf, sign, slen);
                *buf_len = slen;
                free(sign);
                sign = NULL_PTR;
            }
        }
        else {
            fprintf(stderr, "\nError during signing !!\n");
        }
    }
}

void CPSGES_Verify_RSAPSS(CK_FUNCTION_LIST_PTR pFunctionList, CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mtype, CK_OBJECT_HANDLE pubKey, CK_CHAR_PTR message, CK_ULONG messageLen, int* pTestNumber, CK_BYTE_PTR sig, CK_ULONG slen)
{
    CK_RV rv;
    CK_MECHANISM smech;
    int error = 0;
    //CK_BYTE_PTR sig = NULL_PTR;
    //CK_ULONG slen = 0;
    CK_RSA_PKCS_MGF_TYPE ckRsaPssMGF = (mtype == CKM_SHA1_RSA_PKCS_PSS) ? CKG_MGF1_SHA1 : CKG_MGF1_SHA256;
    size_t slenRead;

    CK_RSA_PKCS_PSS_PARAMS rsaPkcsPssParams;
    rsaPkcsPssParams.hashAlg = (mtype == CKM_SHA1_RSA_PKCS_PSS) ? CKM_SHA_1 : CKM_SHA256;
    rsaPkcsPssParams.mgf = ckRsaPssMGF;
    rsaPkcsPssParams.sLen = (mtype == CKM_SHA1_RSA_PKCS_PSS) ? SHA1_HASH_LEN : SHA256_HASH_LEN;

    smech.mechanism = mtype;
    smech.pParameter = &rsaPkcsPssParams;
    smech.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);

    (*pTestNumber)++;
    showBytes(message, messageLen);
   /* char* sig1 = (testOK == TRUE) ? "rsa_pss_sig.bin" : "rsa_pss_sigko.bin";
    char* sig256 = (testOK == TRUE) ? "rsa_pss_sig256.bin" : "rsa_pss_sig256ko.bin";
    error = _IOReadFile((mtype == CKM_SHA1_RSA_PKCS_PSS) ? sig1 : sig256, &sig, &slenRead);
    if (error) {
        return;
    }*/

    rv = (*pFunctionList->C_VerifyInit)(hSession, &smech, pubKey);
    checkPrintResult("C_VerifyInit et parametres corrects", rv, *pTestNumber, MsgsTbl);

    if (rv != CKR_OK) {
        fprintf(stderr, "\nC_VerifyInit failed: rv = 0x%.8X\n", rv);
        error = 1;
    }
    else {
        (*pTestNumber)++;
        printf("\nCall C_Verify().\n");
        rv = (*pFunctionList->C_Verify)(hSession, (CK_BYTE_PTR)message, messageLen, (CK_BYTE_PTR)sig, slen);
        checkPrintResult("C_Verify et parametres corrects", rv, *pTestNumber, MsgsTbl);

        if (rv != CKR_OK) {
            fprintf(stderr, "\nC_Verify failed: rv = 0x%.8X\n", rv);
            error = 1;
        }

        if (rv == CKR_OK) {
            showBytes( sig, slen);
        }
    }
}

//*******************************************************************
// Effectue les tests de signature RSA PSS
//*******************************************************************
void testSignatureRsaPssManagementFunctions(CK_FUNCTION_LIST* pFunctionList, CK_CHAR_PTR pin, CK_BYTE_PTR bufSignature, CK_ULONG_PTR pulBufSignatureLen, CK_BYTE_PTR bufSignature_256, CK_ULONG_PTR pulBufSignature_256Len)
{
    int testNumber = getIndexDebutSectionTests(SIGNATU_RSA_PSS_FUNCTIONS);
	CK_RV rv;
	CK_SESSION_HANDLE sessionRO;
    CK_OBJECT_HANDLE hPrivKey = 0, hPubKey;
    CK_BYTE sig[256];
    CK_ULONG slen;

	rv = (*pFunctionList->C_Initialize)(NULL);
    if (rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
    {
        CK_SLOT_ID tabSlots[MAX_SLOTS], currentSlotID;
        CK_ULONG ulSlotsListSize = MAX_SLOTS;
        //recupération de la liste des slots avec carte
        rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlots, &ulSlotsListSize);
        if (rv != CKR_OK || ulSlotsListSize == 0) return;

        currentSlotID = tabSlots[0];

        //ouverture d'une session en lecture seule sur le premier slot
        rv = (*pFunctionList->C_OpenSession)(currentSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sessionRO);
        checkPrintResult("C_OpenSession sur premier slot", rv, testNumber, MsgsTbl);
        if (rv != CKR_OK) {
            (*pFunctionList->C_Finalize)(NULL);
            return;
        }
        testNumber++;

        rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);
        if (rv != CKR_OK) {
            (*pFunctionList->C_Finalize)(NULL);
            return;
        }
        checkPrintResult("C_Login avec code porteur correct", rv, testNumber, MsgsTbl);

        // Recuperer l'objet clé privée d'authentification (AT_KEYEXCHANGE)
        testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, AT_KEYEXCHANGE, pin, &hPrivKey, NULL);

        CPSGES_Sign_RSAPSS(pFunctionList, sessionRO, CKM_SHA1_RSA_PKCS_PSS, hPrivKey, (CK_CHAR_PTR)DATA_TO_SIGN, strlen(DATA_TO_SIGN), 0, &testNumber, sig, &slen);

        // Recuperer l'objet clé publique d'authentification (AT_KEYEXCHANGE)
        testGetPkcs11Object(pFunctionList, sessionRO, VERISGN_FUNCTIONS, AT_KEYEXCHANGE, pin, &hPubKey, NULL);

        CPSGES_Verify_RSAPSS(pFunctionList, sessionRO, CKM_SHA1_RSA_PKCS_PSS, hPubKey, (CK_CHAR_PTR)DATA_TO_SIGN, strlen(DATA_TO_SIGN), &testNumber, sig, slen);

        CPSGES_Sign_RSAPSS(pFunctionList, sessionRO, CKM_SHA256_RSA_PKCS_PSS, hPrivKey, (CK_CHAR_PTR)DATA_TO_SIGN, strlen(DATA_TO_SIGN), 0, &testNumber, sig, &slen);

        CPSGES_Verify_RSAPSS(pFunctionList, sessionRO, CKM_SHA256_RSA_PKCS_PSS, hPubKey, (CK_CHAR_PTR)DATA_TO_SIGN, strlen(DATA_TO_SIGN), &testNumber, sig, slen);
    }
}