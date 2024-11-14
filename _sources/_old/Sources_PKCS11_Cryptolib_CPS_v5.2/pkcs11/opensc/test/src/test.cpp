// test.cpp : Defines the entry point for the console application.
//

#include "testsysdef.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#ifdef WITH_OPENSSL
#include "openssl/pkcs12.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#endif
#include "testsystem.h"
#include "testconstants.h"

#include "pkcs11.h"

/*************************************************************

  VARIABLES
  
*************************************************************/
#define NO_TRACE      0
#define TRACE_INFO    1
#define TRACE_DEBUG   2
#define TRACE_MAX     3


#define LIGNE_VIDE_CSV ";;;"


sTESTS_MSGS     MsgsTbl[]={
	{ 0, 0x0, "Récupération des pointeurs de fonction (C_GetFunctionList)"},
	{ 1, CKR_CRYPTOKI_NOT_INITIALIZED, "Tentative de fermeture de la librairie qui n'a pas été initialisé (C_Finalize)"},
	{ 2, CKR_CRYPTOKI_NOT_INITIALIZED, "Récupération d'informations de la librairie sans avoir préalablement initialiser (C_GetInfo)"},
  { 4, CKR_OK, "Initialisation avec pointeur d'initialisation (cas 3) (C_Initialize)"},
  { 5, CKR_OK, "Initialisation avec pointeur d'initialisation (cas 4) (C_Initialize)"},
  { 6, CKR_OK, "Initialisation avec pointeur d'initialisation (cas 1) (C_Initialize)"},
  { 7, CKR_OK, "Initialisation avec pointeur d'initialisation (cas 2) (C_Initialize)"},
  { 8, CKR_ARGUMENTS_BAD, "Initialisation avec pointeur d'initialisation (CKR_ARGUMENTS_BAD) (C_Initialize)"},
	{ 9, 0x0, "Initialisation avec pointeur d'initialisation à NULL (C_Initialize)"},
	{ 10, CKR_CRYPTOKI_ALREADY_INITIALIZED, "Initialisation de la librairie déjà initialisée (C_Initialize)"},
	{ 11, CKR_ARGUMENTS_BAD, "Récupération d'informations de la librairie avec un paramètre null (C_GetInfo)"},
	{ 12, 0x0, "Récupération d'informations de la librairie (C_GetInfo)"},
	{ 13, 0x0, "Fermeture (C_Finalize)"},

  {GENPURP_FUNCTIONS,CKR_CRYPTOKI_NOT_INITIALIZED,"Récupération de la liste des lecteurs sans avoir initialisé la librairie (C_GetSlotList)"},
	{GENPURP_FUNCTIONS+1,CKR_CRYPTOKI_NOT_INITIALIZED,"Récupération des informations du lecteur sans avoir initialisé la librairie (C_GetSlotInfo)"},
	{GENPURP_FUNCTIONS+2,CKR_CRYPTOKI_NOT_INITIALIZED,"Récupération des informations de la carte sans avoir initialisé la librairie (C_GetTokenInfo)"},
	{GENPURP_FUNCTIONS+3,0x54,"Attente d'un évenement du lecteur sans avoir initialisé la librairie (C_WaitForSlotEvent)"},
  {GENPURP_FUNCTIONS+4,CKR_CRYPTOKI_NOT_INITIALIZED,"Récupération de la liste des mécanismes supportés sans avoir initialisé la librairie (C_GetMechanismList)"},
	{GENPURP_FUNCTIONS+5,CKR_CRYPTOKI_NOT_INITIALIZED,"Récupération des informations d'un mécanisme sans avoir initialisé la librairie (C_GetMechanismInfo)"},
  {GENPURP_FUNCTIONS+6,CKR_CRYPTOKI_NOT_INITIALIZED,"Initialisation de la carte sans avoir initialisé la librairie (C_InitToken)"},
  {GENPURP_FUNCTIONS+7,CKR_CRYPTOKI_NOT_INITIALIZED,"Initialisation de la carte via le code PIN sans avoir initialisé la librairie (C_InitPIN)"},
	{GENPURP_FUNCTIONS+8,0x190,"Modification du code PIN de la carte sans avoir initialisé la librairie (C_SetPIN)"},
	{GENPURP_FUNCTIONS+9,CKR_ARGUMENTS_BAD,"Récupération de la liste des lecteurs avec un paramètre pulCount à NULL (C_GetSlotList)"},
	{GENPURP_FUNCTIONS+10,0x0,"Récupération du nombre de lecteurs (C_GetSlotList)"},
	{GENPURP_FUNCTIONS+11,0x0,"Récupération des identifiants des lecteurs (C_GetSlotInfo)"},
	{GENPURP_FUNCTIONS+12,0x150,"Récupération des identifiants des lecteurs avec un buffer trop petit (C_GetSlotList)"},
	{GENPURP_FUNCTIONS+13,0x0,"Récupération du nombre de lecteurs ayant une carte insérée (C_GetSlotList)"},
  {GENPURP_FUNCTIONS+14,0x0,"Récupération liste des lecteurs ayant une carte insérée (C_GetSlotList)"},
	{GENPURP_FUNCTIONS+15,CKR_ARGUMENTS_BAD,"Récupération des informations du lecteur avec un paramètre pInfo à NULL (C_GetSlotInfo)"},
	{GENPURP_FUNCTIONS+16,CKR_SLOT_ID_INVALID,"Récupération des informations du lecteur avec un mauvais identifiant de lecteur (C_GetSlotInfo)"},
	{GENPURP_FUNCTIONS+17,0x0,"Récupération des informations du lecteur (C_GetSlotInfo)"},
	{GENPURP_FUNCTIONS+18,CKR_ARGUMENTS_BAD,"Récupération des informations de la carte avec le paramètre pInfo à NULL (C_GetTokenInfo)"},
	{GENPURP_FUNCTIONS+19,0x3,"Récupération des informations de la carte avec un mauvais identifiant de lecteur (C_GetTokenInfo)"},
	{GENPURP_FUNCTIONS+20,0x0,"Récupération des informations de la carte (C_GetTokenInfo)"},
	{GENPURP_FUNCTIONS+21,0x54,"Attente d'un évenement du lecteur avec le flag à 0,retrait carte (C_WaitForSlotEvent)"},
  {GENPURP_FUNCTIONS+22,0x54,"Attente d'un évenement du lecteur avec le flag à 0 réinsertion carte (C_WaitForSlotEvent)"},
	{GENPURP_FUNCTIONS+23,0x8,"Attente d'un évenement du lecteur avec le flag à CKF_DONT_BLOCK (C_WaitForSlotEvent)"},
	{GENPURP_FUNCTIONS+24,0x150,"Récupération de la liste des mécanismes supportés avec un buffer trop petit (C_GetMechanismList)"},
	{GENPURP_FUNCTIONS+25,0x0,"Récupération du nombre de mécanismes supportés (C_GetMechanismList)"},
	{GENPURP_FUNCTIONS+26,0x0,"Récupération de la liste des mécanismes supportés (C_GetMechanismList)"},
	{GENPURP_FUNCTIONS+27,0x0,"Récupération des informations de chaque mécanisme supporté (C_GetMechanismInfo)"},
  {GENPURP_FUNCTIONS+28,CKR_OK,"Liste des lecteurs avec carte insérée (cache valide) (C_GetSlotList)"},
  {GENPURP_FUNCTIONS+29,CKR_OK,"Initialisation de la librairie (cache modifié) (C_Initialize)"},
  {GENPURP_FUNCTIONS+30,CKR_OK,"Liste des lecteurs avec carte insérée (cache modifié) (C_GetSlotList)"},

  {SESSION_FUNCTIONS,0x0,"Ouverture d'une session en lecture seule (C_OpenSession)"},
	{SESSION_FUNCTIONS+1,0x0,"Ouverture d'une session en lecture et écriture (C_OpenSession)"},
  {SESSION_FUNCTIONS+2,0x0,"Ouverture d'une 3eme session en lecture seule (C_OpenSession)"},
  {SESSION_FUNCTIONS+3,0x0,"Ouverture d'une 4eme session en lecture seule (C_OpenSession)"},
  {SESSION_FUNCTIONS+4,0x0,"Ouverture d'une 5eme session en lecture seule (C_OpenSession)"},
	{SESSION_FUNCTIONS+5,0x0,"Récupération des informations d'une session (C_GetSessionInfo)"},
	{SESSION_FUNCTIONS+6,0xB7,"Login SO sur une session en lecture seule (C_Login)"},
	{SESSION_FUNCTIONS+7,0x0,"Login d'un utilisateur (C_Login)"},
	{SESSION_FUNCTIONS+8,0x100,"Login dans une session déjà loguée (C_Login)"},
	{SESSION_FUNCTIONS+9,0x54,"GetOperationState (C_GetOperationState)"},
	{SESSION_FUNCTIONS+10,0x54,"SetOperationState (C_SetOperationState)"},
	{SESSION_FUNCTIONS+11,0x0,"Déconnexion (C_Logout)"},
	{SESSION_FUNCTIONS+12,0x0,"Fermeture d'une session (C_CloseSession)"},
	{SESSION_FUNCTIONS+13,0x0,"Fermeture de toutes les sessions (C_CloseAllSessions)"},
  {SESSION_FUNCTIONS+14,CKR_SESSION_HANDLE_INVALID,"Essai de fermeture de la session 3 (C_CloseSession)"},
  {SESSION_FUNCTIONS+15,CKR_SESSION_HANDLE_INVALID,"Récupération des informations d'une session avec un mauvais handle de session renseigné (C_GetSessionInfo)"},
  {SESSION_FUNCTIONS+16,CKR_SESSION_HANDLE_INVALID,"Login avec un mauvais handle de session renseigné (C_Login)"},
  {SESSION_FUNCTIONS+17, CKR_ARGUMENTS_BAD, "Ouverture d'une session et paramètre d'entrée incorrect (C_OpenSession)"},
	{SESSION_FUNCTIONS+18,CKR_CRYPTOKI_NOT_INITIALIZED,"Ouverture d'une session sans avoir initialisé la librairie (C_OpenSession)"},
	{SESSION_FUNCTIONS+19,CKR_CRYPTOKI_NOT_INITIALIZED,"Récupération des informations d'une session sans avoir initialisé la librairie (C_GetSessionInfo)"},
	{SESSION_FUNCTIONS+20,CKR_CRYPTOKI_NOT_INITIALIZED,"Login sans avoir initialisé la librairie (C_Login)"},
  {SESSION_FUNCTIONS+21,CKR_CRYPTOKI_NOT_INITIALIZED,"InitPIN sans avoir initialisé la librairie (C_InitPIN)"},
  {SESSION_FUNCTIONS+22, CKR_CRYPTOKI_NOT_INITIALIZED,"Déconnexion sans avoir initialisé la librairie (C_Logout)"},
  
  {OBJECTS_FUNCTIONS,CKR_CRYPTOKI_NOT_INITIALIZED,"Init recherche d'objets et lib non intialisée (C_FindObjectInit)"},
  {OBJECTS_FUNCTIONS+1,CKR_CRYPTOKI_NOT_INITIALIZED,"Execution recherche d'objets et lib non intialisée (C_FindObjects)"},
  {OBJECTS_FUNCTIONS+2,CKR_CRYPTOKI_NOT_INITIALIZED,"Fin de recherche d'objets et lib non intialisée (C_FindObjectsFinal)"},
  {OBJECTS_FUNCTIONS+3,CKR_CRYPTOKI_NOT_INITIALIZED,"Recuperation d'attribut d'objet et lib non intialisée (C_GetAttributeValue)"},
  {OBJECTS_FUNCTIONS+4,0x54,"Création d'un objet (C_CreateObject)"},
	{OBJECTS_FUNCTIONS+5,0x54,"Copie d'un objet (C_CopyObject)"},
	{OBJECTS_FUNCTIONS+6,0xB3,"Initialisation de recherche d'objet avec un mauvais handle de session renseigné (C_FindObjectsInit)"},
	{OBJECTS_FUNCTIONS+7,0x0,"Initialisation de recherche d'objet (C_FindObjectsInit)"},
	{OBJECTS_FUNCTIONS+8,0x0,"Recherche d'objet (C_FindObjects)"},
	{OBJECTS_FUNCTIONS+9,0xB3,"Recherche d'objet avec un mauvais handle de session (C_FindObjects)"},
	{OBJECTS_FUNCTIONS+10,0x54,"Récuperation de la taille d'un objet (C_GetObjectSize)"},
	{OBJECTS_FUNCTIONS+11,0x0,"Fin de la recherche d'objets (C_FindObjectsFinal)"},
  {OBJECTS_FUNCTIONS+12,0x0,"Récupération d'un attribut d'objets (C_GetAttributeValue)"},
  {OBJECTS_FUNCTIONS+13,0x0,"Initialisation de recherche de clé privée de signature (C_FindObjectsInit)"},
	{OBJECTS_FUNCTIONS+14,0x0,"Recherche de clé privée de signature (C_FindObjects)"},
  {OBJECTS_FUNCTIONS+15,0x0,"Fin de recherche de clé privée de signature (C_FindObjectsFinal)"},
  {OBJECTS_FUNCTIONS+16,0x0,"Initialisation de recherche de clé publique de signature (C_FindObjectsInit)"},
	{OBJECTS_FUNCTIONS+17,0x0,"Recherche de clé publique de signature (C_FindObjects)"},
  {OBJECTS_FUNCTIONS+18,0x0,"Fin de recherche de clé publique de signature (C_FindObjectsFinal)"},

  {ENCRYPT_FUNCTIONS_CPS3,CKR_FUNCTION_NOT_SUPPORTED,"Initialisation de chiffrement non supporte en CPS3 (C_EncryptInit)"},

  {ENCRYPT_FUNCTIONS+1,CKR_SESSION_HANDLE_INVALID,"Initialisation de chiffrement avec handle de session invalide (C_EncryptInit)"},
  {ENCRYPT_FUNCTIONS+2,CKR_KEY_HANDLE_INVALID,"Initialisation de chiffrement d'objet avec un mauvais handle de clé (C_EncryptInit)"},
	{ENCRYPT_FUNCTIONS+3,CKR_MECHANISM_INVALID,"Initialisation de chiffrement avec mauvais mécanisme (C_EncryptInit)"},
  {ENCRYPT_FUNCTIONS+4,CKR_KEY_TYPE_INCONSISTENT,"Initialisation de chiffrement avec type de clé incohérent (C_EncryptInit)"},
  {ENCRYPT_FUNCTIONS+5,CKR_OPERATION_NOT_INITIALIZED,"Chiffrement et opération non initialisée (C_Encrypt)"},
  {ENCRYPT_FUNCTIONS+6,CKR_OK,"Initialisation de chiffrement correcte (C_EncryptInit)"},
	{ENCRYPT_FUNCTIONS+7,CKR_ARGUMENTS_BAD,"Chiffrement avec mauvais paramètres (C_Encrypt)"},
  {ENCRYPT_FUNCTIONS+8,CKR_BUFFER_TOO_SMALL,"Chiffrement avec taille en sortie insuffisante (C_Encrypt)"},
  {ENCRYPT_FUNCTIONS+9,CKR_OK,"Chiffrement et paramètres corrects (C_Encrypt)"},

  {DECRYPT_FUNCTIONS,CKR_CRYPTOKI_NOT_INITIALIZED,"Initialisation de déchiffrement et librairie non initialisée (C_DecryptInit)"},
  {DECRYPT_FUNCTIONS+1,CKR_SESSION_HANDLE_INVALID,"Initialisation de déchiffrement avec handle de session invalide (C_DecryptInit)"},
  {DECRYPT_FUNCTIONS+2,CKR_OK,"Initialisation de déchiffrement, login utilisateur  (C_Login)"},
	{DECRYPT_FUNCTIONS+3,CKR_OBJECT_HANDLE_INVALID,"Initialisation de déchiffrement avec mauvais handle de clé (C_DecryptInit)"},
  {DECRYPT_FUNCTIONS+4,CKR_MECHANISM_INVALID,"Initialisation de déchiffrement d'objet avec un mauvais mécanisme (C_DecryptInit)"},
  {DECRYPT_FUNCTIONS+5,CKR_USER_NOT_LOGGED_IN,"Initialisation de déchiffrement et utilisateur non logué (C_DecryptInit)"},
  {DECRYPT_FUNCTIONS+6,CKR_OPERATION_NOT_INITIALIZED,"Déchiffrement et opération non initialisée (C_Decrypt)"},
  {DECRYPT_FUNCTIONS+7,CKR_SESSION_HANDLE_INVALID,"Déchiffrement et handle de session invalide (C_Decrypt)"},
  {DECRYPT_FUNCTIONS+8,CKR_OK,"Initialisation de déchiffrement correct, utilisateur authentifié (C_DecryptInit)"},
  {DECRYPT_FUNCTIONS+9,CKR_ARGUMENTS_BAD,"Déchiffrement et paramètre d'entrée invalide (C_Decrypt)"},
  {DECRYPT_FUNCTIONS+10,CKR_BUFFER_TOO_SMALL,"Déchiffrement et buffer de sortie trop petit (C_Decrypt)"},
  {DECRYPT_FUNCTIONS+11,CKR_OK,"Déchiffrement avec demande de la taille en sortie (C_Decrypt)"},
  {DECRYPT_FUNCTIONS+12,CKR_OK,"Déchiffrement effectif (C_Decrypt)"},
  {DECRYPT_FUNCTIONS+13,CKR_OK,"Initialisation librairie (C_Initialize initArgs NULL)"},
  {DECRYPT_FUNCTIONS+14,CKR_OK,"Initialisation de déchiffrement, login utilisateur  (InitArgs NULL)"},
  {DECRYPT_FUNCTIONS+15,CKR_OK,"Initialisation de déchiffrement correct, (C_DecryptInit initArgs NULL)"},
  {DECRYPT_FUNCTIONS+16,CKR_OK,"Déchiffrement avec demande de la taille en sortie (C_Decrypt initArgs NULL)"},
  {DECRYPT_FUNCTIONS+17,CKR_OK,"Déchiffrement effectif (C_Decrypt initArgs NULL)"},
 

   {SIGNATU_FUNCTIONS,CKR_CRYPTOKI_NOT_INITIALIZED,"Initialisation de signature et librairie non initialisée (C_SignInit)"},
   {SIGNATU_FUNCTIONS+1,CKR_CRYPTOKI_NOT_INITIALIZED,"Essai de signature et librairie non initialisée (C_Sign)"},
   {SIGNATU_FUNCTIONS+2,CKR_CRYPTOKI_NOT_INITIALIZED,"Ajout de données à signer et librairie non initialisée (C_SignUpdate)"},
   {SIGNATU_FUNCTIONS+3,CKR_CRYPTOKI_NOT_INITIALIZED,"Essai de signature finale et librairie non initialisée (C_SignFinal)"},
   {SIGNATU_FUNCTIONS+4,CKR_SESSION_HANDLE_INVALID,"Initialisation de signature avec handle de session invalide (C_SignInit)"},
   {SIGNATU_FUNCTIONS+5,CKR_OK,"Initialisation de signature et login utilisateur (C_Login)"},
  {SIGNATU_FUNCTIONS+6,CKR_KEY_HANDLE_INVALID,"Initialisation de signature avec handle de clé invalide (C_SignInit)"},
  {SIGNATU_FUNCTIONS+7,CKR_MECHANISM_INVALID,"Initialisation de signature avec un mauvais mécanisme (C_SignInit)"},
  {SIGNATU_FUNCTIONS+8,CKR_KEY_TYPE_INCONSISTENT,"Initialisation de signature avec type de clé incohérent (C_SignInit)"},
	{SIGNATU_FUNCTIONS+9,CKR_USER_NOT_LOGGED_IN,"Initialisation de signature et utilisateur non authentifié (C_SignInit)"},
  {SIGNATU_FUNCTIONS+10,CKR_OPERATION_NOT_INITIALIZED,"Signature et opération non initialisée (C_Sign)"},
  {SIGNATU_FUNCTIONS+11,CKR_SESSION_HANDLE_INVALID,"Signature et handle de session invalide (C_Sign)"},
  {SIGNATU_FUNCTIONS+12,CKR_OK,"Initialisation de signature correcte (C_SignInit)"},
  {SIGNATU_FUNCTIONS+13,CKR_ARGUMENTS_BAD,"Signature et paramètre d'entrée invalide (C_Sign)"},
  {SIGNATU_FUNCTIONS+14,CKR_OK,"Initialisation de signature correcte (C_SignInit)"},
  {SIGNATU_FUNCTIONS+15,CKR_OK,"Signature avec récupération de la taille de signature (C_Sign)"},
  {SIGNATU_FUNCTIONS+16,CKR_BUFFER_TOO_SMALL,"Signature avec taille de la signature incorrecte (C_Sign)"},
  {SIGNATU_FUNCTIONS+17,CKR_ARGUMENTS_BAD,"Signature avec taille de signature correcte, pData NULL (C_Sign)"},
  {SIGNATU_FUNCTIONS+18,CKR_DATA_LEN_RANGE,"Signature avec taille de données incorrectes (C_Sign)"},
  {SIGNATU_FUNCTIONS+19,CKR_OK,"Initialisation de signature correcte (C_SignInit)"},
  {SIGNATU_FUNCTIONS+20,CKR_OK,"Signature avec paramètres corrects (pSignature à NULL, taille signature) (C_Sign)"},
  {SIGNATU_FUNCTIONS+21,CKR_OK,"Signature avec paramètres corrects (calcul de la signature) (C_Sign)"},
  {SIGNATU_FUNCTIONS+22,CKR_OPERATION_NOT_INITIALIZED,"Signature et opération non initialisée (C_SignUpdate)"},
  {SIGNATU_FUNCTIONS+23,CKR_SESSION_HANDLE_INVALID,"Signature et handle de session invalide (C_SignUpdate)"},
  {SIGNATU_FUNCTIONS+24,CKR_OK,"Initialisation de signature correcte (C_SignInit)"},
  {SIGNATU_FUNCTIONS+25,CKR_ARGUMENTS_BAD,"Signature et paramètre d'entrée invalide (C_SignUpdate)"},
  {SIGNATU_FUNCTIONS+26,CKR_OK,"Signature avec paramètres corrects (C_SignUpdate)"},
  {SIGNATU_FUNCTIONS+27,CKR_OK,"Signature avec paramètres corrects (C_SignUpdate)"},
  {SIGNATU_FUNCTIONS+28,CKR_OPERATION_NOT_INITIALIZED,"Signature finale et opération non initialisée (C_SignFinal)"},
  {SIGNATU_FUNCTIONS+29,CKR_OK,"Initialisation de signature correcte (C_SignInit)"},
  {SIGNATU_FUNCTIONS+30,CKR_SESSION_HANDLE_INVALID,"Signature finale et handle de session invalide (C_SignFinal)"},
  {SIGNATU_FUNCTIONS+31,CKR_ARGUMENTS_BAD,"Signature finale et paramètre d'entrée invalide (C_SignFinal)"},
  {SIGNATU_FUNCTIONS+32,CKR_OK,"Ajout de données à signer avec paramètres corrects (C_SignUpdate)"},
  {SIGNATU_FUNCTIONS+33,CKR_BUFFER_TOO_SMALL,"Signature avec taille du buffer de signature insuffisante (C_SignFinal)"},
  {SIGNATU_FUNCTIONS+34,CKR_OK,"Signature avec récupération de la taille de signature seulement (C_SignFinal)"},
  {SIGNATU_FUNCTIONS+35,CKR_OK,"Signature avec calcul effectif de la signature (C_SignFinal)"},
  {SIGNATU_FUNCTIONS+36,CKR_OK,"Signature de condensat SHA_1 et clé de signature (C_SignInit)"},
  {SIGNATU_FUNCTIONS+37,CKR_OK,"Signature de condensat SHA_1 (taille de signature) (C_Sign)"},
  {SIGNATU_FUNCTIONS+38,CKR_OK,"Signature de condensat SHA_1 (valeur de signature) (C_Sign)"},
  { SIGNATU_FUNCTIONS + 39,CKR_OK,"Signature de condensat SHA_2 et clé de signature (C_SignInit)" },
  { SIGNATU_FUNCTIONS + 40,CKR_OK,"Signature de condensat SHA_2 (taille de signature) (C_Sign)" },
  { SIGNATU_FUNCTIONS + 41,CKR_OK,"Signature de condensat SHA_2 (valeur de signature) (C_Sign)" },
  { SIGNATU_FUNCTIONS + 42,CKR_OK,"Signature de condensat complet SHA_2 et clé de signature (C_SignInit)" },
  { SIGNATU_FUNCTIONS + 43,CKR_OK,"Signature de condensat complet SHA_2 (taille de signature) (C_Sign)" },
  { SIGNATU_FUNCTIONS + 44,CKR_OK,"Signature de condensat complet SHA_2 (valeur de signature) (C_Sign)" },


  {VERISGN_FUNCTIONS,CKR_CRYPTOKI_NOT_INITIALIZED,"Initialisation de vérification de signature et librairie non initialisée (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+1,CKR_CRYPTOKI_NOT_INITIALIZED,"Essai de vérification de signature et librairie non initialisée (C_Verify)"},
  {VERISGN_FUNCTIONS+2,CKR_CRYPTOKI_NOT_INITIALIZED,"Ajout de données à vérifier et librairie non initialisée (C_VerifyUpdate)"},
  {VERISGN_FUNCTIONS+3,CKR_CRYPTOKI_NOT_INITIALIZED,"Essai de vérification effective et librairie non initialisée (C_VerifyFinal)"},
  {VERISGN_FUNCTIONS+4,CKR_SESSION_HANDLE_INVALID,"Initialisation de vérification de signature avec handle de session invalide (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+5,CKR_KEY_HANDLE_INVALID,"Initialisation vérification de signature avec handle de clé invalide (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+6,CKR_MECHANISM_INVALID,"Initialisation vérification de signature avec un mauvais mécanisme (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+7,CKR_ARGUMENTS_BAD,"Initialisation vérification de signature et mauvais paramètre d'entrée (C_VerifyInit)"},
  /*{VERISGN_FUNCTIONS+8,CKR_KEY_TYPE_INCONSISTENT,"Initialisation vérification de signature avec type de clé incohérent (C_VerifyInit)"},*/
  {VERISGN_FUNCTIONS+8,CKR_OPERATION_NOT_INITIALIZED,"Vérification de signature et opération non initialisée (C_Verify)"},
  {VERISGN_FUNCTIONS+9,CKR_SESSION_HANDLE_INVALID,"Vérification de signature et handle de session invalide (C_Verify)"},
  {VERISGN_FUNCTIONS+10,CKR_OK,"Initialisation de verification de signature correcte (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+11,CKR_ARGUMENTS_BAD,"Vérification de signature et paramètre d'entrée invalide (C_Verify)"},
  {VERISGN_FUNCTIONS+12,CKR_DATA_LEN_RANGE,"Vérification de signature avec taille de données incorrectes (C_Verify)"},
  {VERISGN_FUNCTIONS+13,CKR_OK,"Ré-initialisation de verification de signature correcte (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+14,CKR_SIGNATURE_LEN_RANGE,"Vérification de signature avec taille de la signature incorrecte (C_Verify)"},
  {VERISGN_FUNCTIONS+15,CKR_OPERATION_NOT_INITIALIZED,"Vérification de signature et opération terminée (C_Verify)"},
  {VERISGN_FUNCTIONS+16,CKR_OK,"A nouveau, ré-initialisation de verification de signature (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+17,CKR_OK,"Vérification de signature avec tous les paramètres corrects (C_Verify)"},
  {VERISGN_FUNCTIONS+18,CKR_OPERATION_NOT_INITIALIZED,"Vérification de Signature et opération non initialisée (C_VerifyUpdate)"},
  {VERISGN_FUNCTIONS+19,CKR_SESSION_HANDLE_INVALID,"Vérification de Signature et handle de session invalide (C_VerifyUpdate)"},
  {VERISGN_FUNCTIONS+20,CKR_OK,"Initialisation de vérification de signature correcte (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+21,CKR_ARGUMENTS_BAD,"Vérification de signature et paramètre d'entrée invalide (C_VerifyUpdate)"},
  {VERISGN_FUNCTIONS+22,CKR_OK,"Signature avec paramètres corrects (C_VerifyUpdate)"},
  {VERISGN_FUNCTIONS+23,CKR_OK,"Signature avec paramètres corrects (C_VerifyUpdate)"},
  {VERISGN_FUNCTIONS+24,CKR_OPERATION_NOT_INITIALIZED,"Vérification finale de Signature et opération non initialisée (C_VerifyFinal)"},
  {VERISGN_FUNCTIONS+25,CKR_SESSION_HANDLE_INVALID,"Vérification finale de signature et handle de session invalide (C_VerifyFinal)"},
  {VERISGN_FUNCTIONS+26,CKR_OK,"Initialisation correcte de vérification de signature (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+27,CKR_ARGUMENTS_BAD,"Vérification finale de signature et paramètre d'entrée invalide (C_VerifyFinal)"},
  {VERISGN_FUNCTIONS+28,CKR_OK,"Ajout de données à vérifier avec paramètres corrects (C_VerifyUpdate)"},
  {VERISGN_FUNCTIONS+29,CKR_SIGNATURE_LEN_RANGE,"Vérification finale de signature et taille du buffer de signature insuffisante (C_VerifyFinal)"},
  {VERISGN_FUNCTIONS+30,CKR_OPERATION_NOT_INITIALIZED,"Vérification finale de signature et taille du buffer de signature correcte (C_VerifyFinal)"},
  {VERISGN_FUNCTIONS+31,CKR_OK,"De nouveau, initialisation correcte de vérification de signature (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+32,CKR_OK,"Ajout de données à vérifier avec paramètres corrects (C_VerifyUpdate)"},
  {VERISGN_FUNCTIONS+33,CKR_OK,"Vérification de signature (C_VerifyFinal)"},
  {VERISGN_FUNCTIONS+34,CKR_OK,"Vérification de signature de condensat SHA_1 et clé de signature (C_VerifyInit)"},
  {VERISGN_FUNCTIONS+35,CKR_OK,"Vérification de signature de condensat SHA_1 (C_Verify)"},
  { VERISGN_FUNCTIONS + 36,CKR_OK,"Vérification de signature de condensat SHA_256 et clé de signature (C_VerifyInit)" },
  { VERISGN_FUNCTIONS + 37,CKR_OK,"Vérification de signature de condensat SHA_256 (C_Verify)" },
  
  {MDIGEST_FUNCTIONS,CKR_CRYPTOKI_NOT_INITIALIZED,"Initialisation de digest et librairie non initialisée (C_DigestInit)"},
  {MDIGEST_FUNCTIONS+1,CKR_CRYPTOKI_NOT_INITIALIZED,"Operation de digest et librairie non initialisée (C_DigestInit)"},
  {MDIGEST_FUNCTIONS+2,CKR_SESSION_HANDLE_INVALID,"Opération de digest et handle de session invalide (C_DigestInit)"},
  {MDIGEST_FUNCTIONS+3,CKR_OK,"Initialisation de digest correcte (SHA1) (C_DigestInit)"},
  {MDIGEST_FUNCTIONS+4,CKR_OK,"Opération de digest correcte (taille hash) (C_Digest)"},
  {MDIGEST_FUNCTIONS+5,CKR_OK,"Opération de digest correcte (valeur hash) (C_Digest)"},
  {MDIGEST_FUNCTIONS+6,CKR_OK,"Initialisation de digest correcte (SHA256) (C_DigestInit)"},
  {MDIGEST_FUNCTIONS+7,CKR_OK,"MAJ de digest correct (C_DigestUpdate)"},
  {MDIGEST_FUNCTIONS+8,CKR_OK,"Opération de digest correcte (taille hash) (C_DigestFinal)"},
  {MDIGEST_FUNCTIONS+9,CKR_OK,"Opération de digest correcte (valeur hash) (C_DigestFinal)"},
  { MDIGEST_FUNCTIONS + 10,CKR_OK,"Opération de digest non std (Initialisation) (C_DigestInit)" },
  { MDIGEST_FUNCTIONS + 11,CKR_OK,"Opération de digest non std (taille hash) (C_Digest)" },
  { MDIGEST_FUNCTIONS + 12,CKR_OK,"Opération de digest non std (valeur hash) (C_DigestFinal)" },
  { MDIGEST_FUNCTIONS + 13,CKR_OK,"Opération de digest avec buffer alloué (Initialisation) (C_DigestInit)" },
  { MDIGEST_FUNCTIONS + 14,CKR_OK,"Opération de digest avec buffer alloué (taille hash) (C_DigestUpdate)" },
  { MDIGEST_FUNCTIONS + 15,CKR_OK,"Opération de digest avec buffer alloué (valeur hash) (C_DigestFinal)" },
  { MDIGEST_FUNCTIONS + 16,CKR_OK,"Opération de digest avec buffer alloué (Initialisation) (C_DigestInit)" },
  { MDIGEST_FUNCTIONS + 17,CKR_OK,"Opération de digest avec buffer alloué (valeur hash) (C_Digest)" },
  { MDIGEST_FUNCTIONS + 18,CKR_OK,"Opération de digest avec buffer insuffisant (Initialisation) (C_DigestInit)" },
  { MDIGEST_FUNCTIONS + 19,CKR_BUFFER_TOO_SMALL,"Opération de digest avec buffer insuffisant (valeur hash) (C_Digest)" },

  {CPSDATA_TEST_CPS3, CKR_OK,"Ouverture session en lecture/écriture (C_OpenSession)"},
  {CPSDATA_TEST_CPS3+1, CKR_OK,"Login utilisateur PIN correct (C_Login)"},
  {CPSDATA_TEST_CPS3+2, CKR_OK,"Recherche d'objet CPS_DATA (C_FindObjectsInit)"},
  {CPSDATA_TEST_CPS3+3, CKR_OK,"Recherche d'objet CPS_DATA (C_FindObjects)"},
  {CPSDATA_TEST_CPS3+4, CKR_OK,"Recherche d'objet CPS_DATA (C_FindObjectsFinal)"},
  {CPSDATA_TEST_CPS3+5, CKR_OK,"Recuperation taille d'objet CPS_DATA (C_GetAttributeValue)"},
  {CPSDATA_TEST_CPS3+6, CKR_OK,"Recuperation valeur d'objet CPS_DATA (C_GetAttributeValue)"},
  {CPSDATA_TEST_CPS3+7, CKR_OK,"Positionner nouvelle valeur d'objet CPS_DATA (C_SetAttributeValue)"},
  {CPSDATA_TEST_CPS3+8, CKR_OK,"Recuperation nouvelle valeur d'objet CPS_DATA (C_GetAttributeValue)"},
  {CPSDATA_TEST_CPS3+9, CKR_OK,"Login utilisateur PIN correct (C_Login)"},
  {CPSDATA_TEST_CPS3+10, CKR_OK,"Recherche d'objet CPS_ACTIVITY (C_FindObjectsInit)"},
  {CPSDATA_TEST_CPS3+11, CKR_OK,"Recherche d'objet CPS_ACTIVITY (C_FindObjects)"},
  {CPSDATA_TEST_CPS3+12, CKR_OK,"Recherche d'objet CPS_ACTIVITY (C_FindObjectsFinal)"},
  {CPSDATA_TEST_CPS3+13, CKR_OK,"Recuperation taille d'objet CPS_ACTIVITY (C_GetAttributeValue)"},
  {CPSDATA_TEST_CPS3+14, CKR_OK,"Recuperation valeur d'objet CPS_ACTIVITY (C_GetAttributeValue)"},
  {CPSDATA_TEST_CPS3+15, CKR_OK,"Recherche d'objet CPS_NAME_PS (C_FindObjectsInit)"},
  {CPSDATA_TEST_CPS3+16, CKR_OK,"Recherche d'objet CPS_NAME_PS (C_FindObjects)"},
  {CPSDATA_TEST_CPS3+17, CKR_OK,"Recherche d'objet CPS_NAME_PS (C_FindObjectsFinal)"},
  {CPSDATA_TEST_CPS3+18, CKR_OK,"Recuperation taille d'objet CPS_NAME_PS (C_GetAttributeValue)"},
  {CPSDATA_TEST_CPS3+19, CKR_OK,"Recuperation valeur d'objet CPS_NAME_PS (C_GetAttributeValue)"},
  {CPSDATA_TEST_CPS3+20, CKR_OK,"Recherche d'objet CPS_CERTIFICAT (C_FindObjectsInit)"},
  {CPSDATA_TEST_CPS3+21, CKR_OK,"Recherche d'objet CPS_CERTIFICAT (C_FindObjects)"},
  {CPSDATA_TEST_CPS3+22, CKR_OK,"Recherche d'objet CPS_CERTIFICAT (C_FindObjectsFinal)"},
  {CPSDATA_TEST_CPS3+23, CKR_OK,"Recuperation taille d'objet CPS_CERTIFICAT (C_GetAttributeValue)"},
  {CPSDATA_TEST_CPS3+24, CKR_OK,"Recuperation valeur d'objet CPS_CERTIFICAT (C_GetAttributeValue)"},

  {CONTACTLESS_TEST_CPS3, CKR_OK,"Ouverture session en lecture (CL) (C_OpenSession)"},
  {CONTACTLESS_TEST_CPS3+1, CKR_USER_PIN_NOT_INITIALIZED,"Login utilisateur pour vérifier le mode CL (C_Login)"},
  {CONTACTLESS_TEST_CPS3+2, CKR_OK,"Recherche de clé privée (CL) (C_FindObjectsInit)"},
  {CONTACTLESS_TEST_CPS3+3, CKR_OK,"Recherche de clé privée (CL) (C_FindObjects)"},
  {CONTACTLESS_TEST_CPS3+4, CKR_OK,"Recherche de clé privée (CL) (C_FindObjectsFinal)"},
  {CONTACTLESS_TEST_CPS3+5, CKR_OK,"Recherche de clé privée (CL) (C_GetAttributeValue)"},
  {CONTACTLESS_TEST_CPS3+6, CKR_OK,"Recherche de clé privée (CL) (C_GetAttributeValue)"},
  {CONTACTLESS_TEST_CPS3+7, CKR_OK,"Recherche de clé publique (CL) (C_FindObjectsInit)"},
  {CONTACTLESS_TEST_CPS3+8, CKR_OK,"Recherche de clé publique (CL) (C_FindObjects)"},
  {CONTACTLESS_TEST_CPS3+9, CKR_OK,"Recherche de clé publique (CL) (C_FindObjectsFinal)"},
   {CONTACTLESS_TEST_CPS3+10, CKR_MECHANISM_INVALID,"Init signature et mauvais mécanisme (C_SignInit)"},
  {CONTACTLESS_TEST_CPS3+11, CKR_OK,"Init signature correcte (CKM_RSA_PKCS) (C_SignInit)"},
  {CONTACTLESS_TEST_CPS3+12, CKR_OPERATION_ACTIVE,"Init signature déjà faite (C_SignInit)"},
  {CONTACTLESS_TEST_CPS3+13, CKR_OK,"signature d'un coup (taille) (C_Sign)"},
  {CONTACTLESS_TEST_CPS3+14, CKR_OK,"signature d'un coup (valeur) (C_Sign)"},
  {CONTACTLESS_TEST_CPS3+15, CKR_OK,"Init signature correcte (CKM_RSA_PKCS) (C_SignInit)"},
  {CONTACTLESS_TEST_CPS3+16, CKR_OK,"MAJ signature 1er bloc de données (C_SignUpdate)"},
  {CONTACTLESS_TEST_CPS3+17, CKR_OK,"MAJ signature 2ème bloc de données (C_SignUpdate)"},
  {CONTACTLESS_TEST_CPS3+18, CKR_OK,"Signature finale (taille de signature) (C_SignFinal)"},
  {CONTACTLESS_TEST_CPS3+19, CKR_OK,"Signature finale (valeur de signature) (C_SignFinal)"},
  {CONTACTLESS_TEST_CPS3+20, CKR_OK,"Init signature correcte (C_SignInit)"},
  {CONTACTLESS_TEST_CPS3+21, CKR_OK,"MAJ signature avec bloc de données (C_SignUpdate)"},
  {CONTACTLESS_TEST_CPS3+22, CKR_OK,"Signature finale (taille de signature) (C_SignFinal)"},
  {CONTACTLESS_TEST_CPS3+23, CKR_OK,"Signature finale (valeur de signature) (C_SignFinal)"},
  {CONTACTLESS_TEST_CPS3+24, CKR_OK,"Init vérification signature (C_VerifyInit)"},
  {CONTACTLESS_TEST_CPS3+25, CKR_OK,"Vérification de signature effective (C_Verify)"},

  {SIGSHA256_FUNCTIONS, CKR_OK,"Ouverture session en lecture seule (C_OpenSession)"},
  {SIGSHA256_FUNCTIONS+1, CKR_OK,"Initialisation de signature et login utilisateur (C_Login)"},
  {SIGSHA256_FUNCTIONS+2, CKR_OK,"Initialisation de signature CKM_SHA256_RSA_PKCS et clé de signature (C_SignInit)"},
  {SIGSHA256_FUNCTIONS+3, CKR_OK,"MAJ de signature avec bloc de données (C_SignUpdate)"},
  {SIGSHA256_FUNCTIONS+4, CKR_OK,"Signature finale (taille de signature) (C_SignFinal)"},
  {SIGSHA256_FUNCTIONS+5, CKR_OK,"Signature finale (valeur de signature) (C_SignFinal)"},
  {SIGSHA256_FUNCTIONS+6, CKR_OK,"Initialisation de vérification de signature CKM_SHA256_RSA_PKCS et clé de signature (C_VerifyInit)"},
  {SIGSHA256_FUNCTIONS+7, CKR_OK,"MAJ de vérification de signature avec bloc de données (C_VerifyUpdate)"},
  {SIGSHA256_FUNCTIONS+8, CKR_OK,"Vérification de signature effective (C_VerifyFinal)"},

  {MISCELLANEOUS_TEST, CKR_OK, "Récupération du nombre de lecteurs (C_GetSlotList)"},
   {MISCELLANEOUS_TEST+1, CKR_OK,"Insertion d'une carte muette dans le lecteur (C_GestSlotInfo)"},

  { SIGNATU_RSA_PSS_FUNCTIONS, CKR_OK,"Ouverture session en lecture seule (C_OpenSession)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 1, CKR_OK,"Initialisation de signature et login utilisateur (C_Login)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 2, CKR_OK,"Initialisation de signature CKM_SHA1_RSA_PKCS_PSS et clé d'authentification (C_SignInit)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 3, CKR_OK,"Calcul de signature RSA PSS (taille) (C_Sign)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 4, CKR_OK,"Calcul de signature RSA PSS (valeur) (C_Sign)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 5, CKR_OK,"Verification de signature CKM_SHA1_RSA_PKCS_PSS et clé d'authentification (C_VerifyInit)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 6, CKR_OK,"Verification de signature RSA PSS (C_Verify)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 7, CKR_OK,"Initialisation de signature CKM_SHA256_RSA_PKCS_PSS et clé d'authentification (C_SignInit)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 8, CKR_OK,"Calcul de signature RSA PSS 256 (taille) (C_Sign)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 9, CKR_OK,"Calcul de signature RSA PSS 256 (valeur) (C_Sign)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 10, CKR_OK,"Verification de signature CKM_SHA256_RSA_PKCS_PSS et clé d'authentification (C_VerifyInit)" },
  { SIGNATU_RSA_PSS_FUNCTIONS + 11, CKR_OK,"Verification de signature RSA PSS (C_Verify)" },
	{ 0xFFFF, 0, ""}
};

#define SAVE_RESULT(MsgsTbl, testNumber, rv)  (ConsigneResultatCSV(MsgsTbl[testNumber].TestLevel,rv,MsgsTbl[testNumber].usExpectedRc,MsgsTbl[testNumber].Msg))

typedef struct
{
	unsigned long mask;
	char name[60];
} sFLAGS;

sFLAGS mecaInfoFlagsTab[]={
	{CKF_HW,"CKF_HW"},
	{CKF_ENCRYPT,"CKF_ENCRYPT"},
	{CKF_DECRYPT,"CKF_DECRYPT"},
	{CKF_DIGEST,"CKF_DIGEST"},
	{CKF_SIGN,"CKF_SIGN"},
	{CKF_SIGN_RECOVER,"CKF_SIGN_RECOVER"},
	{CKF_VERIFY,"CKF_VERIFY"},
	{CKF_VERIFY_RECOVER,"CKF_VERIFY_RECOVER"},
	{CKF_GENERATE,"CKF_GENERATE"},
	{CKF_GENERATE_KEY_PAIR,"CKF_GENERATE_KEY_PAIR"},
	{CKF_WRAP,"CKF_WRAP"},
	{CKF_UNWRAP,"CKF_UNWRAP"},
	{CKF_DERIVE,"CKF_DERIVE"},
	{CKF_EXTENSION,"CKF_EXTENSION"},
};

sFLAGS tokenInfoFlagsTab[]={
	{CKF_RNG,"CKF_RNG"},
	{CKF_WRITE_PROTECTED,"CKF_WRITE_PROTECTED"},
	{CKF_LOGIN_REQUIRED,"CKF_LOGIN_REQUIRED"},
	{CKF_USER_PIN_INITIALIZED,"CKF_USER_PIN_INITIALIZED"},
	{CKF_RESTORE_KEY_NOT_NEEDED,"CKF_RESTORE_KEY_NOT_NEEDED"},
	{CKF_CLOCK_ON_TOKEN,"CKF_CLOCK_ON_TOKEN"},
	{CKF_PROTECTED_AUTHENTICATION_PATH,"CKF_PROTECTED_AUTHENTIFICATION_PATH"},
	{CKF_DUAL_CRYPTO_OPERATIONS,"CKF_DUAL_CRYPTO_OPERATIONS"},
	{CKF_TOKEN_INITIALIZED,"CKF_TOKEN_INITIALIZED"},
	{CKF_SECONDARY_AUTHENTICATION,"CKF_SECONDARY_AUTHENTICATION"},
	{CKF_USER_PIN_COUNT_LOW,"CKF_USER_PIN_COUNT_LOW"},
	{CKF_USER_PIN_FINAL_TRY,"CKF_USER_PIN_FINAL_TRY"},
	{CKF_USER_PIN_LOCKED,"CKF_USER_PIN_LOCKED"},
	{CKF_USER_PIN_TO_BE_CHANGED,"CKF_USER_PIN_TO_BE_CHANGED"},
	{CKF_SO_PIN_COUNT_LOW,"CKF_SO_PIN_COUNT_LOW"},
	{CKF_SO_PIN_FINAL_TRY,"CKF_SO_PIN_FINAL_TRY"},
	{CKF_SO_PIN_LOCKED,"CKF_SO_PIN_LOCKED"},
	{CKF_SO_PIN_TO_BE_CHANGED,"CKF_SO_PIN_TO_BE_CHANGED"},
};

#define WINLOGON_DECRYPT "winlogonDecrypt"

/* Attributs ancienne CryptoLib CPS */
#define CKA_CPS_KEY_TYPE								CKA_VENDOR_DEFINED+1
#define CKA_CPS_CODE									CKA_VENDOR_DEFINED+213
#define CKA_CPS_NEW_CODE							CKA_VENDOR_DEFINED+214
#define CKA_CPS_SUPER_CODE						CKA_VENDOR_DEFINED+215
#define CKO_CPS_CODE									CKO_VENDOR_DEFINED+9

int traceLevel=TRACE_DEBUG;
CK_BBOOL doWaitForSlotEvent=CK_FALSE;
CK_BBOOL doMultiThreads=CK_FALSE;
CK_BBOOL doInitPIN=CK_FALSE;
CK_BBOOL doUsePIN=CK_FALSE;
CK_BBOOL doUsePUK=CK_FALSE;
CK_BBOOL doCacheTests=CK_FALSE;
CK_BBOOL do1144Tests=CK_FALSE;
CK_BBOOL doCpsDataOnly=CK_FALSE;
CK_BBOOL isCPS3=CK_FALSE;
CK_BBOOL isContactLess = CK_FALSE;
CK_BBOOL isCPS3_Card=CK_FALSE;
CK_BBOOL isCPS2TerPCSC=CK_FALSE;
CK_BBOOL isCPS2TerGALSS=CK_FALSE;


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
extern char bufFileName[];
extern SYS_HANDLE               LoadDynLibrary( CK_CHAR_PTR pLibraryName);
extern CK_PFUNCTION CK_API      GetFunctionPtr( SYS_HANDLE dllInst,CK_CHAR_PTR pFunctionName);
extern int testGetPkcs11Object(CK_FUNCTION_LIST *pFunctionList, CK_SESSION_HANDLE sessionRO, int testLevel, int keySpec,  CK_CHAR_PTR pin, CK_OBJECT_HANDLE_PTR phObject, int * pTestNumber);
int testInitialGetTokenName(CK_FUNCTION_LIST *pFunctionList, char * bufFileName);
int testGeneralPurposeFunctions(CK_FUNCTION_LIST *pFunctionList);
char *getErrorCodeString(CK_RV error, char * strError);
char *getMechanismTypeString(CK_ULONG mekaType, char * strMeka);
int  ConsigneResultatCSV(unsigned short __usTestNumero, unsigned long usRc, unsigned long usExpectedRc, char * libelle);
void sys_getTime(char * buffer);
void testSlotAndTokenManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_BBOOL cacheTest);
CK_RV testGetMechanismInfo(CK_FUNCTION_LIST *pFunctionList, CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR mechanismList, int nbMechanism);
void test(CK_FUNCTION_LIST *pFunctionList);
void testSessionManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BBOOL * pIsContactLess);
void testObjectManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BBOOL isContactLess);
void testEncryptManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_BYTE_PTR * ppEncryptedData, CK_ULONG_PTR pulEncryptedDataLen, CK_CHAR_PTR pin);
void testDecryptManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen);
void testSignatureManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BYTE_PTR bufSignature, CK_ULONG_PTR pulBufSignatureLen, CK_BYTE_PTR bufSignature_256, CK_ULONG_PTR pulBufSignature_256Len);
void testVerificationSignatureManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_BYTE_PTR bufSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR bufSignature_256, CK_ULONG ulBufSignature_256Len);
void testSignatureSHA256ManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BYTE_PTR bufSignature_256, CK_ULONG_PTR pulBufSignature_256Len);
void testDigestManagementFunctions(CK_FUNCTION_LIST *pFunctionList);
void testCpsDataObject(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin);
void testContactlessSignatureManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin);
void testMiscellaneousFunctions(CK_FUNCTION_LIST *pFunctionList);
void testSignatureRsaPssManagementFunctions(CK_FUNCTION_LIST* pFunctionList, CK_CHAR_PTR pin, CK_BYTE_PTR bufSignature, CK_ULONG_PTR pulBufSignatureLen, CK_BYTE_PTR bufSignature_256, CK_ULONG_PTR pulBufSignature_256Len);
unsigned short getIndexDebutSectionTests(int searchedTestLevel);
void checkPrintResult(char * mesgTest, CK_RV rv, int testNumber, sTESTS_MSGS * table);
void htmlWriteHeader( void );
void htmlWriteTableRow( unsigned short __usTestNumero,  char * libelle,  unsigned long usExpectedRc, unsigned long usRc, char * strTime );
void htmlWriteFooter( void );
void deleteCache( void );
int modifyCache( char * serialNumber , char * suffix);
int testScenario_1144( CK_FUNCTION_LIST *pFunctionList );

int main(int argc, char* argv[])
{
  char dllName[256];
  CK_CHAR pukCode[16]={0};
  CK_CHAR pinCode[9]={0};
  CK_ULONG i;
  CK_FUNCTION_LIST *pFunctionList = NULL_PTR;
  CK_BYTE signatureAuth[256];
  CK_ULONG ulSignatureAuth;
  CK_BYTE signatureSign[256];
  CK_ULONG ulSignatureSign;


	for (i=0;i<(CK_ULONG)argc;i++) {
		if (strcmp(argv[i], "/w")==0) {
			doWaitForSlotEvent=CK_TRUE;
		}
		if (strcmp(argv[i], "/i")==0) {
			doInitPIN=CK_TRUE;
			if(argv[i+1] != NULL) {
				strcpy((char *)pukCode, argv[i+1]);
			}
			doUsePUK=CK_TRUE;
		}
		if (strcmp(argv[i], "/c")==0) {
			if(argv[i+1] != NULL) {
				strcpy((char *)pinCode, argv[i+1]);
			}
			doUsePIN=CK_TRUE;
		}
		if (strcmp(argv[i], "/m")==0) {
			doMultiThreads=CK_TRUE;
		}
		if (strcmp(argv[i], "/h")==0) {
			doCacheTests=CK_TRUE;
			/*if(argv[i+1] != NULL) {
				nbIterationsRobustesse=atoi(argv[i+1]);
			} else {
				nbIterationsRobustesse=1;
				printf ("\n!!! Pour effectuer un test de robustesse, vous devez specifier le nombre d'iterations (ex: '/r 100' pour 100 iterations) !!!\n\n");
			}*/
		}
		if (strcmp(argv[i], "/1144")==0) {
			do1144Tests=CK_TRUE;
		}
        if (strcmp(argv[i], "/cpsdataonly")==0) {
			doCpsDataOnly=CK_TRUE;
		}
		if (_stricmp(argv[i], "/cps3")==0)
			isCPS3=CK_TRUE;
		if (_stricmp(argv[i], "/cps2g")==0)
			isCPS2TerGALSS=CK_TRUE;
		if (_stricmp(argv[i], "/cps2p")==0)
			isCPS2TerPCSC=CK_TRUE;
	}

	if(doInitPIN) {
		if(!doUsePIN || !doUsePUK) printf ("\n!!! Pour effectuer un test de deblocage, vous pouvez specifier les codes PIN et PUK (ex: '/i 12345678 /c 1234') !!!\n\nPar defaut PUK -> '12345678' et PIN -> '1234' sont utilises");
	}
	if(pinCode[0] == 0)
		strcpy((char *)pinCode, "1234");
	if(pukCode[0] == 0)
		strcpy((char *)pukCode, "12345678");
	printf("\n\tCode PIN utilise -> '%8s'", pinCode);
	if(doInitPIN) {
		printf("\n\tCode PUK utilise -> '%8s'", pukCode);
	}

	/* On utilise la lib CPS3 par défaut */
	if(!isCPS3 && !isCPS2TerGALSS && !isCPS2TerPCSC) {
		printf ("\n!!! Aucun type de carte specifie, ou type de carte incorrect, vous devez specifier un type de carte parmi : /cps3 (par defaut), /cps2g (CPS2TerGALSS) ou /cps2p (CPS2TerPCSC) !!!\n\n");
		isCPS3=CK_TRUE;
	}

	printf ("\nType de carte considere pour ce test:");
	if(isCPS3) {
		printf (" CPS3 \n\n");
		memcpy (dllName,dllNameCPS3,strlen(dllNameCPS3)+1);
	} else if(isCPS2TerGALSS) {
		printf (" CPS2Ter GALSS \n\n");
		memcpy (dllName,dllNameCPS2TerGALSS,strlen(dllNameCPS2TerGALSS)+1);
	} else if(isCPS2TerPCSC) {
		printf (" CPS2Ter PCSC \n\n");
		memcpy (dllName,dllNameCPS2TerPCSC,strlen(dllNameCPS2TerPCSC)+1);
	}

	//InitTraceFile();

	if (doMultiThreads && (doWaitForSlotEvent || doInitPIN)) {
		doMultiThreads=CK_FALSE;
		//traceInFile(TRACE_INFO, (CK_CHAR_PTR)"option multithreads (/m) incompatible avec les options /i ou /w, elle est donc ignorée");
	}

	SYS_HANDLE dllInst = LoadDynLibrary((CK_CHAR_PTR)dllName);
	if (dllInst==NULL)
	{
		printf ("\n!!! La librairie %s n'a pas pu etre chargee !!!\n",dllName);
		return 1;
	}
	printf ("\nLa librairie %s a ete chargee\n",dllName);

	CK_C_GetFunctionList pC_GetFunctionList = (CK_C_GetFunctionList)GetFunctionPtr( dllInst, (CK_CHAR_PTR)"C_GetFunctionList");
	if ( pC_GetFunctionList == NULL) {
		printf ("\n!!! L'entree C_GetFunctionList est introuvable !!!\n");	
		return 2;
	}
	printf ("\nC_GetFunctionList trouve\n");

	CK_RV rv = (*pC_GetFunctionList)(&pFunctionList);
	if (rv!=CKR_OK){
		printf ("\n!!! Erreur sur l'appel de C_GetFunctionList rv=0x%08x!!!\n",(unsigned int)rv);
//		ConsigneResultatCSV(0,rv,MsgsTbl[0].usExpectedRc,MsgsTbl[0].Msg);
		return (int)rv;
	}
//	ConsigneResultatCSV(0,rv,MsgsTbl[0].usExpectedRc,MsgsTbl[0].Msg);
	printf ("\nC_GetFunctionList OK\n");
	testInitialGetTokenName(pFunctionList, bufFileName);
	printf("***************************************************\n");
	printf("D" E_AIGUE "but des tests d'initialisation.\n");
	printf("***************************************************\n");
	int ret = testGeneralPurposeFunctions(pFunctionList);
	printf("***************************************************\n");
	printf("Fin des tests d'initialisation.\n");
	printf("***************************************************\n");
	if(ret == -1)
	{
	return 1;
	}
	
  if (!doCpsDataOnly) {
    printf("**************************************************************\n");
    printf("D" E_AIGUE "but des tests de gestion des lecteurs et des cartes.\n");
    printf("**************************************************************\n");
    testSlotAndTokenManagementFunctions(pFunctionList, doCacheTests);
    printf("**************************************************************\n");
    printf("Fin des tests de gestion des lecteurs et des cartes.\n");
    printf("**************************************************************\n");



    printf("**************************************************************\n");
    printf("D" E_AIGUE "but des tests de gestion de session.\n");
    printf("**************************************************************\n");
    testSessionManagementFunctions(pFunctionList, pinCode, &isContactLess);
    printf("**************************************************************\n");
    printf("Fin des tests de gestion de session.\n");
    printf("**************************************************************\n");



    printf("**************************************************************\n");
    printf("D" E_AIGUE "but des tests de gestion d'objets.\n");
    printf("**************************************************************\n");
    testObjectManagementFunctions(pFunctionList, pinCode, isContactLess);
    printf("**************************************************************\n");
    printf("Fin des tests de gestion d'objets.\n");
    printf("**************************************************************\n");

    if (isContactLess == CK_FALSE) {
      printf("**************************************************************\n");
      printf("D" E_AIGUE "but des tests de chiffrement.\n");
      printf("**************************************************************\n");
      CK_BYTE_PTR pCipherData;
      CK_ULONG ulCipherDataLen;
      testEncryptManagementFunctions(pFunctionList, &pCipherData, &ulCipherDataLen, pinCode);
      printf("**************************************************************\n");
      printf("Fin des tests de de chiffrement..\n");
      printf("**************************************************************\n");

      printf("**************************************************************\n");
      printf("D" E_AIGUE "but des tests de d" E_AIGUE "chiffrement.\n");
      printf("**************************************************************\n");
      testDecryptManagementFunctions(pFunctionList, pinCode, pCipherData, ulCipherDataLen);
      printf("**************************************************************\n");
      printf("Fin des tests de d" E_AIGUE "chiffrement..\n");
      printf("**************************************************************\n");
    }
  }
	
    if (!doCpsDataOnly) {
	printf("**************************************************************\n");
	printf("D" E_AIGUE "but des tests de signature.\n");
	printf("**************************************************************\n");
  testSignatureManagementFunctions(pFunctionList, pinCode, signatureAuth, &ulSignatureAuth, signatureSign, &ulSignatureSign);
	printf("**************************************************************\n");
	printf("Fin des tests de de signature.\n");
	printf("**************************************************************\n");

  printf("**************************************************************\n");
	printf("D" E_AIGUE "but des tests v" E_AIGUE "rification de signature.\n");
	printf("**************************************************************\n");
  testVerificationSignatureManagementFunctions(pFunctionList, signatureAuth, ulSignatureAuth, signatureSign, ulSignatureSign);
	printf("**************************************************************\n");
	printf("Fin des tests de de v" E_AIGUE "rification de signature.\n");
	printf("**************************************************************\n");
    }

    if (!doCpsDataOnly) {
  printf("**************************************************************\n");
	printf("D" E_AIGUE "but des tests cr" E_AIGUE "ation de digest.\n");
	printf("**************************************************************\n");
    testDigestManagementFunctions(pFunctionList);
	printf("**************************************************************\n");
	printf("Fin des tests de de cr" E_AIGUE "ation de digest.\n");
	printf("**************************************************************\n");
    }

  printf("**************************************************************\n");
	printf("D" E_AIGUE "but des tests gestion CPS_DATA.\n");
	printf("**************************************************************\n");
  testCpsDataObject(pFunctionList, pinCode);
  printf("**************************************************************\n");
	printf("Fin des tests gestion CPS_DATA.\n");
	printf("**************************************************************\n");

    if (!doCpsDataOnly) {
  printf("**************************************************************\n");
	printf("D" E_AIGUE "but des tests de signature SHA_256.\n");
	printf("**************************************************************\n");
  testSignatureSHA256ManagementFunctions(pFunctionList, pinCode, signatureSign, &ulSignatureSign);
  printf("**************************************************************\n");
	printf("Fin des tests de signature SHA_256.\n");
	printf("**************************************************************\n");

	if (isCPS3_Card & TYPE_CPS4) {
		printf("**************************************************************\n");
		printf("D" E_AIGUE "but des tests RSA PSS.\n");
		printf("**************************************************************\n");
		ulSignatureAuth = 256;
		ulSignatureSign = 256;
		testSignatureRsaPssManagementFunctions(pFunctionList, pinCode, signatureAuth, &ulSignatureAuth, signatureSign, &ulSignatureSign);
		printf("**************************************************************\n");
		printf("Fin des tests RSA PSS.\n");
		printf("**************************************************************\n");
	}

	printf("**************************************************************\n");
	printf("D" E_AIGUE "but des tests divers.\n");
	printf("**************************************************************\n");
  testMiscellaneousFunctions(pFunctionList);
  printf("**************************************************************\n");
	printf("Fin des tests divers.\n");
	printf("**************************************************************\n");


    }

#if defined __APPLE__ || defined UNIX_LUX
	if (do1144Tests) {
	printf("**************************************************************\n");
	printf("D" E_AIGUE "but des tests anomalie 1144.\n");
	printf("**************************************************************\n");
	testScenario_1144( pFunctionList );
	printf("**************************************************************\n");
	printf("Fin des tests anomalie 1144.\n");
	printf("**************************************************************\n");
	}
#endif
	
    if (!doCpsDataOnly && isContactLess == CK_TRUE) {
	printf("**************************************************************\n");
	printf("D" E_AIGUE "but des tests authentification sans contact.\n");
	printf("**************************************************************\n");
	testContactlessSignatureManagementFunctions(pFunctionList, pinCode);
	printf("**************************************************************\n");
	printf("Fin des tests authentification sans contact.\n");
	printf("**************************************************************\n");
    }

  printf ("\n#############\n");
	printf (  "##   Fin   ##");
	printf ("\n#############\n");
	printf("Appuyer sur Entr" E_AIGUE "e pour quitter");
  htmlWriteFooter( );
	getchar();
  
  return 0;
}

CK_RV createmutex (void **mutex) {
  return CKR_OK;
}
CK_RV destroymutex (void *mutex) {
  return CKR_OK;
}
CK_RV lockmutex (void *mutex) {
  return CKR_OK;
}
CK_RV unlockmutex (void *mutex) {
  return CKR_OK;
}

int testInitialGetTokenName(CK_FUNCTION_LIST *pFunctionList, char * bufFileName) {
	CK_RV rv;
	CK_SLOT_ID tabSlotIDs[10];
	CK_ULONG slotSize = 10;
	// l'initialisation
	strcpy(bufFileName, "Resultats");
	rv = (*pFunctionList->C_Initialize)(NULL);
	if (rv == CKR_OK) {
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, tabSlotIDs, &slotSize);
		if (rv == CKR_OK && slotSize > 0) {
			CK_SLOT_ID slotID;
			CK_SLOT_INFO slotInfo;
			CK_TOKEN_INFO tokenInfo;
			unsigned char *p;

			slotID = tabSlotIDs[0];
			rv = (*pFunctionList->C_GetSlotInfo)(slotID, &slotInfo);

			if (rv == CKR_OK) {
				p = slotInfo.slotDescription + 63;
				while (*p == 0x20) p--;
				if (*p != 0x20) {
					p++;
					*p = 0;
				}
				strcat(bufFileName, "_");
				strcat(bufFileName, (const char *)slotInfo.slotDescription);
			}

			rv = (*pFunctionList->C_GetTokenInfo)(slotID, &tokenInfo);

			if (rv == CKR_OK) {
				p = tokenInfo.label + 31;
				while (*p == 0x20) p--;
				if (*p != 0x20) {
					p++;
					*p = 0;
				}
				strcat(bufFileName, "_");
				strcat(bufFileName, (const char *)tokenInfo.label);
			}
		}
		strcat(bufFileName, ".HTML");
		rv = (*pFunctionList->C_Finalize)(NULL);
	}
	return 0;
}

//*******************************************************************
//Effectue les tests d'initialisation et de récupération d'informations sur la librairie
//Paramètres :
//	- pFunctionList : Un tableau contenant tous les pointeurs sur fonction de pkcs11
//Valeur retourné :
//	-1 s'il y a eu une erreur lors de l'initialisation, 1 si les tests ont réussi
//*******************************************************************
int testGeneralPurposeFunctions(CK_FUNCTION_LIST *pFunctionList)
{
	int retour = -1;
	CK_INFO info;
	CK_RV rv;
	unsigned short testNumber = 1;

	//finalize avant l'initialisation
	rv = (*pFunctionList->C_Finalize)(NULL);
  checkPrintResult("C_Finalize avant C_Initialize",rv,testNumber,MsgsTbl);

	//getinfo avant l'initialisation
	testNumber++;
	rv = (*pFunctionList->C_GetInfo)(&info);
	checkPrintResult("C_GetInfo avant C_Initialize",rv,testNumber,MsgsTbl);

  //if (!isCPS3) {
  CK_C_INITIALIZE_ARGS pInitArgs;
  //initialisation (Cas 3)
	testNumber++;
  pInitArgs.CreateMutex = createmutex;
  pInitArgs.DestroyMutex = destroymutex;
  pInitArgs.LockMutex = lockmutex;
  pInitArgs.UnlockMutex = unlockmutex;
  pInitArgs.flags = 0;
  pInitArgs.pReserved = NULL_PTR;
  rv = (*pFunctionList->C_Initialize)(&pInitArgs);
  if (!isCPS3)
    MsgsTbl[testNumber].usExpectedRc = CKR_CANT_LOCK;
	checkPrintResult("C_Initialize",rv,testNumber,MsgsTbl);

  if (isCPS3)
    rv = (*pFunctionList->C_Finalize)(NULL_PTR);

  //initialisation (Cas 4)
	testNumber++;
  pInitArgs.CreateMutex = createmutex;
  pInitArgs.DestroyMutex = destroymutex;
  pInitArgs.LockMutex = lockmutex;
  pInitArgs.UnlockMutex = unlockmutex;
  pInitArgs.flags = CKF_OS_LOCKING_OK;
  pInitArgs.pReserved = NULL_PTR;
  if (!isCPS3)
    MsgsTbl[testNumber].usExpectedRc = CKR_CANT_LOCK;
  rv = (*pFunctionList->C_Initialize)(&pInitArgs);
	checkPrintResult("C_Initialize",rv,testNumber,MsgsTbl);

  rv = (*pFunctionList->C_Finalize)(NULL_PTR);

  //initialisation (Cas 1)
	testNumber++;
  pInitArgs.CreateMutex = NULL_PTR;
  pInitArgs.DestroyMutex = NULL_PTR;
  pInitArgs.LockMutex = NULL_PTR;
  pInitArgs.UnlockMutex = NULL_PTR;
  pInitArgs.flags = 0;
  rv = (*pFunctionList->C_Initialize)(&pInitArgs);
	checkPrintResult("C_Initialize",rv,testNumber,MsgsTbl);

  rv = (*pFunctionList->C_Finalize)(NULL_PTR);

  //initialisation (Cas 2)
	testNumber++;
  pInitArgs.CreateMutex = NULL_PTR;
  pInitArgs.DestroyMutex = NULL_PTR;
  pInitArgs.LockMutex = NULL_PTR;
  pInitArgs.UnlockMutex = NULL_PTR;
  pInitArgs.flags = CKF_OS_LOCKING_OK;
  rv = (*pFunctionList->C_Initialize)(&pInitArgs);
	checkPrintResult("C_Initialize",rv,testNumber,MsgsTbl);

  rv = (*pFunctionList->C_Finalize)(NULL_PTR);

   //initialisation
	testNumber++;
  pInitArgs.CreateMutex = createmutex;
  pInitArgs.DestroyMutex = NULL_PTR;
  pInitArgs.LockMutex = NULL_PTR;
  pInitArgs.UnlockMutex = unlockmutex;
  pInitArgs.flags = CKF_OS_LOCKING_OK;
  if (!isCPS3)
    MsgsTbl[testNumber].usExpectedRc = CKR_CANT_LOCK;
  else {
	MsgsTbl[testNumber].usExpectedRc = CKR_ARGUMENTS_BAD;
  }
  rv = (*pFunctionList->C_Initialize)(&pInitArgs);
  checkPrintResult("C_Initialize",rv,testNumber,MsgsTbl);

  //}

	//initialisation avec poiteur d'init à NULL
	testNumber++;
  if (isCPS2TerGALSS || isCPS2TerPCSC)
  {
    MsgsTbl[testNumber].usExpectedRc = CKR_OK;
  }
	rv = (*pFunctionList->C_Initialize)(NULL_PTR);
  checkPrintResult("C_Initialize",rv,testNumber,MsgsTbl);

	//si le test d'initialisation a échoué, on arrête les tests
	if(rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		printf("ERREUR : L'initialisation a " E_AIGUE "chou" E_AIGUE ". Les tests suivants ne seront pas lanc" E_AIGUE "s.\n");
		retour = -1;
	}
	//sinon on continue
	else
	{
		testNumber++;
		rv = (*pFunctionList->C_Initialize)(NULL_PTR);
    checkPrintResult("C_Initialize d" E_AIGUE "j" A_ACCENT " initialis"  E_AIGUE ,rv,testNumber,MsgsTbl);

		//getinfo avec un paramètre null
		testNumber++;
		rv = (*pFunctionList->C_GetInfo)(NULL_PTR);
    checkPrintResult("C_GetInfo avec un parametre null",rv,testNumber,MsgsTbl);

		//getInfo
		testNumber++;
		rv = (*pFunctionList->C_GetInfo)(&info);
    checkPrintResult("C_GetInfo",rv,testNumber,MsgsTbl);
		printf("Informations retourn" E_AIGUE "es : \n");
		printf("Version de la librairie : %u.%u\n",info.libraryVersion.major,info.libraryVersion.minor);
    int index;
    for (index = 31; info.manufacturerID[index] == 0x20; index--);
    info.manufacturerID[index+1] = 0;
		printf("Identifiant de la biblioth" E_GRAVE "que du fabricant : %s\n",info.manufacturerID);
    for (index = 31; info.libraryDescription[index] == 0x20; index--);
    info.libraryDescription[index+1] = 0;
		printf("Description de la librairie : %s\n",info.libraryDescription);
		printf("Version de l'implementation de la librairie : %u.%u\n",info.cryptokiVersion.major,info.cryptokiVersion.minor);
		printf("--Fin des informations retourn" E_AIGUE "es--\n");

		//Finalize
		testNumber++;
		rv = (*pFunctionList->C_Finalize)(NULL_PTR);	
    checkPrintResult("C_Finalize",rv,testNumber,MsgsTbl);

		retour = 1;
	}

	return retour;
}

//*******************************************************************
//Effectue les tests de gestion des lecteurs et des cartes
//*******************************************************************
void testSlotAndTokenManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_BBOOL cacheTest)
{
	//******************
	//TODO : Ecrire les résultats des tests dans le fichier csv
	//******************
	CK_RV rv;
	unsigned short testNumber =  getIndexDebutSectionTests( GENPURP_FUNCTIONS );
	unsigned long nbSlots;
	
	//faire les tests sans avoir initialisé la librairie avant
	rv = (*pFunctionList->C_GetSlotList)(0,NULL,&nbSlots);
  checkPrintResult("C_GetSlotList sans C_Initialize",rv,testNumber,MsgsTbl);
	

	testNumber++; // 101
	rv = (*pFunctionList->C_GetSlotInfo)(0,NULL);
  checkPrintResult("C_GetSlotInfo sans C_Initialize",rv,testNumber,MsgsTbl);
	

	testNumber++;// 102
	rv = (*pFunctionList->C_GetTokenInfo)(0,NULL);
  checkPrintResult("C_GetTokenInfo sans C_Initialize",rv,testNumber,MsgsTbl);
	

	testNumber++;// 103
  MsgsTbl[testNumber].usExpectedRc = CKR_CRYPTOKI_NOT_INITIALIZED;
	rv = (*pFunctionList->C_WaitForSlotEvent)(CKF_DONT_BLOCK,NULL,NULL);
  checkPrintResult("C_WaitForSlotEvent sans C_Initialize",rv,testNumber,MsgsTbl);
	

	testNumber++;// 104
	rv = (*pFunctionList->C_GetMechanismList)(0,NULL,NULL);
  checkPrintResult("C_GetMechanismList sans C_Initialize",rv,testNumber,MsgsTbl);
	

	testNumber++;// 105
	rv = (*pFunctionList->C_GetMechanismInfo)(0,NULL,NULL);
  checkPrintResult("C_GetMechanismInfo sans C_Initialize",rv,testNumber,MsgsTbl);
	

	testNumber++;// 106
  if (!isCPS3) {
      // si on n'est pas en CPS3, la fonction C_InitPIN est non supportée
    MsgsTbl[testNumber].usExpectedRc = CKR_FUNCTION_NOT_SUPPORTED;
  }
	rv = (*pFunctionList->C_InitToken)(0,NULL,0,NULL);
  checkPrintResult("C_InitToken sans C_Initialize",rv,testNumber,MsgsTbl);
	

	testNumber++;// 107
  if (!isCPS3) {
      // si on n'est pas en CPS3, la fonction C_InitPIN est non supportée
    MsgsTbl[testNumber].usExpectedRc = CKR_FUNCTION_NOT_SUPPORTED;
  }
	rv = (*pFunctionList->C_InitPIN)(NULL,NULL,0);
  checkPrintResult("C_InitPIN sans C_Initialize",rv,testNumber,MsgsTbl);
	

	testNumber++;// 108
	rv = (*pFunctionList->C_SetPIN)(0,NULL,0,NULL,0);
  checkPrintResult("C_SetPIN sans C_Initialize",rv,testNumber,MsgsTbl);
	
	
	//initialiser la librairie et faire les tests
	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK)
	{
		//getslotlist avec le paramètre pulCount à null
		testNumber++;// 109
		rv = (*pFunctionList->C_GetSlotList)(CK_FALSE,NULL,NULL);
    checkPrintResult("C_GetSlotList avec le param"  E_GRAVE  "tre pulCount " A_ACCENT " NULL",rv,testNumber,MsgsTbl);
		

		//getslotlist recupration du nombre de slots
		testNumber++;// 110
		rv = (*pFunctionList->C_GetSlotList)(CK_FALSE,NULL,&nbSlots);
    checkPrintResult("C_GetSlotList",rv,testNumber,MsgsTbl);
		
		printf("Nombre de lecteur(s) : %lu\n",nbSlots);

		if(rv == CKR_OK)
		{
			//récupération des identifiants des lecteurs
			testNumber++;// 111
			CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(nbSlots * sizeof(CK_SLOT_ID));
			rv = (*pFunctionList->C_GetSlotList)(CK_FALSE,pSlotList,&nbSlots);
      checkPrintResult("C_GetSlotList avec r" E_AIGUE "cuperation des identifiants des lecteurs",rv,testNumber,MsgsTbl);
			

			for(int i = 0 ; i < (int)nbSlots ; i++)
			{
				printf("Identifiant du lecteur %d : %lu\n",i+1,pSlotList[i]);
			}
			free(pSlotList);

			//récuperation des identifiants des lecteurs avec une taille de buffer insuffisante
			unsigned long badNbSlots = (nbSlots == 0) ? 0 : nbSlots - 1;
      pSlotList = (CK_SLOT_ID_PTR)malloc(badNbSlots);
			testNumber++;// 112
			rv = (*pFunctionList->C_GetSlotList)(CK_FALSE,pSlotList,&badNbSlots);
      checkPrintResult("C_GetSlotList avec r" E_AIGUE "cuperation des identifiants des lecteurs",rv,testNumber,MsgsTbl);
      if (pSlotList != NULL) free(pSlotList);
		}

		//récupération du nombre de lecteurs ayant une carte insérée
		//CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(0);
		testNumber++;// 113
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE,NULL,&nbSlots);
    checkPrintResult("C_GetSlotList avec carte",rv,testNumber,MsgsTbl);
		
		printf("Nombre de lecteur(s) avec une carte : %lu\n",nbSlots);

    // Recuperation liste des identifiants de lecteurs ayant une carte
    testNumber++;// 114
    CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(nbSlots * sizeof(CK_SLOT_ID));
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, pSlotList, &nbSlots);
    checkPrintResult("C_GetSlotList avec r" E_AIGUE "cuperation des identifiants des lecteurs avec carte",rv,testNumber,MsgsTbl);

		//récupération d'informations d'un lecteur avec le paramètre pInfo à null
		testNumber++;// 115
		rv = (*pFunctionList->C_GetSlotInfo)(pSlotList[0],NULL);
    checkPrintResult("C_GetSlotInfo avec pInfo = NULL",rv,testNumber,MsgsTbl);
		

		//récupération d'informations d'un lecteur avec un mauvais identifiant de lecteur
		CK_SLOT_INFO slotInfo;
		testNumber++;// 116
		rv = (*pFunctionList->C_GetSlotInfo)(99,&slotInfo);
    checkPrintResult("C_GetSlotInfo avec slotID = 99",rv,testNumber,MsgsTbl);

		//récupération d'informations d'un lecteur
		testNumber++;// 117
		rv = (*pFunctionList->C_GetSlotInfo)(pSlotList[0], &slotInfo);
    checkPrintResult("C_GetSlotInfo",rv,testNumber,MsgsTbl);
		
		printf("Version du firmware : %u.%u\n",slotInfo.firmwareVersion.major,slotInfo.firmwareVersion.minor);
		printf("Version du mat" E_AIGUE "riel : %u.%u\n",slotInfo.hardwareVersion.major,slotInfo.hardwareVersion.minor);
		printf("Identifiant du lecteur : %s\n",slotInfo.manufacturerID);
		printf("Description du lecteur : %s\n",slotInfo.slotDescription);

		//test flag CKF_TOKEN_PRESENT
		if(slotInfo.flags & CKF_TOKEN_PRESENT)
		{
			printf("Une carte est dans le lecteur ? : OUI\n");
		}
		else
		{
			printf("Une carte est dans le lecteur ? : NON\n");
		}

		//test flag CKF_REMOVABLE_DEVICE
		if(slotInfo.flags & CKF_REMOVABLE_DEVICE)
		{
			printf("Le lecteur g" E_GRAVE "re-t-il les supports amovibles ? : OUI\n");
		}
		else
		{
			printf("Le lecteur g" E_GRAVE "re-t-il les supports amovibles ? : NON\n");
		}

		//test flag CKF_HW_SLOT
		if(slotInfo.flags & CKF_HW_SLOT)
		{
			printf("Le slot est-il mat" E_AIGUE "riel ? : OUI\n");
		}
		else
		{
			printf("Le slot est-il mat" E_AIGUE "riel ? : NON\n");
		}

		//Récupération des infos de la carte
		CK_TOKEN_INFO tokenInfo;

		//Récupération des infos de la carte avec le paramètre pInfo à null
		testNumber++;// 118
		rv = (*pFunctionList->C_GetTokenInfo)(pSlotList[0], NULL);
    checkPrintResult("C_GetTokenInfo avec pInfo " A_ACCENT " NULL",rv,testNumber,MsgsTbl);
		

		//Récupération des infos de la carte avec un mauvais identifiant de lecteur
		testNumber++;// 119
		rv = (*pFunctionList->C_GetTokenInfo)(999999999,&tokenInfo);
    checkPrintResult("C_GetTokenInfo avec mauvais slotID",rv,testNumber,MsgsTbl);

		

		//Récupération des infos de la carte
		testNumber++;// 120
		rv = (*pFunctionList->C_GetTokenInfo)(pSlotList[0], &tokenInfo);
    checkPrintResult("C_GetTokenInfo",rv,testNumber,MsgsTbl);
		
		if(rv == CKR_OK)
		{
			printf("Nom de la carte : %.32s\n",tokenInfo.label);
            // Test du type de carte
            if ( strstr((const char *)tokenInfo.label, (const char *)"CPS3") != NULL) isCPS3_Card = CK_TRUE;
			if (strstr((const char*)tokenInfo.label, (const char*)"CPS4") != NULL) isCPS3_Card |= TYPE_CPS4;
			printf("Identifiant du fabricant : %.32s\n",tokenInfo.manufacturerID);
			printf("Mod" E_GRAVE "le : %.16s\n",tokenInfo.model);
			printf("Num" E_AIGUE "ro de s" E_AIGUE "rie : %.16s\n",tokenInfo.serialNumber);
			printf("Nombre de sessions max :  %lu\n",tokenInfo.ulMaxSessionCount);
			printf("Nombre de sessions ouvertes :  %lu\n",tokenInfo.ulSessionCount);
			printf("Nombre de sessions de lecture/" E_AIGUE "criture max : %lu\n",tokenInfo.ulMaxRwSessionCount);
			printf("Nombre de sessions de lecture/" E_AIGUE "criture ouvertes :  %lu\n",tokenInfo.ulRwSessionCount);
			printf("Taille maximum du code PIN :  %lu\n",tokenInfo.ulMaxPinLen);
			printf("Taille minimum du code PIN :  %lu\n",tokenInfo.ulMinPinLen);
			printf("Capacit" E_AIGUE " m" E_AIGUE "moire public : %lu\n",tokenInfo.ulTotalPublicMemory);
			printf("Capacit" E_AIGUE " m" E_AIGUE "moire public libre : %lu\n",tokenInfo.ulFreePublicMemory);
			printf("Capacit" E_AIGUE " m" E_AIGUE "moire priv" E_AIGUE "e : %lu\n",tokenInfo.ulTotalPrivateMemory);
			printf("Capacit" E_AIGUE " m" E_AIGUE "moire priv" E_AIGUE "e libre : %lu\n",tokenInfo.ulFreePrivateMemory);
			printf("Version du mat" E_AIGUE "riel :  %u.%u\n",tokenInfo.hardwareVersion.major,tokenInfo.hardwareVersion.minor);
			printf("Version du firmware :  %u.%u\n",tokenInfo.firmwareVersion.major,tokenInfo.firmwareVersion.minor);
			printf("Nombre de sessions max :  %lu\n",tokenInfo.ulMaxSessionCount);
			printf("Temps UTC : %s\n",tokenInfo.utcTime);
			//flags
			printf("Flags : %x\n",tokenInfo.flags);
			for(int j = 0 ; j < 18 ; j++)
			{
				if(tokenInfo.flags & tokenInfoFlagsTab[j].mask)
				{
					printf("%s : OUI\n",mecaInfoFlagsTab[j].name);
				}
				else
				{
					printf("%s : NON\n",mecaInfoFlagsTab[j].name);
				}
			}		
			printf("---------------------\n");
		}
		
		CK_SLOT_ID slotID;
		//Attente d'un évenement du lecteur avec un flag à 0. Censé retourner CKR_FUNCTION_NOT_SUPPORTED
		testNumber++;// 121
		if (doWaitForSlotEvent) {
    if (!isCPS3) {
      // si on n'est pas en CPS3, le comportement de C_WaitForSlotEvent est cohérent vis a vis des specs
      MsgsTbl[testNumber].usExpectedRc = CKR_OK;
      printf("\tRetirer / ins" E_AIGUE "rer la carte du lecteur\n");
    }
    
		rv = (*pFunctionList->C_WaitForSlotEvent)(0, &slotID,NULL);
    checkPrintResult("C_WaitForSlotEvent sans le flag CKF_DONT_BLOCK",rv,testNumber,MsgsTbl);
		}
     
    testNumber++;// 122
		if (doWaitForSlotEvent) {
    if (!isCPS3) {
       // si on n'est pas en CPS3, le comportement de C_WaitForSlotEvent est cohérent vis a vis des specs
       MsgsTbl[testNumber].usExpectedRc = CKR_OK;
       printf("\tRetirer / ins" E_AIGUE "rer la carte du lecteur\n");
		   rv = (*pFunctionList->C_WaitForSlotEvent)(0, &slotID,NULL);
       checkPrintResult("C_WaitForSlotEvent sans le flag CKF_DONT_BLOCK",rv,testNumber,MsgsTbl);
		   
    }
		}

		//Attente d'un évenement du lecteur avec un flag défini (CKF_DONT_BLOCK). Retourne CKR_NO_EVENT
		testNumber++;// 123
		rv = (*pFunctionList->C_WaitForSlotEvent)(CKF_DONT_BLOCK,&slotID,NULL);
    checkPrintResult("C_WaitForSlotEvent avec le flag CKF_DONT_BLOCK",rv,testNumber,MsgsTbl);
		

		unsigned long nbMechanism = 1;
		//test de récupération de la liste des mécanismes supportés avec un buffer trop petit
		CK_MECHANISM_TYPE_PTR mechanismList = (CK_MECHANISM_TYPE_PTR)malloc( sizeof(CK_MECHANISM_TYPE));
		nbMechanism = 1;
		testNumber++;// 124
		rv = (*pFunctionList->C_GetMechanismList)(pSlotList[0], mechanismList,&nbMechanism);
    checkPrintResult("C_GetMechanismList avec un buffer trop petit",rv,testNumber,MsgsTbl);
		
		free(mechanismList);

		//test de récupération du nombre de mécanismes supportés
		testNumber++;
		rv = (*pFunctionList->C_GetMechanismList)(pSlotList[0], NULL, &nbMechanism);
    checkPrintResult("C_GetMechanismList",rv,testNumber,MsgsTbl);
		
		if(rv == CKR_OK)
		{
			testNumber++;// 125
			printf("Nombre de m" E_AIGUE "canismes support" E_AIGUE "s : %lu\n",nbMechanism);
			//test de récupération de la liste des mécanismes supportés
			if(nbMechanism > 0)
			{
				mechanismList = (CK_MECHANISM_TYPE_PTR)malloc( sizeof(CK_MECHANISM_TYPE) * nbMechanism);
				
				rv = (*pFunctionList->C_GetMechanismList)(pSlotList[0], mechanismList, &nbMechanism);
        checkPrintResult("C_GetMechanismList",rv,testNumber,MsgsTbl);
				
				char mechanismName[100];
				for(int i = 0 ; i < (int)nbMechanism ; i++)
				{
					getMechanismTypeString(mechanismList[i],mechanismName);
					printf("%s\n",mechanismName);
				}
			}

		}
		testNumber++;// 126
		rv = testGetMechanismInfo(pFunctionList,pSlotList[0], mechanismList,nbMechanism);
    checkPrintResult("C_GetMechanismInfo",rv,testNumber,MsgsTbl);

    if (pSlotList) free(pSlotList);

		(*pFunctionList->C_Finalize)(NULL);
    if( isCPS3 && cacheTest) {
     

    char * tabCardFiles[] = { "_00015031",
     "_00015032","_00017001","_00017002","_00017004","_00017005","_00017006","_00017102","_00017104","_00017105","_00017106","_0001A001","_0001A002","_0001A003","_0001D121","_0001D122","_0001D123","_0001D124","_0001D125","_0001D126","_0001D127","_0001D128","_0001D129","_00025031","_00025032","_2F00","_s_00015031","_s_00015032","_s_00025031","_s_00025032",
      "_s_2F00",
      NULL
    };
    int index = 0;
    int rc = 0;
    while (tabCardFiles[index] != NULL) {
       deleteCache( );

       rv = (*pFunctionList->C_Initialize)(NULL);

      // C_GetSlotList et paramètres corrects
      testNumber++; //128
      rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, NULL_PTR, &nbSlots);
      if (rv == CKR_OK)
        if(nbSlots == 0) rv = CKR_ASIPTEST_FAILED;
      checkPrintResult("C_GetSlotList avec r" E_AIGUE "cuperation des identifiants des lecteurs avec carte",rv,testNumber,MsgsTbl);

      if (rv == CKR_OK)
        if (nbSlots>0)
           rv = (*pFunctionList->C_GetTokenInfo)(0, &tokenInfo);

      (*pFunctionList->C_Finalize)(NULL);

modify:
      rc = modifyCache( (char *)tokenInfo.serialNumber, tabCardFiles[index] );

      if (!rc ) {
        char extendedLibelle[256];
        // C_Initialize et paramètres corrects
        testNumber++; //129
        rv = (*pFunctionList->C_Initialize)(NULL);
        checkPrintResult("C_Initialize avec cache fichiers modifi" E_AIGUE  ,rv,testNumber,MsgsTbl);

        // C_GetSlotList et paramètres corrects
        testNumber++; //130
        rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, NULL_PTR, &nbSlots);
        if (rv == CKR_OK)
           if(nbSlots == 0) rv = CKR_ASIPTEST_FAILED;
        strcpy(extendedLibelle, MsgsTbl[testNumber].Msg);
        strcat(extendedLibelle, " (");
        strcat(extendedLibelle, tabCardFiles[index]);
        strcat(extendedLibelle, ")");
        checkPrintResult("C_GetSlotList avec r" E_AIGUE "cuperation des identifiants des lecteurs avec carte" ,rv,testNumber,MsgsTbl);

        testNumber-= 3;
      }
 
      if (!rc)
        (*pFunctionList->C_Finalize)(NULL);
      index++;
      if ( rc )
        goto modify;
    }

    /* C_Initialize et paramètres corrects
    testNumber++; //129
    rv = (*pFunctionList->C_Initialize)(NULL);
    test=SAVE_RESULT(MsgsTbl, testNumber, rv);
		printf("%03d : C_Initialize avec cache fichiers modifi" E_AIGUE " : %s\n",MsgsTbl[testNumber].TestLevel,test==0?"OK":getErrorCodeString(rv,errorCode));*/

    deleteCache( );
    }
	}
}

//*****************************
//Teste la récupération des informations de chaque mécanisme supporté
//*****************************
CK_RV testGetMechanismInfo(CK_FUNCTION_LIST *pFunctionList, CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR mechanismList, int nbMechanism)
{
	CK_RV rv;
	CK_MECHANISM_INFO mechanismInfo;
	char str[100];
	printf("---------------------\n");
	for(int i = 0 ; i < nbMechanism ; i++)
	{
		rv = (*pFunctionList->C_GetMechanismInfo)(slotID,mechanismList[i],&mechanismInfo);
		printf("Nom du m" E_AIGUE "canisme : %s\n",getMechanismTypeString(mechanismList[i],str));
		printf("Taille minimale de la cl" E_AIGUE " : %lu\n",mechanismInfo.ulMinKeySize);
		printf("Taille maximale de la cl" E_AIGUE " : %lu\n",mechanismInfo.ulMaxKeySize);
		printf("Flags :\n");
		//on teste chaque flag
		for(int j = 0 ; j < 14 ; j++)
		{
			if(mechanismInfo.flags & mecaInfoFlagsTab[j].mask)
			{
				printf("%s : OUI\n",mecaInfoFlagsTab[j].name);
			}
			else
			{
				printf("%s : NON\n",mecaInfoFlagsTab[j].name);
			}
		}		
		printf("---------------------\n");
	}
	return rv;
}

//*******************************************************************
//Effectue les tests de gestion de session
//*******************************************************************
void testSessionManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BBOOL * pIsContactLess)
{
	int testNumber = getIndexDebutSectionTests( SESSION_FUNCTIONS);
	CK_RV rv;
	CK_SESSION_HANDLE sessionRO;
	CK_SESSION_HANDLE sessionRW;
  CK_SESSION_HANDLE session3, session4, session5;
	CK_SESSION_INFO sessionInfo;
  CK_ULONG nbSlots;
	unsigned long operationStateLen;

	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK)
	{
    //récupération du nombre de lecteurs ayant une carte insérée
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE,NULL,&nbSlots);
		//printf("C_GetSlotList nombre de lecteurs avec carte : %s\n", getErrorCodeString(rv,errorCode));

    // Recuperation liste des identifiants de lecteurs ayant une carte
    CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(nbSlots * sizeof(CK_SLOT_ID));
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, pSlotList, &nbSlots);
		//printf("C_GetSlotList avec r" E_AIGUE "cuperation des identifiants des lecteurs avec carte : %s\n", getErrorCodeString(rv,errorCode));

		//ouverture d'une session en lecture seule
		rv = (*pFunctionList->C_OpenSession)(pSlotList[0],CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
    checkPrintResult("C_OpenSession en lecture seule" ,rv,testNumber,MsgsTbl);
		

		//ouverture d'une session en lecture écriture
		testNumber++;
		rv = (*pFunctionList->C_OpenSession)(pSlotList[0],CKF_SERIAL_SESSION | CKF_RW_SESSION,NULL_PTR,NULL_PTR,&sessionRW);
    checkPrintResult("C_OpenSession en lecture et " E_AIGUE "criture" ,rv,testNumber,MsgsTbl);

    //ouverture d'une 3eme session en lecture seule
    testNumber++;
		rv = (*pFunctionList->C_OpenSession)(pSlotList[0],CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&session3);
    checkPrintResult("C_OpenSession en lecture seule (3eme session)" ,rv,testNumber,MsgsTbl);
		
    //ouverture d'une 4eme session en lecture seule
    testNumber++;
		rv = (*pFunctionList->C_OpenSession)(pSlotList[0],CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&session4);
    checkPrintResult("C_OpenSession en lecture seule (4eme session)" ,rv,testNumber,MsgsTbl);

     //ouverture d'une 5eme session en lecture seule
    testNumber++;
		rv = (*pFunctionList->C_OpenSession)(pSlotList[0],CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&session5);
    checkPrintResult("C_OpenSession en lecture seule (5eme session)" ,rv,testNumber,MsgsTbl);

		//récupération des informations d'une session
		testNumber++;
		rv = (*pFunctionList->C_GetSessionInfo)(sessionRO,&sessionInfo);
    checkPrintResult("C_GetSessionInfo" ,rv,testNumber,MsgsTbl);
		
		
		//login SO sur une session en lecture seule
		testNumber++;
		rv = (*pFunctionList->C_Login)(sessionRO,CKU_SO,pin,4);
    checkPrintResult("C_Login SO sur une session en lecture seule" ,rv,testNumber,MsgsTbl);
		

		//login user
		testNumber++;
		rv = (*pFunctionList->C_Login)(sessionRO,CKU_USER,pin,4);
    if (rv == CKR_USER_PIN_NOT_INITIALIZED) {
      /* on est en sans contact */
      MsgsTbl[testNumber].usExpectedRc = CKR_USER_PIN_NOT_INITIALIZED;
      *pIsContactLess = CK_TRUE;
    }
    else {
      if (rv == CKR_PIN_INCORRECT) {
        printf("Code porteur incorrect. Saisissez un code correct: ");
        fscanf(stdin, "%4s", pin);
        getchar();
        rv = (*pFunctionList->C_Login)(sessionRO, CKU_USER, pin, 4);
      }
    }
    checkPrintResult("C_Login utilisateur" ,rv,testNumber,MsgsTbl);
		

		//login dans une session déjà logué
		testNumber++;
    if (*pIsContactLess == CK_TRUE) {
      MsgsTbl[testNumber].usExpectedRc = CKR_USER_PIN_NOT_INITIALIZED;
    }
		rv = (*pFunctionList->C_Login)(sessionRO,CKU_USER,pin,4);
    checkPrintResult("C_Login deuxi" E_GRAVE "me fois" ,rv,testNumber,MsgsTbl);
		

		//initialisation du code pin de l'utilisateur
		//testNumber++;
		//rv = (*pFunctionList->C_InitPIN)(sessionRO,NULL_PTR,0);
		//checkPrintResult("C_InitPIN", rv, testNumber, MsgsTbl);
		//test=SAVE_RESULT(MsgsTbl, testNumber, rv);

		//C_GetOperationState
		testNumber++;
		rv = (*pFunctionList->C_GetOperationState)(sessionRO,NULL_PTR,&operationStateLen);
    checkPrintResult("C_GetOperationState" ,rv,testNumber,MsgsTbl);
		

		//C_SetOperationState
		testNumber++;
		rv = (*pFunctionList->C_SetOperationState)(sessionRO,NULL_PTR,0,NULL_PTR,NULL_PTR);
    checkPrintResult("C_SetOperationState" ,rv,testNumber,MsgsTbl);
		
		
		//déconnexion
		testNumber++;
    if (*pIsContactLess == CK_TRUE) {
      MsgsTbl[testNumber].usExpectedRc = CKR_USER_NOT_LOGGED_IN;
    }
		rv = (*pFunctionList->C_Logout)(sessionRO);
    checkPrintResult("C_Logout" ,rv,testNumber,MsgsTbl);
		

		//fermeture de session
		testNumber++;
		rv = (*pFunctionList->C_CloseSession)(sessionRO);
    checkPrintResult("C_CloseSession" ,rv,testNumber,MsgsTbl);
		

		//fermeture de toutes les sessions
		testNumber++;
		rv = (*pFunctionList->C_CloseAllSessions)(pSlotList[0]);
    checkPrintResult("C_CloseAllSession" ,rv,testNumber,MsgsTbl);

    // fermeture de session 3
		testNumber++;
		rv = (*pFunctionList->C_CloseSession)(session3);
    checkPrintResult("C_CloseSession de session 3" ,rv,testNumber,MsgsTbl);
		

		//*************************************************
		//Tests avec un mauvais handle de session renseigné
		//*************************************************
		
		//récupération des informations d'une session avec un mauvais handle de session
		testNumber++;
		rv = (*pFunctionList->C_GetSessionInfo)(999,&sessionInfo);
    checkPrintResult("C_GetSessionInfo avec mauvais handle de session" ,rv,testNumber,MsgsTbl);
		

		//login avec un mauvais handle de session
		testNumber++;
		rv = (*pFunctionList->C_Login)(999,CKU_USER,pin,4);
    checkPrintResult("C_Login avec mauvais handle de session" ,rv,testNumber,MsgsTbl);

    //ouverture d'une session et mauvais parametre d'entree
    testNumber++;
		rv = (*pFunctionList->C_OpenSession)(0,CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR, NULL_PTR);
    checkPrintResult("C_OpenSession et param" E_GRAVE "tre invalide" ,rv,testNumber,MsgsTbl);
		

		(*pFunctionList->C_Finalize)(NULL);

    if (pSlotList) free(pSlotList);
	}
	
	//*********************************************
	//Les mêmes tests sans la librairie initialisée
	//*********************************************

	//ouverture d'une session
	testNumber++;
	rv = (*pFunctionList->C_OpenSession)(0,CKF_SERIAL_SESSION | CKF_RW_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
  checkPrintResult("C_OpenSession et lib non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	

	//récupération des informations d'une session
	testNumber++;
	rv = (*pFunctionList->C_GetSessionInfo)(sessionRO,&sessionInfo);
  checkPrintResult("C_GetSessionInfo et lib non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	

	//login
	testNumber++;
	rv = (*pFunctionList->C_Login)(sessionRO,CKU_USER,pin,4);
  checkPrintResult("C_Login et lib non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	


	testNumber++;
	if (!isCPS3) {
		// si on n'est pas en CPS3, la fonction C_InitPIN est non supportée
		MsgsTbl[testNumber].usExpectedRc = CKR_FUNCTION_NOT_SUPPORTED;
	}
	rv = (*pFunctionList->C_InitPIN)(sessionRO,NULL_PTR,0);
	checkPrintResult("C_InitPIN et lib non initialis" E_AIGUE "e", rv,testNumber,MsgsTbl);
	//test=SAVE_RESULT(MsgsTbl, testNumber, rv);

	//déconnexion
	testNumber++;
	rv = (*pFunctionList->C_Logout)(sessionRO);
  checkPrintResult("C_Logout et lib non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);
	
	
}

//*******************************************************************
//Effectue les tests de gestion d'objets
//*******************************************************************
void testObjectManagementFunctions(CK_FUNCTION_LIST *pFunctionList, CK_CHAR_PTR pin, CK_BBOOL isContactLess)
{
	int testNumber = getIndexDebutSectionTests(OBJECTS_FUNCTIONS);
	CK_RV rv;
	CK_SESSION_HANDLE sessionRO;
	CK_SESSION_HANDLE sessionRW = 999;
  CK_ULONG nbSlots;
	char errorCode[50];
	unsigned long objCount = 0;

	CK_BBOOL vrai=CK_TRUE;
  /*CK_BBOOL modifiable = CK_TRUE;*/
  CK_BBOOL is_private = CK_FALSE;
	CK_OBJECT_CLASS dataClass=CKO_DATA;
	/*CK_CHAR dataLabel[] = "CPS_DATA";*/
	CK_CHAR dataLabel[] = "CPS_ID_CARD";
	CK_ATTRIBUTE dataTemplate[]={	{CKA_CLASS, &dataClass, sizeof(dataClass)},
	{CKA_TOKEN, &vrai, sizeof(vrai)},
	{/*CKA_MODIFIABLE*/CKA_PRIVATE, &is_private, sizeof(is_private)},
	{CKA_LABEL, dataLabel, (CK_ULONG)strlen((char *)dataLabel)}
	};
  CK_ULONG dataTemplateSize=sizeof(dataTemplate)/sizeof(dataTemplate[0]);
  
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  unsigned short keyType ='S';

  CK_ATTRIBUTE cps2CertTemplate[] = {
	    {CKA_CLASS,&keyClass,sizeof(keyClass)},
	    {CKA_CPS_KEY_TYPE,&keyType,sizeof(keyType)}
  };
  
  CK_ULONG cps2CertTemplateSize=sizeof(cps2CertTemplate)/sizeof(cps2CertTemplate[0]);

	CK_OBJECT_HANDLE hObject=0;
	CK_OBJECT_HANDLE cps2TabObject[3] = {0};

  //findobjectsinit et librairie non initialisee
  rv = (*pFunctionList->C_FindObjectsInit)(sessionRW,dataTemplate,objCount);
  checkPrintResult("C_FindObjectsInit et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);

  // Execution recherche d'objets et lib non intialisée
  testNumber++;
  rv = (*pFunctionList->C_FindObjects)(sessionRW,&hObject,1,&objCount);
  checkPrintResult("C_FindObjects et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);

  // Fin de recherche d'objets et lib non intialisée
  testNumber++;
	rv = (*pFunctionList->C_FindObjectsFinal)(sessionRW);
  checkPrintResult("C_FindObjectsFinal et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);

   // Recuperation d'attribut d'objets et lib non intialisée
  testNumber++;
  rv = (*pFunctionList->C_GetAttributeValue)(sessionRW, hObject, dataTemplate, objCount);
  checkPrintResult("C_GetAttributeValue et librairie non initialis" E_AIGUE "e" ,rv,testNumber,MsgsTbl);

	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK)
	{
    //récupération du nombre de lecteurs ayant une carte insérée
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE,NULL,&nbSlots);
		//printf("C_GetSlotList nombre de lecteurs avec carte : %s\n", getErrorCodeString(rv,errorCode));

    // Recuperation liste des identifiants de lecteurs ayant une carte
    CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(nbSlots * sizeof(CK_SLOT_ID));
		rv = (*pFunctionList->C_GetSlotList)(CK_TRUE, pSlotList, &nbSlots);
		//printf("C_GetSlotList avec r"E_AIGUE"cuperation des identifiants des lecteurs avec carte : %s\n", getErrorCodeString(rv,errorCode));
    
		//ouverture d'une session en lecture seule
		rv = (*pFunctionList->C_OpenSession)(pSlotList[0],CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,&sessionRO);
		
		//ouverture d'une session en lecture écriture		
		rv = (*pFunctionList->C_OpenSession)(pSlotList[0],CKF_SERIAL_SESSION | CKF_RW_SESSION,NULL_PTR,NULL_PTR,&sessionRW);
		
		if (!isCPS3) {
		  rv=(*pFunctionList->C_Login)(sessionRW, CKU_USER, (CK_BYTE_PTR)pin, strlen((const char *)pin));
	      if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN) return;
		}
		

		//createobject
    testNumber++;
    if (!isCPS3) {
      // si on n'est pas en CPS3, le comportement de C_WaitForSlotEvent est cohérent vis a vis des specs
      MsgsTbl[testNumber].usExpectedRc = CKR_TEMPLATE_INCOMPLETE;
    }
		rv = (*pFunctionList->C_CreateObject)(sessionRO,dataTemplate,objCount,&hObject);
    checkPrintResult("C_CreateObject" ,rv,testNumber,MsgsTbl);
		

		//copyobject
		testNumber++;
    if (!isCPS3) {
      // si on n'est pas en CPS3, le comportement de C_WaitForSlotEvent est cohérent vis a vis des specs
      MsgsTbl[testNumber].usExpectedRc = CKR_OBJECT_HANDLE_INVALID;
    }
		CK_OBJECT_HANDLE hNewObject = 0;
		rv = (*pFunctionList->C_CopyObject)(sessionRO,0,dataTemplate,objCount,&hNewObject);
    checkPrintResult("C_CopyObject" ,rv,testNumber,MsgsTbl);
		
		
		//findobjectsinit avec mauvais session handle
		testNumber++;
    rv = (*pFunctionList->C_FindObjectsInit)(999,dataTemplate,dataTemplateSize);
    checkPrintResult("C_FindObjectsInit avec mauvais session handle" ,rv,testNumber,MsgsTbl);
		

		//findobjectsinit
		testNumber++;
		if (!isCPS3) {
		rv = (*pFunctionList->C_FindObjectsInit)(sessionRW, cps2CertTemplate, cps2CertTemplateSize);
		}
		else {
      keyType = AT_SIGNATURE;
      if (isContactLess == CK_TRUE) {
        /* En sans contact, l'objet CPS_DATA que l'on recherche n'est pas modifiable */
        is_private = CK_FALSE;
        keyType = AT_KEYEXCHANGE;
		dataTemplate[2].type = CKA_MODIFIABLE;
		strcpy((char*)dataLabel, "CPS_DATA");
		dataTemplate[3].ulValueLen = strlen((const char*)dataLabel);
      }
    rv = (*pFunctionList->C_FindObjectsInit)(sessionRW,dataTemplate,dataTemplateSize);
	   }
    checkPrintResult("C_FindObjectsInit fonctionnel" ,rv,testNumber,MsgsTbl);
		

		//findobjects
		testNumber++;
		if (!isCPS3) {
		rv = (*pFunctionList->C_FindObjects)(sessionRW, cps2TabObject, 2, &objCount);
		printf("\n\t ****** objCount = %d\n", objCount);
		}
		else {
		rv = (*pFunctionList->C_FindObjects)(sessionRW,&hObject,1,&objCount);
		}
    checkPrintResult("C_FindObjects fonctionnel" ,rv,testNumber,MsgsTbl);
		

		//findobjects avec mauvais handle session
		testNumber++;
		rv = (*pFunctionList->C_FindObjects)(999,&hObject,1,&objCount);
    checkPrintResult("C_FindObjects avec mauvais session handle" ,rv,testNumber,MsgsTbl);
		

		//getobjectsize
		testNumber++;
		unsigned long objectSize = 0;
		rv = (*pFunctionList->C_GetObjectSize)(sessionRO,hObject,&objectSize);
    checkPrintResult("C_GetObjectSize" ,rv,testNumber,MsgsTbl);
		


		//findobjectsfinal
		testNumber++;
		rv = (*pFunctionList->C_FindObjectsFinal)(sessionRW);
    checkPrintResult("C_FindObjectsFinal fonctionnel" ,rv,testNumber,MsgsTbl);

    // Recuperation d'attribut de l'objet CPS_DATA
    testNumber++;
	if (!isCPS3) {
	  rv = (*pFunctionList->C_GetAttributeValue)(sessionRW, cps2TabObject[0], cps2CertTemplate, cps2CertTemplateSize);
	}
	else {
      rv = (*pFunctionList->C_GetAttributeValue)(sessionRW, hObject, dataTemplate, objCount);
	}
    checkPrintResult("C_GetAttributeValue sur objet CPS_DATA" ,rv,testNumber,MsgsTbl);
		
    // Recuperer l'objet clé privée de signature (AT_SIGNATURE)
    hObject = NULL_PTR;
		testGetPkcs11Object(pFunctionList, sessionRO, SIGNATU_FUNCTIONS, keyType, pin, &hObject, &testNumber);

    if (!isContactLess) {
      // Recuperer l'objet clé publique de signature (AT_SIGNATURE)
      hObject = NULL_PTR;
      testGetPkcs11Object(pFunctionList, sessionRO, VERISGN_FUNCTIONS, keyType, NULL, &hObject, &testNumber);
    }

		rv = (*pFunctionList->C_CloseAllSessions)(pSlotList[0]);
    if (rv != CKR_OK)
      printf("ERREUR : C_CloseAllSessions fermeture de toutes les sessions : %s\n", getErrorCodeString(rv,errorCode));


		(*pFunctionList->C_Finalize)(NULL);

    if (pSlotList) free(pSlotList);
	}
}

//*******************************************************************
//Effectue les tests divers et variés
//*******************************************************************
void testMiscellaneousFunctions(CK_FUNCTION_LIST *pFunctionList)
{
	int testNumber = getIndexDebutSectionTests(MISCELLANEOUS_TEST);
	CK_RV rv;
	CK_SESSION_HANDLE sessionRW = 999;
  CK_ULONG nbSlots;
	unsigned long objCount = 0;
    CK_SLOT_INFO slotInfo;

    printf("Insérer une carte CPS à l'envers...");
    getchar();

	rv = (*pFunctionList->C_Initialize)(NULL);
	if(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
        //récupération du nombre de lecteurs sans carte
		rv = (*pFunctionList->C_GetSlotList)(CK_FALSE, NULL,&nbSlots);
		//printf("C_GetSlotList nombre de lecteurs avec carte : %s\n", getErrorCodeString(rv,errorCode));

        // Recuperation liste des identifiants de tous les lecteurs
        CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR)malloc(nbSlots * sizeof(CK_SLOT_ID));
		rv = (*pFunctionList->C_GetSlotList)(CK_FALSE, pSlotList, &nbSlots);
        checkPrintResult("C_GetSlotIList et r" E_AIGUE "cuper" E_AIGUE "ation  de tous les slots" ,rv,testNumber,MsgsTbl);
		//printf("C_GetSlotList avec r" E_AIGUE "cuperation des identifiants des lecteurs avec carte : %s\n", getErrorCodeString(rv,errorCode));
        testNumber++;
		//Recuperation des informations d'un slot
		rv = (*pFunctionList->C_GetSlotInfo)(pSlotList[0], &slotInfo);
        checkPrintResult("C_GetSlotInfo et carte ins" E_AIGUE "r" E_AIGUE "e à l'envers" ,rv,testNumber,MsgsTbl);
		
   

		(*pFunctionList->C_Finalize)(NULL);

    if (pSlotList) free(pSlotList);
	}
}

//stocke les résultats dans un fichier csv
int ConsigneResultatCSV(unsigned short __usTestNumero, unsigned long usRc, unsigned long usExpectedRc, char * libelle)
{
	static unsigned short bFirstCall = TRUE;
	char ligneCSV[1024]="";
	char strTime[100]="";
	FILE * csv = NULL;

	if(bFirstCall) remove("Resultats.csv");

	csv = fopen("Resultats.csv","ab+");
	if(csv)
	{
		if(bFirstCall)
		{
			/* Imprimer une ligne d'en-tete au 1er appel */
			strcpy(ligneCSV, "Num\xe9ro test;Libellé;CR attendu;CR re\xe7u;Statut test;Date");
			fprintf(csv, "%s\n", ligneCSV);
			strcpy(ligneCSV, LIGNE_VIDE_CSV);
			fprintf(csv, "%s\r\n", ligneCSV);
      htmlWriteHeader();
			bFirstCall = FALSE;
		}

		sys_getTime(strTime);
		/*sprintf(ligneCSV, "%03d;%s;0x%04X;%s;",__usTestNumero,libelle,usRc, (usExpectedRc == (unsigned short)-1) ? "OK" : "KO");
		fprintf(csv, "%s\n", ligneCSV);*/
		fprintf(csv, "%03d;%s;0x%04X;0x%04X;%s;%s\r\n",__usTestNumero, libelle, usExpectedRc, usRc, (usExpectedRc == usRc) ? "OK" : "KO", strTime);

		fclose(csv);
    htmlWriteTableRow(__usTestNumero, libelle, usExpectedRc, usRc, strTime);
	}
  return (!(usRc == usExpectedRc));
}


void sys_getTime(char * buffer)
{
	time_t rawtime;
	struct tm * timeinfo;

	time ( &rawtime );
	timeinfo = localtime ( &rawtime );

	strftime(buffer,100,"%d/%m/%Y %H:%M:%S",timeinfo);
}

char * getErrorCodeString(CK_RV error, char * strError)
{
	switch (error){
	case CKR_OK                                : strcpy(strError, "CKR_OK"); break;
	case CKR_CANCEL                            : strcpy(strError, "CKR_CANCEL"); break;
	case CKR_HOST_MEMORY                       : strcpy(strError, "CKR_HOST_MEMORY"); break;
	case CKR_SLOT_ID_INVALID                   : strcpy(strError, "CKR_SLOT_ID_INVALID"); break;
	case CKR_GENERAL_ERROR                     : strcpy(strError, "CKR_GENERAL_ERROR"); break;
	case CKR_FUNCTION_FAILED                   : strcpy(strError, "CKR_FUNCTION_FAILED"); break;
	case CKR_ARGUMENTS_BAD                     : strcpy(strError, "CKR_ARGUMENTS_BAD"); break;
	case CKR_NO_EVENT                          : strcpy(strError, "CKR_NO_EVENT"); break;
	case CKR_NEED_TO_CREATE_THREADS            : strcpy(strError, "CKR_NEED_TO_CREATE_THREADS"); break;
	case CKR_CANT_LOCK                         : strcpy(strError, "CKR_CANT_LOCK"); break;
	case CKR_ATTRIBUTE_READ_ONLY               : strcpy(strError, "CKR_ATTRIBUTE_READ_ONLY"); break;
	case CKR_ATTRIBUTE_SENSITIVE               : strcpy(strError, "CKR_ATTRIBUTE_SENSITIVE"); break;
	case CKR_ATTRIBUTE_TYPE_INVALID            : strcpy(strError, "CKR_ATTRIBUTE_TYPE_INVALID"); break;
	case CKR_ATTRIBUTE_VALUE_INVALID           : strcpy(strError, "CKR_ATTRIBUTE_VALUE_INVALID"); break;
	case CKR_DATA_INVALID                      : strcpy(strError, "CKR_DATA_INVALID"); break;
	case CKR_DATA_LEN_RANGE                    : strcpy(strError, "CKR_DATA_LEN_RANGE"); break;
	case CKR_DEVICE_ERROR                      : strcpy(strError, "CKR_DEVICE_ERROR"); break;
	case CKR_DEVICE_MEMORY                     : strcpy(strError, "CKR_DEVICE_MEMORY"); break;
	case CKR_DEVICE_REMOVED                    : strcpy(strError, "CKR_DEVICE_REMOVED"); break;
	case CKR_ENCRYPTED_DATA_INVALID            : strcpy(strError, "CKR_ENCRYPTED_DATA_INVALID"); break;
	case CKR_ENCRYPTED_DATA_LEN_RANGE          : strcpy(strError, "CKR_ENCRYPTED_DATA_LEN_RANGE"); break;
	case CKR_FUNCTION_CANCELED                 : strcpy(strError, "CKR_FUNCTION_CANCELED"); break;
	case CKR_FUNCTION_NOT_PARALLEL             : strcpy(strError, "CKR_FUNCTION_NOT_PARALLEL"); break;
	case CKR_FUNCTION_NOT_SUPPORTED            : strcpy(strError, "CKR_FUNCTION_NOT_SUPPORTED"); break;
	case CKR_KEY_HANDLE_INVALID                : strcpy(strError, "CKR_KEY_HANDLE_INVALID"); break;
	case CKR_KEY_SIZE_RANGE                    : strcpy(strError, "CKR_KEY_SIZE_RANGE"); break;
	case CKR_KEY_TYPE_INCONSISTENT             : strcpy(strError, "CKR_KEY_TYPE_INCONSISTENT"); break;
	case CKR_KEY_NOT_NEEDED                    : strcpy(strError, "CKR_KEY_NOT_NEEDED"); break;
	case CKR_KEY_CHANGED                       : strcpy(strError, "CKR_KEY_CHANGED"); break;
	case CKR_KEY_NEEDED                        : strcpy(strError, "CKR_KEY_NEEDED"); break;
	case CKR_KEY_INDIGESTIBLE                  : strcpy(strError, "CKR_KEY_INDIGESTIBLE"); break;
	case CKR_KEY_FUNCTION_NOT_PERMITTED        : strcpy(strError, "CKR_KEY_FUNCTION_NOT_PERMITTED"); break;
	case CKR_KEY_NOT_WRAPPABLE                 : strcpy(strError, "CKR_KEY_NOT_WRAPPABLE"); break;
	case CKR_KEY_UNEXTRACTABLE                 : strcpy(strError, "CKR_KEY_UNEXTRACTABLE"); break;
	case CKR_MECHANISM_INVALID                 : strcpy(strError, "CKR_MECHANISM_INVALID"); break;
	case CKR_MECHANISM_PARAM_INVALID           : strcpy(strError, "CKR_MECHANISM_PARAM_INVALID"); break;
	case CKR_OBJECT_HANDLE_INVALID             : strcpy(strError, "CKR_OBJECT_HANDLE_INVALID"); break;
	case CKR_OPERATION_ACTIVE                  : strcpy(strError, "CKR_OPERATION_ACTIVE"); break;
	case CKR_OPERATION_NOT_INITIALIZED         : strcpy(strError, "CKR_OPERATION_NOT_INITIALIZED"); break;
	case CKR_PIN_INCORRECT                     : strcpy(strError, "CKR_PIN_INCORRECT"); break;
	case CKR_PIN_INVALID                       : strcpy(strError, "CKR_PIN_INVALID"); break;
	case CKR_PIN_LEN_RANGE                     : strcpy(strError, "CKR_PIN_LEN_RANGE"); break;
	case CKR_PIN_EXPIRED                       : strcpy(strError, "CKR_PIN_EXPIRED"); break;
	case CKR_PIN_LOCKED                        : strcpy(strError, "CKR_PIN_LOCKED"); break;
	case CKR_SESSION_CLOSED                    : strcpy(strError, "CKR_SESSION_CLOSED"); break;
	case CKR_SESSION_COUNT                     : strcpy(strError, "CKR_SESSION_COUNT"); break;
	case CKR_SESSION_HANDLE_INVALID            : strcpy(strError, "CKR_SESSION_HANDLE_INVALID"); break;
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED    : strcpy(strError, "CKR_SESSION_PARALLEL_NOT_SUPPORTED"); break;
	case CKR_SESSION_READ_ONLY                 : strcpy(strError, "CKR_SESSION_READ_ONLY"); break;
	case CKR_SESSION_EXISTS                    : strcpy(strError, "CKR_SESSION_EXISTS"); break;
	case CKR_SESSION_READ_ONLY_EXISTS          : strcpy(strError, "CKR_SESSION_READ_ONLY_EXISTS"); break;
	case CKR_SESSION_READ_WRITE_SO_EXISTS      : strcpy(strError, "CKR_SESSION_READ_WRITE_SO_EXISTS"); break;
	case CKR_SIGNATURE_INVALID                 : strcpy(strError, "CKR_SIGNATURE_INVALID"); break;
	case CKR_SIGNATURE_LEN_RANGE               : strcpy(strError, "CKR_SIGNATURE_LEN_RANGE"); break;
	case CKR_TEMPLATE_INCOMPLETE               : strcpy(strError, "CKR_TEMPLATE_INCOMPLETE"); break;
	case CKR_TEMPLATE_INCONSISTENT             : strcpy(strError, "CKR_TEMPLATE_INCONSISTENT"); break;
	case CKR_TOKEN_NOT_PRESENT                 : strcpy(strError, "CKR_TOKEN_NOT_PRESENT"); break;
	case CKR_TOKEN_NOT_RECOGNIZED              : strcpy(strError, "CKR_TOKEN_NOT_RECOGNIZED"); break;
	case CKR_TOKEN_WRITE_PROTECTED             : strcpy(strError, "CKR_TOKEN_WRITE_PROTECTED"); break;
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID     : strcpy(strError, "CKR_UNWRAPPING_KEY_HANDLE_INVALID"); break;
	case CKR_UNWRAPPING_KEY_SIZE_RANGE         : strcpy(strError, "CKR_UNWRAPPING_KEY_SIZE_RANGE"); break;
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  : strcpy(strError, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"); break;
	case CKR_USER_ALREADY_LOGGED_IN            : strcpy(strError, "CKR_USER_ALREADY_LOGGED_IN"); break;
	case CKR_USER_NOT_LOGGED_IN                : strcpy(strError, "CKR_USER_NOT_LOGGED_IN"); break;
	case CKR_USER_PIN_NOT_INITIALIZED          : strcpy(strError, "CKR_USER_PIN_NOT_INITIALIZED"); break;
	case CKR_USER_TYPE_INVALID                 : strcpy(strError, "CKR_USER_TYPE_INVALID"); break;
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN    : strcpy(strError, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"); break;
	case CKR_USER_TOO_MANY_TYPES               : strcpy(strError, "CKR_USER_TOO_MANY_TYPES"); break;
	case CKR_WRAPPED_KEY_INVALID               : strcpy(strError, "CKR_WRAPPED_KEY_INVALID"); break;
	case CKR_WRAPPED_KEY_LEN_RANGE             : strcpy(strError, "CKR_WRAPPED_KEY_LEN_RANGE"); break;
	case CKR_WRAPPING_KEY_HANDLE_INVALID       : strcpy(strError, "CKR_WRAPPING_KEY_HANDLE_INVALID"); break;
	case CKR_WRAPPING_KEY_SIZE_RANGE           : strcpy(strError, "CKR_WRAPPING_KEY_SIZE_RANGE"); break;
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT    : strcpy(strError, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"); break;
	case CKR_RANDOM_SEED_NOT_SUPPORTED         : strcpy(strError, "CKR_RANDOM_SEED_NOT_SUPPORTED"); break;
	case CKR_RANDOM_NO_RNG                     : strcpy(strError, "CKR_RANDOM_NO_RNG"); break;
	case CKR_DOMAIN_PARAMS_INVALID             : strcpy(strError, "CKR_DOMAIN_PARAMS_INVALID"); break;
	case CKR_BUFFER_TOO_SMALL                  : strcpy(strError, "CKR_BUFFER_TOO_SMALL"); break;
	case CKR_SAVED_STATE_INVALID               : strcpy(strError, "CKR_SAVED_STATE_INVALID"); break;
	case CKR_INFORMATION_SENSITIVE             : strcpy(strError, "CKR_INFORMATION_SENSITIVE"); break;
	case CKR_STATE_UNSAVEABLE                  : strcpy(strError, "CKR_STATE_UNSAVEABLE"); break;
	case CKR_CRYPTOKI_NOT_INITIALIZED          : strcpy(strError, "CKR_CRYPTOKI_NOT_INITIALIZED"); break;
	case CKR_CRYPTOKI_ALREADY_INITIALIZED      : strcpy(strError, "CKR_CRYPTOKI_ALREADY_INITIALIZED"); break;
	case CKR_MUTEX_BAD                         : strcpy(strError, "CKR_MUTEX_BAD"); break;
	case CKR_MUTEX_NOT_LOCKED                  : strcpy(strError, "CKR_MUTEX_NOT_LOCKED"); break;
  case CKR_ASIPTEST_FAILED                  : strcpy(strError, "CKR_ASIPTEST_FAILED"); break;
	default                                    : sprintf(strError,"0x%08x", error);      break;
	}
	return strError;
}


char * getMechanismTypeString(CK_ULONG mekaType, char * strMeka)
{
	switch (mekaType){
	case CKM_RSA_PKCS_KEY_PAIR_GEN    : strcpy(strMeka,"CKM_RSA_PKCS_KEY_PAIR_GEN"); break;
	case CKM_RSA_PKCS                 : strcpy(strMeka,"CKM_RSA_PKCS"); break;
	case CKM_RSA_9796                 : strcpy(strMeka,"CKM_RSA_9796"); break;
	case CKM_RSA_X_509                : strcpy(strMeka,"CKM_RSA_X_509"); break;
	case CKM_MD2_RSA_PKCS             : strcpy(strMeka,"CKM_MD2_RSA_PKCS"); break;
	case CKM_MD5_RSA_PKCS             : strcpy(strMeka,"CKM_MD5_RSA_PKCS"); break;
	case CKM_SHA1_RSA_PKCS            : strcpy(strMeka,"CKM_SHA1_RSA_PKCS"); break;
	case CKM_RIPEMD128_RSA_PKCS       : strcpy(strMeka,"CKM_RIPEMD128_RSA_PKCS"); break;
	case CKM_RIPEMD160_RSA_PKCS       : strcpy(strMeka,"CKM_RIPEMD160_RSA_PKCS"); break;
	case CKM_RSA_PKCS_OAEP            : strcpy(strMeka,"CKM_RSA_PKCS_OAEP"); break;
	case CKM_RSA_X9_31_KEY_PAIR_GEN   : strcpy(strMeka,"CKM_RSA_X9_31_KEY_PAIR_GEN"); break;
	case CKM_RSA_X9_31                : strcpy(strMeka,"CKM_RSA_X9_31"); break;
	case CKM_SHA1_RSA_X9_31           : strcpy(strMeka,"CKM_SHA1_RSA_X9_31"); break;
	case CKM_RSA_PKCS_PSS             : strcpy(strMeka,"CKM_RSA_PKCS_PSS"); break;
	case CKM_SHA1_RSA_PKCS_PSS        : strcpy(strMeka,"CKM_SHA1_RSA_PKCS_PSS"); break;
	case CKM_DSA_KEY_PAIR_GEN         : strcpy(strMeka,"CKM_DSA_KEY_PAIR_GEN"); break;
	case CKM_DSA                      : strcpy(strMeka,"CKM_DSA"); break;
	case CKM_DSA_SHA1                 : strcpy(strMeka,"CKM_DSA_SHA1"); break;
	case CKM_DH_PKCS_KEY_PAIR_GEN     : strcpy(strMeka,"CKM_DH_PKCS_KEY_PAIR_GEN"); break;
	case CKM_DH_PKCS_DERIVE           : strcpy(strMeka,"CKM_DH_PKCS_DERIVE"); break;
	case CKM_X9_42_DH_KEY_PAIR_GEN    : strcpy(strMeka,"CKM_X9_42_DH_KEY_PAIR_GEN"); break;
	case CKM_X9_42_DH_DERIVE          : strcpy(strMeka,"CKM_X9_42_DH_DERIVE "); break;
	case CKM_X9_42_DH_HYBRID_DERIVE   : strcpy(strMeka,"CKM_X9_42_DH_HYBRID_DERIVE"); break;
	case CKM_X9_42_MQV_DERIVE         : strcpy(strMeka,"CKM_X9_42_MQV_DERIVE"); break;
	case CKM_SHA256_RSA_PKCS          : strcpy(strMeka,"CKM_SHA256_RSA_PKCS"); break;
	case CKM_SHA384_RSA_PKCS          : strcpy(strMeka,"CKM_SHA384_RSA_PKCS"); break;
	case CKM_SHA512_RSA_PKCS          : strcpy(strMeka,"CKM_SHA512_RSA_PKCS"); break;
	case CKM_SHA256_RSA_PKCS_PSS      : strcpy(strMeka,"CKM_SHA256_RSA_PKCS_PSS"); break;
	case CKM_SHA384_RSA_PKCS_PSS      : strcpy(strMeka,"CKM_SHA384_RSA_PKCS_PSS"); break;
	case CKM_SHA512_RSA_PKCS_PSS      : strcpy(strMeka,"CKM_SHA512_RSA_PKCS_PSS"); break;
	case CKM_RC2_KEY_GEN              : strcpy(strMeka,"CKM_RC2_KEY_GEN"); break;
	case CKM_RC2_ECB                  : strcpy(strMeka,"CKM_RC2_ECB"); break;
	case CKM_RC2_CBC                  : strcpy(strMeka,"CKM_RC2_CBC"); break;
	case CKM_RC2_MAC                  : strcpy(strMeka,"CKM_RC2_MAC"); break;
	case CKM_RC2_MAC_GENERAL          : strcpy(strMeka,"CKM_RC2_MAC_GENERAL"); break;
	case CKM_RC2_CBC_PAD              : strcpy(strMeka,"CKM_RC2_CBC_PAD"); break;
	case CKM_RC4_KEY_GEN              : strcpy(strMeka,"CKM_RC4_KEY_GEN"); break;
	case CKM_RC4                      : strcpy(strMeka,"CKM_RC4"); break;
	case CKM_DES_KEY_GEN              : strcpy(strMeka,"CKM_DES_KEY_GEN"); break;
	case CKM_DES_ECB                  : strcpy(strMeka,"CKM_DES_ECB"); break;
	case CKM_DES_CBC                  : strcpy(strMeka,"CKM_DES_CBC"); break;
	case CKM_DES_MAC                  : strcpy(strMeka,"CKM_DES_MAC"); break;
	case CKM_DES_MAC_GENERAL          : strcpy(strMeka,"CKM_DES_MAC_GENERAL"); break;
	case CKM_DES_CBC_PAD              : strcpy(strMeka,"CKM_DES_CBC_PAD"); break;
	case CKM_DES2_KEY_GEN             : strcpy(strMeka,"CKM_DES2_KEY_GEN"); break;
	case CKM_DES3_KEY_GEN             : strcpy(strMeka,"CKM_DES3_KEY_GEN"); break;
	case CKM_DES3_ECB                 : strcpy(strMeka,"CKM_DES3_ECB"); break;
	case CKM_DES3_CBC                 : strcpy(strMeka,"CKM_DES3_CBC"); break;
	case CKM_DES3_MAC                 : strcpy(strMeka,"CKM_DES3_MAC"); break;
	case CKM_DES3_MAC_GENERAL         : strcpy(strMeka,"CKM_DES3_MAC_GENERAL"); break;
	case CKM_DES3_CBC_PAD             : strcpy(strMeka,"CKM_DES3_CBC_PAD"); break;
	case CKM_CDMF_KEY_GEN             : strcpy(strMeka,"CKM_CDMF_KEY_GEN"); break;
	case CKM_CDMF_ECB                 : strcpy(strMeka,"CKM_CDMF_ECB"); break;
	case CKM_CDMF_CBC                 : strcpy(strMeka,"CKM_CDMF_CBC"); break;
	case CKM_CDMF_MAC                 : strcpy(strMeka,"CKM_CDMF_MAC"); break;
	case CKM_CDMF_MAC_GENERAL         : strcpy(strMeka,"CKM_CDMF_MAC_GENERAL"); break;
	case CKM_CDMF_CBC_PAD             : strcpy(strMeka,"CKM_CDMF_CBC_PAD"); break;
	case CKM_MD2                      : strcpy(strMeka,"CKM_MD2"); break;
	case CKM_MD2_HMAC                 : strcpy(strMeka,"CKM_MD2_HMAC"); break;
	case CKM_MD2_HMAC_GENERAL         : strcpy(strMeka,"CKM_MD2_HMAC_GENERAL"); break;
	case CKM_MD5                      : strcpy(strMeka,"CKM_MD5"); break;
	case CKM_MD5_HMAC                 : strcpy(strMeka,"CKM_MD5_HMAC"); break;
	case CKM_MD5_HMAC_GENERAL         : strcpy(strMeka,"CKM_MD5_HMAC_GENERAL"); break;
	case CKM_SHA_1                    : strcpy(strMeka,"CKM_SHA_1"); break;
	case CKM_SHA_1_HMAC               : strcpy(strMeka,"CKM_SHA_1_HMAC"); break;
	case CKM_SHA_1_HMAC_GENERAL       : strcpy(strMeka,"CKM_SHA_1_HMAC_GENERAL "); break;
	case CKM_RIPEMD128                : strcpy(strMeka,"CKM_RIPEMD128"); break;
	case CKM_RIPEMD128_HMAC           : strcpy(strMeka,"CKM_RIPEMD128_HMAC"); break;
	case CKM_RIPEMD128_HMAC_GENERAL   : strcpy(strMeka,"CKM_RIPEMD128_HMAC_GENERAL"); break;
	case CKM_RIPEMD160                : strcpy(strMeka,"CKM_RIPEMD160"); break;
	case CKM_RIPEMD160_HMAC           : strcpy(strMeka,"CKM_RIPEMD160_HMAC"); break;
	case CKM_RIPEMD160_HMAC_GENERAL	  : strcpy(strMeka,"CKM_RIPEMD160_HMAC_GENERAL"); break;
	case CKM_SHA256                   : strcpy(strMeka,"CKM_SHA256"); break;
	case CKM_SHA256_HMAC              : strcpy(strMeka,"CKM_SHA256_HMAC"); break;
	case CKM_SHA256_HMAC_GENERAL      : strcpy(strMeka,"CKM_SHA256_HMAC_GENERAL"); break;
	case CKM_SHA384                   : strcpy(strMeka,"CKM_SHA384"); break;
	case CKM_SHA384_HMAC              : strcpy(strMeka,"CKM_SHA384_HMAC"); break;
	case CKM_SHA384_HMAC_GENERAL      : strcpy(strMeka,"CKM_SHA384_HMAC_GENERAL"); break;
	case CKM_SHA512                   : strcpy(strMeka,"CKM_SHA512"); break;
	case CKM_SHA512_HMAC              : strcpy(strMeka,"CKM_SHA512_HMAC"); break;
	case CKM_SHA512_HMAC_GENERAL      : strcpy(strMeka,"CKM_SHA512_HMAC_GENERAL"); break;
	case CKM_CAST_KEY_GEN             : strcpy(strMeka,"CKM_CAST_KEY_GEN"); break;
	case CKM_CAST_ECB                 : strcpy(strMeka,"CKM_CAST_ECB"); break;
	case CKM_CAST_CBC                 : strcpy(strMeka,"CKM_CAST_CBC"); break;
	case CKM_CAST_MAC                 : strcpy(strMeka,"CKM_CAST_MAC"); break;
	case CKM_CAST_MAC_GENERAL         : strcpy(strMeka,"CKM_CAST_MAC_GENERAL"); break;
	case CKM_CAST_CBC_PAD             : strcpy(strMeka,"CKM_CAST_CBC_PAD"); break;
	case CKM_CAST3_KEY_GEN            : strcpy(strMeka,"CKM_CAST3_KEY_GEN"); break;
	case CKM_CAST3_ECB                : strcpy(strMeka,"CKM_CAST3_ECB"); break;
	case CKM_CAST3_CBC                : strcpy(strMeka,"CKM_CAST3_CBC"); break;
	case CKM_CAST3_MAC                : strcpy(strMeka,"CKM_CAST3_MAC"); break;
	case CKM_CAST3_MAC_GENERAL        : strcpy(strMeka,"CKM_CAST3_MAC_GENERAL"); break;
	case CKM_CAST3_CBC_PAD            : strcpy(strMeka,"CKM_CAST3_CBC_PAD    "); break;
	case CKM_CAST5_KEY_GEN            : strcpy(strMeka,"CKM_CAST5_KEY_GEN OR CKM_CAST128_KEY_GEN"); break;
	case CKM_CAST5_ECB                : strcpy(strMeka,"CKM_CAST5_ECB OR CKM_CAST128_ECB"); break;
	case CKM_CAST5_CBC                : strcpy(strMeka,"CKM_CAST5_CBC OR CKM_CAST128_CBC"); break;
	case CKM_CAST5_MAC                : strcpy(strMeka,"CKM_CAST5_MAC OR CKM_CAST128_MAC"); break;
	case CKM_CAST5_MAC_GENERAL        : strcpy(strMeka,"CKM_CAST5_MAC_GENERAL OR CKM_CAST128_MAC_GENERAL"); break;
	case CKM_CAST5_CBC_PAD            : strcpy(strMeka,"CKM_CAST5_CBC_PAD OR CKM_CAST128_CBC_PAD"); break;
	case CKM_RC5_KEY_GEN              : strcpy(strMeka,"CKM_RC5_KEY_GEN               "); break;
	case CKM_RC5_ECB                  : strcpy(strMeka,"CKM_RC5_ECB"); break;
	case CKM_RC5_CBC                  : strcpy(strMeka,"CKM_RC5_CBC"); break;
	case CKM_RC5_MAC                  : strcpy(strMeka,"CKM_RC5_MAC"); break;
	case CKM_RC5_MAC_GENERAL          : strcpy(strMeka,"CKM_RC5_MAC_GENERAL"); break;
	case CKM_RC5_CBC_PAD              : strcpy(strMeka,"CKM_RC5_CBC_PAD"); break;
	case CKM_IDEA_KEY_GEN             : strcpy(strMeka,"CKM_IDEA_KEY_GEN"); break;
	case CKM_IDEA_ECB                 : strcpy(strMeka,"CKM_IDEA_ECB"); break;
	case CKM_IDEA_CBC                 : strcpy(strMeka,"CKM_IDEA_CBC"); break;
	case CKM_IDEA_MAC                 : strcpy(strMeka,"CKM_IDEA_MAC"); break;
	case CKM_IDEA_MAC_GENERAL         : strcpy(strMeka,"CKM_IDEA_MAC_GENERAL"); break;
	case CKM_IDEA_CBC_PAD             : strcpy(strMeka,"CKM_IDEA_CBC_PAD"); break;
	case CKM_GENERIC_SECRET_KEY_GEN   : strcpy(strMeka,"CKM_GENERIC_SECRET_KEY_GEN"); break;
	case CKM_CONCATENATE_BASE_AND_KEY : strcpy(strMeka,"CKM_CONCATENATE_BASE_AND_KEY"); break;
	case CKM_CONCATENATE_BASE_AND_DATA: strcpy(strMeka,"CKM_CONCATENATE_BASE_AND_DATA"); break;
	case CKM_CONCATENATE_DATA_AND_BASE: strcpy(strMeka,"CKM_CONCATENATE_DATA_AND_BASE"); break;
	case CKM_XOR_BASE_AND_DATA        : strcpy(strMeka,"CKM_XOR_BASE_AND_DATA"); break;
	case CKM_EXTRACT_KEY_FROM_KEY     : strcpy(strMeka,"CKM_EXTRACT_KEY_FROM_KEY"); break;
	case CKM_SSL3_PRE_MASTER_KEY_GEN  : strcpy(strMeka,"CKM_SSL3_PRE_MASTER_KEY_GEN"); break;
	case CKM_SSL3_MASTER_KEY_DERIVE	  : strcpy(strMeka,"CKM_SSL3_MASTER_KEY_DERIVE"); break;
	case CKM_SSL3_KEY_AND_MAC_DERIVE  : strcpy(strMeka,"CKM_SSL3_KEY_AND_MAC_DERIVE"); break;
	case CKM_SSL3_MASTER_KEY_DERIVE_DH: strcpy(strMeka,"CKM_SSL3_MASTER_KEY_DERIVE_DH"); break;
	case CKM_TLS_PRE_MASTER_KEY_GEN	  : strcpy(strMeka,"CKM_TLS_PRE_MASTER_KEY_GEN"); break;
	case CKM_TLS_MASTER_KEY_DERIVE	  : strcpy(strMeka,"CKM_TLS_MASTER_KEY_DERIVE"); break;
	case CKM_TLS_KEY_AND_MAC_DERIVE	  : strcpy(strMeka,"CKM_TLS_KEY_AND_MAC_DERIVE"); break;
	case CKM_TLS_MASTER_KEY_DERIVE_DH : strcpy(strMeka,"CKM_TLS_MASTER_KEY_DERIVE_DH"); break;
	case CKM_SSL3_MD5_MAC		      : strcpy(strMeka,"CKM_SSL3_MD5_MAC"); break;
	case CKM_SSL3_SHA1_MAC		      : strcpy(strMeka,"CKM_SSL3_SHA1_MAC"); break;
	case CKM_MD5_KEY_DERIVATION       : strcpy(strMeka,"CKM_MD5_KEY_DERIVATION"); break;
	case CKM_MD2_KEY_DERIVATION       : strcpy(strMeka,"CKM_MD2_KEY_DERIVATION"); break;
	case CKM_SHA1_KEY_DERIVATION      : strcpy(strMeka,"CKM_SHA1_KEY_DERIVATION"); break;
	case CKM_PBE_MD2_DES_CBC          : strcpy(strMeka,"CKM_PBE_MD2_DES_CBC"); break;
	case CKM_PBE_MD5_DES_CBC          : strcpy(strMeka,"CKM_PBE_MD5_DES_CBC"); break;
	case CKM_PBE_MD5_CAST_CBC         : strcpy(strMeka,"CKM_PBE_MD5_CAST_CBC"); break;
	case CKM_PBE_MD5_CAST3_CBC        : strcpy(strMeka,"CKM_PBE_MD5_CAST3_CBC"); break;
	case CKM_PBE_MD5_CAST5_CBC        : strcpy(strMeka,"CKM_PBE_MD5_CAST5_CBC OR CKM_PBE_MD5_CAST128_CBC"); break;
	case CKM_PBE_SHA1_CAST5_CBC       : strcpy(strMeka,"CKM_PBE_SHA1_CAST5_CBC OR CKM_PBE_SHA1_CAST128_CBC"); break;
	case CKM_PBE_SHA1_RC4_128         : strcpy(strMeka,"CKM_PBE_SHA1_RC4_128"); break;
	case CKM_PBE_SHA1_RC4_40          : strcpy(strMeka,"CKM_PBE_SHA1_RC4_40"); break;
	case CKM_PBE_SHA1_DES3_EDE_CBC    : strcpy(strMeka,"CKM_PBE_SHA1_DES3_EDE_CBC"); break;
	case CKM_PBE_SHA1_DES2_EDE_CBC    : strcpy(strMeka,"CKM_PBE_SHA1_DES2_EDE_CBC"); break;
	case CKM_PBE_SHA1_RC2_128_CBC     : strcpy(strMeka,"CKM_PBE_SHA1_RC2_128_CBC"); break;
	case CKM_PBE_SHA1_RC2_40_CBC      : strcpy(strMeka,"CKM_PBE_SHA1_RC2_40_CBC"); break;
	case CKM_PKCS5_PBKD2              : strcpy(strMeka,"CKM_PKCS5_PBKD2"); break;
	case CKM_PBA_SHA1_WITH_SHA1_HMAC  : strcpy(strMeka,"CKM_PBA_SHA1_WITH_SHA1_HMAC"); break;
	case CKM_KEY_WRAP_LYNKS           : strcpy(strMeka,"CKM_KEY_WRAP_LYNKS"); break;
	case CKM_KEY_WRAP_SET_OAEP		  : strcpy(strMeka,"CKM_KEY_WRAP_SET_OAEP"); break;
	case CKM_SKIPJACK_KEY_GEN		  : strcpy(strMeka,"CKM_SKIPJACK_KEY_GEN"); break;
	case CKM_SKIPJACK_ECB64		      : strcpy(strMeka,"CKM_SKIPJACK_ECB64"); break;
	case CKM_SKIPJACK_CBC64	          : strcpy(strMeka,"CKM_SKIPJACK_CBC64"); break;
	case CKM_SKIPJACK_OFB64	          : strcpy(strMeka,"CKM_SKIPJACK_OFB64"); break;
	case CKM_SKIPJACK_CFB64	          : strcpy(strMeka,"CKM_SKIPJACK_CFB64"); break;
	case CKM_SKIPJACK_CFB32	          : strcpy(strMeka,"CKM_SKIPJACK_CFB32"); break;
	case CKM_SKIPJACK_CFB16	          : strcpy(strMeka,"CKM_SKIPJACK_CFB16"); break;
	case CKM_SKIPJACK_CFB8	          : strcpy(strMeka,"CKM_SKIPJACK_CFB8"); break;
	case CKM_SKIPJACK_WRAP	          : strcpy(strMeka,"CKM_SKIPJACK_WRAP"); break;
	case CKM_SKIPJACK_PRIVATE_WRAP	  : strcpy(strMeka,"CKM_SKIPJACK_PRIVATE_WRAP"); break;
	case CKM_SKIPJACK_RELAYX		  : strcpy(strMeka,"CKM_SKIPJACK_RELAYX"); break;
	case CKM_KEA_KEY_PAIR_GEN		  : strcpy(strMeka,"CKM_KEA_KEY_PAIR_GEN"); break;
	case CKM_KEA_KEY_DERIVE		      : strcpy(strMeka,"CKM_KEA_KEY_DERIVE"); break;
	case CKM_FORTEZZA_TIMESTAMP		  : strcpy(strMeka,"CKM_FORTEZZA_TIMESTAMP"); break;
	case CKM_BATON_KEY_GEN		      : strcpy(strMeka,"CKM_BATON_KEY_GEN"); break;
	case CKM_BATON_ECB128		      : strcpy(strMeka,"CKM_BATON_ECB128"); break;
	case CKM_BATON_ECB96			  : strcpy(strMeka,"CKM_BATON_ECB96	"); break;
	case CKM_BATON_CBC128		      : strcpy(strMeka,"CKM_BATON_CBC128"); break;
	case CKM_BATON_COUNTER		      : strcpy(strMeka,"CKM_BATON_COUNTER"); break;
	case CKM_BATON_SHUFFLE		      : strcpy(strMeka,"CKM_BATON_SHUFFLE"); break;
	case CKM_BATON_WRAP			      : strcpy(strMeka,"CKM_BATON_WRAP"); break;
	case CKM_ECDSA_KEY_PAIR_GEN		  : strcpy(strMeka,"CKM_ECDSA_KEY_PAIR_GEN OR CKM_EC_KEY_PAIR_GEN"); break;
	case CKM_ECDSA			          : strcpy(strMeka,"CKM_ECDSA"); break;
	case CKM_ECDSA_SHA1			      : strcpy(strMeka,"CKM_ECDSA_SHA1"); break;
	case CKM_ECDH1_DERIVE		      : strcpy(strMeka,"CKM_ECDH1_DERIVE"); break;
	case CKM_ECDH1_COFACTOR_DERIVE	  : strcpy(strMeka,"CKM_ECDH1_COFACTOR_DERIVE"); break;
	case CKM_ECMQV_DERIVE		      : strcpy(strMeka,"CKM_ECMQV_DERIVE"); break;
	case CKM_JUNIPER_KEY_GEN		  : strcpy(strMeka,"CKM_JUNIPER_KEY_GEN"); break;
	case CKM_JUNIPER_ECB128		      : strcpy(strMeka,"CKM_JUNIPER_ECB128"); break;
	case CKM_JUNIPER_CBC128		      : strcpy(strMeka,"CKM_JUNIPER_CBC128"); break;
	case CKM_JUNIPER_COUNTER		  : strcpy(strMeka,"CKM_JUNIPER_COUNTER"); break;
	case CKM_JUNIPER_SHUFFLE		  : strcpy(strMeka,"CKM_JUNIPER_SHUFFLE"); break;
	case CKM_JUNIPER_WRAP		      : strcpy(strMeka,"CKM_JUNIPER_WRAP"); break;
	case CKM_FASTHASH			      : strcpy(strMeka,"CKM_FASTHASH"); break;
	case CKM_AES_KEY_GEN			  : strcpy(strMeka,"CKM_AES_KEY_GEN"); break;
	case CKM_AES_ECB			      : strcpy(strMeka,"CKM_AES_ECB"); break;
	case CKM_AES_CBC			      : strcpy(strMeka,"CKM_AES_CBC"); break;
	case CKM_AES_MAC			      : strcpy(strMeka,"CKM_AES_MAC"); break;
	case CKM_AES_MAC_GENERAL		  : strcpy(strMeka,"CKM_AES_MAC_GENERAL"); break;
	case CKM_AES_CBC_PAD              : strcpy(strMeka,"CKM_AES_CBC_PAD"); break;
	case CKM_GOSTR3410_KEY_PAIR_GEN   : strcpy(strMeka,"CKM_GOSTR3410_KEY_PAIR_GEN"); break;
	case CKM_GOSTR3410                : strcpy(strMeka,"CKM_GOSTR3410"); break;
	case CKM_GOSTR3410_WITH_GOSTR3411 : strcpy(strMeka,"CKM_GOSTR3410_WITH_GOSTR3411"); break;
	case CKM_GOSTR3411                : strcpy(strMeka,"CKM_GOSTR3411"); break;
	case CKM_DSA_PARAMETER_GEN        : strcpy(strMeka,"CKM_DSA_PARAMETER_GEN"); break;
	case CKM_DH_PKCS_PARAMETER_GEN    : strcpy(strMeka,"CKM_DH_PKCS_PARAMETER_GEN"); break;
	case CKM_X9_42_DH_PARAMETER_GEN   : strcpy(strMeka,"CKM_X9_42_DH_PARAMETER_GEN"); break;
	default                           : strcpy(strMeka,"CKM_VENDOR_DEFINED"); break;
	}
	return strMeka;
}

unsigned char testAll(unsigned char * pin) {
	return 0;
}

unsigned short getIndexDebutSectionTests(int searchedTestLevel) {
	int indice = 0;
	CK_BBOOL trouve = CK_FALSE;
	size_t sTailleTableau = sizeof(MsgsTbl)/sizeof(MsgsTbl[0]);

	while( !trouve && indice < (int)sTailleTableau) {
		if ( MsgsTbl[indice].TestLevel == searchedTestLevel )
			trouve = CK_TRUE;
		else
			indice++;
	}

	if (!trouve)
		return (unsigned short)-1;

	return (unsigned short)indice;
}

void checkPrintResult(char * mesgTest, CK_RV rv, int testNumber, sTESTS_MSGS * table)
{
  char fullMessage[1024];
  char errorCode[50];
  int testID, testOK;
  size_t offset;

  testID = table[testNumber].TestLevel;

  testOK=SAVE_RESULT(table, testNumber, rv);

  sprintf(fullMessage, "%03d : ", testID);
  strcat(fullMessage, mesgTest);

  offset = strlen(fullMessage);

  sprintf(fullMessage + offset, " - %s\n", testOK == 0 ? "OK" : getErrorCodeString(rv,errorCode));

  printf(fullMessage);
}
