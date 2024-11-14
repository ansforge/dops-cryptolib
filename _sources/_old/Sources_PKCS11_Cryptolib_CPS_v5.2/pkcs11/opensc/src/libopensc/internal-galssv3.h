/*
* internal-galss.h: Reader driver for GALSS version 3 interface
*
* Copyright (C) 2010-2016, ASIP Santé
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __INTERNAL_GALSS_V3_H
#define __INTERNAL_GALSS_V3_H

#define MAX_APP_NAME 16

/* Etat de la carte */
#define LEC_CARTE_ABSENTE      0x0000
#define LEC_CARTE_HORS_TENSION 0x0001
#define LEC_CARTE_SOUS_TENSION 0x0003

#define LEC_CMD_APPLI             0x00

/* pour la mise sous tension de la carte */
#define LEC_CMD_MISE_TENSION_CARTE 0x14
#define LEC_LG_QUESTION_TENSION    0x03
#define LEC_LG_REPONSE_TENSION     0x03
#define LEC_TEMPS_EXEC_TENSION     0x07

/* pour le retrait et mise hors tension de la carte*/
#define LEC_CMD_RETRAIT_CARTE      0x15
#define LEC_LG_QUESTION_RETRAIT    0x04
#define LEC_LG_REPONSE_RETRAIT     0x03
#define LEC_TEMPS_EXEC_RETRAIT     0x07 

/* pour l'instruction carte */
#define LEC_CMD_ORDRE_ENTRANT       0x00
#define LEC_CMD_ORDRE_SORTANT       0x01  
#define LEC_CMD_ORDRE_ENTSORTANT    0x02  
#define LEC_LG_QUESTION_INSTRUCTION 0x04
#define LEC_LG_REPONSE_INSTRUCTION  0x03 
#define LEC_LG_QUESTION_INS_CARTE   0x05
#define LEC_LG_REPONSE_INS_CARTE    0x02
#define LEC_TEMPS_EXEC_INSTRUCTION  0x20

#define LEC_CMD_PRESENCE_CARTE      0x16
#define LEC_LG_REQ_PRESENCE         0x03
#define LEC_LG_REP_PRESENCE         0x03
#define LEC_TEMPS_EXEC_PRESENCE     0xFF



/* CPS 2/2bis/2ter/3 Card Op Code */ 
#define CPS_OpSelect                  0xA4
#define CPS_OpStatus                  0xF2
#define CPS_OpDir                     0xA8
#define CPS_OpCreateFile              0xE0
#define CPS_OpDeleteFile              0xD4
#define CPS_OpInvalidate              0x04
#define CPS_OpRehabilitate            0x44
#define CPS_OpAskRandom               0x84
#define CPS_OpExternalAuthentication  0x82
#define CPS_OpInternalAuthentication  0x88
#define CPS_OpDiversifie              0x10
#define CPS_OpGetResponse             0xC0
#define CPS_OpLock                    0x76
#define CPS_OpUpdateBinary            0xD6
#define CPS_OpWriteBinary             0xD0
#define CPS_OpReadBinary              0xB0
#define CPS_OpGiveRandom              0x86
#define CPS_OpReadBinaryStamped       0xB4
#define CPS_OpLoadKeyFile             0xD8
#define CPS_OpVerifyCHV               0x20
#define CPS_OpChangeCHV               0x24
#define CPS_OpUnblockCHV              0x2C
#define CPS_OpCertifie                0x5C
#define CPS_OpAuthenIntExt            0x50
#define CPS_OpAuthenExt               0x4E
#define CPS_OpSignIntExt              0x52
#define CPS_OpSignExt                 0x5E
#define CPS_OpRSAVerifie              0x58
#define CPS_OpCompare                 0x5A
#define CPS_OpGenerateSessionKey      0x46
#define CPS_OpEncipherSessionKey      0x48
#define CPS_OpDecipherSessionKey      0x4A
#define CPS_OpRecoverSessionKey       0x4C
#define CPS_OpLockEXE                 0xF6
#define CPS_OpLoadEXE                 0xF4
#define CPS_OpCalculRSA               0x3E
#define IAS_SetSecEnv                 0x22
#define IAS_PSODST                    0x2A
#define IAS_GetDataSDO                0xCB


#define MAX_RES_SIZE    8
#define MAX_RESOURCES   255



typedef struct iso_cmd
{
  BYTE clazz;
  BYTE inst;
  BYTE p1;
  BYTE p2;
  BYTE len;
  BYTE data[260];
}iso_cmd;

#define         VERSION_SIZE        4

typedef struct {
  UINT        TypeComposant;
  CHAR        AscVersion[VERSION_SIZE];
} IdentComposant, *LPIdentComposant;




#ifndef __MACOSDEF_H
#pragma pack(1)
#endif

typedef struct _INFO_RESSOURCE {
  BYTE    NomAlias[MAX_RES_SIZE + 1];
  BYTE    NomRessource[MAX_RES_SIZE + 1];
  BYTE    AdrLAD;
  BYTE    AdrPAD;
  BYTE    IndexCanal;
  BYTE    TypeCanal;
  USHORT  TypeConnexion;
  USHORT  Protocole;
} InfoRessource,*LPInfoRessource;

#ifndef __MACOSDEF_H
#pragma pack()
#endif


/* Codes d'erreur des commandes carte -------------------- */
    /* - Erreurs generales*/ 
#define CMD_ERROR_OK                        0x00
#define CMD_ERROR_APP_INCONNU               0x01
#define CMD_ERROR_CMD_INCONNU               0x02
#define CMD_ERROR_CMD_REFUSE                0x03
#define CMD_ERROR_REINIT                    0x04
#define CMD_ERROR_ABANDON_TEMPS             0x05
#define CMD_ERROR_ABANDON_RECEPTION         0x06
#define CMD_ERROR_ABANDON_ENVOI             0x07
#define CMD_ERROR_MATERIELLE                0x08
    /* - Erreur mise sous tension de la carte */
#define CMD_ERROR_CARTE_PAS_SUPPORTEE       0x10
#define CMD_ERROR_CARTE_MUETTE              0x11
    /* - Erreur mise hors tension/retrait de la carte */
#define CMD_ERROR_CARTE_ENCORE_PRESENTE     0x12
    /* - Erreur sur instruction entrante */
#define CMD_ERROR_COMPTEUR                  0x16
#define CMD_ERROR_CARTE_ABSENTE             0x17
#define CMD_ERROR_INSTRUCTION_INCOHERENTE   0x13
    /* - Erreur sur configuration frequence carte */
#define CMD_ERROR_NON_EXECUTION             0x14
#define CMD_ERROR_VALEUR_PAS_ACCEPETE       0x15

#define CMD_ERROR_INVALID_PARAMETER         0x6F
#define CMD_ERROR_NO_MEMORY                 0x6E
#define CMD_ERROR_CARTE_HORS_TENSION        0x6D
#define CMD_ERROR_TRANSMISSION              0x6C
#define CMD_ERROR_PAS_SERVICE               0x6B

#define GALSS_SERIAL_READER "PSS Reader on "

#define GALSSV3_VERSION      3


// GALSS CLIENT
typedef USHORT (API_ENTRY_PTR OuvrirSession_t)(LPSTR pcNomApplication, LPSTR pcNomRessource, PUSHORT pusNumSession, LPBYTE pusNumRessource);
typedef USHORT (API_ENTRY_PTR FermerSession_t)(USHORT usNumSession, PUSHORT pusNumExclusivite);
typedef USHORT (API_ENTRY_PTR DebutExclusivite_t)(LPSTR pcQuestion, LPSTR pcNomApplication, LPSTR pcNomRessource, PUSHORT pusNumExclusivite);
typedef USHORT (API_ENTRY_PTR FinExclusivite_t)(USHORT usNumExclusivite);
typedef USHORT (API_ENTRY_PTR EcritContexte_t)(USHORT usOrdre, USHORT usNumSession, LPVOID pvfContexte, PUSHORT pusTailleCtx);
typedef USHORT (API_ENTRY_PTR LitContexte_t)(USHORT usOrdre, USHORT usNumSession, LPVOID pvfContexte, PUSHORT pusTailleCtx);
typedef USHORT (API_ENTRY_PTR Echange_t)(USHORT usNumSession, USHORT usTempsExe, LPSTR Message, LPUINT TailleBuff, LPSTR MsgReponse, LPUINT TailleReponse);
typedef USHORT (API_ENTRY_PTR LireVersion_t)(LPSTR VersionGALSS, PUSHORT pusNbComposants, LPIdentComposant pComposants);

// GALSS INFO
typedef USHORT (API_ENTRY_PTR TInf_DonneNombreRessources) (PUSHORT pusNbRessources);
typedef USHORT (API_ENTRY_PTR TInf_DonneTableRessources) (LPInfoRessource pInfoRessources, PUSHORT pusNbRessources);



#endif // __INTERNAL_GALSS_V3_H
