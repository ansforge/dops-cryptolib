/*
 * reader-galss.c: Reader driver for GALSS version 3 interface
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

#include "internal.h"

#ifdef ENABLE_GALSS
#include "sysdef.h"
#ifdef _WIN32
#define SYS_MAX_PATH MAX_PATH
#endif
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "internal-galssv3.h"
#include "gal_err.h"

 /* Error printing */
#define GALSS_ERROR(ctx, desc, rv) sc_error(ctx, desc ": 0x%08lx\n", rv);

#define GET_PRIV_DATA(r) ((struct galss_private_data *) (r)->drv_data)
#define GET_SLOT_DATA(r) ((struct galss_slot_data *) (r)->drv_data)

#define CLEAR_MEM(p,s) if (p!=NULL){sc_mem_clear(p,(size_t)s); free(p); p=NULL; }

#define CPS_MAX_COMPOSANTS    16
#define EXCLUSIVITY_WAIT      25000 // (25 sec)
#define EXCLUSIVITY_SLEEP     100   // ms
#define EXCLUSIVITY_INTERVAL  (EXCLUSIVITY_WAIT/EXCLUSIVITY_SLEEP)

VOID galss_update_state(PUSHORT state, USHORT new_state);

#define STR_CARD_ON   "CARD|POWER_ON"
#define STR_CARD_OFF  "CARD|POWER_OFF"
#define STR_NO_CARD   "NO_CARD"


/* AROC 19-01-2012 : Gestion du context cps : Debut */
/* AROC (@@20121108) – rajout du pragma pack pour Windows : Debut */
#ifdef _WIN32
#pragma pack(push,1)
#endif
/* AROC (@@20121108) – rajout du pragma pack pour Windows : Fin */
typedef struct cps_contexte_infos {
  BYTE IIN[5];         /* Identifiant du responsable qui alloue les tags */
  BYTE PIX[2];         /* Identifiant du document de codification des tags */
  BYTE REV_PIX[2];     /* Pix Revision */
  BYTE Filler[991];    /* Filler */
} cps_contexte_infos;

typedef struct cps_contexte {
  CHAR               Denomination[9];      /* 8 caracteres maximum, termines par NULL */
  USHORT             Lg;                   /* longueur totale du contexte */
  USHORT             NumVersionAPIs;       /* numero de versions des APIs */
  USHORT             NumAPI;               /* numero de la derniere API activee */
  USHORT             NumLad;               /* numéro de coupleur (lecteur transparent) */
  USHORT             EtatCarte;            /* etat de la carte CPS (voir jeu de commandes) */
  USHORT             Cpt;                  /* compteur d’etat (voir jeu de commandes) */
  USHORT             LgATR;                /* longeur de la réponse au RESET de la carte */
  BYTE               ATR[50];              /* reponse au RESET de la carte (50 octets maximum) */
  USHORT             LgInfo;               /* longueur des information utiles de la zone info */
  cps_contexte_infos Info;                 /* informations (lg= MAX_LGINFO = 1000) */
} cps_context;

/* AROC (@@20121108) – rajout du pragma pack pour Windows : Debut */
#ifdef _WIN32
#pragma pack(pop)
#endif
/* AROC (@@20121108) – rajout du pragma pack pour Windows : Fin */
/* AROC 19-01-2012 : Gestion du context cps : Fin */

struct galss_global_private_data {
  USHORT galss_ctx;         // Context residuel inutiliser
  INT enable_pinpad;                // Toujours a zero.
  INT connect_exclusive;            // Toujours en exclusif
  INT connect_reset;                // Reset à la deconnection [non]
  INT polling_time;                 // 2000ms
  INT transaction_reset;            // ??? utilite non identifiee
  INT disconnected_reader;          // Faut-il activer les lecteurs deconnectes
  LPCSTR provider_library_cli; // Nom de la librairie Galss Cli
  lt_dlhandle dlhandleCli;          // Handle de la librairie Galss Cli
  OuvrirSession_t OuvrirSession;
  FermerSession_t FermerSession;
  DebutExclusivite_t DebutExclusivite;
  FinExclusivite_t FinExclusivite;
  EcritContexte_t EcritContexte;
  LitContexte_t LitContexte;
  Echange_t Echange;
  LireVersion_t LireVersion;
  LPCSTR provider_library_inf; // Nom de la librairie Galss Inf
  lt_dlhandle dlhandleInf;          // Handle de la librairie Galss Inf
  TInf_DonneNombreRessources DonneNbRes;
  TInf_DonneTableRessources DonneTableRes;
  /* AROC 15-05-2014 (@@20140515-1122)- Memorisation de la table des ressources CPS* : Debut */
  USHORT res_count;
  USHORT res_detected;
  InfoRessource Ressources[MAX_RESOURCES];
  /* AROC 15-05-2014 (@@20140515-1122)- Memorisation de la table des ressources CPS* : Fin */
};

struct galss_private_data {
  LPSTR reader_name;
  struct galss_global_private_data *gpriv;
};

struct galss_slot_data {
  CHAR   app_name[MAX_APP_NAME + 1];
  CHAR   res_name[MAX_RES_SIZE + 1];
  USHORT num_session;
  BYTE   num_lad;
  USHORT card_state;
  USHORT num_excl;
  USHORT cpt;
  USHORT cr_galss;
  USHORT cr_reader;
  USHORT cr_card;
  USHORT init;
  time_t last_test_presence;
  INT    locked;
  USHORT cps_ctx_exist; // AROC 19-01-2012 : Gestion du context cps
};
#define is_card_present_sous_tension(x) ((x->card_state&LEC_CARTE_SOUS_TENSION)==LEC_CARTE_SOUS_TENSION)
#define is_card_present(x) ((x->card_state&LEC_CARTE_HORS_TENSION)==LEC_CARTE_HORS_TENSION)
#define is_card_absent(x) ((x->card_state&LEC_CARTE_ABSENTE)==LEC_CARTE_ABSENTE)

static INT galss_detect_card_presence(sc_reader_t *reader, sc_slot_info_t *slot);
static INT i_galss_open_session(sc_reader_t * reader, sc_slot_info_t * slot);
static INT i_galss_close_session(sc_reader_t * reader, sc_slot_info_t * slot);
static INT i_galss_start_excl(sc_reader_t * reader, sc_slot_info_t * slot);
static INT i_galss_end_excl(sc_reader_t * reader, sc_slot_info_t * slot);
static INT i_galss_exchange_msg(sc_reader_t * reader, sc_slot_info_t * slot, USHORT exec_time, LPBYTE msg_in, PUSHORT msg_in_len, LPBYTE msg_out, PUSHORT msg_ou_len);
static INT i_galss_ctx_read(sc_reader_t * reader, sc_slot_info_t * slot, cps_context *pCpsCtx, PUSHORT lpszCpsCtx);
static INT i_galss_ctx_write(sc_reader_t * reader, sc_slot_info_t * slot, cps_context *pCpsCtx, PUSHORT lpszCpsCtx);
static INT reader_galss_power_on(sc_reader_t * reader, sc_slot_info_t * slot);
static INT reader_galss_power_off(sc_reader_t * reader, sc_slot_info_t * slot);
static INT reader_galss_test_presence(sc_reader_t * reader, sc_slot_info_t * slot);
static INT reader_galss_transmit(sc_reader_t * reader, sc_slot_info_t * slot, const u8 *sendbuf, size_t sendsize, u8 *recvbuf, size_t *recvsize, sc_apdu_t *apdu);



/*--------------------------------------------------------------------------
    galss_ret_to_error

Fonction traduisant un code erreur GALSS en un code erreur OpenSC

Parametres:
        rv : code erreur GALSS

Codes retour:
La fonction renvoie le code OpenSC associé

                                         --------------------------------------------------------------------------*/
static int galss_ret_to_error(USHORT rv)
{
  switch (rv)
  {
 //   return SC_ERROR_TRANSMIT_FAILED;

  case G_ERRFICHIERINI:  /* Fichier de configuration non trouve ou endommage */
  case G_ERRGALSSSRV:  /* Module GALSSSRV non trouve */
  case G_ERRRESSOURCE:  /* Nom de ressource inconnue  */
  case G_ERRDIMTABLES:  /* Dimensionnement des tables internes incorrect ( chargement de la table des ressources) */
  case G_ERRNOPROT:  /* Fichier de configuration errone : il manque la rubrique PROTOCOLE */
  case G_ERRBADPROT:  /* Fichier de configuration errone : le PROTOCOLE specifie est inconnu */
  case G_ERRLOADLIBPRO:  /* Fichier de configuration errone : probleme au chargement de la bibliotheque NOMLIB */
  case G_ERRNOINDEX:  /* Fichier de configuration errone : La rubrique INDEX ou TCANAL est absente ou erronee */
  case G_ERRNOCARAC:  /* Fichier de configuration errone : La rubrique CARACTERISTIQUES est absente ou erronee */
  case G_ERRNOPROINIT:  /* Initialisation de la communication avec le lecteur:impossible d'etablir un lien avec la fonction PROInit du Protocole */
  case G_ERRBADPROINIT:  /* Initialisation de la communication avec le lecteur:La fonction PRO_Init du Protocole retourne une erreur */
  case G_ERRNOPROCNX:  /* Connexion avec le lecteur:impossible d'etablir un lien avec la fonction PROConnect du Protocole */
  case G_ERRBADPROCNX:  /* Connexion avec le lecteur:La fonction PROConnect du Protocole retourne une erreur */
  case G_ERRNONBCANAUX:  /* Fichier de configuration errone : il manque la rubrique NBCANAUX */
  case G_ERRCOMPAT:  /* Erreur de compatibilite d'un ou plusieurs composants du GALSS */
  case G_ERRPADINVALID:  /* Numero de PAD invalide */
  case G_ERRLADINVALID:  /* Numero de LAD invalide */
  case G_ERRRESINVALID:  /* Nom de ressource ou d'alias invalide */
    return SC_ERROR_NO_READERS_FOUND;

  case G_ERRTEMPS:  /* Temps alloue pour le traitement depasse  */
  case G_ERRABMAT:  /* ABORT par le materiel (protocole)   */
  case G_ERRABSTA:  /* ABORT par la station  (protocole)    */
    return SC_ERROR_CARD_UNRESPONSIVE;

  case G_ERRTRANS:  /* Erreur transmission, liaison physique  (protocole)   */
  case G_ERREXCL:  /* Exclusivite deja en cours : commande impossible */
  case G_ERREXCLHS:  /* Plus de numero d'exclusivite disponible  */
  case G_ERRCMD:  /* Commande hors sequence   */
  case G_ERRLOG:  /* Anomalie fonctionnement GALSS: erreur logicielle  */
  case G_ERRTAILLE:  /* Taille parametre incorrecte   */
  case G_ERRBLOC:  /* Bloc Inexistant */
  case G_ERROUVERT:  /* session deja ouverte   */
  case G_ERRTIMOUT:  /* TIME OUT, Non reponse materiel distant (protocole) */
  case G_ERREXIST:  /* Exclusivite-Session inconnue          */
  case G_ERRPARAM:  /* Erreur parametre d'appel            */
  case G_ERRLOADFUNCPRO:  /* Impossible d'etablir le lien avec les fonctions d'un protocole */
    return SC_ERROR_READER;

  case G_ERRBADPRODCNX:  /* Deconnexion du lecteur:La fonction PRODisconnect du Protocole retourne une erreur */
  case G_ERRPROTERM:  /* Terminaison du protocole:La fonction PROTerm du Protocole retourne une erreur */
  case G_ERRCTX_GALSSV1:  /* Valeur réservée (ancien GALSS V1) */
    return SC_ERROR_UNKNOWN;


  default:
    return SC_ERROR_UNKNOWN;
  }
}

/*--------------------------------------------------------------------------
     galss_ins_type

Fonction traduisant un code opération CPS en un type d'instruction carte
à utiliser pour l'envoi de la commande
Parametres:
         rv : code opération CPS

Codes retour:
La fonction renvoie l'instruction carte correspondante

--------------------------------------------------------------------------*/
static BYTE galss_ins_type(unsigned char cmd)
{
  switch (cmd) {
  case IAS_GetDataSDO:
    return LEC_CMD_ORDRE_ENTSORTANT;
  case CPS_OpSelect:
  case CPS_OpDir:
  case CPS_OpVerifyCHV:
  case CPS_OpChangeCHV:
  case CPS_OpUnblockCHV:
  case CPS_OpAuthenExt:
  case CPS_OpSignExt:
  case CPS_OpAuthenIntExt:
  case CPS_OpSignIntExt:
  case CPS_OpUpdateBinary:
  case CPS_OpCreateFile:
  case CPS_OpDeleteFile:
  case CPS_OpCalculRSA:
  case CPS_OpInternalAuthentication:
  case IAS_SetSecEnv:
  case IAS_PSODST:
    return LEC_CMD_ORDRE_ENTRANT;
  case CPS_OpGetResponse:
  case CPS_OpReadBinary:
  case CPS_OpStatus:
  case CPS_OpAskRandom:
    return LEC_CMD_ORDRE_SORTANT;
  default:
    return LEC_CMD_ORDRE_SORTANT;
  }
}

/*--------------------------------------------------------------------------
     galss_transmit

Fonction transmettant l'APDU vers la carte présente dans le slot désigné et réceptionnant la réponse

Parametres:
reader               : Pointeur vers l'objet contenant les informations du driver lecteur
slot                 : Pointeur vers l'objet contenant les informations de la carte dans une fente
apdu                 : Pointeur vers l'objet contenant l'apdu à transmettre

Codes retour:
SC_SUCCESS si l'opération s'est bien passée, autres codes OpenSC sinon

--------------------------------------------------------------------------*/
static INT galss_transmit(sc_reader_t *reader, sc_slot_info_t *slot, sc_apdu_t *apdu)
{
  size_t       ssize, rsize, rbuflen = 0;
  LPBYTE        sbuf = NULL, rbuf = NULL;
  INT          r;

  /* we always use a at least 258 byte size big return buffer
  * to mimic the behaviour of the old implementation (some readers
  * seems to require a larger than necessary return buffer).
  * The buffer for the returned data needs to be at least 2 bytes
  * larger than the expected data length to store SW1 and SW2. */
  rsize = rbuflen = apdu->resplen <= 256 ? 258 : apdu->resplen + 2;
  rbuf = malloc(rbuflen);
  if (rbuf == NULL) {
    return SC_ERROR_MEMORY_FAILURE;
  }

  /* encode and log the APDU */
  r = sc_apdu_get_octets(reader->ctx, apdu, &sbuf, &ssize, slot->active_protocol);
  if (r != SC_SUCCESS) {
    CLEAR_MEM(sbuf, ssize);
    CLEAR_MEM(rbuf, rbuflen);
    return r;
  }
  /* MCUG 02/09/2010 : Ajout du cryptage de données sensibles sur la log d'apdu */
  if (reader->ctx->debug >= 6) {
    sc_apdu_log(reader->ctx, apdu, slot->active_protocol);
  }
  /* MCUG 02/09/2010 : Fin */

  //r = galss_internal_transmit(reader, slot, sbuf, ssize, rbuf, &rsize, apdu->control);
  r = reader_galss_transmit(reader, slot, sbuf, ssize, rbuf, &rsize, apdu);
  if (r < 0) {
    /* unable to transmit ... most likely a reader problem */
    sc_error(reader->ctx, "unable to transmit");
    CLEAR_MEM(sbuf, ssize);
    CLEAR_MEM(rbuf, rbuflen);
    return r;
  }

  /* MCUG 02/09/2010 : Ajout du cryptage de données sensibles sur la log d'apdu */
  if (reader->ctx->debug >= 6) {
    sc_apdu_resp_log(reader->ctx, rbuf, rsize);
  }
  /* MCUG 02/09/2010 : Fin */

  /* set response */
  r = sc_apdu_set_resp(reader->ctx, apdu, rbuf, rsize);
  CLEAR_MEM(sbuf, ssize);
  CLEAR_MEM(rbuf, rbuflen);

  return r;
}


/*--------------------------------------------------------------------------
     galss_free_transmit
                        
Fonction transmettant l'APDU vers la carte présente dans le slot désigné et réceptionnant la réponse

Parametres:
reader               : Pointeur vers l'objet contenant les informations du driver lecteur
slot                 : Pointeur vers l'objet contenant les informations de la carte dans une fente
sendbuf              : Pointeur vers le donnees brutes à transmettre à la carte
sendsize             : Taille des donnees à transmettre à la carte
recvbuf              : Pointeur vers le buffer qui recevra la réponse de la carte
recvsize             : Pointeur vers la taille qui recevra la taille réponse de la carte
control              : Valeur permetant d'identifier le type de commande : (entrante ou sortante)

Codes retour:         
SC_SUCCESS si l'opération s'est bien passée, autres codes OpenSC sinon
           
--------------------------------------------------------------------------*/
static int galss_free_transmit(sc_reader_t *reader, sc_slot_info_t *slot,
      const u8 *sendbuf, size_t sendsize, u8 *recvbuf, size_t *recvsize, unsigned char ins_type)
{
  int rc = OK;
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  unsigned short question_len;
  unsigned char *question = NULL;
  unsigned short response_len;
  unsigned char *response = NULL;
  unsigned short copy_len;


  SC_FUNC_CALLED(reader->ctx, 3);
  assert(pslot != NULL);

  pslot->cr_reader=0;

  /* calculs longueurs buffer à envoyer et buffer a recevoir */
  switch(ins_type) {
  case LEC_CMD_ORDRE_ENTRANT:
    question_len = LEC_LG_QUESTION_INSTRUCTION + (int)sendsize;
    response_len = LEC_LG_REPONSE_INSTRUCTION+LEC_LG_REPONSE_INS_CARTE;
    break;
  case LEC_CMD_ORDRE_SORTANT:
    question_len = LEC_LG_QUESTION_INSTRUCTION + LEC_LG_QUESTION_INS_CARTE;
    response_len = LEC_LG_REPONSE_INSTRUCTION+LEC_LG_REPONSE_INS_CARTE+0x100;
    break;
/* AROC : Cas désactivé 
case LEC_CMD_ORDRE_ENTSORTANT:
    ins_type = LEC_CMD_ORDRE_ENTRANT;
    question_len = LEC_LG_QUESTION_INSTRUCTION + LEC_LG_QUESTION_INS_CARTE + apdu->lc;
    if ( apdu->le == 0)
      response_len = LEC_LG_REPONSE_INSTRUCTION+LEC_LG_REPONSE_INS_CARTE+0x100;
    else
      response_len = LEC_LG_REPONSE_INSTRUCTION+LEC_LG_REPONSE_INS_CARTE+apdu->le;
    break;
*/
  default:
    return SC_ERROR_INVALID_ARGUMENTS;
  }


  question = (unsigned char*)calloc(question_len, sizeof(char));
  if ( question == NULL){
    return SC_ERROR_MEMORY_FAILURE;
  }

  response = (unsigned char*)calloc(response_len, sizeof(char));
  if ( response == NULL){
    free(question);
    return SC_ERROR_MEMORY_FAILURE;
  }

  /* Mise en forme de lordre de transmission de donnees */
  question[0]=0x00;           /* Appli */
  question[1]=pslot->num_lad; /* FU */
  question[2]=ins_type;       /* type instruction */
  question[3]=(u8)pslot->cpt; /* CPTR attendu */

  memcpy(&(question[4]), sendbuf, (size_t)(question_len - LEC_LG_QUESTION_INSTRUCTION)); 

  /* Envoyer l'ordre au lecteur a travers le galss */
  sc_debug(reader->ctx, "DRIVER.GALSS : Instruction Carte > IN");
  rc = i_galss_exchange_msg(reader,  slot,
    LEC_TEMPS_EXEC_INSTRUCTION,
    question,
    &question_len,
    response,
    &response_len);
  sc_debug(reader->ctx, "DRIVER.GALSS : Instruction Carte < OUT");
  sc_debug(reader->ctx, "i_galss_exchange_msg rc = 0x%04X", rc);
  /* verification: de la longueur de la reponse ainsi que le contenu de la reponse */
  /* cr du lecteur */                           
  if (rc == OK){
    pslot->cr_reader = response[0];
    sc_debug(reader->ctx, "reader response 0x%04X", pslot->cr_reader);


    switch (response[0])
    {
    case 0:
    case CMD_ERROR_CMD_REFUSE:
    case CMD_ERROR_COMPTEUR:
    case CMD_ERROR_CARTE_MUETTE:
    case CMD_ERROR_CARTE_PAS_SUPPORTEE:
    case CMD_ERROR_CARTE_ABSENTE:
    case CMD_ERROR_INSTRUCTION_INCOHERENTE:
      if (response_len >= LEC_LG_REPONSE_INSTRUCTION){
        galss_update_state(&pslot->card_state, response[1]);
        pslot->cpt = response[2];

        if (response[0] != 0){
          if(response[0] == CMD_ERROR_COMPTEUR) 
            rc = SC_ERROR_CARD_REMOVED; 
          else if(response[0] == CMD_ERROR_CARTE_MUETTE)
            rc = SC_ERROR_CARD_UNRESPONSIVE;
          else if(response[0] == CMD_ERROR_CARTE_PAS_SUPPORTEE)   
            rc = SC_ERROR_INVALID_CARD;
          else if(response[0] == CMD_ERROR_CARTE_ABSENTE)
            rc = SC_ERROR_CARD_REMOVED; 
          else
            rc=SC_ERROR_UNKNOWN;
        }else{   
          /* recopie reponse carte ds buffer appelant */
          copy_len=response_len-LEC_LG_REPONSE_INSTRUCTION;
          if(copy_len){   
            if (*recvsize >= copy_len){
              memcpy(recvbuf,&response[LEC_LG_REPONSE_INSTRUCTION],copy_len);
              *recvsize=copy_len;
            }else
              rc = SC_ERROR_BUFFER_TOO_SMALL;
          }else
            *recvsize=0;     
        }
      }else 
        rc = SC_ERROR_TRANSMIT_FAILED;                
      break;
    default :
      if (response_len == 1)
        rc = SC_ERROR_CARD_CMD_FAILED;
      else
        rc = SC_ERROR_TRANSMIT_FAILED;
      break;
    }
  }else{
    sc_debug(reader->ctx, "Galss transmit error 0x%04X", pslot->cr_galss);
    rc = galss_ret_to_error(pslot->cr_galss);
  }

  free(question);
  free(response);
  return rc;
}

/*
 * Refresh Slot attributes.
 * if a card is present and powered OR if the slot state changed
 * since the last time.
 */
 /*--------------------------------------------------------------------------
      refresh_slot_attributes

 Fonction mettant à jour les informations de la carte présente dans le slot désigné.
 Ouvre une session GALSS si aucun numéro de session dans la structure 'slot'
 Met l'état carte à 'changé' si la carte est présente et déjà sous tension

 Parametres:
 reader               : Pointeur vers l'objet contenant les informations du driver lecteur
 slot                 : Pointeur vers l'objet contenant les informations de la carte dans une fente

 Codes retour:
 SC_SUCCESS si l'opération s'est bien passée, autres codes OpenSC sinon

 --------------------------------------------------------------------------*/
static INT refresh_slot_attributes(sc_reader_t *reader, sc_slot_info_t *slot)
{
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  USHORT rc;
  USHORT saved_cr_galss = 0;
  USHORT old_cpt = 0;
  USHORT old_state = 0;
  cps_context cpsCtx;
  USHORT szCpsCtx = sizeof(cps_context);

  SC_FUNC_CALLED(reader->ctx, 3);

  old_cpt = pslot->cpt;
  old_state = pslot->card_state;
  if (pslot->num_session == 0) {
    i_galss_open_session(reader, slot);
  }

  /* Start an exclusivity on the slot if not already done */
  if (pslot->locked != TRUE) {
    rc = i_galss_start_excl(reader, slot);
    if (rc != OK) {
      return galss_ret_to_error(pslot->cr_galss);
    }
  }

  /* Vérifier la présence du Context Ressources CPS */
  memset(&cpsCtx, 0, sizeof(cps_context));
  i_galss_ctx_read(reader, slot, &cpsCtx, &szCpsCtx);  // AROC 19-01-2012 : Gestion du context cps

  /* Ckeck card presence on the reader */
  rc = reader_galss_test_presence(reader, slot);
  if (rc != OK) {
    saved_cr_galss = pslot->cr_galss;
    /* Release exclusivity only if it was locked into this function */
    if (pslot->locked != TRUE) {
      i_galss_end_excl(reader, slot);
    }
    return galss_ret_to_error(saved_cr_galss);
  }

  /* AROC - 10/11/2015 - Mettre à jour le compteur d'état dans le contexte ressource. (@@20151110-1308) : Debut */
  if (is_card_present_sous_tension(pslot) || old_cpt != pslot->cpt) {
    // Mettre la jour le context ressource cps 
    i_galss_ctx_write(reader, slot, &cpsCtx, &szCpsCtx); // AROC 19-01-2012 : Gestion du context cps
  }
  /* AROC - 10/11/2015 - Mettre à jour le compteur d'état dans le contexte ressource. (@@20151110-1308) : Fin */

  /* If a card is inserted and power on */
  if (is_card_present(pslot)) {
    /* Identify state changes since last time */
    slot->flags |= SC_SLOT_CARD_PRESENT;
    if (!pslot->init && (old_cpt != pslot->cpt || old_state != pslot->card_state)) {
      slot->flags |= SC_SLOT_CARD_CHANGED;
    }
    else {
      slot->flags &= ~SC_SLOT_CARD_CHANGED;
    }
  }
  else
    slot->flags &= ~(SC_SLOT_CARD_PRESENT | SC_SLOT_CARD_CHANGED);

  /* Release exclusivity only if it was locked into this function */
  if (pslot->locked != TRUE) {
    i_galss_end_excl(reader, slot);
  }

  return SC_SUCCESS;
}

/*--------------------------------------------------------------------------
     galss_detect_card_presence

Fonction testant la présence d'une carte dans une fente du lecteur désigné

Parametres:
reader               : Pointeur vers l'objet contenant les informations du driver lecteur
slot                 : Pointeur vers l'objet contenant les informations de la carte dans une fente

Codes retour:
SC_SUCCESS si l'opération s'est bien passée, autres codes OpenSC sinon

--------------------------------------------------------------------------*/
static INT galss_detect_card_presence(sc_reader_t *reader, sc_slot_info_t *slot)
{
  INT rv;

  if ((rv = refresh_slot_attributes(reader, slot)) < 0) {
    if (rv == SC_ERROR_READER) { 
      reader->detected = 0; 
    }
    return rv;
  }
  return slot->flags;
}

/*--------------------------------------------------------------------------
     galss_connect

Fonction réalisant la connexion à une carte dans une fente du lecteur désigné.
Met la carte sous tension si elle ne l'est pas déjà

Parametres:
reader               : Pointeur vers l'objet contenant les informations du driver lecteur
slot                 : Pointeur vers l'objet contenant les informations de la carte dans une fente

Codes retour:
SC_SUCCESS si l'opération s'est bien passée, autres codes OpenSC sinon

--------------------------------------------------------------------------*/
static INT galss_connect(sc_reader_t *reader, sc_slot_info_t *slot)
{
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  USHORT rc;
  int r = SC_SUCCESS;
  cps_context cpsCtx;
  USHORT szCpsCtx = (USHORT)sizeof(cps_context);

  /* Refresh slot attributes */
  r = refresh_slot_attributes(reader, slot);
  if (r) {
    return r;
  }

  if (!is_card_present_sous_tension(pslot)) {
    /* Start an exclusivity on the slot */
    rc = i_galss_start_excl(reader, slot);
    if (rc != OK) return galss_ret_to_error(pslot->cr_galss);

    /* Power On the card */
    rc = reader_galss_power_on(reader, slot);
    if (rc == OK) {
      slot->active_protocol = SC_PROTO_T0;
      sc_debug(reader->ctx, "After connect protocol = %d", slot->active_protocol);

      // Mettre la jour le context ressource cps 
      memset(&cpsCtx, 0, sizeof(cps_context));
      i_galss_ctx_write(reader, slot, &cpsCtx, &szCpsCtx); // AROC 19-01-2012 : Gestion du context cps
    }

    /* Release exclusivity */
    i_galss_end_excl(reader, slot);
  }
  return (r != SC_SUCCESS ? r : SC_SUCCESS);
}

/*
 * Disconnect the card.
 */
 /*--------------------------------------------------------------------------
      galss_disconnect

 Fonction fermant la session GALSS pour se déconncter de la carte dans une fente du lecteur désigné.

 Parametres:
 reader               : Pointeur vers l'objet contenant les informations du driver lecteur
 slot                 : Pointeur vers l'objet contenant les informations de la carte dans une fente

 Codes retour:
 SC_SUCCESS

 --------------------------------------------------------------------------*/
static INT galss_disconnect(sc_reader_t * reader, sc_slot_info_t * slot)
{
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);

  struct galss_private_data *priv = GET_PRIV_DATA(reader);

  /* Power off de la carte */
  if (priv->gpriv->transaction_reset) {
	  int rc = SC_SUCCESS;
	  rc = i_galss_start_excl(reader, slot);
	  if (rc == OK) {
		  reader_galss_power_off(reader, slot);
		  i_galss_end_excl(reader, slot);
	  }
  }

  /* Close Galss session */
  if (pslot->num_session != 0) {
    i_galss_close_session(reader, slot);
  }

  /* Reset the slot */
  pslot->card_state = 0;
  pslot->cpt = 0;
  pslot->cr_card = 0;
  pslot->cr_galss = 0;
  pslot->cr_reader = 0;
  pslot->locked = 0;
  pslot->num_excl = 0;
  pslot->num_lad = 0;
  pslot->num_session = 0;
  pslot->last_test_presence = 0;
  pslot->cps_ctx_exist = 0; // AROC 19-01-2012 : Gestion du context cps
  memset(pslot->app_name, 0, sizeof(pslot->app_name));
  slot->flags = 0;
  return SC_SUCCESS;
}

/*
 * Lock reader access.
 */
 /*--------------------------------------------------------------------------
      galss_lock

 Fonction prenant une exclusivité GALSS sur la carte dans une fente du lecteur désigné.

 Parametres:
 reader               : Pointeur vers l'objet contenant les informations du driver lecteur
 slot                 : Pointeur vers l'objet contenant les informations de la carte dans une fente

 Codes retour:
 SC_SUCCESS

 --------------------------------------------------------------------------*/
static INT galss_lock(sc_reader_t *reader, sc_slot_info_t *slot)
{
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  USHORT rc;

  SC_FUNC_CALLED(reader->ctx, 3);
  assert(pslot != NULL);

  /* We locked access on the reader by starting a Galss exclusivity */
  rc = i_galss_start_excl(reader, slot);
  if (rc != OK) {
    return galss_ret_to_error(pslot->cr_galss);
  }

  pslot->locked = TRUE;
  return SC_SUCCESS;
}

/*--------------------------------------------------------------------------
     galss_unlock

Fonction libérant l'exclusivité GALSS prise sur la carte dans une fente du lecteur désigné.

Parametres:
reader               : Pointeur vers l'objet contenant les informations du driver lecteur
slot                 : Pointeur vers l'objet contenant les informations de la carte dans une fente

Codes retour:
SC_SUCCESS

--------------------------------------------------------------------------*/
static INT galss_unlock(sc_reader_t *reader, sc_slot_info_t *slot)
{
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);

  SC_FUNC_CALLED(reader->ctx, 3);
  assert(pslot != NULL);

  /* Unlocked access on the reader by releasing the Galss exclusivity */
  i_galss_end_excl(reader, slot);
  pslot->locked = FALSE;
  return SC_SUCCESS;
}

/*--------------------------------------------------------------------------
     galss_release

Fonction libérant les ressources mémoire de l'objet driver lecteur.

Parametres:
reader               : Pointeur vers l'objet contenant les informations du driver lecteur

Codes retour:
SC_SUCCESS

--------------------------------------------------------------------------*/
static int galss_release(sc_reader_t *reader)
{
  struct galss_private_data *priv = GET_PRIV_DATA(reader);
  //struct galss_slot_data *pslot = GET_SLOT_DATA(reader->slot);
  struct sc_slot_info *slot = &reader->slot[0];
  if (slot != NULL) galss_disconnect(reader, slot);

  // Close Galss session
  //if (pslot != NULL && pslot->num_session != 0) {
  //  i_galss_close_session(reader, reader->slot);
  //}
  /* Reset all private data */
  free(priv->reader_name);
  free(priv);

  if (reader->slot[0].drv_data != NULL) {
    free(reader->slot[0].drv_data);
    reader->slot[0].drv_data = NULL;
  }
  return SC_SUCCESS;
}

static struct sc_reader_operations galss_ops;

static struct sc_reader_driver galss_drv = {
  "GALSS reader",
  "galss",
  &galss_ops,
  0,
  0,
  NULL
};


/*--------------------------------------------------------------------------
     galss_init

Fonction initialisant un nouvel objet driver lecteur.
En particulier, charge en mémoire les librairies Galsscli et Galssinf

Parametres:
ctx                  : Pointeur vers l'objet du contexte OpenSC
reader_data          : Pointeur de pointeur vers l'objet driver lecteur instancié

Codes retour:
SC_SUCCESS
SC_ERROR_INTERNAL
SC_ERROR_OUT_OF_MEMORY
SC_ERROR_CANNOT_LOAD_MODULE

--------------------------------------------------------------------------*/
static INT galss_init(sc_context_t *ctx, LPVOID *reader_data, int transaction_reset)
{
  struct galss_global_private_data *gpriv;
  int ret = SC_ERROR_INTERNAL;
 
  *reader_data = NULL;

  gpriv = (struct galss_global_private_data *) calloc(1, sizeof(struct galss_global_private_data));
  if (gpriv == NULL) {
    ret = SC_ERROR_OUT_OF_MEMORY;
    return ret;
  }

  /* Set Defaults */
  gpriv->connect_reset = 0;
  gpriv->connect_exclusive = 1;
  gpriv->transaction_reset = transaction_reset;/* 1 en MAJ 0 sinon*/
  //gpriv->transaction_reset = 0;
  gpriv->enable_pinpad = 0;
  gpriv->polling_time = 2000; // Defalut polling time
 /* AROC - (@@20140519-0001155) - Recherche du parametre tpc_polling_time (ms) pour le galss: Debut */
  if (ctx->gal_tpc_polling_time > gpriv->polling_time)   gpriv->polling_time = ctx->gal_tpc_polling_time;
  /* AROC - (@@20140519-0001155) - Recherche du parametre tpc_polling_time (ms) pour le galss: Fin */
  /* AROC : (@@20121030) - Desactiver la detection de l'arrachement de lecteur sous Linux : Debut */
#ifndef UNIX_LUX
  gpriv->disconnected_reader = 1;
#else
  gpriv->disconnected_reader = 0;
#endif
  /* AROC : (@@20121030) : Fin */
  gpriv->galss_ctx = -1;
  gpriv->provider_library_cli = GALSS_PROVIDER;
  gpriv->provider_library_inf = GALSS_PROVIDER_INFO;

  /* Load Galss Client library */
  gpriv->dlhandleCli = lt_dlopen(gpriv->provider_library_cli);
  if (gpriv->dlhandleCli == NULL) {
    sc_error(ctx, "galss_init failed to load : %s", GALSS_PROVIDER);
    free(gpriv);
    return SC_ERROR_CANNOT_LOAD_MODULE;
  }

  /* Init Galss Client library functions */
  gpriv->OuvrirSession = (OuvrirSession_t)lt_dlsym(gpriv->dlhandleCli, "OuvrirSession");
  gpriv->FermerSession = (FermerSession_t)lt_dlsym(gpriv->dlhandleCli, "FermerSession");
  gpriv->DebutExclusivite = (DebutExclusivite_t)lt_dlsym(gpriv->dlhandleCli, "DebutExclusivite");
  gpriv->FinExclusivite = (FinExclusivite_t)lt_dlsym(gpriv->dlhandleCli, "FinExclusivite");
  gpriv->EcritContexte = (EcritContexte_t)lt_dlsym(gpriv->dlhandleCli, "EcritContexte");
  gpriv->LitContexte = (LitContexte_t)lt_dlsym(gpriv->dlhandleCli, "LitContexte");
  gpriv->Echange = (Echange_t)lt_dlsym(gpriv->dlhandleCli, "Echange");
  gpriv->LireVersion = (LireVersion_t)lt_dlsym(gpriv->dlhandleCli, "LireVersion");

  /* Load Galss Information library */
  gpriv->dlhandleInf = lt_dlopen(gpriv->provider_library_inf);
  if (gpriv->dlhandleInf == NULL) {
    sc_error(ctx, "galss_init failed to load : %s", GALSS_PROVIDER_INFO);
    lt_dlclose(gpriv->dlhandleCli);
    free(gpriv);
    return SC_ERROR_CANNOT_LOAD_MODULE;
  }

  /* Init Galss Information library functions */
  gpriv->DonneNbRes = (TInf_DonneNombreRessources)lt_dlsym(gpriv->dlhandleInf, "DonneNombreRessources");
  gpriv->DonneTableRes = (TInf_DonneTableRessources)lt_dlsym(gpriv->dlhandleInf, "DonneTableRessources");

  /* Verifiy  initialised data */
  if (
    gpriv->OuvrirSession == NULL ||
    gpriv->FermerSession == NULL ||
    gpriv->DebutExclusivite == NULL ||
    gpriv->FinExclusivite == NULL ||
    gpriv->EcritContexte == NULL ||
    gpriv->LitContexte == NULL ||
    gpriv->Echange == NULL ||
    gpriv->LireVersion == NULL ||
    gpriv->DonneNbRes == NULL ||
    gpriv->DonneTableRes == NULL)
  {
    if (gpriv->OuvrirSession == NULL) { sc_error(ctx, "galss_init faild : OuvrirSession == NULL"); }
    if (gpriv->FermerSession == NULL) { sc_error(ctx, "galss_init faild : FermerSession == NULL"); }
    if (gpriv->DebutExclusivite == NULL) { sc_error(ctx, "galss_init faild : DebutExclusivite == NULL"); }
    if (gpriv->FinExclusivite == NULL) { sc_error(ctx, "galss_init faild : FinExclusivite == NULL"); }
    if (gpriv->EcritContexte == NULL) { sc_error(ctx, "galss_init faild : EcritContexte == NULL"); }
    if (gpriv->LitContexte == NULL) { sc_error(ctx, "galss_init faild : LitContexte == NULL"); }
    if (gpriv->Echange == NULL) { sc_error(ctx, "galss_init faild : Echange == NULL"); }
    if (gpriv->LireVersion == NULL) { sc_error(ctx, "galss_init faild : LireVersion == NULL"); }
    if (gpriv->DonneNbRes == NULL) { sc_error(ctx, "galss_init faild : DonneNbRes == NULL"); }
    if (gpriv->DonneTableRes == NULL) { sc_error(ctx, "galss_init faild : DonneTableRes == NULL"); }
    lt_dlclose(gpriv->dlhandleCli);
    lt_dlclose(gpriv->dlhandleInf);
    free(gpriv);
    return SC_ERROR_CANNOT_LOAD_MODULE;
  }

  /* AROC 15-05-2014 (@@20140515-1122)- Memorisation de la table des ressources CPS* : Debut */
  gpriv->res_count = 0;
  gpriv->res_detected = 0;
  /* AROC 15-05-2014 (@@20140515-1122)- Memorisation de la table des ressources CPS* : Fin */
  memset(gpriv->Ressources, 0, sizeof(gpriv->Ressources));
  *reader_data = gpriv;

  return SC_SUCCESS;
}

/*--------------------------------------------------------------------------
     galss_finish

Fonction supprimant les données internes de l'objet driver lecteur.
Egalement, décharge les librairies Galsscli et Galssinf

Parametres:
ctx                  : Pointeur vers l'objet du contexte OpenSC
prv_data             : Pointeur vers les données internes du driver lecteur

Codes retour:
SC_SUCCESS

--------------------------------------------------------------------------*/
static int galss_finish(sc_context_t *ctx, void *prv_data)
{
  struct galss_global_private_data *gpriv = (struct galss_global_private_data *) prv_data;

  /* Release laoded libraries and free private data */
  if (gpriv) {
    if (gpriv->dlhandleCli != NULL)
      lt_dlclose(gpriv->dlhandleCli);
    if (gpriv->dlhandleInf != NULL)
      lt_dlclose(gpriv->dlhandleInf);
    free(gpriv);
  }

  return SC_SUCCESS;
}

/*--------------------------------------------------------------------------
     galss_detect_readers

Fonction détectant les lecteurs PSS connectés au poste.
Maintient une liste de lecteurs pour gérer la deconnexion/reconnexion des lecteurs PSS

Parametres:
ctx                  : Pointeur vers l'objet du contexte OpenSC
prv_data             : Pointeur vers les données internes du driver lecteur

Codes retour:
SC_SUCCESS
SC_ERROR_NO_READERS_FOUND
SC_ERROR_INTERNAL
SC_ERROR_OUT_OF_MEMORY

--------------------------------------------------------------------------*/
static INT galss_detect_readers(sc_context_t *ctx, LPVOID prv_data)
{
  struct galss_global_private_data *gpriv = (struct galss_global_private_data *) prv_data;

  CHAR reader_name[50];
  USHORT usRv;
  USHORT usNbRessources;
  InfoRessource ResTbl[MAX_RESOURCES];
  UINT i, j;
  INT ret = SC_NO_ERROR;
  /* Utilisé pour mémoriser les lecteurs déconnectés depuis la dernière détection */
  sc_reader_t * deconnected_reader_list[256] = { 0 };
  /* CLCO 04/06/2010 : fin */

  SC_FUNC_CALLED(ctx, 3);

  if (!gpriv) {
    SC_FUNC_RETURN(ctx, 3, SC_ERROR_NO_READERS_FOUND);
  }

  sc_debug(ctx, "Probing galss readers");

  /* AROC 15-05-2014 (@@20140515-1122)- Memorisation de la table des ressources CPS* : Debut */
  if (!gpriv->res_detected) {
    /* Get number of resources available */
    usRv = gpriv->DonneNbRes(&usNbRessources);
    if (usRv != OK) {
      GALSS_ERROR(ctx, "DonneNbRessources failed", usRv);
      ret = galss_ret_to_error(usRv);
      gpriv->res_detected = 1;
      SC_FUNC_RETURN(ctx, 3, ret);
    }

    sc_debug(ctx, "Found '%d' galss resources", usNbRessources);
    if (usNbRessources == 0) {
      ret = SC_ERROR_NO_READERS_FOUND;
      gpriv->res_detected = 1;
      SC_FUNC_RETURN(ctx, 3, ret);
    }

    /* Get available resources data */
    usRv = gpriv->DonneTableRes((InfoRessource*)ResTbl, &usNbRessources);
    if (usRv != OK) {
      GALSS_ERROR(ctx, "DonneTableRessources failed", usRv);
      ret = galss_ret_to_error(usRv);
      gpriv->res_detected = 1;
      SC_FUNC_RETURN(ctx, 3, ret);
    }

    /* Only resources begining by CPS will be used and alias will by ignored */
    for (i = 0; i < usNbRessources; i++) {
      if (strncasecmp("CPS", (LPSTR)ResTbl[i].NomRessource, strlen("CPS")) == 0) {
        INT isAlias = FALSE;

        if (ResTbl[i].TypeCanal != 1) {
          continue;
        }

        if (gpriv->res_count != 0) {
          for (j = 0; j < usNbRessources; j++) {
            if (strcmp((LPSTR)gpriv->Ressources[j].NomRessource, (char*)ResTbl[i].NomRessource) == 0) {
              isAlias = TRUE; /* c'est un alias */
            }
          }
          if (isAlias) {
            continue;
          }
        }
        memcpy(&gpriv->Ressources[gpriv->res_count], &ResTbl[i], sizeof(InfoRessource));
        gpriv->res_count++;
      }
    }
    gpriv->res_detected = 1;
  }
  /* AROC 15-05-2014 (@@20140515-1122)- Memorisation de la table des ressources CPS* : Fin */

  /* CLCO 04/06/2010 : gestion de la déconnexion des lecteurs */
  /* Balayer la liste des lecteurs déjà identifiés */
  j = 0;
  for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
    sc_reader_t *reader2 = sc_ctx_get_reader(ctx, i);
    if (reader2 == NULL) {
      SC_FUNC_RETURN(ctx, 3, SC_ERROR_INTERNAL);
    }
    if (reader2->ops == &galss_ops) {
      if (!reader2->detected) {
        deconnected_reader_list[j++] = reader2; /* Mémoriser les lecteurs déjà déconnectés */
      }
      reader2->detected = 0; /* cela servira à détecter les nouveaux lecteurs déconnectés */
    }
  }
  /* CLCO 04/06/2010 : fin */

  /* Add each available reader */
  for (i = 0; i < gpriv->res_count; i++) {
    sc_reader_t *reader = NULL;
    struct galss_private_data *priv = NULL;
    struct galss_slot_data *pslot = NULL;
    sc_slot_info_t *slot = NULL;
    UINT l;
    BOOL found = FALSE;
    USHORT tstSessNum;
    USHORT tstExcNum; // needed but not used
    BYTE  num_lad;   // needed but not used
    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    BOOL reconnected = FALSE;
    /* CLCO 04/06/2010 : fin */


    sprintf(reader_name, "%s%s", GALSS_SERIAL_READER, gpriv->Ressources[i].NomRessource);
    if (gpriv->disconnected_reader) {
      USHORT rc;
      sc_debug(ctx, "Probing reader ");
      rc = gpriv->OuvrirSession("TST_READER", (LPSTR)gpriv->Ressources[i].NomRessource, &tstSessNum, &num_lad);
      if (rc != 0 && rc != G_ERROUVERT) {
        sc_debug(ctx, "Reader '%s' seems not to be connected rc=%x", gpriv->Ressources[i].NomRessource, rc);
        continue;
      }
      else {
        gpriv->FermerSession(tstSessNum, &tstExcNum);
      }
    }

    /* Do not add a reader previously found */
    for (l = 0; l < sc_ctx_get_reader_count(ctx) && !found; l++) {
      sc_reader_t *reader2 = sc_ctx_get_reader(ctx, l);
      if (reader2 == NULL) {
        SC_FUNC_RETURN(ctx, 3, SC_ERROR_INTERNAL);
      }
      if (reader2->ops == &galss_ops && !strcmp(reader2->name, reader_name)) {
        found = TRUE;
        /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
        reader2->detected = 1; /* le lecteur est donc bien connecté */
        /* rechercher dans la liste des lecteurs déconnectés pour savoir s'il s'agit d'une reconnexion */
        for (j = 0; deconnected_reader_list[j]; j++) {
          if (deconnected_reader_list[j] == reader2) {
            /* c'est un lecteur reconnecté, on le mémorise pour la suite des traitements */
            reconnected = TRUE;
            reader = reader2;
            break;
          }
        }
        /* CLCO 04/06/2010 : fin */
      }
    }

    /* Reader already available, skip */
    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    if (found && !reconnected) { /* s'il s'agit d'un lecteur reconnecté, il faut faire le ménage */
    /* CLCO 04/06/2010 : fin */
      continue;
    }

    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    if (!reconnected) {
      sc_debug(ctx, "Found new galss reader '%s'", reader_name);
      /* Allocate new reader data*/
      if ((reader = (sc_reader_t *)calloc(1, sizeof(sc_reader_t))) == NULL) {
        SC_FUNC_RETURN(ctx, 3, SC_ERROR_MEMORY_FAILURE);
      }
    }
    else {
      /* il s'agit d'un lecteur reconnecté, il faut faire le ménage */
      sc_debug(ctx, "Found reconnected galss reader '%s'", reader_name);
      ret = galss_release(reader);
      if (ret) {
        if (priv != NULL) { if (priv->reader_name) { free(priv->reader_name); } free(priv); }
        if (reader != NULL) { if (reader->name) { free(reader->name); } free(reader); }
        if (pslot != NULL) { free(pslot); }
        SC_FUNC_RETURN(ctx, 3, ret);
      }
    }
    /* CLCO 04/06/2010 : fin */

    if ((priv = (struct galss_private_data *) malloc(sizeof(struct galss_private_data))) == NULL) {
      /*if (priv != NULL) { if (priv->reader_name) { free(priv->reader_name); } free(priv); }*/
      if (reader != NULL) { if (reader->name) { free(reader->name); } free(reader); }
      if (pslot != NULL) { free(pslot); }
      SC_FUNC_RETURN(ctx, 3, SC_ERROR_OUT_OF_MEMORY);
    }

    if ((pslot = (struct galss_slot_data *) malloc(sizeof(struct galss_slot_data))) == NULL) {
      if (priv != NULL) { if (priv->reader_name) { free(priv->reader_name); } free(priv); }
      if (reader != NULL) { if (reader->name) { free(reader->name); } free(reader); }
      if (pslot != NULL) { free(pslot); }
      SC_FUNC_RETURN(ctx, 3, SC_ERROR_OUT_OF_MEMORY);
    }

    /* Init new reader */
    reader->drv_data = priv;
    reader->ops = &galss_ops;
    reader->driver = &galss_drv;
    reader->slot_count = 1;
    reader->detected = 1;

    if ((reader->name = strdup(reader_name)) == NULL) {
      if (priv != NULL) { if (priv->reader_name) { free(priv->reader_name); } free(priv); }
      if (reader != NULL) { if (reader->name) { free(reader->name); } free(reader); }
      if (pslot != NULL) { free(pslot); }
      SC_FUNC_RETURN(ctx, 3, SC_ERROR_OUT_OF_MEMORY);
    }

    priv->gpriv = gpriv;
    if ((priv->reader_name = strdup(reader_name)) == NULL) {
      if (priv != NULL) { if (priv->reader_name) { free(priv->reader_name); } free(priv); }
      if (reader != NULL) { if (reader->name) { free(reader->name); } free(reader); }
      if (pslot != NULL) { free(pslot); }
      SC_FUNC_RETURN(ctx, 3, SC_ERROR_OUT_OF_MEMORY);
    }

    slot = &reader->slot[0];
    memset(slot, 0, sizeof(*slot));
    slot->drv_data = pslot;
    /* BPER (@@20160609-1359) - Positionner le protocole en GALSS
      pour avoir les apdus 'select file' corrects dans les logs */
    slot->active_protocol = SC_PROTO_T0;
    /* BPER (@@20160609-1359) - Fin */
    memset(pslot, 0, sizeof(*pslot));

    /* CLCO 04/06/2010 : gestion de la déconnexion/reconnexion des lecteurs */
    if (!reconnected && _sc_add_reader(ctx, reader)) { /* on ajoute pas un lecteur reconnecté */
    /* CLCO 04/06/2010 : fin */
      if (priv != NULL) { if (priv->reader_name) { free(priv->reader_name); } free(priv); }
      if (reader != NULL) { if (reader->name) { free(reader->name); } free(reader); }
      if (pslot != NULL) { free(pslot); }
      SC_FUNC_RETURN(ctx, 3, SC_SUCCESS);/* silent ignore */
    }
    strcpy((LPSTR)pslot->res_name, (LPSTR)gpriv->Ressources[i].NomRessource);
    pslot->init = 1;

#if defined (UNIX_LUX) || defined (__APPLE__)
    if (refresh_slot_attributes(reader, slot) != SC_SUCCESS)
#else
    if (refresh_slot_attributes(reader, slot) == SC_ERROR_READER)
#endif
    {
      reader->detected = 0; // le lecteur est déconnecté
    }
    pslot->init = 0;
  }
  ret = SC_SUCCESS;

  SC_FUNC_RETURN(ctx, 3, ret);
}

/*--------------------------------------------------------------------------
     sc_get_galss_driver

Fonction initialisant les différents points d'entrée du driver GALSS définis dans ce fichier.

Parametres:

Codes retour:
La fonction renvoie la structure du driver initialisé

--------------------------------------------------------------------------*/
struct sc_reader_driver * sc_get_galss_driver(void)
{
  galss_ops.init = galss_init;
  galss_ops.finish = galss_finish;
  galss_ops.detect_readers = galss_detect_readers;
  galss_ops.transmit = galss_transmit;
  galss_ops.detect_card_presence = galss_detect_card_presence;
  galss_ops.lock = galss_lock;
  galss_ops.unlock = galss_unlock;
  galss_ops.release = galss_release;
  galss_ops.connect = galss_connect;
  galss_ops.disconnect = galss_disconnect;
  galss_ops.perform_verify = NULL; /* Not implemented*/
  galss_ops.wait_for_event = NULL; /* Not implemented */
  galss_ops.reset = NULL; /* Not implemented*/
  /* AROC 08/04/2013 - Ajout de la fonction de tramsmission de données de manière transparente */
   galss_ops.free_transmit = galss_free_transmit;
   galss_ops.get_status = NULL;

  return &galss_drv;
}

/* ------------------ Interface du Galss ------------------
 *
 * Les fonctions d'interface de Galss retour OK  ou KO.
 * si une erreur galss apparaite durant le traitement, cette derniere
 * est memoriser dans la variable "cr_galss" des donnees privees du slot.
*/

/* i_galss_open_session
 *
 * Ouverture de session Galss
 */
static INT i_galss_open_session(sc_reader_t * reader, sc_slot_info_t * slot)
{
  struct galss_private_data *priv = GET_PRIV_DATA(reader);
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  CHAR   app_name[MAX_APP_NAME + 1];
  INT    index = 1;

  /* Ouvrir une session Galss avec un nom d'application suffixer par un index */
  do {
    sprintf(app_name, "OPENSC_%.3d", index);
    pslot->cr_galss = priv->gpriv->OuvrirSession(app_name, (LPSTR)pslot->res_name, &pslot->num_session, &pslot->num_lad);
    index++;
  } while (G_ERROUVERT == pslot->cr_galss);

  if (pslot->cr_galss != OK) {
    sc_error(reader->ctx, "i_galss_open_session failed : 0x%04x", pslot->cr_galss);
    return KO;
  }
  /* Memoriser le nom d'applicartion */
  strcpy((char*)pslot->app_name, app_name);
  sc_debug(reader->ctx, "GALSS Session : %d, opened (App:%s,Res:%s)", pslot->num_session, app_name, (LPSTR)pslot->res_name);
  return OK;
}

/* i_galss_close_session
 * Fermeture d'une session Galss
 */
static INT i_galss_close_session(sc_reader_t * reader, sc_slot_info_t * slot)
{
  struct galss_private_data *priv = GET_PRIV_DATA(reader);
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);

  pslot->cr_galss = priv->gpriv->FermerSession(pslot->num_session, &pslot->num_excl);
  if (pslot->cr_galss != OK) {
    sc_error(reader->ctx, "i_galss_close_session failed : 0x%04x", pslot->cr_galss);
    return KO;
  }
  sc_debug(reader->ctx, "GALSS Session : %d, closed ", pslot->num_session);
  return OK;
}

/* i_galss_start_excl
 * Demarrer une exclusivite sur une fente du lecteur
 */
static INT i_galss_start_excl(sc_reader_t * reader, sc_slot_info_t * slot)
{
  struct galss_private_data *priv = GET_PRIV_DATA(reader);
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  CHAR tampon[20];
  INT  cpt = 0;

  /* Si une exclusivite est deja en cours, ne rien faire */
  if (pslot->num_excl != 0) return OK;

  pslot->num_excl = 0;
  sprintf(tampon, "%u:3", pslot->num_session);
  do {
    pslot->cr_galss = priv->gpriv->DebutExclusivite(tampon, NULL, NULL, &pslot->num_excl);
    if (pslot->cr_galss != OK && pslot->cr_galss == G_ERREXCL) {
      msleep(EXCLUSIVITY_SLEEP);
    }
    else {
      break;
    }
    cpt++;
  } while (cpt < EXCLUSIVITY_INTERVAL);
  if (pslot->cr_galss != OK) {
    sc_error(reader->ctx, "i_galss_start_excl failed : 0x%04x", pslot->cr_galss);
    return KO;
  }
  sc_debug(reader->ctx, "GALSS Exclusivity started : %d", pslot->num_excl);

  return OK;
}

/* i_galss_end_excl
 * Liberer une exclusivite sur une fente du lecteur
 */

static INT i_galss_end_excl(sc_reader_t * reader, sc_slot_info_t * slot)
{
  struct galss_private_data *priv = GET_PRIV_DATA(reader);
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);

  /* Si l'exclsivite a deja ete liberee, ne rien faire */
  if (pslot->num_excl == 0) { return OK; }

  pslot->cr_galss = priv->gpriv->FinExclusivite(pslot->num_excl);
  if (pslot->cr_galss != OK) {
    sc_error(reader->ctx, "i_galss_end_excl failed : 0x%04x", pslot->cr_galss);
    return KO;
  }
  sc_debug(reader->ctx, "GALSS Exclusivity ended : %d", pslot->num_excl);
  pslot->num_excl = 0;

  return OK;
}

/* i_galss_exchange_msg
 * Echange de message avec le Galss
 */
static INT i_galss_exchange_msg(sc_reader_t    * reader,
  sc_slot_info_t * slot,
  USHORT           exec_time,
  LPBYTE           msg_in,
  PUSHORT          msg_in_len,
  LPBYTE           msg_out,
  PUSHORT          msg_ou_len)
{
  struct galss_private_data *priv = GET_PRIV_DATA(reader);
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  UINT ul_msg_in = *msg_in_len;
  UINT ul_msg_out = *msg_ou_len;

  pslot->cr_galss = priv->gpriv->Echange(pslot->num_session, exec_time, (char*)msg_in, &ul_msg_in, (char*)msg_out, &ul_msg_out);
  *msg_ou_len = (USHORT)ul_msg_out;
  if (pslot->cr_galss == G_ERRTIMOUT) {
    reader->detected = 0;
    return KO;
  }
  else {
    reader->detected = 1;
  }
  if (pslot->cr_galss != OK) return KO;

  return OK;
}
/* AROC 19-01-2012 : Gestion du context cps : Debut */

/* i_galss_ctx_read
 * Lecture du context ressources
 */
static INT i_galss_ctx_read(sc_reader_t * reader, sc_slot_info_t * slot, cps_context *pCpsCtx, PUSHORT lpszCpsCtx)
{
  struct galss_private_data *priv = GET_PRIV_DATA(reader);
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  LPSTR buf = NULL;
  size_t blen = 0;
  size_t ssize = 0;
  USHORT rc_galss;

  ssize = sizeof(cps_context) - sizeof(cps_contexte_infos);

  rc_galss = priv->gpriv->LitContexte(2, pslot->num_session, pCpsCtx, lpszCpsCtx);
  if (!rc_galss) {
    pslot->cps_ctx_exist = 1;
    if (pCpsCtx->LgATR != 0) {
      slot->atr_len = pCpsCtx->LgATR;
      memcpy(slot->atr, pCpsCtx->ATR, slot->atr_len);
    }

  }
  if (reader->ctx->debug > 0) {
    sc_hex_dump_get_len(ssize, &blen);
    buf = (LPSTR)calloc(blen, sizeof(CHAR));
    if (buf == NULL) {
      return KO;
    }

    sc_hex_dump(reader->ctx, (const u8 *)pCpsCtx, ssize, buf, blen);

    sc_debug(reader->ctx,
      "\n%s GALSS CONTEXT read data         [%5u bytes] =====================================\n"
      "%s"
      "============================================================================================\n",
      "Incoming", ssize,
      buf);

    free(buf);
  }

  return 0;
}
/* galss_update_state
 * Mise a jour de l'etat carte.
 */
VOID galss_update_state(PUSHORT state, USHORT new_state)
{
  /* met a jour que 2 bits de poids faible: En/Hors Tension et Presence/Absence */
  *state = ((new_state & 0x03) | (*state & 0xfffc));
}

/* i_galss_ctx_write
 * Ecriture du context ressources
 */
static INT i_galss_ctx_write(sc_reader_t * reader, sc_slot_info_t * slot, cps_context *pCpsCtx, PUSHORT lpszCpsCtx)
{
  struct galss_private_data *priv = GET_PRIV_DATA(reader);
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  size_t blen = 0;
  size_t ssize = 0;
  LPSTR   buf = NULL;

  /* AROC - 10/11/2015 - Mettre à jour le compteur d'état dans le contexte ressource. (@@20151110-1308) : Debut */
  if (!pslot->cps_ctx_exist || (pCpsCtx->LgATR == 0 && slot->atr_len != 0) || pCpsCtx->Cpt != pslot->cpt) {
    /* AROC - 10/11/2015 - Mettre à jour le compteur d'état dans le contexte ressource. (@@20151110-1308) : Fin */
    strcpy((LPSTR)pCpsCtx->Denomination, "APICPS");
    pCpsCtx->LgInfo = 0;
    pCpsCtx->NumAPI = 1;
    pCpsCtx->NumLad = pslot->num_lad;
    pCpsCtx->Lg = *lpszCpsCtx;
    pCpsCtx->NumVersionAPIs = 5 * 256 + 7; // 5.07
    pCpsCtx->NumAPI = 4;                // IntroCarte
    pCpsCtx->Cpt = pslot->cpt;
    galss_update_state(&pCpsCtx->EtatCarte, pslot->card_state);
    pCpsCtx->LgATR = (USHORT)slot->atr_len;
    if (slot->atr_len != 0)
      memcpy(pCpsCtx->ATR, slot->atr, slot->atr_len);

    ssize = sizeof(cps_context) - sizeof(cps_contexte_infos);
    if (reader->ctx->debug > 0) {
      sc_hex_dump_get_len(ssize, &blen);
      buf = (LPSTR)calloc(blen, sizeof(CHAR));
      if (buf == NULL) {
        return KO;
      }

      sc_hex_dump(reader->ctx, (const u8 *)pCpsCtx, ssize, buf, blen);

      sc_debug(reader->ctx,
        "\n%s GALSS CONTEXT written data    [%5u bytes] =====================================\n"
        "%s"
        "============================================================================================\n",
        "Outgoing", ssize,
        buf);
      free(buf);
    }
    priv->gpriv->EcritContexte(2, pslot->num_session, pCpsCtx, lpszCpsCtx);
  }

  return 0;
}
/* AROC 19-01-2012 : Gestion du context cps : Fin */

const LPSTR m_get_state(USHORT full_state)
{
  USHORT state;
  state = full_state & 0x03;

  if (state == 0) return STR_NO_CARD;
  if (state == 1) return STR_CARD_OFF;
  return STR_CARD_ON;
}

/* ------------------ Interface Lecteur ------------------
 * Ces fonction permettent d'envoyer des ordres lecteur.
 */

 /* reader_galss_test_presence
  * Teste la presence de la carte dans la fente du lecteur désigné.
  */
static int reader_galss_test_presence(sc_reader_t * reader, sc_slot_info_t * slot)
{
  int rc = OK;
  struct galss_private_data *priv = GET_PRIV_DATA(reader);
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  time_t now, end_time;
  BOOL can_redo = TRUE;
  INT  retry = 0;

  /* Mise en forme de lordre de test presence carte */
  USHORT question_len = LEC_LG_REQ_PRESENCE;
  u8 question[LEC_LG_REQ_PRESENCE] = { LEC_CMD_APPLI, 0, LEC_CMD_PRESENCE_CARTE };
  USHORT response_len = LEC_LG_REP_PRESENCE;
  u8       response[LEC_LG_REP_PRESENCE];

  /* Optimisation de l'appel a test presence carte */
  time(&now);
  sc_debug(reader->ctx, "reader_galss_test_presence previous (state = %s,cpt = %d)", m_get_state(pslot->card_state), pslot->cpt);
  if (pslot->last_test_presence == 0) {
    pslot->last_test_presence = now;
  }
  else {
    end_time = pslot->last_test_presence + (priv->gpriv->polling_time + 999) / 1000;
    if (now < end_time) {
      sc_debug(reader->ctx, "reader_galss_test_presence optimisation, return last state : %d", pslot->card_state);
      return OK;
    }
  }
  pslot->cr_reader = 0;
  question[1] = (u8)pslot->num_lad;

  do {
    /* Envoyer l'ordre au lecteur a travers le galss */
    rc = i_galss_exchange_msg(reader, slot, LEC_TEMPS_EXEC_PRESENCE, question, &question_len, response, &response_len);
    if (rc == OK)
    {
      pslot->last_test_presence = time(&now);
      /* Interpreter le code erreur carte */
      pslot->cr_galss = OK;
      pslot->cr_reader = response[0];
      sc_debug(reader->ctx, "reader_galss_test_presence pslot->cr_galss = 0x%04X, pslot->cr_reader = 0x%04X", pslot->cr_galss, pslot->cr_reader);
      switch (response[0])
      {
      case 0:
        if (response_len == LEC_LG_REP_PRESENCE)
        {
          galss_update_state(&pslot->card_state, response[1]);
          pslot->cpt = (USHORT)response[2];
          sc_debug(reader->ctx, "reader_galss_test_presence now (state = %d,cpt = %d)", pslot->card_state, pslot->cpt);

          /* Test Etat carte qui prime sur CR lecteur */
          if (pslot->card_state == LEC_CARTE_ABSENTE) {
            pslot->cr_reader = CMD_ERROR_CARTE_ABSENTE;
            break;
          }
          if (pslot->card_state == LEC_CARTE_HORS_TENSION) {
            pslot->cr_reader = CMD_ERROR_CARTE_HORS_TENSION;
            break;
          }
        }
        else {
          pslot->cr_reader = CMD_ERROR_TRANSMISSION;
        }
        break;

      default:
        if (response_len == 1) {
          pslot->cr_reader = CMD_ERROR_PAS_SERVICE;
        }
        else {
          pslot->cr_reader = CMD_ERROR_TRANSMISSION;
        }
        break;
      }

    }
    else {
      sc_debug(reader->ctx, "reader_galss_test_presence pslot->cr_galss= 0x%04X (can_redo = %d)", pslot->cr_galss, can_redo);
      if (pslot->cr_galss == G_ERRTRANS)
      {
        if (can_redo == TRUE) {
          sc_debug(reader->ctx, "reader_galss_test_presence try_reconnect");
#ifdef __APPLE__
          msleep(100);
#endif
          response_len = LEC_LG_REP_PRESENCE;
          can_redo = FALSE;
        }
        retry += 1;
      }

    }
  } while ((pslot->cr_galss == G_ERRTRANS) && (retry < 2));

  return (rc);
}

/* reader_galss_power_on
 * Met sous tension la carte dans la fente du lecteur désigné.
 */
static INT reader_galss_power_on(sc_reader_t * reader, sc_slot_info_t * slot)
{
  INT rc = OK;
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);

  /* Mise en forme de lordre de mise sous tension de la carte*/
  u8 question[LEC_LG_QUESTION_TENSION] = { LEC_CMD_APPLI,                /* APPLI */
                                        0,                            /* FU    */
                                        LEC_CMD_MISE_TENSION_CARTE    /* CC    */
  };
  USHORT  question_len = LEC_LG_QUESTION_TENSION;
  USHORT  response_len;
  u8 * response = NULL;

  USHORT  copy_len;
  USHORT  tmp_len;

  pslot->cr_reader = 0;
  question[1] = (u8)pslot->num_lad;
  tmp_len = SC_MAX_ATR_SIZE/**atr_len*/;

  /* calcul longueur buffer de reponse */
  response_len = LEC_LG_REPONSE_TENSION + tmp_len;

  /* Allocation zone de travail pour le buffer de reponse */
  response = (u8*)calloc(response_len, sizeof(u8));
  if (response == NULL) {
    pslot->cr_reader = CMD_ERROR_NO_MEMORY;
    return KO;
  }

  /* Envoyer l'ordre au lecteur a travers le galss */
  rc = i_galss_exchange_msg(reader,
    slot,
    LEC_TEMPS_EXEC_TENSION,
    question,
    &question_len,
    response,
    &response_len);

  if (rc != OK) {
    free(response);
    /* AROC - (@@20130910-0001089) - Debut */
    sc_debug(reader->ctx, "Galss exchange message error 0x%04X", pslot->cr_galss);
    rc = galss_ret_to_error(pslot->cr_galss);
    return rc;
    /* AROC - (@@20130910-0001089) - Fin*/
  }

  /* verification: de la longueur de la reponse ainsi que le contenu de la reponse */
  /* cr du lecteur */
  pslot->cr_reader = response[0];

  switch (response[0]) {
  case CMD_ERROR_OK:
  case CMD_ERROR_CARTE_MUETTE:
  case CMD_ERROR_CARTE_PAS_SUPPORTEE:
  case CMD_ERROR_CMD_REFUSE:
    rc = KO;
    if (response_len < LEC_LG_REPONSE_TENSION)
      break;

    galss_update_state(&pslot->card_state, response[1]);
    pslot->cpt = (USHORT)response[2];

    /* Test Etat carte qui prime sur rc */
    if (pslot->card_state == LEC_CARTE_ABSENTE) {
      pslot->cr_reader = CMD_ERROR_CARTE_ABSENTE;
      /* AROC - (@@20130910-0001089) - Debut */
      rc = SC_ERROR_CARD_REMOVED;
      /* AROC - (@@20130910-0001089) - Fin */
      break;
    }

    if (pslot->cr_reader == CMD_ERROR_OK) {
      copy_len = response_len - LEC_LG_REPONSE_TENSION;
      if (copy_len) {
        if (tmp_len >= copy_len) {
          /* recopie zone ATR */

          memcpy(slot->atr, &(response[3]), copy_len);
          slot->atr_len = copy_len;
          rc = OK;
        }
      }

      /* AROC - (@@20130910-0001089) - Debut */
    }
    else {
      if (response[0] == CMD_ERROR_CARTE_MUETTE) { rc = SC_ERROR_CARD_UNRESPONSIVE; }
      else if (response[0] == CMD_ERROR_CMD_REFUSE) { rc = SC_ERROR_NOT_ALLOWED; }
      else if (response[0] == CMD_ERROR_CARTE_PAS_SUPPORTEE) { rc = SC_ERROR_INVALID_CARD; }
    }
    /* AROC - (@@20130910-0001089) - Fin */

    break;
  default:
    rc = KO;
    break;
  }

  /* liberation zones memoire de travail */
  free(response);
  return rc;
}

/* reader_galss_power_off
* Mise hors tension de la carte dans la fente du lecteur dÃ©signÃ©.
*/
static INT reader_galss_power_off(sc_reader_t * reader, sc_slot_info_t * slot)
{
	int rc = OK;
	struct galss_slot_data *pslot = GET_SLOT_DATA(slot);

	/* Mise en forme de l'ordre de mise hors tension de la carte*/
	u8 question[LEC_LG_QUESTION_RETRAIT] = { LEC_CMD_APPLI,                /* APPLI */
	  0,                            /* FU    */
	  LEC_CMD_RETRAIT_CARTE,        /* CC    */
	  1                             /* Sans retrait carte*/
	};
	unsigned short  question_len = LEC_LG_QUESTION_RETRAIT;
	u8 response[LEC_LG_REPONSE_RETRAIT];
	unsigned short  response_len = LEC_LG_REPONSE_RETRAIT;

	pslot->cr_reader = 0;
	question[1] = (u8)pslot->num_lad;

	/* Envoyer l'ordre au lecteur a travers le galss */
	sc_debug(reader->ctx, "DRIVER.GALSS : Mise Hors tension Carte > IN");
	rc = i_galss_exchange_msg(reader,
		slot,
		LEC_TEMPS_EXEC_RETRAIT,
		question,
		&question_len,
		response,
		&response_len);
	sc_debug(reader->ctx, "DRIVER.GALSS : Mise Hors tension Carte < OUT");

	/* copie infos */
	if (rc == OK) {
		/* Interpreter le code erreur carte */
		pslot->cr_galss = OK;
		pslot->cr_reader = response[0];

		switch (response[0])
		{
		case 0:
		case CMD_ERROR_CARTE_ENCORE_PRESENTE:
			if (response_len == LEC_LG_REPONSE_RETRAIT)
			{
				galss_update_state(&pslot->card_state, response[1]);
				pslot->cpt = (unsigned short)response[2];
			}
			else
				pslot->cr_reader = CMD_ERROR_TRANSMISSION;
			break;

		default:
			if (response_len == 1)
				pslot->cr_reader = CMD_ERROR_PAS_SERVICE;
			else
				pslot->cr_reader = CMD_ERROR_TRANSMISSION;
			break;
		}
	}

	return (rc);
}

/* reader_galss_transmit
 * Transmet des donnees a la carte dans une instruction carte
 * (commande entrante, sortante, les deux).
 */
static INT reader_galss_transmit(sc_reader_t * reader,
  sc_slot_info_t * slot,
  const u8 *sendbuf,
  size_t sendsize,
  u8 *recvbuf,
  size_t *recvsize,
  sc_apdu_t *apdu)
{

  INT rc = OK;
  struct galss_slot_data *pslot = GET_SLOT_DATA(slot);
  unsigned char ins_type;
  USHORT question_len;
  LPBYTE question = NULL;
  USHORT response_len;
  LPBYTE response = NULL;
  USHORT copy_len;
  INT nbTries = 0;
  INT retryNeeded = 0;

  SC_FUNC_CALLED(reader->ctx, 3);
  assert(pslot != NULL);

  do{
    pslot->cr_reader = 0;

    /* calculs longueurs buffer à envoyer et buffer a recevoir */
    ins_type = galss_ins_type(sendbuf[1]);
    switch (ins_type) {
    case LEC_CMD_ORDRE_ENTRANT:
      question_len = LEC_LG_QUESTION_INSTRUCTION + LEC_LG_QUESTION_INS_CARTE + (USHORT)apdu->lc;
      response_len = LEC_LG_REPONSE_INSTRUCTION + LEC_LG_REPONSE_INS_CARTE;
      break;
    case LEC_CMD_ORDRE_SORTANT:
      question_len = LEC_LG_QUESTION_INSTRUCTION + LEC_LG_QUESTION_INS_CARTE;
      if (apdu->le == 0)
        response_len = LEC_LG_REPONSE_INSTRUCTION + LEC_LG_REPONSE_INS_CARTE + 0x100;
      else
        response_len = LEC_LG_REPONSE_INSTRUCTION + LEC_LG_REPONSE_INS_CARTE + (USHORT)apdu->le;
      break;
    case LEC_CMD_ORDRE_ENTSORTANT:
      ins_type = LEC_CMD_ORDRE_ENTRANT;
      question_len = LEC_LG_QUESTION_INSTRUCTION + LEC_LG_QUESTION_INS_CARTE + (USHORT)apdu->lc;
      if (apdu->le == 0)
        response_len = LEC_LG_REPONSE_INSTRUCTION + LEC_LG_REPONSE_INS_CARTE + 0x100;
      else
        response_len = LEC_LG_REPONSE_INSTRUCTION + LEC_LG_REPONSE_INS_CARTE + (USHORT)apdu->le;
      break;
    default:
      return SC_ERROR_INVALID_ARGUMENTS;
    }


    question = (unsigned char*)calloc(question_len, sizeof(char));
    if (question == NULL) {
      return SC_ERROR_MEMORY_FAILURE;
    }

    response = (unsigned char*)calloc(response_len, sizeof(char));
    if (response == NULL) {
      free(question);
      return SC_ERROR_MEMORY_FAILURE;
    }

    /* Mise en forme de lordre de transmission de donnees */
    question[0] = 0x00;           /* Appli */
    question[1] = pslot->num_lad; /* FU */
    question[2] = ins_type;       /* type instruction */
    question[3] = (u8)pslot->cpt; /* CPTR attendu */

    memcpy(&(question[4]), sendbuf, (size_t)(question_len - LEC_LG_QUESTION_INSTRUCTION));

    /* Envoyer l'ordre au lecteur a travers le galss */
    rc = i_galss_exchange_msg(reader, slot, LEC_TEMPS_EXEC_INSTRUCTION, question, &question_len, response, &response_len);
    sc_debug(reader->ctx, "i_galss_exchange_msg rc = 0x%04X", rc);
    /* verification: de la longueur de la reponse ainsi que le contenu de la reponse */
    /* cr du lecteur */
    if (rc == OK) {
      pslot->cr_reader = response[0];
      sc_debug(reader->ctx, "reader response 0x%04X", pslot->cr_reader);


      switch (response[0])
      {
      case 0:
      case CMD_ERROR_CMD_REFUSE:
      case CMD_ERROR_COMPTEUR:
      case CMD_ERROR_CARTE_MUETTE:
      case CMD_ERROR_CARTE_PAS_SUPPORTEE:
      case CMD_ERROR_CARTE_ABSENTE:
      case CMD_ERROR_INSTRUCTION_INCOHERENTE:
        retryNeeded = 0;
        if (response_len >= LEC_LG_REPONSE_INSTRUCTION) {
          galss_update_state(&pslot->card_state, response[1]);
          pslot->cpt = response[2];

          if (response[0] != 0) {
            if (response[0] == CMD_ERROR_COMPTEUR) {
              if (nbTries < 1) {
                /* mise a jour du compteur */
                pslot->cpt = response[2];
                sc_debug(reader->ctx, "Galss counter updated 0x%04X. Retry query.", pslot->cpt);
                free(question);
                free(response);
                nbTries += 1;
                retryNeeded = 1;
              }
              else {
                retryNeeded = 0;
                rc = SC_ERROR_CARD_REMOVED;
              }
            }
            else if (response[0] == CMD_ERROR_CARTE_MUETTE) {
              rc = SC_ERROR_CARD_UNRESPONSIVE;
            }
            else if (response[0] == CMD_ERROR_CARTE_PAS_SUPPORTEE) {
              rc = SC_ERROR_INVALID_CARD;
            }
            else if (response[0] == CMD_ERROR_CARTE_ABSENTE) {
              rc = SC_ERROR_CARD_REMOVED;
            }
            else if (response[1] == CMD_ERROR_CARTE_HORS_TENSION) {
              rc = SC_ERROR_CARD_RESET;
            }
            else {
              rc = SC_ERROR_UNKNOWN;
            }
          }
          else {
            /* recopie reponse carte ds buffer appelant */
            copy_len = response_len - LEC_LG_REPONSE_INSTRUCTION;
            if (copy_len) {
              if (*recvsize >= copy_len) {
                memcpy(recvbuf, &response[LEC_LG_REPONSE_INSTRUCTION], copy_len);
                *recvsize = copy_len;
              }
              else {
                rc = SC_ERROR_BUFFER_TOO_SMALL;
              }
            }
            else {
              *recvsize = 0;
            }
          }
        }
        else {
          rc = SC_ERROR_TRANSMIT_FAILED;
        }
        break;
      default:
        retryNeeded = 0;
        if (response_len == 1) {
          rc = SC_ERROR_CARD_CMD_FAILED;
        }
        else {
          rc = SC_ERROR_TRANSMIT_FAILED;
        }
        break;
      }
    }
    else {
      retryNeeded = 0;
      sc_debug(reader->ctx, "Galss transmit error 0x%04X", pslot->cr_galss);
      rc = galss_ret_to_error(pslot->cr_galss);
    }
  }while (retryNeeded == 1);

  free(question);
  free(response);
  return rc;
}

#endif   /* ENABLE_GALSS */


