/*
 * gal_err.h : Fichier des constantes d'erreur du galss
 *
 * Copyright (C) 1996-2016, ASIP Santé
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


/*  erreurs internes */
#ifndef OK
    #define OK                 0
#endif
#ifndef KO
    #define KO                 1
#endif
#define ERRCANAL               2
#define DIALOGENCOURS          2

/* Erreurs renvoye aux applications  */
#define G_NOERR           0x0000
/* Erreurs de fonctionnement */
#define G_ERRLOG          0x0001  /* Anomalie fonctionnement GALSS: erreur logicielle  */
#define G_ERRDIM          0x0002  /* Dimensionnement insuffisant pour cette commande */
#define G_ERREXCLHS       0x0002  /* Plus de numero d'exclusivite disponible  */
#define G_ERRSESSHS       0x0002  /* Plus de numero de session disponible  */
#define G_ERRMEMORY       0x0002  /* Plus de memoire */
#define G_ERREXCL         0x0004  /* Exclusivite deja en cours : commande impossible */
#define G_ERRCMD          0x0008  /* Commande hors sequence   */
#define G_ERRNOEXCL       0x0008  /* LAD non pris en exclusivite */
#define G_ERRTAILLE       0x0010  /* Taille parametre incorrecte   */
#define G_ERRBLOC         0x0020  /* Bloc Inexistant */
#define G_ERRCTX          0x0020  /* Donnees de contexte inexistant */
#define G_ERROUVERT       0x0800  /* session deja ouverte   */
#define G_ERRABMAT        0x0040  /* ABORT par le materiel (protocole)   */
#define G_ERRABSTA        0x0080  /* ABORT par la station  (protocole)    */
#define G_ERRTEMPS        0x0100  /* Temps alloue pour le traitement depasse  */
#define G_ERRTRANS        0x0200  /* Erreur transmission, liaison physique  (protocole)   */
#define G_ERRRESSHS       0x0200  /* Ressource non accessible */
#define G_ERRTIMOUT       0x0400  /* TIME OUT, Non reponse materiel distant (protocole) */
#define G_ERREXIST        0x1000  /* Exclusivite-Session inconnue          */
#define G_ERRPADLAD       0x2000  /* Ressource non definie dans le fichier de config.  */
#define G_ERRRESSOURCE    0x2000  /* Nom de ressource inconnue  */
#define G_ERRPARAM        0x4000  /* Erreur parametre d'appel            */

/* Erreurs d'initialisation */
#define G_ERRFICHIERINI   0x8001  /* Fichier de configuration non trouve ou endommage */
#define G_ERRGALSSSRV     0x8002  /* Module GALSSSRV non trouve */
#define G_ERRDIMTABLES    0x8003  /* Dimensionnement des tables internes incorrect ( chargement de la table des ressources) */
#define G_ERRNOPROT       0x8004  /* Fichier de configuration errone : il manque la rubrique PROTOCOLE */
#define G_ERRBADPROT      0x8005  /* Fichier de configuration errone : le PROTOCOLE specifie est inconnu */
#define G_ERRLOADLIBPRO   0x8006  /* Fichier de configuration errone : probleme au chargement de la bibliotheque NOMLIB */
#define G_ERRNOINDEX      0x8007  /* Fichier de configuration errone : La rubrique INDEX ou TCANAL est absente ou erronee */
#define G_ERRNOCARAC      0x8008  /* Fichier de configuration errone : La rubrique CARACTERISTIQUES est absente ou erronee */
#define G_ERRNOPROINIT    0x8009  /* Initialisation de la communication avec le lecteur:impossible d'etablir un lien avec la fonction PROInit du Protocole */
#define G_ERRBADPROINIT   0x800A  /* Initialisation de la communication avec le lecteur:La fonction PRO_Init du Protocole retourne une erreur */
#define G_ERRNOPROCNX     0x800B  /* Connexion avec le lecteur:impossible d'etablir un lien avec la fonction PROConnect du Protocole */
#define G_ERRBADPROCNX    0x800C  /* Connexion avec le lecteur:La fonction PROConnect du Protocole retourne une erreur */
#define G_ERRNONBCANAUX   0x800D  /* Fichier de configuration errone : il manque la rubrique NBCANAUX */
#define G_ERRCOMPAT       0x800E  /* Erreur de compatibilite d'un ou plusieurs composants du GALSS */
#define G_ERRPADINVALID   0x800F  /* Numero de PAD invalide */
#define G_ERRLADINVALID   0x8010  /* Numero de LAD invalide */
#define G_ERRRESINVALID   0x8011  /* Nom de ressource ou d'alias invalide */
/* %v3.02 DREN 27/09/2000 : Gestion multi-protocoles */
#define G_ERRBADPRODCNX   0x8012  /* Deconnexion du lecteur:La fonction PRODisconnect du Protocole retourne une erreur */
#define G_ERRPROTERM      0x8013  /* Terminaison du protocole:La fonction PROTerm du Protocole retourne une erreur */
#define G_ERRLOADFUNCPRO  0x8014 /* Impossible d'etablir le lien avec les fonctions d'un protocole */
#define G_ERRCTX_GALSSV1  0x8020 /* Valeur réservée (ancien GALSS V1) */
/* %v3.02 DREN 27/09/2000 : Fin */

