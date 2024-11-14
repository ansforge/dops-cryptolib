/*
*cps3pkcs11ver.h : Versioning header file
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

/*
---------------------------------------------------------------------------
  PROJET    : Cryptolib
 
  MODULE    : Version
 
  VERSION   : 1.00
 
  FICHIER   : cps3pkcs11ver.h
 
  Fichier contenant la version de libcps3_pkcs11_lux.so / libcps3_pkcs11_osx.dylib
 --------------------------------------------------------------------------
  Version 1.00

  AROC - 08/03/2011 - Creation
---------------------------------------------------------------------------
  Version 1.01
  
  AROC - 05/09/2012 - Prise en compte des différentes corrections et évolutions des sources communs
                      depuis 2010 realisées sous windows et mac. 
      08/08/2011 - Corrections dans l'interface Galss afin de remonter correctement les événements.
      15/11/2011 - Corrections/Evolutions :
        - Sauvegarder les fichiers de cache de la carte CPS3 dans le dossier %ALLUSERAPPDATA%/santesocial/cps/cache
        - Desactiver le mode bloquant dans la fonction C_WaitForSlotEvent
        - Suppression de la double lecture du fichier EF.SN.ICC lors de l'initialisation de la librairie.
        - Ne pas remonter le token de la carte CPS3 a Firefox.
        - Correction Anomalie 8043 - Pointeur NULL dans la fonction C_OpenSession
        - Correction Anomalie 8037 - Problème de vérification du code PIN
        - Correction Anomalie 8039 - Pointeur NULL dans la fonction C_GetMechanismList
        - Correction Anomalie 8038 - Problème de validation du SlotID.
        - En contexte multi-thread, bloquer la phase d'initialisation afin que les variables globales soient correctement positionnées
        - Filtrer l'ATR des cartes insérées dans les lecteurs pc/sc, afin de limiter les accès cartes.
      28-11-2011 - Correction du trap lorsque les traces sont actives.
      17-01-2012 - Correction de l'anomalie 8193 : Ajout de l'émulation du contexte ressource CPS.
      27-06-2012 - (@@MOD20120627) Correction de l'anomalie 8401.
        La carte CPS3 n'est pas reconnue si le card manager est sélectionné : 
        il n'y a pas re-sélection de l'application CPS2ter si les commandes ne sont pas reconnues (6E00)
      10-09-2012 - (@@20120907-xxxxx) Modification concernant la détection du retrait/insertion lecteur.
        Le polling de firefox sur le ou les lecteurs surchargeait l'appel à la couche Galss (sur OpenSession),
        ce qui avait comme conséquence de bloquer le navigateur. 
        Une détection réelle des lecteurs Galss est à présent réalisée que toutes les 5 secondes.
      27-06-2012 - Correction de l'annomalie 789 (@@20120723-0000789)
        Toujours effectuer la détection d'une carte         
  BPER - 15-10-2012 - Adaptations pour conformité vis a vis des specs. (@@20121015)
    Tests sur les pointeurs nuls dans les fonctions. 
    Dans C_SignInit, vérifier que l'utilisateur est loggé sur la session en cours
    Dans C_VerifyInit, vérifier dans le cadre de la gestion IAS la compatibilité de la clé publique d'authentification avec l'algo choisi
    Dans C_Verify, vérifier que la taille de la signature correspond au modulus bits de la clé publique
  AROC - 29/10/2012 : Ajout de la version de la librairie dans le binaire
  AROC - 30/10/2012 : Desactiver la detection de l'arrachement de lecteur sous Linux (@@20121030)
---------------------------------------------------------------------------
  Version 1.02 Mac 
  Version 1.03 Linux

  AROC - 14-12-2012 - vérifier qu'il ne manque pas des pointeurs dans C_Initialize (@@201212014)
  AROC - 12-02-2013 - Optimisation du code : suppression des reste d'implementation pour
                      compatibilité avec le Galss V4. (@@20130212-opti)
  BPER - 05-08-2013 - Anomalie Mantis 1075, sous Windows, prise en compte de l'arret de winscard en context RDP;(@@201308005-1075)
                       impossible de rouvrir une session RDP pour la 3e tentative
  AROC - 01-08-2013 - Supprimer les traces en francais. (@@20130801-1068)
  AROC - 07-08-2013 - En sans contact il doit être possible de signer sans se loguer (@@20130807-1088)
 --------------------------------------------------------------------------- 
 Version 1.03 Mac 
 Version 1.04 Linux

  AROC - 27-09-2013 - Mauvaise gestion du cache si celui-ci a ete altere (@@20130927-0001102)
  AROC - 02-10-2013 - Evolution : utilisation de la cle prive de siganture du volet CPS2 ter avec le mecanisme CKM_RSA_PKCS (@@20131002-0001104)
 ---------------------------------------------------------------------------
 Version 1.04 Mac 
 Version 1.05 Linux

 AROC - 01-08-2013 - Ne pas bloquer la carte quand les données sont lues en cache (@@20130801-1071)
 AROC - 09-10-2013 - Mauvais retour de C_GetSlotInfo pour une carte en panne dans un lecteur PSS (@@20130910-0001089)
 AROC - 02-04-2014 - Ouverture de sessions GALSS sans les refermer (@@20140402-0001144)
 AROC - 15-05-2014 - Memorisation de la table des ressources CPS* (@@20140515-1122)
 AROC - 19-05-2014 - Prise en compte du nouveau parametre du galss tpc_polling_time (@@20140519-0001155)
 ---------------------------------------------------------------------------
 Version 1.05 Mac
 Version 1.06 Linux
 AROC - 26/03/2015 -  : Patch cert signature unused bits (@@20150326-0001232)
 ---------------------------------------------------------------------------
 Version 1.07 Linux 32 & 64 bits
 AROC - 26/05/2015 - Identifier une carte CPS definitivement bloquee (@@20150526-0001175)
 BPER - 26/05/2015 - Lecture superflue des données de l'objet CPS_DATA lors d'un appel C_GetAttributeValue() avec pointeur NULL (@@20150526-0001226)
 ---------------------------------------------------------------------------
 Version 1.06 Mac
 AROC - 15/10/2014 - Utiliser la fonction ScardBeginTransaction pour identifier les evenements cartes (@@20141012-1192)
                     Prise en compte de l'état SCARD_STATE_INUSE positionné sous Yosemite, cet etat etait mal interprete
                     par la CryptoLib et qui par conséquence invalidait l’ensemble des session PKCS#11 ouvertes sur le lecteur.
 AROC - 13/08/2015 - Modification du repertoire par defaut du cache et
                     rendre le dossier de cache configurable (@@20150814-0001201)
 AROC - 13/08/2015 - Ne pas remonter d'erreur si le dossier de cache ne peut être cree (@@20150813-0001199)
 ---------------------------------------------------------------------------
 Version 1.09 Linux 32 & 64 bits
 Version 1.08 MAC OS X
 AROC - 07/12/2015 - Le contexte GALSS n'est pas mis a jour suite au retrait retait/insertion de la CAPS dans un TL 3.30+
 (@@20151110-1308) (Ano_1332_MAC & Ano_1333_Linux)
 AROC - 18/12/2015 - Correction des warnings (Ano_1345)
 ---------------------------------------------------------------------------
 Version 1.10 MAC OS X
 AROC - 25/01/2016 - Recompilation en mode Universel (32bits/64bits)(Ano_1349)
 ---------------------------------------------------------------------------
 Version 1.12.00 MAC OS X
 AROC - 12/01/2016 - Suite à un retrait/insertion carte le 1er appel à C_GetSlotList renvoie un nombre de slots avec token erroné (Ano_1347)
 ---------------------------------------------------------------------------
 Version 2.00 MAC OS X & LINUX
 AROC - 07/03/2017 - La signature des donnŽes avec les mŽchanismes CKM_SHA1_RSA_PKCS && CKM_SHA256_RSA_PKCS ne doit pas
                     ,�tre rŽalisŽe avec la commande Hash Off Card.
                   - Ajout de l'acc�s au DAM du volet CPS2ter. (Ano_1417)
 ---------------------------------------------------------------------------
 Version 2.01 MAC OS X & 2.00 LINUX
 BPER - 07/04/2017 - Dans le cas du hashOffCard, gerer la suppression éventuelle du DigestInfo des données à signer
                     lorsque le mécanisme CKM_RSA_PKCS est utilisé.
                   - Gestion particulière de condensat avec les appels C_Digest \ C_DigestFinal
 ---------------------------------------------------------------------------
 Version 2.02 MAC OS X & 2.01 LINUX
 BPER - 26/07/2017 - Rendre parametrable le repertoire des logs dans le fichier cps3_pkcs11.conf
 ---------------------------------------------------------------------------
 Version 2.03 MAC OS X & 2.02 LINUX
 BPER - 14/11/2017 - Gestion de l'ATR dans le contexte GALSS pour certains lecteurs Vitale
 ---------------------------------------------------------------------------
 Version 2.04 MAC OS X & 2.03 LINUX
 AROC - 29/11/2017 - Retour incorrect de C_GetSlotList et C_GestSlotInfo lorsque le TLA est débranché (Anomalie 1480)
---------------------------------------------------------------------------
 Version 2.05 MAC OS X & 2.04 LINUX
 BPER - 06/04/2018 - Réduction des noms de lecteurs PC/SC par la librairie PKCS11 (Anomalie 1532/1530)
 BPER - 06/04/2018 - Autoriser le déchiffrement avec la clé d'authentification    (Anomalie 1526)
---------------------------------------------------------------------------
 Version 2.06 MAC OS X & 2.05 LINUX
 BPER - 14/12/2018 - Retour CKR_TOKEN_NOT_PRESENT au lieu de CKR_GENERAL_ERROR dans certains cas (Anomalie 1573)
---------------------------------------------------------------------------
 Version 2.06.01 MAC OS X & 2.05.01 LINUX
 BPER - 24/04/2019 - Ajout des fonctions de Mise a jour de la carte CPS (Evolution 1534)
---------------------------------------------------------------------------
 Version 2.06.02 MAC OS X
 BPER - 19/09/2019 - Suppression des adherences au framwork Java.ñè
 ---------------------------------------------------------------------------
 Version 2.07 MAC OS X & 2.06 LINUX
 BPER - 11/07/2019 - Carte non dŽtectŽe suite ˆ une absence de rŽponse temporaire d'un lecteur PSS (Anomalie 1598), Passage en Full 64b (Anomalie 1596)
 ---------------------------------------------------------------------------
 Version 2.08 MAC OS X
 AROC - 20/01/2021 - Version de test ARM
 ---------------------------------------------------------------------------
 Version 2.09 MAC OS X
 AROC - 26/01/2021 - Version finale ARM
 ---------------------------------------------------------------------------
 Version 2.10 MAC OS X
 AROC - 19/02/2021 - Detection de l'exécution en mode sandbox afin de pouvroir créer les fichier de cache
  - Prise en compte du paramètre "cpsUpdate" à l'appel de C_Initialize nécessaire au CPSAgent :
  > lire uniquement les informations nécessaires
  > Ne pas remonté les cartes en sans contact (le processus de mise à jour nécessite l'insertion de la carte en contact
  > Optimisation des accès carte lors de l'insetion dans un lecteur
 ---------------------------------------------------------------------------
 Version 2.11 MAC OS X
 AROC - 06/10/2021 - Changer le chemin d'installation dans le projet xcode /usr/local/lib
 AROC - 07/10/2021 - ne pas prendre en compte la modification (1629)
 AROC - 17/10/2022 - Tracer dans le dossier ~/Library/Logs/santesocial/CPS (1677-1678)
 ---------------------------------------------------------------------------
 Version 3.00 MAC OS X - Portage version Windows avec :
 AROC - 13/05/2024 - 0001711: Exposer des labels PKCS11 pour les donnÈes de situation du volet CPS2TER (1 ‡  16 fichiers)
 AROC - 13/05/2024 - 0001714: Support de la carte CPSv4
 AROC - 24/05/2024 - 00017xx: implÈmenter l'internal authenticate (RSA_PKCS) via le dÈchiffrement avec la CPS 4
 AROC - 29/05/2024 - ajout d'un second ATR de la CPS4 forÁant le T=0
 AROC - 29/05/2024 - definir le status word de donnÈes ‡ lire.
 ---------------------------------------------------------------------------
 Version 3.01 MAC OS X - Correction ano 1722
 ---------------------------------------------------------------------------*/


#ifndef CPS3PKCSVERH
#define CPS3PKCSVERH
/*
% Bibliotheque
% ------------
*/

/*
% Macros
% ------
*/

/*
% Declaration des inclusions
% --------------------------
*/

/*
% Declaration de la version
% --------------------------
*/
/* !! Attention: ne pas oublier d'incrementer les versions ascii ET binaires !! */
#ifdef __APPLE__
#define STR_COMPLETE_VERSION             "03.01.00"
#define BINARY_VERSION_MAJOR          3
#define BINARY_VERSION_MINOR          1
#define BINARY_VERSION_RELEASE        0


#define PKCS_STR_PRODUCT   "CPS3 PKCS#11 MACOSX"
#endif

#ifdef UNIX_LUX
#define STR_COMPLETE_VERSION             "03.01.00"
#define BINARY_VERSION_MAJOR          3
#define BINARY_VERSION_MINOR          1
#define BINARY_VERSION_RELEASE        0


#define PKCS_STR_PRODUCT   "CPS3 PKCS#11 LINUX"
#endif

#define CPS_PKCS_COPYRIGHT     "Copyright © 2003-2024 ANS"
#define CPS_PKCS_COMPANY_NAME  "ANS"

#define GETINFO_PKCS_STR_PRODUCT PKCS_STR_PRODUCT

#ifdef __APPLE__
#ifdef _DEBUG
#define CPS3_PKCS_VER_COMMENT   "CPS3 PKCS#11 MACOSX (Version Debug)"
#else
#define CPS3_PKCS_VER_COMMENT   "CPS3 PKCS#11 MACOSX (Version Release)"
#endif

#endif

#ifdef UNIX_LUX
#ifdef _DEBUG
#define CPS3_PKCS_VER_COMMENT   "CPS3 PKCS#11 LINUX (Version Debug)"
#else
#define CPS3_PKCS_VER_COMMENT   "CPS3 PKCS#11 LINUX (Version Release)"
#endif
#endif
#define CPS3_PKCS_VER_VERSION   "##[ProductVersion  " STR_COMPLETE_VERSION __DATE__ " " __TIME__
#define CPS3_PKCS_VER_NAME      "##[ProductName "PKCS_STR_PRODUCT

extern char CPS3PKCSVerComment[];
extern char CPS3PKCSVerVersion[];
extern char CPS3PKCSVerName[];
#endif
