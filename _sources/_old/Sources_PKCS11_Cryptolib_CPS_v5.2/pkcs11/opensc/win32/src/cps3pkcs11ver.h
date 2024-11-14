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
%---------------------------------------------------------------------------
% PROJET    : Cryptolib
%
% MODULE    : Version
%
% VERSION   : 1.00
%
% FICHIER   : cps3pkcs11ver.h
%
% Fichier contenant la version de cps3_pkcs11_win32
% --------------------------------------------------------------------------
% Version 1.00
%
% CLCO - 02/06/2010 - Creation
%---------------------------------------------------------------------------
% Version 1.03
%
% AROC - 08/08/2011 - Corrections : 
%                      1/ dans l'interface pcsc pour la compatibilite Citrix.
%                      2/ dans l'interface galss afin de remonter correctement les
%                         evenements.
%---------------------------------------------------------------------------
% Version 1.04 : 
% AROC - 15/11/2011 - Corrections/Evolutions :
%    - Sauvegarder les fichiers de cache de la carte CPS3 dans le dossier %ALLUSERAPPDATA%/santesocial/cps/cache
%    - Desactiver le mode bloquant dans la fonction C_WaitForSlotEvent
%    - Suppression de la double lecture du fichier EF.SN.ICC lors de l'initialisation de la librairie.
%    - Ne pas remonter le token de la carte CPS3 a Firefox.
%    - Correction Anomalie 8043 - Pointeur NULL dans la fonction C_OpenSession
%    - Correction Anomalie 8037 - Problème de verification du code PIN
%    - Correction Anomalie 8039 - Pointeur NULL dans la fonction C_GetMechanismList
%    - Correction Anomalie 8038 - Problème de validation du SlotID.
%    - En context multi-thread, bloquer la phase d'initialisation afin que les variables globales soient correctement positionée
%    - Filtrer l'ATR des carte insérées dans les lecteurs pc/sc, afin de limiter les accès cartes.
%---------------------------------------------------------------------------
% Version 1.05 : 
% AROC - 28-11-2011 - Correction du trap lorsquer les traces sont actives.
%---------------------------------------------------------------------------
% Version 1.06 : 
% AROC - 17-01-2012 - Correction de l'anomalie 8193 :
%                     Ajout de l'emulation du context ressource CPS.
%---------------------------------------------------------------------------
% Version 1.07 :
% AROC - 15-02-2012 - Suppression de la boite de dialoque de debug sur l'acces au galss info.
%---------------------------------------------------------------------------
% Version 1.08 : (@@MOD20120627)
% AROC - 27-06-2012 - Correction de l'annomalie 8401.
%   La carte CPS3 n'est pas reconnue si le card manager est sélectionné : 
%   il n'y a pas reselection de l'application CPS2ter si les commandes ne sont pas reconnue (6E00)
%---------------------------------------------------------------------------
% Version 1.09 :
% AROC - 27-06-2012 - Correction de l'annomalie 789 (@@20120723-0000789)
%   Toujours effectuer la détection d'une carte 
% BPER - 15-10-2012 - Adaptations pour conformité vis a vis des specs. (@@20121015)
%   Tests sur les pointeurs nuls dans les fonctions. 
%   Dans C_SignInit, vérifier que l'utilisateur est loggé sur la session en cours
%   Dans C_VerifyInit, vérifier dans le cadre de la gestion IAS la compatibilité de la clé publique d'authentification avec l'algo choisi
%   Dans C_Verify, vérifier que la taille de la signature correspond au modulus bits de la clé publique
% AROC - 08-11-2012 - rajout du pragma pack pour Windows. (@@20121108)
% AROC - 12-11-2012 - vérifier la cohérence des données à tracer (@@20121109)
%---------------------------------------------------------------------------
% Version 1.10:
% AROC - 14-12-2012 - vérifier qu'il ne manque pas des pointeurs dans C_Initialize (@@201212014)
% AROC - 12-02-2013 - Optimisation du code : suppression des reste d'implementation pour
%                     compatibilité avec le Galss V4. (@@20130212-opti)
% BPER - 05-08-2013 - Anomalie Mantis 1075, sous Windows, prise en compte de l'arret de winscard en context RDP;(@@201308005-1075)
%                      impossible de rouvrir une session RDP pour la 3e tentative
% AROC - 01-08-2013 - Supprimer les traces en francais. (@@20130801-1068)
% AROC - 07-08-2013 - En sans contact il doit être possible de signer sans se loguer (@@20130807-1088)
%---------------------------------------------------------------------------
% Version 1.10.1
% AROC - 24-09-2013 - Ajout du Copyright et le bon nom de fichier dans les infos de la librairie (@@20130924-0001096)
% Version 1.10.2
% AROC - 24-09-2013 - Re-faire un SCardBeginTransaction après reconnection lors de la prise en exclusivité de la carte en PC/SC (@@20130924-0001097)
% Version 1.10.3
% AROC - 27-09-2013 - Mauvaise gestion du cache si celui-ci a été altéré (@@20130927-0001102)
% Version 1.10.4
% AROC - 02-10-2013 - Evolution : utilisation de la clé privé de siganture du volet CPS2 ter avec le mecanisme CKM_RSA_PKCS (@@20131002-0001104)
% Version 1.11:
% AROC - 11-10-2013 - Version Finale qui integre les modifications 1.10-1 à 1.10.4
% Version 1.12:
% AROC - 18-10-2013 - Problème d'identification de la CPS3 lors de l'aiguillage de la signature
% Version 1.13:
% AROC - 24-10-2013 - Coquille sur la récupération de la variable traces sous windows depuis que le paramètre 
%                     Sign_Hash est crée par l'installeur. (@@20131024-0001104-2)
%---------------------------------------------------------------------------
% Version 1.14:
% AROC - 01-08-2013 - Ne pas bloquer la carte quand les données sont lues en cache (@@20130801-1071)
% AROC - 09-10-2013 - Mauvais retour de C_GetSlotInfo pour une carte en panne dans un lecteur PSS (@@20130910-0001089)
% BPER - 10-12-2013 - En mode EPM sous Win8, creer le cache & les traces dans le répertoire TEMP de IE Metro avec l'appel GetTempPath() (@@20131210-0001135)
% AROC - 02-04-2014 - Ouverture de sessions GALSS sans les refermer (@@20140402-0001144)
% AROC - 19-05-2014 - Passage du parametre debug en DWORD sous windows (@@20140519-0001114)
% AROC - 15-05-2014 - Memorisation de la table des ressources CPS* (@@20140515-1122)
% AROC - 19-05-2014 - Prise en compte du nouveau parametre du galss tpc_polling_time (@@20140519-0001155)
% BPER - 28-05-2014 - Tester si le chemin vers %ALLUSERSPROFILE% est réellement trouvé (cas du mode EPM sous IE en Windows 8) (@@20140528-1135)
%---------------------------------------------------------------------------
% Version 1.14.5
% BPER - 16-02-2015 - Lecture superflue des données en requete 'size only' (@@20150216-1226)
%---------------------------------------------------------------------------
% Version 1.15 		- Initialement prévu dans une livraison a été avortée
%---------------------------------------------------------------------------
% Version 1.16 
% BPER - 23-03-2015 - Patcher l'octet Unused bits (@@20150323-00001232)
%---------------------------------------------------------------------------
% Version 1.17
% AROC - 31-07-2014 - Prise en compte des correction de l'anomalie 1027 pour l'anomalie 1181
% AROC - 25-06-2014 - Impossible d’identifier une carte CPS3 bloquée lorsque le nombre de maximum de déblocage a été atteint. (@@20140625-1175)
% AROC - 02/07/2014 - Correction (@@20140702-1177) - Les détails des fichiers ne sont pas cohérents
% BPER - 16-02-2015 - Lecture superflue des données en requete 'size only' (@@20150216-1226)
% BPER - 06-10-2014 - Reconnection PC/SC en contexte TSE/Smartcard Logon avec la partie contactless - anomalie 1196
% BPER - 26-01-2015 - Optimisations en contexte TSE/Smartcard Logon  - anomalie 1214
%---------------------------------------------------------------------------
% Version 1.18
% AROC - 10/11/2015 - Mettre à jour le compteur d'état dans le contexte ressource. (@@20151110-1308)
%---------------------------------------------------------------------------
% Version 1.19
% AROC - 13/01/2016 - Suite à un retrait/insertion carte le 1er appel à C_GetSlotList renvoie un nombre de slots avec token erroné (@@20160113-1347)
% AROC - 07/03/2016 - C_GetTokenInfo renvoit les informations de la carte précédente lors d'un appel à la librairie PKCS#11 via RDP 8. (@@20160307-1359)
% BPER - 25/05/2016 - Le calcul de signature n'est pas performant quand le calcul de Hash passe par la lib PKCS#11 - anomalie 1266
% BPER - 02/06/2016 - Reselectionner l'application IAS CPS (@@20160602-1359)
% BPER - 08/06/2016 - Reselectionner l'application IAS CPS lors de chaque do_single_transmit (@@20160608-1359)
% BPER - 08/06/2016 - C_GetTokenInfo voit parfois la CPS3 comme une CPS2ter - anomalie 1362
% BPER - 09/06/2016 - En GALSS, positionner le protocole SC_PROTO_T0 au niveau du slot pour avoir les apdus 'select' corrects dans les traces (@@20160609-1359)
%---------------------------------------------------------------------------
% Version 1.20
% AROC - 20/09/2016 - Correction concernant la non détection d'une carte CPS3 lorsque le cache cps3 à été alimenté par les données
%                     venant du volet 2ter (bascule sur le driver carte CPS2ter)
%---------------------------------------------------------------------------
% Version 2.00
% AROC - 18/10/2016 - Accès DAM (1416/1417/1418)
% AROC - 18/10/2016 - Implémenter la commande PSO Hash Off Card  (1375)
% BPER - 08/11/2016 - Solution C pour le SmartCard Logon TSE (1381/1195/1218)
% BPER - 06/12/2016 - Affichage version d'OpenSC (1396)
%---------------------------------------------------------------------------
% Version 2.01
% BPER - 05/01/2017 - Ré-intégration de la correction du ticket 1413 (Correction concernant la non détection d'une carte CPS3 ...)
%---------------------------------------------------------------------------
% Version 2.02
% BPER - 11/01/2017 - Ré-intégration de la correction du ticket 1135 (Support du cache et logs en contexte Edge / EPM)
%---------------------------------------------------------------------------
% Version 2.03
% BPER - 30/01/2017 - Lecteurs PSS qui mettent sous tension la carte CPS: gestion de l'absence d'ATR dans le contexte GALSS.
%---------------------------------------------------------------------------
% Version 2.04
% BPER - 27/02/2017 - Suppression du paramétrage d'initialisation 'hashOffCard'; la fonctionnalié est activée par défaut.
%---------------------------------------------------------------------------
% Version 2.05
% AROC - 07/03/2017 - La signature des données avec les méchanismes CKM_SHA1_RSA_PKCS && CKM_SHA256_RSA_PKCS ne soit pas 
%                     être réalisée avec la commande Hash Off Card.
%
%---------------------------------------------------------------------------
% Version 2.06
% AROC - 05/04/2017 - Suppression des emissions de logs dans les fonctions de gestion des mutexes.
%---------------------------------------------------------------------------
% Version 2.07
% BPER - 07/04/2017 - Dans le cas du hashOffCard, gerer la suppression éventuelle du DigestInfo des données à signer
%                     lorsque le mécanisme CKM_RSA_PKCS est utilisé.
%                   - Gestion particulière de condensat avec les appels C_Digest \ C_DigestFinal
%---------------------------------------------------------------------------
% Version 2.08
% AROC - 08/11/2017 - Différences d’initialisation du contexte GALSS entre la v5.0.34 et la v5.0.35 (Anomalie 1484)
%---------------------------------------------------------------------------
% Version 2.09
% AROC - 29/11/2017 - Retour incorrect de C_GetSlotList et C_GestSlotInfo lorsque le TLA est débranché (Anomalie 1480)
%---------------------------------------------------------------------------
% Version 2.10
% BPER - 05/03/2018 - Autoriser le déchiffrement avec la clé privée d'authentification hors Winlogon (Evolution 1526)
%---------------------------------------------------------------------------
% Version 2.11
% AROC - 19/11/2018 - Retour CKR_GENERAL_ERROR au lieu de CKR_TOKEN_NOT_PRESENT (Anomalie 1460)
%---------------------------------------------------------------------------
% Version 2.11.1
% AROC - 05/04/2019 - Support de la mise a jour des cartes CPS (Evolution 1533)
%---------------------------------------------------------------------------
% Version 2.11.2
% AROC - 08/11/2019 - Suppression du pont JNI.
%---------------------------------------------------------------------------
% Version 2.12
% AROC - 20/06/2019 - Ré-ouverture de session pkcs suite a un deb.rebranchement de lecteur PSS (Anomalie 1589)
%---------------------------------------------------------------------------
% Version 2.13
% AROC - 18/05/2021 - Problème de détection d'évènement (Anomalie 1629)
%---------------------------------------------------------------------------
% Version 3.00
% AROC - 13/05/2024 - 0001711: Exposer des labels PKCS11 pour les données de situation du volet CPS2TER (1 à 16 fichiers)
% AROC - 13/05/2024 - 0001714: Support de la carte CPSv4 
%---------------------------------------------------------------------------
% Version 3.01
% AROC - 24/05/2024 - 00017xx: implémenter l'internal authenticate (RSA_PKCS) via le déchiffrement avec la CPS 4
% AROC - 29/05/2024 - ajout d'un second ATR de la CPS4 forçant le T=0
%---------------------------------------------------------------------------
% Version 3.02
% AROC - 29/05/2024 - definir le status word de données à lire.
%---------------------------------------------------------------------------
% Version 3.02.01
% BPER - 12/06/2024 - 0001715: Implémenter le chiffrement RSA via OpenSSL.
% --------------------------------------------------------------------------
% Version 3.03.00
% BPER - 18/06/2024 - 0001715: C_Encrypt: gestion des erreurs CKR_ARGUMENT_BAD & CKR_BUFFER_TOO_SMALL.
% --------------------------------------------------------------------------
% Version 3.04.00
% BPER - 23 / 07 / 2024 - 0001722: Re select CPS4 AID on chanel One 
% --------------------------------------------------------------------------
*/

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
#define STR_COMPLETE_VERSION             "03.04.00"
#define BINARY_VERSION_MAJOR          3
#define BINARY_VERSION_MINOR          4
#define BINARY_VERSION_RELEASE        0
#define YEAR                             "2024"


/////////////////////////////////
// !!!! LA VERSION DITE "A VALIDER" DOIT ETRE COMPLIE AVEC CE DEFINE
/////////////////////////////////

//#define A_VALIDER                     0

#ifndef A_VALIDER
  #ifdef _DEBUG 
    #define VERSION_TYPE "Version Debug"
  #else
    #define VERSION_TYPE "Version Release"
  #endif
#else
#pragma message("!!!!  COMPILATION DE LA VERSION DITE - A VALIDER - !!!!")
  #define VERSION_TYPE "VERSION DE TEST"
#endif


#ifdef _WIN64
#define ARCH_TYPE            "WIN 64"
#define CPS_ORIGINALFILENAME "cps3_pkcs11_w64.dll"
#else
#define ARCH_TYPE            "WIN 32"
#define CPS_ORIGINALFILENAME "cps3_pkcs11_w32.dll"
#endif
#define CPS_PKCS_COMPANY_NAME  "ANS"
#define CPS_PKCS_COPYRIGHT     "Copyright © 2003-" YEAR " " CPS_PKCS_COMPANY_NAME

#define CPS_PKCS_VER_COMMENT   "Librairie PKCS#11 de la carte CPS3/CPS4 " ARCH_TYPE " (" VERSION_TYPE ")"
#define PKCS_STR_PRODUCT   "CPS3 PKCS#11 " ARCH_TYPE  " (" VERSION_TYPE ")"
#define GETINFO_PKCS_STR_PRODUCT "CPS3 PKCS#11 " ARCH_TYPE

#define CPS_PKCS_VER_VERSION   "##[ProductVersion  " STR_COMPLETE_VERSION __DATE__ " " __TIME__
#define CPS_PKCS_VER_NAME      "##[ProductName  " PKCS_STR_PRODUCT

extern char CPSPKCSVerComment[];
extern char CPSPKCSVerVersion[];
extern char CPSPKCSVerName[];
#endif
