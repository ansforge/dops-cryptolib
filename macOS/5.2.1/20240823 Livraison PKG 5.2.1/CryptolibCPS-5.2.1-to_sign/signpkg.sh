#!/bin/bash
#
# Script de signature d'un pkg sous MAC.
#

BAD_PARAMS="0"
PRODNAME="CryptolibCPS"
DEV_ID_INST_CERT="Developer ID Installer"
APPLE_ID="laurent.ragain@esante.gouv.fr"
TEAM_ID="Y8WQ8FQ7KH"
XRUN_PWD="lznw-hbmp-efsn-gqzi"
clear

mk_sign()
{

  test -z "$1" && echo "mk_sign - Erreur : package d'entrée non spécifié" && return 0
  test -z "$2" && echo "mk_sign - Erreur : package de sortie non spécifié" && return 0

  echo "productsign --timestamp --sign $DEV_ID_INST_CERT $1 $2"
  productsign --timestamp --sign "$DEV_ID_INST_CERT" "$1" "$2"

  if [ -f "$2" ]
  then
    echo ""
    echo "------------ Validation de la signature du package : $2"
    pkgutil --check-signature "$2"
    return 1
  fi
    return 0
}




test -z "$1" && BAD_PARAMS="1" && PARAM_ERR="Pas de numero de version du Package"
if test "$BAD_PARAMS" = "1"
then
	echo " "
	echo "***** Erreur : $PARAM_ERR *****"
	echo " "
	echo "----------------------------------------------------------------------------"
	echo "Usage  : $0 param1"
	echo " "
	echo "  Param1 : Version du package à signer au format :                  [ X.Y.Z ]"
	echo " "
	echo "  Exemple: $0 5.0.34"
	echo " "
	echo "----------------------------------------------------------------------------"
	echo " "
	echo " "
	exit
else
  VERSION="$1"
  DISTPATH="."
  UNSIGNED_PKG="$DISTPATH/$PRODNAME-$VERSION-unsigned.pkg"
  SIGNED_PKG="$DISTPATH/$PRODNAME-$VERSION.pkg"
  DMGNAME="$DISTPATH/$PRODNAME-$VERSION.dmg"
  DMGDIR="$DISTPATH/$PRODNAME-$VERSION"
  BUNDLE_ID="$PRODNAME-$VERSION"
fi

echo "----------------------------------------------------------------------------"
echo " Processus de signature et de création du dmg"
echo "----------------------------------------------------------------------------"
echo ""

#cleanup
test -f $SIGNED_PKG && rm -f $SIGNED_PKG && echo "- $SIGNED_PKG supprimé"
test -f $DMGNAME && rm -f $DMGNAME && echo "- $DMGNAME supprimé"
test -d $DMGDIR && rm -fR $DMGDIR && echo  "- $DMGDIR supprimé"


echo "------------ Recherche du package à signer..."
test ! -f "$UNSIGNED_PKG" && echo "" && echo "***** Erreur : $UNSIGNED_PKG absent *****" && echo "" && exit
echo "------------ $UNSIGNED_PKG trouvé"

echo ""
echo "------------ Signature du package : $UNSIGNED_PKG..."
mk_sign "$UNSIGNED_PKG" "$SIGNED_PKG" && exit


echo ""
echo "------------ Notarisation du package : $SIGNED_PKG..."
# notarize
xcrun notarytool submit $SIGNED_PKG --apple-id $APPLE_ID --team-id $TEAM_ID --password $XRUN_PWD --wait
echo ""
echo "------------ Creation du DMG : $DMGNAME..."


# make the dmg directory
mkdir $DMGDIR
mv $SIGNED_PKG $DMGDIR/

hdiutil create -format UDRO -srcfolder ./$DMGDIR $DMGNAME

test -d $DMGDIR && rm -fR $DMGDIR

echo ""
echo "------------ SHA1 du DMG : $DMGNAME..."
shasum $DMGNAME > "./$DMGNAME-sha1.txt"
