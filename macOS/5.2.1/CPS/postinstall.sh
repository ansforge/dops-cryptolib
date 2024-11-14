#! /bin/bash
#--------------------------------------------------------------------
# Auteur : ASIP Sante
# Date   : voir ci-dessous
#--------------------------------------------------------------------
# Assistant pour une modification de l'installation de la Cryptolib 
# CPS pour MacOS
#--------------------------------------------------------------------

# Lance le script de desinstallation avec l’option d’affichage menu

LOCALPATH=$0
LOCALPATH=`dirname "${LOCALPATH}"`

if [ -f "${LOCALPATH}/uninstall.sh" ]
then
    #echo "local script"
    #exit
    "${LOCALPATH}/uninstall.sh" -m
elif [ -f "/Library/Application Support/santesocial/CPS/uninstall.sh" ]
then
    #echo `pwd`
    #echo "install script"
    #exit
    "/Library/Application Support/santesocial/CPS/uninstall.sh" -m
else
    echo "La Cryptolib CPS n'est pas installée sur ce poste de travail."
    echo "Veuillez l'installer pour pouvoir utiliser ce script."
fi

exit 0
