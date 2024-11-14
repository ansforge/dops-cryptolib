#include <stdio.h>
#include <string.h>
#include "pkcs11.h"

// Début du document MTML avec les styles CSS pour les statuts OK et KO
// et l'en-tete du tableau
#define HTML_HEADER "<html>\r\n\
<head><title>%s</title>\r\n\
<style type=\"text/css\">\r\n\
 body {background-color:#FDE9D9;}\r\n\
 tr {\r\n \
     font-family: Arial;\r\n\
     text-align:center;\r\n\
     font-size: 16px;}\r\n\
 th {\r\n\
      font-family: Arial;\r\n \
      text-align:center;\r\n \
      font-size: 16px;\r\n \
      background-color:lightgray;\r\n \
 }\r\n \
 .idOK, td.idOK, th.idOK{\r\n\
	font-family:Arial;\r\n\
	font-weight:normal;\r\n\
	font-size:16px;\r\n\
	color:#000000;\r\n\
	background-color:#C2D69A;\r\n\
  padding:2px 2px 2px 2px;\r\n\
  text-align:center;\r\n\
 }\r\n\
 .idKO, td.idKO, th.idKO{\r\n\
	font-family:Arial;\r\n\
	font-weight:normal;\r\n\
	font-size:16px;\r\n\
	color:#000000;\r\n\
	background-color:#de9992;\r\n\
  padding:2px 2px 2px 2px;\r\n\
  text-align:center;\r\n\
 }\r\n\
 .descr, td.descr{\r\n\
 text-align:left;\r\n\
 }\r\n\
</style>\r\n \
</head>\r\n \
<body>\r\n \
<div id='test' align=\"center\">\r\n \
<table border=\"1\" cellpadding=\"3\">\r\n \
<caption>%s</caption>\r\n \
<tr>\r\n \
<th>Num. test</th><th>Libell&eacute;</th><th>CR attendu</th><th>CR re&ccedil;u</th><th>Statut</th><th>Date du test</th> \
</tr>\r\n"

// Fin du document HTML
#define HTML_FOOTER "</table>\r\n</div>\r\n</body>\r\n</html>"

// Nom du fichier HTML des résultats
#define HTML_FILE_RESULTS "Resultats.HTML"

// Mode d'ouverture du fichier
#define HTML_FILE_MODE "ab+"

char bufFileName[128] = { 0 };
// handle du fichier de résultats
static FILE * prv_phFile;

static void htmlWriteHeader(char * pcTitle);

extern char * getErrorCodeString(CK_RV rv, char * strError);

// Ecrit le début du document HTML des résultats
// comprenant les styles CSS utilisés et l'en-tete du tableau des résultats
void htmlWriteHeader( ) {
  char * title = "R&eacute;sultats des tests";
  
  // supprime le fichier
  remove( bufFileName );
  // génère l'en-tete du document HTML avec un titre
  htmlWriteHeader(title);
  
}

static void htmlWriteHeader(char * pcTitle) {

  if (prv_phFile == NULL) {
    prv_phFile = fopen(bufFileName, HTML_FILE_MODE);
  }

  if (prv_phFile != NULL) {
     fprintf(prv_phFile, HTML_HEADER, pcTitle, pcTitle);

     fclose( prv_phFile );
     prv_phFile = NULL;
  }
}

// Ecrit le pied de page du document HTML
void htmlWriteFooter( ) {

  if (prv_phFile == NULL) {
    prv_phFile = fopen(bufFileName, HTML_FILE_MODE);
  }

  if (prv_phFile != NULL) {
     fprintf(prv_phFile, HTML_FOOTER);

     fclose( prv_phFile );
     prv_phFile = NULL;
  }
}

// Ecrit une ligne de résultat d'un test dans le tableau HTML
void htmlWriteTableRow( unsigned short __usTestNumero,  char * libelle,  unsigned long usExpectedRc, unsigned long usRc, char * strTime ) {

  char buffer[1024];
  char useStyle[32];
  char strExpRC[64];
  char strRC[64];

   strcpy(useStyle, "");
  if (usExpectedRc == usRc) {
    strcpy(useStyle, "class=\"idOK\"");
  }
  else {
    strcpy(useStyle, "class=\"idKO\"");
  }
  getErrorCodeString(usExpectedRc, strExpRC);
  getErrorCodeString(usRc, strRC);
  sprintf(buffer, "<tr><td>%4d</td><td class=\"descr\">%s</td><td class=\"descr\">%s</td><td class=\"descr\">%s</td><td %s>%s</td><td>%s</td></tr>", __usTestNumero, libelle, strExpRC, strRC, useStyle , (usExpectedRc == usRc) ? "OK" : "KO", strTime);

  if (prv_phFile == NULL) {
    prv_phFile = fopen(bufFileName, HTML_FILE_MODE);
  }

  if (prv_phFile != NULL) {
     fprintf(prv_phFile, "%s\r\n", buffer);

     fclose( prv_phFile );
     prv_phFile = NULL;
  }
}
