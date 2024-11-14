/*
* system.c : System dependent functions
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
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>


/* AROC - 29/10/2012 : Ajout de la version de la librairie dans le binaire : Debut*/
#include "cps3pkcs11ver.h"
char CPS3PKCSVerComment[]=CPS3_PKCS_VER_COMMENT;
char CPS3PKCSVerVersion[]=CPS3_PKCS_VER_VERSION;
char CPS3PKCSVerName[]=CPS3_PKCS_VER_NAME;


/* MCUG 09/11/2010 : Fonction de récupération des fichiers de cache à supprimer */
int sc_get_card_cached_files(const char *_path, const char *serialNumber, char ***cached_files, int* size) {

	DIR *rep1 = opendir(_path);
	DIR *rep2 = opendir(_path);
	char file_path[260];
	int i = 0;
	
	if (rep1 != NULL) {
		struct dirent * ent;
	
		*size = 0;
		
		while ((ent = readdir(rep1)) != NULL)
			// Considers only the cached file that belongs to the given card and avoid removing the EF_DIR file
			if(strstr(ent->d_name,serialNumber) != NULL
				&& strstr(ent->d_name,"2F00") == NULL)
				(*size)++;

		if(rep1 != NULL)
			closedir(rep1);
		
	}
	
	if (rep2 != NULL) {
		struct dirent * ent;	
	
		// cached_files allocation 
		*cached_files = (char **) malloc((*size)*sizeof(char*));
		if(*cached_files == NULL)
			return 1;				
				
		rep2 = opendir(_path);

		while ((ent = readdir(rep2)) != NULL) {
			// Considers only the cached file that belongs to the given card and avoid removing the EF_DIR file
			if(strstr(ent->d_name,serialNumber) != NULL
				&& strstr(ent->d_name,"2F00") == NULL) {
				(*cached_files)[i] = (char *) malloc(sizeof(ent->d_name));
				strcpy(file_path,_path);
				strcat(file_path,ent->d_name);
				strcpy((*cached_files)[i],file_path);
				i++;				
			}
		}
		
		if(rep2 != NULL)
			closedir(rep2);
	}

	
	return 0;	
	
}

/* MCUG 09/11/2010 : FIN */
