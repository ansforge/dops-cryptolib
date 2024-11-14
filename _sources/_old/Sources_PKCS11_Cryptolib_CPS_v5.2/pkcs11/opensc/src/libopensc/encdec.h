/*
* encded.h : cipher functions header file
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
*
* Partially based on the ISO7816 driver.
*
*/
#include "types.h"
#include "opensc.h"
 
/* AROC 07/03/2011 : la methode systeme encrypt existe sous MACOSX, encrypt devient opensc_encrypt */
/*                   et donc par convention decrypt devient opensc_decrypt                         */

/* AROC - (@@20130927-0001102) - Debut */
void opensc_encrypt(sc_card_t *card, u8 *Msg, u8 **ppOut, size_t *size, u8 *control_data, int control_data_len);
void opensc_decrypt( sc_card_t *card, u8 *Msg, u8 **ppOut, size_t *size, u8 *control_data, int control_data_len);
/* AROC - (@@20130927-0001102) - Fin */

