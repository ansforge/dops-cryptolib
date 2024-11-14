/*
* opensc_conf.h: default configuration
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

#define OPENSC_CONFIG_STRING "app default { \
  debug = 0; \
  reader_drivers = pcsc,galss,internal; \
  reader_driver pcsc { \
    apdu_masquerade = case4as3; \
    connect_reset = false; \
  } \
   \
  reader_driver galss { \
    apdu_masquerade = case4as3; \
    tpc_polling_time = 2000 \
  } \
   \
   \
  card_drivers = cps3; \
  card_driver cps3 { \
    no_cache_file_list = 0001D107\
  } \
  card_drivers = cps4; \
  card_driver cps4 { \
    no_cache_file_list = 0001D107\
  } \
   \
  framework pkcs15 { \
    use_caching = false; \
    enable_pkcs15_emulation = no; \
    try_emulation_first = no; \
    enable_builtin_emulation = no; \
  }  \
   \
}  \
  \
app opensc-pkcs11 { \
  pkcs11 { \
    num_slots = 1; \
    hide_empty_tokens = true; \
    lock_login = false; \
    cache_pins = true; \
    soft_keygen_allowed = false; \
  } \
}"
