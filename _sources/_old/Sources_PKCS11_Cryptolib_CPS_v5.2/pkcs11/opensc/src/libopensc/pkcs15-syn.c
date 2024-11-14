/*
 * pkcs15-syn.c: PKCS #15 emulation of non-pkcs15 cards
 *
 * Copyright (C) 2003  Olaf Kirch <okir@suse.de>
 *               2004  Nils Larsch <nlarsch@betrusted.com>
  * Copyright (C) 2010-2016  ASIP Santé
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
#include "pkcs15.h"
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>


static struct {
  const char *    name;
  int      (*handler)(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);
} builtin_emulators[] = {
  { NULL, NULL }
};

static int parse_emu_block(sc_pkcs15_card_t *, scconf_block *);
static const char *builtin_name = "builtin";
static const char *func_name    = "sc_pkcs15_init_func";
static const char *exfunc_name  = "sc_pkcs15_init_func_ex";


int sc_pkcs15_is_emulation_only(sc_card_t *card)
{
  return 0;
}

int
sc_pkcs15_bind_synthetic(sc_pkcs15_card_t *p15card)
{
  sc_context_t    *ctx = p15card->card->ctx;
  scconf_block    *conf_block, **blocks, *blk;
  sc_pkcs15emu_opt_t  opts;
  int      i, r = SC_ERROR_WRONG_CARD;

  SC_FUNC_CALLED(ctx, 1);
  memset(&opts, 0, sizeof(opts));
  conf_block = NULL;

  conf_block = sc_get_conf_block(ctx, "framework", "pkcs15", 1);

  if (!conf_block) {
    /* no conf file found => try bultin drivers  */
    sc_debug(ctx, "no conf file (or section), trying all builtin emulators\n");
    for (i = 0; builtin_emulators[i].name; i++) {
      sc_debug(ctx, "trying %s\n", builtin_emulators[i].name);
      r = builtin_emulators[i].handler(p15card, &opts);
      if (r == SC_SUCCESS)
        /* we got a hit */
        goto out;
    }
  } else {
    /* we have a conf file => let's use it */
    int builtin_enabled; 
    const scconf_list *list, *item;

    builtin_enabled = scconf_get_bool(conf_block, "enable_builtin_emulation", 1);
    list = scconf_find_list(conf_block, "builtin_emulators"); /* FIXME: rename to enabled_emulators */

    if (builtin_enabled && list) {
      /* get the list of enabled emulation drivers */
      for (item = list; item; item = item->next) {
        /* go through the list of builtin drivers */
        const char *name = item->data;

        sc_debug(ctx, "trying %s\n", name);
        for (i = 0; builtin_emulators[i].name; i++)
          if (!strcmp(builtin_emulators[i].name, name)) {
            r = builtin_emulators[i].handler(p15card, &opts);
            if (r == SC_SUCCESS)
              /* we got a hit */
              goto out;
          }
      }  
    }
    if (builtin_enabled) {
      sc_debug(ctx, "no emulator list in config file, trying all builtin emulators\n");
      for (i = 0; builtin_emulators[i].name; i++) {
        sc_debug(ctx, "trying %s\n", builtin_emulators[i].name);
        r = builtin_emulators[i].handler(p15card, &opts);
        if (r == SC_SUCCESS)
          /* we got a hit */
          goto out;
      }
    }

    /* search for 'emulate foo { ... }' entries in the conf file */
    sc_debug(ctx, "searching for 'emulate foo { ... }' blocks\n");
    blocks = scconf_find_blocks(ctx->conf, conf_block, "emulate", NULL);
    for (i = 0; blocks && (blk = blocks[i]) != NULL; i++) {
      const char *name = blk->name->data;
      sc_debug(ctx, "trying %s\n", name);
      r = parse_emu_block(p15card, blk);
      if (r == SC_SUCCESS) {
        free(blocks);
        goto out;
      }
    }
    if (blocks)
      free(blocks);
  }
    
  /* Total failure */
  return SC_ERROR_WRONG_CARD;

out:  if (r == SC_SUCCESS) {
    p15card->magic  = SC_PKCS15_CARD_MAGIC;
    p15card->flags |= SC_PKCS15_CARD_FLAG_EMULATED;
  } else if (r != SC_ERROR_WRONG_CARD) {
    sc_error(ctx, "Failed to load card emulator: %s\n",
        sc_strerror(r));
  }

  return r;
}

static int emu_detect_card(sc_card_t *card, const scconf_block *blk, int *force)
{
  int ret = 0;

  /* TBD */

  return ret;
}

static int parse_emu_block(sc_pkcs15_card_t *p15card, scconf_block *conf)
{
  sc_card_t  *card = p15card->card;
  sc_context_t  *ctx = card->ctx;
  sc_pkcs15emu_opt_t opts;
  lt_dlhandle  handle = NULL;
  int    (*init_func)(sc_pkcs15_card_t *);
  int    (*init_func_ex)(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);
  int    r, force = 0;
  const char  *driver, *module_name;

  driver = conf->name->data;

  r = emu_detect_card(card, conf, &force);
  if (r < 0)
    return SC_ERROR_INTERNAL;

  init_func    = NULL;
  init_func_ex = NULL;

  memset(&opts, 0, sizeof(opts));
  opts.blk     = conf;
  if (force != 0)
    opts.flags   = SC_PKCS15EMU_FLAGS_NO_CHECK;

  module_name = scconf_get_str(conf, "module", builtin_name);
  if (!strcmp(module_name, "builtin")) {
    int  i;

    /* This function is built into libopensc itself.
     * Look it up in the table of emulators */
    module_name = driver;
    for (i = 0; builtin_emulators[i].name; i++) {
      if (!strcmp(builtin_emulators[i].name, module_name)) {
        init_func_ex = builtin_emulators[i].handler;
        break;
      }
    }
  } else {
    const char *(*get_version)(void);
    const char *name = NULL;
    void  *address;

    sc_debug(ctx, "Loading %s\n", module_name);
    
    /* try to open dynamic library */
    handle = lt_dlopen(module_name);
    if (!handle) {
      sc_debug(ctx, "unable to open dynamic library '%s': %s\n",
               module_name, lt_dlerror());
      return SC_ERROR_INTERNAL;
    }
    /* try to get version of the driver/api */
    get_version =  (const char *(*)(void)) lt_dlsym(handle, "sc_driver_version");
    if (!get_version || strcmp(get_version(), "0.9.3") < 0) {
      /* no sc_driver_version function => assume old style
       * init function (note: this should later give an error
       */
      /* get the init function name */
      name = scconf_get_str(conf, "function", func_name);

      address = lt_dlsym(handle, name);
      if (address)
        init_func = (int (*)(sc_pkcs15_card_t *)) address;
    } else {
      name = scconf_get_str(conf, "function", exfunc_name);

      address = lt_dlsym(handle, name);
      if (address)
        init_func_ex = (int (*)(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *)) address;
    }
  }
  /* try to initialize the pkcs15 structures */
  if (init_func_ex)
    r = init_func_ex(p15card, &opts);
  else if (init_func)
    r = init_func(p15card);
  else
    r = SC_ERROR_WRONG_CARD;

  if (r >= 0) {
    sc_debug(card->ctx, "%s succeeded, card bound\n",
        module_name);
    p15card->dll_handle = handle;
  } else if (ctx->debug >= 4) {
    sc_debug(card->ctx, "%s failed: %s\n",
        module_name, sc_strerror(r));
    /* clear pkcs15 card */
    sc_pkcs15_card_clear(p15card);
    if (handle)
      lt_dlclose(handle);
  }

  return r;
}
