/*
 * scconf.c
 *
 * Copyright (C) 2002 Antti Tapaninen <aet@cc.hut.fi>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#include "scconf.h"


scconf_context *scconf_new(const char *filename)
{
  scconf_context *config;

  config = (scconf_context *) malloc(sizeof(scconf_context));
  if (!config) {
    return NULL;
  }
  memset(config, 0, sizeof(scconf_context));
  config->filename = filename ? strdup(filename) : NULL;
  config->root = (scconf_block *) malloc(sizeof(scconf_block));
  if (!config->root) {
    if (config->filename) {
      free(config->filename);
    }
    free(config);
    return NULL;
  }
  memset(config->root, 0, sizeof(scconf_block));
  return config;
}

void scconf_free(scconf_context * config)
{
  if (config) {
    scconf_block_destroy(config->root);
    if (config->filename) {
      free(config->filename);
    }
    free(config);
  }
}

const scconf_block *scconf_find_block(const scconf_context * config, const scconf_block * block, const char *item_name)
{
  scconf_item *item;

  if (!block) {
    block = config->root;
  }
  if (!item_name) {
    return NULL;
  }
  for (item = block->items; item; item = item->next) {
    if (item->type == SCCONF_ITEM_TYPE_BLOCK &&
        strcasecmp(item_name, item->key) == 0) {
      return item->value.block;
    }
  }
  return NULL;
}

scconf_block **scconf_find_blocks(const scconf_context * config, const scconf_block * block, const char *item_name, const char *key)
{
  scconf_block **blocks = NULL, **tmp;
  int alloc_size, size;
  scconf_item *item;

  if (!block) {
    block = config->root;
  }
  if (!item_name) {
    return NULL;
  }
  size = 0;
  alloc_size = 10;
  blocks = (scconf_block **) calloc(sizeof(scconf_block *), alloc_size);
  if (blocks == NULL) {
    return NULL;
  }

  for (item = block->items; item; item = item->next) {
    if (item->type == SCCONF_ITEM_TYPE_BLOCK &&
        strcasecmp(item_name, item->key) == 0) {
      if (key && strcasecmp(key, item->value.block->name->data)) {
        continue;
      }
      if (size + 1 >= alloc_size) {
        alloc_size *= 2;
        tmp = (scconf_block **) realloc(blocks, sizeof(scconf_block *) * alloc_size);
        if (!tmp) {
          free(blocks);
          return NULL;
        }
        blocks = tmp;
      }
      blocks[size++] = item->value.block;
    }
  }
  blocks[size] = NULL;
  return blocks;
}

const scconf_list *scconf_find_list(const scconf_block * block, const char *option)
{
  scconf_item *item;

  if (!block) {
    return NULL;
  }
  for (item = block->items; item; item = item->next) {
    if (item->type == SCCONF_ITEM_TYPE_VALUE &&
        strcasecmp(option, item->key) == 0) {
      return item->value.list;
    }
  }
  return NULL;
}

const char *scconf_get_str(const scconf_block * block, const char *option, const char *def)
{
  const scconf_list *list;

  list = scconf_find_list(block, option);
  return !list ? def : list->data;
}

int scconf_get_int(const scconf_block * block, const char *option, int def)
{
  const scconf_list *list;

  list = scconf_find_list(block, option);
  return !list ? def : (int)strtol(list->data, NULL, 0);
}

int scconf_get_bool(const scconf_block * block, const char *option, int def)
{
  const scconf_list *list;

  list = scconf_find_list(block, option);
  if (!list) {
    return def;
  }
  return toupper((int) *list->data) == 'T' || toupper((int) *list->data) == 'Y';
}

scconf_item *scconf_item_copy(const scconf_item * src, scconf_item ** dst)
{
  scconf_item *ptr, *_dst = NULL, *next = NULL;

  next = (scconf_item *) malloc(sizeof(scconf_item));
  if (!next) {
    return NULL;
  }
  memset(next, 0, sizeof(scconf_item));
  ptr = next;
  _dst = next;
  while (src) {
    if (!next) {
      next = (scconf_item *) malloc(sizeof(scconf_item));
      if (!next) {
        scconf_item_destroy(ptr);
        return NULL;
      }
      memset(next, 0, sizeof(scconf_item));
      _dst->next = next;
    }
    next->type = src->type;
    switch (src->type) {
    case SCCONF_ITEM_TYPE_COMMENT:
      next->value.comment = src->value.comment ? strdup(src->value.comment) : NULL;
      break;
    case SCCONF_ITEM_TYPE_BLOCK:
      scconf_block_copy(src->value.block, &next->value.block);
      break;
    case SCCONF_ITEM_TYPE_VALUE:
      scconf_list_copy(src->value.list, &next->value.list);
      break;
    }
    next->key = src->key ? strdup(src->key) : NULL;
    _dst = next;
    next = NULL;
    src = src->next;
  }
  *dst = ptr;
  return ptr;
}

void scconf_item_destroy(scconf_item * item)
{
  scconf_item *next;

  while (item) {
    next = item->next;

    switch (item->type) {
    case SCCONF_ITEM_TYPE_COMMENT:
      if (item->value.comment) {
        free(item->value.comment);
      }
      item->value.comment = NULL;
      break;
    case SCCONF_ITEM_TYPE_BLOCK:
      scconf_block_destroy(item->value.block);
      break;
    case SCCONF_ITEM_TYPE_VALUE:
      scconf_list_destroy(item->value.list);
      break;
    }

    if (item->key) {
      free(item->key);
    }
    item->key = NULL;
    free(item);
    item = next;
  }
}

scconf_block *scconf_block_copy(const scconf_block * src, scconf_block ** dst)
{
  if (src) {
    scconf_block *_dst = NULL;

    _dst = (scconf_block *) malloc(sizeof(scconf_block));
    if (!_dst) {
      return NULL;
    }
    memset(_dst, 0, sizeof(scconf_block));
    if (src->name) {
      scconf_list_copy(src->name, &_dst->name);
    }
    if (src->items) {
      scconf_item_copy(src->items, &_dst->items);
    }
    *dst = _dst;
    return _dst;
  }
  return NULL;
}

void scconf_block_destroy(scconf_block * block)
{
  if (block) {
    scconf_list_destroy(block->name);
    scconf_item_destroy(block->items);
    free(block);
  }
}

scconf_list *scconf_list_add(scconf_list ** list, const char *value)
{
  scconf_list *rec, **tmp;

  rec = (scconf_list *) malloc(sizeof(scconf_list));
  if (!rec) {
    return NULL;
  }
  memset(rec, 0, sizeof(scconf_list));
  rec->data = value ? strdup(value) : NULL;

  if (!*list) {
    *list = rec;
  } else {
    for (tmp = list; *tmp; tmp = &(*tmp)->next);
    *tmp = rec;
  }
  return rec;
}

scconf_list *scconf_list_copy(const scconf_list * src, scconf_list ** dst)
{
  scconf_list *next;

  while (src) {
    next = src->next;
    scconf_list_add(dst, src->data);
    src = next;
  }
  return *dst;
}

void scconf_list_destroy(scconf_list * list)
{
  scconf_list *next;

  while (list) {
    next = list->next;
    if (list->data) {
      free(list->data);
    }
    free(list);
    list = next;
  }
}

