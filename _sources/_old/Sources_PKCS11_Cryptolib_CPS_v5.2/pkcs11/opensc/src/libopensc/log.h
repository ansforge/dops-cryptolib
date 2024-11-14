/*
 * log.h: Logging functions header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003  Antti Tapaninen <aet@cc.hut.fi>
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

#ifndef _OPENSC_LOG_H
#define _OPENSC_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include "opensc.h"

#define SC_LOG_TYPE_ERROR  0
#define SC_LOG_TYPE_VERBOSE  1
#define SC_LOG_TYPE_DEBUG  2


#define sc_error _sc_error
#define sc_debug _sc_debug

  void _sc_error(sc_context_t *ctx, const char *format, ...);
  void _sc_debug(sc_context_t *ctx, const char *format, ...);
  void sc_do_log(sc_context_t *ctx, int type, const char *file, int line, const char *func, const char *format, ...);
  void sc_do_log_va(sc_context_t *ctx, int type, const char *file, int line, const char *func, const char *format, va_list args);

  void sc_hex_dump(sc_context_t *ctx, const u8 * buf, size_t len, char *out, size_t outlen);
  void sc_hex_dump_get_len(size_t inlen, size_t * reqlen);

#define SC_FUNC_CALLED(ctx, level) do { \
  if (ctx->debug >= level) \
     sc_do_log(ctx, SC_LOG_TYPE_DEBUG, NULL, 0L, __FUNCTION__, "called\n"); \
} while (0)

#define SC_FUNC_RETURN(ctx, level, r) do { \
  int _ret = (int)r; \
  if (_ret < 0 && !ctx->suppress_errors) { \
    sc_do_log(ctx, SC_LOG_TYPE_ERROR, __FILE__, __LINE__, __FUNCTION__, "returning with: %s\n", sc_strerror(_ret)); \
  } else if (ctx->debug >= level) { \
    sc_do_log(ctx, SC_LOG_TYPE_DEBUG, NULL, 0L, __FUNCTION__, "returning with: %d\n", _ret); \
  } \
  return _ret; \
} while(0)

#define SC_TEST_RET(ctx, r, text) do { \
  int _ret = (int)(r); \
  if (_ret < 0) { \
    sc_do_log(ctx, SC_LOG_TYPE_ERROR, __FILE__, __LINE__, __FUNCTION__, "%s: %s\n", (text), sc_strerror(_ret)); \
    return _ret; \
  } \
} while(0)

#define sc_perror(ctx, errno, str) { \
  sc_do_log(ctx, SC_LOG_TYPE_ERROR, __FILE__, __LINE__, __FUNCTION__, "%s: %s\n", str, sc_strerror(errno)); \
}

#ifdef __cplusplus
}
#endif

#endif
