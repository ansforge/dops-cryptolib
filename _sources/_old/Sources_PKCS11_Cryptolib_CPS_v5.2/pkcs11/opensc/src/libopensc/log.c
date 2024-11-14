/*
 * log.c: Miscellaneous logging functions
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

#include "internal.h"
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <sys/timeb.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif

char logDirOPSC[256] = { 0 };

/* Number of bytes displayed for one line */
#define BYTES_PER_LINE 16
#include "sys_config.h"

void sc_add_time_to_log(FILE * logFile)
{
  char *timeline;
#ifdef __APPLE__
  struct timeb timebuffer;
  struct timeval tval;
  struct timespec tspec;
  gettimeofday(&tval, 0);
  TIMEVAL_TO_TIMESPEC(&tval, &tspec);
  timebuffer.time = tspec.tv_sec;
  timebuffer.millitm = tspec.tv_nsec / 1000000;
  timeline = ctime(&(timebuffer.time));
  fprintf(logFile, "%.19s.%03hu : ", timeline, timebuffer.millitm);
  return;
#else //
  struct timeb timebuffer;
  ftime(&timebuffer);

  timeline = ctime(&(timebuffer.time));

  fprintf(logFile, "%.19s.%03hu : ", timeline, timebuffer.millitm);
#endif
}

static int sc_ui_display_msg(sc_context_t *ctx, int type, const char *msg)
{
  FILE   *outf = NULL;
  int    n;

  CHAR traceFileName[512] = { 0 };
  ULONG threadID, processID;

  /* quelque soit la nature de la trace, debug=0 signifie pas de traces */
  if (ctx->debug == 0) {
    return 0;
  }

  getCurrentProcess(&processID);
  getCurrentThread(&threadID);

  if (logDirOPSC[0] == 0) {
    sys_GetLogPath(logDirOPSC, sizeof(logDirOPSC));
  }

  switch (type) {
  case SC_LOG_TYPE_ERROR:
  case SC_LOG_TYPE_DEBUG:
    sprintf(traceFileName, "%scps3opsc_%lx_%lx.log", logDirOPSC, processID, threadID);
    outf = fopen(traceFileName, "a");
    break;
  }
  if (outf == NULL) {
    return 0;
  }

  sc_add_time_to_log(outf);
  fprintf(outf, "%s", msg);
  n = (INT)strlen(msg);
  if (n == 0 || msg[n - 1] != '\n') {
    fprintf(outf, "\n");
  }
  fflush(outf);
  fclose(outf);
  return 0;
}

static int sc_ui_display_error_default(sc_context_t *ctx, const char *msg)
{
  return sc_ui_display_msg(ctx, SC_LOG_TYPE_ERROR, msg);
}

static int sc_ui_display_debug_default(sc_context_t *ctx, const char *msg)
{
  return sc_ui_display_msg(ctx, SC_LOG_TYPE_DEBUG, msg);
}

/* Although not used, we need this for consistent exports */
void _sc_error(sc_context_t *ctx, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  sc_do_log_va(ctx, SC_LOG_TYPE_ERROR, NULL, 0, NULL, format, ap);
  va_end(ap);
}

/* Although not used, we need this for consistent exports */
void _sc_debug(sc_context_t *ctx, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  sc_do_log_va(ctx, SC_LOG_TYPE_DEBUG, NULL, 0, NULL, format, ap);
  va_end(ap);
}

void sc_do_log(sc_context_t *ctx, int type, const char *file, int line, const char *func, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  sc_do_log_va(ctx, type, file, line, func, format, ap);
  va_end(ap);
}

void sc_do_log_va(sc_context_t *ctx, int type, const char *file, int line, const char *func, const char *format, va_list args)
{
  int(*display_fn)(sc_context_t *, const char *);
  char  buf[1836], *p;
  const char *tag = "";
  int  r;
  size_t  left;

  assert(ctx != NULL);

  switch (type) {
  case SC_LOG_TYPE_ERROR:
    if (!ctx->suppress_errors) {
      display_fn = &sc_ui_display_error_default;
      tag = "error:";
      break;
    }
    /* Fall thru - suppressed errors are logged as
     * debug messages */
    tag = "error (suppressed):";
  case SC_LOG_TYPE_DEBUG:
    if (ctx->debug == 0) {
      return;
    }
    display_fn = &sc_ui_display_debug_default;
    break;

  default:
    return;
  }

  if (file != NULL) {
    r = snprintf(buf, sizeof(buf), "[%s] %s:%d:%s: ", ctx->app_name, file, line, func ? func : "");
    if (r < 0 || (unsigned int)r > sizeof(buf)) {
      return;
    }
  }
  else if (func != NULL) {
    r = snprintf(buf, sizeof(buf), "%s : ", func);
    if (r < 0 || (unsigned int)r > sizeof(buf)) {
      return;
    }
  }
  else {
    r = 0;
  }
  p = buf + r;
  left = sizeof(buf) - r;

  r = vsnprintf(p, left, format, args);
  if (r < 0)
    return;
  p += r;
  left -= r;

  display_fn(ctx, buf);
}

void sc_hex_dump(sc_context_t *ctx, const u8 * in, size_t count, char *buf, size_t len)
{
  char *p = buf;
  int lines = 0;

  assert(buf != NULL && in != NULL);
  buf[0] = 0;

  while (count) {
    char ascbuf[17];
    size_t i;

    for (i = 0; i < count && i < 16; i++) {
      sprintf(p, "%02X ", *in);
      if (isprint(*in))
        ascbuf[i] = *in;
      else
        ascbuf[i] = '.';
      p += 3;
      in++;
    }
    count -= i;
    ascbuf[i] = 0;
    for (; i < 16 && lines; i++) {
      strcat(p, "   ");
      p += 3;
    }
    strcat(p, ascbuf);
    p += strlen(p);
    sprintf(p, "\n");
    p++;
    lines++;
  }
}

void sc_hex_dump_get_len(size_t inlen, size_t * reqlen)
{
  int minReqBytes = BYTES_PER_LINE * 3 + 1 + BYTES_PER_LINE;
  if (inlen < BYTES_PER_LINE) {
    *reqlen = minReqBytes;
    return;
  }

  if (inlen % BYTES_PER_LINE == 0) {
    /* one extra byte for the trailing new line */
    *reqlen = (inlen / BYTES_PER_LINE) * minReqBytes + sizeof(char);
    return;
  }

  *reqlen = (inlen / BYTES_PER_LINE) * minReqBytes + minReqBytes;
  return;
}
