/*

   ratproxy - strcasestr implementation
   ------------------------------------

   Some modern operating systems still ship with no strcasestr() or memmem()
   implementations in place, for reasons beyond comprehension.

   This is a simplified version of the code that ships with NetBSD. The
   original code is licensed under a BSD license, as follows:

   Copyright (c) 1990, 1993
   The Regents of the University of California.  All rights reserved.

   This code is derived from software contributed to Berkeley by
   Chris Torek.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the University nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   SUCH DAMAGE.

 */

#ifndef _HAVE_STRCASESTR_INL_H
#define _HAVE_STRCASESTR_INL_H

#include "types.h"

static inline _u8* rp_strcasestr(const _u8* haystack, const _u8* needle) {
  _u8 c, sc;
  _u32 len;

  if (!haystack || !needle) return 0;

  if ((c = *needle++)) {

    c = tolower(c);
    len = strlen(needle);

    do {
      do {
	if (!(sc = *haystack++)) return 0;
      } while (tolower(sc) != c);
    } while (strncasecmp(haystack, needle, len));

    haystack--;

  }

  return (_u8*)haystack;

}


static inline void* rp_memmem(const void* haystack, _u32 h_len, const void* needle, _u32 n_len) {
  _u8* sp = (_u8*)haystack;
  _u8* pp = (_u8*)needle;
  _u8* eos = sp + h_len - n_len;

  if (!(haystack && needle && h_len && n_len)) return 0;

  while (sp <= eos) {
    if (*sp == *pp)
      if (memcmp(sp, pp, n_len) == 0) return sp;
    sp++;
  }

  return 0;

}

#endif /* !_HAVE_STRCASESTR_INL_H */
