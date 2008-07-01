/*

   ratproxy - naive dynamic list implementation
   --------------------------------------------

   Multiple macros for handling several types of dynamic lists and
   strings.

   Author: Michal Zalewski <lcamtuf@google.com>

   Copyright 2007, 2008 by Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#ifndef _HAVE_NLIST_H
#define _HAVE_NLIST_H

#include "types.h"

#define ALLOC_CHUNK 32

struct naive_list { _u8** v; _u32 c; };

#define ADD(list,val) do { \
    struct naive_list* __list = &(list); \
    if (!(__list->c % ALLOC_CHUNK)) { \
      __list->v = realloc(__list->v,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      if (!__list->v) fatal("out of memory"); \
    } \
    __list->v[__list->c++] = (val); \
    __list->v[__list->c] = 0; \
  } while (0)
  
#define DYN_ADD(list,val) do { \
    _u8* _s = strdup(val); \
    if (!_s) fatal("out of memory"); \
    ADD((list),_s); \
  } while (0)

#define FREE(list) do { \
    struct naive_list* __list = &(list); \
    if (__list->v) free(__list->v); \
    __list->v = 0; \
    __list->c = 0; \
  } while (0);

#define DYN_FREE(list) do { \
    _u32 _i; \
    struct naive_list* __list = &(list); \
    for (_i=0;_i<__list->c;_i++) \
      if (__list->v[_i]) free(__list->v[_i]); \
    if (__list->v) free(__list->v); \
    __list->v = 0; \
    __list->c = 0; \
  } while (0);

struct naive_list2 { _u8 **v1, **v2; _u32 c; };

#define ADD2(list, val1, val2) do { \
    struct naive_list2* __list = &(list); \
    if (!(__list->c % ALLOC_CHUNK)) { \
      __list->v1 = realloc(__list->v1,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      __list->v2 = realloc(__list->v2,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      if (!__list->v1 || !__list->v2) fatal("out of memory"); \
    } \
    __list->v1[__list->c] = (val1); \
    __list->v2[__list->c++] = (val2); \
  } while (0)

#define DYN_ADD2(list,val1,val2) do { \
    _u8 *_s1 = strdup(val1), *_s2 = strdup(val2); \
    if (!_s1 || !_s2) fatal("out of memory"); \
    ADD2((list),_s1,_s2); \
  } while (0)

#define FREE2(list) do { \
    struct naive_list2* __list = &(list); \
    if (__list->v1) free(__list->v1); \
    if (__list->v2) free(__list->v2); \
    __list->v1 = 0; \
    __list->v2 = 0; \
    __list->c = 0; \
  } while (0);

#define DYN_FREE2(list) do { \
    _u32 _i; \
    struct naive_list2* __list = &(list); \
    for (_i=0;_i<__list->c;_i++) { \
      if (__list->v1[_i]) free(__list->v1[_i]); \
      if (__list->v2[_i]) free(__list->v2[_i]); \
    } \
    if (__list->v1) free(__list->v1); \
    if (__list->v2) free(__list->v2); \
    __list->v1 = 0; \
    __list->v2 = 0; \
    __list->c = 0; \
  } while (0);


/* A specialized structure for parameter handling. */
struct naive_list_p { 
  _u8 **v1;	/* Field name */
  _u8 **v2;	/* Field value */
  _u8 **fn;	/* Filename ("" if none) */
  _u32 *l2;	/* Field value length (0 - ASCIZ ) */
  _u32 c; 	/* Field count */
};

#define ADDP(list, val1, val2, fnval) do { \
    struct naive_list_p* __list = &(list); \
    if (!(__list->c % ALLOC_CHUNK)) { \
      __list->v1 = realloc(__list->v1,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      __list->v2 = realloc(__list->v2,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      __list->fn = realloc(__list->fn,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      __list->l2 = realloc(__list->l2,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u32)); \
      if (!__list->v1 || !__list->v2 || !__list->fn || !__list->l2) fatal("out of memory"); \
    } \
    __list->v1[__list->c] = (val1); \
    __list->v2[__list->c] = (val2); \
    __list->fn[__list->c] = (fnval); \
    __list->l2[__list->c++] = 0; \
  } while (0)

#define ADDP_RAWMEM(list, val1, val2, v2len, fnval) do { \
    struct naive_list_p* __list = &(list); \
    if (!(__list->c % ALLOC_CHUNK)) { \
      __list->v1 = realloc(__list->v1,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      __list->v2 = realloc(__list->v2,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      __list->fn = realloc(__list->fn,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u8*)); \
      __list->l2 = realloc(__list->l2,(2 + ALLOC_CHUNK + __list->c) * sizeof(_u32)); \
      if (!__list->v1 || !__list->v2 || !__list->fn || !__list->l2) fatal("out of memory"); \
    } \
    __list->v1[__list->c] = (val1); \
    __list->v2[__list->c] = (val2); \
    __list->fn[__list->c] = (fnval); \
    __list->l2[__list->c++] = (v2len); \
  } while (0)
  
#define DYN_ADDP(list,val1,val2,fn) do { \
    _u8 *_s1 = strdup(val1), *_s2 = strdup(val2), *_fn = strdup(fn); \
    if (!_s1 || !_s2 || !_fn) fatal("out of memory"); \
    ADDP((list),_s1,_s2,_fn); \
  } while (0)

#define DYN_ADDP_RAWMEM(list,val1,val2,v2len,fn) do { \
    _u32 _l2 = (v2len); \
    _u8 *_s1 = strdup(val1), *_s2 = malloc(_l2), *_fn = strdup(fn); \
    if (!_s1 || !_s2 || !_fn) fatal("out of memory"); \
    memcpy(_s2,(val2),_l2); \
    _s2[_l2] = 0; \
    ADDP_RAWMEM((list),_s1,_s2,_l2,_fn); \
  } while (0)

struct dyn_str { _u8* v; _u32 l; };

#define STR_FREE(buf) do { \
    struct dyn_str* _str = &(buf); \
    if (_str->v) free(_str->v); \
    _str->v = 0; \
    _str->l = 0; \
  } while (0)

#define STR_APPEND(buf,value) do { \
    _u8* _data = (value); \
    _u32 _len = strlen(_data); \
    struct dyn_str* _str = &(buf); \
    _str->v = realloc(_str->v,_str->l + _len + 1); \
    if (!_str->v) fatal("out of memory"); \
    memcpy(_str->v + _str->l, _data, _len); \
    _str->l += _len; \
    _str->v[_str->l] = 0; \
  } while (0)

#define STR_APPEND_RAWMEM(buf,value,vlen) do { \
    _u8* _data = (value); \
    _u32 _len = (vlen); \
    struct dyn_str* _str = &(buf); \
    _str->v = realloc(_str->v,_str->l + _len + 1); \
    if (!_str->v) fatal("out of memory"); \
    memcpy(_str->v + _str->l, _data, _len); \
    _str->l += _len; \
    _str->v[_str->l] = 0; \
  } while (0)

#define STR_APPEND_CHAR(buf,value) do { \
    _u8 _data = (value); \
    struct dyn_str* _str = &(buf); \
    _str->v = realloc(_str->v,_str->l + 2); \
    if (!_str->v) fatal("out of memory"); \
    _str->v[_str->l++] = _data; \
    _str->v[_str->l] = 0; \
  } while (0)

#endif /* ! _HAVE_NLIST_H */
