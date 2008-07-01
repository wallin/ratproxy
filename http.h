/*
   ratproxy - HTTP request handling
   --------------------------------

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

#ifndef _HAVE_HTTP_H
#define _HAVE_HTTP_H

#include "types.h"
#include "nlist.h"

struct http_request {
  _u8*  method;			/* HTTP method          */
  _u8*  host;			/* Target host          */
  _u32  port;                   /* Target TCP port      */
  _u8*  path;                   /* Target URL path      */
  _u8*  ext;                    /* File extension       */
  _u8*  query;                  /* Query string         */        

  struct naive_list2 h;         /* Header set           */

  _u8   is_connect;		/* CONNECT method?      */
  _u8   from_ssl;		/* SSL decapsulation?   */
  _u8   xsrf_safe;		/* Has anti-XSRF token? */
  _u8   authsub;		/* Uses authsub?        */
  _u8*  referer;		/* 'Referer' header     */
  _u8*  ref_host;		/* Referer host, if any */
  _u8   multipart;		/* Multipart request?   */
  _u8   non_param;              /* Non-param payload    */

  _u8*  use_boundary;           /* Multipart boundary   */

  _u32  ppar_bound;		/* Query/payload delim  */

  _u32  payload_len;            /* POST payload length  */
  _u8*  payload;                /* POST payload data    */

  struct naive_list2 cookies;   /* Sent cookies         */

  struct naive_list_p p;	/* Decoded parameters   */

};

#define INTENT_NONE	0
#define INTENT_PRIV	1
#define INTENT_PUB 	2

struct http_response {
  _u32  code;			/* HTTP return code     */
 
  _u8*  ext;			/* File extension       */
  
  struct naive_list2 h;		/* Header set           */

  _u8*  mime_type;		/* Declared MIME type   */
  _u8*  charset;                /* Declared charset     */
  _u8*  sniffed_mime;           /* Detected MIME type   */
  _u8*  location;		/* Location: update     */

  _u8   ex10intent;		/* Expires intent       */
  _u8   pr10intent;             /* Pragma intent        */
  _u8   cc11intent;             /* Cache-Control intent */

  _u8   has_multiple;		/* Has duplicate fields */
  _u8   has_badclen;		/* Bad content length?  */
  _u8   is_attach;		/* Attachment?          */
  _u8   is_text;		/* Text document?       */
  _u8   bad_cset;               /* Mistyped charset?    */

  struct naive_list2 cookies;   /* Set cookies          */

  _u32  payload_len;		/* Response body length */
  _u8*  payload;                /* Response body data   */

  _u64  cksum;			/* Payload checksum     */

};


struct http_request* collect_request(FILE* client,_u8* ssl_host,_u32 ssl_port);

FILE* open_server_complete(FILE* client, struct http_request* r);

struct http_response* send_request(FILE* client, FILE* server, struct http_request* r, 
                                   _u8 strip_state);

void send_response(FILE* client, struct http_response* r);

void checksum_response(struct http_response* r);

void detect_charset(struct http_response* r);

void parse_urlencoded(struct naive_list_p* p, _u8* string);

void parse_multipart(struct naive_list_p* p, _u8* string, _u32 slen);

_u8 contains_token(_u8* name, _u8* val);

_u8* S(_u8* string, _u8 nl);

_u8* stringify_payload(struct http_request* r);

void reconstruct_request(struct http_request* r);

#endif /* !_HAVE_HTTP_H */
