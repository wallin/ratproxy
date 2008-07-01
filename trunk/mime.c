/*
   ratproxy - MIME detection
   -------------------------

   MIME content sniffing routines. This code tries to figure out
   what is actually being served, regardless of what HTTP headers
   say.

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/wait.h>
#include <ctype.h>
#include <netdb.h>
#include <openssl/md5.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "nlist.h"
#include "http.h"
#include "mime.h"
#include "string-inl.h"


/* Check for JSON prologues... */
static _u8 is_json_safe_mime(_u8* str) {
  _u32 i = 0;

  /* JSON prologues of more than 1 characters are "authoritative" and override
     further content sniffing. */

  while (json_safe[i]) {
    if (json_safe[i][1] && !strncmp(str,json_safe[i],strlen(json_safe[i]))) return 1;
    i++;
  }

  return 0;

}


/* Attempt MIME type detection for formats that are likely to be served by a 
   modern web application based on payload signature matching. */
void detect_mime(struct http_response* r) {
  _u32 i, max;
  _u8  text = 1;
  _u8  sniffbuf[SNIFFBUF + 1];
  _u8* xxx;

  /* TODO: Add more popular formats. This is oriented toward common web 2.0
     technologies at the moment. */

  if (!r->payload_len) return;

  if (r->payload_len > SNIFFBUF) max = SNIFFBUF; else max = r->payload_len;
  memcpy(sniffbuf,r->payload,max);
  sniffbuf[max] = 0;

  /* Is this a plain-text file? */

  for (i=0;i<max;i++) 
    if (sniffbuf[i] < 0x20 && !isspace(sniffbuf[i])) { text = 0; break; }

  if (text) {
    _u8 got_alpha = 0, got_bracket = 0, got_try = 0, got_alpha_before = 0;

    r->is_text = 1;

    /* First, some files with known, fixed signatures. */

    if (!strncmp(sniffbuf,"%!PS",4)) {
      r->sniffed_mime = "application/postscript";
      return;
    }

    if (!strncmp(sniffbuf,"{\\rtf",5)) {
      r->sniffed_mime = "text/rtf";
      return;
    }

    /* Try to detect Javascript - this is a bit tricky, because
       JSON snippets can have minimal syntax, and CSS uses a notation
       vaguely resembling Javascript. */

    /* JSON breaker prefixes automatically qualify content as JS */
    if (is_json_safe_mime(sniffbuf)) goto got_javascript;

    for (i=0;i<max;i++) {

      /* First, skip comment blocks */

      if (!strncmp(sniffbuf+i,"//",2)) {
        _u8* x = strchr(sniffbuf + i + 2, '\n');
        if (!x) i = max; else i = x - sniffbuf;
        continue;
      }

      if (!strncmp(sniffbuf+i,"/*",2)) {
        _u8* x = strstr(sniffbuf + i + 2, "*/");
        if (!x) i = max; else i = x - sniffbuf + 1;
        continue;
      }

      /* If what follows look HTML-esque, bail out */

      if ((sniffbuf[i] == '<' || !strcmp(sniffbuf+i,"&lt;"))) break;

      if (!strncmp(sniffbuf+i,"try",3) && (isspace(sniffbuf[i+3]) || sniffbuf[i+3] == '{'))
        got_try = 1;

      /* try { ... is a special JSON-like response that looks like CSS, but should
         be handled as Javascript. */

      if (sniffbuf[i] == '{' && got_try) goto got_javascript;

      /* Otherwise, if { is encountered before any =, (, or HTML, but after alnums,
         it's likely a stylesheet... well, unless followed by '"', in which case it
         might be a serialized object with a non-standard anti-XSSI prologue. */
      
      if (got_alpha && sniffbuf[i] == '{') {
        _u32 j = i + 1;

        while (j < max && sniffbuf[j] && !isalpha(sniffbuf[j])) {
          if (sniffbuf[j] == '{'  || sniffbuf[j] == '"' || 
              sniffbuf[j] == '\'' || sniffbuf[j] == '(') goto got_javascript;
          j++;
        }

        r->sniffed_mime = "text/css";
        return;
      }

      if (isalpha(sniffbuf[i])) got_alpha = 1;
      if (sniffbuf[i] == '{') { got_bracket = 1; got_alpha_before = got_alpha; }

      /* { "foo" is very JSONish. */
      if (!got_alpha && got_bracket && sniffbuf[i] == '"') goto got_javascript;

      /* { foo: 1 is JSONish too. */
      if (!got_alpha_before && got_alpha && got_bracket && sniffbuf[i] == ':')
        goto got_javascript;

      /* And finally, if =, ( or JS keyword is encountered before <, assume JS. */

      if (sniffbuf[i] == '=' || sniffbuf[i] == '(' || sniffbuf[i] == '[' ||
          !strncmp(sniffbuf + i, "function ",9) ||
          !strncmp(sniffbuf + i, "throw ",6) ||
          !strncmp(sniffbuf + i, "var ",4)) {

got_javascript:

        r->sniffed_mime = "application/x-javascript";

        /* RFC 4329 lists no fewer than 16 variations of Javascript MIME type.
           Not all of them are common in the wild, but all are roughly equivalent
           security-wise, so let's be lenient. */

        if (r->mime_type) {
 
          if (!strcasecmp(r->mime_type,"text/javascript")) 
            r->sniffed_mime = "text/javascript";
          else if (!strcasecmp(r->mime_type,"application/javascript"))
            r->sniffed_mime = "application_javascript";
          else if (!strcasecmp(r->mime_type,"application/json"))
            r->sniffed_mime = "application/json";
 
        }

        return;
      }

    }

    /* OpenSearch */

    if (strstr(sniffbuf,"<OpenSearch")) {
      r->sniffed_mime = "application/opensearchdescription+xml";
      return;
    }

    /* Try to detect RSS */

    if (strstr(sniffbuf,"<channel") || strstr(sniffbuf,"<description") ||
        strstr(sniffbuf,"<item")    || strstr(sniffbuf,"<rdf:RDF") ||
        strstr(sniffbuf,"<rss")) {
      r->sniffed_mime = "application/rss+xml";
      return;
    }

    /* Try to detect Atom */

    if (strstr(sniffbuf,"<feed ") || strstr(sniffbuf,"<updated>")) {
      r->sniffed_mime = "application/atom+xml";
      return;
    }

    /* Try to detect WML */

    if (rp_strcasestr(sniffbuf,"<wml") || rp_strcasestr(sniffbuf,"<!DOCTYPE wml ")) {
      r->sniffed_mime = "text/vnd.wap.wml";
      return;
    }

    /* Try to detect <cross-domain-policy> - just promote the new, fancy MIME type for
       security reasons. */

    if (rp_strcasestr(sniffbuf,"<cross-domain-policy>")) {
      r->sniffed_mime = "text/x-cross-domain-policy";
      return;  
    }
  
    /* Try to detect XHTML, SVG, or generic XML of some other type. */

    if (rp_strcasestr(sniffbuf,"<?xml")) {

      if (rp_strcasestr(sniffbuf,"<svg"))
        r->sniffed_mime = "image/svg+xml";
      else if (rp_strcasestr(sniffbuf,"<!doctype") && !rp_strcasestr(sniffbuf,"cross-domain-policy"))
        r->sniffed_mime = "application/xhtml+xml";
      else {

        if (r->mime_type && !strcasecmp(r->mime_type,"text/xml"))
          r->sniffed_mime = "text/xml";
        else r->sniffed_mime = "application/xml";
      }

      return;
    }

    /* Try to detect generic HTML */
         
    if (rp_strcasestr(sniffbuf,"<html")     || rp_strcasestr(sniffbuf,"<meta")     ||
        rp_strcasestr(sniffbuf,"<head")     || rp_strcasestr(sniffbuf,"<title")    ||
        rp_strcasestr(sniffbuf,"<!--")      || 
        rp_strcasestr(sniffbuf,"<!doctype") || rp_strcasestr(sniffbuf,"<body")     ||
        rp_strcasestr(sniffbuf,"<font")     || rp_strcasestr(sniffbuf,"<br")       ||
        rp_strcasestr(sniffbuf,"<td")       || rp_strcasestr(sniffbuf,"<div")      ||
        rp_strcasestr(sniffbuf,"<span")     || rp_strcasestr(sniffbuf,"<img")      || 
        rp_strcasestr(sniffbuf,"<li")       || rp_strcasestr(sniffbuf,"href=")     || 
        rp_strcasestr(sniffbuf,"<ol")       || rp_strcasestr(sniffbuf,"<ul")       || 
        rp_strcasestr(sniffbuf,"<style")    || rp_strcasestr(sniffbuf,"<script")) {

      r->sniffed_mime = "text/html";
      return;
    }

    /* Last resort for XML */

    xxx = sniffbuf;
    while (isspace(*xxx)) xxx++;

    if (rp_strcasestr(xxx,"<![CDATA[") || (xxx[0] == '<' && (strstr(xxx,"</") || strstr(xxx,"/>") || strstr(xxx,"/ >")))) {

        if (r->mime_type && !strcasecmp(r->mime_type,"text/xml"))
          r->sniffed_mime = "text/xml";
        else r->sniffed_mime = "application/xml";

    }

    /* Oh well, at least it seems to be text. */

    r->sniffed_mime = "text/plain";

  } else {

    /* This is considerably less messy - binary signatures for some non-text files. */

    if (sniffbuf[0] == 0xFF && sniffbuf[1] == 0xD8 && 
        sniffbuf[2] == 0xFF) {
      r->sniffed_mime = "image/jpeg";

      /* Progressive JPEG; recognized by MSIE. */

      if (r->mime_type && !strcasecmp(r->mime_type,"image/pjpeg"))
        r->sniffed_mime = "image/pjpeg";

      return;
    }

    if (sniffbuf[0] == 'G' && sniffbuf[1] == 'I' && 
        sniffbuf[2] == 'F' && sniffbuf[3] == '8') {
      r->sniffed_mime = "image/gif";
      return;
    }

    if (sniffbuf[0] == 0x89 && sniffbuf[1] == 'P' && 
        sniffbuf[2] == 'N' && sniffbuf[3] == 'G') {
      r->sniffed_mime = "image/png";
      return;
    }

    if (sniffbuf[0] == 'B' && sniffbuf[1] == 'M') {
      r->sniffed_mime = "image/x-ms-bmp";
      return;
    }

    if (sniffbuf[0] == 'I' && sniffbuf[1] == 'I' && sniffbuf[2] == 42) {
      r->sniffed_mime = "image/tiff";
      return;
    }

    if (sniffbuf[0] == 0xFF && sniffbuf[1] == 0xFB) {
      r->sniffed_mime = "audio/mpeg";
      return;
    }

    if (sniffbuf[0] == 0x00 && sniffbuf[1] == 0x00 && 
        sniffbuf[2] == 0x01 && (sniffbuf[3] & 0xF0) == 0xB0) {
      r->sniffed_mime = "video/mpeg";
      return;
    }

    if (sniffbuf[0] == 'O' && sniffbuf[1] == 'g' && 
        sniffbuf[2] == 'g' && sniffbuf[3] == 'S') {
      r->sniffed_mime = "application/ogg";
      return;
    }

    if (sniffbuf[0] == 'R' && sniffbuf[1] == 'I' &&
        sniffbuf[2] == 'F' && sniffbuf[3] == 'F') {

       if (sniffbuf[8] == 'A') {
         if (sniffbuf[9] == 'C') {
           r->sniffed_mime = "application/x-navi-animation";
         } else {
           r->sniffed_mime = "video/avi";
         }
       } else r->sniffed_mime = "audio/wav";

      return;

    }

    if (sniffbuf[0] == 0x28 && sniffbuf[1] == 'R' &&
        sniffbuf[2] == 'M' && sniffbuf[3] == 'F') {

      r->sniffed_mime = "audio/x-realaudio";
      return;

    }

    if (sniffbuf[0] == 0x30 && sniffbuf[1] == 0x26 &&
        sniffbuf[2] == 0xB2) {

      r->sniffed_mime = "video/x-ms-asf";
      return;

    }

    if (!strncmp(sniffbuf+4,"free",4) || !strncmp(sniffbuf+4,"mdat",4) || 
        !strncmp(sniffbuf+4,"wide",4) || !strncmp(sniffbuf+4,"pnot",4) || 
        !strncmp(sniffbuf+4,"skip",4) || !strncmp(sniffbuf+4,"moov",4)) {

      r->sniffed_mime = "video/quicktime";
      return;

    }


    if ((sniffbuf[0] == 0x46 || sniffbuf[0] == 0x43) &&
         sniffbuf[1] == 0x57 && sniffbuf[2] == 0x53) {

      r->sniffed_mime = "application/x-shockwave-flash";
      return;

    }

    if (sniffbuf[0] == 0x46 && sniffbuf[1] == 0x4C && sniffbuf[2] == 0x56) {

      /* Again, multiple valid options in use; be polite. */

      if (r->mime_type && !strcasecmp(r->mime_type,"video/flv"))
        r->sniffed_mime = "video/flv";
      else
        r->sniffed_mime = "video/x-flv";

      return;

    }

    if (r->payload_len > 3 && sniffbuf[0] == 0 && sniffbuf[1] == 0 && sniffbuf[2] < 3 && sniffbuf[3] == 0) {

      /* Be polite again. */

      if (r->mime_type && !strcasecmp(r->mime_type,"image/x-icon"))
        r->sniffed_mime = "image/x-icon";
        else
      if (r->mime_type && !strcasecmp(r->mime_type,"image/bmp"))
        r->sniffed_mime = "image/bmp";
        else r->sniffed_mime = "image/vnd.microsoft.icon";

      return;
    }

    if (sniffbuf[0] == '%' && sniffbuf[1] == 'P' && sniffbuf[2] == 'D' && sniffbuf[3] == 'F') {
      r->sniffed_mime = "application/pdf";
      return;
    }

    if (sniffbuf[0] == 'P' && sniffbuf[1] == 'K' && sniffbuf[2] < 6 && sniffbuf[3] < 7) {

      if (rp_memmem(r->payload,r->payload_len,"META-INF/",9))
        r->sniffed_mime = "application/java-archive";
      else
        r->sniffed_mime = "application/zip";

      return;
    }

    if (sniffbuf[0] == 0xCA && sniffbuf[1] == 0xFE && sniffbuf[2] == 0xBA && sniffbuf[3] == 0xBE) {
      r->sniffed_mime = "application/java-vm";
      return;
    }

    /* Microsoft office is kind-of fuzzy. */

    if (sniffbuf[0] == 0xD0 && sniffbuf[1] == 0xCF && 
        sniffbuf[2] == 0x11 && sniffbuf[3] == 0xE0 && r->payload_len > 512) {

      _u8 c = r->payload[512];

      switch (c) {
        case 0xEC: r->sniffed_mime = "application/msword"; break;
        case 0xFD:
        case 0x09: r->sniffed_mime = "application/vnd.ms-excel"; break;
        case 0x00:
        case 0x0F:
        case 0xA0: r->sniffed_mime = "application/vnd.ms-powerpoint"; break;
      }

      return;

    }

    /* If we have no idea what it is, just leave it NULL. */

  }

}
