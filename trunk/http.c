/*
   ratproxy - HTTP request handling
   --------------------------------

   The following routines take care of HTTP request handling, parsing,
   and error reporting.

   Note that this code is one-shot, process is terminated when request
   handling is done - and as such, we rely on the OS to do garbage
   collection.

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
#include <time.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "nlist.h"
#include "http.h"
#include "ssl.h"
#include "string-inl.h"

extern _u8* use_proxy;		/* Runtime setting exports from ratproxy. */
extern _u32 proxy_port;
extern _u8  use_len;

static _u8 srv_buf[MAXLINE],	/* libc IO buffers */
           cli_buf[MAXLINE];


/* Read a single line of HTTP headers, strip whitespaces */
static _u8* grab_line(FILE* where) {
  static _u8 inbuf[MAXLINE];
  _u32 l;

  if (!fgets(inbuf,MAXLINE,where)) return 0;

  l = strlen(inbuf);

  /* Excessive line length is bad, let's bail out. */
  if (l == MAXLINE-1) return 0;

  while (l && isspace(inbuf[l-1])) inbuf[--l] = 0;

  return inbuf;
}


/* Return a generic HTTP error message, end current process.
   Note that this function should not handle user-controlled data. */
static void http_error(FILE* client, _u8* message,_u8 sink) {

  if (client) {
    _u8* l;
 
    if (sink) while ((l=grab_line(client)) && l[0]);

    fprintf(client,
      "HTTP/1.0 500 %s\n"
      "Content-type: text/html\n\n"
      
      "<font face=\"Bitstream Vera Sans Mono,Andale Mono,Lucida Console\">\n"
      "The proxy is unable to process your request.\n"
      "<h1><font color=red><b>%s.</b></font></h1>\n", message, message);

    fflush(client);
    fclose(client);
 
  }

  debug("[!] WARNING: %s.\n", message);
  exit(0);

}


static _u8* BASE16 = "0123456789ABCDEF";

/* Decode URL-encoded parameter string */
void parse_urlencoded(struct naive_list_p* p, _u8* string) {
  _u8 val_now = 0;
  _u8 name[MAXLINE+1], val[MAXLINE+1];
  _u32 nlen = 0, vlen = 0;

  name[0] = 0;
  val[0] = 0;

  do {

    _u8 dec = 0;

    switch (*string) {
      case '+':
        dec = ' ';
        break;

      case '=':
        val_now = 1;
        break;

      case '%': {
          _u8 *a, *b;

          /* Parse %nn code, if valid; default to '?nn' if not, replace with ? if \0. */

          if (!string[1] || !string[2] || !(a=strchr(BASE16,toupper(string[1]))) ||
              !(b=strchr(BASE16,toupper(string[2])))) { dec = '?'; break; }

          dec = (a-BASE16) * 16 + (b-BASE16);
          string += 2;
          if (!dec) dec = '?';

          break;

        }

      case '&':
      case 0:

        /* Handle parameter terminator; note that we also iterate over \0
           because of loop condition placement. */

        if (nlen) {
          name[nlen] = 0;
          val[vlen] = 0;
          DYN_ADDP(*p,name,val,"");
        }

        val_now = 0;
        nlen = 0;
        vlen = 0;
        break;

      default:
        if (!(dec=*string)) dec = '?';

    }

    /* Append decoded char, if any, to field name or value as needed. */

    if (dec) {
      if (!val_now) { if (nlen < MAXLINE) name[nlen++] = dec; }
        else { if (vlen < MAXLINE) val[vlen++] = dec; }
    }

  } while (*(string++));
  
}


/* Read a line of multipart data from a linear buffer, advance buffer pointer. */
static _u8* get_multipart_line(_u8** buf) {
  static _u8* retbuf;
  _u8* x;
  _u32 cnt;

  if (retbuf) free(retbuf);

  /* We assume \r\n formatting here, which is RFC-mandated and implemtned
     by well-behaved browsers. */

  x = strchr(*buf,'\r');

  if (!x || x[1] != '\n') {
    _u32 l = strlen(*buf);
    retbuf = malloc(l + 1);
    if (!retbuf) fatal("out of memory");
    strcpy(retbuf,*buf);
    *buf += l;
    return retbuf;
  }

  cnt = x - *buf;

  retbuf = malloc(cnt + 1);
  if (!retbuf) fatal("out of memory");
  memcpy(retbuf,*buf,cnt);
  retbuf[cnt] = 0;

  *buf += cnt + 2;

  return retbuf;

}


/* Collect multipart data from a reasonably well-behaved browser. This routine
   makes multiple assumptions that might be not true for maliciously formatted
   data, but we do not strive to serve such requests well. */
void parse_multipart(struct naive_list_p* p, _u8* string, _u32 slen) {
  _u8* field, *fname;
  _u8* endptr = string + slen;

  do {

    _u8 *l, *end, *c;

    field = 0;
    fname = 0;

    /* Skip boundary */
    l = get_multipart_line(&string);
    if (l[0] != '-' || l[1] != '-') return;

    /* Sink headers, but grab field name if any */
    while ((l = get_multipart_line(&string)) && l[0]) {
      if (!strncasecmp(l,"Content-Disposition:",20)) {

        /* Grab field name. */
        _u8* f = rp_strcasestr(l,"; name=\"");
        if (!f) continue;
        f += 7;
        c = strchr(++f,'"');
        if (!c) continue;
        *c = 0;
          
        field = strdup(f);
        if (!field) fatal("out of memory");

        /* Grab file name, if any. */

        f = rp_strcasestr(c + 1,"; filename=\"");
        if (!f) continue;
        f += 11;
        c = strchr(++f,'"');
        if (!c) continue;
        *c = 0;
        fname = strdup(f);
        if (!fname) fatal("out of memory");

      }

    }

    end = rp_memmem(string,endptr - string, "\r\n--", 4);
    if (!end) return;

    if (field) 
      DYN_ADDP_RAWMEM(*p,field,string,end-string,fname ? fname : (_u8*)"");

    string = end + 2;

  } while (1);

}



#define BASE64 "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+/_-"

/* Looks for what could pass for a reasonably robust session token or XSRF protection. */
_u8 contains_token(_u8* name, _u8* value) {
  _u32 run16 = 0, run64 = 0, run64_true = 0, run64_num = 0, run64_up = 0;
  _u8* st = 0;
  static _u32 tmin,tmax;
  _u32 fno = 0;

  if (!tmin) {
    tmin = time(0);
    tmax = tmin + (60 * 60 * 24 * 30); /* One month forward */
    tmin -= (60 * 60 * 24 * 365 * 5);  /* Five years back */
  }

  /* Known bad field names - return 0. */

  fno = 0;

  while (no_xsrf_fields[fno]) {
    if (no_xsrf_fields[fno][0] == '=') {
      if (!strcasecmp(name,no_xsrf_fields[fno] + 1)) return 0;
    } else {
      if (rp_strcasestr(name,no_xsrf_fields[fno])) return 0;
    }
    fno++;
  }

  /* Known safe field names - return 1. */

  fno = 0;

  while (xsrf_fields[fno]) {
    if (xsrf_fields[fno][0] == '=') {
      if (!strcasecmp(name,xsrf_fields[fno] + 1)) return 1;
    } else {
      if (rp_strcasestr(name,xsrf_fields[fno])) return 1;
    }
    fno++;
  }

  /* URLs are not anti-XSRF tokens, no matter how random they look. */

  if (!strncmp(value,"http",4)) return 0;

  /* Iterate over value data, compute base16 / base64 runs, collect
     basic character disttributin data, rule out patterns such as unix 
     time, and make the call. */

  do {

    if (*value && strchr(BASE16,toupper(*value))) {

      run16++; 

    } else {

      if (run16 >= XSRF_B16_MIN && run16 <= XSRF_B16_MAX) {
        _u8 tmp[5];
        _u32 val;

        strncpy(tmp,st,4);
        tmp[4] = 0;
        val = atoi(tmp); 

        if ((val < tmin / 1000000 || val > tmax / 1000000) &&
            (st[0] != st[1] || st[0] != st[2])) return 1;
      }

      run16 = 0;

    }

    if (*value && strchr(BASE64,toupper(*value))) {

      if (!isalpha(*value)) run64_num++;
      if (isupper(*value)) run64_up++;
      if (!run16) run64_true = 1;
      if (!run64) st = value;
      run64++;

    } else {

      if (run64 >= XSRF_B64_MIN && run64 <= XSRF_B64_MAX && 
          ((run64_num >= XSRF_B64_NUM && run64_up >= XSRF_B64_UP) || 
           (run64_num >= XSRF_B64_NUM2)) && run64_true) 
        if (st[0] != st[1] || st[0] != st[2]) return 1;
      run64 = 0;
      run64_num = 0;
      run64_true = 0;
      st = 0;

    }

  } while (*(value++));

  return 0;

}


/* Try to parse cookie header values. */
static void parse_cookies(_u8* str, struct naive_list2* c) {
  _u8 name[128], val[128];

  /* Iterate over cookies. We ignore cookies over 128 bytes for
     name / value, and "special" values such as expiration date,
     version, etc. */

  while (str) {
    while (isspace(*str)) str++;
    if (sscanf(str,"%127[^;=]=%127[^;]",name,val) == 2) {
      if (strcasecmp(name,"expires") && strcasecmp(name,"comment") &&
          strcasecmp(name,"version") && strcasecmp(name,"max-age") &&
          strcasecmp(name,"path") && strcasecmp(name,"domain") && name[0] != '$')
        DYN_ADD2(*c,name,val);
    }

    str = strchr(str + 1 ,';');
    if (str) str++;

  }

}


/* Process the entire HTTP request, parse fields, and extract some preliminary signals. */
struct http_request* collect_request(FILE* client,_u8* ssl_host, _u32 ssl_port) {
  struct http_request* ret;
  _u8 *line, *x;
  _u32 i;

  /* Begin carefully - on CONNECT requests, we do not want to read more than
     absolutely necessary. As soon as non-CONNECT is confirmed, we switch
     to proper buffering. */

  setvbuf(client, cli_buf, _IONBF, 0);

  ret = calloc(1, sizeof(struct http_request));
  if (!ret) fatal("out of memory");

  line = grab_line(client);
  if (!line || !line[0]) exit(0);

  x = strchr(line,' ');
  if (!x || x == line) http_error(client, "URL address missing or malformed request",1);
  *(x++) = 0;

  ret->method = strdup(line);
  if (!ret->method) fatal("out of memory");

  if (strcmp(line,"CONNECT")) {

    /* Ok, safe to handle HTTP at full speed now. */

    setvbuf(client, cli_buf, _IOFBF, sizeof(cli_buf));

    if (!ssl_host) {

      /* Unless coming from within CONNECT, we want a
         properly specified protocol and so forth. */

      if (x[0] == '/') 
        http_error(client, "Direct HTTP requests not allowed",1);

      if (strncmp(x,"http://",7))
        http_error(client, "Unsupported protocol",1);

      x += 7;

    }

  } else {

    /* We do not want CONNECT requests within CONNECT requests, really. */ 
    if (ssl_host) http_error(client,"Evil CONNECT nesting",1);

    ret->is_connect = 1;

  }

  ret->host = x;

  x = strchr(ret->host,' ');
  if (!x) http_error(client,"Missing HTTP protocol version",1);

  if (strcmp(x," HTTP/1.0") && strcmp(x," HTTP/1.1"))
    http_error(client,"unsupported HTTP protocol version",1);

  /* Trim HTTP/1.x part now, we do not need it */

  *x = 0; 
  
  if (!ret->is_connect) {

    ret->path = strchr(ret->host,'/');
    if (!ret->path) http_error(client,"Incomplete request URL",1);
    *(ret->path++) = 0;

  }

  /* Try to find port, if any */

  x = strchr(ret->host,':');

  if (x) { 

    ret->port = atoi(x+1);

    if (!ret->port || ret->port > 65535) 
      http_error(client,"Illegal port specification",1);

    if (ret->port < 1024 && ret->port != 80 && ret->port != 443)
      http_error(client,"Access to this port denied",1);

    *x = 0; 

  } else {
    if (ret->is_connect) ret->port = 443;
      else ret->port = 80;
  }

  /* Populate HTTP envelope data with higher-level CONNECT
     information if one present. */

  if (ssl_host) {
    ret->host = ssl_host;
    ret->port = ssl_port;
    ret->from_ssl = 1;
  }

  if (!ret->host[0])
    http_error(client,"Host name is missing",1);

  ret->host = strdup(ret->host);
  if (!ret->host) fatal("out of memory");

  /* Grab query data */

  if (!ret->is_connect && (x = strchr(ret->path,'?'))) {

    *(x++) = 0;
    ret->query = strdup(x);
    if (!ret->query) fatal("out of memory");

  }

  /* Grab path data */

  if (!ret->is_connect) {

    ret->path = strdup(ret->path);
    if (!ret->path) fatal("out of memory");
    
    x = strrchr(ret->path,'.');

    if (x) ret->ext = x + 1;

  }

  /* Request target is now fully parsed. Let's collect headers, if any. */

  while (1) {

    line = grab_line(client);

    if (!line) http_error(client,"Incomplete or malformed request headers",1);

    /* Empty line == end of headers */
    if (!line[0]) break;

    x = strchr(line,':');
    if (!x) http_error(client,"Invalid request header",1);
    *x = 0;
    while (isspace(*(++x)));

    if (!strcasecmp(line,"Content-Length")) { 

      ret->payload_len = atoi(x); 

      if (ret->payload_len > MAXPAYLOAD)
        http_error(client,"Payload size limit exceeded",1);

    }

    if (!strncasecmp(line,"Cookie",6))
      parse_cookies(x,&ret->cookies);

    if (!strcasecmp(line,"Referer")) {
      _u8* rh;

      ret->referer = strdup(x);
      if (!ret->referer) fatal("out of memory");

      /* Extract referer host to simplify other checks later on. */

      if ((rh = strstr(x,"://"))) {
        _u8* x;

        rh = strdup(rh + 3);
        if (!rh) fatal("out of memory");
        if ((x = strchr(rh,'/'))) *x = 0;
        if ((x = strchr(rh,':'))) *x = 0;

        ret->ref_host = rh;

      }

    }

    if (!strcasecmp(line,"X-Ratproxy-Loop")) 
      http_error(client,"Proxy loop detected",1);

    /* These are specific to publicly documented anti-XSRF features of
       Google Web Toolkit and Google Data APIs; this might be further
       extended to accomodate other custom schemes in popular frameworks. */

    if (!strcasecmp(line,"Authorization") && !strncasecmp(x,"GoogleLogin auth=",17)) {
      ret->xsrf_safe = 1;
      ret->authsub = 1;
    }

    if (!strcasecmp(line,"Content-Type")) {

      if (rp_strcasestr(x,"text/x-gwt-rpc")) { ret->xsrf_safe = 1; ret->authsub = 1; }

      if (rp_strcasestr(x,"multipart/form-data")) ret->multipart = 1;
      else if (!rp_strcasestr(x,"application/x-www-form-urlencoded")) ret->non_param = 1;
    }

    DYN_ADD2(ret->h,line,x);

  }

  /* Get POST payload */

  if (ret->payload_len) {

    ret->payload = malloc(ret->payload_len + 1);
    if (!ret->payload) fatal("out of memory");

    if (fread(ret->payload,ret->payload_len,1,client) != 1) 
      http_error(client,"Premature end of payload data",0);

    /* To make string matching safe. */
    ret->payload[ret->payload_len] = 0;

  }

  /* Parse GET/POST parameters */

  if (ret->query) parse_urlencoded(&ret->p, ret->query);

  ret->ppar_bound = ret->p.c;

  /* Do not parse payloads of arcane types. */

  if (ret->payload && !ret->non_param) {
    if (ret->multipart) parse_multipart(&ret->p, ret->payload, ret->payload_len);
     else parse_urlencoded(&ret->p, ret->payload);
  }

  /* Locate XSRF tokens, if any */
  /* Do not perform contains_token() checks on file fields. */

  for (i=0;i<ret->p.c;i++)
    if (!ret->p.fn[i][0] && contains_token(ret->p.v1[i],ret->p.v2[i]))
      { ret->xsrf_safe = 1; break; }

  return ret;

}


/* Connect to server */
static FILE* open_server(FILE* client, _u8* host, _u32 port) {
  FILE* ret;
  struct sockaddr_in sin;
  struct hostent* he;
  _s32 ss;

  if (!(he = gethostbyname(host)) || !(he->h_addr_list[0])) 
    http_error(client,"Unable to find target host",0);

  ss = socket(PF_INET, SOCK_STREAM, 0);
  if (ss < 0) pfatal("socket() failed");

  sin.sin_family = PF_INET;
  sin.sin_port   = htons(port);

  memcpy(&sin.sin_addr, he->h_addr_list[0], 4);

  if (connect(ss,(struct sockaddr*)&sin,sizeof(struct sockaddr_in)))
    http_error(client,"Connection to target failed",0);

  ret = fdopen(ss,"w+");
  if (!ret) fatal("fdopen() failed");

  setvbuf(ret, srv_buf, _IOFBF, sizeof(srv_buf));

  return ret;

}


/* Connect to server, take proxy CONNECT handling into account */
FILE* open_server_complete(FILE* client, struct http_request* r) {
  FILE* ret;
  _u8* l;

  if (use_proxy) 
    ret = open_server(client, use_proxy, proxy_port);
  else 
    ret = open_server(client, r->host, r->port);

  if (r->is_connect) {

    if (use_proxy) {
      fprintf(ret,"CONNECT %s:%u HTTP/1.0\r\n\r\n",r->host,r->port);
      fflush(ret);

      setvbuf(ret, srv_buf, _IONBF, 0);
      /* Sink proxy response */
      while ((l=grab_line(ret)) && l[0]);
    }

    if (client) {
      fprintf(client,"HTTP/1.0 200 Go ahead, please.\r\n\r\n");
      fflush(client);
    }

  } 

  return ret;

}


#define NEEDS_URLENC(x) \
   (!(x) || !strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.",toupper(x)))


/* Rewrite GET and POST parameters as needed. */
void reconstruct_request(struct http_request* r) {
  struct dyn_str p = { 0, 0 }, q = { 0, 0 };
  _u32 cp = 0, i;
  _u8 c;
  _u8 tmp[32];

  /* Encode params to query string, until ppar boundary is hit. */

  for (;cp<r->p.c;cp++) {

    if (cp == r->ppar_bound) break;

    if (q.l) STR_APPEND_CHAR(q,'&');

    i = 0;
    while ((c=r->p.v1[cp][i])) {
      if (NEEDS_URLENC(c)) {
        sprintf(tmp,"%%%02X",c);
      } else {
        tmp[0] = c;
        tmp[1] = 0;
      }
      STR_APPEND(q,tmp);
      i++;
    }

    STR_APPEND_CHAR(q,'=');

    i = 0;
    while ((c=r->p.v2[cp][i])) {
      if (NEEDS_URLENC(c)) {
        sprintf(tmp,"%%%02X",c);
      } else {
        tmp[0] = c;
        tmp[1] = 0;
      }
      STR_APPEND(q,tmp);
      i++;
    }

  }

  /* Update query string. */
  if (q.l) r->query = q.v;


  /* Deal with the rest of parameters, putting them in a multipart
     envelope or as urlencoded payload, as needed. */
  
  if (r->multipart) {

    /* Update boundary; be just random enough to prevent accidents. */

    sprintf(tmp,"ratproxybound%08x",rand());
    r->use_boundary = strdup(tmp);
    if (!r->use_boundary) fatal("out of memory");

    for (;cp<r->p.c;cp++) {
      STR_APPEND(p,"--");
      STR_APPEND(p,r->use_boundary);
      STR_APPEND(p,"\r\nContent-Disposition: form-data; name=\"");
      STR_APPEND(p,r->p.v1[cp]);

      if (r->p.fn[cp][0]) {
        STR_APPEND(p,"\"; filename=\"");
        STR_APPEND(p,r->p.fn[cp]);
      }

      STR_APPEND(p,"\"\r\n\r\n");
      if (r->p.l2[cp]) {
        STR_APPEND_RAWMEM(p,r->p.v2[cp],r->p.l2[cp]);
      } else {
        STR_APPEND(p,r->p.v2[cp]);
      }

      STR_APPEND(p,"\r\n");

    }

    STR_APPEND(p,"--");
    STR_APPEND(p,r->use_boundary);
    STR_APPEND(p,"--\r\n");
    
  } else if (!r->non_param) {

    for (;cp<r->p.c;cp++) {

      if (p.l) STR_APPEND_CHAR(p,'&');

      i = 0;
      while ((c=r->p.v1[cp][i])) {
        if (NEEDS_URLENC(c)) {
          sprintf(tmp,"%%%02X",c);
        } else {
          tmp[0] = c;
          tmp[1] = 0;
        }
        STR_APPEND(p,tmp);
        i++;
      }
  
      STR_APPEND_CHAR(p,'=');

      i = 0;
      while ((c=r->p.v2[cp][i])) {
        if (NEEDS_URLENC(c)) {
          sprintf(tmp,"%%%02X",c);
        } else {
          tmp[0] = c;
          tmp[1] = 0;
        }
        STR_APPEND(p,tmp);
        i++;

      }

    }

    if (p.l) STR_APPEND(p,"\r\n");

  } else return; /* Leave payload intact. */

  /* Update POST string. */
  if (p.l) {
    r->payload = p.v;
    r->payload_len = p.l;
  }

  return;

}


/* Detect and convert GWT RPC syntax where appropriate. This is specific to
   Google Web Toolkit. */
static _u8* maybe_gwt_rpc(_u8* str) {
  struct dyn_str p = { 0, 0 };
  _u8 *c = str, *n;
  _u32 num = 0;

  _u32 l = strlen(str);
  if (l < 3 || str[l-3] != 0xEF || str[l-2] != 0xBF || str[l-1] != 0xBF) return str;

  STR_APPEND(p,"GWT_RPC[");

  while ((n = strstr(c,"\xEF\xBF\xBF"))) {
    *n = 0;

    if (num > 4) {
      if (num != 5) STR_APPEND_CHAR(p,',');   
      STR_APPEND_CHAR(p,'\'');

      if (!strncmp(c,"[L",2)) c += 2;

      if (!strncmp(c,"com.google.",11) || !strncmp(c,"java.",5)) c = strrchr(c,'.') + 1;

      /* We *could* escape here, but it's probably not worth the effort. */

      STR_APPEND(p,c); 
      STR_APPEND_CHAR(p,'\'');
    }

    num++;
    *n = '\xEF';
    c = n + 3;
  }

  STR_APPEND_CHAR(p,']');

  return p.v;

}


/* Convert multipart data to URLencoded string, to simplify reporting. */
_u8* stringify_payload(struct http_request* r) {
  struct dyn_str p = { 0, 0 };
  _u32 cp, i, c;
  _u8 tmp[32];
  
  if (!r->multipart) return maybe_gwt_rpc(r->payload);

  /* Reconstruct payload from multipart boundary... */

  for (cp=r->ppar_bound;cp<r->p.c;cp++) {

    if (p.l) STR_APPEND_CHAR(p,'&');

    i = 0;
    while ((c=r->p.v1[cp][i])) {
      if (NEEDS_URLENC(c)) {
        sprintf(tmp,"%%%02X",c);
      } else {
        tmp[0] = c;
        tmp[1] = 0;
      }
      STR_APPEND(p,tmp);
      i++;
    }

    STR_APPEND_CHAR(p,'=');

    /* When dealing with a file field, use field name, rather than
       field data. */

    if (r->p.fn[cp][0]) {
      STR_APPEND(p,"FILE[");

      i = 0;
      while ((c=r->p.fn[cp][i])) {
        if (NEEDS_URLENC(c)) {
          sprintf(tmp,"%%%02X",c);
        } else {
          tmp[0] = c;
          tmp[1] = 0;
        }
        STR_APPEND(p,tmp);
        i++;
      }

      STR_APPEND_CHAR(p,']');

    } else {

      i = 0;
      while ((c=r->p.v2[cp][i])) {
        if (NEEDS_URLENC(c)) {
          sprintf(tmp,"%%%02X",c);
        } else {
          tmp[0] = c;
          tmp[1] = 0;
        }
        STR_APPEND(p,tmp);
        i++;
      }

    }

  }

  return p.v;

}


/* Do a naive date comparison for t-1 sec/min/hr scenarios. */
_u8 comp_dates(_u8* exp, _u8* dat) {
  _s32 i = strlen(dat), dc = 0;

  if (i != strlen(exp)) return 1;

  while (--i >= 0) {
    if (exp[i] != dat[i]) {
      if (!isdigit(dat[i]) || exp[i] > dat[i] || ++dc > 1) return 1;
    }
  }

  return 0;
}



/* Send HTTP request, collect and parse response, spot header-related problems. */
struct http_response* send_request(FILE* client, FILE* server, struct http_request* r,
                                   _u8 strip_state) {
  struct http_response* ret;
  _u8 *line, *x;
  _s32 decl_clen = -1;
  _u32 i;
  _u8 port_spec[16] = { 0 };
  _u8 *exp_value = 0, *dat_value = 0;

  /* Send the request... unfortunately, we cannot specify :80 on all
     standard requests, as some URL rewriters that redirect to https
     will copy this over and cause problems. */

  if (!r->from_ssl) {
    if (r->port != 80) sprintf(port_spec,":%u",r->port);
  } else {
    if (r->port != 443) sprintf(port_spec,":%u",r->port);
  }

  if (use_proxy && !r->from_ssl)
    fprintf(server,
      "%s http://%s:%u/%s%s%s HTTP/1.0\r\n"
      "Connection: close\r\n"
      "Host: %s%s\r\n"
      "Accept-Encoding: identity\r\n"
      "X-Ratproxy-Loop: 1\r\n"
      "Content-Length: %u\r\n", r->method, r->host, r->port, r->path,
      r->query ? "?" : "", r->query ? r->query : (_u8*)"", 
      r->host, port_spec, r->payload_len);
  else
    fprintf(server,
      "%s /%s%s%s HTTP/1.0\r\n"
      "Connection: close\r\n"
      "Host: %s%s\r\n"
      "Accept-Encoding: identity\r\n"
      "X-Ratproxy-Loop: 1\r\n"
      "Content-Length: %u\r\n", r->method, r->path,
      r->query ? "?" : "", r->query ? r->query : (_u8*)"", 
      r->host, port_spec, r->payload_len);

  if (!strip_state)
    for (i=0;i<r->h.c;i++) {

      /* There are several types of headers we'd rather skip
         and override elsewhere. */

#ifdef FORCE_NOCACHE
      if (!strncasecmp(r->h.v1[i],"If-",3)) continue;
#endif /* FORCE_NOCACHE */

      if (!strcasecmp(r->h.v1[i],"Host")) continue;
      if (!strcasecmp(r->h.v1[i],"Range")) continue;
      if (!strcasecmp(r->h.v1[i],"Connection")) continue;
      if (!strncasecmp(r->h.v1[i],"Proxy-",6)) continue;
      if (!strcasecmp(r->h.v1[i],"Accept-Encoding")) continue;
      if (!strcasecmp(r->h.v1[i],"Content-Length")) continue;

      /* Override multipart boundary on requests after rewriting. */

      if (!strcasecmp(r->h.v1[i],"Content-Type") && r->use_boundary) {
        fprintf(server,"Content-Type: multipart/form-data; boundary=%s\r\n",r->use_boundary);
        continue;
      }

      fprintf(server,"%s: %s\r\n",r->h.v1[i],r->h.v2[i]);

    }

  fprintf(server,"\r\n");

  if (r->payload_len) 
    fwrite(r->payload,r->payload_len,1,server);

  fflush(server);

  /* Ok, sending complete. */

  /* Process the response... */

  ret = calloc(1,sizeof(struct http_response));
  if (!ret) fatal("out of memory");

  ret->ext = r->ext;

  line = grab_line(server);

  if (!line || !line[0]) http_error(client,"Malformed HTTP response",0);

  x = strchr(line,' ');
  if (!x || x == line) http_error(client,"HTTP response code missing",0);
  *(x++) = 0;

  ret->code = atoi(x);
  if (ret->code < 100 || ret->code > 999) 
    http_error(client,"Invalid HTTP response code",0);

  while (1) {

    line = grab_line(server);
    if (!line) http_error(client,"Premature end of server headers",0);

    if (!line[0]) break;

    x = strchr(line,':');
    if (!x) http_error(client,"Invalid response header",0);
    *x = 0;
    while (isspace(*(++x)));

    for (i=0;i<ret->h.c;i++) 
      if (!strcasecmp(line,ret->h.v1[i]) && strcmp(x,ret->h.v2[i]) &&
           strncasecmp(line,"Set-Cookie",10) && strncasecmp(line,"X-Cache",7) &&
           strncasecmp(line,"Server",7))
        ret->has_multiple = 1;

    /* Again, some headers need to be analyzed in more detail or skipped. */

    /* Caching headers checks... */
    if (!strcasecmp(line,"Expires")) {
      exp_value = strdup(x);
      if (!exp_value) fatal("out of memory");
    }

    if (!strcasecmp(line,"Date")) {
      dat_value = strdup(x);
      if (!dat_value) fatal("out of memory");
    }

    /* Both "no-store" and "max-age=0" are generally discouraged, but in practice,
       should be sufficient, so let's be polite. */

    /* TODO: These checks should be probably more robust to detect typos
       such as missing whitespaces. */

    if (!strcasecmp(line,"Cache-Control")) {
      if (strstr(x,"no-cache") || strstr(x,"private") || 
          strstr(x,"max-age=0") || strstr(x,"no-store"))
        ret->cc11intent = INTENT_PRIV; else ret->cc11intent = INTENT_PUB;
    }

    if (!strcasecmp(line,"Pragma")) {
      if (strstr(x,"no-cache")) ret->pr10intent = INTENT_PRIV; 
        else ret->pr10intent = INTENT_PUB;
    }

    if (!strcasecmp(line,"Connection")) continue;
    if (!strcasecmp(line,"Content-Range")) continue;

    if (!strcasecmp(line,"Content-Type")) {
      _u8 *copy = strdup(x), *y;
      if (!copy) fatal("out of memory");

      if ((y = strrchr(copy,';'))) {
        *(y++) = 0;
        while (isspace(*y)) y++;
        if (!strncasecmp(y,"charset=",8)) {
          y += 8;
          if (*y == '"' && y[strlen(y)-1] == '"') {
            y[strlen(y)-1]=0;
            y++;
          }
          ret->charset = y;
        }
      } 

      ret->mime_type  = copy;

    }

    if (!strcasecmp(line,"Content-Disposition")) {
      _u8* y;

      ret->is_attach = (strncasecmp(x,"attachment;",11) == 0) || 
                       (strcasecmp(x,"attachment") == 0);

      /* If filename is specified, try to grab it (it supersedes
         any URL-derived ones). */

      y=strrchr(x,'.');
      if (y && y[1] && y[1] != '"') {
        ret->ext = strdup(y + 1);
        if (!ret->ext) fatal("out of memory");
        y = strchr(y + 1,'"');
        if (y) *y=0;
      }

    }

    if (!strcasecmp(line,"Location")) {
      ret->location = strdup(x);
      if (!ret->location) fatal("out of memory");
    }

    if (!strcasecmp(line,"Set-Cookie")) parse_cookies(x,&ret->cookies);

    if (!strcasecmp(line,"Content-Length")) {

      decl_clen = atoi(x);
      if (decl_clen < 0) 
        http_error(client,"Bogus content length returned by server.",0);

      continue;
    }

    DYN_ADD2(ret->h,line,x);

  }

  /* Some final "Expires" parsing for caching headers checks... */

  if (exp_value) {

    _u8* year = 0, *z = strchr(exp_value,',');

    ret->ex10intent = INTENT_PUB;

    /* Try to extract the year, at least roughly... */

    if (!isalnum(exp_value[0])) {

      /* "Expires: -1" is a nasty trick, but it works. */
      ret->ex10intent = INTENT_PRIV;

    } else if (dat_value && (!strcmp(exp_value,dat_value) || !comp_dates(exp_value,dat_value))) {
     
      /* Date == Expires is an alternative and valid method. */
      ret->ex10intent = INTENT_PRIV;

    } else {

      if (z && z == exp_value + 3 && strlen(exp_value) > 11) {

        /* Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123 */
        year = exp_value + 11;
        if (*year == ' ') year++;

      } else if (z) {

        /* Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036 */
        year = strchr(z,'-');
        if (year) year = strchr(year + 1,'-');
        if (year) year++;

      } else if (strlen(x) > 19) {

        /* Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format */
        year = exp_value + 19;
        if (*year == ' ') year++;

      }

      if (year) {
        _u32 yval = atoi(year);

        if (yval < 1000) {
          yval += 1900;			  /* 94 -> 1994, 104 -> 2004 */
          if (yval < 1970) yval += 100;   /* 03 -> 2003, 93 -> 1993 */
        }

        if (yval < 2008) ret->ex10intent = INTENT_PRIV;

      }

    }

  }

  /* Headers read. Grab the actual payload, regardless of content
     length (but note a discrepancy, if present).  */

  while (1) {
    _u8 buf[1024];
    _s32 i;
 
    if ((i = fread(buf,1,1024,server)) <= 0) break;

    ret->payload = realloc(ret->payload, ret->payload_len + i + 1);    
    if (!ret->payload) fatal("out of memory");

    memcpy(ret->payload + ret->payload_len, buf, i);
    ret->payload_len += i;

    if (ret->payload_len > MAXPAYLOAD)
      http_error(client,"Response size limit exceeded",0);

  }

  if (ret->payload_len) 
    ret->payload[ret->payload_len] = 0;

  /* Let payload_len < decl_clen slip through - transmission errors happen. */

  if (decl_clen >= 0 && ret->payload_len > decl_clen)
    ret->has_badclen = 1;

  fflush(server);
  fclose(server);

  return ret;

}


/* Just send data back to client. */
void send_response(FILE* client, struct http_response* r) {
  _u32 i;

  setvbuf(client, cli_buf, _IOFBF, sizeof(cli_buf));

  fprintf(client,
    "HTTP/1.0 %u Proxied response\r\n"
    "Connection: close\r\n"
#ifdef FORCE_NOCACHE
    "Pragma: no-cache\r\n"
    "Expires: Fri, 01 Jan 1990 00:00:00 GMT\r\n"
    "Cache-Control: no-cache, must-revalidate\r\n"
#endif /* FORCE_NOCACHE */
    "Content-Length: %u\r\n", r->code, r->payload_len);

  for (i=0;i<r->h.c;i++) {

#ifdef FORCE_NOCACHE
    if (!strcasecmp(r->h1[i],"Expires")) continue;
    if (!strcasecmp(r->h1[i],"Last-Modified")) continue;
    if (!strcasecmp(r->h1[i],"Cache-Control")) continue;
    if (!strcasecmp(r->h1[i],"Pragma")) continue;
#endif /* FORCE_NOCACHE */

    fprintf(client,"%s: %s\r\n",r->h.v1[i],r->h.v2[i]);
  }

  fprintf(client,"\r\n");

  if (r->payload_len)
    fwrite(r->payload,r->payload_len,1,client);

  fflush(client);
  fclose(client);

}



/* Calculate a checksum for response payload */
void checksum_response(struct http_response* r) {
  MD5_CTX ctx;
  _u8  res[16];

  if (use_len) {
    r->cksum = r->payload_len;
    return;
  }

  if (!r->payload_len) return;

  MD5_Init(&ctx);
  MD5_Update(&ctx, r->payload, r->payload_len);
  MD5_Final((char*)res, &ctx);

  r->cksum = *(_u64*)res;

}


/* Attempt charset sniffing inside the payload; currently, supports HTML http-equiv only;
   kinda fuzzy, but should be good enough. */

/* TODO: Make this a bit more robust; reversed http-equiv / content order is
   not detected, for example. */

void detect_charset(struct http_response* r) {
  _u8  sniffed[33];
  _u32 i, max;
  _u8 got_equiv = 0;

  if (r->payload_len > CHARSNIFF) max = CHARSNIFF; else max = r->payload_len;

  for (i=0;i<max;i++) {

    if (r->payload[i] < 0x20 && !isspace(r->payload[i])) break;

    if (!strncasecmp(r->payload+i,"http-equiv",10)) got_equiv = 1;

    if (r->payload[i] == '>') got_equiv = 0;

    if (got_equiv && !strncasecmp(r->payload+i,"charset=",8)) {
      _u32 p = 0;
      _u8* cp = r->payload + i + 8;
      while (p < 32 && (isalnum(*cp) || *cp == '-' || *cp == '_')) sniffed[p++] = *(cp++);
      sniffed[p] = 0;
      break;
    }

  }

  if (i != max) {
    if (r->charset && strcasecmp(sniffed,r->charset)) r->has_multiple = 1;
    r->charset = strdup(sniffed);
    if (!r->charset) fatal("out of memory");
  }

  if (!r->charset) return;

  i = 0;
  while (valid_charsets[i]) {
    if (!strcasecmp(r->charset,valid_charsets[i])) return;
    i++;
  }

  /* But note that utf8, iso_8859_2, etc, are not recognized and lead to XSS... */
  r->bad_cset = 1;

  if (!r->charset[0]) r->charset = 0;

}


#define TOHEX(c) ("0123456789abcdef"[c])

/* Sanitize output; make sure it's easily reversible, too. */
_u8* S(_u8* string, _u8 nl) {
  _u8* ret = malloc(MAXTOKEN + 10 /* &#x00;...\0 */), *wp = ret;
  if (!ret) fatal("out of memory");

  while (*string) {
    switch (tolower(*string)) {

      /* Well, we kind-of want to maintain readaibility of text output, so let's
         pay the price and let '&' through. */

      case '&':

      /* Quote literally */
      case 'a' ... 'z':
      case '0' ... '9':
      case ' ':  case '+':  case '!':  case '@':  case '#':  case '$':
      case '%':  case '^':  case '*':  case '(':  case ')':  case '-':
      case '_':  case '=':  case '{':  case '[':  case '}':  case ']':
      case ':':  case ';':  case ',':  case '.':  case '?':  case '/':
      case '~':  case '`':  case '\\':
        *(wp++) = *string;
        break;

      /* These can be harmful or confusing, so replace with HTML entities */
      case '"':
      case '\'':
      case '<':
      case '>':
      case '|':
      case 127 ... 255:

entitify:

        *(wp++) = '&';
        *(wp++) = '#';
        *(wp++) = 'x';
        *(wp++) = TOHEX(*string / 16);
        *(wp++) = TOHEX(*string % 16);
        *(wp++) = ';';
        break;

      /* Replace with shorthand codes */
      case '\r':
        if (nl) {
          *(wp++) = *string;
        } else {
          *(wp++) = '\\';
          *(wp++) = 'r';
        }
        break;

      case '\n':
        if (nl) {
          *(wp++) = *string;
        } else {
          *(wp++) = '\\';
          *(wp++) = 'n';
        }
        break;

      case '\t':
        if (nl) {
          *(wp++) = *string;
        } else {
          *(wp++) = '\\';
          *(wp++) = 't';
        }
        break;

      /* Replace with hex tokens */
      default:
        if (nl) goto entitify;
        *(wp++) = '\\';
        *(wp++) = 'x';
        *(wp++) = TOHEX(*string / 16);
        *(wp++) = TOHEX(*string % 16);

    }

    if (wp - ret >= MAXTOKEN) {
      *(wp++) = '.';
      *(wp++) = '.';
      *(wp++) = '.';
      break;
    }

    string++;

  }

  *(wp++) = 0;
  return ret;

}


