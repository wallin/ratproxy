/*
   ratproxy
   --------

   A simple HTTP proxy to use for code audits of rich web 2.0 applications.
   Meant to detect JSON-related and other script-accessible content problems as
   you interact with the tested application and otherwise just mind your business.

   Please use this tool responsibly and in good faith. Thanks.

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
#include <signal.h>
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
#include "mime.h"
#include "ssl.h"
#include "string-inl.h"

static struct naive_list  domains;		/* Domains to keep track of   */

static _u8  check_png,				/* Check all PNG files?       */
            dump_urls,				/* Dump all visited URLs?     */
            all_files,				/* Report all file inclusions */
            all_flash,				/* Report all Flash documents */
            get_xsrf,				/* Report GET XSRF status     */
            bad_js,				/* Report risky Javascript    */
            all_post,				/* Report all POST requests   */
            all_cookie,				/* Report all cookie URLs     */
            picky_cache,			/* Be picky about chdrs       */
            use_double,				/* Make 2, not 1 extra req    */
            try_attacks,			/* Validate XSRF/XSS suspects */
            fix_attacks,			/* Correct XSRF/XSS fallout   */
            log_active,				/* Log cross-domain content   */
            log_mixed,				/* Log mixed content          */
            use_any,				/* Listen on any address      */
            all_xss;				/* Report all XSS suspects    */

static _u32 use_port = DEFAULT_PORT;		/* Proxy port to listen on    */

_u8* use_proxy;					/* Upstream proxy             */
_u8* trace_dir;					/* Trace directory            */
_u32 proxy_port = 8080;				/* Upstream proxy port        */
_u8  use_len;					/* Use length, not cksum      */

static FILE* outfile;				/* Output file descriptor     */

/* Display usage information */
static void usage(_u8* argv0) {

  debug("Usage: %s [ -w logfile ] [ -v logdir ] [ -p port ] [ -d domain ] [ -P host:port ] "
        "[ -xtifkgmjscael2XCr ]\n"
        "   -w logfile    - write results to a specified file (default: stdout)\n"
        "   -v logdir     - write HTTP traces to a specified directory (default: none)\n"
        "   -p port       - listen on a custom TCP port (default: 8080)\n"
        "   -d domain     - analyze requests to specified domains only (default: all)\n"
        "   -P host:port  - use upstream proxy for all requests (format host:port)\n"
        "   -r            - accept remote connections (default: 127.0.0.1 only)\n"
        "   -l            - use response length, not checksum, for identity check\n"
        "   -2            - perform two, not one, page identity check\n"
        "   -e            - perform pedantic caching headers checks\n"
        "   -x            - log all XSS candidates\n"
        "   -t            - log all directory traversal candidates\n"
        "   -i            - log all PNG files served inline\n"
        "   -f            - log all Flash applications for analysis (add -v to decompile)\n"
        "   -s            - log all POST requests for analysis\n"
        "   -c            - log all cookie setting URLs for analysis\n"
        "   -g            - perform XSRF token checks on all GET requests\n"
        "   -j            - report on risky Javascript constructions\n"
        "   -m            - log all active content referenced across domains\n"
        "   -X            - disruptively validate XSRF, XSS protections\n"
        "   -C            - try to auto-correct persistent side effects of -X\n"
        "   -k            - flag HTTP requests as bad (for HTTPS-only applications)\n"
        "   -a            - indiscriminately report all visited URLs\n\n"

        "Example settings suitable for most tests:\n"
        "  1) Low verbosity  : -v <outdir> -w <outfile> -d <domain> -lfscm\n"
        "  2) High verbosity : -v <outdir> -w <outfile> -d <domain> -lextifscgjm\n"
        "  3) Active testing : -v <outdir> -w <outfile> -d <domain> -XClfscm\n\n"

        "Multiple -d options are allowed. Consult the documentation for more.\n", argv0);

  exit(1);

}


#define sayf(x...) fprintf(outfile,x)


/* Check hostname against a list of tracked ones. */
static _u8 host_ok(_u8* hname) {
  _u32 i, hlen;

  /* If no domains defined, accept all. */
  if (!domains.c) return 1;

  hlen = strlen(hname);

  for (i=0;i<domains.c;i++) {
    _u32 dlen = strlen(domains.v[i]);
    if (dlen > hlen) continue;
    if (!strcmp(hname + (hlen - dlen), domains.v[i])) return 1;
  }

  return 0;
}


/* Test for XSSable payload */
static _u8 xss_field(_u8* value, _u8 head) {
  _u32 c = 0;

  if (strlen(value) < (head ? MIN_XSS_HEAD : MIN_XSS_LEN)) return 0;

  while (no_xss_text[c]) {
    if (!strncasecmp(value,no_xss_text[c],strlen(no_xss_text[c]))) return 0;
    c++;
  }
  return 1;
}


#define MOD_PRED    1
#define MOD_AUTH    2
#define MOD_ECHO    4

#define NOECHO(_x) ((_x) & ~MOD_ECHO)
#define ECHO(_x) ((_x) & MOD_ECHO)

/* Check if the page has a predictable URL, user-specific content, echoed parameters. */
static _u8 get_modifiers(struct http_request* req, struct http_response* res) {
  FILE *server;
  static struct http_response* mini = 0;
  _u32 ret = 0;
  _u32 fno = 0;
  _u32 i;

  /* Test for echoed query parameters in response body... */

  if (res->is_text && res->payload_len) {

#ifdef CHECK_ECHO_PATH
    if (req->path && strstr(res->payload,req->path)) ret = MOD_ECHO;
#endif /* CHECK_ECHO_PATH */

    for (i=0;!ret && i<req->p.c;i++) 
      if (!req->p.fn[i][0] && xss_field(req->p.v2[i],0) && strstr(res->payload,req->p.v2[i]))
        { ret = MOD_ECHO; break; }

  }

  /* ...and in HTTP header values. */

  for (i=0;!ret && i<req->p.c;i++)
    if (!req->p.fn[i][0] && xss_field(req->p.v2[i],1)) {
      _u32 j;
      for (j=0;j<res->h.c;j++)
        if (strstr(res->h.v2[j],req->p.v2[i])) { ret = MOD_ECHO; break; }
    }      

  /* Check for predictable URLs. */

  if (!req->xsrf_safe) ret |= MOD_PRED;

  /* Check for authentication. */
  /* Some field names may override our checks. */

  while (auth_fields[fno]) {
    _u32 i;
    for (i=0;i<req->p.c;i++) {
      if (auth_fields[fno][0] == '=') {
        if (!strcasecmp(req->p.v1[i],auth_fields[fno] + 1)) return ret | MOD_AUTH;
      } else {
        if (rp_strcasestr(req->p.v1[i],auth_fields[fno])) return ret | MOD_AUTH;
      }
    }
    fno++;
  }

  /* No cookies? Then do not resend. */
  if (!req->cookies.c) return ret;

  /* Try to verify that the request requires authentication by replaying it with
     no cookies. This should have no side effects in sanely written applications. */

  /* TODO: We should continue also if custom HTTP headers or HTTP auth is detected;
     we currently bail out on this, however. */

  if (!mini) {

    server = open_server_complete(0,req);

    if (req->from_ssl) {
      ssl_setup();
      ssl_start(fileno(server),-1);
      fclose(server);
      server = fdopen(ssl_srv_tap,"w+");
    }

    mini = send_request(0,server,req,1);
    if (req->from_ssl) ssl_shutdown();

    checksum_response(mini);

    if (use_double) {
      _u64 temp = mini->cksum;

      /* ...and do it again! */

      server = open_server_complete(0,req);

      if (req->from_ssl) {
        ssl_setup();
        ssl_start(fileno(server),-1);
        fclose(server);
        server = fdopen(ssl_srv_tap,"w+");
      }

      mini = send_request(0,server,req,1);
      if (req->from_ssl) ssl_shutdown();

      checksum_response(mini);
 
      /* If checksum changes over time, give up. */
      if (temp != mini->cksum) mini->cksum = res->cksum;

    }
    

  }

  if (mini->cksum != res->cksum) ret |= MOD_AUTH;

  return ret;

}


/* DISRUPTIVE CHECK: Try removing XSRF protection, see what happens. */
static void try_replay_xsrf(struct http_request* req, struct http_response* res) {

  FILE *server;
  struct http_response* not;
  struct http_request r2;
  _u32 i;
  _u8 got_token = 0;

  if (!req->xsrf_safe || req->authsub) return;

  memcpy(&r2,req,sizeof(struct http_request));

  /* Duplicate parameter value pointer array, so that we may modify it at will. */

  r2.p.v2 = malloc(r2.p.c * sizeof(_u8*));
  if (!r2.p.v2) fatal("out of memory");
  memcpy(r2.p.v2,req->p.v2,r2.p.c * sizeof(_u8*));

  /* Do not run contains_token() checks on file fields. */

  for (i=0;i<req->p.c;i++)
    if (!req->p.fn[i][0] && contains_token(req->p.v1[i],req->p.v2[i])) {
      got_token = 1;
      r2.p.v2[i] = "0"; /* Clobber value. */
    }

  /* Ooops! */
  if (!got_token) return;

  /* Rebuild query / payload strings. */
  reconstruct_request(&r2);

  server = open_server_complete(0,req);

  if (req->from_ssl) {
    ssl_setup();
    ssl_start(fileno(server),-1);
    fclose(server);
    server = fdopen(ssl_srv_tap,"w+");
  }


  not = send_request(0,server,&r2,0);
  if (req->from_ssl) ssl_shutdown();

  /* Fix potential side effects of our request. */

  if (fix_attacks) {
    server = open_server_complete(0,req);

    if (req->from_ssl) {
      ssl_setup();
      ssl_start(fileno(server),-1);
      fclose(server);
      server = fdopen(ssl_srv_tap,"w+");
    }

    send_request(0,server,req,0); /* sink response */
    if (req->from_ssl) ssl_shutdown();
  }

  checksum_response(not);

  /* Clobbering all XSRF-ish tokens caused no change? */

  if (not->cksum == res->cksum) req->xsrf_safe = 0;

}




/* DISRUPTIVE CHECK: Try injecting XSS payload, see what happens. */
static _u8 try_replay_xss(struct http_request* req, struct http_response* res) {

  FILE *server;
  struct http_response* not;
  struct http_request r2;
  _u32 i;
  _u8 got_candidate = 0;
  _u8* cur;
  _u8 htmlstate = 0, htmlurl = 0;

  if (!res->is_text) return 0;

  memcpy(&r2,req,sizeof(struct http_request));

  /* Duplicate parameter value pointer array, so that we may modify it at will. */

  r2.p.v2 = malloc(r2.p.c * sizeof(_u8*));
  if (!r2.p.v2) fatal("out of memory");
  memcpy(r2.p.v2,req->p.v2,r2.p.c * sizeof(_u8*));

  for (i=0;i<req->p.c;i++) 
    if (!req->p.fn[i][0] && xss_field(req->p.v2[i],0) && strstr(res->payload,req->p.v2[i])
#ifndef XSS_XSRF_TOKENS
         && !contains_token(req->p.v1[i],req->p.v2[i])
#endif /* !XSS_XSRF_TOKENS */
  ) {

      /* This does not account for all scenarios possible XSS scenarios, but is a
         pretty good all-around string. Since we want to minimize the number of
         requests generated, it will have to do. */

      r2.p.v2[i] = "qg:qg qg=-->qg\"qg>qg'qg>qg+qg<qg>";
      got_candidate = 1;

    }

  if (!got_candidate) return 0;

  /* Rebuild query / payload strings. */
  reconstruct_request(&r2);

  server = open_server_complete(0,req);

  if (req->from_ssl) {
    ssl_setup();
    ssl_start(fileno(server),-1);
    fclose(server);
    server = fdopen(ssl_srv_tap,"w+");
  }

  not = send_request(0,server,&r2,0);
  if (req->from_ssl) ssl_shutdown();

  /* Fix potential side effects of our request. */

  if (fix_attacks) {
    server = open_server_complete(0,req);

    if (req->from_ssl) {
      ssl_setup();
      ssl_start(fileno(server),-1);
      fclose(server);
      server = fdopen(ssl_srv_tap,"w+");
    }

    send_request(0,server,req,0); /* sink response */
    if (req->from_ssl) ssl_shutdown();
  }

  if (!not->payload_len) return 0;

  detect_mime(not);

  if (not->is_text)
    detect_charset(not);

  /* Do some minimal and dumbed down HTML parsing on the response to detect q9g
     strings in dangerous configurations. */

#define HS_IN_TAG   1
#define HS_IN_DBLQ  2
#define HS_IN_SNGQ  4
#define HS_IN_COMM  8
#define HS_IN_CDATA 16

  cur = not->payload;

  while (*cur) {

    /* Detect successful XSS attempts... */

    if (!strncasecmp(cur,"qg",2)) {

      /* <tag foo=bar onload=...> */
      if (htmlstate == HS_IN_TAG && !strncasecmp(cur+2," qg=",4)) return 1;

      /* <tag src=foo:bar...> */
      if (htmlurl && !strncasecmp(cur+2,":qg",3)) return 1;

      /* <tag><script>... */
      if (htmlstate == 0 && !strncasecmp(cur+2,"<qg",3)) return 1;

      /* <tag>+ADw-script+AD4-... */
      if (htmlstate == 0 && (!not->charset || not->bad_cset) && !strncasecmp(cur+2,"+qg",3)) return 1;

      /* <tag foo="bar"onload=...> */
      if (htmlstate == (HS_IN_TAG|HS_IN_DBLQ) && !strncasecmp(cur+2,"\"qg",3)) return 1;

      /* <tag foo='bar'onload=...> */
      if (htmlstate == (HS_IN_TAG|HS_IN_SNGQ) && !strncasecmp(cur+2,"'qg",3)) return 1;

    } else {

      /* Handle CDATA blocks */
      if (htmlstate == 0 && !strncasecmp(cur,"<![CDATA[",9)) { htmlstate = HS_IN_CDATA; cur += 9; continue; }
      if (htmlstate == HS_IN_CDATA && !strncmp(cur,"]]>",3)) { htmlstate = 0; cur += 3; continue; }

      /* Handle <!-- --> blocks (this depends on rendering mode, but hey). */
      if (htmlstate == 0 && !strncmp(cur,"<!--",4)) { htmlstate = HS_IN_COMM; cur += 4; continue; }
      if (htmlstate == HS_IN_COMM && !strncmp(cur,"-->",3)) { htmlstate = 0; cur += 3; continue; }

      /* Detect what could pass for tag opening / closure... */
      if (htmlstate == 0 && *cur == '<' && (isalpha(cur[1]) || cur[1] == '!' || cur[1] == '?')) { htmlstate = HS_IN_TAG; cur++; continue; }
      if (htmlstate == HS_IN_TAG && *cur == '>') { htmlstate = 0; htmlurl = 0; cur++; continue; }

 
      /* Handle double quotes around HTML parameters */
      if (htmlstate == HS_IN_TAG && cur[-1] == '=' && *cur == '"') { htmlstate |= HS_IN_DBLQ; cur++; continue; }
      if (htmlstate == (HS_IN_TAG|HS_IN_DBLQ) && *cur == '"') { htmlstate = HS_IN_TAG; cur++; continue; }

      /* Handle single quotes around HTML parameters */
      if (htmlstate == HS_IN_TAG && cur[-1] == '=' && *cur == '\'') { htmlstate |= HS_IN_SNGQ; cur++; continue; }
      if (htmlstate == (HS_IN_TAG|HS_IN_SNGQ) && *cur == '\'') { htmlstate = HS_IN_TAG; cur++; continue; }

      /* Special handling for SRC= and HREF= locations. */

      if (htmlstate == HS_IN_TAG && isspace(cur[-1]) && !strncasecmp(cur,"href=",5)) {
        htmlurl = 1; cur += 5; continue;
      }


      if (htmlstate == HS_IN_TAG && isspace(cur[-1]) && !strncasecmp(cur,"src=",4)) {
        htmlurl = 1; cur += 4; continue;
      }

      /* Cancel mode if any character other than ", ', or qg: URL is encountered. */
      if (htmlurl) htmlurl = 0;

    }

    cur++;

  }

  /* So, no XSS? Bummer. */
  return 0;

}


/* Check for publicly cacheable documents. Returns 0 if not public,
   1 if apparently meant to be public, 2 if partly protected. */
static _u8 is_public(struct http_request* req, struct http_response* res) {
  _u8 http10intent;

  /* "Expires" and "Pragma" should say the same. */
  if (res->pr10intent && res->ex10intent && res->pr10intent != res->ex10intent) return 2;

  http10intent = res->ex10intent ? res->ex10intent : res->pr10intent;

  /* HTTP/1.0 and HTTP/1.1 intents should say the same. */
  if (http10intent && res->cc11intent && http10intent != res->cc11intent) return 2;

  /* [Picky] HTTP/1.0 and HTTP/1.1 intents should not appear at all, or appear at once */
  if (picky_cache && (http10intent ^ res->cc11intent)) {
    if (strcmp(req->method,"GET")) return 0; /* Non-GET requests won't be cached. */
    return 2;
  }

  if (res->cc11intent == INTENT_PRIV || http10intent == INTENT_PRIV) return 0;

  /* No interest in making this document private was expressed... */

  if (strcmp(req->method,"GET")) return 0; /* Non-GET requests won't be cached. */
  return 1;

}



static _u8 dump_fn[1024];
static _u8 dumped_already;

/* Save trace data to file, if requested. */
static _u8* save_trace(struct http_request* req, struct http_response* res) {
  _s32 f;
  _u32 i;
  FILE* out;

  if (!trace_dir) return "-";

  /* Do not save the same request twice. */
  if (dumped_already) return dump_fn;
  dumped_already = 1;

  sprintf(dump_fn,"%.512s/%08x-%04x.trace",trace_dir,(_u32)time(0),getpid());

  f = open(dump_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (f < 0) {    
    debug(">>> Unable to open trace file '%s'! <<<\n",dump_fn);
    return "-";
  } 
  out = fdopen(f,"w");

  fprintf(out,"== REQUEST TO %s:%u (%u headers, %u byte payload) ==\n\n%s /%s%s%s HTTP/1.0\n",
     req->host, req->port, req->h.c, req->payload_len,
     req->method, req->path, req->query ? "?" : "", req->query ? req->query : (_u8*)"");

  for (i=0;i<req->h.c;i++)
    fprintf(out,"%s: %s\n", req->h.v1[i], req->h.v2[i]);

  fprintf(out,"\n");
  if (req->payload_len)
    fwrite(req->payload,req->payload_len > MAXTRACEITEM ? MAXTRACEITEM : req->payload_len,1,out);

  if (req->payload_len > MAXTRACEITEM) 
    fprintf(out,"\n*** DATA TRUNCATED DUE TO SIZE LIMITS ***");

  fprintf(out,"\n\n== SERVER RESPONSE (%u headers, %u byte payload, detected MIME %s) ==\n\n"
    "HTTP/1.0 %u \n",
    res->h.c, res->payload_len, res->mime_type ? res->mime_type : (_u8*)"(none)",
    res->code);

  for (i=0;i<res->h.c;i++)
    fprintf(out,"%s: %s\n", res->h.v1[i], res->h.v2[i]);

  fprintf(out,"\n");
  if (res->payload_len)
    fwrite(res->payload,res->payload_len > MAXTRACEITEM ? MAXTRACEITEM : res->payload_len,1,out);

  if (res->payload_len > MAXTRACEITEM) 
    fprintf(out,"\n*** DATA TRUNCATED DUE TO SIZE LIMITS ***");

  fprintf(out,"\n\n== END OF TRANSACTION ==\n");

  fclose(out);
  close(f);

  return dump_fn;

}


/* Use Flare to decode Flash file, if available. */
static void decode_flash(struct http_response* res) {
  _s32 f, pid;
  _u8 tmp[1024];
  struct stat st;

  if (!dumped_already || !res->payload_len) return; /* ? */

  sprintf(tmp,"%s.swf",dump_fn);

  f = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (f < 0) return;

  write(f, res->payload, res->payload_len);
  close(f);

  if (!(pid = fork())) {
    /* Flare is way too noisy, let's close stderr. */
    close(2);
    execl("./flare","flare",tmp,NULL);
    execlp("flare","flare",tmp,NULL);
    exit(1);
  }

  if (pid > 0) waitpid(pid, (int*)&f, 0);

  unlink(tmp);

  sprintf(tmp,"%s.flr",dump_fn);
  if (stat(tmp,&st) || !st.st_size) unlink(tmp);

  /* So we should have a non-zero length .flr file next to a trace file
     now; ratproxy-report.sh will detect this. */

}


/* A "fuzzy" comparator to avoid reporting "refresher" cookies where some minor parameters
   were changed as new cookie arrivals; but to detect blanking or other major overwrites. */
static _u8 unique_cookies(struct naive_list2* reqc, struct naive_list2* resc) {
  _u32 i,j;

  if (!resc->c) return 0; /* No cookies set at all. */
  if (!reqc->c) return 1; /* All set cookies must be new. */

  for (i=0;i<resc->c;i++) {

    for (j=0;j<reqc->c;j++) {
      if (!strcasecmp(resc->v1[i],reqc->v1[j]) &&       /* Same name   */
          strlen(resc->v2[i]) == strlen(reqc->v2[j]))   /* Same length */
            break; /* ...must be a refresher cookie. */
    }

    /* No refresher cookie matches for one cookie? Good enough. */
    if (j == reqc->c) return 1;

  }

  /* All cookies were refreshers. */
  return 0;

}


/* Cookie renderer, for reporting purposes. */
static _u8* make_cookies(struct naive_list2* reqc, struct naive_list2* resc) {
  _u8* ret = 0;
  _u32 i,j;
  _u8 had_some = 0;

  if (!resc->c) return "-";

#define ALLOC_STRCAT(dest,src) do { \
    _u32 _sl = strlen(src); \
    _u32 _dl = 0; \
    if (dest) _dl = strlen(dest); \
    dest = realloc(dest,_sl + _dl + 1); \
    if (!dest) fatal("out of memory"); \
    strcpy(dest + _dl, src); \
  } while (0)

  for (i=0;i<resc->c;i++) {

    /* Render only newly set cookies! */

    for (j=0;j<reqc->c;j++) {
      if (!strcasecmp(resc->v1[i],reqc->v1[j]) &&       /* Same name   */
          strlen(resc->v2[i]) == strlen(reqc->v2[j]))   /* Same length */
            break; /* ...must be a refresher cookie. */
    }

    if (j == reqc->c) {
      if (!had_some) had_some = 1; else ALLOC_STRCAT(ret,"; ");
      ALLOC_STRCAT(ret,resc->v1[i]);
      ALLOC_STRCAT(ret,"=");
      ALLOC_STRCAT(ret,resc->v2[i]);
    }

  }

  return ret ? ret : (_u8*)"-";
}


/* Check for safe JSON prologues. */
static _u8 is_json_safe(_u8* str) {
  _u32 i = 0;

  while (json_safe[i]) {
    if (!strncmp(str,json_safe[i],strlen(json_safe[i]))) return 1;
    i++;
  }

  return 0;

}


/* Check for scripts that appear to be standalone or empty (as opposed to
   JSON-like dynamically generated response snippets for on-page execution). */
static _u8 standalone_script(_u8* str) {

  if (!str) return 1; /* Empty */

skip_more:

  while (*str && isspace(*str)) str++;

  if (!strncmp(str,"/*",2)) {
    str = strstr(str+2, "*/");
    if (!str) return 1; /* Empty */
    goto skip_more;
  }

  if (!strncmp(str,"//",2)) {
    str += 2;
    while (*str && strchr("\r\n",*str)) str++;
    goto skip_more;
  }

  if (*str == '(') { str++; goto skip_more; }

  if (!*str) return 1; /* Empty */

  /* This is not very scientific - in fact, there is no good way to
     settle this - but should be a pretty good predictor in most cases. */

  if (!strncasecmp(str,"var",3) && isspace(str[3])) return 1; /* Script */
  if (!strncasecmp(str,"function",8) && isspace(str[8])) return 1; /* Script */

  return 0; /* Probably JSON */

}


/* The main request handling and routing routine. */
static void handle_client(FILE* client) {
  FILE *server;
  struct http_request* req;
  struct http_response* res;
  _u8 m;
  _u32 i;
  _u8 got_xss = 0;

#define BEST_MIME (res->sniffed_mime ? res->sniffed_mime : \
                   (res->mime_type ? res->mime_type : (_u8*)""))

  /* TODO: Ideally, S() shouldn't do HTML escaping in machine
     output (just filter | and control chars); but this requires
     ratproxy-report.sh to be reworked. */

// Request printer macros - since most of the data does not change.
#define SHOW_REF_MSG(warn,mesg,mod) \
    sayf("%u|%u|%s|-|%u|%u|%s|http%s://%s:%u/%s%s%s|-|%s|-|%s|-|-|-\n", \
      warn, mod, mesg, res->code, res->payload_len, res->mime_type ? \
      res->mime_type : (_u8*)"-", req->from_ssl ? "s" : "", S(req->host,0), req->port, \
      S(req->path,0), req->query ? "?" : "", req->query ? \
      S(req->query,0) : (_u8*)"", save_trace(req,res), S(req->referer,0))

#define SHOW_MSG(warn,mesg,off_par,mod) \
    sayf("%u|%u|%s|%s|%u|%u|%s|%s|%s|%s|%s|http%s://%s:%u/%s%s%s|%s|%s|%s\n", \
      warn, mod ,mesg, off_par ? S(off_par,0) : (_u8*)"-", \
      res->code, res->payload_len, \
      res->mime_type ? S(res->mime_type,0) : (_u8*)"-", \
      res->sniffed_mime ? S(res->sniffed_mime,0) : (_u8*)"-", \
      res->charset ? S(res->charset,0) : (_u8*)"-", \
      save_trace(req,res), \
      S(req->method,0), req->from_ssl ? "s" : "", S(req->host,0), \
      req->port, S(req->path,0), req->query ? "?" : "", \
      req->query ? S(req->query,0) : (_u8*)"", \
      S(make_cookies(&req->cookies,&res->cookies),0), \
      req->payload_len ? S(stringify_payload(req),0) : (_u8*)"-", \
      res->payload_len ? S(res->payload,0) : (_u8*)"-") 

  /* First, let's collect and complete the request */

  req = collect_request(client,0,0);

  server = open_server_complete(client, req);

  if (req->is_connect) {
    ssl_setup();
    ssl_start(fileno(server),fileno(client));

    fclose(client); fclose(server);
    client = fdopen(ssl_cli_tap,"w+");
    server = fdopen(ssl_srv_tap,"w+");
    if (!client || !server) fatal("out of memory");
    req = collect_request(client, req->host, req->port);

  }

  res = send_request(client, server, req, 0);
  send_response(client,res);
  if (req->from_ssl) ssl_shutdown();

  /* Now, if the target is not within the set of tested domains,
     there are several things we want to check if it originated
     from within the tested locations. */

  if (!host_ok(req->host)) {
    _u8 *refq;

    if (!req->ref_host) goto skip_tests;

    /* Requests between non-analyzed sites do not concern us. */

    if (!host_ok(req->ref_host)) goto skip_tests;

    /* Referer token leakage test: contains_token() succeeds on "Referer" query */

    if ((refq=strchr(req->referer,'?'))) {
      struct naive_list_p p = { 0, 0, 0, 0, 0 };
      _u32 i;

      parse_urlencoded(&p,refq + 1);
      
      for (i=0;i<p.c;i++)
        if (contains_token(p.v1[i],p.v2[i])) break;

      if (i != p.c)
        SHOW_REF_MSG(3,"Referer may leak session tokens",1);

    }

    /* Cross-domain script inclusion check */

    detect_mime(res);

    if (rp_strcasestr(BEST_MIME,"script") || 
        !strcasecmp(BEST_MIME,"application/json")|| !strcasecmp(BEST_MIME,"text/css")) 
      SHOW_REF_MSG(3,"External code inclusion",1);

    /* POST requests between domains - outgoing. */

    if (strcmp(req->method,"GET")) {
      SHOW_REF_MSG(2,"Cross-domain POST requests",0);
    } else if (log_active) {
    
      i = 0;
      while (active_mime[i]) {
        if (!strcasecmp(BEST_MIME,active_mime[i])) {
          SHOW_REF_MSG(1,"References to external active content",1);
          break;
        }
        i++;
      }

    }

    goto skip_tests;

  }

  /* All right, everything below pertains to checks on URLs within
     the tested domain. Let's do some basic information gathering first. */

  checksum_response(res);

  detect_mime(res);

  if (res->is_text)
    detect_charset(res);

  if (dump_urls) SHOW_MSG(0,"!All visited URLs",0,0);

  /* If requested to do so, we need to log non-HTTPS traffic and
     prioritize it depending on document type. */

  if (log_mixed && !req->from_ssl) {

    m = get_modifiers(req,res);

    if (!strcasecmp(BEST_MIME,"text/html") || rp_strcasestr(BEST_MIME,"script") ||
        !strcasecmp(BEST_MIME,"application/json") ||
        !strcasecmp(BEST_MIME,"text/css") || !strcasecmp(BEST_MIME,"application/xhtml+xml"))
      SHOW_MSG(2,"Potential mixed content",0,m);
      else SHOW_MSG(0,"Potential mixed content",0,m);

  }

  /* If instructed to do so, adjust XSRF "safety" rating based on packet
     replay now. */

  if (try_attacks) try_replay_xsrf(req,res);

  /***********************
   * HEADER BASED CHECKS *
   ***********************/

  if (res->code < 200 || res->code >= 400) {

    switch (NOECHO(m = get_modifiers(req,res))) {

      /* No big deal, but warrants an investigation; more important if
         the content is user-specific. */

      case 0:
      case MOD_PRED:
        SHOW_MSG(0,"HTTP errors",0,m); break;
      case MOD_AUTH:
      case MOD_PRED | MOD_AUTH:
        SHOW_MSG(1,"HTTP errors",0,m); break; 

    }

  }

  /* Detect 302 with Location: that contains req->query or req->payload,
     and lacks XSRF token? */

  if (res->location && (req->query || req->payload) && !req->xsrf_safe) {
     _u8* hname = strdup(res->location), *y;
     if (!hname) fatal("out of memory");
     if (!strncasecmp(hname,"http://",7)) hname += 7; else
     if (!strncasecmp(hname,"https://",8)) hname += 8;
     y = hname;
     while (isalnum(*y) || *y == '-' || *y == '.') y++;
     *y = 0;

     if (hname[0] && ((req->query   && rp_strcasestr(req->query,hname)) ||
                      (req->payload && rp_strcasestr(req->payload,hname)))) {
       SHOW_MSG(3,"HTTP redirector",0,1);
     }

  }

  /* If not a HTTP redirector, examine for HTML redirection anyway */

  if (!res->location && (req->query || req->payload) && res->payload && !req->xsrf_safe) {

    _u8* mref=rp_strcasestr(res->payload,"HTTP-EQUIV=\"Refresh\"");
    _u8* hname = mref ? rp_strcasestr(mref + 20, ";URL=") : 0;

    if (hname) {

       _u8* mrefend = strchr(mref + 20,'>'), *y;

       if (mrefend && hname < mrefend) {
         hname = strdup(hname + 5);
         if (!hname) fatal("out of memory");
         if (!strncasecmp(hname,"http://",7)) hname += 7; else
         if (!strncasecmp(hname,"https://",8)) hname += 8;
         y = hname;
         while (isalnum(*y) || *y == '-' || *y == '.') y++;
         *y = 0;

         if (hname[0] && ((req->query   && rp_strcasestr(req->query,hname)) ||
                          (req->payload && rp_strcasestr(req->payload,hname)))) {
           SHOW_MSG(3,"HTML META redirector",0,1);
         }
 
       }

     }

  }

  if (req->multipart) {
    m = get_modifiers(req,res);
    SHOW_MSG(0,"File upload forms",0,m); 
  }

  if (all_post && req->payload && strcasecmp(req->method,"GET")) {
    m = get_modifiers(req,res);
    SHOW_MSG(0,"All POST requests",0,m);
  }

  if (unique_cookies(&req->cookies,&res->cookies) && !req->xsrf_safe && (req->payload || req->query)) {
    m = get_modifiers(req,res);
    SHOW_MSG(2,"Cookie issuer with no XSRF protection",0,m);

    /* TODO: Maybe check if query data copied over to cookies. */

  }

  if (all_cookie && unique_cookies(&req->cookies,&res->cookies)) {
    m = get_modifiers(req,res);
    SHOW_MSG(0,"All cookie setting URLs",0,m);
  }

  /* If there's a request that requires authentication and accept parameters,
     it should probably employ anti-XSRF protection of some sort. */

  if (!req->xsrf_safe && (req->payload || req->query)) {

    m = get_modifiers(req,res);

    if (m & MOD_AUTH) {

      if (!strcasecmp(req->method,"GET")) {
        if (get_xsrf)
          SHOW_MSG(0,"GET query with no XSRF protection",0,m);
      } else
        SHOW_MSG(3,"POST query with no XSRF protection",0,m);

    } else {

      /* POST requests that do not require authentication are interesting,
         though not necessarily very troubling. */

      if (strcasecmp(req->method,"GET"))
        SHOW_MSG(1,"POST query with no XSRF protection",0,m);
    }

  }

  if (res->has_multiple) {

    /* Duplicate Content-Type or Content-Disposition headers are a sure
       way to get into trouble. */

    switch (NOECHO(m = get_modifiers(req,res))) {
   
      case 0:
        SHOW_MSG(1,"Ambiguous HTTP content headers",0,m); break;
      case MOD_PRED:
      case MOD_AUTH:
        SHOW_MSG(2,"Ambiguous HTTP content headers",0,m); break;
      case MOD_PRED | MOD_AUTH:
        SHOW_MSG(3,"Ambiguous HTTP content headers",0,m); break; 
 
    }

  }

  /* Unusual, but hey, let's report it because we can. */

  if (res->has_badclen)
    SHOW_MSG(3,"Misstated Content-Length",0,0);

  /* POST requests that pass auth tokens between domains. If coming
     from an excluded domain, this is more important. */

  if (req->ref_host && strcmp(req->method,"GET") &&
      strcasecmp(req->host,req->ref_host)) {
    if (!host_ok(req->ref_host)) 
      SHOW_REF_MSG(2,"Cross-domain POST requests",0);
    else
      SHOW_REF_MSG(1,"Cross-domain POST requests",0);
  }

  /* Report caching headers issues (but only once!) */

  if (!req->from_ssl && unique_cookies(&req->cookies,&res->cookies) && is_public(req,res)) {

    switch (NOECHO(m = get_modifiers(req,res))) {
      case 0:
      case MOD_AUTH:
        SHOW_MSG(1,"Bad caching headers","cacheable SetCookie",m);
        break;
      case MOD_PRED:
      case MOD_AUTH | MOD_PRED:
        SHOW_MSG(3,"Bad caching headers","cacheable SetCookie",m);
        break;
    }

  } else if (!req->from_ssl && is_public(req,res) == 2 && res->payload_len && res->code < 300) {

    m = get_modifiers(req,res);

    if (NOECHO(m) == (MOD_AUTH | MOD_PRED)) SHOW_MSG(3,"Bad caching headers","Expires/Date/Cache-Control mismatch",m);
      else if (NOECHO(m) == MOD_AUTH) SHOW_MSG(2,"Bad caching headers","Expires/Date/Cache-Control mismatch",m);

  }

  /************************
   * PAYLOAD BASED CHECKS *
   ************************/

  /* If the document is empty, bail out (everything below relies on non-NULL res->payload). */

  if (!res->payload_len) goto skip_tests;

  if (res->is_text && (!res->charset || res->bad_cset)) {

    /* Missing charsets and typos lead to UTF-7 cross-site scripting. */

    if (strcasecmp(BEST_MIME,"text/css")) {

      /* Cases where content is echoed back are higher risk, but we care
         about stored attacks too. */

      switch (NOECHO(m = get_modifiers(req,res))) {
   
        case 0:
          SHOW_MSG(ECHO(m) ? 3 : 1,"Bad or no charset declared for renderable file",0,m); break;
        case MOD_PRED:
        case MOD_AUTH:
          SHOW_MSG(ECHO(m) ? 3 : 1,"Bad or no charset declared for renderable file",0,m); break;
        case MOD_PRED | MOD_AUTH:
          SHOW_MSG(ECHO(m) ? 3 : 2,"Bad or no charset declared for renderable file",0,m); break; 
 
      }

    }

  }

  if (res->mime_type && !strcasecmp(res->mime_type,"text/plain")) {

    /* Modern interactive websites have very few reasons to serve 
       text/plain documents, and if these documents are user-controlled,
       content sniffing can lead to XSS. */

    /* Let's just ignore text/css; the next check will catch it anyway,
       and it's nearly guaranteed to be harmless. */

    if (strcasecmp(BEST_MIME,"text/css")) 
      switch (NOECHO(m = get_modifiers(req,res))) {

      case 0:
        SHOW_MSG(1,"MIME type set to text/plain",0,m); break;
      case MOD_AUTH:
      case MOD_PRED:
        SHOW_MSG(ECHO(m) ? 2 : 1,"MIME type set to text/plain",0,m); break;
      case MOD_PRED | MOD_AUTH:
        SHOW_MSG(ECHO(m) ? 3 : 2,"MIME type set to text/plain",0,m); break; 

    }

  }

  if (!res->mime_type) {

    /* Having no MIME type almost always warrants scrutiny, as content
       sniffing runs rampant and may have a browser-specific outcome. */

    switch (NOECHO(m = get_modifiers(req,res))) {

      case 0:
        SHOW_MSG(1,"MIME type missing",0,m); break;
      case MOD_PRED:
      case MOD_AUTH:
        SHOW_MSG(ECHO(m) ? 2 : 1,"MIME type missing",0,m); break;
      case MOD_PRED | MOD_AUTH:
        SHOW_MSG(ECHO(m) ? 3 : 2,"MIME type missing",0,m); break; 

    }

  }

  /* Let's be annoying here for initial betas, why not?. */

  if (res->payload_len > 10 && res->mime_type && !res->sniffed_mime)
    debug(">>> Failed to detect MIME type '%s' (%s:%u/%s?%s), tell lcamtuf@google.com <<<\n",
      S(res->mime_type,0), S(req->host,0), req->port, S(req->path,0), req->query ? 
      S(req->query,0) : (_u8*)"");

  if (res->sniffed_mime && res->mime_type &&
      strcasecmp(res->mime_type, res->sniffed_mime)) {

    if (res->is_text) {

      /* MIME mismatch on text formats that are rendered by the browser
         is usually a major problem and may lead to XSS. */

      /* Do not be too picky about HTML - XHTML mismatches, though... */

      if (res->mime_type && res->sniffed_mime &&
          !strcasecmp(res->mime_type,"text/html") &&
          !strcasecmp(res->sniffed_mime,"application/xhtml+xml"))
        goto ignore_mime_mismatch;

      if (strcasecmp(BEST_MIME,"text/css")) 
        switch (NOECHO(m = get_modifiers(req,res))) {
  
        case 0:
          SHOW_MSG(1,"MIME type mismatch on renderable file",0,m); 
          break;
        case MOD_AUTH:
        case MOD_PRED:
          SHOW_MSG(ECHO(m) ? 2 : 1,"MIME type mismatch on renderable file",0,m); break;
        case MOD_PRED | MOD_AUTH:
          SHOW_MSG(ECHO(m) ? 3 : 2,"MIME type mismatch on renderable file",0,m); break; 
  
      }

    } else if (!strncasecmp(BEST_MIME,"image/",6)) {

      /* Subtle mismatches with images may have disastrous effects as 
         content sniffing inevitably kicks in and may lead to HTML
         parsing in EXIF or comment data.*/

      switch (NOECHO(m = get_modifiers(req,res))) {
  
        case 0:
          SHOW_MSG(1,"MIME type mismatch on image file",0,m); break;
        case MOD_AUTH:
        case MOD_PRED:
          SHOW_MSG(2,"MIME type mismatch on image file",0,m); break;
        case MOD_PRED | MOD_AUTH:
          SHOW_MSG(3,"MIME type mismatch on image file",0,m); break; 
  
      }

    } else {

      if (!strcasecmp(res->mime_type,"application/octet-stream")) {

        /* Defaulting to application/octet-stream may trigger content
           sniffing. */

        switch (NOECHO(m = get_modifiers(req,res))) {
   
          case 0:
            SHOW_MSG(1,"Generic MIME type used",0,m); break;
          case MOD_AUTH:
          case MOD_PRED:
            SHOW_MSG(ECHO(m) ? 2 : 1,"Generic MIME type used",0,m); break;
          case MOD_PRED | MOD_AUTH:
            SHOW_MSG(ECHO(m) ? 3 : 2,"Generic MIME type used",0,m); break; 
  
        }

      } else {

        /* Other MIME type mismatches still warrant attention, as this
           might be a result of a typo or the like. */

        switch (NOECHO(m = get_modifiers(req,res))) {
   
          case 0:
          case MOD_AUTH:
          case MOD_PRED:
            SHOW_MSG(1,"MIME type mismatch on binary file",0,m); break;
          case MOD_PRED | MOD_AUTH:
            SHOW_MSG(2,"MIME type mismatch on binary file",0,m); break; 
  
        }

      }

    }

  }

ignore_mime_mismatch:

  if ((rp_strcasestr(BEST_MIME,"script") || !strcasecmp(BEST_MIME,"application/json"))) {

    /* JSON is almost always worth inspecting - doubly so if not secured against XSRF. */

    switch (NOECHO(m = get_modifiers(req,res))) {
   
      case 0:
      case MOD_PRED:
        break;

      case MOD_AUTH:
        SHOW_MSG(standalone_script(res->payload) ? 0 : 1,
                 "Dynamic Javascript for direct inclusion",0,m); break;
      case MOD_PRED | MOD_AUTH:

        /* TODO: Move this to a proper Javascript analyzer instead. */

        if (standalone_script(res->payload)) {
          SHOW_MSG(0,"Dynamic Javascript for direct inclusion",0,m);
        } else if (is_json_safe(res->payload)) {
          SHOW_MSG(ECHO(m) ? 1 : 0,"Dynamic Javascript for direct inclusion",0,m);
        } else {
          SHOW_MSG(ECHO(m) ? 3 : 2,"Dynamic Javascript for direct inclusion",0,m);
        }
        break;
 
    }

  }

  if (!strcasecmp(BEST_MIME,"image/png") && !res->is_attach) {

    switch (NOECHO(m = get_modifiers(req,res))) {
   
      case 0:
      case MOD_PRED:
        if (check_png) SHOW_MSG(2,"Inline PNG image",0,m); break;
      case MOD_AUTH:
        SHOW_MSG(2,"Inline PNG image",0,m); break;
      case MOD_PRED | MOD_AUTH:
        SHOW_MSG(3,"Inline PNG image",0,m); break; 
 
    }

  }

  /* Echoed markup in a query is bad. */

  for (i=0;i<req->p.c;i++)
    if (!req->p.fn[i][0] && strchr(req->p.v2[i],'<') && strstr(res->payload,req->p.v2[i])) {
 
      switch (NOECHO(m = get_modifiers(req,res))) {
   
        case 0:
        case MOD_AUTH:
          SHOW_MSG(2,"Direct markup echoed back",req->p.v2[i],m); break;
        case MOD_PRED:
        case MOD_PRED | MOD_AUTH:
          SHOW_MSG(3,"Direct markup echoed back",req->p.v2[i],m); break; 
      }

      break;

    }

  /* Non-echoed paths in query are often bad, though there are some common patterns
     of false psoitives. */

  for (i=0;i<req->p.c;i++) if (!req->p.fn[i][0] && strlen(req->p.v2[i]) < MAX_FPATH &&
    strcmp(req->p.v1[i],"utmp") /* Analytics-specific. */ ) {
    _u8* x = strchr(req->p.v2[i],'/');
    _u8* y = strchr(req->p.v2[i],'.');

    if (!x) continue;				/* No slash - no problem       */
    if (y && y <= x) continue;			/* "www.foo.com/bar/baz.jpg"   */
    if (x[1] == '/') continue;			/* "http://www.foo.com/"       */

    if (isdigit(x[1]) && isdigit(x[2]) && x[3] == '/') continue; /* 01/02/2007 */
    if (isdigit(x[1]) && isdigit(x[3]) && x[2] == '/') continue; /* 01/2/2007 */

    do { x++; } while (isalnum(*x) || *x == '_');

    if (*x != '/') continue;			/* "text/plain"                */

    if (strstr(res->payload,req->p.v2[i]))	/* Text simply echoed back?    */
      continue;

    switch (NOECHO(m = get_modifiers(req,res))) {
    
      case 0:
        case MOD_AUTH:
          SHOW_MSG(2,"File path in query parameters",req->p.v2[i],m); break;
        case MOD_PRED:
        case MOD_PRED | MOD_AUTH:
          SHOW_MSG(3,"File path in query parameters",req->p.v2[i],m); break; 

    }

    /* Report only once per URL. */
    goto no_more_paths;

  }

  /* Non-echoed filenames are not necessarily evil, but worth examining. */

  if (all_files)
    for (i=0;i<req->p.c;i++) if (!req->p.fn[i][0] && strlen(req->p.v2[i]) < MAX_FPATH && 
    strcmp(req->p.v1[i],"utmp") /* Analytics-specific again. */ ) {

      _u8* x = req->p.v2[i];
      while (isalnum(*x) || *x == '_' || *x == '/') x++;
      if (*x == '.' && isalpha(x[1]) && isalpha(x[2]) && strlen(x+1) <= 5 &&
          !strstr(res->payload,req->p.v2[i])) {

        m = get_modifiers(req,res);
        SHOW_MSG(1,"File name in query parameters",req->p.v2[i],m);
        break;

      }
    }

no_more_paths:

  /* Java method names in a query are bad. */

  for (i=0;i<req->p.c;i++) if (!req->p.fn[i][0]) {
    _u8* x = strstr(req->p.v2[i],"com.");
    if (x && isalpha(x[4]) && strchr(x+4,'.') && !strstr(res->payload,req->p.v2[i]) &&
        !strchr(x,'/')) {
      switch (NOECHO(m = get_modifiers(req,res))) {
    
        case 0:
        case MOD_AUTH:
          SHOW_MSG(2,"Java method call in query parameters",req->p.v2[i],m); break;
        case MOD_PRED:
        case MOD_PRED | MOD_AUTH:
          SHOW_MSG(3,"Java method call in query parameters",req->p.v2[i],m); break; 
      }

      break;
    }
  }

  /* Javascript code in a query is bad; ignore alert(...) though, as this is almost
     always a sign of manual XSS testing, not a legitimate functionality. */

  for (i=0;i<req->p.c;i++) if (!req->p.fn[i][0]) {
    _u8* x = strchr(req->p.v2[i],'(');
    if (x && (x == req->p.v2[i] || isalpha(x[-1])) && strchr(x+1,')') && 
        !rp_strcasestr(req->p.v2[i],"alert(") &&
        strstr(res->payload,req->p.v2[i])) {
      switch (NOECHO(m = get_modifiers(req,res))) {
    
        case 0:
        case MOD_AUTH:
          SHOW_MSG(2,"Javascript code echoed back",req->p.v2[i],m); break;
        case MOD_PRED:
        case MOD_PRED | MOD_AUTH:
          SHOW_MSG(3,"Javascript code echoed back",req->p.v2[i],m); break; 
      }

      break;
    }
  }

  /* SQL statement in a query is bad. */

  for (i=0;i<req->p.c;i++) if (!req->p.fn[i][0]) {
    _u8* x = rp_strcasestr(req->p.v2[i],"SELECT");
    if (x && rp_strcasestr(x+1,"FROM") && !strstr(res->payload,req->p.v2[i])) {
      switch (NOECHO(m = get_modifiers(req,res))) {
    
        case 0:
        case MOD_AUTH:
          SHOW_MSG(2,"SQL code in query parameters",req->p.v2[i],m); break;
        case MOD_PRED:
        case MOD_PRED | MOD_AUTH:
          SHOW_MSG(3,"SQL code in query parameters",req->p.v2[i],m); break; 
      }

      break;
    }
  }

  /* Check for OGNL-style parameter names. */
 
  if (!req->non_param)
  for (i=0;i<req->p.c;i++) {
    if (!req->p.fn[i][0] && req->p.v1[i][0] && req->p.v2[i][0]) {
      _u8* x = strchr(req->p.v1[i] + 1, '.');		// 'user.lname'
      _u8* x1 = x ? strchr(x + 1, '.') : 0;		// 'user.lname.foo'
      _u8* y = strchr(req->p.v1[i] + 1, '[');		// 'users[0].lname'
      if (((x && x1) || y) && req->p.v1[i][0] != '[') {
        switch (NOECHO(m = get_modifiers(req,res))) {
          case 0:
          case MOD_AUTH:
            SHOW_MSG(1,"Suspicious parameter passing scheme",req->p.v1[i],m); break;
          case MOD_PRED:
          case MOD_PRED | MOD_AUTH:
            SHOW_MSG(2,"Suspicious parameter passing scheme",req->p.v1[i],m); break;
        }
        break;
      }
    }
  }

  /* Locate generic XSS candidates. */

  if (try_attacks)
    if (try_replay_xss(req,res)) {
      m = get_modifiers(req,res);
      SHOW_MSG(3,"Confirmed XSS vectors",0,m);
      got_xss = 1;
    }

  if (all_xss && !got_xss && res->is_text)
    for (i=0;i<req->p.c;i++)
      if (!req->p.fn[i][0] && xss_field(req->p.v2[i],0) && strstr(res->payload,req->p.v2[i])) {
        m = get_modifiers(req,res);
        if (!rp_strcasestr(BEST_MIME,"script") && strcasecmp(BEST_MIME,"application/json"))
          SHOW_MSG(0,"XSS candidates",req->p.v1[i],m); 
          else SHOW_MSG(1,"XSS candidates (script)",req->p.v1[i],m); 
        break;
      }

  for (i=0;i<req->p.c;i++)
    if (!req->p.fn[i][0] && xss_field(req->p.v2[i],1)) {
      _u32 j;
      for (j=0;j<res->h.c;j++)
        if (strstr(res->h.v2[j],req->p.v2[i])) {
          m = get_modifiers(req,res);
          SHOW_MSG(0,"Request splitting candidates",req->p.v1[i],m); 
          goto xss_done;
        }
    }

xss_done:

  /* Check for what looks like JSON with inline HTML (we skip standalone scripts,
     as they often contain static HTML to be rendered). We do some basic quote
     state tracking not to get confused by regular arithmetic. No comment
     tracking, but that shouldn't break easily. */

  if ((rp_strcasestr(BEST_MIME,"script") || !strcasecmp(BEST_MIME,"application/json")) &&
      !standalone_script(res->payload)) {
    _u8* p = res->payload, qstate = 0, got_html = 0, esc_next = 0, pv = ' ';

    do {

      if (esc_next) { esc_next = 0; continue; }

      /* TODO: This should be replaced with a proper Javascript analyzer. */

      switch (*p) {
        case '\\': esc_next = 1; break;
        case '\'': case '"':
          if (qstate == *p) qstate = 0; else if (!qstate) qstate = *p;
          break;
        case '<': if (qstate) got_html = 1; break;    
        case '>': if (qstate && got_html) got_html = 2; break;
      }

    } while (got_html < 2 && (pv=*(p++)));

    if (got_html == 2) {
      switch (NOECHO(m = get_modifiers(req,res))) {
        case 0: case MOD_PRED: case MOD_AUTH:
          SHOW_MSG(1,"Markup in dynamic Javascript",0,m); break;
        case MOD_AUTH | MOD_PRED:
          SHOW_MSG(ECHO(m) ? 2 : 1,"Markup in dynamic Javascript",0,m); break;
      }
    }

  }

  if (all_flash && !strcasecmp(BEST_MIME,"application/x-shockwave-flash")) {
    m = get_modifiers(req,res);
    SHOW_MSG(0,"All Flash applications",0,m); 
    if (trace_dir) decode_flash(res);
  }

  /* TODO: Add more index checks and other troubling server responses. */

  if (strstr(res->payload,">[To Parent Directory]<") ||
      strstr(res->payload,"<title>Index of /")) {
    m = get_modifiers(req,res);
    SHOW_MSG(0,"Directory indexes",0,m); 
  }

  /* TODO: This should be replaced with a proper Javascript analyzer. */

  if (bad_js && res->is_text && (
                 rp_strcasestr(res->payload,".write(") ||
                 rp_strcasestr(res->payload,".writeln("))) {
    m = get_modifiers(req,res);
    SHOW_MSG(1,"Risky Javascript code","document.write",m); 
  }

  if (bad_js && res->is_text &&
                 (rp_strcasestr(res->payload,".innerHtml") || 
                 rp_strcasestr(res->payload,".outerHtml"))) {
    m = get_modifiers(req,res);
    SHOW_MSG(1,"Risky Javascript code","innerHTML",m); 
  }

  if (bad_js && res->is_text &&
                 rp_strcasestr(res->payload,"document.referrer")) {
    m = get_modifiers(req,res);
    SHOW_MSG(2,"Risky Javascript code","document.referrer",m); 
  }

  if (bad_js && res->is_text &&
                 rp_strcasestr(res->payload,"document.domain")) {
    m = get_modifiers(req,res);
    SHOW_MSG(2,"Risky Javascript code","document.domain",m); 
  }

skip_tests:
 
  fflush(outfile);
  exit(0);

}


static void listen_loop(void) {
  _s32 lsock, csock, on = 1;
  _u32 x;
  struct sockaddr_in saddr;
  
  lsock=socket(AF_INET, SOCK_STREAM, 0);
  if (lsock < 0) pfatal("cannot create socket");

  if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(_s32)) == -1) 
    pfatal("cannot setsockopt()");  

  saddr.sin_family      = AF_INET;

  if (!use_any) {
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  } else {
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
  }
  
  saddr.sin_port        = htons(use_port);

  x = sizeof(saddr);
  
  if (bind(lsock, (struct sockaddr*)&saddr, x)) pfatal("cannot bind to port");  
  if (listen(lsock, 10)) pfatal("listen() failed");

  debug("[*] Proxy configured successfully. Have fun, and please do not be evil.\n");

  if (use_proxy)
    debug("    Upstream proxy is %s:%u\n",use_proxy,proxy_port);

  if (try_attacks)
    debug("    WARNING: Disruptive tests enabled. use with care.\n");

  debug("[+] Accepting connections on port %u/tcp (%s)...\n", use_port,
        use_any ? "any source" : "local only");

  while ((csock = accept(lsock, (struct sockaddr*)&saddr, &x)) >= 0) {

    /* Bury zombies */
    while (waitpid(-1,&x,WNOHANG) > 0);

    if (!fork()) { 
      FILE* client;
      close(lsock);
      client = fdopen(csock,"w+");
      if (!client) fatal("fdopen() failed");
      handle_client(client); 
      /* Not reached */
      exit(0); 
    }

    close(csock);

  }

  pfatal("accept() failed");

}
   


int main(int argc, char** argv) {
  _s32 opt;
  _u8* x;

  signal(SIGPIPE, SIG_IGN);

  debug("ratproxy version " VERSION " by <lcamtuf@google.com>\n");

  while ((opt = getopt(argc,argv,"+w:v:p:d:P:itxgjmafske2clXCr")) > 0) 
    switch (opt) {

      case 'w': {
          _s32 f;
          if (outfile) fatal("multiple -w options make no sense");
          unlink(optarg); /* Ignore errors */
          f = open(optarg,O_WRONLY|O_CREAT|O_EXCL,0600);
          if (f < 0) pfatal("cannot open log file");
          outfile = fdopen(f,"w");
          if (!outfile) pfatal("fdopen failed");
        }
        break;

      case 'v': {
          if (trace_dir) fatal("multiple -v options make no sense");
          trace_dir = optarg;
          mkdir(trace_dir,0700); /* Ignore errors */
          if (access(trace_dir,X_OK)) pfatal("cannot create -v directory");
        }
        break;

      case 'p':
        use_port = atoi(optarg);
        if (!use_port || use_port > 65535) fatal("invalid -p value");
        break;

      case 'P':
        use_proxy = optarg;
        x = strchr(optarg,':');
        if (!x) break;
        *(x++) = 0;
        proxy_port = atoi(x);
        if (!proxy_port || proxy_port > 65535) fatal("invalid proxy port");
        break;

      case '2':
        use_double = 1;
        break;

      case 'd':
        ADD(domains,optarg);
        break;

      case 'i':
        check_png = 1;
        break;

      case 'e':
        picky_cache = 1;
        break;

      case 't':
        all_files = 1;
        break;

      case 'f':
        all_flash = 1;
        break;

      case 'x':
        all_xss = 1;
        break;

      case 'g':
        get_xsrf = 1;
        break;

      case 'j':
        bad_js = 1;
        break;

      case 'l':
        use_len = 1;
        break;

      case 's':
        all_post = 1;
        break;

      case 'a':
        dump_urls = 1;
        break;

      case 'c':
        all_cookie = 1;
        break;

      case 'X':
        try_attacks = 1;
        break;

      case 'm':
        log_active = 1;
        break;

      case 'C':
        fix_attacks = 1;
        break;

      case 'k':
        log_mixed = 1;
         break;

      case 'r':
        use_any = 1;
        break;

      default: 
        usage(argv[0]);
    }
       
  if (optind != argc) usage(argv[0]);

  if (optind == 1) 
    debug("\n[!] WARNING: Running with no command-line config options specified. This is\n"
            "    almost certainly not what you want, as most checks are disabled. Please\n"
            "    consult the documentation or use --help for more information.\n\n");
  else if (!domains.c)
    debug("\n[!] WARNING: Running with no 'friendly' domains specified. Many cross-domain\n"
            "    checks will not work. Please consult the documentation for advice.\n\n");

  if (!outfile) outfile = stdout;

  listen_loop();

  /* Not reached */
  return 0; 

}
