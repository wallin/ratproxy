/*

   ratproxy - hardcoded configuration
   ----------------------------------

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

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#include "types.h"

#define VERSION		"1.51-beta"

/* Maximum request / response header line length (HTTP traffic
   that exceeds this limit will be rejected). */

#define MAXLINE 	8192

/* Maximum request payload size (to avoid DoS / malloc overflows). */

#define MAXPAYLOAD      (30 * 1024 * 1024)

/* Maximum saved trace file payload size (to conserve disk space). */

#define MAXTRACEITEM    (1 * 1024 * 1024)

/* Default proxy listen port. */

#define DEFAULT_PORT    8080

/* Uncomment to forcibly disable client-side page caching. Will slow
   things down - but may be useful if there is no way to purge browser
   cache manually prior to testing, or if you are forgetful. */

// #define FORCE_NOCACHE 1

/* Maximum token length for log entries produced (making this higher
   will include more query / response data in reports). */

#define MAXTOKEN	1024

/* MIME sniffing buffer size. */

#define SNIFFBUF	1024

/* Character set sniffing buffer size (when looking for META directives). */

#define CHARSNIFF       1024

/* Minimum parameter value length to be tested as an XSS candidate. */

#define MIN_XSS_LEN     4

/* The same, but for HTTP header injection checks. */

#define MIN_XSS_HEAD    6

/* Maximum parameter length to be considered a file path, as opposed to
   being just a random base64 blob with slashes in it. */

#define MAX_FPATH       64

/* Uncomment to XSS anti-XSRF tokens in -X mode. When defined, may prompt 
   the proxy to miss some self-XSS vectors (because clobbered security 
   tokens may inhibit page rendering), but will improve coverage in poorly
   written apps with no real XSRF protection to begin with. */

// #define XSS_XSRF_TOKENS 1

/* Uncomment to look for query path, not only parameters, being echoed back
   in response body, to derive risk flags. This may trigger false positives
   with some applciations, and hence is disabled by default. */

// #define CHECK_ECHO_PATH 1

/* NULL-terminated list of query field names that imply authentication.
   These override standard request repost based checks. This is a substring
   match - prefix with '=' to do full field matching. You might want to
   customize this list to include any other common values you encounter. */

static _u8* __attribute__((used)) auth_fields[] = {
  "login",
  "user",
  "sess",
  "account",
  "pass",
  0
};

/* NULL-terminated list of known fields that implement XSRF protection
   features, even if they fail our tests. You might want to customize
   this list to troubleshoot any false positives you encounter. */

static _u8* __attribute__((used)) xsrf_fields[] = {
  "token",
  "once",
  "secret",
  "secid",
  "auth",
  "=tok",
  "=sig",

  /* The values below are chiefly Google-specific. */

  "=gb",
  "=usg",
  "=at",
  "=bb",
  "=cid",
  "=ids",
  "=et",
  0
};

/* NULL-terminated list of known fields that look like XSRF tokens,
   but have a different meaning and should be ignored. This is
   chiefly Google-specific - customize as needed, based on -X
   mode findings or manual testing. */

static _u8* __attribute__((used)) no_xsrf_fields[] = {
  "=ver",
  "=id",
  "=zx",
  0
};

/* NULL-terminated list of common values that if visible in request 
   parameters and inline on a page, do not really imply an XSS
   vector. */

static _u8* __attribute__((used)) no_xss_text[] = {
  "utf",
  "html",
  0
};

/* NULL-terminated list of JSON-like response prefixes we consider to 
   be sufficiently safe against cross-site script inclusion. You
   might want to extend the list as needed. */

static _u8* __attribute__((used)) json_safe[] = {
  "while(1);",		/* Parser looping - common      */
  "while (1);",		/* ...                          */
  "while(true);",	/* ...                          */
  "while (true);",	/* ...                          */
  "&&&",		/* Parser breaking - OpenSocial */
  "//OK[",		/* Line commenting - GWT        */
  "{\"",		/* Serialized object - common   */
  "{{\"",		/* Serialized object - common   */
  "throw 1;",           /* Parser bailout - common      */
  0
};

/* NULL-terminated list of known valid charsets. Charsets not on
   the list are considered invalid, as they may trigger strange
   encoded XSS attack vectors, etc. You might want to extend
   this list as needed when testing foreign-language applications.

   WARNING: Please note that "harmless" misspellings such as
   'utf8' or 'utf_8' are *not* harmless, and may trigger utf-7
   XSSes. Do not add these to the list unless thoroughly
   validated. */

static _u8* __attribute__((used)) valid_charsets[] = {
  "utf-8",              /* Valid Unicode                 */
  "iso8859-1",          /* Valid Western                 */
  "iso-8859-1",         /* Invalid but recognized        */
  "iso8859-2",          /* Valid European                */
  "iso-8859-2",         /* Invalid but recognized        */
  "iso8859-15",		/* ISO-8859-1, new and improved  */
  "iso-8859-15",	/* ISO-8859-1, new and improved  */
  "windows-1252",       /* Microsoft's Western           */
  "windows-1250",       /* Microsoft's European          */
  "us-ascii",           /* Old school but generally safe */
  0
};


/* NULL-terminated list of active content MIME types, as produced
   by our sniffer. Any content that may execute in the browser
   in the security context of its serving domain belongs here. */

static _u8* __attribute__((used)) active_mime[] = {
  "text/html",				/* HTML       */
  "application/xhtml+xml",		/* XHTML      */
  "application/java-vm",		/* Java class */
  "application/java-archive",		/* Java JAR   */
  "application/x-shockwave-flash",	/* Flash      */
  "video/flv",				/* Flash      */
  "video/x-flv",			/* Flash      */
  0
};

/* XSRF detector parameters; these might need to be tweaked if
   seeing false positives, but are otherwise OK for most intents
   and purposes. */

#define XSRF_B16_MIN 	10	/* Minimum base16 token length */
#define XSRF_B16_MAX 	45	/* Maximum base16 token length */

#define XSRF_B64_MIN	9	/* Minimum base32/64 token length */
#define XSRF_B64_MAX	32	/* Maximum base32/64 token length */
#define XSRF_B64_NUM	1	/* Require at least this many digit chars */
#define XSRF_B64_UP 	2	/* Require at least this many uppercase chars */
#define XSRF_B64_NUM2 	3	/* Digit char count threshold to waive uppercase check */

#endif /* ! _HAVE_CONFIG_H */
