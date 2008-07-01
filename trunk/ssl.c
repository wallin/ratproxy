/*
   ratproxy - SSL worker
   ---------------------

   This helper process is launched on CONNECT requests to act as a
   SSL MITM intermediary.

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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "ssl.h"

_s32 ssl_cli_tap,		/* Client traffic tap      */
     ssl_srv_tap;		/* Server traffic tap      */

static _s32 ssl_cli_tap_b,	/* Rear end of client tap  */
            ssl_srv_tap_b,	/* Rear end of server tap  */
	    ssl_pid;		/* SSL worker PID          */


static _u8 rdbuf[MAXLINE],	/* Internal I/O buffer     */
	   init_ok;		/* Initialization state    */


/* Prepare pipes for SSL worker */
void ssl_setup(void) {
  int p[2];

  if (init_ok) fatal("ssl_setup() called twice");
  init_ok = 1;

  if (socketpair(AF_UNIX,SOCK_STREAM,0,p)) pfatal("socketpair() failed");

  ssl_cli_tap = p[0];
  ssl_cli_tap_b = p[1];

  if (socketpair(AF_UNIX,SOCK_STREAM,0,p)) pfatal("socketpair() failed");

  ssl_srv_tap = p[0];
  ssl_srv_tap_b = p[1];

}


/* Clean up SSL worker */
void ssl_shutdown(void) {
  int st;
 
  if (init_ok != 2) fatal("ssl_shutdown() called prior to ssl_start()");
  init_ok = 0;

  if (ssl_pid > 0) {
    ssl_pid = 0;
    close(ssl_cli_tap);
    close(ssl_srv_tap);
    wait(&st);
  }

}


/* Display SSL-enabled error message */

#define ssl_fatal(reason,err) do { \
    if (init_ok == 2) \
      ERR_print_errors(err); \
    fatal("%s", reason); \
  } while (1)


/* Start SSL worker and do the dirty job */
void ssl_start(_s32 srv_fd, _s32 cli_fd) {
  SSL_CTX *cli_ctx, *srv_ctx;
  SSL *cli_ssl, *srv_ssl;
  BIO* err;
  _s32 i;
  _u8 no_client = (cli_fd < 0);

  if (!init_ok || init_ok == 2) fatal("ssl_start() called out of order");
  init_ok = 2;

  ssl_pid = fork();

  if (ssl_pid < 0) pfatal("fork() failed");

  /* Make sure that each endpoint has just the right set of pipes */

  if (ssl_pid) {

    close(ssl_cli_tap_b);
    close(ssl_srv_tap_b);
    ssl_cli_tap_b  = -1;
    ssl_srv_tap_b  = -1;
    return;

  }

  close(ssl_cli_tap);
  close(ssl_srv_tap);
  ssl_cli_tap  = -1;
  ssl_srv_tap  = -1;

  SSL_library_init();
  SSL_load_error_strings();

  err = BIO_new_fp(stderr,BIO_NOCLOSE);
  srv_ctx = SSL_CTX_new(SSLv23_client_method()); /* To server */
  cli_ctx = SSL_CTX_new(SSLv23_server_method()); /* To client */

  if (!srv_ctx || !cli_ctx || !err) ssl_fatal("unable to create SSL CTX or BIO", err);

  if (SSL_CTX_use_certificate_chain_file(cli_ctx,"keyfile.pem") != 1) 
    ssl_fatal("certificate load failed", err);

  if (SSL_CTX_use_PrivateKey_file(cli_ctx,"keyfile.pem",SSL_FILETYPE_PEM) != 1) 
    ssl_fatal("private key load failed", err);

  cli_ssl = SSL_new(cli_ctx);
  srv_ssl = SSL_new(srv_ctx);

  if (!srv_ssl || !cli_ssl) ssl_fatal("unable to create SSL objects", err);

  SSL_set_fd(srv_ssl, srv_fd);
  if (SSL_connect(srv_ssl) != 1) ssl_fatal("server SSL handshake failed", err);

  if (!no_client) {
    SSL_set_fd(cli_ssl, cli_fd);
    if (SSL_accept(cli_ssl) != 1) ssl_fatal("client SSL handshake failed", err);
  }

  while (1) {
    _s32 fmax = 0;

    fd_set fds;

    FD_ZERO(&fds);

    if (!no_client) {
      FD_SET(cli_fd,&fds);         
      fmax = cli_fd;
      FD_SET(ssl_cli_tap_b,&fds);  
      if (ssl_cli_tap_b > fmax) fmax = ssl_cli_tap_b;
    }

    if (ssl_srv_tap_b > 0) {
      FD_SET(srv_fd,&fds);
      if (srv_fd > fmax) fmax = srv_fd;
      FD_SET(ssl_srv_tap_b,&fds);  
      if (ssl_srv_tap_b > fmax) fmax = ssl_srv_tap_b;
    }

    if (select(1 + fmax, &fds, 0, 0, 0) <= 0) exit(0);

    /* Real client sending - send to cli_tap socket. */
    if (!no_client && FD_ISSET(cli_fd,&fds)) {
      i = SSL_read(cli_ssl,rdbuf,sizeof(rdbuf));
      if (i <= 0) exit(0);
      if (write(ssl_cli_tap_b,rdbuf,i) != i) 
        pfatal("short write to client tap");
    }

    /* Real server sending - send to srv_tap socket. */
    if (ssl_srv_tap_b > 0 && FD_ISSET(srv_fd,&fds)) {
      i = SSL_read(srv_ssl,rdbuf,sizeof(rdbuf));
      if (i <= 0) {

        /* In no_client mode, server shutdown means end of work. */

        if (no_client) exit(0);

        /* In client mode, we still want to relay proxy-processed
           client response before exiting. Just let the proxy
           know by shutting down the server tap. */

        close(ssl_srv_tap_b);
        ssl_srv_tap_b = -1;
      } else {
        if (write(ssl_srv_tap_b,rdbuf,i) != i) 
          pfatal("short write to server tap");
      }
    }

    /* Data from srv_tap socket - send to server. */
    if (ssl_srv_tap_b > 0 && FD_ISSET(ssl_srv_tap_b,&fds)) {
      i = read(ssl_srv_tap_b,rdbuf,sizeof(rdbuf));
      if (i <= 0) exit(0);
      if (SSL_write(srv_ssl,rdbuf,i) != i) exit(0);
    }
    
    /* Data from cli_tap socket - send to client. */
    if (!no_client && FD_ISSET(ssl_cli_tap_b,&fds)) {
      i = read(ssl_cli_tap_b,rdbuf,sizeof(rdbuf));
      if (i <= 0) exit(0);
      if (SSL_write(cli_ssl,rdbuf,i) != i) exit(0);
    }

  }

}
