#
# ratproxy - Makefile
# -------------------
#
# Author: Michal Zalewski <lcamtuf@google.com>
#
# Copyright 2007, 2008 by Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

PROGNAME = ratproxy
CFLAGS	 = -Wall -O3 -Wno-pointer-sign -D_GNU_SOURCE
LDFLAGS  = -lcrypto -lssl

all: $(PROGNAME) flare-check

$(PROGNAME): $(PROGNAME).c http.c mime.c ssl.c http.h mime.h ssl.h nlist.h config.h debug.h types.h string-inl.h
	$(CC) $(PROGNAME).c -o $(PROGNAME)  $(CFLAGS) http.c mime.c ssl.c $(LDFLAGS)

flare-check:
	@flare-dist/flare 2>&1 | grep -qF Igor || ( \
	  echo; \
	  echo '*** WARNING: 'flare-dist/flare' bianry is not operational.'; \
	  echo '*** Please see flare-dist/README and update it for your OS.'; \
	  echo )

clean:
	rm -f $(PROGNAME) *.exe *.o *~ a.out core core.[1-9][0-9]* *.stackdump

