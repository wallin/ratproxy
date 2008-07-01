/*

   ratproxy - debugging macros
   ---------------------------

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

#ifndef _HAVE_DEBUG_H
#define _HAVE_DEBUG_H

#include "types.h"

#define debug(x...) fprintf(stderr,x)

#define fatal(x...) do { \
    debug("PROGRAM ABORT: " x); \
    debug(" [%s(), %s:%u]\n",__FUNCTION__,__FILE__,__LINE__); \
    exit(1); \
  } while (0)

#define pfatal(x...) do { \
    debug( "SYSTEM ERROR : " x); \
    debug( " [%s(), %s:%u]\n",__FUNCTION__,__FILE__,__LINE__); \
    perror("     Message "); \
    exit(1); \
  } while (0)


#endif /* ! _HAVE_DEBUG_H */
