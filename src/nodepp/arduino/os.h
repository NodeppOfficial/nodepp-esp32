/*
 * Copyright 2023 The Nodepp Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/NodeppOfficial/nodepp/blob/main/LICENSE
 */

/*────────────────────────────────────────────────────────────────────────────*/

#ifndef NODEPP_ARDUINO_OS
#define NODEPP_ARDUINO_OS

/*────────────────────────────────────────────────────────────────────────────*/

#include <unistd.h>
#include <cerrno>

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { namespace os {
    
    inline void exit( int err=0 ){ ::exit(err); }

    /*─······································································─*/

    inline uint pid(){ return ::getpid(); }
    
    /*─······································································─*/

    inline string_t tmp(){ return "/"; }

    inline string_t cwd(){ return "/"; }

    /*─······································································─*/

    inline uint error(){ return errno; }

}}

/*────────────────────────────────────────────────────────────────────────────*/

#endif