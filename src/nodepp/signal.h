/*
 * Copyright 2023 The Nodepp Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/NodeppOfficial/nodepp/blob/main/LICENSE
 */

/*────────────────────────────────────────────────────────────────────────────*/

#ifndef NODEPP_SIGNAL
#define NODEPP_SIGNAL

/*────────────────────────────────────────────────────────────────────────────*/

#include <csignal>
#include "event.h"

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { namespace process {

    event_t<int> onSIGERROR; event_t<> onSIGEXIT; event_t<> onSIGCLOSE;

namespace signal {

    inline void start() {
        ::signal( SIGFPE,  []( int param ){ onSIGERROR.emit(SIGFPE ); console::error("SIGFPE: Floating Point Exception"); onSIGEXIT .emit(); });
        ::signal( SIGSEGV, []( int param ){ onSIGERROR.emit(SIGSEGV); console::error("SIGSEGV: Segmentation Violation");  onSIGEXIT .emit(); });
        ::signal( SIGILL,  []( int param ){ onSIGERROR.emit(SIGILL ); console::error("SIGILL: Illegal Instruction");      onSIGEXIT .emit(); });
        ::signal( SIGTERM, []( int param ){ onSIGERROR.emit(SIGTERM); console::error("SIGTERM: Process Terminated");      onSIGEXIT .emit(); });
        ::signal( SIGINT,  []( int param ){ onSIGERROR.emit(SIGINT ); console::error("SIGINT: Signal Interrupt");         onSIGEXIT .emit(); });
    #ifdef SIGPIPE
        ::signal( SIGPIPE, []( int param ){ onSIGERROR.emit(SIGPIPE); console::error("SIGPIPE: Broked Pipeline");         onSIGEXIT .emit(); });
        ::signal( SIGKILL, []( int param ){ onSIGERROR.emit(SIGKILL); console::error("SIGKILL: Process Killed");          onSIGEXIT .emit(); });
    #endif
        ::signal( SIGABRT, []( int param ){ onSIGERROR.emit(SIGABRT); console::error("SIGABRT: Process Abort");           onSIGEXIT .emit(); });
        ::atexit( /*----*/ []( /*-----*/ ){ /*-------------------------------------------------------------------------*/ onSIGCLOSE.emit(); });
    #ifdef SIGPIPE
        ::signal( SIGPIPE, SIG_IGN );
    #endif
    }

    inline void unignore( int signal ){ ::signal( signal, SIG_DFL ); }
    inline void   ignore( int signal ){ ::signal( signal, SIG_IGN ); }
	inline void     emit( int signal ){ ::raise ( signal );          }

}

}}

/*────────────────────────────────────────────────────────────────────────────*/

#endif
