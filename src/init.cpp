
#include "stdafx.h"
#include <commctrl.h>       // InitCommonControlsEx, etc.

#include <stdexcept>
using std::runtime_error;

static int const init = []() -> int
{
    DWORD const icc_flags = ICC_WIN95_CLASSES;  // Minimum that works.
    INITCOMMONCONTROLSEX const params = { sizeof( params ), icc_flags };
    bool const ok = !!InitCommonControlsEx( &params );
    if( ! ok )
    {
        throw std::runtime_error( "InitCommonControlsEx failed" );
    }
    return 42;
}();
