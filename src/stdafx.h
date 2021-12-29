
//==============================================================================
//
//     stdafx.h : include file for standard system include files,
//           or project specific include files that are used frequently, but
//           are changed infrequently
//
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================


#ifndef __STDAFX_F__
#define __STDAFX_F__

#ifdef _DEBUG
#define PRINT_OUT		printf
#define PRINT_OUT_S		_tprintf_s
#else
#define PRINT_OUT 
#define PRINT_OUT_S	
#endif // _DEBUG
#define WIN32_LEAN_AND_MEAN
#include "targetver.h"

#include <windows.h>
#include <process.h>
#include <iostream>
#include <tchar.h>
#include <stdio.h>
#include <AccCtrl.h>
#include <winbase.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <windowsx.h>
#include <shlobj.h>

#include <commctrl.h>       // InitCommonControlsEx, etc.
#include <stdexcept>


//#include <winsock2.h>
//#include <ws2tcpip.h>


// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <wincrypt.h>
#include <tchar.h>

#include <shellapi.h>

#include "macros.h"
#include "nowarns.h"

#include <assert.h>
#define ASSERT(x)	assert(x)

#ifdef PLATFORM_PC
#include <conio.h>
#include <iostream>
#include <string>

std::string base_name(std::string const & path);
typedef std::basic_string<TCHAR> String;
inline std::string string_base_name(std::string const & path);
void decomposePath(const TCHAR *filePath, TCHAR *fileDir, TCHAR *fileName, TCHAR *fileExt);
String GetErrorMessage(DWORD dwErrorCode);

#endif // PLATFORM_PC
#undef  STRICT
#define STRICT
#undef  NOMINMAX
#define NOMINMAX
#undef  MBCS        // Treat MBCS as an unsupported no-effect symbol.
#undef  WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#undef  OEMRESOURCE
#define OEMRESOURCE

#undef CCC_CALL_CONV
#undef CCC_INTERFACE_DEF_NOCC
#undef CCC_INTERFACE_DEF

#ifdef CCC_STATIC_LINKING
#  define CCC_CALL_CONV
#  define CCC_INTERFACE_DEF_NOCC
#  define CCC_INTERFACE_DEF(x)   x
#else
//#  define CCC_CALL_CONV  __stdcall
#  define CCC_CALL_CONV  __cdecl
#  ifdef CCC_EXPORTS
#    define CCC_INTERFACE_DEF_NOCC __declspec(dllexport)                    
#    define CCC_INTERFACE_DEF(x)   __declspec(dllexport) x CCC_CALL_CONV 
#  else
#    define CCC_INTERFACE_DEF_NOCC __declspec(dllimport)                    
#    define CCC_INTERFACE_DEF(x)   __declspec(dllimport) x CCC_CALL_CONV
#  endif
#endif

#define DESKTOP_ALL (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | \
DESKTOP_CREATEMENU | DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | \
DESKTOP_JOURNALPLAYBACK | DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | \
DESKTOP_SWITCHDESKTOP | STANDARD_RIGHTS_REQUIRED)

#define WINSTA_ALL (WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | \
WINSTA_ACCESSCLIPBOARD | WINSTA_CREATEDESKTOP | \
WINSTA_WRITEATTRIBUTES | WINSTA_ACCESSGLOBALATOMS | \
WINSTA_EXITWINDOWS | WINSTA_ENUMERATE | WINSTA_READSCREEN | \
STANDARD_RIGHTS_REQUIRED)

#define GENERIC_ACCESS (GENERIC_READ | GENERIC_WRITE | \
GENERIC_EXECUTE | GENERIC_ALL)

#ifdef _DEBUG
#define _DEBUGPRINTF printf
#else
#define _DEBUGPRINTF
#endif
#ifdef UNICODE
#pragma message("-------------------------------")
#pragma message("CHARACTER SET IS UNICODE ")
#define _PRINTF wprintf
#else
#pragma message("-------------------------------")
#pragma message("CHARACTER SET IS SINGLE BYTE ")
#define _PRINTF printf
#endif 

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#pragma message("BYTE ORDER ==> LITTLE ENDIAN")
#else
#pragma message("BYTE ORDER ==> BIG ENDIAN")
#endif

#ifdef DEJA_DISABLED
#pragma message("-------------------------------")
#pragma message("DEJA INSIGHT IS DISABLED")
#else
#pragma message("-------------------------------")
#pragma message("DEJA INSIGHT IS ENABLED")
#endif 


#ifdef UNICODE
#  define			_STRCMP		    wstrcmp
#  define			_STRRCHR		wcsrchr
#  define			_STRLEN			wcslen
#  define			__SNPRINTF		_snwprintf
#  define			__SPRINTF		_swprintf
#define				_STRNCPY		wcsncpy
#  define			_STRNLEN		wcsnlen
#else
#  define			_STRCMP		    strcmp
#  define			_STRRCHR		strrchr
#  define			_STRLEN			strlen
#  define			__SNPRINTF		_snprintf
#  define			__SPRINTF		_sprintf
#  define			_STRNCPY		strncpy
#  define			_STRNLEN		strnlen
#endif
#if defined _WIN32
#  define			__PATH_SEPARATOR  _T('\\')
#else
#  define			__PATH_SEPARATOR  _T('/')
#endif


 //
 // Use dummy macros, if SAL 2 is not available
 //
#include <sal.h>
#if (_SAL_VERSION < 20)
#include <no_sal2.h>
#endif

//
// Don't use the SDK status values
//
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

//
// Let the NDK know we're in Application Mode
//
#define NTOS_MODE_USER

//
// Dependencies
//
#include <windef.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winioctl.h>

//
// Compiler Definitions
//
#ifndef _MANAGED
#if defined(_M_IX86)
#ifndef FASTCALL
#define FASTCALL                        __fastcall
#endif
#else
#define FASTCALL
#endif
#else
#define FASTCALL                        NTAPI
#endif

#if !defined(_M_CEE_PURE)
#define NTAPI_INLINE                    NTAPI
#else
#define NTAPI_INLINE
#endif

//
// Alignment Macros
//
#define ALIGN_DOWN_BY(size, align) \
     ((ULONG_PTR)(size) & ~((ULONG_PTR)(align) - 1))

#define ALIGN_UP_BY(size, align) \
     (ALIGN_DOWN_BY(((ULONG_PTR)(size) + align - 1), align))

#define ALIGN_DOWN_POINTER_BY(ptr, align) \
     ((PVOID)ALIGN_DOWN_BY(ptr, align))

#define ALIGN_UP_POINTER_BY(ptr, align) \
     ((PVOID)ALIGN_UP_BY(ptr, align))

#define ALIGN_DOWN(size, type) \
     ALIGN_DOWN_BY(size, sizeof(type))

#define ALIGN_UP(size, type) \
     ALIGN_UP_BY(size, sizeof(type))

#define ALIGN_DOWN_POINTER(ptr, type) \
     ALIGN_DOWN_POINTER_BY(ptr, sizeof(type))

#define ALIGN_UP_POINTER(ptr, type) \
     ALIGN_UP_POINTER_BY(ptr, sizeof(type))

 //
 // Native API Return Value Macros
 //
#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)          ((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status)              ((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status)                ((((ULONG)(Status)) >> 30) == 3)

//
// Limits
//
#define MINCHAR                         0x80
#define MAXCHAR                         0x7f
#define MINSHORT                        0x8000
#define MAXSHORT                        0x7fff
#define MINLONG                         0x80000000
#define MAXLONG                         0x7fffffff
#define MAXUCHAR                        0xff
#define MAXUSHORT                       0xffff
#define MAXULONG                        0xffffffff

//
// Basic Types that aren't defined in User-Mode Headers
//
typedef CONST int CINT;
typedef CONST char* PCSZ;
typedef ULONG CLONG;
typedef short CSHORT;
typedef CSHORT* PCSHORT;
typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;
typedef LONG KPRIORITY;

#endif//__STDAFX_F__