
//==============================================================================
//
// stdafx.cpp : source file that includes just the standard includes
// NAVVO Service.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information
//
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================


#include "stdafx.h"
#include <Windows.h>
#include <system_error>
#include <memory>
#include <string>

typedef std::basic_string<TCHAR> String;

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Wtsapi32.lib")
// TODO: reference any additional headers you need in STDAFX.H
// and not in this file
std::string base_name(std::string const & path)
{
	return path.substr(path.find_last_of("/\\") + 1);
}
inline std::string string_base_name(std::string const & path)
{
	return base_name(path);
}


void decomposePath(const TCHAR *filePath, TCHAR *fileDir, TCHAR *fileName, TCHAR *fileExt)
{
	const TCHAR *lastSeparator = _STRRCHR(filePath, __PATH_SEPARATOR);
	const TCHAR *lastDot = _STRRCHR(filePath, _T('.'));
	const TCHAR *endOfPath = filePath + _STRLEN(filePath);
	const TCHAR *startOfName = lastSeparator ? lastSeparator + 1 : filePath;
	const TCHAR *startOfExt = lastDot > startOfName ? lastDot : endOfPath;
	if (fileDir)
		__SNPRINTF(fileDir, MAX_PATH, _T("%.*s"),int( startOfName - filePath), filePath);

	if (fileName)
		__SNPRINTF(fileName, MAX_PATH, _T("%.*s"), int(startOfExt - startOfName), startOfName);

	if (fileExt)
		__SNPRINTF(fileExt, MAX_PATH, _T("%s"), startOfExt);

}

String GetErrorMessage(DWORD dwErrorCode)
{
	LPTSTR psz{ nullptr };
	const DWORD cchMsg = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM
		| FORMAT_MESSAGE_IGNORE_INSERTS
		| FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL, // (not used with FORMAT_MESSAGE_FROM_SYSTEM)
		dwErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPTSTR>(&psz),
		0,
		NULL);
	if (cchMsg > 0)
	{
		// Assign buffer to smart pointer with custom deleter so that memory gets released
		// in case String's c'tor throws an exception.
		auto deleter = [](void* p) { ::LocalFree(p); };
		std::unique_ptr<TCHAR, decltype(deleter)> ptrBuffer(psz, deleter);
		return String(ptrBuffer.get(), cchMsg);
	}
	else
	{
		auto error_code{ ::GetLastError() };
		throw std::system_error(error_code, std::system_category(),
			"Failed to retrieve error message string.");
	}
}

