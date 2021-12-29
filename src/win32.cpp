
//==============================================================================
//
//   win32.cpp
//
//   note those 2 are originally from https://github.com/hlldz/Phant0m: 
//     WinEvent::GetPIDFromSCManager
//     WinEvent::GetPIDFromWMI
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================


#include "stdafx.h"
#include "win32.h"
#include <Windows.h>
#include <minwindef.h>
#include "log.h"
#include <stdio.h>
#include <tlhelp32.h>
#include "psapi.h"
#include <stdio.h>
#include <tchar.h>

#include <windows.h>
#include <Psapi.h>
#include <sddl.h>
#include <AclAPI.h>
#include <winternl.h>
// #define USE_VDMDBG // Uncomment this if you don´t wat to use vdmdbg at all
#include <string>
#include <fstream>

#include <comdef.h>
#include <Wbemidl.h>


#pragma comment(lib, "wbemuuid.lib")
using namespace std;
namespace C
{
	namespace WinTime
	{

		VOID TimeToTimeFields( PLARGE_INTEGER Time,PTIME_FIELDS TimeFields)
		{
			const UCHAR* Months;
			ULONG SecondsInDay, CurYear;
			ULONG LeapYear, CurMonth;
			ULONG Days;
			ULONGLONG IntTime = Time->QuadPart;

			/* Extract millisecond from time and convert time into seconds */
			TimeFields->Milliseconds = (CSHORT)((IntTime % TICKSPERSEC) / TICKSPERMSEC);
			IntTime = IntTime / TICKSPERSEC;

			/* Split the time into days and seconds within the day */
			Days = (ULONG)(IntTime / SECSPERDAY);
			SecondsInDay = IntTime % SECSPERDAY;

			/* Compute time of day */
			TimeFields->Hour = (CSHORT)(SecondsInDay / SECSPERHOUR);
			SecondsInDay = SecondsInDay % SECSPERHOUR;
			TimeFields->Minute = (CSHORT)(SecondsInDay / SECSPERMIN);
			TimeFields->Second = (CSHORT)(SecondsInDay % SECSPERMIN);

			/* Compute day of week */
			TimeFields->Weekday = (CSHORT)((EPOCHWEEKDAY + Days) % DAYSPERWEEK);

			/* Compute year */
			CurYear = EPOCHYEAR;
			CurYear += Days / DAYSPERLEAPYEAR;
			Days -= DaysSinceEpoch(CurYear);
			while (TRUE)
			{
				LeapYear = IsLeapYear(CurYear);
				if (Days < YearLengths[LeapYear])
				{
					break;
				}
				CurYear++;
				Days = Days - YearLengths[LeapYear];
			}
			TimeFields->Year = (CSHORT)CurYear;

			/* Compute month of year */
			LeapYear = IsLeapYear(CurYear);
			Months = MonthLengths[LeapYear];
			for (CurMonth = 0; Days >= Months[CurMonth]; CurMonth++)
			{
				Days = Days - Months[CurMonth];
			}
			TimeFields->Month = (CSHORT)(CurMonth + 1);
			TimeFields->Day = (CSHORT)(Days + 1);
		} 

	}
	namespace WinEvent
	{

		DWORD GetPIDFromSCManager() {

			PRINT_OUT("[*] Attempting to detect PID from Service Manager...\n");

			SC_HANDLE schSCManager, schService;
			SERVICE_STATUS_PROCESS ssProcess = {};
			DWORD dwBytesNeeded = 0;

			schSCManager = OpenSCManagerA(NULL, NULL, SERVICE_QUERY_STATUS);

			if (NULL == schSCManager) {

				PRINT_OUT("[!] SCM: OpenSCManager failed (%d)\n", GetLastError());
				return 0;

			}

			schService = OpenServiceA(schSCManager, "EventLog", SERVICE_QUERY_STATUS);

			if (schService == NULL) {

				PRINT_OUT("[!] SCM: OpenService failed (%d)\n", GetLastError());
				CloseServiceHandle(schSCManager);
				return 0;

			}

			if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssProcess), sizeof(ssProcess), &dwBytesNeeded)) {

				PRINT_OUT("[!] SCM: QueryServiceStatusEx failed (%d)\n", GetLastError());
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return 0;

			}

			return ssProcess.dwProcessId;
		}


		DWORD GetPIDFromWMI() {

			PRINT_OUT("[*] Attempting to detect PID from WMI....\n");

			DWORD dwEventLogPID = 0;

			HRESULT hRes;

			hRes = CoInitializeEx(0, COINIT_MULTITHREADED);

			if (FAILED(hRes)) {

				PRINT_OUT("[!] WMI: Failed to initialize COM library.\n");
				return 0;

			}

			hRes = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

			if (FAILED(hRes)) {

				PRINT_OUT("[!] WMI: Failed to initialize security.\n");
				CoUninitialize();
				return 0;

			}

			IWbemLocator* pLoc = NULL;

			hRes = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

			if (FAILED(hRes)) {

				PRINT_OUT("[!] WMI: Failed to create IWbemLocator object.\n");
				CoUninitialize();
				return 0;

			}

			IWbemServices* pSvc = NULL;

			hRes = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

			if (FAILED(hRes)) {

				PRINT_OUT("[!] WMI: Could not connect.");
				pLoc->Release();
				CoUninitialize();
				return 0;

			}

			hRes = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

			if (FAILED(hRes)) {

				PRINT_OUT("[!] WMI: Could not set proxy blanket.\n");
				pSvc->Release();
				pLoc->Release();
				CoUninitialize();
				return 0;

			}

			IEnumWbemClassObject* pEnumerator = NULL;

			hRes = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_Service"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

			if (FAILED(hRes)) {

				PRINT_OUT("[!] WMI: Query failed.\n");
				pSvc->Release();
				pLoc->Release();
				CoUninitialize();
				return 0;

			}

			IWbemClassObject* pclsObj = NULL;
			ULONG uReturn = 0;

			while (pEnumerator) {

				HRESULT hR = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

				if (0 == uReturn) {

					break;

				}

				VARIANT vtProp;
				VariantInit(&vtProp);

				hR = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);

				if (_wcsicmp(vtProp.bstrVal, L"eventlog") == 0) {

					hR = pclsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);
					dwEventLogPID = vtProp.intVal;
					break;

				}

				VariantClear(&vtProp);
				pclsObj->Release();

			}

			pSvc->Release();
			pLoc->Release();
			pEnumerator->Release();
			CoUninitialize();

			return dwEventLogPID;
		}		
	}

	namespace Process
	{
		LPVOID addr;
		typedef NTSTATUS(NTAPI *__NtQueryInformationProcess)(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, DWORD ProcessInformationLength, PDWORD ReturnLength);


		BOOL IsRunAsAdministrator()
		{
			BOOL fIsRunAsAdmin = FALSE;
			DWORD dwError = ERROR_SUCCESS;
			PSID pAdministratorsGroup = NULL;

			// Allocate and initialize a SID of the administrators group.
			SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
			if (!AllocateAndInitializeSid(
				&NtAuthority,
				2,
				SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_ADMINS,
				0, 0, 0, 0, 0, 0,
				&pAdministratorsGroup))
			{
				dwError = GetLastError();
				goto Cleanup;
			}

			// Determine whether the SID of administrators group is enabled in 
			// the primary access token of the process.
			if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
			{
				dwError = GetLastError();
				goto Cleanup;
			}

		Cleanup:
			// Centralized cleanup for all allocated resources.
			if (pAdministratorsGroup)
			{
				FreeSid(pAdministratorsGroup);
				pAdministratorsGroup = NULL;
			}

			// Throw the error if something failed in the function.
			if (ERROR_SUCCESS != dwError)
			{
				throw dwError;
			}

			return fIsRunAsAdmin;
		}



		BOOL CheckIntegrityLevel() {

			BOOL checkResult = FALSE;

		    HANDLE hToken, hProcess;

		    DWORD dwLengthNeeded, dwIntegrityLevel;
		    DWORD dwError = ERROR_SUCCESS;

		    PTOKEN_MANDATORY_LABEL pTIL = NULL;

		    hProcess = GetCurrentProcess();
		    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken)) {

		        if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {

		            dwError = GetLastError();
		            if (dwError == ERROR_INSUFFICIENT_BUFFER) {

		                pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
		                if (pTIL != NULL) {

		                    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {

		                        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

		                        if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
		                            checkResult = TRUE;
		                        }

		                    }

		                    LocalFree(pTIL);
		                }

		            }

		        }

		        CloseHandle(hToken);

		    }

			return checkResult;

		}

		DWORD GetCurrentSessionId()
		{
			WTS_SESSION_INFO *pSessionInfo;
			DWORD n_sessions = 0;
			BOOL ok = WTSEnumerateSessions(WTS_CURRENT_SERVER, 0, 1, &pSessionInfo, &n_sessions);
			if (!ok)
				return 0;

			DWORD SessionId = 0;

			for (DWORD i = 0; i < n_sessions; ++i)
			{
				if (pSessionInfo[i].State == WTSActive)
				{
					SessionId = pSessionInfo[i].SessionId;
					break;
				}
			}

			WTSFreeMemory(pSessionInfo);
			return SessionId;
		}		
		BOOL EnableDebugPrivilege() {

		    HANDLE hToken;

		    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		        TOKEN_PRIVILEGES tp;
		        LUID luid;

		        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {

		            tp.PrivilegeCount = 1;
		            tp.Privileges[0].Luid = luid;
		            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {

		                return TRUE;

		            }
		        }
		    }

		    return FALSE;
		}

		BOOL IsDebugPrivilegeEnabled() {

		    BOOL privilgeStatus = FALSE;

		    LUID luid;
		    PRIVILEGE_SET privs;
		    HANDLE hProcess;
		    HANDLE hToken;
		    hProcess = GetCurrentProcess();

		    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {

		        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {

		            privs.PrivilegeCount = 1;
		            privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
		            privs.Privilege[0].Luid = luid;
		            privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

		            BOOL privCheckResult;
		            PrivilegeCheck(hToken, &privs, &privCheckResult);

		            if (privCheckResult == TRUE) {

		                PRINT_OUT("[+] SeDebugPrivilege is enable, continuing...\n\n");

		                privilgeStatus = TRUE;
		            }
		            else {

		                PRINT_OUT("[!] SeDebugPrivilege is not enabled, trying to enable...\n");
		                
		                if (EnableDebugPrivilege() == TRUE) {
		                
		                    PRINT_OUT("[+] SeDebugPrivilege is enabled, continuing...\n\n");

		                    privilgeStatus = TRUE;
		                
		                }
		                else {
		                    
		                    privilgeStatus = FALSE;
		                
		                }
		            
		            }
		        
		        }
		    
		    }

		    return privilgeStatus;

		}
		LPCWSTR GetIntegrityLevelName(DWORD integrityLevel)
		{
			if (integrityLevel >= SECURITY_MANDATORY_UNTRUSTED_RID && integrityLevel < SECURITY_MANDATORY_LOW_RID) return L"Untrusted";
			else if (integrityLevel >= SECURITY_MANDATORY_LOW_RID && integrityLevel < SECURITY_MANDATORY_MEDIUM_RID) return L"Low";
			else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && integrityLevel < SECURITY_MANDATORY_HIGH_RID) return L"Medium";
			else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID && integrityLevel < SECURITY_MANDATORY_SYSTEM_RID) return L"High";
			else if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) return L"System";
			else return NULL;
		}

		


		BOOL SetPrivilege(
			HANDLE hToken,          // access token handle
			LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
			BOOL bEnablePrivilege   // to enable or disable privilege
		)
		{
			TOKEN_PRIVILEGES tp;
			LUID luid;

			if (!LookupPrivilegeValue(
				NULL,            // lookup privilege on local system
				lpszPrivilege,   // privilege to lookup 
				&luid))        // receives LUID of privilege
			{
				PRINT_OUT(_T("LookupPrivilegeValue error: %u\n"), GetLastError());
				return FALSE;
			}

			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			if (bEnablePrivilege)
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			else
				tp.Privileges[0].Attributes = 0;

			// Enable the privilege or disable all privileges.

			if (!AdjustTokenPrivileges(
				hToken,
				FALSE,
				&tp,
				sizeof(TOKEN_PRIVILEGES),
				(PTOKEN_PRIVILEGES)NULL,
				(PDWORD)NULL))
			{
				PRINT_OUT(_T("AdjustTokenPrivileges error: %u\n"), GetLastError());
				return FALSE;
			}

			if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

			{
				PRINT_OUT(_T("The token does not have the specified privilege. \n"));
				return FALSE;
			}

			return TRUE;
		}

		BOOL EnableRequiredPrivileges()
		{
			DWORD dwError = ERROR_SUCCESS;

			TCHAR szUserProfileDir[MAX_PATH];
			DWORD cchUserProfileDir = ARRAYSIZE(szUserProfileDir);
			STARTUPINFO si = { sizeof(si) };
			PROCESS_INFORMATION pi = { 0 };

			DWORD dwWaitResult;
			DWORD dwSessionId = GetCurrentSessionId();
			if (dwSessionId == 0)    // no-one logged in
			{
				PRINT_OUT(TEXT("GetCurrentSessionId failed (%d).\n"), GetLastError());
				return false;
			}

			RevertToSelf();
			HANDLE hToken = NULL;
			BOOL goodToken = WTSQueryUserToken(dwSessionId, &hToken);
			if (!goodToken)
			{
				DWORD err = GetLastError();
				PRINT_OUT(TEXT("WTSQueryUserToken failed (%d).\n"), GetLastError());

				if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken))
				{
					if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
						return FALSE;
					}
				}
			}

			BOOL bSeDebugPrivilege = SetPrivilege(hToken, TEXT("SeDebugPrivilege"), TRUE);
			if (!bSeDebugPrivilege) {
				PRINT_OUT_S(TEXT("[*] SetPrivilege SeDebugPrivilege failed. CODE: 0x%08X\n"), GetLastError());
			}
			BOOL bSeAssignPrimaryTokenPrivilege = SetPrivilege(hToken, TEXT("SeAssignPrimaryTokenPrivilege"), TRUE);
			if (!bSeAssignPrimaryTokenPrivilege) {
				PRINT_OUT_S(TEXT("[*] SetPrivilege SeAssignPrimaryTokenPrivilege failed. CODE: 0x%08X\n"), GetLastError());
			}
			BOOL bSeImpersonatePrivilege = SetPrivilege(hToken, TEXT("SeImpersonatePrivilege"), TRUE);
			if (!bSeImpersonatePrivilege) {
				PRINT_OUT_S(TEXT("[*] SetPrivilege SeImpersonatePrivilege failed. CODE: 0x%08X\n"), GetLastError());
			}
			BOOL bSeCreateTokenPrivilege = SetPrivilege(hToken, TEXT("SeCreateTokenPrivilege"), TRUE);
			if (!bSeCreateTokenPrivilege) {
				PRINT_OUT_S(TEXT("[*] SetPrivilege SeCreateTokenPrivilege failed. CODE: 0x%08X\n"), GetLastError());
			}
			BOOL bSeTcbPrivilege = SetPrivilege(hToken, TEXT("SeTcbPrivilege"), TRUE);
			if (!bSeTcbPrivilege) {
				PRINT_OUT_S(TEXT("[*] SetPrivilege SeTcbPrivilege failed. CODE: 0x%08X\n"), GetLastError());
			}
			BOOL bSeIncreaseQuotaPrivilege = SetPrivilege(hToken, TEXT("SeIncreaseQuotaPrivilege"), TRUE);
			if (!bSeIncreaseQuotaPrivilege) {
				PRINT_OUT_S(TEXT("[*] SetPrivilege SeIncreaseQuotaPrivilege failed. CODE: 0x%08X\n"), GetLastError());
			}

			if (!bSeAssignPrimaryTokenPrivilege ||
				!bSeImpersonatePrivilege ||
				!bSeCreateTokenPrivilege ||
				!bSeTcbPrivilege ||
				!bSeIncreaseQuotaPrivilege)
			{
				PRINT_OUT_S(TEXT("[*] SetPrivilege failed.\n"));
				return false;
			}
			PRINT_OUT_S(TEXT("[*] Privilege Enabled: SeAssignPrimaryTokenPrivilege\n"));
			PRINT_OUT_S(TEXT("[*] Privilege Enabled: SeImpersonatePrivilege\n"));
			PRINT_OUT_S(TEXT("[*] Privilege Enabled: SeCreateTokenPrivilege\n"));
			PRINT_OUT_S(TEXT("[*] Privilege Enabled: SeTcbPrivilege\n"));
			PRINT_OUT_S(TEXT("[*] Privilege Enabled: SeIncreaseQuotaPrivilege\n"));
			
			return TRUE;
		}

		void ElevateNow(int argc, TCHAR argv[], TCHAR envp)
		{
			BOOL bAlreadyRunningAsAdministrator = FALSE;
			try
			{
				bAlreadyRunningAsAdministrator = IsRunAsAdministrator();
			}
			catch (...)
			{
				std::cout << "Failed to determine if application was running with admin rights" << std::endl;
				DWORD dwErrorCode = GetLastError();
				TCHAR szMessage[256];
				PRINT_OUT_S(szMessage, ARRAYSIZE(szMessage), _T("Error code returned was 0x%08lx"), dwErrorCode);
				std::cout << szMessage << std::endl;
			}
			if (!bAlreadyRunningAsAdministrator)
			{
				TCHAR szPath[MAX_PATH];
				if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
				{
					std::cout << "Running under ELEVATION: " << szPath << std::endl;
					TCHAR szParams[256];
					PRINT_OUT_S(szParams, ARRAYSIZE(szParams), _T("-u tet"));
					std::cout << szParams << std::endl;

					// Launch itself as admin
					SHELLEXECUTEINFO sei = { sizeof(sei) };
					sei.lpParameters = szParams;
					sei.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_NOCLOSEPROCESS;
					sei.lpVerb = TEXT("runas");
					sei.lpFile = szPath;
					sei.hwnd = NULL;
					sei.nShow = SW_NORMAL;
					
					if (!ShellExecuteEx(&sei))
					{
						DWORD dwError = GetLastError();
						if (dwError == ERROR_CANCELLED)
						{
							// The user refused to allow privileges elevation.
							std::cout << "End user did not allow elevation" << std::endl;
						}
					}
				}
			}
		}
		// Either returns true (for a retry) or false (success or failure)
		// Failure: pnbProcesses is 0 and there is no buffer to free
		// Success: pnbProcesses is greater than 0 and *pprocesses contains a pointer to be freed
		BOOL FillProcessesListWithAlloc(PDWORD *pprocesses, DWORD size, PDWORD pnbProcesses)
		{
			DWORD *processes, bytes = 0, result = 0;
			BOOL retry = FALSE, realloc = FALSE;

			// Attempt allocation or reallocation
			if (!(*pprocesses)) {
				processes = (PDWORD)HeapAlloc(GetProcessHeap(), 0, size);
			}
			else {
				processes = (PDWORD)HeapReAlloc(GetProcessHeap(), 0, *pprocesses, size);
				realloc = TRUE;
			}
			// If allocation for requested size succeeded
			if (processes) {
				if (EnumProcesses(processes, size, &bytes)) {
					// Success
					if (bytes<size) {
						result = bytes / sizeof(DWORD);
					}
					else {
						// Buffer too small to list all processIDs
						retry = TRUE;
					}
					// Writes the allocation pointer back in case of success or retry
					*pprocesses = processes;
				}
				else {
					HeapFree(GetProcessHeap(), 0, processes);
					PRINT_OUT(_T("EnumProcesses() failure, error %#.8x\n"), GetLastError());
				}
			} // if processes
			else {
				// Allocation failure handling
				PRINT_OUT(_T("Allocation failure (requested %#.8x bytes), aborting\n"), size);
				// If realloc failed, a free is necessary
				if (realloc) {
					HeapFree(GetProcessHeap(), 0, *pprocesses);
				}
			}
			// Write back nb of processe only if we are done
			if (!retry) {
				*pnbProcesses = result;
			}
			return retry;
		}

		// Attemps to fill the stack buffer if large enough, otherwise move on to allocations
		DWORD FillProcessesList(PDWORD *pprocesses, DWORD bufsize)
		{
			DWORD nb_processes = 0, bytes, size = bufsize;
			BOOL retry;

			// First attemps on stack buffer
			if (EnumProcesses(*pprocesses, size, &bytes)) {
				if (bytes >= size) {
					// Not large enough, allocating
					*pprocesses = NULL;
					do {
						size *= 2;    // doubling size of buffer for processIDs list
						retry = FillProcessesListWithAlloc(pprocesses, size, &nb_processes);
					} while (retry);
				}
				else {
					nb_processes = bytes / sizeof(DWORD);
				}
			} // if enumProcesses
			else {
				PRINT_OUT(_T("EnumProcesses failed with error %#.8x\n"), GetLastError());
			}
			return nb_processes;
		}
		BOOL ProcessIdToName(DWORD processId, TCHAR* processName, DWORD buffSize)
		{
			BOOL ret = FALSE;
			HANDLE handle = OpenProcess(
				PROCESS_QUERY_LIMITED_INFORMATION,
				FALSE,
				processId 
			);
			if (handle){
				DWORD copied = QueryFullProcessImageName(handle, 0, processName, &buffSize);
				if (copied > 0 && copied <= buffSize){
					ret = TRUE;
				}
				else{
					PRINT_OUT("Error QueryFullProcessImageName : %lu", GetLastError());
				}
				CloseHandle(handle);
			}
			else{
				PRINT_OUT("Error OpenProcess : %lu", GetLastError());
			}
			return ret;
		}
		// Returns success boolean and outputs process handle with requested rights
		BOOL GetProcessbyNameOrId(LPTSTR searchstring, PHANDLE phProcess, DWORD rights)
		{
			BOOL found = FALSE;
			HMODULE hMod;
			DWORD *processes, lpProcesses[QUITE_LARGE_NB_PROCESSES], bytes, processId;
			SIZE_T nbProcesses, i;
			HANDLE hProcess;
			TCHAR processname[MAX_PATH + 1], *stop;

			processId = _tcstoul(searchstring, &stop, 0);
			if (processId && *stop == L'\0') {
				hProcess = OpenProcess(rights, FALSE, processId);
				if (hProcess) {
					*phProcess = hProcess;
					found = TRUE;
				}
			}
			else {
				processes = lpProcesses;
				nbProcesses = FillProcessesList(&processes, sizeof(lpProcesses));
				if (nbProcesses) {
					for (i = 0; i<nbProcesses && !found; i++) {
						hProcess = OpenProcess(IDENTIFICATION_RIGHTS, FALSE, processes[i]);
						if (hProcess) {
							if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &bytes)) {
								if (GetModuleBaseName(hProcess, hMod, processname, sizeof(processname) / sizeof(TCHAR))) {
									// Found the process by that name
									if (!_tcsicmp(searchstring, processname)) {
										// Close the handle and attempt reopenning with requested rights
										CloseHandle(hProcess);
										hProcess = OpenProcess(rights, FALSE, processes[i]);
										if (hProcess) {
											*phProcess = hProcess;
											found = TRUE;
										}
									} // if _tcsicmp
								} // if GetModuleBaseName
							} // if EnumProcessModules
							if (!found) {
								// Only close this process handle if it is not the one we are looking for
								CloseHandle(hProcess);
							}
						} // if hProcess
					} // for all processes
					if (processes != lpProcesses) {
						HeapFree(GetProcessHeap(), 0, processes);
					}
				} // if nbProcesses
			}
			return found;
		}


		BOOL ListProcessThreads(DWORD dwOwnerPID, TThreads &threads)
		{
			HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
			HANDLE hThread = NULL;
			THREADENTRY32 te32;

			// Take a snapshot of all running threads  
			hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (hThreadSnap == INVALID_HANDLE_VALUE)
				return(FALSE);

			// Fill in the size of the structure before using it. 
			te32.dwSize = sizeof(THREADENTRY32);

			// Retrieve information about the first thread,
			// and exit if unsuccessful
			if (!Thread32First(hThreadSnap, &te32))
			{
				printError(TEXT("Thread32First"));  // Show cause of failure
				CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
				return(FALSE);
			}

			// Now walk the thread list of the system,
			// and display information about each thread
			// associated with the specified process
			do
			{
				if (te32.th32OwnerProcessID == dwOwnerPID)
				{
					hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
					SThreadEntry thrd;
					thrd.threadId = te32.th32ThreadID;
					thrd.parentPid = dwOwnerPID;
					thrd.startAddress = GetThreadStartAddress(hThread);
					thrd.size = te32.dwSize;
					thrd.flags = te32.dwFlags;
					threads.push_back(thrd);
				}
			} while (Thread32Next(hThreadSnap, &te32));


			//  Don't forget to clean up the snapshot object.
			CloseHandle(hThreadSnap);
			return(TRUE);
		}

		DWORD GetThreadStartAddress(HANDLE hThread)
		{

			NTSTATUS ntStatus;
			DWORD dwStartAddress = 0;

			pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
			if (NtQueryInformationThread == NULL)
				return 0;

			ntStatus = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(DWORD), NULL);

			CloseHandle(hThread);


			if (ntStatus != STATUS_SUCCESS) return 0;

			return dwStartAddress;

		}
		void printError(TCHAR* msg)
		{
			DWORD eNum;
			TCHAR sysMsg[256];
			TCHAR* p;

			eNum = GetLastError();
			FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, eNum,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
				sysMsg, 256, NULL);

			// Trim the end of the line and terminate it with a null
			p = sysMsg;
			while ((*p > 31) || (*p == 9))
				++p;
			do { *p-- = 0; } while ((p >= sysMsg) &&
				((*p == '.') || (*p < 33)));

			// Display the message
			PRINT_OUT(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
		}

	}

	namespace Thread
	{
		typedef LONG    NTSTATUS;
		typedef NTSTATUS(WINAPI* pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);
		#define STATUS_SUCCESS    ((NTSTATUS)0x00000000L)
		#define ThreadQuerySetWin32StartAddress 9

		DWORD WINAPI GetThreadStartAddress(HANDLE hThread)
		{
			NTSTATUS ntStatus;
			HANDLE hDupHandle;
			DWORD dwStartAddress;

			pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");

			if (NtQueryInformationThread == NULL) return 0;

			HANDLE hCurrentProcess = GetCurrentProcess();

			if (!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)) {
				SetLastError(ERROR_ACCESS_DENIED);
				return 0;
			}

			ntStatus = NtQueryInformationThread(hDupHandle, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(DWORD), NULL);

			CloseHandle(hDupHandle);

			if (ntStatus != STATUS_SUCCESS) return 0;
			return dwStartAddress;
		}
	}

	namespace Service
	{
		SC_HANDLE GetServiceByName(LPCWSTR name)
		{
			SC_HANDLE serviceManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
			if (!serviceManager) return NULL;

			SC_HANDLE service = OpenServiceW(serviceManager, name, SC_MANAGER_ALL_ACCESS);

			CloseServiceHandle(serviceManager);
			return service;
		}
		DWORD GetServiceState(SC_HANDLE service)
		{
			SERVICE_STATUS_PROCESS status;
			DWORD bytesNeeded;
			if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) return 0;

			return status.dwCurrentState;
		}
		DWORD GetServiceProcessId(SC_HANDLE service)
		{
			SERVICE_STATUS_PROCESS status;
			DWORD bytesNeeded;
			if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) return 0;

			return status.dwProcessId;
		}
		BOOL StartServiceWait(SC_HANDLE service, DWORD expectedState, DWORD delayMilliseconds, DWORD timeoutMilliseconds)
		{
			BOOL result = FALSE;
			ULONGLONG startTime = GetTickCount64();

			while (!result && GetTickCount64() - startTime < timeoutMilliseconds)
			{
				StartServiceW(service, 0, NULL);
				Sleep(delayMilliseconds);

				result = GetServiceState(service) == expectedState;
			}

			return result;
		}
		BOOL ControlServiceWait(SC_HANDLE service, DWORD control, DWORD expectedState, DWORD delayMilliseconds, DWORD timeoutMilliseconds)
		{
			BOOL result = FALSE;
			ULONGLONG startTime = GetTickCount64();
			SERVICE_STATUS_PROCESS status;

			while (!result && GetTickCount64() - startTime < timeoutMilliseconds)
			{
				ControlService(service, control, (LPSERVICE_STATUS)&status);
				Sleep(delayMilliseconds);

				result = GetServiceState(service) == expectedState;
			}

			return result;
		}
	}

}