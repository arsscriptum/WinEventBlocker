
//==============================================================================
//
//   win32.h 
//
//   note those 2 are originally from https://github.com/hlldz/Phant0m: 
//     WinEvent::GetPIDFromSCManager
//     WinEvent::GetPIDFromWMI
//==============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================


#ifndef WINAPIEX_H
#define WINAPIEX_H


#include <fstream>
#include <Windows.h>
#include <winternl.h>
#include <shlobj.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <lm.h>
#include <Psapi.h>
#include <vector>
#include <string>

#ifdef UNICODE
#define LOADLIBRARY "LoadLibraryW"
#else
#define LOADLIBRARY "LoadLibraryA"
#endif
#define TIMEOUT_10SEC 10000
#define QUITE_LARGE_NB_PROCESSES 256
#define SOME_SYSTEM_PROCESS_IN_CURRENT_SESSION _T("winlogon.exe")
#define INJECTION_RIGHTS (PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE)
#define IDENTIFICATION_RIGHTS (PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ)


typedef struct _TIME_FIELDS {
	USHORT Year;        // range [1601...]
	USHORT Month;       // range [1..12]
	USHORT Day;         // range [1..31]
	USHORT Hour;        // range [0..23]
	USHORT Minute;      // range [0..59]
	USHORT Second;      // range [0..59]
	USHORT Milliseconds;// range [0..999]
	USHORT Weekday;     // range [0..6] == [Sunday..Saturday]
} TIME_FIELDS;
typedef TIME_FIELDS* PTIME_FIELDS;
#define TICKSPERMIN        600000000
#define TICKSPERSEC        10000000
#define TICKSPERMSEC       10000
#define SECSPERDAY         86400
#define SECSPERHOUR        3600
#define SECSPERMIN         60
#define MINSPERHOUR        60
#define HOURSPERDAY        24
#define EPOCHWEEKDAY       1
#define DAYSPERWEEK        7
#define EPOCHYEAR          1601
#define DAYSPERNORMALYEAR  365
#define DAYSPERLEAPYEAR    366
#define MONSPERYEAR        12

#if defined(__GNUC__)
#define TICKSTO1970         0x019db1ded53e8000LL
#define TICKSTO1980         0x01a8e79fe1d58000LL
#else
#define TICKSTO1970         0x019db1ded53e8000i64
#define TICKSTO1980         0x01a8e79fe1d58000i64
#endif


static const unsigned int YearLengths[2] =
{
	DAYSPERNORMALYEAR, DAYSPERLEAPYEAR
};
static const UCHAR MonthLengths[2][MONSPERYEAR] =
{
	{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
	{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static __inline int IsLeapYear(int Year)
{
	return Year % 4 == 0 && (Year % 100 != 0 || Year % 400 == 0) ? 1 : 0;
}

static int DaysSinceEpoch(int Year)
{
	int Days;
	Year--; /* Don't include a leap day from the current year */
	Days = Year * DAYSPERNORMALYEAR + Year / 4 - Year / 100 + Year / 400;
	Days -= (EPOCHYEAR - 1) * DAYSPERNORMALYEAR + (EPOCHYEAR - 1) / 4 - (EPOCHYEAR - 1) / 100 + (EPOCHYEAR - 1) / 400;
	return Days;
}


namespace C
{
	//TODO: Review checking of invalid handles (NULL vs INVALID_HANDLE_VALUE, INVALID_SOMETHING_HANDLE, etc.)
	//FEATURE: Injection bootstrapper for .NET DLL's

	template<typename T>
	struct Array
	{
	private:
		int _Capacity = 0;
		int _Count = 0;
		T* _Values = NULL;

		void __ctor(int capacity)
		{
			_Capacity = capacity;
			_Values = new T[_Capacity];
		}
	public:
		Array()
		{
			__ctor(0);
		}
		Array(int capacity)
		{
			__ctor(capacity);
		}

		int Count()
		{
			return _Count;
		}
		void Add(const T &value)
		{
			if (_Count == _Capacity)
			{
				_Capacity = (_Capacity & ~0xff) + 0x100;

				T *newValues = new T[_Capacity];
				memcpy(newValues, _Values, sizeof(T) * _Count);

				delete[] _Values;
				_Values = newValues;
			}

			_Values[_Count++] = value;
		}

		const T& operator [](int index)
		{
			if (index < 0 || index >= _Count) throw;
			return _Values[index];
		}
	};

	enum class SpecialFolder
	{
		Desktop = CSIDL_DESKTOP,
		Internet = CSIDL_INTERNET,
		Programs = CSIDL_PROGRAMS,
		Controls = CSIDL_CONTROLS,
		Printers = CSIDL_PRINTERS,
		MyDocuments = CSIDL_MYDOCUMENTS,
		Favorites = CSIDL_FAVORITES,
		Startup = CSIDL_STARTUP,
		Recent = CSIDL_RECENT,
		SendTo = CSIDL_SENDTO,
		BitBucket = CSIDL_BITBUCKET,
		StartMenu = CSIDL_STARTMENU,
		MyMusic = CSIDL_MYMUSIC,
		MyVideo = CSIDL_MYVIDEO,
		DesktopDirectory = CSIDL_DESKTOPDIRECTORY,
		Drives = CSIDL_DRIVES,
		Network = CSIDL_NETWORK,
		NetHood = CSIDL_NETHOOD,
		Fonts = CSIDL_FONTS,
		Templates = CSIDL_TEMPLATES,
		CommonStartMenu = CSIDL_COMMON_STARTMENU,
		CommonPrograms = CSIDL_COMMON_PROGRAMS,
		CommonStartup = CSIDL_COMMON_STARTUP,
		CommonDesktopDirectory = CSIDL_COMMON_DESKTOPDIRECTORY,
		AppData = CSIDL_APPDATA,
		PrintHood = CSIDL_PRINTHOOD,
		LocalAppData = CSIDL_LOCAL_APPDATA,
		AltStartup = CSIDL_ALTSTARTUP,
		CommonAltStartup = CSIDL_COMMON_ALTSTARTUP,
		CommonFavorites = CSIDL_COMMON_FAVORITES,
		InternetCache = CSIDL_INTERNET_CACHE,
		Cookies = CSIDL_COOKIES,
		History = CSIDL_HISTORY,
		CommonAppData = CSIDL_COMMON_APPDATA,
		Windows = CSIDL_WINDOWS,
		System = CSIDL_SYSTEM,
		ProgramFiles = CSIDL_PROGRAM_FILES,
		MyPictures = CSIDL_MYPICTURES,
		Profile = CSIDL_PROFILE,
		SystemX86 = CSIDL_SYSTEMX86,
		ProgramFilesX86 = CSIDL_PROGRAM_FILESX86,
		ProgramFilesCommon = CSIDL_PROGRAM_FILES_COMMON,
		ProgramFilesCommonX86 = CSIDL_PROGRAM_FILES_COMMONX86,
		CommonTemplates = CSIDL_COMMON_TEMPLATES,
		CommonDocuments = CSIDL_COMMON_DOCUMENTS,
		CommonAdminTools = CSIDL_COMMON_ADMINTOOLS,
		AdminTools = CSIDL_ADMINTOOLS,
		Connections = CSIDL_CONNECTIONS,
		CommonMusic = CSIDL_COMMON_MUSIC,
		CommonPictures = CSIDL_COMMON_PICTURES,
		CommonVideo = CSIDL_COMMON_VIDEO,
		Resources = CSIDL_RESOURCES,
		ResourcesLocalized = CSIDL_RESOURCES_LOCALIZED,
		CommonOemLinks = CSIDL_COMMON_OEM_LINKS,
		CDBurnArea = CSIDL_CDBURN_AREA,
		ComputersNearMe = CSIDL_COMPUTERSNEARME
	};
	

	namespace WinTime
	{
		VOID TimeToTimeFields( PLARGE_INTEGER Time, PTIME_FIELDS TimeFields);
	}
	namespace WinEvent
	{
		DWORD GetPIDFromSCManager();
		DWORD GetPIDFromWMI();
	}



#define STATUS_SUCCESS    ((NTSTATUS)0x00000000L)
#define ThreadQuerySetWin32StartAddress 9
	namespace Process
	{
		typedef struct _CLIENT_ID {
			HANDLE UniqueProcess;
			HANDLE UniqueThread;
		} CLIENT_ID;

		typedef struct _THREAD_BASIC_INFORMATION {
			NTSTATUS    exitStatus;
			PVOID       pTebBaseAddress;
			CLIENT_ID   clientId;
			KAFFINITY	AffinityMask;
			int			Priority;
			int			BasePriority;
			int			v;

		} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

		typedef enum _SC_SERVICE_TAG_QUERY_TYPE {
			ServiceNameFromTagInformation = 1,
			ServiceNameReferencingModuleInformation,
			ServiceNameTagMappingInformation,
		} SC_SERVICE_TAG_QUERY_TYPE, * PSC_SERVICE_TAG_QUERY_TYPE;

		typedef struct _SC_SERVICE_TAG_QUERY {
			ULONG   processId;
			ULONG   serviceTag;
			ULONG   reserved;
			PVOID   pBuffer;
		} SC_SERVICE_TAG_QUERY, * PSC_SERVICE_TAG_QUERY;

		struct SModuleEntry
		{
			std::string imageName;
			std::string moduleName;
			DWORD baseAddress;
			DWORD size;
		};
		struct SThreadEntry
		{
			DWORD threadId;
			DWORD parentPid;
			DWORD startAddress;
			DWORD size;
			DWORD flags;
		};
		typedef std::vector<SModuleEntry> TModules;
		typedef TModules::iterator ModuleListIter;
		typedef std::vector<SThreadEntry> TThreads;
		typedef TThreads::iterator ThreadsListIter;

		typedef struct _MODULEINFO {
			LPVOID lpBaseOfDll;
			DWORD SizeOfImage;
			LPVOID EntryPoint;
		} MODULEINFO, * LPMODULEINFO;
		//  Forward declarations:

		typedef LONG    NTSTATUS;
		typedef NTSTATUS(WINAPI* pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);

		BOOL IsDebugPrivilegeEnabled();
		BOOL EnableDebugPrivilege();
		LPCWSTR GetIntegrityLevelName(DWORD integrityLevel);
		BOOL CheckIntegrityLevel();
		DWORD GetProcessIdByName(LPCWSTR name);
		BOOL CreateProcessWithIntegrity(LPCWSTR commandLine, DWORD integrityLevel, LPDWORD processId);
		BOOL TerminateProcess(DWORD processId, UINT uExitCode);
		LPWSTR GetProcessName(DWORD processId);
		LPWSTR GetProcessCommandLine(DWORD processId);
		DWORD GetProcessIntegrityLevel(HANDLE process);
		DWORD GetParentProcessId(DWORD processId);
		Array<HWND>* GetProcessWindows(DWORD processID);
		BOOL InjectDll(HANDLE process, LPCWSTR dllPath);
		BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
		// Privilage Elevation
		DWORD GetCurrentSessionId();
		BOOL CreateInteractiveProcessForUser(LPTSTR lpszUsername, LPTSTR lpszDomain, LPTSTR lpszPassword, LPTSTR lpCommandLine);
		BOOL CreateInteractiveProcess(TCHAR* pszCommandLine);
		BOOL ProcessIdToName(DWORD processId, TCHAR* processName, DWORD buffSize);
		BOOL GetLogonSID(HANDLE hToken, PSID *ppsid);
		BOOL AddAceToWindowStation(HWINSTA hwinsta, PSID psid);
		BOOL AddAceToDesktop(HDESK hdesk, PSID psid);
		BOOL FillProcessesListWithAlloc(PDWORD*, DWORD, PDWORD);
		DWORD FillProcessesList(PDWORD*, DWORD);
		BOOL GetProcessbyNameOrId(LPTSTR searchstring, PHANDLE phProcess, DWORD rights);
		DWORD GetProcessSession(HANDLE hProcess);
		BOOL IsRunAsAdministrator();
		void ElevateNow(int argc, TCHAR argv[], TCHAR envp);
		BOOL EnableRequiredPrivileges();
		bool FillModuleListPSAPI(TModules& mods, DWORD pid, HANDLE hProcess);
		bool FillModuleListTH32(C::Process::TModules& modules, DWORD pid);
		BOOL ListProcessThreads(DWORD dwOwnerPID, TThreads & t);
		void printError(TCHAR* msg);
		DWORD GetThreadStartAddress(HANDLE hThread);
	}

	namespace Thread
	{
		DWORD WINAPI GetThreadStartAddress(HANDLE hThread);
	}

	namespace Service
	{
		//FEATURE: GetAllServices()
		SC_HANDLE GetServiceByName(LPCWSTR name);
		DWORD GetServiceState(SC_HANDLE service);
		DWORD GetServiceProcessId(SC_HANDLE service);
		BOOL StartServiceWait(SC_HANDLE service, DWORD expectedState, DWORD delayMilliseconds, DWORD timeoutMilliseconds);
		BOOL ControlServiceWait(SC_HANDLE service, DWORD control, DWORD expectedState, DWORD delayMilliseconds, DWORD timeoutMilliseconds);
	}

}

#endif