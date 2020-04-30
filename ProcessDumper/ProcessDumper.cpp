/*
		There is a detailed example on MSDN:
		https://msdn.microsoft.com/en-us/library/windows/desktop/ms682623(v=vs.85).aspx

*/

#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include<processsnapshot.h>
#include<DbgHelp.h>
#include<iostream>
#include<string>
#pragma comment (lib, "dbghelp.lib")

#include "errorexit.h"
#include "DebugPriv.h"

// https://stackoverflow.com/questions/27220/how-to-convert-stdstring-to-lpcwstr-in-c-unicode
std::wstring s2ws(const std::string& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	return r;
}

// https://docs.microsoft.com/en-us/previous-versions/windows/desktop/proc_snap/export-a-process-snapshot-to-a-file
BOOL CALLBACK MyMiniDumpWriteDumpCallback(
	__in     PVOID CallbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
	switch (CallbackInput->CallbackType)
	{
	case 16: // IsProcessSnapshotCallback
		CallbackOutput->Status = S_FALSE;
		break;
	}
	return TRUE;
}

/*
* https://docs.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-module-list
* Currently not being used, but left in to remind myself about this function
*/

BOOL ListProcessModules(DWORD dwPID) {

	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	//  Take a snapshot of all modules in the specified process. 
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		ErrorDetails(LPTSTR("CreateToolhelp32Snapshot (of modules)"), false);
		return(FALSE);
	}

	//  Set the size of the structure before using it. 
	me32.dwSize = sizeof(MODULEENTRY32);

	//  Retrieve information about the first module, 
	//  and exit if unsuccessful 
	if (!Module32First(hModuleSnap, &me32))
	{
		ErrorDetails(LPTSTR("Module32First()"), true);  // Show cause of failure 
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object! 
		return(FALSE);
	}

	//  Now walk the module list of the process, 
	//  and display information about each module 
	do
	{
		_tprintf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
		_tprintf(TEXT("\n     executable     = %s"), me32.szExePath);
		_tprintf(TEXT("\n     process ID     = 0x%08X"), me32.th32ProcessID);
		_tprintf(TEXT("\n     ref count (g)  =     0x%04X"), me32.GlblcntUsage);
		_tprintf(TEXT("\n     ref count (p)  =     0x%04X"), me32.ProccntUsage);
		_tprintf(TEXT("\n     base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
		_tprintf(TEXT("\n     base size      = %d"), me32.modBaseSize);

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(TRUE);
}

int main(void) {

	// Setup for memory dump
	DWORD processPid = 0;
	HANDLE processHandle = NULL;
	LPCWSTR processName = L"";

	// Gotta Love MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
	// Create a system snapshot and get a handle
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682489(v=vs.85).aspx
	// Use TH32CS_SNAPPROCESS for now - Students can improvise

	if (!EnableDebugAbilityWithChecks()) {
		return 1;
	}

	HANDLE	hAllProcessSnap = INVALID_HANDLE_VALUE;

	hAllProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (INVALID_HANDLE_VALUE == hAllProcessSnap) {
		ErrorDetails(LPTSTR("CreateToolhelp32Snapshot"), true);
	}

	// Let us know get the process details from the system snapshot
	// Looks like we have the findfirst findnext style APIs for this
	// Process32First https://msdn.microsoft.com/en-us/library/windows/desktop/ms684834(v=vs.85).aspx
	// Process32Next https://msdn.microsoft.com/en-us/library/windows/desktop/ms684836(v=vs.85).aspx
	// ParseProcessDetails is defined upstairs

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);  // Documentation requests to set size before use

	// Get the first entry
	if (!Process32First(hAllProcessSnap, &processEntry)) {

		// Unusual if we don't get anything? :) 
		ErrorDetails(LPTSTR("Process32First()"), true);
	}

	// do-while is the best for findfirst, findnext style APIs
	do {
		_tprintf(_T("PPID: %d	PID: %d		EXE: %s\n"),
			processEntry.th32ParentProcessID,
			processEntry.th32ProcessID,
			processEntry.szExeFile);

	} while (Process32Next(hAllProcessSnap, &processEntry));

	_tprintf(_T("\nEnter a PID to Dump:\n"));
	std::cin >> processPid;

	std::wstring stemp = s2ws(std::to_string(processPid) + ".dmp");
	LPCWSTR filename = stemp.c_str();

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processPid);

	// If the token is NULL, attempt to duplicate the token and then try again
	if (processHandle == NULL) {

		BOOL retValue = DuplicateToken(processPid);

		if (!retValue) {
			CloseHandle(hAllProcessSnap);
			return 0;
		}
		else {
			processHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, processPid);
			if (processHandle == NULL) {
				ErrorDetails(LPTSTR("OpenProcess()"), true);
			}
		}
	}	

	// https://docs.microsoft.com/en-us/previous-versions/windows/desktop/proc_snap/export-a-process-snapshot-to-a-file
	// https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
	DWORD CaptureFlags = (DWORD)PSS_CAPTURE_VA_CLONE
		| PSS_CAPTURE_HANDLES
		| PSS_CAPTURE_HANDLE_NAME_INFORMATION
		| PSS_CAPTURE_HANDLE_BASIC_INFORMATION
		| PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
		| PSS_CAPTURE_HANDLE_TRACE
		| PSS_CAPTURE_THREADS
		| PSS_CAPTURE_THREAD_CONTEXT
		| PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
		| PSS_CREATE_BREAKAWAY
		| PSS_CREATE_BREAKAWAY_OPTIONAL
		| PSS_CREATE_USE_VM_ALLOCATIONS
		| PSS_CREATE_RELEASE_SECTION;

	HANDLE snapshotHandle = NULL;
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	SecureZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = MyMiniDumpWriteDumpCallback;
	CallbackInfo.CallbackParam = NULL;

	DWORD dwResultCode = PssCaptureSnapshot(processHandle,
		(PSS_CAPTURE_FLAGS)CaptureFlags,
		CONTEXT_ALL,
		(HPSS*)&snapshotHandle);

	if (dwResultCode != ERROR_SUCCESS) {
		_tprintf(_T("Result Code: %d\n"), dwResultCode);
		ErrorDetails(LPTSTR("PssCaptureSnapshot()"), true);
	}

	HANDLE outFile = CreateFile(filename, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	BOOL isDumped = MiniDumpWriteDump(snapshotHandle, processPid, outFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);

	if (!isDumped) {
		_tprintf(_T("Failed to dump process\n"));
		ErrorDetails(LPTSTR("MiniDumpWriteDump()"), false);
	}
	else {
		_tprintf(_T("Successfully dumped process %d\n"), processPid);
	}

	PssFreeSnapshot(GetCurrentProcess(), (HPSS)snapshotHandle);
	CloseHandle(hAllProcessSnap);

	return	0;
}