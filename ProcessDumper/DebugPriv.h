#include <TlHelp32.h>
#include <windows.h>
#include <strsafe.h>
#include <tchar.h>

BOOL EnableDebugAbilityWithChecks(void) {

	// Get the privilege value for SeDebugPrivilege
	// API - https://msdn.microsoft.com/en-us/library/windows/desktop/aa379180(v=vs.85).aspx
	// Privs - https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716(v=vs.85).aspx

	LUID	privilegeLuid;
	if (!LookupPrivilegeValue(NULL, _T("SeDebugPrivilege"), &privilegeLuid)) {

		ErrorDetails(LPTSTR("LookupPrivilegeValue()"), true);
	}

	// Fill up the TOKEN_PRIVILEGES structure
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx

	TOKEN_PRIVILEGES	tkPrivs;

	tkPrivs.PrivilegeCount = 1; // Only modify one privilege
	tkPrivs.Privileges[0].Luid = privilegeLuid; // specify the privilege to be modified i.e. SeDebugPrivilege
	tkPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // lets enable this privilege

	// All set! Now lets the process token
	// Get current process handle - https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179(v=vs.85).aspx
	// Get process token - https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295(v=vs.85).aspx
	// Token access rights - https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

	HANDLE	currentProcessHandle = GetCurrentProcess();
	HANDLE	processToken;

	// IMPORTANT:  TOKEN_QUERY IS REQUIRED!!

	if (!OpenProcessToken(currentProcessHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken)) {

		ErrorDetails(LPTSTR("OpenProcessToken()"), true);
	}

	// Did you check if the privilege is available before enabling it? :) 
	// GetTokenInformation()
	// TokenPrivileges
	// MSDN sample: https://msdn.microsoft.com/en-us/library/aa390429(v=vs.85).aspx

	// Let's first get the structure size

	DWORD structSize;

	GetTokenInformation(processToken, TokenPrivileges, NULL, 0, &structSize);


	// Now lets get all the available Privileges and check if SeDebugPrivilege is even available 
	// for enabling?  If not raise an error to the user and exit

	DWORD structSize2;   // should come out of the API with same value as structSize2
	PTOKEN_PRIVILEGES processTokenPrivs;

	processTokenPrivs = (PTOKEN_PRIVILEGES)malloc(structSize);

	if (!GetTokenInformation(processToken, TokenPrivileges, processTokenPrivs, structSize, &structSize2)) {

		ErrorDetails(LPTSTR("GetTokenInformation()"), true);
	}

	// Now let us iterate through and see if we can find SeDebugPrivilege

	PLUID_AND_ATTRIBUTES runner;
	bool seDebugAvailable = false;

	for (DWORD x = 0; x < processTokenPrivs->PrivilegeCount; x++) {

		runner = &processTokenPrivs->Privileges[x];

		// RtlEqualLuid https://msdn.microsoft.com/en-us/library/windows/hardware/ff561842(v=vs.85).aspx
		// used in device drivers
		// However the comparison is so simple we can do it ourselves 
		// LUID:  https://msdn.microsoft.com/en-us/library/windows/desktop/aa379261(v=vs.85).aspx

		if ((runner->Luid.LowPart == privilegeLuid.LowPart) && (runner->Luid.HighPart == privilegeLuid.HighPart)) {

			_tprintf(_T("[+] SeDebugPrivilege available for enabling!\n"));
			seDebugAvailable = true;
			break;
		}
	}

	if (!seDebugAvailable) {

		// if we reached here we could not find the Privilege in the token 
		_tprintf(_T("[-] SeDebugPrivilege unavailable\nPlease run with Privileges!"));
		return FALSE;
	}

	// Awesome! next step! 
	// Let us now enable debug privileges in the token!

	if (!AdjustTokenPrivileges(processToken, false, &tkPrivs, 0, NULL, NULL)) {

		ErrorDetails(LPTSTR("AdjustTokenPrivileges()"), true);
	}

	_tprintf(_T("[+] SeDebugPrivilege enabled!\n"));

	return TRUE;
}

BOOL DuplicateToken(DWORD processPid) {

	// QUERY Information is important if we want to impersonate the token  
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, processPid);
	if (procHandle == NULL) {
		ErrorDetails(LPTSTR("OpenProcess(PROCESS_QUERY_INFORMATION)"), true);
	}

	HANDLE tokenProcHandle;
	if (!OpenProcessToken(procHandle, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &tokenProcHandle)) {
		ErrorDetails(LPTSTR("OpenProcessToken()"), true);
	}

	HANDLE dupTokenHandle;
	if (!DuplicateToken(tokenProcHandle, SecurityImpersonation, &dupTokenHandle)) {
		ErrorDetails(LPTSTR("DuplicateToken()"), true);
	}

	// Close handles that we are finished with
	CloseHandle(procHandle);
	CloseHandle(tokenProcHandle);

	if (!SetThreadToken(NULL, dupTokenHandle)) {
		ErrorDetails(LPTSTR("DuplicateToken()"), true);
	}

	_tprintf(_T("\n[+] %d Process Token Successfully Duplicated\n"), processPid);

	return TRUE;
}


