#pragma once
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <algorithm>
#include <stdio.h>
#include <DbgHelp.h>
#include <comdef.h>

void Error(
	_In_ DWORD lastError
);

DWORD FindPid(
	_In_ std::wstring imageName
);

BOOL SetPrivilege(
	_In_ HANDLE hToken,          // access token handle
	_In_ LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	_In_ BOOL bEnablePrivilege   // to enable or disable privilege
);

bool UnhookDll(
	_In_ std::string dllPath
);

typedef BOOL(WINAPI* pMiniDumpWriteDump)
(
	HANDLE hProcess,
	DWORD ProcessId,
	HANDLE hFile,
	MINIDUMP_TYPE DumpType,
	PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
	PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	PMINIDUMP_CALLBACK_INFORMATION CallbackParam
	);


namespace RAII
{
	class Handle
	{
	public:
		Handle(HANDLE inputHandle);
		~Handle();
		HANDLE GetHandle();

	private:
		HANDLE _internalHandle;
	};

	class Hmodule
	{
	public:
		Hmodule(HMODULE inputHmodule);
		~Hmodule();
		HMODULE GetHmodule();

	private:
		HMODULE _internalHmodule;
	};
};


int TokenSteal(char* arg, char* arg2);