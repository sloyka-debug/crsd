#pragma once
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef UNICODE
#define UNICODE
#endif
#include "pch.h"
#include <iostream>

#include <vector>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h> 
#include <lm.h>
#include "banned.h"
#include <tchar.h>
#include "Aexecute.h"

#pragma warning(disable:4996)

using namespace std;

#ifdef __MINGW32__

#else
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_DEPRECATE 1
#endif
#ifdef __MINGW32__
#include "mingw-unicode.c"
#endif

class SCAN : public Aexecute
{
public:

	void execute() override;
	void netview_enum(vector<wstring> &hosts, wchar_t *domain);
	void net_enum(wchar_t *host, wchar_t *domain);
	void ip_enum(wchar_t *host);	
	bool CanAccessFolder(LPCTSTR folderName, DWORD genericAccessRights);
};