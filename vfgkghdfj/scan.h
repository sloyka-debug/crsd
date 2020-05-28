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

// Windows includes 
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h> 
#include <lm.h>
#include "./banned.h"
#include <tchar.h>

#pragma warning(disable:4996)

using namespace std;

#ifdef __MINGW32__
// This is if __MINGW32__ is not placed as a -D flag for the complier.
// The compiler will default to _WIN32 options. 
#else
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_DEPRECATE 1
#endif
#ifdef __MINGW32__
//This option is to handle the Unicode mangling with the wmain error.
//By default wmain's entry point is not found this is a temporary fix.
//https://github.com/coderforlife/mingw-unicode-main
#include "mingw-unicode.c"
#endif

class SCAN
{
public:

	int ex();
	void netview_enum(vector<wstring> &hosts, wchar_t *domain);
	void net_enum(wchar_t *host, wchar_t *domain);
	void ip_enum(wchar_t *host);	
	bool CanAccessFolder(LPCTSTR folderName, DWORD genericAccessRights);
};