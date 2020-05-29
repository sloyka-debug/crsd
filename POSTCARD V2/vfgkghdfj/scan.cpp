#include "pch.h"
#include "scan.h"

void SCAN::execute()
{
	FILE *file_of_hosts;
	FILE *file_exclude_hosts;
	FILE *outputfile = nullptr;
	BOOL bReadFromFile = FALSE;
	BOOL bDomainspecified = FALSE;
	BOOL bCheckShareAccess = FALSE;
	BOOL bReadFromFileArg = FALSE;
	BOOL bDomainArg = FALSE;
	BOOL bOutputToFile = FALSE;
	wchar_t *domain = NULL;
	wchar_t *group = NULL;
	wchar_t *host = NULL;
	wchar_t *tempHost = NULL;
	int interval = 0;
	double jitter = 0;
	char *filename = nullptr;
	char *outputfilename;
	char line[255];
	char tmphost[255];
	vector<wstring> hosts;
	vector<wstring> users;
	vector<wstring> excludeHosts;

	setbuf(stdout, NULL);

	bDomainArg = TRUE;
	netview_enum(hosts, domain);

	printf("\n[+] Number of hosts: %d\n", hosts.size());

	for (vector<wstring>::iterator it = hosts.begin(); it != hosts.end(); ++it)
	{
		fflush(stdout);
		host = const_cast<wchar_t *>(it->c_str());
		BOOL excludeHost = FALSE;

		// check if the host is in the exclude list, ignoring case
		for (vector<wstring>::iterator it = excludeHosts.begin(); it != excludeHosts.end(); ++it) {
			tempHost = const_cast<wchar_t *>(it->c_str());
			if (!_wcsnicmp(host, tempHost, wcslen(host))) {
				excludeHost = TRUE;
			}
		}

		// only enumerate the host if it wasn't in the exclude list
		if (!excludeHost) {
			wprintf(L"\n\n[+] Host: %ws", host);

			net_enum(host, domain);
			ip_enum(host);


			if (interval > 0.0) {
				srand(time(NULL));
				int min = (int)(interval * (1 - jitter));
				int max = (int)(interval * (1 + jitter));
				int range = max - min + 1;
				int sleep_time = rand() % range + min;
				printf("\n[*] Sleeping: %d seconds", sleep_time);

				Sleep(sleep_time * 1000);
			}
		}
	}

	if (bOutputToFile)
	{
		fclose(outputfile);
	}
	return;
}

void SCAN::netview_enum(vector<wstring>& hosts, wchar_t * domain)
{
	NET_API_STATUS nStatus;
	LPWSTR pszServerName = NULL;
	DWORD dwLevel = 101;
	LPSERVER_INFO_101 pBuf = NULL;
	LPSERVER_INFO_101 pTmpBuf;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwServerType = SV_TYPE_SERVER;
	LPWSTR pszDomainName = domain;
	DWORD dwResumeHandle = 0;


	nStatus = NetServerEnum(pszServerName,
		dwLevel,
		(LPBYTE *)& pBuf,
		dwPrefMaxLen,
		&dwEntriesRead,
		&dwTotalEntries,
		dwServerType,
		pszDomainName,
		&dwResumeHandle);

	if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
	{
		if ((pTmpBuf = pBuf) != NULL)
		{
			for (unsigned int i = 0; i < dwEntriesRead; i++)
			{
				assert(pTmpBuf != NULL);
				if (pTmpBuf == NULL)
				{
					fprintf(stderr, "An access violation has occurred\n");
					break;
				}
				else
				{
					hosts.push_back(wstring(pTmpBuf->sv101_name));
					pTmpBuf++;
				}
			}
		}
	}

	if (pBuf != NULL)
	{
		NetApiBufferFree(pBuf);
	}
}

void SCAN::net_enum(wchar_t * host, wchar_t * domain)
{
	NET_API_STATUS nStatus;
	LPWSTR pszServerName = host;
	DWORD dwLevel = 101;
	LPSERVER_INFO_101 pBuf = NULL;
	LPSERVER_INFO_101 pTmpBuf;


	nStatus = NetServerGetInfo(pszServerName,
		dwLevel,
		(LPBYTE *)& pBuf
	);

	if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
	{
		if ((pTmpBuf = pBuf) != NULL)
		{
			assert(pTmpBuf != NULL);
			if (pTmpBuf == NULL)
			{
				fprintf(stderr, "An access violation has occurred\n");
				return;
			}
			else
			{

				if (pTmpBuf->sv101_type & SV_TYPE_DOMAIN_CTRL)
				{
					wprintf(L"[+] %ws - Domain Controller\n", host);
				}
				if (pTmpBuf->sv101_type & SV_TYPE_DOMAIN_BAKCTRL)
				{
					wprintf(L"[+] %ws - Backup Domain Controller\n", host);
				}

				if (pTmpBuf->sv101_type & SV_TYPE_SQLSERVER)
				{
					wprintf(L"[+] %ws - MSSQL Server\n", host);
				}
			}
		}
	}
	if (pBuf != NULL)
	{
		NetApiBufferFree(pBuf);
	}
}

void SCAN::ip_enum(wchar_t * host)
{
	FILE* forpsxc;

	WSADATA wsaData;
	int iResult;
	int iRetval;
	DWORD dwRetval;

#ifdef __MINGW32__	
	struct addrinfo *result = NULL;
	struct addrinfo *ptr = NULL;
	struct addrinfo hints;
#else
	ADDRINFOW *result = NULL;
	ADDRINFOW *ptr = NULL;
	ADDRINFOW hints;
#endif

	LPSOCKADDR sockaddr_ip;
	wchar_t ipstringbuffer[46];
	DWORD ipbufferlength = 46;

	printf("\nIP ADRESSES: \n");
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		wprintf(L"WSAStartup failed: %d\n", iResult);
		return;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;


#ifdef __MINGW32__

	char tmphost[255];
	int len = 0;
	len = wcstombs(tmphost, host, sizeof(tmphost));
	dwRetval = getaddrinfo(tmphost, 0, &hints, &result);

#else
	dwRetval = GetAddrInfoW(host, 0, &hints, &result);
#endif

	if (dwRetval != 0)
	{
		wprintf(L"[-] %ls - IP(s) could not be enumerated\n", host);
		WSACleanup();
		return;
	}
	else
	{
#define BUFFER_SIZE 100
		size_t   i;
		char      *pMBBuffer = (char *)malloc(BUFFER_SIZE);

		for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
		{
			switch (ptr->ai_family) {
			case AF_INET:
				wprintf(L"[+] - ");
				sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
				ipbufferlength = 46;
				iRetval = WSAAddressToString(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL, ipstringbuffer, &ipbufferlength);
				if (iRetval)
					wprintf(L"WSAAddressToString failed with %u\n", WSAGetLastError());
				else
					wprintf(L"%ls\n", ipstringbuffer);

				wcstombs_s(&i, pMBBuffer, (size_t)BUFFER_SIZE,
					ipstringbuffer, (size_t)BUFFER_SIZE);
				forpsxc = fopen("ADR.txt", "ab");
				fprintf(forpsxc, "%ls\n", ipstringbuffer);
				fclose(forpsxc);


				break;

			}
		}
#ifdef __MINGW32__
		freeaddrinfo(result);
#else
		FreeAddrInfoW(result);
#endif		

		WSACleanup();
	}
}

bool SCAN::CanAccessFolder(LPCTSTR folderName, DWORD genericAccessRights)
{
	bool bRet = false;
	DWORD length = 0;
	if (!::GetFileSecurity(folderName, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
		| DACL_SECURITY_INFORMATION, NULL, NULL, &length) &&
		ERROR_INSUFFICIENT_BUFFER == ::GetLastError()) {
		PSECURITY_DESCRIPTOR security = static_cast<PSECURITY_DESCRIPTOR>(::malloc(length));
		if (security && ::GetFileSecurity(folderName, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
			| DACL_SECURITY_INFORMATION, security, length, &length)) {
			HANDLE hToken = NULL;
			if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY |
				TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken)) {
				HANDLE hImpersonatedToken = NULL;
				if (::DuplicateToken(hToken, SecurityImpersonation, &hImpersonatedToken)) {
					GENERIC_MAPPING mapping = { 0xFFFFFFFF };
					PRIVILEGE_SET privileges = { 0 };
					DWORD grantedAccess = 0, privilegesLength = sizeof(privileges);
					BOOL result = FALSE;

					mapping.GenericRead = FILE_GENERIC_READ;
					mapping.GenericWrite = FILE_GENERIC_WRITE;
					mapping.GenericExecute = FILE_GENERIC_EXECUTE;
					mapping.GenericAll = FILE_ALL_ACCESS;

					::MapGenericMask(&genericAccessRights, &mapping);
					if (::AccessCheck(security, hImpersonatedToken, genericAccessRights,
						&mapping, &privileges, &privilegesLength, &grantedAccess, &result)) {
						bRet = (result == TRUE);
					}
					::CloseHandle(hImpersonatedToken);
				}
				::CloseHandle(hToken);
			}
			::free(security);
		}
	}

	return bRet;		
	
}
