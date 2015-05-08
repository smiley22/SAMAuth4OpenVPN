/**
 * SAMAuth4OpenVPN 
 *
 * Performs authentication against local (non Active-Directory) Windows user
 * accounts.
 * 
 * Author:   Torben Könke (torben dot koenke at gmail dot com)
 * Date:     07.05.2015
 * Website:  https://www.github.com/smiley22/SAMAuth4OpenVPN

 * Remarks:
 * The SAM database (which stores local users' passwords on Windows systems) is
 * not LDAP compliant, so the LDAP provider (and as such the Auth4OpenVPN Plugin)
 * cannot be used to access it.
 *
 */
#include <Windows.h>
#include <stdio.h>
#include <LM.h>

#pragma comment(lib, "netapi32.lib")

// forward declarations.
BOOL IsMemberOfGroup(LPCWSTR lpszUsername, LPCWSTR lpszGroup);
DWORD ValidateCredentials(LPCWSTR lpszUsername, LPCWSTR lpszPassword);
void Log(LPCWSTR lpszDir, LPCWSTR fmt, ...);

/**
  * The process must return an exit code of 0 as an indication to OpenVPN that
  * the client's authentication request is to be accepted.
  */
#define EXIT_SUCCESS			0
/**
  * ...or an exit code of 1 to indicate failure and cause OpenVPN to reject the
  * client.
  */
#define EXIT_FAILURE			1
/**
  * The default name of the local group an account must be a member of in order
  * to pass authentication.
  */
#define DEFAULT_GROUPNAME		L"VPN Users"

/**
  * OpenVPN passes the credentials as a set of environment variables when it
  * invokes the program for authenticating a client.
  */
#define ENV_OPENVPN_USERNAME	L"username"
#define ENV_OPENVPN_PASSWORD	L"password"

/**
  * Determines whether log entries should be written for client authentication
  * attempts.
  */
static BOOL bLogging = FALSE;

/**
  * The entry-point of the application.
  */
int wmain(int argc, WCHAR* argv[]) {
	LPCWSTR lpszGroupName = DEFAULT_GROUPNAME;
	if (argc > 1)
		lpszGroupName = argv[1];
	BOOL bCheckGroup = lstrcmpi(L"", lpszGroupName);
	WCHAR lpszUsername[UNLEN], lpszPassword[PWLEN];
	bLogging = argc > 2 && _wcsicmp(argv[2], L"false");
	LPCWSTR lpszLogDir = L".";
	if (argc > 3) {
		lpszLogDir = argv[3];
		// Create log directory in case it doesn't exist. Note this will only
		// create the final directory in the path.
		CreateDirectory(lpszLogDir, NULL);
	}
	if (!GetEnvironmentVariable(ENV_OPENVPN_USERNAME, lpszUsername, UNLEN) ||
		!GetEnvironmentVariable(ENV_OPENVPN_PASSWORD, lpszPassword, PWLEN)) {
			Log(lpszLogDir,
				L"Could not retrieve environment variables (error code %i).",
				GetLastError());
			return EXIT_FAILURE;
	}
	int ec = EXIT_FAILURE;
	if (ValidateCredentials(lpszUsername, lpszPassword) == ERROR_SUCCESS) {
		if (!bCheckGroup || IsMemberOfGroup(lpszUsername, lpszGroupName)) {
			ec = EXIT_SUCCESS;
			Log(lpszLogDir, L"Successfully authenticated %s.", lpszUsername);
		} else {
			Log(lpszLogDir,
				L"Failed login-attempt with username = %s, password = %s." \
				L"Credentials valid but lacking required group membership.",
				lpszUsername, lpszPassword);
		}
	} else {
		Log(lpszLogDir,
			L"Failed login-attempt with username = %s, password = %s.",
			lpszUsername, lpszPassword);
	}
	return ec;
}

/**
  * Validates the specified credentials.
  *
  * @lpszUsername
  *  The name of the Windows user account to validate.
  * @lpszPassword
  *  The matching password for the Windows user account to validat.
  * @returns
  *  ERROR_SUCCESS if the specified credentials are valid; otherwise an
  *  errorcode detailing the cause of the failure.
  */
DWORD ValidateCredentials(LPCWSTR lpszUsername, LPCWSTR lpszPassword) {
	HANDLE hToken;
	LogonUser(lpszUsername, L".", lpszPassword, LOGON32_LOGON_NETWORK,
		LOGON32_PROVIDER_DEFAULT, &hToken);
	DWORD dwRet = GetLastError();
	CloseHandle(hToken);
	return dwRet;
}

/**
  * Determines whether the specified Windows account is a member of the
  * specified local group.
  *
  * @lpszUsername
  *  The name of the Windows user account.
  * @lpszGroup
  *  The name of the group.
  * @returns
  *  TRUE if the specified Windows account is a member of the specified
  *  group; otherwise FALSE.
  */
BOOL IsMemberOfGroup(LPCWSTR lpszUsername, LPCWSTR lpszGroup) {
	LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH, dwEntriesRead = 0,
		dwTotalEntries = 0;
	BOOL bRet = FALSE;
	NET_API_STATUS nStatus = NetUserGetLocalGroups(NULL, lpszUsername, 0, 0,
		(LPBYTE *) &pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries);
	if (nStatus == NERR_Success) {
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
		DWORD i, dwTotalCount = 0;
		if ((pTmpBuf = pBuf) != NULL) {
			for (i = 0; i < dwEntriesRead; i++) {
				if(!_wcsicmp(lpszGroup, pTmpBuf->lgrui0_name)) {
					bRet = TRUE;
					break;
				}
				pTmpBuf++;
				dwTotalCount++;
			}
		}
	}
	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
	return bRet;
}

/**
  * Logs the specified message to a text file.
  *
  * @lpszDir
  *  The directory in which the log file will be created.
  * @fmt
  *  The formatted string to log.
  */
void Log(LPCWSTR lpszDir, LPCWSTR fmt, ...) {
	WCHAR buf[4096], name[MAX_PATH + _MAX_FNAME];
	va_list args;
	SYSTEMTIME lt;
	if (!bLogging)
		return;
	GetLocalTime(&lt);
	va_start(args, fmt);
	vswprintf(buf, fmt, args);
	va_end(args);
	wsprintf(name, L"%s/%02d-%02d-%02d.log", lpszDir, lt.wDay, lt.wMonth,
		lt.wYear);
	HANDLE hFile = CreateFile(name, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		return;
	int len = WideCharToMultiByte(CP_UTF8, 0, buf, -1, NULL, 0, NULL, NULL);
	if (len > 0) {
		LPSTR lpszUTF8 = (LPSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
		WideCharToMultiByte(CP_UTF8, 0, buf, -1, lpszUTF8, len,
			NULL, NULL);
		DWORD dwBytesWritten;
		char timePrefix[128];
		sprintf(timePrefix, "%02d:%02d:%02d: ", lt.wHour, lt.wMinute, lt.wSecond);
		WriteFile(hFile, timePrefix, lstrlenA(timePrefix), &dwBytesWritten, NULL);
		WriteFile(hFile, lpszUTF8, lstrlenA(lpszUTF8), &dwBytesWritten, NULL);
		WriteFile(hFile, "\r\n", lstrlenA("\r\n"), &dwBytesWritten, NULL);
		HeapFree(GetProcessHeap(), 0, lpszUTF8);
	}
	CloseHandle(hFile);
}