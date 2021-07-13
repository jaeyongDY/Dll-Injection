/*
#include<stdio.h>
#include<Windows.h>
#include<tchar.h>
#include<TlHelp32.h>
#include<sal.h>

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL);


BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		_tprintf(L"OpenProcessToken error : %u \n", GetLastError());
		return FALSE;
	}
	
	if (!LookupPrivilegeValue(NULL,
		lpszPrivilege,
		&luid))
	{
		_tprintf(L"LookupPrivilegeValue error : %u \n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		_tprintf(L"AdjustTokenPrivilege error : %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		_tprintf(L"The token does not have the specified privilege \n");
		return FALSE;
	}

	return TRUE;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{

	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	//DWORD dwBufSize = lstrlen(szDllPath) + 1;
	LPTHREAD_START_ROUTINE pThreadProc;

	BOOL bSuccess = TRUE;
	HMODULE nNTDLL = NULL;


	// #1. dwPid를 이용하여 대상 프로세스 (notepad.exe)의 HANDLE을 구한다.
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf(L"OpenProcess(%d) failed	[%d] \n", dwPID, GetLastError());
		return FALSE;
	}


	// #2. 대상 프로세스(notepad.exe) 메모리에 szDllPath 크기만큼 메모리를 할당한다.
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	if(pRemoteBuf)
		// #3. 할당 받은 메모리에 myhack.dll 경로 ("c://~")를 쓴다.
		WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

	// #4. LoadLibraryW() API 주소를 구한다.
	hMod = GetModuleHandle(L"kernel32.dll");
	
	if (hMod == NULL)
	{
		OutputDebugString(_T("Error : hMod fail(NULL)"));
		return FALSE;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");


	// #5. notepad.exe 프로세스에 스레드를 실행
	hThread = CreateRemoteThread(hProcess,	// hProcess
		NULL,				// lpThreadAttributes
		0,						// dwStackSize
		pThreadProc,		// lpStartAddress
		pRemoteBuf,		// lpParameter
		0,						// dwCreationFlags
		NULL);				// lpThreadId
	
	if (hThread == NULL)
	{
		OutputDebugString(_T("Error : CreateRemoteThread fail "));
		DWORD dwError = GetLastError();


		if (dwError == 5)
		{
			OutputDebugString(L"Error : CreateRemoteThread GetLast Error 5");
			nNTDLL = LoadLibrary(L"ntdll.dll");
			if (!nNTDLL)
			{
				bSuccess = FALSE;
			}

			CLIENT_ID cid;
			pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCreateUserThread");
			if (RtlCreateUserThread)
			{
				NTSTATUS status = 0;
				status = RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf, &hThread, &cid);
				if (status && hThread != NULL)
				{
					OutputDebugString(L"success RtlCreateUserThread");
				}
				else
				{
					OutputDebugString(L"fail RtlCreateUserThread");
					bSuccess = FALSE;
				}
			}
			else {
				bSuccess = FALSE;
			}
		}
		if (dwError == 8)
		{
			OutputDebugString(L"Error : CreateRemoteThread GetLast Error 8");
			nNTDLL = LoadLibrary(L"ntdll.dll");
			if (!nNTDLL)
			{
				bSuccess = FALSE;
			}

			CLIENT_ID cid;
			pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCreateUserThread");
			if (RtlCreateUserThread)
			{
				NTSTATUS status = 0;
				status = RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf, &hThread, &cid);
				if (status && hThread != NULL)
				{
					OutputDebugString(L"success RtlCreateUserThread");
				}
				else
				{
					OutputDebugString(L"fail RtlCreateUserThread");
					bSuccess = FALSE;
				}
			}
			else {
				bSuccess = FALSE;
			}
		}
	}
	OutputDebugString(L"dll inject");

	if (hThread)
	{
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}
	CloseHandle(hProcess);

	return bSuccess;
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc != 3)
	{
		_tprintf(L"USAGE : %s <pid> <dll_path>\n", argv[0]);
		return 1;
	}

	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
		return 1;

	// injection dll
	if (InjectDll((DWORD)_tstol(argv[1]), argv[2]))
		_tprintf(L"InjectDll(\"%s\") success\n", argv[2]);
	else
		_tprintf(L"InjectDll(\"%s\") failed\n", argv[2]);

	return 0;
}
*/


#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#pragma comment(lib,"Advapi32.lib") 

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

#define NT_SUCCESS(x) ((x) >= 0)

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL);

BOOL InjectDll(UINT32 ProcessId, char* DllFullPath)
{

	if (strstr(DllFullPath, "\\\\") != 0)
	{
		printf("[!]Wrong Dll path\n");
		return FALSE;
	}

	if (strstr(DllFullPath, "\\") == 0)
	{
		printf("[!]Need Dll full path\n");
		return FALSE;
	}

	HANDLE ProcessHandle = NULL;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (ProcessHandle == NULL)
	{
		printf("[!]OpenProcess error\n");
		return FALSE;
	}

	UINT32 DllFullPathLength = (strlen(DllFullPath) + 1);
	PVOID DllFullPathBufferData = VirtualAllocEx(ProcessHandle, NULL, DllFullPathLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (DllFullPathBufferData == NULL)
	{
		CloseHandle(ProcessHandle);
		printf("[!]DllFullPathBufferData error\n");
		return FALSE;
	}
	SIZE_T ReturnLength;
	BOOL bOk = WriteProcessMemory(ProcessHandle, DllFullPathBufferData, DllFullPath, strlen(DllFullPath) + 1, &ReturnLength);

	LPTHREAD_START_ROUTINE LoadLibraryAddress = NULL;
	HMODULE Kernel32Module = GetModuleHandle(L"Kernel32");
	LoadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32Module, "LoadLibraryA");
	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL)
	{
		CloseHandle(ProcessHandle);
		printf("[!]NtCreateThreadEx error\n");
		return FALSE;
	}
	HANDLE ThreadHandle = NULL;
	NtCreateThreadEx(&ThreadHandle, 0x1FFFFF, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, DllFullPathBufferData, FALSE, NULL, NULL, NULL, NULL);
	if (ThreadHandle == NULL)
	{
		CloseHandle(ProcessHandle);
		printf("[!]ThreadHandle error\n");
		return FALSE;
	}
	if (WaitForSingleObject(ThreadHandle, INFINITE) == WAIT_FAILED)
	{
		printf("[!]WaitForSingleObject error\n");
		return FALSE;
	}
	CloseHandle(ProcessHandle);
	CloseHandle(ThreadHandle);
	return TRUE;
}


BOOL FreeDll(UINT32 ProcessId, char* DllFullPath)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot;
	HMODULE hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bSuccess = FALSE;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me)) {
		if (!_tcsicmp((LPCTSTR)me.szModule, DllFullPath) || !_tcsicmp((LPCTSTR)me.szExePath, DllFullPath))
		{
			bFound = TRUE;
			break;
		}
	}
	if (!bFound) {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	HANDLE ProcessHandle = NULL;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (ProcessHandle == NULL)
	{
		printf("[!]OpenProcess error\n");
		return FALSE;
	}

	LPTHREAD_START_ROUTINE FreeLibraryAddress = NULL;
	HMODULE Kernel32Module = GetModuleHandle(L"Kernel32");
	FreeLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32Module, "FreeLibrary");
	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL)
	{
		CloseHandle(ProcessHandle);
		printf("[!]NtCreateThreadEx error\n");
		return FALSE;
	}
	HANDLE ThreadHandle = NULL;

	NtCreateThreadEx(&ThreadHandle, 0x1FFFFF, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)FreeLibraryAddress, me.modBaseAddr, FALSE, NULL, NULL, NULL, NULL);
	if (ThreadHandle == NULL)
	{
		CloseHandle(ProcessHandle);
		printf("[!]ThreadHandle error\n");
		return FALSE;
	}
	if (WaitForSingleObject(ThreadHandle, INFINITE) == WAIT_FAILED)
	{
		printf("[!]WaitForSingleObject error\n");
		return FALSE;
	}
	CloseHandle(ProcessHandle);
	CloseHandle(ThreadHandle);
	return TRUE;
}

BOOL EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

int main(int argc, char* argv[])
{
	printf("Use NtCreateThreadEx to inject dll\n\n");
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
	}

	if (argc != 3)
	{
		printf("Usage:\n");
		printf("%s <PID> <Dll Full Path>\n", argv[0]);
		return 0;
	}
	if (!InjectDll((DWORD)atoi(argv[1]), argv[2]))
	{
		printf("[!]InjectDll error \n");
		return 1;
	}

	if (!FreeDll((DWORD)atoi(argv[1]), argv[2]))
	{
		printf("[!]FreeDll error \n");
		return 1;
	}
	printf("[+]InjectDll success\n");
	return 0;
}