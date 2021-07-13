// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include<Windows.h>
#include<tchar.h>
#include<urlmon.h>

#pragma comment(lib,"urlmon.lib")

#define DEF_URL  (L"http://www.gtec.ac.kr/index.do")
#define DEF_FILE_NAME (L"index.html")


HMODULE g_hMod = NULL;

DWORD WINAPI ThreadProc(LPVOID lParam)
{
    TCHAR szPath[_MAX_PATH] = { 0, };

    if (!GetModuleFileName(g_hMod, szPath, MAX_PATH))
    {
        return FALSE;
    }

    TCHAR* p = _tcsrchr(szPath, '\\');
    if (!p)
        return FALSE;

    _tcscpy_s(p + 1, _MAX_PATH, DEF_FILE_NAME);

    URLDownloadToFile(NULL, DEF_URL, szPath, 0, NULL);

    return 0;
}

BOOL WINAPI DllMain(HMODULE hinstDLL,
    DWORD  fdwReason,
    LPVOID lpReserved
)
{

    HANDLE hThread = NULL;

    g_hMod = (HMODULE)hinstDLL;

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugString(L"myhack.dll Injection");
        MessageBox(NULL, L"injection success",L"dll injection", MB_OK);
        hThread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
        if (hThread)
            CloseHandle(hThread);
        break;
    }

    return TRUE;
}

