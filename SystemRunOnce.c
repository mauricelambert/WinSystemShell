//    A local privilege escalation utility that allows elevating from an
//    administrator context to the SYSTEM account on Windows to perform
//    high-privilege operations.
//    Copyright (C) 2026  WinSystemShell

//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.

//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.

//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.

// "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
// "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.50.35717\bin\HostX64\x64\CL.exe" /O2 /std:c++20 /TP SystemRunOnce.c

#define _WIN32_DCOM
#include <windows.h>
#include <taskschd.h>
#include <stdio.h>
#include <comdef.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comsupp.lib")

int wmain(int argc, wchar_t* argv[])
{
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    ITaskDefinition* pTask = NULL;
    IRegistrationInfo* pRegInfo = NULL;
    IPrincipal* pPrincipal = NULL;
    ITriggerCollection* pTriggers = NULL;
    ITrigger* pTrigger = NULL;
    ITimeTrigger* pTimeTrigger = NULL;
    IActionCollection* pActions = NULL;
    IAction* pAction = NULL;
    IExecAction* pExec = NULL;
    IRegisteredTask* pRegisteredTask = NULL;
    ITaskSettings* pSettings = NULL;

    if (argc < 4) {
        wprintf(L"Usage: %s <taskname> <taskcreator> <command> [arguments]\n", argv[0]);
        return 1;
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return 1;

    hr = CoCreateInstance(CLSID_TaskScheduler, NULL,
        CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) goto cleanup;

    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr)) goto cleanup;

    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) goto cleanup;

    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) goto cleanup;

    SYSTEMTIME st;
    FILETIME ft;
    ULARGE_INTEGER uli;

    GetLocalTime(&st);
    SystemTimeToFileTime(&st, &ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    uli.QuadPart += 3ULL * 10000000ULL;

    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;
    FileTimeToSystemTime(&ft, &st);

    wchar_t startTime[64];
    swprintf(startTime, 64,
        L"%04d-%02d-%02dT%02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    uli.QuadPart += 30ULL * 10000000ULL;

    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;
    FileTimeToSystemTime(&ft, &st);

    wchar_t endTime[64];
    swprintf(endTime, 64,
        L"%04d-%02d-%02dT%02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    pTask->get_RegistrationInfo(&pRegInfo);
    pRegInfo->put_Author(_bstr_t(argv[2]));
    pRegInfo->Release();

    pTask->get_Principal(&pPrincipal);
    pPrincipal->put_UserId(_bstr_t(L"SYSTEM"));
    pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
    pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
    pPrincipal->Release();

    pTask->get_Triggers(&pTriggers);

    pTriggers->Create(TASK_TRIGGER_TIME, &pTrigger);

    pTrigger->QueryInterface(IID_ITimeTrigger, (void**)&pTimeTrigger);
    pTimeTrigger->put_StartBoundary(_bstr_t(startTime));
    pTimeTrigger->put_EndBoundary(_bstr_t(endTime));

    pTask->get_Settings(&pSettings);
    pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
    pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
    pSettings->put_RestartCount(0);
    pSettings->put_DeleteExpiredTaskAfter(_bstr_t(L"PT1M"));
    pSettings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW);
    pSettings->Release();

    pTimeTrigger->put_StartBoundary(_bstr_t(startTime));
    pTimeTrigger->Release();
    pTrigger->Release();
    pTriggers->Release();

    pTask->get_Actions(&pActions);

    pActions->Create(TASK_ACTION_EXEC, &pAction);

    pAction->QueryInterface(IID_IExecAction, (void**)&pExec);
    pExec->put_Path(argv[3]);

    if (argc >= 5)
        pExec->put_Arguments(argv[4]);

    pExec->Release();
    pAction->Release();
    pActions->Release();

    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(argv[1]),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(L"SYSTEM"),
        _variant_t(),
        TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(L""),
        &pRegisteredTask
    );

    if (SUCCEEDED(hr))
        wprintf(L"Scheduled task created successfully (user: SYSTEM, one-shot) at %s (expire at: %s).\n", startTime, endTime);

cleanup:
    if (pRegisteredTask) pRegisteredTask->Release();
    if (pTask) pTask->Release();
    if (pRootFolder) pRootFolder->Release();
    if (pService) pService->Release();

    CoUninitialize();
    return 0;
}
