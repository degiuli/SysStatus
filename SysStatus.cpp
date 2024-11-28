/*--
The MIT License (MIT)

Copyright (c) 2010-2019 De Giuli Informática Ltda. (http://www.degiuli.com.br)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
--*/

#include "SysStatus.h"
#include "USB.h"
#include "WMI.h"
#include "MonitorIPs.h"

#include <climits>
#include <sstream>

#include <aclapi.h>

#include "chrono.hpp"
#include "error_codes.hpp"
#include "final_act.hpp"
#include "log.hpp"

BOOL gbTerminate = FALSE;       //to indicate the application end has been requested
BOOL gbShutdown = FALSE;        //to indicate the system session is ending
HWND ghWnd = NULL;
HINSTANCE ghInstance = NULL;
BOOL gbForceChecking = FALSE;

char gszLogFilePrefix[1024] = {0};
uint64_t gTickStart = 0;
uint64_t _start_{};

std::vector<HANDLE> PendingThreads;

/* additional functions:
 * https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-enumsystemfirmwaretables
 * https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
 * https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexa
 * https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwaretype

 * https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexa
 * https://docs.microsoft.com/en-us/windows/win32/api/secext/nf-secext-getcomputerobjectnamea
 * https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getintegrateddisplaysize
 * https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getnativesysteminfo

 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent

 * https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumpagefilesa
 * 
 * GEO Location:
 * Enum ids: https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemgeoid
 * In the callback: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/dd317817(v=vs.85)
 *      Get the IDs https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getgeoinfoa
 *      using those types https://docs.microsoft.com/en-us/windows/win32/api/winnls/ne-winnls-sysgeotype
 */

/******************************************************************************
*
*  AUXILIARY FUNCTIONS
*
******************************************************************************/
/*
** Thread safe processing functions
*/
void _thSetInt(int *piProtectedVar, int iValue)
{
    if (!piProtectedVar)
        return;

    char sMember[100] = { 0 };
    _snprintf(sMember, sizeof(sMember) - 1, "%p", piProtectedVar);
    HANDLE hdTh = CreateMutex(NULL, FALSE, sMember);
    WaitForSingleObject(hdTh, INFINITE);

    *piProtectedVar = iValue;

    ReleaseMutex(hdTh);
    CloseHandle(hdTh);
}

int _thGetInt(int *piProtectedVar)
{
    if (!piProtectedVar)
        return 0;

    char sMember[100] = { 0 };
    _snprintf(sMember, sizeof(sMember) - 1, "%p", piProtectedVar);
    HANDLE hdTh = CreateMutex(NULL, FALSE, sMember);
    WaitForSingleObject(hdTh, INFINITE);

    int const iRetVal = *piProtectedVar;

    ReleaseMutex(hdTh);
    CloseHandle(hdTh);

    return iRetVal;
}

/*
** DebugStringToFile: save debug details in the trace file
*/
void DebugStringToFile(char *message, int typeDebug)
{
    if (typeDebug&LOG_DEBUG_ALL)
    {
        HANDLE hdTh = CreateMutex(NULL, FALSE, "SysStatus_Trace");
        WaitForSingleObject(hdTh, INFINITE);

        char line[3000] = { 0 };
        char extension[4] = { 0 };

        if (typeDebug&LOG_DEBUG)
        {
            strncpy(extension, "dbg", 3);
        }
        else if (typeDebug&LOG_DEBUG_WND)
        {
            strncpy(extension, "wnd", 3);
        }
        else if (typeDebug&LOG_DEBUG_WMI)
        {
            strncpy(extension, "wmi", 3);
        }

        SYSTEMTIME stLocalTime = { 0 };
        GetLocalTime(&stLocalTime);

        _snprintf(line, sizeof(line), "%.4d-%.2d-%.2d %.2d:%.2d:%.2d.%.3d PID %.5u %s",
            stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay, stLocalTime.wHour,
            stLocalTime.wMinute, stLocalTime.wSecond, stLocalTime.wMilliseconds,
            GetCurrentProcessId(), message);

        DWORD dwBytesWritten = 0;
        char logFile[1024] = { 0 };
        _snprintf(logFile, sizeof(logFile), "%s.%s.log", gszLogFilePrefix, extension);

        while (true)
        {
            HANDLE hTraceFile = CreateFile(logFile,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);
            if (hTraceFile != INVALID_HANDLE_VALUE)
            {
                //Set position o the end of the file
                DWORD dwFileSize = GetFileSize(hTraceFile, NULL);
                if (dwFileSize > (MBYTES * 9))
                {
                    CloseHandle(hTraceFile);
                    hTraceFile = INVALID_HANDLE_VALUE;

                    char oldFile[1024] = { 0 };
                    _snprintf(oldFile, sizeof(oldFile), "%s.%s_old", gszLogFilePrefix, extension);

                    //remove old file
                    static_cast<void>(remove((const char*)oldFile));
                    static_cast<void>(rename((const char*)logFile, (const char*)oldFile));
                }
                else
                {
                    SetFilePointer(hTraceFile, 0, NULL, FILE_END);
                    WriteFile(hTraceFile, line, static_cast<DWORD>(strlen(line)), &dwBytesWritten, NULL);
                    CloseHandle(hTraceFile);
                    break;      //exit loop
                }
            }
        }

        ReleaseMutex(hdTh);
        CloseHandle(hdTh);
    }   //END: if(bDebug)
    OutputDebugString(message);
}

/*
** Log: Trace the information
*/
void Log(int type, int id, const char*format, ...)
{
    char message[3000] = { 0 };
    char buffer[2048] = { 0 };
    va_list argptr;

    HANDLE hdTh = CreateMutex(NULL, FALSE, "SysStatus_Log");
    WaitForSingleObject(hdTh, INFINITE);

    //Format the message to be logged
    va_start(argptr, format);
    _vsnprintf(buffer, sizeof(buffer) - 1, format, argptr);
    va_end(argptr);

    //Format log string according to the type
    if (type == LOG_HEADER)
    {
        SYSTEMTIME stLocalTime = { 0 };
        GetLocalTime(&stLocalTime);

        _snprintf(message, sizeof(message), "\r\n%.4d-%.2d-%.2d %.2d:%.2d:%.2d.%.3d PID %.5lu TID %.5lu ID %.5i\r\n%s\r\n",
            stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay, stLocalTime.wHour,
            stLocalTime.wMinute, stLocalTime.wSecond, stLocalTime.wMilliseconds,
            GetCurrentProcessId(), GetCurrentThreadId(), id, buffer);
    }
    if (type == LOG_MESSAGE)
    {
        _snprintf(message, sizeof(message), "\t%s\r\n", buffer);
    }

    //if not debug, trace in the file
    if (!(type&LOG_DEBUG_ALL))
    {
        DWORD dwBytesWritten = 0;
        char logFile[1024] = { 0 };
        _snprintf(logFile, sizeof(logFile), "%s.log", gszLogFilePrefix);
        HANDLE hTraceFile = CreateFile(logFile,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hTraceFile != INVALID_HANDLE_VALUE)
        {
            //Set position o the end of the file
            SetFilePointer(hTraceFile, 0, NULL, FILE_END);
            WriteFile(hTraceFile, message, static_cast<DWORD>(strlen(message)), &dwBytesWritten, NULL);
            CloseHandle(hTraceFile);
        }
    }
    _snprintf(message, sizeof(message), "TID %.5lu ID %.5i %s\r\n", GetCurrentThreadId(), id, buffer);

    ReleaseMutex(hdTh);
    CloseHandle(hdTh);

    //Trace on debug view
    DebugStringToFile(message, LOG_DEBUG);
}

/*
** CheckLogFileSize: Check the log file size and create backups when limit is reached
*/
void CheckLogFileSize(DWORD dwMaxSize)
{
    HANDLE hTraceFile = NULL;
    DWORD dwFileSize = 0;

    Log(LOG_DEBUG, __LINE__, ">> ChkLogFileSz, %u", dwMaxSize);

    HANDLE hdTh = CreateMutex(NULL, FALSE, "SysStatus_Log");
    WaitForSingleObject(hdTh, INFINITE);

    if (dwMaxSize > 0)
    {
        char logFile[1024] = { 0 };
        _snprintf(logFile, sizeof(logFile), "%s.log", gszLogFilePrefix);

        Log(LOG_DEBUG, __LINE__, "-- ChkLogFileSz, Opng %s", logFile);
        hTraceFile = CreateFile(logFile,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hTraceFile != INVALID_HANDLE_VALUE)
        {
            //Set position o the end of the file
            SetFilePointer(hTraceFile, 0, NULL, FILE_END);
            dwFileSize = GetFileSize(hTraceFile, NULL);
            Log(LOG_DEBUG, __LINE__, "-- ChkLogFileSz, %s Sz %u", logFile, dwFileSize);
            CloseHandle(hTraceFile);
            hTraceFile = NULL;
        }
    }

    //check whether the file size reached the limit
    //or it is initialization - to start new run in new file
    if (dwFileSize > dwMaxSize || dwMaxSize == 0)
    {
        //find the last file
        int x;
        for (x = 999; x >= 0; x--)
        {
            char temp[_MAX_PATH] = { 0 };
            _snprintf(temp, sizeof(temp), "%s.%.3d.log", gszLogFilePrefix, x);
            Log(LOG_DEBUG, __LINE__, "-- ChkLogFileSz, Trying opng %s", temp);
            hTraceFile = CreateFile(temp, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL);
            if (hTraceFile != INVALID_HANDLE_VALUE)
            {
                Log(LOG_DEBUG, __LINE__, "-- ChkLogFileSz, Last file fnd: %s", temp);
                CloseHandle(hTraceFile);
                hTraceFile = NULL;

                //all file were filled, removed the last one
                if (x == 999) {
                    Log(LOG_DEBUG, __LINE__, "-- ChkLogFileSz, Removing %s - oldest file", temp);
                    remove((char*)temp);
                }

                break;      //last one was found
            }
        }

        //rename the last one to the previous
        char newFile[_MAX_PATH] = { 0 };
        char oldFile[_MAX_PATH] = { 0 };
        for (; x >= 0; x--)
        {
            //rename the <.xxx.log> to .<xxx+1.log>
            _snprintf(newFile, sizeof(newFile), "%s.%.3d.log", gszLogFilePrefix, x + 1);
            _snprintf(oldFile, sizeof(oldFile), "%s.%.3d.log", gszLogFilePrefix, x);

            Log(LOG_DEBUG, __LINE__, "-- ChkLogFileSz, Renaming %s -> %s", oldFile, newFile);
            static_cast<void>(rename((const char*)oldFile, (const char*)newFile));
        }

        //rename the .log to .000.log
        _snprintf(newFile, sizeof(newFile), "%s.000.log", gszLogFilePrefix);
        _snprintf(oldFile, sizeof(oldFile), "%s.log", gszLogFilePrefix);
        Log(LOG_DEBUG, __LINE__, "-- ChkLogFileSz, Remaining %s -> %s", oldFile, newFile);
        static_cast<void>(rename((const char*)oldFile, (const char*)newFile));
    }

    ReleaseMutex(hdTh);
    CloseHandle(hdTh);
    Log(LOG_DEBUG, __LINE__, "<< ChkLogFileSz");
}

/*
** USBTraceInfo: Trace USB device information
*/
void USBTraceInfo(PCHAR StartString, PCHAR DeviceInterfaceName)
{
    PCHAR   pVendorID = nullptr;
    PCHAR   pProductID = nullptr;
    PCHAR   pSerial = nullptr;
    PCHAR   pTmp = nullptr;

    PCHAR pName = (PCHAR)malloc(strlen(DeviceInterfaceName) + 1);
    if (pName)
    {
        memset(pName, 0x00, (strlen(DeviceInterfaceName) + 1));
        strcpy(pName, DeviceInterfaceName);

        // Get Vid value
        pVendorID = strchr(pName, 'V');
        if (pVendorID)
        {
            pVendorID += 4;

            // Get Pid value
            pProductID = strchr(pVendorID, 'P');
            if (pProductID)
            {
                pProductID += 4;
                pTmp = pVendorID + 4;
                *pTmp = 0;

                //Get SerialId value
                pSerial = strchr(pProductID, '#');
                if (pSerial)
                {
                    *pSerial = 0;
                    pTmp = ++pSerial;
                    while ((*pTmp) && (*pTmp != '#'))
                        pTmp++;
                    *pTmp = 0;
                }
            }

            uint64_t const vendorId = static_cast<uint64_t const>(std::stoul(std::string(pVendorID, 4), nullptr, 16));
            Log(LOG_MESSAGE, __LINE__, "%s [VID:%s PID:%s SN:%s] %s", StartString, pVendorID, pProductID, pSerial, USB::GetVendorString(vendorId).c_str());
        }
        free(pName);
    }
    else
    {
        Log(LOG_DEBUG, __LINE__, "-- New DeviceName nullptr");
    }
}

/*
** GUID2Str: Convert GUID structure to LPSTR pointer
** -> {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
*/
std::string GUID2Str(GUID const &guid)
{
    char szGuid[_MAX_PATH]{};

    //{xxxxxxxx-
    uint8_t* data = (uint8_t*)&guid.Data1;
    _snprintf(szGuid, sizeof(szGuid), "{%.2X%.2X%.2X%.2X-", data[3], data[2], data[1], data[0]);

    //xxxx-
    data = (uint8_t*)&guid.Data2;
    _snprintf(szGuid, sizeof(szGuid), "%s%.2X%.2X-", szGuid, data[1], data[0]);

    //xxxx-
    data = (uint8_t*)&guid.Data3;
    _snprintf(szGuid, sizeof(szGuid), "%s%.2X%.2X-", szGuid, data[1], data[0]);

    //xxxx-
    _snprintf(szGuid, sizeof(szGuid), "%s%.2X%.2X-", szGuid, guid.Data4[0], guid.Data4[1]);

    //xxxxxxxxxxxx}
    size_t size = strlen(szGuid);
    for (int i = 2; i < 8; i++)
    {
        _snprintf(&szGuid[size], sizeof(szGuid) - size, "%.2X", guid.Data4[i]);
        size += 2;
    }
    szGuid[size++] = '}';

    return std::string(szGuid);
}

/*
** parseNullTerminatedStrings:  Parse list of null terminated strings, which ends with double-null
*/
std::vector<std::string> parseNullTerminatedStrings(char const* input)
{
    std::vector<std::string> stringsList;
    int nullCount = 0, possibleStringInit = 0;
    char *p = nullptr;

    for (int i = 0; nullCount < 2; i++)
    {
        if (input[i] == 0)
        {
            nullCount++;
            possibleStringInit = i + 1;
            if (p != nullptr)
            {
                std::string aux(p);
                //result.push_back(aux);
                stringsList.push_back(aux);
            }
            p = nullptr;
            continue;
        }

        if (p == nullptr)
        {
            nullCount = 0;
            p = const_cast<char*>(&input[possibleStringInit]);
        }
    }
    return stringsList;
}

/*
** ReportAttemptsToSetUnhandledExceptionFilter
*/
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI ReportAttemptsToSetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
    Log(LOG_DEBUG, __LINE__, "-- Prevented attempt to set unhandled exception filter. lpTopLevelExceptionFilter: 0x%p", lpTopLevelExceptionFilter);
    return nullptr;
}

/*
** RedirectSetUnhandledExceptionFilter
*/
BOOL RedirectSetUnhandledExceptionFilter()
{
    HMODULE hKernel32 = LoadLibrary("kernel32.dll");
    if (hKernel32 == nullptr)
        return FALSE;

    void *pOriginalFunc = GetProcAddress(hKernel32, "SetUnhandledExceptionFilter");
    if (pOriginalFunc == nullptr)
    {
        FreeLibrary(hKernel32);
        return FALSE;
    }

    DWORD dwOriginalAddr = (DWORD)pOriginalFunc;
    dwOriginalAddr += 5; // add 5 for 5 op-codes for jmp far

    void *pDecoyFunc = &ReportAttemptsToSetUnhandledExceptionFilter;
    DWORD dwDecoyAddr = (DWORD)pDecoyFunc;
    DWORD dwRelativeAddr = dwDecoyAddr - dwOriginalAddr;

    unsigned char jump[100];
    jump[0] = 0xE9;  // JMP absolute
    memcpy(&jump[1], &dwRelativeAddr, sizeof(pDecoyFunc));
    SIZE_T bytesWritten;

    BOOL bRet = WriteProcessMemory(GetCurrentProcess(), pOriginalFunc, jump, sizeof(pDecoyFunc) + 1, &bytesWritten);

    FreeLibrary(hKernel32);
    return bRet;
}

/*
** CreateMiniDump: Create minidump file on exception
*/
void CreateMiniDump(LPEXCEPTION_POINTERS pExceptionInfo)
{
    char chFileName[MAX_PATH] = { 0 };
    SYSTEMTIME stLocalTime = { 0 };
    GetLocalTime(&stLocalTime);

    uint64_t const _end_ = static_cast<uint64_t const>(std::chrono::steady_clock::now().time_since_epoch().count());
    _snprintf(chFileName, sizeof(chFileName) - 1, "%s_%.5lu_%5lu_%.4d-%.2d-%.2d_%.2d-%.2d-%.2d_%llu.dmp", gszLogFilePrefix,
        GetCurrentProcessId(), GetCurrentThreadId(),
        stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay,
        stLocalTime.wHour, stLocalTime.wMinute, stLocalTime.wSecond,
        _end_);

    // Create the file first.
    HANDLE hFile = CreateFile(chFileName, GENERIC_READ | GENERIC_WRITE,
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        MINIDUMP_EXCEPTION_INFORMATION stMDEI = { 0 };
        MINIDUMP_EXCEPTION_INFORMATION * pMDEI = nullptr;

        if (pExceptionInfo != nullptr)
        {
            stMDEI.ThreadId = GetCurrentThreadId();
            stMDEI.ExceptionPointers = pExceptionInfo;
            stMDEI.ClientPointers = TRUE;
            pMDEI = &stMDEI;
        }

        // Got the file open.  Write it.
        BOOL bRet = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
            hFile, MiniDumpWithPrivateReadWriteMemory, pMDEI, NULL, NULL);

        if (TRUE == bRet)
        {
            Log(LOG_HEADER, __LINE__, "CreateMiniDump, Created MiniDump file located at %s", chFileName);
        }
        else
        {
            Log(LOG_HEADER, __LINE__, "CreateMiniDump, Failed to create MiniDump file. %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        }

        // Close the open file.
        CloseHandle(hFile);
    }
}

/*
** AppUnhandledExceptionFilter: Exception handle filter
*/
LONG WINAPI AppUnhandledExceptionFilter(LPEXCEPTION_POINTERS pExceptionInfo)
{
    auto _run_time_ = gsl::finally([] {
        uint64_t const _end_ = static_cast<uint64_t const>(dgi::get_tick_epoch_count()) - _start_;
        Log(LOG_MESSAGE, __LINE__, "%.9f s", (static_cast<double>(_end_) / 1'000'000'000));
    });

    Log(LOG_HEADER, __LINE__, "AppUnhndldExcptFltr, Attempt to create MiniDump file before exit proc due to unhndld exception.");
    CreateMiniDump(pExceptionInfo);

    exit(static_cast<int>(ERROR_UNHANDLED_EXCEPTION));
}

/*
** WideStrToMultiStr: convert string from Unicode to ASCII
*/
PCHAR WideStrToMultiStr(PWCHAR WideStr)
{
    ULONG nBytes;
    PCHAR MultiStr;

    // Get the length of the converted string
    //
    nBytes = WideCharToMultiByte(
        CP_ACP,
        0,
        WideStr,
        -1,
        NULL,
        0,
        NULL,
        NULL);

    if (nBytes == 0)
    {
        return NULL;
    }

    // Allocate space to hold the converted string
    //
    MultiStr = (char *)malloc(nBytes);
    if (MultiStr)
    {
        // Convert the string
        //
        nBytes = WideCharToMultiByte(
            CP_ACP,
            0,
            WideStr,
            -1,
            MultiStr,
            nBytes,
            NULL,
            NULL);

        if (nBytes == 0)
        {
            free(MultiStr);
            MultiStr = NULL;
        }
    }
    return MultiStr;
}

/*
** GetWinVer: get version of the running Windows system
*/
DWORD GetWinVer()
{
    OSVERSIONINFOEX osvEx = { 0 };
    osvEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    if (VerifyVersionInfo(&osvEx, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, 0))
    {
        return osvEx.dwMajorVersion;
    }
    else
    {
        OSVERSIONINFO osver = { 0 };
        osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx(&osver);
        return osver.dwMajorVersion;
    }
}

/*
** SysTick
*/
uint64_t SysTick()
{
    auto const nanosecs = dgi::get_tick_epoch_count();
    return static_cast<uint64_t>((static_cast<double>(nanosecs) / 1'000'000) + 0.5);
}

/*
** CalcElapsedTime
*/
void CalcElapsedTime(uint64_t const tickStart, uint64_t& tickEnd, double& timeElapsed, uint64_t& seconds)
{
    tickEnd = SysTick();
    timeElapsed = (static_cast<double>(tickEnd - tickStart) / static_cast<double>(SECOND));
    seconds = static_cast<uint64_t>(timeElapsed + 0.5);
}

/*
** LogElapsedTime
*/
void LogElapsedTime(unsigned long const line, uint64_t const tickStart, char const* lpszAdditionalMsg)
{
    uint64_t tickEnd{};
    double timeElapsed{};
    uint64_t seconds{};
    CalcElapsedTime(tickStart, tickEnd, timeElapsed, seconds);
    if (lpszAdditionalMsg)
    {
        Log(LOG_HEADER, line, "%s, %02llu:%02llu:%02llu, %.3f s", lpszAdditionalMsg, seconds / 3600, (seconds % 3600) / 60, seconds % 60, timeElapsed);
    }
    else
    {
        Log(LOG_MESSAGE, line, "%02llu:%02llu:%02llu, %.3f s", seconds / 3600, (seconds % 3600) / 60, seconds % 60, timeElapsed);
    }
}

/*
** SetThreadName
*/
#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
    DWORD dwType; // Must be 0x1000.
    LPCSTR szName; // Pointer to name (in user addr space).
    DWORD dwThreadID; // Thread ID (-1=caller thread).
    DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

#define MS_VC_EXCEPTION     ((DWORD)0x406D1388)

void SetThreadName(char const* threadName, DWORD dwThreadID)
{
    THREADNAME_INFO info = { 0 };
    info.dwType = 0x1000;
    info.szName = threadName;
    info.dwThreadID = dwThreadID;
    info.dwFlags = 0;

    Log(LOG_DEBUG, __LINE__, "-- SetThrdName, Tp %p, Name %s, Id %u, Flags %p", info.dwType, info.szName, info.dwThreadID, info.dwFlags);

    __try
    {
        RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

/*
** StartThread: Used to start any processing thread
*/
bool StartThread(std::string const& threadName, unsigned(__stdcall *threadFunction)(void*), void *threadData, DWORD threadTimeout, HANDLE *pthreadHandle)
{
    unsigned int uiThreadId = 0;
    HANDLE hThread = NULL;
    bool ret = true;

    Log(LOG_DEBUG, __LINE__, ">> StartThrd, Name %s, Func %p, Dat %p, Timeout %u, pHndl %p", threadName.c_str(), threadFunction, threadData, threadTimeout, pthreadHandle);

    /* Logical Drivers */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        hThread = (HANDLE)_beginthreadex(NULL, 0, threadFunction, threadData, 0, &uiThreadId);
        if (hThread != NULL)
        {
            Log(LOG_DEBUG, __LINE__, "-- StartThrd, %s Id %u, Hnd %p", threadName.c_str(), uiThreadId, hThread);
            SetThreadName(threadName.c_str(), uiThreadId);

            //Wait thread
            if (threadTimeout > 0)
            {
				auto const wait_ret = WaitForSingleObject(hThread, threadTimeout);
                if (wait_ret != WAIT_OBJECT_0)
                {
					Log(LOG_HEADER, __LINE__, "-- StartThrd, %s Wait err %lu. Adding to Pending.", threadName.c_str(), wait_ret);
                    PendingThreads.push_back(hThread);
                }
            }
        }
        else
        {
            Log(LOG_HEADER, __LINE__, "-- StartThrd, No %s thrd created", threadName.c_str());
            ret = false;
        }
    }

    if (ret)
    {
        //Set output if it is not null
        char msg[_MAX_PATH] = { 0 };
        if (pthreadHandle)
        {
            *pthreadHandle = hThread;
            _snprintf(msg, sizeof(msg) - 1, "<< StartThrd, %p", *pthreadHandle);
        }
        else
        {
            //Close the thread handle
            CloseHandle(hThread);
            hThread = NULL;
            strcpy(msg, "<< StartThrd, ret True");
        }
        Log(LOG_DEBUG, __LINE__, msg);
    }
    else
    {
        Log(LOG_DEBUG, __LINE__, "<< StartThrd, ret False");
    }
    return ret;
}

/*
** EndPendingThread: used to release memmory stack and terminate a pending thread
*/
void EndPendingThread(HANDLE hThread)
{
    Log(LOG_DEBUG, __LINE__, ">> EndPendgThrd, Hndl %p", hThread);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    //Release thread stack

    if (GetWinVer() < 6)   //WinXP or older
    {
        //Used to release the thread stacker
        typedef VOID(WINAPI *PRtlFreeUserThreadStack)(HANDLE hProcess, HANDLE hThread);
        PRtlFreeUserThreadStack RtlFreeUserThreadStack = NULL;

        HMODULE NTLibrary = GetModuleHandleW(L"ntdll.dll");
        if (NTLibrary)
        {
            RtlFreeUserThreadStack = (PRtlFreeUserThreadStack)GetProcAddress(NTLibrary, "RtlFreeUserThreadStack");
        }

        //Release thread stacker
        if (RtlFreeUserThreadStack != NULL)
            RtlFreeUserThreadStack(GetCurrentProcess(), hThread);

        if (NTLibrary)
        {
            FreeLibrary(NTLibrary);
            NTLibrary = NULL;
        }
    }

    TerminateThread(hThread, exitCode);
    Log(LOG_DEBUG, __LINE__, "<< EndPendgThrd");
}

char const* PowerManagementEvent(size_t const type)
{
    switch (type)
    {
    case PBT_APMPOWERSTATUSCHANGE:  return "Power Status Change";
    case PBT_APMRESUMEAUTOMATIC:    return "Resume Automatic";
    case PBT_APMRESUMESUSPEND:      return "Resume Suspend";
    case PBT_APMSUSPEND:            return "Suspend";
    case PBT_POWERSETTINGCHANGE:    return "Power Settings Change";
    default:                        return "Unknwon";
    }
}

/*
** WndProcMessage: message window proceduce
*/
LRESULT WINAPI WndProcMessage(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    POINTS lPoints = { 0 };
    int iRet = 0;

    Log(LOG_DEBUG_WND, __LINE__, "-- WndProcMsg, Wnd %p, Msg 0x%.4X, WPrm 0x%.8X HI 0x%.4X LO 0x%.4X, LPrm 0x%.8X HI 0x%.4X LO 0x%.4X", hWnd, uMsg, wParam, HIWORD(wParam), LOWORD(wParam), lParam, HIWORD(lParam), LOWORD(lParam));

    switch (uMsg)
    {
    case WM_QUERYENDSESSION:    //session closure requested
        Log(LOG_HEADER, __LINE__, "Session Closure Requested");
        _thSetInt(&gbTerminate, TRUE);
        _thSetInt(&gbShutdown, TRUE);
        return (LRESULT)(DefWindowProc(hWnd, uMsg, wParam, lParam));
        break;

    case WM_ENDSESSION:         //session is ending
        Log(LOG_HEADER, __LINE__, "End Session");
        LogElapsedTime(__LINE__, gTickStart, "SysStatus");
        return (LRESULT)(DefWindowProc(hWnd, uMsg, wParam, lParam));
        break;

    case WM_DISPLAYCHANGE:
        Log(LOG_HEADER, __LINE__, "DisplayChange: %zu bits per pixel, Res %ux%u", size_t(wParam), LOWORD(lParam), HIWORD(lParam));
        return (LRESULT)(DefWindowProc(hWnd, uMsg, wParam, lParam));
        break;

    case WM_POWERBROADCAST:
        Log(LOG_HEADER, __LINE__, "Power Management: 0x%lX(%s)", size_t(wParam), PowerManagementEvent(static_cast<size_t const>(wParam)));
        if (wParam == PBT_POWERSETTINGCHANGE && lParam != NULL)
        {
            PPOWERBROADCAST_SETTING settings = reinterpret_cast<PPOWERBROADCAST_SETTING>(lParam);
            Log(LOG_MESSAGE, __LINE__, "   GUID %s, Data (%lu)%p", GUID2Str(settings->PowerSetting).c_str(), settings->DataLength, settings->Data);
        }
        return (LRESULT)(DefWindowProc(hWnd, uMsg, wParam, lParam));
        break;

    case WM_DEVICECHANGE:
        _thSetInt(&gbForceChecking, TRUE);

        switch (wParam)
        {
        case DBT_USERDEFINED:
            //device event identifies a user-defined event
        {
            _DEV_BROADCAST_USERDEFINED * pDevBcastUserDefined = (_DEV_BROADCAST_USERDEFINED *)lParam;
            if (!pDevBcastUserDefined)
                break;

            Log(LOG_HEADER, __LINE__, "User Defined %s, Size %u, DevType %u", pDevBcastUserDefined->dbud_szName, pDevBcastUserDefined->dbud_dbh.dbch_size, pDevBcastUserDefined->dbud_dbh.dbch_devicetype);
        }
        break;

        case DBT_DEVICEARRIVAL:
        case DBT_DEVICEQUERYREMOVE:
        case DBT_DEVICEQUERYREMOVEFAILED:
        case DBT_DEVICEREMOVEPENDING:
        case DBT_DEVICEREMOVECOMPLETE:
        {
            PDEV_BROADCAST_HDR pDevBcastHdr = (PDEV_BROADCAST_HDR)lParam;
            if (!pDevBcastHdr)
                break;
            
            std::string type{ "???" };
            switch (wParam)
            {
            case DBT_DEVICEARRIVAL:
                type = R"("Arrived")";
                break;
            case DBT_DEVICEQUERYREMOVE:
                type = R"("Removal Request")";
                break;
            case DBT_DEVICEQUERYREMOVEFAILED:
                type = R"("Removal Aborted")";
                break;
            case DBT_DEVICEREMOVEPENDING:
                type = R"("Removal Pending")";
                break;
            case DBT_DEVICEREMOVECOMPLETE:
                type = R"("Removed")";
                break;
            }
            Log(LOG_HEADER, __LINE__, "Device %s, Size %u, DevType %u", type.c_str(), pDevBcastHdr->dbch_size, pDevBcastHdr->dbch_devicetype);
            if (pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
            {
                PDEV_BROADCAST_DEVICEINTERFACE pDevBcastDevIface = (PDEV_BROADCAST_DEVICEINTERFACE)lParam;
                Log(LOG_MESSAGE, __LINE__, "Usb CHANGE Dev <%s GUID %s>", (LPBYTE)pDevBcastDevIface->dbcc_name, GUID2Str(pDevBcastDevIface->dbcc_classguid).c_str());

                if (wParam == DBT_DEVICEARRIVAL)
                    USBTraceInfo("USB ARRIVAL", (PCHAR)pDevBcastDevIface->dbcc_name);
                else
                    USBTraceInfo("USB  REMOVE", (PCHAR)pDevBcastDevIface->dbcc_name);
            }
            else if (pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_VOLUME)
            {
                PDEV_BROADCAST_VOLUME pDevBcastVolume = (PDEV_BROADCAST_VOLUME)lParam;
                Log(LOG_MESSAGE, __LINE__, "Volume CHANGE <Flags %p, UnitMask %p>", pDevBcastVolume->dbcv_flags, pDevBcastVolume->dbcv_unitmask);
            }
            else if (pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_OEM)
            {
                PDEV_BROADCAST_OEM pDevBcastOem = (PDEV_BROADCAST_OEM)lParam;
                Log(LOG_MESSAGE, __LINE__, "Oem CHANGE <Id %p, SuppFunc %p>", pDevBcastOem->dbco_identifier, pDevBcastOem->dbco_suppfunc);
            }
            else if (pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_DEVNODE)
            {
                PDEV_BROADCAST_DEVNODE pDevBcastDevNode = (PDEV_BROADCAST_DEVNODE)lParam;
                Log(LOG_MESSAGE, __LINE__, "DevNode CHANGE <%p>", pDevBcastDevNode->dbcd_devnode);
            }
            else if (pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_PORT)
            {
                PDEV_BROADCAST_PORT pDevBcastPort = (PDEV_BROADCAST_PORT)lParam;
                Log(LOG_MESSAGE, __LINE__, "Port CHANGE <%s>", (LPBYTE)pDevBcastPort->dbcp_name);
            }
            else if (pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_NET)
            {
                PDEV_BROADCAST_NET pDevBcastNet = (PDEV_BROADCAST_NET)lParam;
                Log(LOG_MESSAGE, __LINE__, "Net CHANGE <Resource 0x%X, Flags 0x%X>", (LPBYTE)pDevBcastNet->dbcn_resource, pDevBcastNet->dbcn_flags);
            }
            else if (pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_HANDLE)
            {
                PDEV_BROADCAST_HANDLE pDevBcastHandle = (PDEV_BROADCAST_HANDLE)lParam;
                Log(LOG_MESSAGE, __LINE__, "Handle CHANGE <Handle %p, NameOffset %d, Name %s, DevNotify %p, EvntGUID %s>", pDevBcastHandle->dbch_handle, pDevBcastHandle->dbch_nameoffset, (LPBYTE)pDevBcastHandle->dbch_data, pDevBcastHandle->dbch_hdevnotify, GUID2Str(pDevBcastHandle->dbch_eventguid).c_str());
            }
        }
        break;
        }
        break;

    case WM_MOUSEMOVE:
        //if mouse is moved in the window square, control key is pressed
        //ask whether or not it should be stopped;
        //if so, set terminate flag to stop loop processing
        if (wParam == MK_CONTROL)
        {
            lPoints = MAKEPOINTS(lParam);
            if (lPoints.x <= 20 && lPoints.y <= 20)
            {
                iRet = MessageBox(hWnd, "Would you like to close this application?", "SysStatus", MB_YESNO | MB_ICONQUESTION | MB_SYSTEMMODAL);
                if (iRet == IDYES)
                {
                    Log(LOG_HEADER, __LINE__, "Exit Requested");
                    _thSetInt(&gbTerminate, TRUE);
                }
            }
        }
        //if mouse is moved in the window square, shift key is pressed
        //ask whether or not it should be quickly stopped;
        //if so, set terminate and shutdown flags to stop loop 
        //processing as it would do during a end session
        //(shutdown, logoff, restart)
        else if (wParam == MK_SHIFT)
        {
            lPoints = MAKEPOINTS(lParam);
            if (lPoints.x <= 20 && lPoints.y <= 20)
            {
                iRet = MessageBox(hWnd, "Would you like to quickly close this application?", "SysStatus", MB_YESNO | MB_ICONQUESTION | MB_SYSTEMMODAL);
                if (iRet == IDYES)
                {
                    Log(LOG_HEADER, __LINE__, "Quick Exit Requested");
                    _thSetInt(&gbTerminate, TRUE);
                    _thSetInt(&gbShutdown, TRUE);
                }
            }
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_QUIT:
        break;

    default:
        return (LRESULT)(DefWindowProc(hWnd, uMsg, wParam, lParam));
    }
    return 0;
}

/*
** ThreadMessage:   Thread function for the window messages
*/
unsigned WINAPI ThreadMessage(LPVOID input)
{
    bool *pbShowWindow = (bool*)input;
    bool bShowWindow = (pbShowWindow ? *pbShowWindow : true);

    MSG msg{};

    Log(LOG_DEBUG, __LINE__, ">> ThrdMsg");

    //Create application instance
    WNDCLASS  WindowClass = { 0 };

    WindowClass.style = CS_HREDRAW | CS_VREDRAW;
    WindowClass.lpfnWndProc = (WNDPROC)WndProcMessage;
    WindowClass.cbClsExtra = 0;
    WindowClass.cbWndExtra = 0;
    WindowClass.hInstance = ghInstance;
    WindowClass.hIcon = (HICON)NULL;
    WindowClass.hCursor = (HCURSOR)NULL;
    WindowClass.hbrBackground = (HBRUSH)NULL;
    WindowClass.lpszMenuName = (LPCTSTR)NULL;
    WindowClass.lpszClassName = "SysStatusWClass";

    //Register window
    if (!RegisterClass(&WindowClass))
    {
        Log(LOG_HEADER, __LINE__, "<< ThrdMsg, RegCls %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        _endthreadex(static_cast<unsigned>(-1));
        return static_cast<unsigned>(-1);
    }

    RECT wndSize{ 0, 0, 25, 25 };
    MONITORINFO monitorInfo{ sizeof(MONITORINFO), {0,0,0,0}, {0,0,0,0}, 0 };
    if (GetMonitorInfo(MonitorFromWindow(FindWindow("Shell_TrayWnd", nullptr), MONITOR_DEFAULTTOPRIMARY), &monitorInfo))
    {
        Log(LOG_DEBUG, __LINE__, "-- ThrdMsg, Monitor (%li, %li, %li, %li), Work (%li, %li, %li, %li), Flag %lXh",
            monitorInfo.rcMonitor.left, monitorInfo.rcMonitor.top, monitorInfo.rcMonitor.right, monitorInfo.rcMonitor.bottom,
            monitorInfo.rcWork.left, monitorInfo.rcWork.top, monitorInfo.rcWork.right, monitorInfo.rcWork.bottom, monitorInfo.dwFlags);

        wndSize.left = (monitorInfo.rcWork.left + monitorInfo.rcMonitor.left);
        wndSize.top = (monitorInfo.rcWork.top + monitorInfo.rcMonitor.top);
    }
    else
    {
        Log(LOG_DEBUG, __LINE__, "-- ThrdMsg, GetMonitorInfo(Tray) %s", dgi::win_error_code_to_str(GetLastError()).c_str());
    }

    //Create window
    if (bShowWindow)
    {
        Log(LOG_DEBUG, __LINE__, "-- ThrdMsg, WndSize (%li, %li, %li, %li)", wndSize.left, wndSize.top, wndSize.right, wndSize.bottom);
    }

    ghWnd = CreateWindowEx((bShowWindow ? WS_EX_DLGMODALFRAME : 0),
        (LPCSTR)"SysStatusWClass", (LPCSTR)"SysStatus",
        (bShowWindow ? WS_BORDER | WS_POPUP : 0),
        wndSize.left, wndSize.top, wndSize.right, wndSize.bottom,
        (HWND)NULL, (HMENU)NULL,
        ghInstance, (LPVOID)NULL);

    if (ghWnd == NULL || IsWindow(ghWnd) == FALSE)
    {
        Log(LOG_HEADER, __LINE__, "<< ThrdMsg, CreateWnd %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        _endthreadex(static_cast<unsigned>(-1));
        return static_cast<unsigned>(-1);
    }

    //show the window application
    if (bShowWindow)
    {
        ShowWindow(ghWnd, SW_SHOW);
        Sleep(MILLISECOND * 50UL);
    }

    //Register to receive notification when a USB device or hub is plugged in
    HDEVNOTIFY hNotifyDevHandle = nullptr;
    HDEVNOTIFY hNotifyHubHandle = nullptr;
    DEV_BROADCAST_DEVICEINTERFACE broadcastInterface{};

    ZeroMemory(&broadcastInterface, sizeof(broadcastInterface));
    broadcastInterface.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
    broadcastInterface.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;

    //Register for Device nofitications
    memcpy(&(broadcastInterface.dbcc_classguid), &(GUID_CLASS_USB_DEVICE), sizeof(struct _GUID));
    hNotifyDevHandle = RegisterDeviceNotification(ghWnd, &broadcastInterface, DEVICE_NOTIFY_WINDOW_HANDLE);

    //Register for Hub notifications
    memcpy(&(broadcastInterface.dbcc_classguid), &(GUID_CLASS_USBHUB), sizeof(struct _GUID));
    hNotifyHubHandle = RegisterDeviceNotification(ghWnd, &broadcastInterface, DEVICE_NOTIFY_WINDOW_HANDLE);

    //Register to receive notification when a network component is changed
    HDEVNOTIFY hNotifyNetHandle = NULL;
    DEV_BROADCAST_NET broadcastNet;

    ZeroMemory(&broadcastNet, sizeof(broadcastNet));
    broadcastNet.dbcn_size = sizeof(DEV_BROADCAST_NET);
    broadcastNet.dbcn_devicetype = DBT_DEVTYP_NET;

    //Register for network notifications
    hNotifyNetHandle = RegisterDeviceNotification(ghWnd, &broadcastNet, DEVICE_NOTIFY_WINDOW_HANDLE);

    //Message loop
    while (GetMessage(&msg, ghWnd, 0, 0))
    {
        if (msg.message == TERMINATE_WINDOW_MSG)
        {
            break;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    //Unregister notifications
    UnregisterDeviceNotification(hNotifyDevHandle);
    UnregisterDeviceNotification(hNotifyHubHandle);
    UnregisterDeviceNotification(hNotifyNetHandle);

    DestroyWindow(ghWnd);
    Log(LOG_DEBUG, __LINE__, "<< ThrdMsg");
    _endthreadex(0);
    return 0;
}

/******************************************************************************
*
*  STATUS FUNCTIONS
*
******************************************************************************/
/*
** Enumerate USBs
*/
unsigned WINAPI ThreadUSB(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> ThrdUSB (%p)", lpData);

    USB * pUsb = new USB();
    if (!pUsb)
    {
        Log(LOG_DEBUG, __LINE__, "<< ThrdUSB, New USB class null");
        _endthreadex(ERROR_OUTOFMEMORY);
        return ERROR_OUTOFMEMORY;
    }

    pUsb->EnumerateUSB();
    pUsb->USBDevicesDetails();

    delete pUsb;
    pUsb = NULL;

    Log(LOG_DEBUG, __LINE__, "<< ThrdUSB");
    _endthreadex(0);
    return 0;
}

/*
** ProcessInfo: Function that collects and traces processes running in the system.
*/
unsigned WINAPI ProcessInfo(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> ProcInfo (%p)", lpData);

    PROCESS_MEMORY_COUNTERS pmc = { 0 };

    FILETIME CreationTime = { 0 };
    FILETIME ExitTime = { 0 };
    FILETIME KernelTime = { 0 };
    FILETIME UserTime = { 0 };
    SYSTEMTIME tKernelTime = { 0 };
    SYSTEMTIME tUserTime = { 0 };

    DWORD dwHandleCount = 0;

    DWORD aProcesses[1024] = { 0 }, cbNeeded = 0, cProcesses = 0;

    uint64_t tickStart = SysTick();

    //get list of process
    memset(aProcesses, 0x00, sizeof(aProcesses));
    cbNeeded = 0;
    cProcesses = 0;
    if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {

        //calculate how many process identifiers were returned.
        cProcesses = cbNeeded / sizeof(DWORD);
        Log(LOG_HEADER, __LINE__, "Processes Information, Number of processes: %u", cProcesses);
        if (cProcesses > 0)        //skip from current process
            Log(LOG_MESSAGE, __LINE__, ">      ProcessID, Process Name, Handles, CPUTime, PagefileUsage, PeakPagefileUsage, PageFaultCount, PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage");

        for (DWORD i = 0; i < cProcesses; i++)
        {
            //get a handle to the process
            DWORD dwProcessID = aProcesses[i];
            HANDLE hProcInfo = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessID);
            if (hProcInfo)
            {
                //get process name
                HMODULE hMod = NULL;
                cbNeeded = 0;
                TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

                //enumerate modules
                if (EnumProcessModules(hProcInfo, &hMod, sizeof(hMod), &cbNeeded))
                {
                    GetModuleBaseName(hProcInfo, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                }

                //get process memory information
                GetProcessMemoryInfo(hProcInfo, &pmc, sizeof(pmc));

                //get process time information
                GetProcessTimes(hProcInfo, &CreationTime, &ExitTime, &KernelTime, &UserTime);
                FileTimeToSystemTime(&KernelTime, &tKernelTime);
                unsigned long seconds = (unsigned long)tKernelTime.wSecond + ((unsigned long)tKernelTime.wMinute * 60) + ((unsigned long)tKernelTime.wHour * 3600);
                FileTimeToSystemTime(&UserTime, &tUserTime);
                seconds = seconds + (unsigned long)tUserTime.wSecond + ((unsigned long)tUserTime.wMinute * 60) + ((unsigned long)tUserTime.wHour * 3600);

                //get process handle count
                GetProcessHandleCount(hProcInfo, &dwHandleCount);

                Log(LOG_MESSAGE, __LINE__, "> %.3d, %05u, %s, %u, %02d:%02d:%02d, %u, %u, %u, %u, %u, %u, %u, %u, %u", i + 1,
                    dwProcessID, szProcessName, dwHandleCount, seconds / 3600, (seconds % 3600) / 60, seconds % 60,
                    pmc.PagefileUsage, pmc.PeakPagefileUsage, pmc.PageFaultCount, pmc.PeakWorkingSetSize, pmc.WorkingSetSize,
                    pmc.QuotaPeakPagedPoolUsage, pmc.QuotaPagedPoolUsage, pmc.QuotaPeakNonPagedPoolUsage, pmc.QuotaNonPagedPoolUsage);

                //close the process handle
                CloseHandle(hProcInfo);
                hProcInfo = NULL;
            }
            else
            {
                Log(LOG_DEBUG, __LINE__, "ProcessInfo, OpenProcess(PID %lu) %s", dwProcessID, dgi::win_error_code_to_str(GetLastError()).c_str());
                Log(LOG_MESSAGE, __LINE__, "> %.3d, %05u, <unknown>, ?, ??:??:??, ?, ?, ?, ?, ?, ?, ?, ?, ?", i + 1, dwProcessID);
            }
        }
    }
    else
    {
        Log(LOG_HEADER, __LINE__, "ProcessInfo, EnumProcesses %s", dgi::win_error_code_to_str(GetLastError()).c_str());
    }

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< ProcInfo");
    _endthreadex(0);
    return 0;
}

/*
** HwProfile
*/
unsigned WINAPI HwProfile(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> HwProfile (%p)", lpData);

    uint64_t tickStart = SysTick();

    //get hardware profile
    HW_PROFILE_INFO HwProfileInfo = { 0 };
    if (GetCurrentHwProfile(&HwProfileInfo))
    {
        Log(LOG_HEADER, __LINE__, "Hardware Profile, DockInfo %p, GUID %s, Name %s",
            HwProfileInfo.dwDockInfo, HwProfileInfo.szHwProfileGuid, HwProfileInfo.szHwProfileName);
    }
    else
    {
        Log(LOG_HEADER, __LINE__, "HwProfile, GetCurrentHwProfile %s", dgi::win_error_code_to_str(GetLastError()).c_str());
    }

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< HwProfile");
    _endthreadex(0);
    return 0;
}

/*
** SystemInfo
*/
double ProcessorSpeed()
{
    LARGE_INTEGER nFreq{};

    //retrieve performance-counter frequency per second
    if (!QueryPerformanceFrequency(&nFreq))
    {
        Log(LOG_DEBUG, __LINE__, "ProcSpeed, QueryPerformanceFrequency %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        return 0;
    }

    return static_cast<double>(static_cast<double>(nFreq.QuadPart) / MHz);
}

DWORD CurrentProcessorNumber(void)
{
    DWORD processor = 1;
    LPFN_GCPN gcpn = (LPFN_GCPN)GetProcAddress(GetModuleHandle("kernel32"), "GetCurrentProcessorNumber");
    if (nullptr == gcpn)
    {
        Log(LOG_DEBUG, __LINE__, "-- CurrentProcessorNumber, GetCurrentProcessorNumber is not supported.");
    }
    else
    {
        processor = gcpn();
    }
    return processor;
}

unsigned WINAPI SystemInfo(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> SysInfo (%p)", lpData);

    uint64_t tickStart = SysTick();

    SYSTEM_INFO SystemInfo = { 0 };
    char szComputeName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD dwSize = MAX_COMPUTERNAME_LENGTH;

    //get process handle
    GetSystemInfo(&SystemInfo);

    //get computer information
    GetComputerName(szComputeName, &dwSize);

    Log(LOG_HEADER, __LINE__, "Computer: %s, Processor(s) %u %.4f Mhz Current %u, %s, Level %u, Rev %u, Type %u; Page Size %u",
        szComputeName, SystemInfo.dwNumberOfProcessors, ProcessorSpeed(), CurrentProcessorNumber(),
        (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64 (AMD or Intel)" :
        (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 ? "Intel Itanium-based" :
            (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86" : "Unknown"))),
        SystemInfo.wProcessorLevel, SystemInfo.wProcessorRevision, SystemInfo.dwProcessorType,
        SystemInfo.dwPageSize);

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< SysInfo");
    _endthreadex(0);
    return 0;
}

/*
** OSInfo: get operate system information
*/
unsigned WINAPI OSInfo(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> OSInfo (%p)", lpData);

    uint64_t tickStart = SysTick();

    //get OS version
    DWORD const flag = (VER_MINORVERSION | VER_MAJORVERSION | VER_BUILDNUMBER | VER_PLATFORMID |
                        VER_SERVICEPACKMINOR | VER_SERVICEPACKMAJOR | VER_SUITENAME | VER_PRODUCT_TYPE);
    OSVERSIONINFOEX osverEx = { 0 };
    osverEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    if (VerifyVersionInfo(&osverEx, flag, 0))
    {
        Log(LOG_HEADER, __LINE__, "OSInfo, Version %u.%u.%u, Platform %u, SP %s(%u.%u), Suite 0x%08X, %s",
            osverEx.dwMajorVersion, osverEx.dwMinorVersion, osverEx.dwBuildNumber, osverEx.dwPlatformId,
            osverEx.szCSDVersion, osverEx.wServicePackMajor, osverEx.wServicePackMinor, osverEx.wSuiteMask,
            (osverEx.wProductType == VER_NT_DOMAIN_CONTROLLER ? "Domain Controller" : (osverEx.wProductType == VER_NT_SERVER ? "Server" : "Workstation")));
    }
    else
    {
        Log(LOG_DEBUG, __LINE__, "OSInfo, VerifyVersionInfo %s", dgi::win_error_code_to_str(GetLastError()).c_str());

        OSVERSIONINFO osver = { 0 };
        osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx(&osver);
        Log(LOG_HEADER, __LINE__, "OSInfo, Version %u.%u.%u, Platform %u, %s", osver.dwMajorVersion, osver.dwMinorVersion, osver.dwBuildNumber, osver.dwPlatformId, osver.szCSDVersion);
    }

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< OSInfo");
    _endthreadex(0);
    return 0;
}

/*
** SystemMemory
*/
unsigned WINAPI SystemMemory(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> SysMem (%p)", lpData);

    uint64_t tickStart = SysTick();

    //get system memory
    MEMORYSTATUSEX Memst = { 0 };
    Memst.dwLength = sizeof(Memst);
    GlobalMemoryStatusEx(&Memst);

    Log(LOG_HEADER, __LINE__, "System Memory");
    Log(LOG_MESSAGE, __LINE__, "Usage: %u%% used", SIZE_MB(Memst.dwMemoryLoad));
    Log(LOG_MESSAGE, __LINE__, "Physical: %u MB used, %u MB avail", SIZE_MB(Memst.ullTotalPhys), SIZE_MB(Memst.ullAvailPhys));
    Log(LOG_MESSAGE, __LINE__, "Pagefile: %u MB used, %u MB avail", SIZE_MB(Memst.ullTotalPageFile), SIZE_MB(Memst.ullAvailPageFile));
    Log(LOG_MESSAGE, __LINE__, "Virtual: %u MB used, %u MB avail, %u MB extended", SIZE_MB(Memst.ullTotalVirtual), SIZE_MB(Memst.ullAvailVirtual), SIZE_MB(Memst.ullAvailExtendedVirtual));

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< SysMem");
    _endthreadex(0);
    return 0;
}

/*
** SystemTimes
*/
unsigned WINAPI SystemTimes(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> SysTimes (%p)", lpData);

    FILETIME ExitTime = { 0 };
    FILETIME KernelTime = { 0 };
    FILETIME UserTime = { 0 };
    FILETIME IdleTime = { 0 };
    SYSTEMTIME tKernelTime = { 0 };
    SYSTEMTIME tUserTime = { 0 };
    SYSTEMTIME tIdleTime = { 0 };
    unsigned long seconds = 0;

    uint64_t tickStart = SysTick();

    Log(LOG_HEADER, __LINE__, "System Times");

    //get system times
    GetSystemTimes(&IdleTime, &KernelTime, &UserTime);

    FileTimeToSystemTime(&KernelTime, &tKernelTime);
    seconds = (long)tKernelTime.wSecond + ((long)tKernelTime.wMinute * 60) + ((long)tKernelTime.wHour * 3600);
    Log(LOG_MESSAGE, __LINE__, "Kernel time: %02d:%02d:%02d (%u s).", seconds / 3600, (seconds % 3600) / 60, seconds % 60, seconds);

    FileTimeToSystemTime(&UserTime, &tUserTime);
    seconds = (long)tUserTime.wSecond + ((long)tUserTime.wMinute * 60) + ((long)tUserTime.wHour * 3600);
    Log(LOG_MESSAGE, __LINE__, "User time: %02d:%02d:%02d (%u s).", seconds / 3600, (seconds % 3600) / 60, seconds % 60, seconds);

    FileTimeToSystemTime(&IdleTime, &tIdleTime);
    seconds = (long)tIdleTime.wSecond + ((long)tIdleTime.wMinute * 60) + ((long)tIdleTime.wHour * 3600);
    Log(LOG_MESSAGE, __LINE__, "Idle: %02d:%02d:%02d (%u s).", seconds / 3600, (seconds % 3600) / 60, seconds % 60, seconds);

    //processor counts/times
    //retrieve performance-counter frequency per second
    uint64_t nCtr = 0, nFreq = 0;
    if (QueryPerformanceFrequency((LARGE_INTEGER *)&nFreq))
    {
        //retrieve the current value of the performance counter
        QueryPerformanceCounter((LARGE_INTEGER *)&nCtr);

        float processorTime = (float)(nCtr / nFreq);
        seconds = (unsigned long)(processorTime + 0.5);
        Log(LOG_MESSAGE, __LINE__, "Processor: %I64u counts, %I64u counts/sec, %02d:%02d:%02d %f s", nCtr, nFreq, seconds / 3600, (seconds % 3600) / 60, seconds % 60, processorTime);
    }

    ULONGLONG interruptTime{}, unbiasedInterruptTime{};
    QueryInterruptTimePrecise(&interruptTime);
    QueryUnbiasedInterruptTimePrecise(&unbiasedInterruptTime);
    Log(LOG_MESSAGE, __LINE__, "Interrupt Time: %I64u counts/110ns, Unbiased %I64u counts/110ns", interruptTime, unbiasedInterruptTime);

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< SysTimes");
    _endthreadex(0);
    return 0;
}

/*
** LogicalDrives: get drivers information
*/
char * DriverTypeName(DWORD driverType)
{
    switch (driverType)
    {
    case DRIVE_NO_ROOT_DIR:
        return "NoRootDir";
    case DRIVE_REMOVABLE:
        return "Removable";
    case DRIVE_FIXED:
        return "Fixed";
    case DRIVE_REMOTE:
        return "Remote";
    case DRIVE_CDROM:
        return "CDRom";
    case DRIVE_RAMDISK:
        return "RamDisk";
    case DRIVE_UNKNOWN:
    default:
        return "Unknown";
    }
}

unsigned WINAPI LogicalDrives(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> LogDrvs (%p)", lpData);

    char temp[10000] = { 0 };

    uint64_t tickStart = SysTick();

    DWORD const numDrivers = GetLogicalDriveStrings(sizeof(temp), temp);

    std::vector<std::string> const drivers = parseNullTerminatedStrings(temp);

    Log(LOG_HEADER, __LINE__, "Logical Drivers %u(%u) (0x%.8X)", drivers.size(), numDrivers, GetLogicalDrives());

    size_t x{};
    for (auto const& driver : drivers)
    {
        DWORD driverType = 0;
        char const* strdrv = driver.c_str();

        driverType = GetDriveType(strdrv);
        Log(LOG_MESSAGE, __LINE__, ">> %.3d, %s: Type %s(%u)", ++x, strdrv, DriverTypeName(driverType), driverType);

        char lpVolumeNameBuffer[10000]{}, lpFileSystemNameBuffer[10000]{};
        DWORD nVolumeSerialNumber{}, nMaximumComponentLength{}, nFileSystemFlags{};

        if (GetVolumeInformation(strdrv, lpVolumeNameBuffer, sizeof(lpVolumeNameBuffer), &nVolumeSerialNumber, &nMaximumComponentLength, &nFileSystemFlags, lpFileSystemNameBuffer, sizeof(lpFileSystemNameBuffer)))
        {
            Log(LOG_MESSAGE, __LINE__, "   VolumeInfo, Name %s, SerialNumber %lu, MaxComponentLength %lu, FileSysflags 0x%08X, FileSysName %s",
                lpVolumeNameBuffer, nVolumeSerialNumber, nMaximumComponentLength, nFileSystemFlags, lpFileSystemNameBuffer);

            DWORD dwSectorsPerCluster{}, dwBytesPerSector{}, dwNumberOfFreeClusters{}, dwTotalNumberOfClusters{};
            if (GetDiskFreeSpace(strdrv, &dwSectorsPerCluster, &dwBytesPerSector, &dwNumberOfFreeClusters, &dwTotalNumberOfClusters))
            {
                Log(LOG_MESSAGE, __LINE__, "   FreeSpace, SectorsPerCluster %lu, BytesPerSector %lu, NumberOfFreeClusters %lu, TotalNumberOfClusters %lu",
                    dwSectorsPerCluster, dwBytesPerSector, dwNumberOfFreeClusters, dwTotalNumberOfClusters);
            }
        }
    }

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< LogDrvs");
    _endthreadex(0);
    return 0;
}

/*
** SystemDirs
*/
unsigned WINAPI SystemDirs(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> SysDirs (%p)", lpData);

    char temp[10000];

    uint64_t tickStart = SysTick();

    Log(LOG_HEADER, __LINE__, "System Directories");

    memset(temp, 0x00, sizeof(temp));
    GetSystemDirectory(temp, sizeof(temp));
    Log(LOG_MESSAGE, __LINE__, "SysDir %s", temp);

    memset(temp, 0x00, sizeof(temp));
    GetTempPath(sizeof(temp), temp);
    Log(LOG_MESSAGE, __LINE__, "TempPath %s", temp);

    memset(temp, 0x00, sizeof(temp));
    GetWindowsDirectory(temp, sizeof(temp));
    Log(LOG_MESSAGE, __LINE__, "WinDir %s", temp);

    memset(temp, 0x00, sizeof(temp));
    GetSystemWindowsDirectory(temp, sizeof(temp));
    Log(LOG_MESSAGE, __LINE__, "WinSysDir %s", temp);

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< SysDirs");
    _endthreadex(0);
    return 0;
}

/*
** SystemLogicalProcessorInforamtion:   Function that collects the logical processor(s) information.
**/
// Helper function to count set bits in the processor mask.
DWORD CountSetBits(ULONG_PTR bitMask)
{
    DWORD LSHIFT = sizeof(ULONG_PTR) * 8 - 1;
    DWORD bitSetCount = 0;
    ULONG_PTR bitTest = (ULONG_PTR)1 << LSHIFT;
    DWORD i;

    for (i = 0; i <= LSHIFT; ++i)
    {
        bitSetCount += ((bitMask & bitTest) ? 1 : 0);
        bitTest /= 2;
    }

    return bitSetCount;
}

unsigned WINAPI SystemLogicalProcessorInforamtion(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> SysLogProcInfo (%p)", lpData);

    BOOL done = FALSE;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION ptr = NULL;
    DWORD returnLength = 0;
    PCACHE_DESCRIPTOR Cache;

    uint64_t const tickStart = SysTick();

    LPFN_GLPI glpi = (LPFN_GLPI)GetProcAddress(GetModuleHandle("kernel32"), "GetLogicalProcessorInformation");
    if (nullptr == glpi)
    {
        Log(LOG_DEBUG, __LINE__, "<< SysLogProcInfo, Out, Unsupp GetLogicalProcessorInformation");
        _endthreadex(ERROR_NOT_SUPPORTED);
        return ERROR_NOT_SUPPORTED;
    }

    while (!done)
    {
        DWORD rc = glpi(buffer, &returnLength);

        if (FALSE == rc)
        {
            DWORD const dwLastError = GetLastError();
            if (dwLastError == ERROR_INSUFFICIENT_BUFFER)
            {
                if (buffer)
                    free(buffer);

                buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)malloc(returnLength);
                if (nullptr == buffer)
                {
                    Log(LOG_DEBUG, __LINE__, "-- SysLogProcInfo, Allocation failure");
                    break;
                }
            }
            else
            {
                Log(LOG_DEBUG, __LINE__, "-- SysLogProcInfo, GLPI %s", dgi::win_error_code_to_str(dwLastError).c_str());
                break;
            }
        }
        else
        {
            done = TRUE;
        }
    }

    if (done)
    {
        DWORD logicalProcessorCount = 0;
        DWORD numaNodeCount = 0;
        DWORD processorCoreCount = 0;
        DWORD processorL1CacheCount = 0;
        DWORD processorL2CacheCount = 0;
        DWORD processorL3CacheCount = 0;
        DWORD processorPackageCount = 0;
        ptr = buffer;

        if (ptr)
        {
            DWORD byteOffset = 0;
            while (byteOffset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) <= returnLength)
            {
                switch (ptr->Relationship)
                {
                case RelationNumaNode:
                    // Non-NUMA systems report a single record of this type.
                    numaNodeCount++;
                    break;

                case RelationProcessorCore:
                    processorCoreCount++;

                    // A hyperthreaded core supplies more than one logical processor.
                    logicalProcessorCount += CountSetBits(ptr->ProcessorMask);
                    break;

                case RelationCache:
                    // Cache data is in ptr->Cache, one CACHE_DESCRIPTOR structure for each cache. 
                    Cache = &ptr->Cache;
                    if (Cache->Level == 1)
                    {
                        processorL1CacheCount++;
                    }
                    else if (Cache->Level == 2)
                    {
                        processorL2CacheCount++;
                    }
                    else if (Cache->Level == 3)
                    {
                        processorL3CacheCount++;
                    }
                    break;

                case RelationProcessorPackage:
                    // Logical processors share a physical package.
                    processorPackageCount++;
                    break;

                default:
                    Log(LOG_DEBUG, __LINE__, "-- SysLogProcInfo, Unsupp LOGICAL_PROCESSOR_RELATIONSHIP value %d", ptr->Relationship);
                    break;
                }
                byteOffset += sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
                ptr++;
            }
        }

        Log(LOG_HEADER, __LINE__, "Logical Processor(s) Information");
        Log(LOG_MESSAGE, __LINE__, "Number of NUMA nodes: %d", numaNodeCount);
        Log(LOG_MESSAGE, __LINE__, "Number of physical processor packages: %d", processorPackageCount);
        Log(LOG_MESSAGE, __LINE__, "Number of processor cores: %d", processorCoreCount);
        Log(LOG_MESSAGE, __LINE__, "Number of logical processors: %d", logicalProcessorCount);
        Log(LOG_MESSAGE, __LINE__, "Number of processor L1/L2/L3 caches: %d/%d/%d", processorL1CacheCount, processorL2CacheCount, processorL3CacheCount);

        free(buffer);
    }

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< SysLogProcInfo");
    _endthreadex(0);
    return 0;
}      

/*
** DeviceDrivers
*/
unsigned WINAPI DeviceDrivers(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> DevDrvs (%p)", lpData);

    const int DriveArraySize = 5000;
    std::vector<LPVOID> drivers(DriveArraySize);
    DWORD cbNeeded = 0;

    uint64_t tickStart = SysTick();

    DWORD const size = static_cast<DWORD const>(sizeof(LPVOID) + drivers.size());
    if (EnumDeviceDrivers(&drivers[0], size, &cbNeeded) && (cbNeeded < size))
    {
        size_t const cDrivers = cbNeeded / sizeof(drivers[0]);

        Log(LOG_HEADER, __LINE__, "Device Drivers, Number of: %d", cDrivers);
        for (size_t i = 0; i < cDrivers; i++)
        {
            char szDriver[DriveArraySize] = { 0 };
            char szFile[DriveArraySize] = { 0 };

            GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]));
            GetDeviceDriverFileName(drivers[i], szFile, sizeof(szFile) / sizeof(szFile[0]));

            Log(LOG_MESSAGE, __LINE__, "> %.3zu, %s, %s", i + 1, szDriver, szFile);
        }
    }
    else
    {
        Log(LOG_HEADER, __LINE__, "DevDrvs, EnumDeviceDrivers %s (array size needed %u)", dgi::win_error_code_to_str(GetLastError()).c_str(), cbNeeded / sizeof(LPVOID));
    }

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< DevDrvs");
    _endthreadex(0);
    return 0;
}

/*
** PerformanceInfo
*/
unsigned WINAPI PerformanceInfo(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> PerfInfo (%p)", lpData);

    uint64_t tickStart = SysTick();

    PERFORMANCE_INFORMATION perfInfo = { 0 };
    if (GetPerformanceInfo(&perfInfo, sizeof(PERFORMANCE_INFORMATION)))
    {
        Log(LOG_HEADER, __LINE__, "Performance Information");
        Log(LOG_MESSAGE, __LINE__, "Commit: Total %u, Limit %u, Peak %u", perfInfo.CommitTotal, perfInfo.CommitLimit, perfInfo.CommitPeak);
        Log(LOG_MESSAGE, __LINE__, "Physical: Total %u, Available %u", perfInfo.PhysicalTotal, perfInfo.PhysicalAvailable);
        Log(LOG_MESSAGE, __LINE__, "System Cache %u", perfInfo.SystemCache);
        Log(LOG_MESSAGE, __LINE__, "Kernel: Total %u, Paged %u, Nonpaged %u", perfInfo.KernelTotal, perfInfo.KernelPaged, perfInfo.KernelNonpaged);
        Log(LOG_MESSAGE, __LINE__, "Page Size %u", perfInfo.PageSize);
        Log(LOG_MESSAGE, __LINE__, "Process %u, Handles %u, Threads %u", perfInfo.ProcessCount, perfInfo.HandleCount, perfInfo.ThreadCount);
    }
    else
    {
        Log(LOG_HEADER, __LINE__, "PerfInfo, GetPerformanceInfo %s", dgi::win_error_code_to_str(GetLastError()).c_str());
    }

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< PerfInfo");
    _endthreadex(0);
    return 0;
}

/*
** PrinterInfo: list and capabilities of all printers
*/
typedef struct {
    char name[24];
} NAME_24BYTES;

typedef struct {
    char name[32];
} NAME_32BYTES;

typedef struct {
    char name[64];
} NAME_64BYTES;

typedef struct _printer_info_
{
    char PrinterName[_MAX_PATH];
    char PortName[_MAX_PATH];
    char DriverName[_MAX_PATH];
} PRINTER_INFO, *LP_PRINTER_INFO;

typedef struct _printer_info_list_
{
    int num;
    PRINTER_INFO PrinterInfo[1];
} PRINTER_INFO_LIST, *LP_PRINTER_INFO_LIST;

LP_PRINTER_INFO_LIST gpPrinterInfoList = nullptr;

int GetPrintersList(void)
{
    int l = 0, n = 0;
    PBuffer B;

    Log(LOG_DEBUG, __LINE__, ">> GetPtrsList");

    //release printer info list
    if (gpPrinterInfoList)
    {
        delete[] gpPrinterInfoList;
        gpPrinterInfoList = nullptr;
    }

    //get number of printers
    EnumPrinters(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2, NULL, l, (DWORD*)&l, (DWORD*)&n);
    if (l == 0)
    {
        Log(LOG_DEBUG, __LINE__, "<< GetPtrsList, No Printer");
        return 0;
    }
    n = 0;
    LPBYTE lpbPtrInfo = B._allocMem(l);
    if (!lpbPtrInfo)
    {
        Log(LOG_DEBUG, __LINE__, "<< GetPtrsList, new PtrInfo null");
        return 0;
    }

    //get the printer list information
    if (!EnumPrinters(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2, lpbPtrInfo, l, (DWORD*)&l, (DWORD*)&n))
    {
        Log(LOG_DEBUG, __LINE__, "<< GetPtrsList, EnumPrinters %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        return 0;
    }

    //create list of printer info
    size_t size = sizeof(PRINTER_INFO_LIST) + ((n - 1) * sizeof(PRINTER_INFO));
    gpPrinterInfoList = (LP_PRINTER_INFO_LIST)new BYTE[size];
    if (!gpPrinterInfoList)
    {
        Log(LOG_DEBUG, __LINE__, "<< GetPtrsList, new PrtInfoList null");
        return 0;
    }
    memset(gpPrinterInfoList, 0x00, size);

    Log(LOG_HEADER, __LINE__, "Printers Information (%d):", n);
    PRINTER_INFO_2* pi2 = (PRINTER_INFO_2*)lpbPtrInfo;
    Log(LOG_MESSAGE, __LINE__, ">     Printer, Port, Driver, Processor, Status, Priority, Location, Share, Comment");
    for (int i = 0; i < n; i++)
    {
        Log(LOG_MESSAGE, __LINE__, "> %.2d: \\\\%s\\%s, %s, %s, %s, %u, %u, %s, %s, %s", i + 1,
            pi2->pServerName ? pi2->pServerName : "<LocalPrinter>", pi2->pPrinterName,
            pi2->pPortName, pi2->pDriverName, pi2->pPrintProcessor, pi2->Status,
            pi2->Priority, pi2->pLocation, pi2->pShareName, pi2->pComment);

        strncpy(gpPrinterInfoList->PrinterInfo[i].PrinterName, pi2->pPrinterName, _MAX_PATH - 1);
        strncpy(gpPrinterInfoList->PrinterInfo[i].PortName, pi2->pPortName, _MAX_PATH - 1);
        strncpy(gpPrinterInfoList->PrinterInfo[i].DriverName, pi2->pDriverName, _MAX_PATH - 1);
        gpPrinterInfoList->num++;
        pi2++;
    }

    Log(LOG_DEBUG, __LINE__, "<< GetPtrsList");
    return gpPrinterInfoList->num;
}

typedef struct _ptrdata_info_
{
    DWORD id;
    char name[_MAX_PATH];
    long x;
    long y;
} PTRDATA_INFO, *LP_PTRDATA_INFO;

typedef struct _ptrdata_info_list_
{
    int num;
    PTRDATA_INFO PtrDataInfo[1];
} PTRDATA_INFO_LIST, *LP_PTRDATA_INFO_LIST;

LP_PTRDATA_INFO_LIST GetBinList(char const* PrinterName, char const* PortName)
{
    int l = 0, n = 0, i = 0, bins = 0;
    LP_PTRDATA_INFO_LIST pList = NULL;

    WORD *pw = NULL;
    BYTE *ppi = NULL;
    PBuffer B;

    Log(LOG_DEBUG, __LINE__, ">> GetBinList, Name %s, Port %s", PrinterName, PortName);

    // *** bins
    if ((l = DeviceCapabilities(PrinterName, PortName, DC_BINS, NULL, NULL)) <= 0)
    {
        Log(LOG_DEBUG, __LINE__, "<< GetBinList, DeviceCapabilities(DC_BINS, null) %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        return NULL;
    }
    else
    {
        ppi = B._allocMem(l * sizeof(WORD));
        if (!ppi)
        {
            Log(LOG_DEBUG, __LINE__, "<< GetBinList, <%s> new DC_BINS mem null", PrinterName);
            return NULL;
        }
        else
        {
            bins = l;
            size_t size = sizeof(PTRDATA_INFO_LIST) + ((l - 1) * sizeof(PTRDATA_INFO));
            pList = (LP_PTRDATA_INFO_LIST)new BYTE[size];
            if (!pList)
            {
                Log(LOG_DEBUG, __LINE__, "<< GetBinList, <%s> new PTRDATA_INFO_LIST mem null", PrinterName);
                return NULL;
            }
            memset(pList, 0x00, size);
            pList->num = bins;

            if ((n = DeviceCapabilities(PrinterName, PortName, DC_BINS, (LPSTR)ppi, NULL)) != l)
            {
                Log(LOG_DEBUG, __LINE__, "<< GetBinList, DeviceCapabilities(DC_BINS, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
                delete[] pList;
                return NULL;
            }
            else
            {
                for (i = 0, pw = (WORD *)ppi; i < n; i++, pw++)
                {
                    pList->PtrDataInfo[i].id = *pw;
                }
            }
        }
    }

    // *** binnames
    ppi = B._allocMem(bins * sizeof(NAME_24BYTES));
    if (!ppi)
    {
        Log(LOG_DEBUG, __LINE__, "-- GetBinList, <%s> new DC_BINNAMES mem null", PrinterName);
    }
    else
    {
        if ((n = DeviceCapabilities(PrinterName, PortName, DC_BINNAMES, (LPSTR)ppi, NULL)) != l)
        {
            Log(LOG_DEBUG, __LINE__, "-- GetBinList, DeviceCapabilities(DC_BINNAMES, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
        }
        else
        {
            NAME_24BYTES *pn24 = NULL;
            for (i = 0, pn24 = (NAME_24BYTES *)ppi; i < n; i++, pn24++)
            {
                memcpy(pList->PtrDataInfo[i].name, pn24->name, sizeof(NAME_24BYTES));
            }
        }
    }

    Log(LOG_DEBUG, __LINE__, "<< GetBinList, List %p", pList);
    return pList;
}

DEVMODE* GetDeviceMode(const char* PrinterName, const char* DriverName)
{
    DEVMODE *pdm = nullptr;
    HANDLE hPrinter = nullptr;

    if (OpenPrinter(const_cast<LPSTR>(PrinterName), &hPrinter, nullptr))
    {
        long const l = DocumentProperties(NULL, hPrinter, const_cast<LPSTR>(DriverName), nullptr, nullptr, 0);
        pdm = reinterpret_cast<DEVMODE *>(new uint8_t[l]);
        if (pdm)
        {
            memset(pdm, 0x00, sizeof(uint8_t)*l);
            DocumentProperties(NULL, hPrinter, const_cast<LPSTR>(DriverName), pdm, NULL, DM_OUT_BUFFER);
        }
    }
    return pdm;
}

LP_PTRDATA_INFO_LIST GetPaperList(char const* PrinterName, char const* PortName, DEVMODE const* pdm)
{
    int l = 0, n = 0, i = 0, papers = 0;
    LP_PTRDATA_INFO_LIST pList = NULL;

    WORD *pw = NULL;
    BYTE *ppi = NULL;
    POINT *pp = NULL;
    PBuffer B;

    Log(LOG_DEBUG, __LINE__, ">> GetPaperList, Name %s, Port %s", PrinterName, PortName);

    if ((l = DeviceCapabilities(PrinterName, PortName, DC_PAPERS, NULL, pdm)) <= 0)
    {
        Log(LOG_DEBUG, __LINE__, "<< GetPaperList, DeviceCapabilities(DC_PAPERS, null) %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        return NULL;
    }
    else
    {
        ppi = B._allocMem(l * sizeof(WORD));
        if (!ppi)
        {
            Log(LOG_DEBUG, __LINE__, "<< GetPaperList, <%s> new DC_PAPERS mem null", PrinterName);
            return NULL;
        }
        else
        {
            papers = l;
            size_t size = sizeof(PTRDATA_INFO_LIST) + ((l - 1) * sizeof(PTRDATA_INFO));
            pList = (LP_PTRDATA_INFO_LIST)new BYTE[size];
            if (!pList)
            {
                Log(LOG_DEBUG, __LINE__, "<< GetPaperList, <%s> new PTRDATA_INFO_LIST mem null", PrinterName);
                return NULL;
            }
            memset(pList, 0x00, size);
            pList->num = papers;

            if ((n = DeviceCapabilities(PrinterName, PortName, DC_PAPERS, (LPSTR)ppi, NULL)) != l)
            {
                Log(LOG_DEBUG, __LINE__, "<< GetPaperList, DeviceCapabilities(DC_PAPERS, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
                delete[] pList;
                return NULL;
            }
            else
            {
                for (i = 0, pw = (WORD *)ppi; i < n; i++, pw++)
                {
                    pList->PtrDataInfo[i].id = *pw;
                }
            }
        }
    }

    // *** paper sizes
    ppi = B._allocMem(papers * sizeof(POINT));
    if (!ppi)
    {
        Log(LOG_DEBUG, __LINE__, "-- GetPaperList, <%s> new DC_PAPERSIZE mem null", PrinterName);
    }
    else
    {
        if ((n = DeviceCapabilities(PrinterName, PortName, DC_PAPERSIZE, (LPSTR)ppi, NULL)) != l)
        {
            Log(LOG_DEBUG, __LINE__, "-- GetPaperList, DeviceCapabilities(DC_PAPERSIZE, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
        }
        else
        {
            for (i = 0, pp = (POINT *)ppi; i < n; i++, pp++)
            {
                pList->PtrDataInfo[i].x = pp->x;
                pList->PtrDataInfo[i].y = pp->y;
            }
        }
    }

    // *** paper names
    ppi = B._allocMem(papers * sizeof(NAME_64BYTES));
    if (!ppi)
    {
        Log(LOG_DEBUG, __LINE__, "-- GetPaperList, <%s> new DC_PAPERNAMES mem null", PrinterName);
    }
    else
    {
        if ((n = DeviceCapabilities(PrinterName, PortName, DC_PAPERNAMES, (LPSTR)ppi, NULL)) != l)
        {
            Log(LOG_DEBUG, __LINE__, "-- GetPaperList, DeviceCapabilities(DC_PAPERNAMES, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
        }
        else
        {
            NAME_64BYTES *pn64 = NULL;
            for (i = 0, pn64 = (NAME_64BYTES *)ppi; i < n; i++, pn64++)
            {
                memcpy(pList->PtrDataInfo[i].name, pn64->name, sizeof(NAME_64BYTES));
            }
        }
    }

    Log(LOG_DEBUG, __LINE__, "<< GetPaperList, List %p", pList);
    return pList;
}

LP_PTRDATA_INFO_LIST GetMediaTypeList(char const* PrinterName, char const* PortName)
{
    int l = 0, n = 0, i = 0, mediaTypes = 0;
    LP_PTRDATA_INFO_LIST pList = nullptr;

    DWORD *pdw = NULL;
    BYTE *ppi = NULL;
    PBuffer B;

    Log(LOG_DEBUG, __LINE__, ">> GetMediaTypeList, Name %s, Port %s", PrinterName, PortName);

    if ((l = DeviceCapabilities(PrinterName, PortName, DC_MEDIATYPES, NULL, NULL)) <= 0)
    {
        Log(LOG_DEBUG, __LINE__, "<< GetMediaTypeList, DeviceCapabilities(DC_MEDIATYPES, null) %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        return NULL;
    }
    else
    {
        ppi = B._allocMem(l * sizeof(DWORD));
        if (!ppi)
        {
            Log(LOG_DEBUG, __LINE__, "-- GetMediaTypeList, <%s> new DC_MEDIATYPES mem null", PrinterName);
        }
        else
        {
            mediaTypes = l;
            size_t size = sizeof(PTRDATA_INFO_LIST) + ((l - 1) * sizeof(PTRDATA_INFO));
            pList = (LP_PTRDATA_INFO_LIST)new BYTE[size];
            if (!pList)
            {
                Log(LOG_DEBUG, __LINE__, "<< GetMediaTypeList, <%s> new PTRDATA_INFO_LIST mem null", PrinterName);
                return NULL;
            }
            memset(pList, 0x00, size);
            pList->num = mediaTypes;

            if ((n = DeviceCapabilities(PrinterName, PortName, DC_MEDIATYPES, (LPSTR)ppi, NULL)) != l)
            {
                Log(LOG_DEBUG, __LINE__, "<< GetMediaTypeList, DeviceCapabilities(DC_MEDIATYPES, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
                delete[] pList;
                return NULL;
            }
            else
            {
                for (i = 0, pdw = (DWORD *)ppi; i < n; i++, pdw++)
                {
                    pList->PtrDataInfo[i].id = *pdw;
                }
            }
        }
    }

    // *** media type names
    ppi = B._allocMem(mediaTypes * sizeof(NAME_64BYTES));
    if (!ppi)
    {
        Log(LOG_DEBUG, __LINE__, "-- GetMediaTypeList, <%s> new DC_MEDIATYPENAMES mem null", PrinterName);
    }
    else
    {
        if ((n = DeviceCapabilities(PrinterName, PortName, DC_MEDIATYPENAMES, (LPSTR)ppi, NULL)) != l)
        {
            Log(LOG_DEBUG, __LINE__, "-- GetMediaTypeList, DeviceCapabilities(DC_MEDIATYPENAMES, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
        }
        else
        {
            NAME_64BYTES *pn64 = nullptr;
            for (i = 0, pn64 = (NAME_64BYTES *)ppi; i < n && pList; ++i, ++pn64)
            {
                memcpy(pList->PtrDataInfo[i].name, pn64->name, sizeof(NAME_64BYTES));
            }
        }
    }

    Log(LOG_DEBUG, __LINE__, "<< GetMediaTypeList, List %p", pList);
    return pList;
}

unsigned WINAPI PrinterInfo(LPVOID lpData)
{
    int l = 0, n = 0, i = 0;
    DWORD *pdw = nullptr;
    BYTE *ppi = nullptr;
    PBuffer B;

    char PrinterName[_MAX_PATH] = { 0 };
    char DriverName[_MAX_PATH] = { 0 };
    char PortName[_MAX_PATH] = { 0 };

    NAME_32BYTES *pn32 = nullptr;
    NAME_64BYTES *pn64 = nullptr;

    uint64_t tickStart = SysTick();

    Log(LOG_DEBUG, __LINE__, ">> PtrInfo (%p)", lpData);
    if (GetPrintersList() == 0)
    {
        Log(LOG_DEBUG, __LINE__, "<< PtrInfo, No Printer");
        _endthreadex(0);
        return 0;
    }

    if (!gpPrinterInfoList)
    {
        Log(LOG_DEBUG, __LINE__, "<< PtrInfo, PtrInfoList null");
        _endthreadex(ERROR_OUTOFMEMORY);
        return ERROR_OUTOFMEMORY;
    }

    for (int printerCnt = 0; printerCnt < gpPrinterInfoList->num; printerCnt++)
    {
        memset(PrinterName, 0x00, sizeof(PrinterName));
        memset(PortName, 0x00, sizeof(PortName));
        memset(DriverName, 0x00, sizeof(DriverName));

        strncpy(PrinterName, gpPrinterInfoList->PrinterInfo[printerCnt].PrinterName, _MAX_PATH - 1);
        strncpy(PortName, gpPrinterInfoList->PrinterInfo[printerCnt].PortName, _MAX_PATH - 1);
        strncpy(DriverName, gpPrinterInfoList->PrinterInfo[printerCnt].DriverName, _MAX_PATH - 1);

        Log(LOG_HEADER, __LINE__, "Info from %s, Port %s, Driver %s (%d)", PrinterName, PortName, DriverName, printerCnt);

        //GET PRINTER CAPABILITIES
        // *** resolution(s)
        if ((l = DeviceCapabilities(PrinterName, PortName, DC_ENUMRESOLUTIONS, NULL, NULL)) <= 0)
        {
            Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_ENUMRESOLUTIONS, null) %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        }
        else
        {
            ppi = B._allocMem(l * sizeof(POINT));
            if (!ppi)
            {
                Log(LOG_DEBUG, __LINE__, "-- PtrInfo, <%s> new DC_ENUMRESOLUTIONS mem null", PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_ENUMRESOLUTIONS, (LPSTR)ppi, NULL)) != l)
                {
                    Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_ENUMRESOLUTIONS, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
                }
                else
                {
                    Log(LOG_MESSAGE, __LINE__, "DC_ENUMRESOLUTIONS (%d):", n);
                    for (i = 0, pdw = (DWORD*)ppi; i < n; i++)
                    {
                        Log(LOG_MESSAGE, __LINE__, ">%.2d: %u x %u", i + 1, pdw[i * 2], pdw[i * 2 + 1]);
                    }
                }
            }
        }

        // *** bins & binnames
        try
        {
            LP_PTRDATA_INFO_LIST pBinList = GetBinList(PrinterName, PortName);
            if (pBinList)
            {
                Log(LOG_MESSAGE, __LINE__, "DC_BINS, DC_BINNAMES (%d):", pBinList->num);
                for (i = 0; i < pBinList->num; i++)
                {
                    Log(LOG_MESSAGE, __LINE__, ">%.2d: %u, %s", i + 1, pBinList->PtrDataInfo[i].id, pBinList->PtrDataInfo[i].name);
                }
                delete[] pBinList;
                pBinList = NULL;
            }
        }
        catch (...)
        {
            Log(LOG_DEBUG, __LINE__, "-- PtrInfo, Catch unhndld excpetion on BinList");
        }

        // *** papers & paper names & paper sizes
        try
        {
            DEVMODE* pdm = GetDeviceMode(PrinterName, DriverName);

            LP_PTRDATA_INFO_LIST pPaperList = GetPaperList(PrinterName, PortName, pdm);
            if (pPaperList)
            {
                Log(LOG_MESSAGE, __LINE__, "DC_PAPERS, DC_PAPERNAMES, DC_PAPERSIZE (%d):", pPaperList->num);
                for (i = 0; i < pPaperList->num; i++)
                {
                    Log(LOG_MESSAGE, __LINE__, ">%.2d: %u, %s, %.5d %.5d", i + 1, pPaperList->PtrDataInfo[i].id, pPaperList->PtrDataInfo[i].name, pPaperList->PtrDataInfo[i].x, pPaperList->PtrDataInfo[i].y);
                }
                delete[] pPaperList;
                pPaperList = NULL;
            }

            if (pdm) delete[] reinterpret_cast<uint8_t*>(pdm);
        }
        catch (...)
        {
            Log(LOG_DEBUG, __LINE__, "-- PtrInfo, Catch unhndld excpetion on PaperList");
        }

        // *** portrait - landscape
        l = DeviceCapabilities(PrinterName, PortName, DC_ORIENTATION, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_ORIENTATION %d", l);

        // *** maximum number of copies supported
        l = DeviceCapabilities(PrinterName, PortName, DC_COPIES, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_COPIES %d", l);

        // *** collate
        l = DeviceCapabilities(PrinterName, PortName, DC_COLLATE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_COLLATE %d", l);

        // *** color support
        l = DeviceCapabilities(PrinterName, PortName, DC_COLORDEVICE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_COLORDEVICE %d", l);

        // *** duplex support
        l = DeviceCapabilities(PrinterName, PortName, DC_DUPLEX, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_DUPLEX %d", l);

        // *** driver version
        l = DeviceCapabilities(PrinterName, PortName, DC_DRIVER, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_DRIVER %d", l);

        // *** spec driver version
        l = DeviceCapabilities(PrinterName, PortName, DC_VERSION, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_VERSION %d", l);

        // *** fields
        l = DeviceCapabilities(PrinterName, PortName, DC_FIELDS, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_FIELDS %u", l);

        // *** maximum paper size
        l = DeviceCapabilities(PrinterName, PortName, DC_MAXEXTENT, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_MAXEXTENT: Length %u, Width %u", HIWORD((DWORD)l), LOWORD((DWORD)l));

        // *** minimum paper size
        l = DeviceCapabilities(PrinterName, PortName, DC_MINEXTENT, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_MINEXTENT: Length %u, Width %u", HIWORD((DWORD)l), LOWORD((DWORD)l));

        // *** size
        l = DeviceCapabilities(PrinterName, PortName, DC_SIZE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_SIZE %d", l);

        // *** staple
        l = DeviceCapabilities(PrinterName, PortName, DC_STAPLE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_STAPLE %d", l);

        // *** TrueType
        l = DeviceCapabilities(PrinterName, PortName, DC_TRUETYPE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE, __LINE__, "DC_TRUETYPE %d", l);

        // *** multiple document pages per printed page
        if ((l = DeviceCapabilities(PrinterName, PortName, DC_NUP, NULL, NULL)) <= 0)
        {
            Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_NUP, null) %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        }
        else
        {
            ppi = B._allocMem(l * sizeof(DWORD));
            if (!ppi)
            {
                Log(LOG_DEBUG, __LINE__, "-- PtrInfo, <%s> new DC_NUP mem null", PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_NUP, (LPSTR)ppi, NULL)) != l)
                {
                    Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_NUP, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
                }
                else
                {
                    Log(LOG_MESSAGE, __LINE__, "DC_NUP (%d):", n);
                    for (i = 0, pdw = (DWORD *)ppi; i < n; i++, pdw++)
                    {
                        Log(LOG_MESSAGE, __LINE__, ">%.2d: %u", i + 1, *pdw);
                    }
                }
            }
        }

        // *** field dependencies
        if ((l = DeviceCapabilities(PrinterName, PortName, DC_FILEDEPENDENCIES, NULL, NULL)) <= 0)
        {
            Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_FILEDEPENDENCIES, null) %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        }
        else
        {
            ppi = B._allocMem(l * sizeof(NAME_64BYTES));
            if (!ppi)
            {
                Log(LOG_DEBUG, __LINE__, "-- PtrInfo, <%s> new DC_FILEDEPENDENCIES mem null", PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_FILEDEPENDENCIES, (LPSTR)ppi, NULL)) != l)
                {
                    Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_FILEDEPENDENCIES, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
                }
                else
                {
                    pn64 = NULL;
                    Log(LOG_MESSAGE, __LINE__, "DC_FILEDEPENDENCIES (%d):", n);
                    for (i = 0, pn64 = (NAME_64BYTES *)ppi; i < n; i++, pn64++)
                    {
                        pn64->name[63] = 0x00;      //avoid memory over-read if the whole buffer is filled
                        Log(LOG_MESSAGE, __LINE__, ">%.2d: %s", i + 1, pn64->name);
                    }
                }
            }
        }

        // *** paper forms
        if ((l = DeviceCapabilities(PrinterName, PortName, DC_MEDIAREADY, NULL, NULL)) <= 0)
        {
            Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_MEDIAREADY, null) %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        }
        else
        {
            ppi = B._allocMem(l * sizeof(NAME_64BYTES));
            if (!ppi)
            {
                Log(LOG_DEBUG, __LINE__, "-- PtrInfo, <%s> new DC_MEDIAREADY mem null", PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_MEDIAREADY, (LPSTR)ppi, NULL)) != l)
                {
                    Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_MEDIAREADY, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
                }
                else
                {
                    pn64 = NULL;
                    Log(LOG_MESSAGE, __LINE__, "DC_MEDIAREADY (%d):", n);
                    for (i = 0, pn64 = (NAME_64BYTES *)ppi; i < n; i++, pn64++)
                    {
                        pn64->name[63] = 0x00;      //avoid memory over-read if the whole buffer is filled
                        Log(LOG_MESSAGE, __LINE__, ">%.2d: %s", i + 1, pn64->name);
                    }
                }
            }
        }

        if (GetWinVer() > 5)
        {
            // *** media types & media type names
            try
            {
                LP_PTRDATA_INFO_LIST pMediaTypeList = GetMediaTypeList(PrinterName, PortName);
                if (pMediaTypeList)
                {
                    Log(LOG_MESSAGE, __LINE__, "DC_MEDIATYPES, DC_MEDIATYPENAMES (%d):", pMediaTypeList->num);
                    for (i = 0; i < pMediaTypeList->num; i++)
                    {
                        Log(LOG_MESSAGE, __LINE__, ">%.2d: %u, %s", i + 1, pMediaTypeList->PtrDataInfo[i].id, pMediaTypeList->PtrDataInfo[i].name);
                    }
                    delete[] pMediaTypeList;
                    pMediaTypeList = NULL;
                }
            }
            catch (...)
            {
                Log(LOG_DEBUG, __LINE__, "-- PtrInfo, Catch unhndld excpetion on MediaTypeList");
            }
        }

        // *** list of printer description languages supported
        if ((l = DeviceCapabilities(PrinterName, PortName, DC_PERSONALITY, NULL, NULL)) <= 0)
        {
            Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_PERSONALITY, null) %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        }
        else
        {
            ppi = B._allocMem(l * sizeof(NAME_32BYTES));
            if (!ppi)
            {
                Log(LOG_DEBUG, __LINE__, "-- PtrInfo, <%s> new DC_PERSONALITY mem null", PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_PERSONALITY, (LPSTR)ppi, NULL)) != l)
                {
                    Log(LOG_DEBUG, __LINE__, "-- PtrInfo, DeviceCapabilities(DC_PERSONALITY, %p) %s", ppi, dgi::win_error_code_to_str(GetLastError()).c_str());
                }
                else
                {
                    pn32 = NULL;
                    Log(LOG_MESSAGE, __LINE__, "DC_PERSONALITY (%d):", n);
                    for (i = 0, pn32 = (NAME_32BYTES *)ppi; i < n; i++, pn32++)
                    {
                        pn32->name[31] = 0x00;      //avoid memory over-read if the whole buffer is filled
                        Log(LOG_MESSAGE, __LINE__, ">%.2d: %s", i + 1, pn32->name);
                    }
                }
            }
        }

        // *** document properties
        HANDLE hPrinter = NULL;
        if (OpenPrinter(PrinterName, &hPrinter, NULL))
        {
            l = DocumentProperties(NULL, hPrinter, DriverName, NULL, NULL, 0);
            DEVMODE *pdm = (DEVMODE *)new char[l];
            if (pdm)
            {
                memset(pdm, 0x00, sizeof(char)*l);
                DocumentProperties(NULL, hPrinter, DriverName, pdm, NULL, DM_OUT_BUFFER);
                Log(LOG_MESSAGE, __LINE__, "DEVMODE:");
                Log(LOG_MESSAGE, __LINE__, "> DeviceName %s", pdm->dmDeviceName);
                Log(LOG_MESSAGE, __LINE__, "> SpecVersion %d", pdm->dmSpecVersion);
                Log(LOG_MESSAGE, __LINE__, "> DriverVersion %d", pdm->dmDriverVersion);
                Log(LOG_MESSAGE, __LINE__, "> Size %d", pdm->dmSize);
                Log(LOG_MESSAGE, __LINE__, "> DriverExtra %d", pdm->dmDriverExtra);
                Log(LOG_MESSAGE, __LINE__, "> DriverFields 0x%.8X", pdm->dmFields);
                Log(LOG_MESSAGE, __LINE__, "> Orient %d", pdm->dmOrientation);
                Log(LOG_MESSAGE, __LINE__, "> PaperSize %d", pdm->dmPaperSize);
                Log(LOG_MESSAGE, __LINE__, "> PaperLength %d", pdm->dmPaperLength);
                Log(LOG_MESSAGE, __LINE__, "> PaperWidth %d", pdm->dmPaperWidth);
                Log(LOG_MESSAGE, __LINE__, "> Scale %d", pdm->dmScale);
                Log(LOG_MESSAGE, __LINE__, "> Copies %d", pdm->dmCopies);
                Log(LOG_MESSAGE, __LINE__, "> DefaultSource %d", pdm->dmDefaultSource);
                Log(LOG_MESSAGE, __LINE__, "> PrintQulity %d", pdm->dmPrintQuality);
                Log(LOG_MESSAGE, __LINE__, "> Color %d", pdm->dmColor);
                Log(LOG_MESSAGE, __LINE__, "> Duplex %d", pdm->dmDuplex);
                Log(LOG_MESSAGE, __LINE__, "> YResolution %d", pdm->dmYResolution);
                Log(LOG_MESSAGE, __LINE__, "> TTOption %d", pdm->dmTTOption);
                Log(LOG_MESSAGE, __LINE__, "> Collate %d", pdm->dmCollate);
                Log(LOG_MESSAGE, __LINE__, "> FormName %s", pdm->dmFormName);
                Log(LOG_MESSAGE, __LINE__, "> LogPixels %d", pdm->dmLogPixels);
                Log(LOG_MESSAGE, __LINE__, "> BitsPerPel %u", pdm->dmBitsPerPel);
                Log(LOG_MESSAGE, __LINE__, "> PelsWidth %u", pdm->dmPelsWidth);
                Log(LOG_MESSAGE, __LINE__, "> PelsHeight %d", pdm->dmPelsHeight);
                if (GetWinVer() >= 4)
                {
                    Log(LOG_MESSAGE, __LINE__, "> ICMMethod %u", pdm->dmICMMethod);
                    Log(LOG_MESSAGE, __LINE__, "> ICMIntent %u", pdm->dmICMIntent);
                    Log(LOG_MESSAGE, __LINE__, "> MediaType %u", pdm->dmMediaType);
                    Log(LOG_MESSAGE, __LINE__, "> DitherType %u", pdm->dmDitherType);
                    Log(LOG_MESSAGE, __LINE__, "> Reserved1 %u", pdm->dmReserved1);
                    Log(LOG_MESSAGE, __LINE__, "> Reserved2 %u", pdm->dmReserved2);
                    if (GetWinVer() >= 5)
                    {
                        Log(LOG_MESSAGE, __LINE__, "> PanningWidth %u", pdm->dmPanningWidth);
                        Log(LOG_MESSAGE, __LINE__, "> PanningHeight %u", pdm->dmPanningHeight);
                    }
                }

                delete[] pdm;
                pdm = nullptr;
            }
            ClosePrinter(hPrinter);
        }
        else
        {
            Log(LOG_DEBUG, __LINE__, "-- PtrInfo, OpenPrinter %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        }

        // *** fonts information
        HDC hdc = CreateIC(DriverName, PrinterName, NULL, NULL);
        if (hdc)
        {
            Log(LOG_MESSAGE, __LINE__, "DeviceCaps:");

            l = GetDeviceCaps(hdc, DRIVERVERSION);
            Log(LOG_MESSAGE, __LINE__, "> DRIVERVERSION %d", l);

            l = GetDeviceCaps(hdc, TECHNOLOGY);
            Log(LOG_MESSAGE, __LINE__, "> TECHNOLOGY %d", l);

            l = GetDeviceCaps(hdc, HORZSIZE);
            Log(LOG_MESSAGE, __LINE__, "> HORZSIZE %d", l);

            l = GetDeviceCaps(hdc, VERTSIZE);
            Log(LOG_MESSAGE, __LINE__, "> VERTSIZE %d", l);

            l = GetDeviceCaps(hdc, HORZRES);
            Log(LOG_MESSAGE, __LINE__, "> HORZRES %d", l);

            l = GetDeviceCaps(hdc, VERTRES);
            Log(LOG_MESSAGE, __LINE__, "> VERTRES %d", l);

            l = GetDeviceCaps(hdc, BITSPIXEL);
            Log(LOG_MESSAGE, __LINE__, "> BITSPIXEL %d", l);

            l = GetDeviceCaps(hdc, PLANES);
            Log(LOG_MESSAGE, __LINE__, "> PLANES %d", l);

            l = GetDeviceCaps(hdc, NUMBRUSHES);
            Log(LOG_MESSAGE, __LINE__, "> NUMBRUSHES %d", l);

            l = GetDeviceCaps(hdc, NUMPENS);
            Log(LOG_MESSAGE, __LINE__, "> NUMPENS %d", l);

            l = GetDeviceCaps(hdc, NUMMARKERS);
            Log(LOG_MESSAGE, __LINE__, "> NUMMARKERS %d", l);

            l = GetDeviceCaps(hdc, NUMFONTS);
            Log(LOG_MESSAGE, __LINE__, "> NUMFONTS %d", l);

            l = GetDeviceCaps(hdc, NUMCOLORS);
            Log(LOG_MESSAGE, __LINE__, "> NUMCOLORS %d", l);

            l = GetDeviceCaps(hdc, PDEVICESIZE);
            Log(LOG_MESSAGE, __LINE__, "> PDEVICESIZE %d", l);

            l = GetDeviceCaps(hdc, CURVECAPS);
            Log(LOG_MESSAGE, __LINE__, "> CURVECAPS %d", l);

            l = GetDeviceCaps(hdc, LINECAPS);
            Log(LOG_MESSAGE, __LINE__, "> LINECAPS %d", l);

            l = GetDeviceCaps(hdc, POLYGONALCAPS);
            Log(LOG_MESSAGE, __LINE__, "> POLYGONALCAPS %d", l);

            l = GetDeviceCaps(hdc, TEXTCAPS);
            Log(LOG_MESSAGE, __LINE__, "> TEXTCAPS %d", l);

            l = GetDeviceCaps(hdc, CLIPCAPS);
            Log(LOG_MESSAGE, __LINE__, "> CLIPCAPS %d", l);

            l = GetDeviceCaps(hdc, RASTERCAPS);
            Log(LOG_MESSAGE, __LINE__, "> RASTERCAPS %d", l);

            l = GetDeviceCaps(hdc, ASPECTX);
            Log(LOG_MESSAGE, __LINE__, "> ASPECTX %d", l);

            l = GetDeviceCaps(hdc, ASPECTY);
            Log(LOG_MESSAGE, __LINE__, "> ASPECTY %d", l);

            l = GetDeviceCaps(hdc, ASPECTXY);
            Log(LOG_MESSAGE, __LINE__, "> ASPECTXY %d", l);

            l = GetDeviceCaps(hdc, LOGPIXELSX);
            Log(LOG_MESSAGE, __LINE__, "> LOGPIXELSX %d", l);

            l = GetDeviceCaps(hdc, LOGPIXELSY);
            Log(LOG_MESSAGE, __LINE__, "> LOGPIXELSY %d", l);

            l = GetDeviceCaps(hdc, SIZEPALETTE);
            Log(LOG_MESSAGE, __LINE__, "> SIZEPALETTE %d", l);

            l = GetDeviceCaps(hdc, NUMRESERVED);
            Log(LOG_MESSAGE, __LINE__, "> NUMRESERVED %d", l);

            l = GetDeviceCaps(hdc, COLORRES);
            Log(LOG_MESSAGE, __LINE__, "> COLORRES %d", l);

            l = GetDeviceCaps(hdc, PHYSICALWIDTH);
            Log(LOG_MESSAGE, __LINE__, "> PHYSICALWIDTH %d", l);

            l = GetDeviceCaps(hdc, PHYSICALHEIGHT);
            Log(LOG_MESSAGE, __LINE__, "> PHYSICALHEIGHT %d", l);

            l = GetDeviceCaps(hdc, PHYSICALOFFSETX);
            Log(LOG_MESSAGE, __LINE__, "> PHYSICALOFFSETX %d", l);

            l = GetDeviceCaps(hdc, PHYSICALOFFSETY);
            Log(LOG_MESSAGE, __LINE__, "> PHYSICALOFFSETY %d", l);

            l = GetDeviceCaps(hdc, SCALINGFACTORX);
            Log(LOG_MESSAGE, __LINE__, "> SCALINGFACTORX %d", l);

            l = GetDeviceCaps(hdc, SCALINGFACTORY);
            Log(LOG_MESSAGE, __LINE__, "> SCALINGFACTORY %d", l);

            l = GetDeviceCaps(hdc, VREFRESH);
            Log(LOG_MESSAGE, __LINE__, "> VREFRESH %d", l);

            l = GetDeviceCaps(hdc, DESKTOPVERTRES);
            Log(LOG_MESSAGE, __LINE__, "> DESKTOPVERTRES %d", l);

            l = GetDeviceCaps(hdc, DESKTOPHORZRES);
            Log(LOG_MESSAGE, __LINE__, "> DESKTOPHORZRES %d", l);

            l = GetDeviceCaps(hdc, BLTALIGNMENT);
            Log(LOG_MESSAGE, __LINE__, "> BLTALIGNMENT %d", l);

            if (GetWinVer() >= 5)
            {
                l = GetDeviceCaps(hdc, SHADEBLENDCAPS);
                Log(LOG_MESSAGE, __LINE__, "> SHADEBLENDCAPS %d", l);

                l = GetDeviceCaps(hdc, COLORMGMTCAPS);
                Log(LOG_MESSAGE, __LINE__, "> COLORMGMTCAPS %d", l);
            }

            //*** device context layout
            DWORD dw = GetLayout(hdc);
            Log(LOG_MESSAGE, __LINE__, "Layout %u", dw);

            //*** printer to the default FONT
            HGDIOBJ hGdi = NULL;
            if ((hGdi = GetCurrentObject(hdc, OBJ_FONT)) != NULL)
            {
                int iBufferSize = GetObject(hGdi, 0, NULL);
                if (iBufferSize > 0)
                {
                    LOGFONT *pLogFont = (LOGFONT *)new char[iBufferSize];
                    if (pLogFont)
                    {
                        if (GetObject(hGdi, iBufferSize, pLogFont))
                        {
                            Log(LOG_MESSAGE, __LINE__, "DEFAULT FONT:");
                            Log(LOG_MESSAGE, __LINE__, "> Height %d", pLogFont->lfHeight);
                            Log(LOG_MESSAGE, __LINE__, "> Width %d", pLogFont->lfWidth);
                            Log(LOG_MESSAGE, __LINE__, "> Escapment %d", pLogFont->lfEscapement);
                            Log(LOG_MESSAGE, __LINE__, "> Orientation %d", pLogFont->lfOrientation);
                            Log(LOG_MESSAGE, __LINE__, "> Weight %d", pLogFont->lfWeight);
                            Log(LOG_MESSAGE, __LINE__, "> Italic %.2Xh", pLogFont->lfItalic);
                            Log(LOG_MESSAGE, __LINE__, "> Underline %.2Xh", pLogFont->lfUnderline);
                            Log(LOG_MESSAGE, __LINE__, "> StrikeOut %.2Xh", pLogFont->lfStrikeOut);
                            Log(LOG_MESSAGE, __LINE__, "> CharSet %.2Xh", pLogFont->lfCharSet);
                            Log(LOG_MESSAGE, __LINE__, "> OutPrecision %.2Xh", pLogFont->lfOutPrecision);
                            Log(LOG_MESSAGE, __LINE__, "> ClipPrecision %.2Xh", pLogFont->lfClipPrecision);
                            Log(LOG_MESSAGE, __LINE__, "> Quality %.2Xh", pLogFont->lfQuality);
                            Log(LOG_MESSAGE, __LINE__, "> PitchAndFamily %.2Xh", pLogFont->lfPitchAndFamily);
                            Log(LOG_MESSAGE, __LINE__, "> FaceName %s", pLogFont->lfFaceName);
                        }
                        delete[] pLogFont;
                    }
                    else
                    {
                        Log(LOG_DEBUG, __LINE__, "-- PtrInfo, new LOGFONT null");
                    }
                }
            }
            DeleteDC(hdc);
        }
        else
        {
            Log(LOG_DEBUG, __LINE__, "-- PtrInfo, CreateIC %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        }
    }   //END: for(int printerCnt=0;printerCnt<gpPrinterInfoList->num;printerCnt++)

    //release printer info list
    if (gpPrinterInfoList)
    {
        delete[] gpPrinterInfoList;
        gpPrinterInfoList = NULL;
    }

    LogElapsedTime(__LINE__, tickStart);

    Log(LOG_DEBUG, __LINE__, "<< PtrInfo");
    _endthreadex(0);
    return 0;
}

/*
** GetSystemIPAddresses: list all IP addresses in the system, if possible
*/
void GetSystemIPAddresses(MonitorIPs *monIps, bool bMonIps)
{
    Log(LOG_DEBUG, __LINE__, ">> GetSysIPAddrs, %p, %s", monIps, (bMonIps ? "True" : "False"));

    if (bMonIps && monIps)
    {
        uint64_t tickStart = SysTick();
        std::vector<std::string> ips;
        monIps->GetIPs(ips);

        if (ips.size())
        {
            Log(LOG_HEADER, __LINE__, "IP Addresses (%zu):", ips.size());

            for (unsigned int cnt = 0; cnt < ips.size(); cnt++)
            {
                Log(LOG_MESSAGE, __LINE__, "> %02u %s", cnt + 1, ips.at(cnt).c_str());
            }
        }

        LogElapsedTime(__LINE__, tickStart);
    }
    Log(LOG_DEBUG, __LINE__, "<< GetSysIPAddrs");
}

/******************************************************************************
*
*  MAIN APPLICATION FUNCTIONS
*
******************************************************************************/
/*
** GetSystemDetails: Base system information
*/
void GetSystemDetails(void)
{
    Log(LOG_DEBUG, __LINE__, ">> GetSysDets");

    /* Hardware Profile */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("HwProfile", HwProfile, NULL, MINUTE);
    }

    /* Computer */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("SysInfo", SystemInfo, NULL, MINUTE);
    }

    /* OSInfo */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("OSInfo", OSInfo, NULL, MINUTE);
    }

    /* Logical Processor(s) Information */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("SysLogPrcsrInfo", SystemLogicalProcessorInforamtion, NULL, MINUTE);
    }

    /* System Directories */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("SysDirs", SystemDirs, NULL, MINUTE);
    }

    Log(LOG_DEBUG, __LINE__, "<< GetSysDets");
}

/*
** GetSystemStatus: Performance system information
*/
void GetSystemStatus(void)
{
    Log(LOG_DEBUG, __LINE__, ">> GetSysSts");

    /* System Times */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("SysTimes", SystemTimes, NULL, MINUTE);
    }

    /* System Memory */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("SysMem", SystemMemory, NULL, MINUTE);
    }

    /* Performance Information */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("PerfInfo", PerformanceInfo, NULL, MINUTE);
    }

    /* Processes Informaton */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("ProcInfo", ProcessInfo, NULL, MINUTE);
    }

    if (_thGetInt(&gbShutdown) == FALSE)
    {
        SYSTEM_POWER_STATUS powerStatus{};
        if (GetSystemPowerStatus(&powerStatus))
        {
            Log(LOG_HEADER, __LINE__, "Power Status");
            Log(LOG_MESSAGE, __LINE__, "Line Status: [%.2Xh] %s", powerStatus.ACLineStatus, (powerStatus.ACLineStatus == 0 ? "Offline" : (powerStatus.ACLineStatus == 1 ? "Online" : "Unknown")));
            Log(LOG_MESSAGE, __LINE__, "Batery Flag: [%.2Xh] %s", powerStatus.BatteryFlag, (powerStatus.BatteryFlag == 1 ? "High" : (powerStatus.BatteryFlag == 2 ? "Low" : (powerStatus.BatteryFlag == 4 ? "Critical" : (powerStatus.BatteryFlag == 8 ? "Charging" : (powerStatus.BatteryFlag == 128 ? "No battery" : "Unknown"))))));
            Log(LOG_MESSAGE, __LINE__, "Life: %s%s", (powerStatus.BatteryLifePercent == 255 ? "Unknown" : std::to_string(static_cast<int>(powerStatus.BatteryLifePercent))), (powerStatus.BatteryLifePercent == 255 ? "" : "%"));
            Log(LOG_MESSAGE, __LINE__, "System Status: %s", (powerStatus.SystemStatusFlag == 0 ? "battery saver is off" : "battery saver is on"));
            Log(LOG_MESSAGE, __LINE__, "Battery Life Time: %s%s", (powerStatus.BatteryLifeTime == static_cast<DWORD>(-1) ? "Remaining unknown or" : std::to_string(powerStatus.BatteryLifeTime)), (powerStatus.BatteryLifeTime == static_cast<DWORD>(-1) ? " in AC." : "s"));
            Log(LOG_MESSAGE, __LINE__, "Battery Full Life Time: %s%s", (powerStatus.BatteryFullLifeTime == static_cast<DWORD>(-1) ? "Unknown or" : std::to_string(powerStatus.BatteryLifeTime)), (powerStatus.BatteryFullLifeTime == static_cast<DWORD>(-1) ? " in AC." : "s"));
        }
        else
        {
            Log(LOG_HEADER, __LINE__, "-- GetSysSts, GetSystemPowerStatus %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        }
    }

    Log(LOG_DEBUG, __LINE__, "<< GetSysSts");
}

/*
** GetSystemStatusChanges: Runtime changable system information
*/
void GetSystemStatusChanges(void)
{
    /* Logical Drivers */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("LogDrvs", LogicalDrives, NULL, MINUTE);
    }

    /* Enumerate USB */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("USB", ThreadUSB, NULL, MINUTE);
    }

    /* Device Drivers */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("DevDrvrs", DeviceDrivers, NULL, MINUTE);
    }

    /* Printers Information */
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("PtrInfo", PrinterInfo, NULL, MINUTE);
    }
}

/*
** GetWMIStatus
*/
//thread for system performance
unsigned WINAPI ThreadWMISystemPerformance(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> ThrdWMISysPerf (%p)", lpData);

    WMISystemPerformance();

    Log(LOG_DEBUG, __LINE__, "<< ThrdWMISysPerf");
    _endthreadex(0);
    return 0;
}

//thread for hardware sensor information
unsigned WINAPI ThreadWMIHardwareSensor(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> ThrdWMIHwSnsr (%p)", lpData);

    WMIHardwareSensor();

    Log(LOG_DEBUG, __LINE__, "<< ThrdWMIHwSnsr");
    _endthreadex(0);
    return 0;
}

//thread for all system volume details
unsigned WINAPI ThreadWMISystemVolumes(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> ThrdWMISysVols (%p)", lpData);

    WMISystemVolumes();

    Log(LOG_DEBUG, __LINE__, "<< ThrdWMISysVols");
    _endthreadex(0);
    return 0;
}

#ifdef _GET_WMI_USBINFO
//thread for all system usb details
unsigned WINAPI ThreadWMISystemUsb(LPVOID lpData)
{
    Log(LOG_DEBUG, __LINE__, ">> ThrdWMISysUsb (%p)", lpData);

    WMISystemUsb();

    Log(LOG_DEBUG, __LINE__, "<< ThrdWMISysUsb");
    _endthreadex(0);
    return 0;
}
#endif

void GetWMIStatus(void)
{
    Log(LOG_DEBUG, __LINE__, ">> GetWMISts");

    //get system performance
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("WMISysPerf", ThreadWMISystemPerformance, nullptr, MINUTE * 5);
    }

    //get hardware sensor information
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("WMIHwSnsr", ThreadWMIHardwareSensor, nullptr, MINUTE * 5);
    }

    //get all system volume details
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("WMISysVols", ThreadWMISystemVolumes, nullptr, MINUTE * 5);
    }

#ifdef _GET_WMI_USBINFO
    //get all system usb details
    if (_thGetInt(&gbShutdown) == FALSE)
    {
        StartThread("WMISysUsb", ThreadWMISystemUsb, nullptr, MINUTE * 5);
    }
#endif
    Log(LOG_DEBUG, __LINE__, "<< GetWMISts");
}

bool ModifyPrivilege(const char* privilegeName, bool enable)
{
    Log(LOG_DEBUG, __LINE__, ">> ModifyPrivilege: %s '%s'", (enable ? "Enable" : "Disable"), privilegeName);

    HANDLE processToken = nullptr;
    if (!::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken))
    {
        Log(LOG_DEBUG, __LINE__, "<< ModifyPrivilege, OpenProcessToken %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        return false;
    }

    TOKEN_PRIVILEGES token{};
    token.PrivilegeCount = 1;
    token.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : 0);
    ::LookupPrivilegeValue(NULL, privilegeName, &token.Privileges[0].Luid);

    if (!::AdjustTokenPrivileges(processToken, FALSE, &token, 0, nullptr, 0))
    {
        Log(LOG_DEBUG, __LINE__, "<< ModifyPrivilege, AdjustTokenPrivileges %s", dgi::win_error_code_to_str(GetLastError()).c_str());
        CloseHandle(processToken);
        return false;
    }

    CloseHandle(processToken);
    Log(LOG_DEBUG, __LINE__, "<< ModifyPrivilege");
    return true;
}

void AdjustProcessRights()
{
    Log(LOG_DEBUG, __LINE__, ">> AdjtProcRights");

    // Before adjusting any rights, we need to ensure we have the correct privileges required
    if (ModifyPrivilege(SE_SECURITY_NAME, true))
    {
        PACL currentDacl = nullptr;
        PACL newDacl = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;

        auto _sd_ = gsl::finally([&securityDescriptor]() {
            if (securityDescriptor)
                ::LocalFree(securityDescriptor);
        });

        auto _dacl_ = gsl::finally([&newDacl]() {
            if (newDacl)
                ::LocalFree(newDacl);
        });

        try
        {
            // Adjust the DACL of our process to allow any other process to synchronize on our handle (including DbdDevApi)
            HANDLE processHandle = ::OpenProcess(ACCESS_SYSTEM_SECURITY | WRITE_DAC, FALSE, GetCurrentProcessId());
            if (!processHandle)
            {
                throw std::runtime_error(dgi::win_error_code_to_str(GetLastError()));
            }

            auto _prochandle_ = gsl::finally([&processHandle]() {
                CloseHandle(processHandle);
            });

            // Get the current DACL of the process
            DWORD rc = ::GetSecurityInfo(processHandle, SE_KERNEL_OBJECT, SACL_SECURITY_INFORMATION, nullptr, nullptr, &currentDacl, nullptr, &securityDescriptor);
            if (rc != ERROR_SUCCESS)
            {
                throw std::runtime_error(dgi::win_error_code_to_str(GetLastError()));
            }

            // Ensure that 'Everyone' has the synchronize permission.  Use the SID instead of the name to support localization
            DWORD sidSize = SECURITY_MAX_SID_SIZE;
            std::vector<unsigned char> sidBuffer(sidSize);
            if (!::CreateWellKnownSid(WinWorldSid, nullptr, sidBuffer.data(), &sidSize))
            {
                throw std::runtime_error(dgi::win_error_code_to_str(GetLastError()));
            }

            // Create the structure that defines the required permission
            EXPLICIT_ACCESS explicitAccess = { 0 };
            explicitAccess.grfAccessMode = GRANT_ACCESS;
            explicitAccess.grfAccessPermissions = SYNCHRONIZE;
            explicitAccess.grfInheritance = NO_INHERITANCE;
            ::BuildTrusteeWithSid(&explicitAccess.Trustee, sidBuffer.data());

            // Add the synchronize permission to the current DACL
            rc = ::SetEntriesInAcl(1, &explicitAccess, currentDacl, &newDacl);
            if (rc != ERROR_SUCCESS)
            {
                throw std::runtime_error(dgi::win_error_code_to_str(GetLastError()));
            }

            // Update our process handle with the new DACL
            rc = ::SetSecurityInfo(processHandle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
            if (rc != ERROR_SUCCESS)
            {
                throw std::runtime_error(dgi::win_error_code_to_str(GetLastError()));
            }

            Log(LOG_DEBUG, __LINE__, "-- AdjtProcRights, Successfully adjusted the process rights.");
        }
        catch (const std::runtime_error& ex)
        {
            Log(LOG_DEBUG, __LINE__, "-- AdjtProcRights, %s", ex.what());
        }

        // Remove the privilege as it is no longer required
        ModifyPrivilege(SE_SECURITY_NAME, false);
    }
    Log(LOG_DEBUG, __LINE__, "<< AdjtProcRights");
}

std::string NetworkAliveType(DWORD const dwNetType)
{
    std::string str{ "" };

    if (dwNetType & NETWORK_ALIVE_LAN)
        str += ".LAN";

    if (dwNetType & NETWORK_ALIVE_WAN)
        str += ".WAN";

    if (dwNetType & NETWORK_ALIVE_AOL)
        str += ".AOL";

    if (dwNetType & NETWORK_ALIVE_INTERNET)
        str += ".INTERNET";

    str += ".";
    return str;
}

std::string GetAppVersion()
{
    DWORD dwVersionLength = 0;
    DWORD dwVersionHandle = 0;
    DWORD dwBytes = 0;
    VS_FIXEDFILEINFO *lpFixedFileInfo = NULL;

    dwVersionLength = GetFileVersionInfoSize("SysStatus.exe", &dwVersionHandle);

    char szVersion[_MAX_PATH]{};
    if (dwVersionLength > 0)
    {
        std::vector<char> version(dwVersionLength);
        if (GetFileVersionInfo("SysStatus.exe", dwVersionHandle, dwVersionLength, &version[0]))
        {
            if (VerQueryValue(version.data(), TEXT("\\"), (void**)&lpFixedFileInfo, (PUINT)&dwBytes))
            {
                _snprintf(szVersion, sizeof(szVersion) - 1, "%u.%u.%u.%u",
                    HIWORD(lpFixedFileInfo->dwFileVersionMS),
                    LOWORD(lpFixedFileInfo->dwFileVersionMS),
                    HIWORD(lpFixedFileInfo->dwFileVersionLS),
                    LOWORD(lpFixedFileInfo->dwFileVersionLS));
            }
            else
            {
                _snprintf(szVersion, sizeof(szVersion) - 1, "0.0.0.0");
            }
        }
        else
        {
            _snprintf(szVersion, sizeof(szVersion) - 1, "0.0.0.0");
        }
    }
    else
    {
        _snprintf(szVersion, sizeof(szVersion) - 1, "0.0.0.0");
    }

#ifdef _DEBUG
    _snprintf(szVersion, sizeof(szVersion) - 1, "%s - DEBUG", szVersion);
#endif
    return std::string(szVersion);
}

/*
** WinMain: Main program function
*/
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    _start_ = static_cast<uint64_t>(dgi::get_tick_epoch_count());
    auto _run_time_ = gsl::finally([] {
        uint64_t const _end_ = static_cast<uint64_t const>(dgi::get_tick_epoch_count()) - _start_;
        Log(LOG_MESSAGE, __LINE__, "%.9f s", (static_cast<double>(_end_) / 1'000'000'000));
    });

    HANDLE hThreadWMI = nullptr;
    HANDLE hThreadMSG = nullptr;
    DWORD dwTimer = (MINUTE * 5);       //default 5 minutes
    DWORD dwRet = 0;
    DWORD dwLogSize = (MBYTES * 5);     //default 5 MB

    uint64_t ui64Wait = 0;

    DWORD dwNetType = 0;
    BOOL bNet = FALSE;

    bool bShowWindow = true;
    bool bRunWMI = false;
    bool bRunOnce = false;
    bool bWMIThreadRunning = false;
    bool bAppendLog = false;

    //LPTOP_LEVEL_EXCEPTION_FILTER pPreviousExceptionFilter = SetUnhandledExceptionFilter(AppUnhandledExceptionFilter);
    static_cast<void>(SetUnhandledExceptionFilter(AppUnhandledExceptionFilter));
    RedirectSetUnhandledExceptionFilter();

    ghInstance = hInstance;

    //check whether or not it to run once
    if (lpCmdLine)
    {
        //convert command line to be checked
        _strlwr(lpCmdLine);

        //check whether the app should run only once
        if (strstr(lpCmdLine, "runonce") != NULL)
        {
            bRunOnce = true;
        }
        else
        {
            bRunOnce = false;
        }

        //check whether the app should get information details about the system thru WMI
        if (strstr(lpCmdLine, "sysinfo") != NULL)
        {
            bRunWMI = true;
        }
        else
        {
            bRunWMI = false;
        }

        //check whether the app should not show the window
        if (strstr(lpCmdLine, "nowindow") != NULL)
        {
            bShowWindow = false;
        }

        //check the wait time between exeutions
        char *timer = strstr(lpCmdLine, "timer");
        if (timer)
        {
            timer += 6;
            dwTimer = (DWORD)atoi(timer);

            //timer from 1 to 360 minutes for checking the system status
            DWORD minTimer = 1, maxTimer = 360;
            if (dwTimer >= minTimer && dwTimer <= maxTimer)
            {
                dwTimer *= MINUTE;      //number of minutes specified in milliseconds
            }
        }

        //check the wait time between exeutions
        char *logsize = strstr(lpCmdLine, "logsize");
        if (logsize)
        {
            logsize += 8;
            dwLogSize = (DWORD)(atoi(logsize)*KBYTES);
            //maximum log file size should be 25 MB
            if (dwLogSize > (MBYTES * 25))
            {
                dwLogSize = (MBYTES * 25);
            }
        }

        //check the wait time between exeutions
        if (strstr(lpCmdLine, "appendlog"))
        {
            bAppendLog = true;
        }

        char *logdir = strstr(lpCmdLine, "logdir");
        if (logdir)
        {
            //remove 'logdir:'
            logdir += 7;

            //add '\' if last by doesn't
            if (strlen(logdir) > 0)
            {
                if (logdir[strlen(logdir) - 1] != '\\')
                {
                    _snprintf(gszLogFilePrefix, sizeof(gszLogFilePrefix) - 1, "%s\\SysStatus", logdir);
                }
                else
                {
                    _snprintf(gszLogFilePrefix, sizeof(gszLogFilePrefix) - 1, "%sSysStatus", logdir);
                }
            }
            else
            {
                //get log file prefix
                if (GetModuleBaseName(GetCurrentProcess(), NULL, gszLogFilePrefix, sizeof(gszLogFilePrefix)) > 0)
                {
                    //remove log file extension
                    PathRemoveExtension(gszLogFilePrefix);
                }
                else
                {
                    //copy default name
                    strcpy(gszLogFilePrefix, "SysStatus");
                }
            }
        }
        else
        {
            //get log file prefix
            if (GetModuleBaseName(GetCurrentProcess(), NULL, gszLogFilePrefix, sizeof(gszLogFilePrefix)) > 0)
            {
                //remove log file extension
                PathRemoveExtension(gszLogFilePrefix);
            }
            else
            {
                //copy default name
                strcpy(gszLogFilePrefix, "SysStatus");
            }
        }
    }

    gTickStart = SysTick();
    //start new log
    CheckLogFileSize(bAppendLog ? dwLogSize : 0UL);

    Log(LOG_DEBUG, __LINE__, ">> WinMain");

    Log(LOG_HEADER, __LINE__, "SysStatus (Version %s), CmdLine %s", GetAppVersion().c_str(), lpCmdLine);

    PendingThreads.clear();

    AdjustProcessRights();

    //Start window thread
    StartThread("ThrdMsg", ThreadMessage, &bShowWindow, 0, &hThreadMSG);

    if (bRunWMI)
    {
        //Start WMI main thread
        bWMIThreadRunning = StartThread("ThrWMI", ThreadWMI, NULL, 0, &hThreadWMI);
    }

    //Start IPs monitor
    MonitorIPs monIps;
    bool bMonIps = monIps.Initialize();

    if ((bRunOnce == false) || (bRunOnce == true && bWMIThreadRunning == true))
    {
        //get unchangeable system information
        GetSystemDetails();

        //get runtime changeable system information
        GetSystemStatusChanges();

        //get IPs if possible
        GetSystemIPAddresses(&monIps, bMonIps);
    }

    double timeElapsed{};
    uint64_t seconds{};
    uint64_t tickEnd{};
    char wndText[_MAX_PATH]{};

    //run while:
    // 1. close or end session has been requested AND 
    //    running mode is continuous
    // OR
    // 2. close or end session has been requested AND 
    //    running mode is simple AND
    //    WMI thread is still running
    while (_thGetInt(&gbTerminate) == FALSE &&
        ((bRunOnce == false) || (bRunOnce == true && bWMIThreadRunning == true))
        )
    {
        if (bRunWMI)
        {
            if (WaitForSingleObject(hThreadWMI, (MILLISECOND * 100)) == WAIT_TIMEOUT)
            {
                bWMIThreadRunning = true;
            }
            else
            {
                bWMIThreadRunning = false;
            }
        }

        if (ui64Wait > SysTick() && _thGetInt(&gbForceChecking) == FALSE)
        {
            //Wait a second and then continue
            Sleep(SECOND);
            continue;
        }

        if (_thGetInt(&gbForceChecking) == TRUE)
        {
            //get runtime changeable system information
            GetSystemStatusChanges();

            //stop force checking
            _thSetInt(&gbForceChecking, FALSE);
        }

        //get system information
        GetSystemStatus();

        //get WMI status information if WMI system info thread has been completed
        if (!bWMIThreadRunning && bRunWMI)
        {
            //get WMI status information
            GetWMIStatus();
        }

        //Is network alive?
        bNet = IsNetworkAlive(&dwNetType);
        dwRet = GetLastError();

        //Was function executed successfully?
        if (ERROR_SUCCESS == dwRet)
        {
            Log(LOG_HEADER, __LINE__, "Net Alive? %s, Type 0x%X(%s)", (bNet ? "Yes" : "No"), dwNetType, NetworkAliveType(dwNetType).c_str());
        }
        else
        {
            Log(LOG_HEADER, __LINE__, "Net Chkg %s", dgi::win_error_code_to_str(dwRet).c_str());
        }

        //Get IPs if possible and changed
        if (monIps.IsChanged())
        {
            GetSystemIPAddresses(&monIps, bMonIps);
        }

        CalcElapsedTime(gTickStart, tickEnd, timeElapsed, seconds);
        Log(LOG_DEBUG, __LINE__, "-- %02llu:%02llu:%02llu, %.3f s", seconds / 3600, (seconds % 3600) / 60, seconds % 60, timeElapsed);

        if (bShowWindow)
        {
            //Update the window name with the time app is running
            memset(wndText, 0x00, sizeof(wndText));
            _snprintf(wndText, sizeof(wndText) - 1, "SysStatus - Running for %02llu:%02llu", seconds / 3600, (seconds % 3600) / 60);
            SetWindowText(ghWnd, (LPCTSTR)wndText);
        }

        //check de log file size
        CheckLogFileSize(dwLogSize);

        //set timer for next checking
        ui64Wait = SysTick() + dwTimer;
    }   //END: while(_thGetInt(&gbTerminate)==FALSE && bRunOnce==false)

    //wait for WMI Ascii thread completion
    if (hThreadWMI)
    {
        if (bRunOnce)
        {
            //wait until it is completed
            WaitForSingleObject(hThreadWMI, INFINITE);
        }
        else
        {
            //quickly wait while the thread has not completed
            //and, when timeout is completed, force terminate
            //the WMI thread if the thread is still runing
            if (WaitForSingleObject(hThreadWMI, (MINUTE * 10)) == WAIT_TIMEOUT)
            {
                EndPendingThread(hThreadWMI);
            }
        }
        CloseHandle(hThreadWMI);
    }

    //get unchangeable system information
    GetSystemDetails();

    //get runtime changeable system information
    GetSystemStatusChanges();

    //get IPs if possible
    GetSystemIPAddresses(&monIps, bMonIps);

    //get system information
    GetSystemStatus();

    if (bRunWMI || bRunOnce)
    {
        //get WMI status information
        GetWMIStatus();
    }

    //Close window
    if (ghWnd)
    {
        PostMessage(ghWnd, TERMINATE_WINDOW_MSG, 0, 0);
        Log(LOG_DEBUG, __LINE__, "-- WinMain, Wait ThrdMsg %u", WaitForSingleObject(hThreadMSG, MINUTE));
        CloseHandle(hThreadMSG);
    }

    //force terminate all pending threads
    if (!PendingThreads.empty())
    {
        Log(LOG_DEBUG, __LINE__, "-- WinMain, Remvg %zu pending thds", PendingThreads.size());

        for (auto const thread : PendingThreads)
        {
            if (WaitForSingleObject(thread, (MILLISECOND * 2)) == WAIT_TIMEOUT)
            {
                EndPendingThread(thread);
            }
            CloseHandle(thread);
        }
    }

    //SetUnhandledExceptionFilter(pPreviousExceptionFilter);
    LogElapsedTime(__LINE__, gTickStart, "SysStatus");
    return 0;
}
