/*--
The MIT License (MIT)

Copyright (c) 2010-2013 De Giuli Informática Ltda. (http://www.degiuli.com.br)

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

BOOL gbTerminate = FALSE;       //to indicate the application end has been requested
BOOL gbShutdown = FALSE;        //to indicate the system session is ending
HWND ghWnd = NULL;
HINSTANCE ghInstance = NULL;
BOOL gbForceChecking = FALSE;

char gszLogFilePrefix[1024] = {0};
unsigned __int64 gTickStart = 0;

vector<HANDLE> PendingThreads;

/******************************************************************************
*
*  AUXILIARY FUNCTIONS
*
******************************************************************************/
/*
** Thread safe processing functions
*/
void _thSetInt(int *piProtectedVar,int iValue)
{
    char sMember[100]={0};
    HANDLE hdTh =0;

    if (!piProtectedVar)
        return;

    _snprintf(sMember,sizeof(sMember)-1,"%p",(int)piProtectedVar);
    hdTh = CreateMutex(NULL,FALSE,sMember);
    WaitForSingleObject(hdTh,INFINITE);

    *piProtectedVar = iValue;

    ReleaseMutex(hdTh);
    CloseHandle (hdTh);
}
int _thGetInt(int *piProtectedVar)
{
    //retorna uma copia int do valor do endereco da variavel recebida. 
    //Garante a integridade da variavel durante processamento multithread.

    int iRetVal;
    char sMember[100]={0};
    HANDLE hdTh =0;

    if(!piProtectedVar)
        return 0;

    _snprintf(sMember,sizeof(sMember)-1,"%p",(int)piProtectedVar);
    hdTh = CreateMutex(NULL,FALSE,sMember);
    WaitForSingleObject(hdTh,INFINITE);

    iRetVal = *piProtectedVar;

    ReleaseMutex(hdTh);
    CloseHandle(hdTh);

    return iRetVal;
}

/*
** DebugStringToFile: save debug details in the trace file
*/
void DebugStringToFile(char *message,int typeDebug)
{
    if(typeDebug&LOG_DEBUG_ALL)
    {
        HANDLE hdTh = CreateMutex(NULL,FALSE,"SysStatus_Trace");
        WaitForSingleObject(hdTh,INFINITE);

        char line[3000] = {0};
        char extension[4] = {0};

        if(typeDebug&LOG_DEBUG)
        {
            strncpy(extension,"dbg",3);
        }
        else if(typeDebug&LOG_DEBUG_WND)
        {
            strncpy(extension,"wnd",3);
        }
        else if(typeDebug&LOG_DEBUG_WMI)
        {
            strncpy(extension,"wmi",3);
        }

        SYSTEMTIME stLocalTime = {0};
        GetLocalTime( &stLocalTime );

        _snprintf(line,sizeof(line),"%.4d-%.2d-%.2d %.2d:%.2d:%.2d.%.3d PID %.5u %s",
                       stLocalTime.wYear,stLocalTime.wMonth,stLocalTime.wDay,stLocalTime.wHour,
                       stLocalTime.wMinute,stLocalTime.wSecond,stLocalTime.wMilliseconds,
                       GetCurrentProcessId(),message);

        DWORD dwBytesWritten = 0;
        char logFile[1024] = {0};
        _snprintf(logFile,sizeof(logFile),"%s.%s",gszLogFilePrefix,extension);

        while(true)
        {
            HANDLE hTraceFile = CreateFile(logFile,
                                           GENERIC_READ|GENERIC_WRITE,
                                           FILE_SHARE_READ|FILE_SHARE_WRITE,
                                           NULL,
                                           OPEN_ALWAYS,
                                           FILE_ATTRIBUTE_NORMAL,
                                           NULL);
            if(hTraceFile!=INVALID_HANDLE_VALUE)
            {
                //Set position o the end of the file
                DWORD dwFileSize = GetFileSize(hTraceFile,NULL);
                if(dwFileSize>(MBYTES*9))
                {
                    CloseHandle(hTraceFile);
                    hTraceFile = INVALID_HANDLE_VALUE;

                    char oldFile[1024] = {0};
                    _snprintf(oldFile,sizeof(oldFile),"%s.%s_old",gszLogFilePrefix,extension);

                    //remove old file
                    remove((const char*)oldFile);
                    rename((const char*)logFile,(const char*)oldFile);
                }
                else
                {
                    SetFilePointer(hTraceFile,0,NULL,FILE_END);
                    WriteFile(hTraceFile,line,strlen(line),&dwBytesWritten,NULL); 
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
void Log(int type,int id,const char*format,...)
{
    char message[3000] = {0};
    char buffer[2048] = {0};
    va_list	argptr;

    HANDLE hdTh = CreateMutex(NULL,FALSE,"SysStatus_Log");
    WaitForSingleObject(hdTh,INFINITE);

    //Format the message to be logged
    va_start(argptr,format);
    _vsnprintf(buffer,sizeof(buffer)-1,format,argptr);
    va_end(argptr);

    //Format log string according to the type
    if(type==LOG_HEADER)
    {
        SYSTEMTIME stLocalTime = {0};
        GetLocalTime( &stLocalTime );

        _snprintf(message,sizeof(message),"\r\n%.4d-%.2d-%.2d %.2d:%.2d:%.2d.%.3d PID %.5u TID %.5u ID %.5u\r\n%s\r\n",
                  stLocalTime.wYear,stLocalTime.wMonth,stLocalTime.wDay,stLocalTime.wHour,
                  stLocalTime.wMinute,stLocalTime.wSecond,stLocalTime.wMilliseconds,
                  GetCurrentProcessId(),GetCurrentThreadId(),id,buffer);
    }
    if(type==LOG_MESSAGE)
    {

        _snprintf(message,sizeof(message),"\t%s\r\n",buffer);
    }

    //if not debug, trace in the file
    if(!(type&LOG_DEBUG_ALL))
    {
	    DWORD dwBytesWritten = 0;
        char logFile[1024] = {0};
        _snprintf(logFile,sizeof(logFile),"%s.log",gszLogFilePrefix);
        HANDLE hTraceFile = CreateFile(logFile,
                                       GENERIC_READ|GENERIC_WRITE,
                                       FILE_SHARE_READ|FILE_SHARE_WRITE,
                                       NULL,
                                       OPEN_ALWAYS,
                                       FILE_ATTRIBUTE_NORMAL,
                                       NULL);
	    if(hTraceFile!=INVALID_HANDLE_VALUE)
	    {
            //Set position o the end of the file
            SetFilePointer(hTraceFile,0,NULL,FILE_END);
		    WriteFile(hTraceFile,message,strlen(message),&dwBytesWritten,NULL); 
		    CloseHandle(hTraceFile);
	    }
    }
    _snprintf(message,sizeof(message),"TID %.5u ID %.5u %s\r\n",GetCurrentThreadId(),id,buffer);

    ReleaseMutex(hdTh);
    CloseHandle(hdTh);

    //Trace on debug view
    DebugStringToFile(message,type);
}

/*
** CheckLogFileSize: Check the log file size and create backups when limit is reached
*/
void CheckLogFileSize(DWORD dwMaxSize)
{
    HANDLE hTraceFile = NULL;
    DWORD dwFileSize = 0;

    Log(LOG_DEBUG,__LINE__,">> ChkLogFileSz, %u",dwMaxSize);

    HANDLE hdTh = CreateMutex(NULL,FALSE,"SysStatus_Log");
    WaitForSingleObject(hdTh,INFINITE);

    if(dwMaxSize>0)
    {
        char logFile[1024] = {0};
        _snprintf(logFile,sizeof(logFile),"%s.log",gszLogFilePrefix);

        DWORD dwBytesWritten = 0;
        Log(LOG_DEBUG,__LINE__,"-- ChkLogFileSz, Opng %s",logFile);
        hTraceFile = CreateFile(logFile,
                                GENERIC_READ|GENERIC_WRITE,
                                FILE_SHARE_READ|FILE_SHARE_WRITE,
                                NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);
        if(hTraceFile!=INVALID_HANDLE_VALUE)
        {
            //Set position o the end of the file
            SetFilePointer(hTraceFile,0,NULL,FILE_END);
	        dwFileSize = GetFileSize(hTraceFile,NULL);
            Log(LOG_DEBUG,__LINE__,"-- ChkLogFileSz, %s Sz %u",logFile,dwFileSize);
	        CloseHandle(hTraceFile);
            hTraceFile = NULL;
        }
    }
    
    //check whether the file size reached the limit
    //or it is inicialization - to start new run in new file
    if(dwFileSize>dwMaxSize || dwMaxSize==0)
    {
        //find the last file
        int x;
        for(x=999;x>=0;x--)
        {
            char temp[_MAX_PATH] = {0};
            _snprintf(temp,sizeof(temp),"%s.%.3d",gszLogFilePrefix,x);
            Log(LOG_DEBUG,__LINE__,"-- ChkLogFileSz, Trying opng %s",temp);
            hTraceFile = CreateFile(temp,GENERIC_READ|GENERIC_WRITE,
                                          FILE_SHARE_READ|FILE_SHARE_WRITE,
                                          NULL,
                                          OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL,
                                          NULL);
            if(hTraceFile!=INVALID_HANDLE_VALUE)
            {
                Log(LOG_DEBUG,__LINE__,"-- ChkLogFileSz, Last file fnd: %s",temp);
                CloseHandle(hTraceFile);
                hTraceFile = NULL;

                //all file were filled, removed the last one
                if(x==999) {
                    Log(LOG_DEBUG,__LINE__,"-- ChkLogFileSz, Removing %s - oldest file",temp);
                    remove((char*)temp);
                }

                break;      //last one was found
            }
        }

        //rename the last one to the previous
        char newFile[_MAX_PATH] = {0};
        char oldFile[_MAX_PATH] = {0};
        for(;x>=0;x--)
        {
            //rename the <.xxx> to .<xxx+1>
            _snprintf(newFile,sizeof(newFile),"%s.%.3d",gszLogFilePrefix,x+1);
            _snprintf(oldFile,sizeof(oldFile),"%s.%.3d",gszLogFilePrefix,x);

            Log(LOG_DEBUG,__LINE__,"-- ChkLogFileSz, Renaming %s -> %s",oldFile,newFile);
            rename((const char*)oldFile,(const char*)newFile);
        }

        //rename the .log to .000
        _snprintf(newFile,sizeof(newFile),"%s.000",gszLogFilePrefix);
        _snprintf(oldFile,sizeof(oldFile),"%s.log",gszLogFilePrefix);
        Log(LOG_DEBUG,__LINE__,"-- ChkLogFileSz, Remaning %s -> %s",oldFile,newFile);
        rename((const char*)oldFile,(const char*)newFile);
    }

    ReleaseMutex(hdTh);
    CloseHandle(hdTh);
    Log(LOG_DEBUG,__LINE__,"<< ChkLogFileSz");
}

/*
** GetLastErrorMessage: get the text message for the last error code
*/
char * GetLastErrorMessage(DWORD dwLastError, char * lpBuffer, DWORD nSize)
{
    HMODULE hModule = NULL; //default to system source

    DWORD dwFormatFlags = FORMAT_MESSAGE_IGNORE_INSERTS |
                          FORMAT_MESSAGE_FROM_SYSTEM;

    //if dwErrorCode is in the network range, load the message source.
    if ((dwLastError >= NERR_BASE) && (dwLastError <= MAX_NERR))
        hModule = LoadLibraryEx("netmsg.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);

    if (hModule != NULL)
        dwFormatFlags |= FORMAT_MESSAGE_FROM_HMODULE;

    //call FormatMessage() to allow for message text to be acquired
    //from the system or from the supplied module handle.
    if (FormatMessage(dwFormatFlags, hModule, dwLastError,
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //default language
                      lpBuffer, nSize, NULL))
	{
		if(strlen(lpBuffer) > 2)
			lpBuffer[strlen(lpBuffer) - 2] = NULL;	//over-write the newline char
		else
			lpBuffer[0] = NULL;						//set first char to null
	}
	else
	{
		//set first char to null
		lpBuffer[0] = NULL;
	}

    //if we loaded a message source, unload it.
    if (hModule != NULL)
        FreeLibrary(hModule);

	return lpBuffer;
}

/*
** USBTraceInfo: Trace USB device information
*/
void USBTraceInfo(PCHAR StartString, PCHAR DeviceInterfaceName)
{
	PCHAR	pVendorID = NULL;
	PCHAR	pProductID = NULL;
	PCHAR	pSerial = NULL;
	PCHAR	pName = NULL;
	PCHAR	pTmp = NULL;

	pName = (PCHAR)malloc(strlen(DeviceInterfaceName)+1);
    if(pName)
    {
        memset(pName,0x00,(strlen(DeviceInterfaceName)+1));
	    strcpy(pName,DeviceInterfaceName);
    		
	    // Get Vid value
	    if (pVendorID = strchr (pName, 'V'))
	    {
		    pVendorID += 4;
    		
		    // Get Pid value
		    if (pProductID = strchr (pVendorID, 'P'))
		    {
			    pProductID += 4;
	            pTmp = pVendorID+4;
			    *pTmp = 0;
    	
			    //Get SerialId value
			    if (pSerial = strchr (pProductID, '#'))
			    {
				    *pSerial = 0;
				    pTmp = ++pSerial;
				    while((*pTmp) && (*pTmp != '#'))
					    pTmp++;
				    *pTmp = 0;
			    }
		    }
            USHORT vendorId = 0;
            for(int x=0;x<4;x++)
            {
                USHORT us = 0;
                if(isdigit(pVendorID[x]))
                    us = (USHORT)(pVendorID[x]-0x30);
                else
                    us = (USHORT)(pVendorID[x]-0x37);
                vendorId += (USHORT)(us<<(3-x)*4);
            }
            Log(LOG_MESSAGE,__LINE__,"%s [VID:%s PID:%s SN:%s] %s",StartString, pVendorID, pProductID, pSerial, USB::GetVendorString(vendorId));
	    }
    	free(pName);
    }
    else
    {
        Log(LOG_DEBUG,__LINE__,"-- New DeviceName null");
    }
}

/*
** GUID2Str: Convert GUID structu to LPSTR pointer
** -> {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
*/
LPSTR GUID2Str(LPGUID lpGuid, LPSTR lpStr, unsigned int maxLenght)
{
    if(!lpGuid || !lpStr)
    {
        return NULL;
    }

    if(maxLenght<50)
    {
        return NULL;
    }

    LPBYTE data = NULL;
    int x = 0, i = 0;

    lpStr[x++] = '{';
    data = (LPBYTE)&lpGuid->Data1;

    //cChar = ((*(lpBufBin+ulIndex)) >> 4) & 0x0f;
    //*(lpszBufStr+2*ulIndex) = cChar + 0x30;
    //cChar = (*(lpBufBin+ulIndex)) & 0x0f;
    //*(lpszBufStr+2*ulIndex+1) = cChar + 0x30;

    sprintf(&lpStr[x],"%.2X",data[3]);
    x += 2;
    sprintf(&lpStr[x],"%.2X",data[2]);
    x += 2;
    sprintf(&lpStr[x],"%.2X",data[1]);
    x += 2;
    sprintf(&lpStr[x],"%.2X",data[0]);
    x += 2;
    lpStr[x++] = '-';

    data = (LPBYTE)&lpGuid->Data2;
    sprintf(&lpStr[x],"%.2X",data[1]);
    x += 2;
    sprintf(&lpStr[x],"%.2X",data[0]);
    x += 2;
    lpStr[x++] = '-';

    data = (LPBYTE)&lpGuid->Data3;
    sprintf(&lpStr[x],"%.2X",data[1]);
    x += 2;
    sprintf(&lpStr[x],"%.2X",data[0]);
    x += 2;
    lpStr[x++] = '-';

    sprintf(&lpStr[x],"%.2X",lpGuid->Data4[0]);
    x += 2;
    sprintf(&lpStr[x],"%.2X",lpGuid->Data4[1]);
    x += 2;
    lpStr[x++] = '-';

    for(i=2;i<8;i++)
    {
        sprintf(&lpStr[x],"%.2X",lpGuid->Data4[i]);
        x += 2;
    }
    lpStr[x++] = '}';

    return lpStr;
}

/*
** parseNullTerminatedStrings:	Parse list of null terminated strings, which ends with double-null
*/
void parseNullTerminatedStrings(char* input, vector<string> &stringsList)
{
    //vector<string> result;
    int nullCount = 0, possibleStringInit = 0;
    char *p = NULL;

    for(int i=0;nullCount<2;i++)
    {
        if(input[i]==0)
        {
            nullCount++;
            possibleStringInit = i + 1;
            if(p!=NULL)
            {
                string aux(p);
                //result.push_back(aux);
                stringsList.push_back(aux);
            }
            p = NULL;
            continue;
        }
        if(p==NULL)
        {
            nullCount=0;
            p = &input[possibleStringInit];
        }
    }
    return; //result;
}

/*
** ReportAttemptsToSetUnhandledExceptionFilter
*/
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI ReportAttemptsToSetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
	Log(LOG_DEBUG,__LINE__,"-- Prevented attempt to set unhandled exception filter. lpTopLevelExceptionFilter: 0x%p", lpTopLevelExceptionFilter);
	return NULL;
}

/*
** RedirectSetUnhandledExceptionFilter
*/
BOOL RedirectSetUnhandledExceptionFilter()
{
	HMODULE hKernel32 = LoadLibrary("kernel32.dll");
	if (hKernel32 == NULL) 
		return FALSE;

	void *pOriginalFunc = GetProcAddress(hKernel32, "SetUnhandledExceptionFilter");
	if (pOriginalFunc == NULL) 
		return FALSE;

	DWORD dwOriginalAddr = (DWORD) pOriginalFunc;
	dwOriginalAddr += 5; // add 5 for 5 op-codes for jmp far

	void *pDecoyFunc = &ReportAttemptsToSetUnhandledExceptionFilter;
	DWORD dwDecoyAddr = (DWORD) pDecoyFunc;
	DWORD dwRelativeAddr = dwDecoyAddr - dwOriginalAddr;

	unsigned char jump[ 100 ];
	jump[ 0 ] = 0xE9;  // JMP absolute
	memcpy(&jump[ 1 ], &dwRelativeAddr, sizeof(pDecoyFunc));
	SIZE_T bytesWritten;

	BOOL bRet = WriteProcessMemory(GetCurrentProcess(), pOriginalFunc, jump, sizeof(pDecoyFunc) + 1, &bytesWritten);

	return bRet;
}

/*
** CreateMiniDump: Create minidump file on exception
*/
void CreateMiniDump( LPEXCEPTION_POINTERS pExceptionInfo )
{
    char chFileName[MAX_PATH] = {0};
    SYSTEMTIME stLocalTime = {0};
	GetLocalTime( &stLocalTime );

	_snprintf(chFileName,sizeof(chFileName)-1,"%s_%.4d-%.2d-%.2d_%.2d-%.2d-%.2d.dmp",gszLogFilePrefix,
                        stLocalTime.wYear,stLocalTime.wMonth,stLocalTime.wDay,
                        stLocalTime.wHour,stLocalTime.wMinute,stLocalTime.wSecond );

    // Create the file first.
    HANDLE hFile = CreateFile(chFileName,GENERIC_READ|GENERIC_WRITE,
                              0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);

    if ( hFile != INVALID_HANDLE_VALUE )
    {
        MINIDUMP_EXCEPTION_INFORMATION stMDEI = {0};
        MINIDUMP_EXCEPTION_INFORMATION * pMDEI = NULL;

        if ( pExceptionInfo != NULL )
        {
            stMDEI.ThreadId = GetCurrentThreadId();
            stMDEI.ExceptionPointers = pExceptionInfo;
            stMDEI.ClientPointers = TRUE;
			pMDEI = &stMDEI;
        }

        // Got the file open.  Write it.
        BOOL bRet = MiniDumpWriteDump(GetCurrentProcess(),GetCurrentProcessId(),
			                          hFile,MiniDumpWithPrivateReadWriteMemory,pMDEI,NULL,NULL);

        if ( TRUE == bRet )
        {
			Log(LOG_HEADER,__LINE__,"CreateMiniDump, Created MiniDump file located at %s",chFileName);
        }
        else
        {
            char szLastError[1024] = {0};
            DWORD dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
            Log(LOG_HEADER,__LINE__,"CreateMiniDump, Failed to create MiniDump file. Last Error: %d, %s", dwLastError,szLastError);
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
    Log(LOG_HEADER,__LINE__,"AppUnhndldExcptFltr, Attempt to create MiniDump file before exit proc due to unhndld exception.");
	CreateMiniDump(pExceptionInfo);

	exit(static_cast<int>(ERROR_UNHANDLED_EXCEPTION));

	// Continue execution, which in fact will never happen because we just called ExitProcess.
	return EXCEPTION_CONTINUE_EXECUTION;
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
    if(MultiStr)
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
    OSVERSIONINFO osv = {0};
    osv.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osv);
    return osv.dwMajorVersion;
}

/*
** SysTick
*/
unsigned __int64 SysTick()
{
	HMODULE hKernel32 = LoadLibrary("kernel32.dll");
	if (hKernel32 == NULL) 
		return (unsigned __int64)GetTickCount();

    typedef unsigned __int64 (WINAPI *PGetTickCount64)();
    PGetTickCount64 pGetTickCount64 = (PGetTickCount64)GetProcAddress(hKernel32,"GetTickCount64");

	if (pGetTickCount64 == NULL) 
		return (unsigned __int64)GetTickCount();
    else
        return pGetTickCount64();
}


/*
** CalcElapsedTime
*/
void CalcElapsedTime(unsigned __int64 tickStart,unsigned __int64 &tickEnd,float &timeElapsed,unsigned long &seconds)
{
    tickEnd = SysTick();
    timeElapsed = (float)(tickEnd-tickStart)/SECOND;
    seconds = (unsigned long)(timeElapsed+0.5);
}

/*
** LogElapsedTime
*/
void LogElapsedTime(unsigned long line,unsigned __int64 tickStart,char *lpszAdditionalMsg)
{
    unsigned __int64 tickEnd;
    float timeElapsed;
    unsigned long seconds;
    CalcElapsedTime(tickStart,tickEnd,timeElapsed,seconds);
    if(lpszAdditionalMsg)
    {
        Log(LOG_HEADER,line,"%s, %02d:%02d:%02d, %f s",lpszAdditionalMsg,seconds/3600,(seconds % 3600)/60,seconds % 60,timeElapsed);
    }
    else
    {
        Log(LOG_MESSAGE,line,"%02d:%02d:%02d, %f s",seconds/3600,(seconds % 3600)/60,seconds % 60,timeElapsed);
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

void SetThreadName(const char *threadName,DWORD dwThreadID)
{
    THREADNAME_INFO info = {0};
    info.dwType = 0x1000;
    info.szName = threadName;
    info.dwThreadID = dwThreadID;
    info.dwFlags = 0;

    Log(LOG_DEBUG,__LINE__,"-- SetThrdName, Tp %p, Name %s, Id %u, Flags %p",info.dwType,info.szName,info.dwThreadID,info.dwFlags);

    __try
    {
        RaiseException(MS_VC_EXCEPTION,0,sizeof(info)/sizeof(ULONG_PTR),(ULONG_PTR*)&info );
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

/*
** StartThread: Used to start any processing thread
*/
bool StartThread(string threadName,unsigned (__stdcall *threadFunction)(void*),void *threadData,DWORD threadTimeout,HANDLE *pthreadHandle)
{
    unsigned int uiThreadId = 0;
    HANDLE hThread = NULL;
    bool ret = true;

    Log(LOG_DEBUG,__LINE__,">> StartThrd, Name %s, Func %p, Dat %p, Timeout %u, pHndl %p",threadName.c_str(),threadFunction,threadData,threadTimeout,pthreadHandle);

    /* Logical Drivers */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        hThread = (HANDLE)_beginthreadex(NULL,0,threadFunction,threadData,0,&uiThreadId);
        if(hThread!=NULL)
        {
            Log(LOG_DEBUG,__LINE__,"-- StartThrd, %s Id %u, Hnd %p",threadName.c_str(),uiThreadId,hThread);
            SetThreadName(threadName.c_str(),uiThreadId);

            //Wati thread
            if(threadTimeout>0)
            {
                if(WaitForSingleObject(hThread,threadTimeout)!=WAIT_OBJECT_0)
                {
                    PendingThreads.push_back(hThread);
                }
            }
        }
        else
        {
            Log(LOG_HEADER,__LINE__,"-- StartThrd, No %s thrd created",threadName.c_str());
            ret = false;
        }
    }

    if(ret)
    {
        //Set output if it is not null
        char msg[_MAX_PATH] = {0};
        if(pthreadHandle)
        {
            *pthreadHandle = hThread;
            _snprintf(msg,sizeof(msg)-1,"<< StartThrd, %p",*pthreadHandle);
        }
        else
        {
            //Close the thread handle
            CloseHandle(hThread);
            hThread = NULL;
            strcpy(msg,"<< StartThrd, ret True");
        }
        Log(LOG_DEBUG,__LINE__,msg);
    }
    else
    {
        Log(LOG_DEBUG,__LINE__,"<< StartThrd, ret False");
    }
    return ret;
}

/*
** EndPendingThread: used to release memmory stack and terminate a pending thread
*/
void EndPendingThread(HANDLE hThread)
{
    Log(LOG_DEBUG,__LINE__,">> EndPendgThrd, Hndl %p",hThread);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread,&exitCode);

    //Release thread stack

    if(GetWinVer()<6)   //WinXP or older
    {
        //Used to release the thread stacker
        typedef	VOID (WINAPI *PRtlFreeUserThreadStack)(HANDLE hProcess,HANDLE hThread);
        PRtlFreeUserThreadStack RtlFreeUserThreadStack = NULL;
         
        HMODULE NTLibrary = GetModuleHandleW(L"ntdll.dll");
        if(NTLibrary)
        {
            RtlFreeUserThreadStack = (PRtlFreeUserThreadStack)GetProcAddress(NTLibrary,"RtlFreeUserThreadStack");
        }

        //Release thread stacker
        if(RtlFreeUserThreadStack != NULL)
            RtlFreeUserThreadStack(GetCurrentProcess(),hThread);

        if(NTLibrary)
        {
            FreeLibrary(NTLibrary);
            NTLibrary = NULL;
        }
    }

    TerminateThread(hThread,exitCode);
    Log(LOG_DEBUG,__LINE__,"<< EndPendgThrd");
}

/*
** WndProcMessage: message window proceduce
*/
LRESULT WINAPI WndProcMessage(HWND hWnd,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
    char szGuid[_MAX_PATH] ={0};
    POINTS lPoints = {0};
    int iRet = 0;

    Log(LOG_DEBUG_WND,__LINE__,"-- WndProcMsg, Wnd %p, Msg 0x%.4X, WPrm 0x%.8X HI 0x%.4X LO 0x%.4X, LPrm 0x%.8X HI 0x%.4X LO 0x%.4X",hWnd,uMsg,wParam,HIWORD(wParam),LOWORD(wParam),lParam,HIWORD(lParam),LOWORD(lParam));

    switch(uMsg)
    {
        case WM_QUERYENDSESSION:    //session closure requested
            Log(LOG_HEADER,__LINE__,"Session Closure Requested");
            _thSetInt(&gbTerminate,TRUE);
            _thSetInt(&gbShutdown,TRUE);
            return (LRESULT)(DefWindowProc(hWnd,uMsg,wParam,lParam));
            break;

        case WM_ENDSESSION:         //session is ending
            Log(LOG_HEADER,__LINE__,"End Session");
            LogElapsedTime(__LINE__,gTickStart,"SysStatus");
            return (LRESULT)(DefWindowProc(hWnd,uMsg,wParam,lParam));
            break;

		case WM_DEVICECHANGE:
			switch (wParam)
			{
                case DBT_CONFIGCHANGED:
                    //current configuration changed
                    break;

                case DBT_CUSTOMEVENT:
                    //customer device event
                    //DEV_BROADCAST_HDR
                    break;

                case DBT_DEVICETYPESPECIFIC:
                    //device specific
                    //DEV_BROADCAST_HDR
                    break;

                case DBT_DEVNODES_CHANGED:
                    //a device has been added to or removed from the system
                    break;

                case DBT_USERDEFINED:
                    //device event identifies a user-defined event
                    {
                        _DEV_BROADCAST_USERDEFINED * pDevBcastUserDefined = (_DEV_BROADCAST_USERDEFINED *)lParam;
                        if(!pDevBcastUserDefined)
                            break;

                        Log(LOG_HEADER,__LINE__,"User Defined %s, Size %u, DevType %u",pDevBcastUserDefined->dbud_szName,pDevBcastUserDefined->dbud_dbh.dbch_size,pDevBcastUserDefined->dbud_dbh.dbch_devicetype);
                    }
                    break;

				case DBT_DEVICEARRIVAL:
				case DBT_DEVICEREMOVECOMPLETE:
                    //device has been either arrived or completly removed
                    {
					    PDEV_BROADCAST_HDR pDevBcastHdr = (PDEV_BROADCAST_HDR)lParam;
					    if (!pDevBcastHdr)
						    break;

                        Log(LOG_HEADER,__LINE__,"Device %s, Size %u, DevType %u",(wParam==DBT_DEVICEARRIVAL?"Arrived":"Removed"),pDevBcastHdr->dbch_size,pDevBcastHdr->dbch_devicetype);
                        if (pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
                        {
					        PDEV_BROADCAST_DEVICEINTERFACE pDevBcastDevIface = (PDEV_BROADCAST_DEVICEINTERFACE)lParam;
                            Log(LOG_MESSAGE,__LINE__,"Usb CHANGE Dev <%s GUID %s>",(LPBYTE)pDevBcastDevIface->dbcc_name,GUID2Str(&pDevBcastDevIface->dbcc_classguid,szGuid,sizeof(szGuid)-1));

					        if (wParam == DBT_DEVICEARRIVAL)
						        USBTraceInfo("USB ARRIVAL",(PCHAR)pDevBcastDevIface->dbcc_name);
                            else
						        USBTraceInfo("USB  REMOVE",(PCHAR)pDevBcastDevIface->dbcc_name);

                            _thSetInt(&gbForceChecking,TRUE);

                        }
                        else if(pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_VOLUME)
                        {
					        PDEV_BROADCAST_VOLUME pDevBcastVolume = (PDEV_BROADCAST_VOLUME)lParam;
                            Log(LOG_MESSAGE,__LINE__,"Volume CHANGE <Flags %p, UnitMask %p>",pDevBcastVolume->dbcv_flags,pDevBcastVolume->dbcv_unitmask);

                            _thSetInt(&gbForceChecking,TRUE);
                        }
                        else if(pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_OEM)
                        {
					        PDEV_BROADCAST_OEM pDevBcastOem = (PDEV_BROADCAST_OEM)lParam;
                            Log(LOG_MESSAGE,__LINE__,"Oem CHANGE <Id %p, SuppFunc %p>",pDevBcastOem->dbco_identifier,pDevBcastOem->dbco_suppfunc);
                        }
                        else if(pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_DEVNODE)
                        {
					        PDEV_BROADCAST_DEVNODE pDevBcastDevNode = (PDEV_BROADCAST_DEVNODE)lParam;
                            Log(LOG_MESSAGE,__LINE__,"DevNode CHANGE <%p>",pDevBcastDevNode->dbcd_devnode);
                        }
                        else if(pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_PORT)
                        {
					        PDEV_BROADCAST_PORT pDevBcastPort = (PDEV_BROADCAST_PORT)lParam;
                            Log(LOG_MESSAGE,__LINE__,"Port CHANGE <%s>",(LPBYTE)pDevBcastPort->dbcp_name);

                            _thSetInt(&gbForceChecking,TRUE);
                        }
                        else if(pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_NET)
                        {
					        PDEV_BROADCAST_NET pDevBcastNet = (PDEV_BROADCAST_NET)lParam;
                            Log(LOG_MESSAGE,__LINE__,"Net CHANGE <Resource %p, Flags %p>",(LPBYTE)pDevBcastNet->dbcn_resource,pDevBcastNet->dbcn_flags);

                            _thSetInt(&gbForceChecking,TRUE);
                        }
                        else if(pDevBcastHdr->dbch_devicetype == DBT_DEVTYP_HANDLE)
                        {
					        PDEV_BROADCAST_HANDLE pDevBcastHandle = (PDEV_BROADCAST_HANDLE)lParam;
                            Log(LOG_MESSAGE,__LINE__,"Handle CHANGE <Handle %p, NameOffset %d, Name %s, DevNotify %p, EvntGUID %s>",pDevBcastHandle->dbch_handle,pDevBcastHandle->dbch_nameoffset,(LPBYTE)pDevBcastHandle->dbch_data,pDevBcastHandle->dbch_hdevnotify,GUID2Str(&pDevBcastHandle->dbch_eventguid,szGuid,sizeof(szGuid)-1));
                        }
                    }
                    break;
            }
            break;

        case WM_MOUSEMOVE:
            //if mouse is moved in the window square, control key is pressed
            //ask whether or not it should be stopped;
            //if so, set terminate flag to stop loop processing
            if(wParam==MK_CONTROL)
            {
                lPoints = MAKEPOINTS(lParam);
                if(lPoints.x<=20 && lPoints.y<=20)
                {
                    iRet = MessageBox(hWnd,"Would you like to close this application?","SysStatus",MB_YESNO|MB_ICONQUESTION|MB_SYSTEMMODAL);
                    if(iRet==IDYES)
                    {
                        Log(LOG_HEADER,__LINE__,"Exit Requested");
                        _thSetInt(&gbTerminate,TRUE);
                    }
                }
            }
            //if mouse is moved in the window square, shift key is pressed
            //ask whether or not it should be quickly stopped;
            //if so, set terminate and shutdown flags to stop loop 
            //processing as it would do during a end session
            //(shutdown, logoff, restart)
            else if(wParam==MK_SHIFT)
            {
                lPoints = MAKEPOINTS(lParam);
                if(lPoints.x<=20 && lPoints.y<=20)
                {
                    iRet = MessageBox(hWnd,"Would you like to quickly close this application?","SysStatus",MB_YESNO|MB_ICONQUESTION|MB_SYSTEMMODAL);
                    if(iRet==IDYES)
                    {
                        Log(LOG_HEADER,__LINE__,"Quick Exit Requested");
                        _thSetInt(&gbTerminate,TRUE);
                        _thSetInt(&gbShutdown,TRUE);
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
            return (LRESULT)(DefWindowProc(hWnd,uMsg,wParam,lParam));
    }
    return 0;
}

/*
** ThreadMessage:	Thread function for the window messages
*/
unsigned WINAPI ThreadMessage(LPVOID input)
{
    bool *pbShowWindow = (bool*)input;
    bool bShowWindow = (pbShowWindow?*pbShowWindow:true);

	int iRet = 0;
	MSG msg;

	Log(LOG_DEBUG,__LINE__,">> ThrdMsg");

	//Create application instance
    WNDCLASS  WindowClass = {0};

    WindowClass.style            = CS_HREDRAW|CS_VREDRAW;
    WindowClass.lpfnWndProc      = (WNDPROC)WndProcMessage;
    WindowClass.cbClsExtra       = 0;
    WindowClass.cbWndExtra       = 0;
    WindowClass.hInstance        = ghInstance;
    WindowClass.hIcon            = (HICON)NULL;
    WindowClass.hCursor          = (HCURSOR)NULL;
    WindowClass.hbrBackground    = (HBRUSH)NULL;
    WindowClass.lpszMenuName     = (LPCTSTR)NULL;
    WindowClass.lpszClassName    = "SysStatusWClass";

    //Register window
    if(!RegisterClass(&WindowClass))
    {
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
		Log(LOG_HEADER,__LINE__,"<< ThrdMsg, RegCls %u, %s",dwLastError,szLastError);
		_endthreadex(-1);
		return -1;
	}

    //Create window
	DWORD dwError = 0;
	ghWnd = CreateWindowEx((bShowWindow?WS_EX_DLGMODALFRAME:0),
                           (LPCSTR)"SysStatusWClass",(LPCSTR)"SysStatus",
                           (bShowWindow?WS_BORDER|WS_POPUP:0),
                           0,0,20,20,
                           (HWND)NULL,(HMENU)NULL,
                           ghInstance,(LPVOID)NULL); 
	dwError = GetLastError();
	if(ghWnd==NULL || IsWindow(ghWnd)==FALSE)
    {
        char szLastError[1024] = {0};
        GetLastErrorMessage(dwError,szLastError,sizeof(szLastError));
		Log(LOG_HEADER,__LINE__,"<< ThrdMsg, CreateWnd %u, %s",dwError,szLastError);
		_endthreadex(-1);
		return -1;
    }

	//show the window application
    if(bShowWindow)
    {
    	ShowWindow(ghWnd,SW_SHOW);
	    Sleep(MILLISECOND*50L);
    }

    //Register to receive notification when a USB device or hub is plugged in
	HDEVNOTIFY hNotifyDevHandle = NULL;
	HDEVNOTIFY hNotifyHubHandle = NULL;
    DEV_BROADCAST_DEVICEINTERFACE broadcastInterface;

    ZeroMemory(&broadcastInterface,sizeof(broadcastInterface));
    broadcastInterface.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
    broadcastInterface.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;

    //Register for Device nofitications
    memcpy(&(broadcastInterface.dbcc_classguid),&(GUID_CLASS_USB_DEVICE),sizeof(struct _GUID));
    hNotifyDevHandle = RegisterDeviceNotification(ghWnd,&broadcastInterface,DEVICE_NOTIFY_WINDOW_HANDLE);

    //Register for Hub notifications
    memcpy(&(broadcastInterface.dbcc_classguid),&(GUID_CLASS_USBHUB),sizeof(struct _GUID));
    hNotifyHubHandle = RegisterDeviceNotification(ghWnd,&broadcastInterface,DEVICE_NOTIFY_WINDOW_HANDLE);

    //Register to receive notification when a network component is changed
	HDEVNOTIFY hNotifyNetHandle = NULL;
    DEV_BROADCAST_NET broadcastNet;

    ZeroMemory(&broadcastNet,sizeof(broadcastNet));
    broadcastNet.dbcn_size = sizeof(DEV_BROADCAST_NET);
    broadcastNet.dbcn_devicetype = DBT_DEVTYP_NET;

    //Register for network nofitications
    hNotifyNetHandle = RegisterDeviceNotification(ghWnd,&broadcastNet,DEVICE_NOTIFY_WINDOW_HANDLE);

	//Message loop
	while(GetMessage(&msg,ghWnd,0,0))  
	{
		if (msg.message==TERMINATE_DLL_MSG)
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
    Log(LOG_DEBUG,__LINE__,"<< ThrdMsg");
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
    Log(LOG_DEBUG,__LINE__,">> ThrdUSB");

    USB * pUsb = new USB();
    if(!pUsb)
    {
        Log(LOG_DEBUG,__LINE__,"<< ThrdUSB, New USB class null");
        _endthreadex(ERROR_OUTOFMEMORY);
        return ERROR_OUTOFMEMORY;
    }

    pUsb->EnumerateUSB();
    pUsb->USBDevicesDetails();

    delete pUsb;
    pUsb = NULL;

    Log(LOG_DEBUG,__LINE__,"<< ThrdUSB");
    _endthreadex(0);
    return 0;
}

/*
** ProcessInfo:	Function that collects and traces processes running in the system.
*/
unsigned WINAPI ProcessInfo(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> ProcInfo");

    PROCESS_MEMORY_COUNTERS pmc = {0};

    FILETIME CreationTime = {0};
    FILETIME ExitTime = {0};
    FILETIME KernelTime = {0};
    FILETIME UserTime = {0};
    SYSTEMTIME tKernelTime = {0};
    SYSTEMTIME tUserTime = {0};

    DWORD dwHandleCount = 0;

    unsigned long seconds = 0;

    DWORD aProcesses[1024] = {0}, cbNeeded = 0, cProcesses = 0;

    unsigned __int64 tickStart = SysTick();

    //get list of process
    memset(aProcesses,0x00,sizeof(aProcesses));
    cbNeeded = 0;
    cProcesses = 0;
    if(EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded))
    {

        //calculate how many process identifiers were returned.
        cProcesses = cbNeeded / sizeof(DWORD);
        Log(LOG_HEADER,__LINE__,"Processes Informaton, Number of processes: %u",cProcesses);
        if(cProcesses>0)        //skip from current process
            Log(LOG_MESSAGE,__LINE__,">      ProcessID, Process Name, Handles, CPUTime, PagefileUsage, PeakPagefileUsage, PageFaultCount, PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage");

        for(DWORD i=0;i<cProcesses;i++)
        {
            //get a handle to the process
            DWORD dwProcessID = aProcesses[i];
            HANDLE hProcInfo = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,dwProcessID);
            if(hProcInfo)
            {
                //get process name
                HMODULE hMod = NULL;
                cbNeeded = 0;
                TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

                //enumerate modules
                if(EnumProcessModules(hProcInfo,&hMod,sizeof(hMod),&cbNeeded))
                {
	                GetModuleBaseName(hProcInfo,hMod,szProcessName,sizeof(szProcessName)/sizeof(TCHAR));
                }

                //get process menory information
                GetProcessMemoryInfo(hProcInfo,&pmc,sizeof(pmc));

                //get process time information
                seconds = 0;
                GetProcessTimes(hProcInfo,&CreationTime,&ExitTime,&KernelTime,&UserTime);
                FileTimeToSystemTime(&KernelTime,&tKernelTime);
                seconds = (long)tKernelTime.wSecond + ((long)tKernelTime.wMinute*60) + ((long)tKernelTime.wHour*3600);
                FileTimeToSystemTime(&UserTime,&tUserTime);
                seconds = seconds + (long)tUserTime.wSecond + ((long)tUserTime.wMinute*60) + ((long)tUserTime.wHour*3600);

                //get process handle count
                GetProcessHandleCount(hProcInfo,&dwHandleCount);

                Log(LOG_MESSAGE,__LINE__,"> %.3d, %05u, %s, %u, %02d:%02d:%02d, %u, %u, %u, %u, %u, %u, %u, %u, %u",i+1,
                                dwProcessID,szProcessName,dwHandleCount,seconds/3600,(seconds % 3600)/60, seconds % 60,
                                pmc.PagefileUsage,pmc.PeakPagefileUsage,pmc.PageFaultCount,pmc.PeakWorkingSetSize,pmc.WorkingSetSize,
                                pmc.QuotaPeakPagedPoolUsage,pmc.QuotaPagedPoolUsage,pmc.QuotaPeakNonPagedPoolUsage,pmc.QuotaNonPagedPoolUsage);
                
                //close the process handle
                CloseHandle(hProcInfo);
                hProcInfo = NULL;
            }
            else
            {
                Log(LOG_MESSAGE,__LINE__,"> %.3d, %05u, <unknown>, ?, ??:??:??, ?, ?, ?, ?, ?, ?, ?, ?, ?",i+1,dwProcessID);
            }
        }
    }
    else
    {
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
        Log(LOG_HEADER,__LINE__,"ProcessInfo, EnumProcesses failed: %u, %s",dwLastError,szLastError);
    }

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< ProcInfo");
    _endthreadex(0);
    return 0;
}

/*
** HwProfile
*/
unsigned WINAPI HwProfile(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> HwProfile");

    unsigned __int64 tickStart = SysTick();

    //get hardware profile
    HW_PROFILE_INFO HwProfileInfo = {0};
    if(GetCurrentHwProfile(&HwProfileInfo))
    {
        Log(LOG_HEADER,__LINE__,"Hardware Profile, DockInfo %p, GUID %s, Name %s",
                        HwProfileInfo.dwDockInfo,HwProfileInfo.szHwProfileGuid,HwProfileInfo.szHwProfileName);
    }
    else
    {
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
        Log(LOG_HEADER,__LINE__,"HwProfile, GetCurrentHwProfile %u, %s",dwLastError,szLastError);
    }

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< HwProfile");
    _endthreadex(0);
    return 0;
}

/*
** SystemInfo
*/
float ProcessorSpeedCalc()
{
    /*
    RdTSC: It's the Pentium instruction "ReaD Time Stamp Counter". It measures the
    number of clock cycles that have passed since the processor was reset, as a
    64-bit number. That's what the _emit lines do.*/
    #define RdTSC __asm _emit 0x0f __asm _emit 0x31

    //variables for the clock-cycles
    __int64 cyclesStart = 0, cyclesStop = 0;

    //variables for the High-Res Preformance Counter
    unsigned __int64 nCtr = 0, nFreq = 0, nCtrStop = 0;

    //retrieve performance-counter frequency per second
    if(!QueryPerformanceFrequency((LARGE_INTEGER *) &nFreq))
        return 0;

    //retrieve the current value of the performance counter
    QueryPerformanceCounter((LARGE_INTEGER *) &nCtrStop);

    //add the frequency to the counter-value
    nCtrStop += nFreq;

    _asm
    {
        //retrieve the clock-cycles for the start value
        RdTSC
        mov DWORD PTR cyclesStart, eax
        mov DWORD PTR [cyclesStart + 4], edx
    }

    do{
        //retrieve the value of the performance counter until 1 sec has gone by
        QueryPerformanceCounter((LARGE_INTEGER *)&nCtr);
    }while (nCtr < nCtrStop);

    _asm 
    {
        //retrieve again the clock-cycles after 1 sec has gone by
        RdTSC
        mov DWORD PTR cyclesStop, eax
        mov DWORD PTR [cyclesStop + 4], edx
    }

    //stop-start is speed in Hz divided by 1,000,000 is speed in MHz
    return	((float)cyclesStop-(float)cyclesStart) / MHz;
}
DWORD CurrentProcessorNumber(void)
{
    DWORD processor = 1;
    LPFN_GCPN gcpn = (LPFN_GCPN)GetProcAddress(GetModuleHandle("kernel32"),"GetCurrentProcessorNumber");
    if (NULL == gcpn) 
    {
        Log(LOG_DEBUG,__LINE__,"-- CurrentProcessorNumber, GetCurrentProcessorNumber is not supported.");
    }
    else
    {
        processor = gcpn();
    }
    return processor;
}
unsigned WINAPI SystemInfo(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> SysInfo");

    unsigned __int64 tickStart = SysTick();

    SYSTEM_INFO SystemInfo = {0};
    char szComputeName[MAX_COMPUTERNAME_LENGTH+1] = {0};
    DWORD dwSize = MAX_COMPUTERNAME_LENGTH;

    //get process handle
    GetSystemInfo(&SystemInfo);

    //get computer information
    dwSize = MAX_COMPUTERNAME_LENGTH;
    GetComputerName(szComputeName,&dwSize);

    Log(LOG_HEADER,__LINE__,"Computer: %s, Processor(s) %u %f Mhz Current %u, %s, Level %u, Rev %u, Type %u; Page Size %u",
                 szComputeName,SystemInfo.dwNumberOfProcessors,ProcessorSpeedCalc(),CurrentProcessorNumber(),
                 (SystemInfo.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64?"x64 (AMD or Intel)":
                    (SystemInfo.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_IA64?"Intel Itanium-based":
                    (SystemInfo.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL?"x86":"Unknown"))),
                SystemInfo.wProcessorLevel,SystemInfo.wProcessorRevision,SystemInfo.dwProcessorType,
                SystemInfo.dwPageSize);

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< SysInfo");
    _endthreadex(0);
    return 0;
}

/*
** OSInfo: get operate system information
*/
unsigned WINAPI OSInfo(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> OSInfo");

    unsigned __int64 tickStart = SysTick();

    //get OS version
    OSVERSIONINFOEX osverEx = {0};
    osverEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((LPOSVERSIONINFO)&osverEx);
    Log(LOG_HEADER,__LINE__,"OSInfo, Version %u.%u.%u, Platform %u, SP %s(%u.%u), Suite 0x%08X, %s",
                      osverEx.dwMajorVersion,osverEx.dwMinorVersion,osverEx.dwBuildNumber,osverEx.dwPlatformId,
                      osverEx.szCSDVersion,osverEx.wServicePackMajor,osverEx.wServicePackMinor,osverEx.wSuiteMask,
                      (osverEx.wProductType==VER_NT_DOMAIN_CONTROLLER?"Domain Controller":(osverEx.wProductType==VER_NT_SERVER?"Server":"Workstation")));

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< OSInfo");
    _endthreadex(0);
    return 0;
}

/*
** SystemMemory
*/
unsigned WINAPI SystemMemory(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> SysMem");

    unsigned __int64 tickStart = SysTick();

    //get system memory
    MEMORYSTATUSEX Memst = {0};
    Memst.dwLength = sizeof(Memst);
    GlobalMemoryStatusEx(&Memst);

    Log(LOG_HEADER,__LINE__,"System Memory");
    Log(LOG_MESSAGE,__LINE__,"Usage: %u%% used",SIZE_MB(Memst.dwMemoryLoad));
    Log(LOG_MESSAGE,__LINE__,"Physical: %u MB used, %u MB avail",SIZE_MB(Memst.ullTotalPhys),SIZE_MB(Memst.ullAvailPhys));
    Log(LOG_MESSAGE,__LINE__,"Pagefile: %u MB used, %u MB avail",SIZE_MB(Memst.ullTotalPageFile),SIZE_MB(Memst.ullAvailPageFile));
    Log(LOG_MESSAGE,__LINE__,"Virtual: %u MB used, %u MB avail, %u MB extended",SIZE_MB(Memst.ullTotalVirtual),SIZE_MB(Memst.ullAvailVirtual),SIZE_MB(Memst.ullAvailExtendedVirtual));

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< SysMem");
    _endthreadex(0);
    return 0;
}

/*
** SystemTimes
*/
unsigned WINAPI SystemTimes(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> SysTimes");

    FILETIME ExitTime = {0};
    FILETIME KernelTime = {0};
    FILETIME UserTime = {0};
    FILETIME IdleTime = {0};
    SYSTEMTIME tKernelTime = {0};
    SYSTEMTIME tUserTime = {0};
    SYSTEMTIME tIdleTime = {0};
    unsigned long seconds = 0;

    unsigned __int64 tickStart = SysTick();

    Log(LOG_HEADER,__LINE__,"System Times");

    //get system times
    GetSystemTimes(&IdleTime,&KernelTime,&UserTime);

    FileTimeToSystemTime(&KernelTime,&tKernelTime);
    seconds = (long)tKernelTime.wSecond + ((long)tKernelTime.wMinute*60) + ((long)tKernelTime.wHour*3600);
    Log(LOG_MESSAGE,__LINE__,"Kernel time: %02d:%02d:%02d (%u s).",seconds/3600,(seconds % 3600)/60,seconds % 60,seconds);

    FileTimeToSystemTime(&UserTime,&tUserTime);
    seconds = (long)tUserTime.wSecond + ((long)tUserTime.wMinute*60) + ((long)tUserTime.wHour*3600);
    Log(LOG_MESSAGE,__LINE__,"User time: %02d:%02d:%02d (%u s).",seconds/3600,(seconds % 3600)/60,seconds % 60,seconds);

    FileTimeToSystemTime(&IdleTime,&tIdleTime);
    seconds = (long)tIdleTime.wSecond + ((long)tIdleTime.wMinute*60) + ((long)tIdleTime.wHour*3600);
    Log(LOG_MESSAGE,__LINE__,"Idle: %02d:%02d:%02d (%u s).",seconds/3600,(seconds % 3600)/60,seconds % 60,seconds);

    //processor counts/times
    //retrieve performance-counter frequency per second
    unsigned __int64 nCtr = 0, nFreq = 0;
    if(QueryPerformanceFrequency((LARGE_INTEGER *)&nFreq))
    {
        //retrieve the current value of the performance counter
        QueryPerformanceCounter((LARGE_INTEGER *)&nCtr);

        float processorTime = (float)(nCtr/nFreq);
        seconds = (unsigned long)(processorTime+0.5);
        Log(LOG_MESSAGE,__LINE__,"Processor: %I64u counts, %I64u counts/sec, %02d:%02d:%02d %f s",nCtr,nFreq,seconds/3600,(seconds % 3600)/60,seconds % 60,processorTime);
    }
    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< SysTimes");
    _endthreadex(0);
    return 0;
}

/*
** LogicalDrives: get drivers information
*/
char * DriverTypeName(DWORD driverType)
{
    switch(driverType)
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
    Log(LOG_DEBUG,__LINE__,">> LogDrvs");

    DWORD dwSectorsPerCluster = 0,
          dwBytesPerSector = 0,
          dwNumberOfFreeClusters = 0,
          dwTotalNumberOfClusters = 0;

    char lpVolumeNameBuffer[10000] = {0},
        lpFileSystemNameBuffer[10000] = {0};

    DWORD nVolumeSerialNumber = 0,
          nMaximumComponentLength = 0,
          nFileSystemFlags = 0;

    char temp[10000] = {0};

    unsigned __int64 tickStart = SysTick();

    DWORD numDrivers = GetLogicalDriveStrings(sizeof(temp),temp);

    vector<string> drivers;
    parseNullTerminatedStrings(temp,drivers);

    Log(LOG_HEADER,__LINE__,"Logical Drivers %u (0x%.8X)",drivers.size(),GetLogicalDrives());

    for(unsigned int x=0;x<drivers.size();x++)
    {
        char driver[100] = {0};
        DWORD driverType = 0;
        strncpy(driver,drivers.at(x).c_str(),sizeof(driver)-1);

        driverType = GetDriveType(driver);
        Log(LOG_MESSAGE,__LINE__,">> %.3d, %s: Type %s(%u)",x+1,driver,DriverTypeName(driverType),driverType);

        if(GetVolumeInformation(driver,lpVolumeNameBuffer,sizeof(lpVolumeNameBuffer),&nVolumeSerialNumber,&nMaximumComponentLength,&nFileSystemFlags,lpFileSystemNameBuffer,sizeof(lpFileSystemNameBuffer)))
        {
            Log(LOG_MESSAGE,__LINE__,"   VolumeInfo, Name %s, SerialNumber %u, MaxComponentLenght %u, FileSysflags 0x%08X, FileSysName %s",
                                lpVolumeNameBuffer,nVolumeSerialNumber,nMaximumComponentLength,nFileSystemFlags,lpFileSystemNameBuffer);
            if(GetDiskFreeSpace(driver,&dwSectorsPerCluster,&dwBytesPerSector,&dwNumberOfFreeClusters,&dwTotalNumberOfClusters))
            {
                Log(LOG_MESSAGE,__LINE__,"   FreeSpace, SectorsPerCluster %u, BytesPerSector %u, NumberOfFreeClusters %u, TotalNumberOfClusters %u",
                                    dwSectorsPerCluster,dwBytesPerSector,dwNumberOfFreeClusters,dwTotalNumberOfClusters);
            }
        }
    }

    drivers.clear();

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< LogDrvs");
    _endthreadex(0);
    return 0;
}

/*
** SystemDirs
*/
unsigned WINAPI SystemDirs(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> SysDirs");

    char temp[10000];

    unsigned __int64 tickStart = SysTick();

    Log(LOG_HEADER,__LINE__,"System Directories");

    memset(temp,0x00,sizeof(temp));
    GetSystemDirectory(temp,sizeof(temp));
    Log(LOG_MESSAGE,__LINE__,"SysDir %s",temp);

    memset(temp,0x00,sizeof(temp));
    GetTempPath(sizeof(temp),temp);
    Log(LOG_MESSAGE,__LINE__,"TempPath %s",temp);

    memset(temp,0x00,sizeof(temp));
    GetWindowsDirectory(temp,sizeof(temp));
    Log(LOG_MESSAGE,__LINE__,"WinDir %s",temp);

    memset(temp,0x00,sizeof(temp));
    GetSystemWindowsDirectory(temp,sizeof(temp));
    Log(LOG_MESSAGE,__LINE__,"WinSysDir %s",temp);

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< SysDirs");
    _endthreadex(0);
    return 0;
}

/*
** SystemLogicalProcessorInforamtion:	Function that collects the logical processor(s) information.
**/
// Helper function to count set bits in the processor mask.
DWORD CountSetBits(ULONG_PTR bitMask)
{
    DWORD LSHIFT = sizeof(ULONG_PTR)*8 - 1;
    DWORD bitSetCount = 0;
    ULONG_PTR bitTest = (ULONG_PTR)1 << LSHIFT;    
    DWORD i;
    
    for (i = 0; i <= LSHIFT; ++i)
    {
        bitSetCount += ((bitMask & bitTest)?1:0);
        bitTest/=2;
    }

    return bitSetCount;
}

unsigned WINAPI SystemLogicalProcessorInforamtion(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> SysLogProcInfo");

    LPFN_GLPI glpi = NULL;
    BOOL done = FALSE;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION ptr = NULL;
    DWORD returnLength = 0;
    DWORD logicalProcessorCount = 0;
    DWORD numaNodeCount = 0;
    DWORD processorCoreCount = 0;
    DWORD processorL1CacheCount = 0;
    DWORD processorL2CacheCount = 0;
    DWORD processorL3CacheCount = 0;
    DWORD processorPackageCount = 0;
    DWORD byteOffset = 0;
    PCACHE_DESCRIPTOR Cache;

    unsigned __int64 tickStart = SysTick();

    char szLastError[1024] = {0};
    DWORD dwLastError = 0;

    glpi = (LPFN_GLPI) GetProcAddress(GetModuleHandle("kernel32"),"GetLogicalProcessorInformation");
    if (NULL == glpi) 
    {
        Log(LOG_DEBUG,__LINE__,"<< SysLogProcInfo, Out, Unsupp GetLogicalProcessorInformation");
        _endthreadex(ERROR_NOT_SUPPORTED);
        return ERROR_NOT_SUPPORTED;
    }

    while (!done)
    {
        DWORD rc = glpi(buffer, &returnLength);

        if (FALSE == rc) 
        {
            if ((dwLastError = GetLastError()) == ERROR_INSUFFICIENT_BUFFER) 
            {
                if (buffer) 
                    free(buffer);

                buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)malloc(returnLength);
                if (NULL == buffer) 
                {
                    Log(LOG_DEBUG,__LINE__,"-- SysLogProcInfo, Allocation failure");
                    break;
                }
            } 
            else 
            {
                char szLastError[1024] = {0};
                GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
                Log(LOG_DEBUG,__LINE__,"-- SysLogProcInfo, GLPI Error %u, %s",dwLastError,szLastError);
                break;
            }
        } 
        else
        {
            done = TRUE;
        }
    }

    if(done)
    {
        ptr = buffer;

        if(ptr)
        {
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
                    Log(LOG_DEBUG,__LINE__,"-- SysLogProcInfo, Unsupp LOGICAL_PROCESSOR_RELATIONSHIP value %d",ptr->Relationship);
                    break;
                }
                byteOffset += sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
                ptr++;
            }
        }

        Log(LOG_HEADER,__LINE__,"Logical Processor(s) Information");
        Log(LOG_MESSAGE,__LINE__,"Number of NUMA nodes: %d",numaNodeCount);
        Log(LOG_MESSAGE,__LINE__,"Number of physical processor packages: %d",processorPackageCount);
        Log(LOG_MESSAGE,__LINE__,"Number of processor cores: %d",processorCoreCount);
        Log(LOG_MESSAGE,__LINE__,"Number of logical processors: %d",logicalProcessorCount);
        Log(LOG_MESSAGE,__LINE__,"Number of processor L1/L2/L3 caches: %d/%d/%d",processorL1CacheCount,processorL2CacheCount,processorL3CacheCount);
        
        free(buffer);
    }

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< SysLogProcInfo");
    _endthreadex(0);
    return 0;
}

/*
** DeviceDrivers
*/
unsigned WINAPI DeviceDrivers(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> DevDrvs");

    const int DriveArraySize = 5000;
    LPVOID drivers[DriveArraySize];
    DWORD cbNeeded = 0;
    int cDrivers = 0;

    unsigned __int64 tickStart = SysTick();

    if(EnumDeviceDrivers(drivers,sizeof(drivers),&cbNeeded) && cbNeeded < sizeof(drivers))
    { 
        char szDriver[DriveArraySize] = {0};
        char szFile[DriveArraySize] = {0};
        cDrivers = cbNeeded / sizeof(drivers[0]);
        
        Log(LOG_HEADER,__LINE__,"Device Drivers, Number of: %d",cDrivers);
        for(int i=0;i<cDrivers;i++)
        {
            GetDeviceDriverBaseName(drivers[i],szDriver,sizeof(szDriver)/sizeof(szDriver[0]));
            GetDeviceDriverFileName(drivers[i],szFile,sizeof(szFile)/sizeof(szFile[0]));

            Log(LOG_MESSAGE,__LINE__,"> %.3d, %s, %s",i+1,szDriver,szFile);

            memset(szDriver,0x00,sizeof(szDriver));
            memset(szFile,0x00,sizeof(szFile));
        }
    }
    else 
    {
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
        Log(LOG_HEADER,__LINE__,"DevDrvs, EnumDeviceDrivers failed: %u, %s (array size needed %u)",dwLastError,szLastError,cbNeeded/sizeof(LPVOID));
    }

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< DevDrvs");
    _endthreadex(0);
    return 0;
}

/*
** PerformanceInfo
*/
unsigned WINAPI PerformanceInfo(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> PerfInfo");

    unsigned __int64 tickStart = SysTick();

    PERFORMANCE_INFORMATION perfInfo = {0};
    if(GetPerformanceInfo(&perfInfo,sizeof(PERFORMANCE_INFORMATION)))
    {
        Log(LOG_HEADER,__LINE__,"Performance Information");
        Log(LOG_MESSAGE,__LINE__,"Commit: Total %u, Limit %u, Peak %u",perfInfo.CommitTotal,perfInfo.CommitLimit,perfInfo.CommitPeak);
        Log(LOG_MESSAGE,__LINE__,"Physical: Total %u, Available %u",perfInfo.PhysicalTotal,perfInfo.PhysicalAvailable);
        Log(LOG_MESSAGE,__LINE__,"System Cache %u",perfInfo.SystemCache);
        Log(LOG_MESSAGE,__LINE__,"Kernel: Total %u, Paged %u, Nonpaged %u",perfInfo.KernelTotal,perfInfo.KernelPaged,perfInfo.KernelNonpaged);
        Log(LOG_MESSAGE,__LINE__,"Page Size %u",perfInfo.PageSize);
        Log(LOG_MESSAGE,__LINE__,"Process %u, Handles %u, Threads %u",perfInfo.ProcessCount,perfInfo.HandleCount,perfInfo.ThreadCount);
    }
    else
    {
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
        Log(LOG_HEADER,__LINE__,"PerfInfo, GetPerformanceInfo failed %u, %s",dwLastError,szLastError);
    }

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< PerfInfo");
    _endthreadex(0);
    return 0;
}

/*
** PrinterInfo: list and capabilities of all printes
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

LP_PRINTER_INFO_LIST gpPrinterInfoList = NULL;

int GetPrintersList(void)
{
    int l = 0, n = 0;
    DWORD dwLastError = 0;
    char szLastError[_MAX_PATH] = {0};
    PRINTER_INFO_2 *pi2 = NULL;
    PBuffer B;

    Log(LOG_DEBUG,__LINE__,">> GetPtrsList");

    //release printer info list
    if(gpPrinterInfoList)
    {
        delete [] gpPrinterInfoList;
        gpPrinterInfoList = NULL;
    }

    //get number of printers
    EnumPrinters(PRINTER_ENUM_LOCAL|PRINTER_ENUM_CONNECTIONS,NULL,2,NULL,l,(DWORD*)&l,(DWORD*)&n);
    if(l==0)
    {
        Log(LOG_DEBUG,__LINE__,"<< GetPtrsList, No Printer");
        return 0;
    }
    n = 0;
    LPBYTE lpbPtrInfo  = B._allocMem(l);
    if (!lpbPtrInfo)
    {
        Log(LOG_DEBUG,__LINE__,"<< GetPtrsList, new PtrInfo null");
        return l;
    }

    //get the printer list information
    if (!EnumPrinters(PRINTER_ENUM_LOCAL|PRINTER_ENUM_CONNECTIONS,NULL,2,lpbPtrInfo,l,(DWORD*)&l,(DWORD*)&n))
    {
        dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
        Log(LOG_DEBUG,__LINE__,"<< GetPtrsList, EnumPrinters Err %d Msg %s",dwLastError,szLastError);
        return (int)dwLastError;
    }

    //create list of printer info
    size_t size = sizeof(PRINTER_INFO_LIST)+((n-1)*sizeof(PRINTER_INFO));
    gpPrinterInfoList = (LP_PRINTER_INFO_LIST)new BYTE[size];
    if(!gpPrinterInfoList)
    {
        Log(LOG_DEBUG,__LINE__,"<< GetPtrsList, new PrtInfoList null");
        return size;
    }
    memset(gpPrinterInfoList,0x00,size);

    Log(LOG_HEADER,__LINE__,"Printers Information (%d):",n);
    pi2 = (PRINTER_INFO_2*)lpbPtrInfo;
    Log(LOG_MESSAGE,__LINE__,">     Printer, Port, Driver, Processor, Status, Priority, Location, Share, Comment");
    for (int i=0; i<n; i++)
    {
        Log(LOG_MESSAGE,__LINE__,"> %.2d: \\\\%s\\%s,  %s, %s, %s, %u, %u, %s, %s, %s",i+1,
                     pi2->pServerName ? pi2->pServerName : "<LocalPrinter>",pi2->pPrinterName,
                     pi2->pPortName,pi2->pDriverName,pi2->pPrintProcessor,pi2->Status,
                     pi2->Priority,pi2->pLocation,pi2->pShareName,pi2->pComment);

        strncpy(gpPrinterInfoList->PrinterInfo[i].PrinterName,pi2->pPrinterName,_MAX_PATH-1);
        strncpy(gpPrinterInfoList->PrinterInfo[i].PortName,pi2->pPortName,_MAX_PATH-1);
        strncpy(gpPrinterInfoList->PrinterInfo[i].DriverName,pi2->pDriverName,_MAX_PATH-1);
        gpPrinterInfoList->num++;
        pi2++;
    }

    Log(LOG_DEBUG,__LINE__,"<< GetPtrsList");
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

LP_PTRDATA_INFO_LIST GetBinList(const char *PrinterName,const char *PortName)
{
    int l = 0, n = 0, i = 0, bins = 0;
    LP_PTRDATA_INFO_LIST pList = NULL;

    WORD *pw = NULL;
    BYTE *ppi = NULL;
    PBuffer B;

    DWORD dwLastError = 0;
    char szLastError[_MAX_PATH] = {0};

    Log(LOG_DEBUG,__LINE__,">> GetBinList, Name %s, Port %s",PrinterName,PortName);

    // *** bins
    if ((l = DeviceCapabilities(PrinterName, PortName, DC_BINS, NULL, NULL)) <= 0)
    {
        dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
        Log(LOG_DEBUG,__LINE__,"<< GetBinList, DeviceCapabilities(DC_BINS, null) Err %d Msg %s",dwLastError,szLastError);
        return NULL;
    }
    else
    {
        ppi = B._allocMem(l*sizeof(WORD));
        if (!ppi)
        {
            Log(LOG_DEBUG,__LINE__,"<< GetBinList, <%s> new DC_BINS mem null",PrinterName);
            return NULL;
        }
        else
        {
            bins = l;
            size_t size = sizeof(PTRDATA_INFO_LIST)+((l-1)*sizeof(PTRDATA_INFO));
            pList = (LP_PTRDATA_INFO_LIST)new BYTE[size];
            if (!pList)
            {
                Log(LOG_DEBUG,__LINE__,"<< GetBinList, <%s> new PTRDATA_INFO_LIST mem null",PrinterName);
                return NULL;
            }
            memset(pList,0x00,size);
            pList->num = bins;

            if ((n = DeviceCapabilities(PrinterName, PortName, DC_BINS, (LPSTR)ppi, NULL)) != l)
            {
                dwLastError = GetLastError();
                GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
                Log(LOG_DEBUG,__LINE__,"<< GetBinList, DeviceCapabilities(DC_BINS, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
                delete [] pList;
                return NULL;
            }
            else
            {
                for (i=0, pw=(WORD *)ppi; i<n; i++, pw++)
                {
                    pList->PtrDataInfo[i].id = *pw;
                }
            }
        }
    }

    // *** binnames
    ppi = B._allocMem(bins*sizeof(NAME_24BYTES));
    if (!ppi)
    {
        Log(LOG_DEBUG,__LINE__,"-- GetBinList, <%s> new DC_BINNAMES mem null",PrinterName);
    }
    else
    {
        if ((n = DeviceCapabilities(PrinterName, PortName, DC_BINNAMES, (LPSTR)ppi, NULL)) != l)
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- GetBinList, DeviceCapabilities(DC_BINNAMES, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
        }
        else
        {
            NAME_24BYTES *pn24 = NULL;
            for (i=0, pn24=(NAME_24BYTES *)ppi; i<n; i++, pn24++)
            {
                memcpy(pList->PtrDataInfo[i].name,pn24->name,sizeof(NAME_24BYTES));
            }
        }
    }

    Log(LOG_DEBUG,__LINE__,"<< GetBinList, List %p",pList);
    return pList;
}
LP_PTRDATA_INFO_LIST GetPaperList(const char *PrinterName,const char *PortName)
{
    int l = 0, n = 0, i = 0, papers = 0;
    LP_PTRDATA_INFO_LIST pList = NULL;

    WORD *pw = NULL;
    BYTE *ppi = NULL;
    POINT *pp = NULL;
    PBuffer B;

    DWORD dwLastError = 0;
    char szLastError[_MAX_PATH] = {0};

    Log(LOG_DEBUG,__LINE__,">> GetPaperList, Name %s, Port %s",PrinterName,PortName);

    // *** papers
    if ((l = DeviceCapabilities(PrinterName, PortName, DC_PAPERS, NULL, NULL)) <= 0)
    {
        dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
        Log(LOG_DEBUG,__LINE__,"<< GetPaperList, DeviceCapabilities(DC_PAPERS, null) Err %d Msg %s",dwLastError,szLastError);
        return NULL;
    }
    else
    {
        ppi = B._allocMem(l*sizeof(WORD));
        if (!ppi)
        {
            Log(LOG_DEBUG,__LINE__,"<< GetPaperList, <%s> new DC_PAPERS mem null",PrinterName);
            return NULL;
        }
        else
        {
            papers = l;
            size_t size = sizeof(PTRDATA_INFO_LIST)+((l-1)*sizeof(PTRDATA_INFO));
            pList = (LP_PTRDATA_INFO_LIST)new BYTE[size];
            if (!pList)
            {
                Log(LOG_DEBUG,__LINE__,"<< GetPaperList, <%s> new PTRDATA_INFO_LIST mem null",PrinterName);
                return NULL;
            }
            memset(pList,0x00,size);
            pList->num = papers;

            if ((n = DeviceCapabilities(PrinterName, PortName, DC_PAPERS, (LPSTR)ppi, NULL)) != l)
            {
                dwLastError = GetLastError();
                GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
                Log(LOG_DEBUG,__LINE__,"<< GetPaperList, DeviceCapabilities(DC_PAPERS, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
                delete [] pList;
                return NULL;
            }
            else
            {
                for (i=0, pw=(WORD *)ppi; i<n; i++, pw++)
                {
                    pList->PtrDataInfo[i].id = *pw;
                }
            }
        }
    }

    // *** paper sizes
    ppi = B._allocMem(papers*sizeof(POINT));
    if (!ppi)
    {
        Log(LOG_DEBUG,__LINE__,"-- GetPaperList, <%s> new DC_PAPERSIZE mem null",PrinterName);
    }
    else
    {
        if ((n = DeviceCapabilities(PrinterName, PortName, DC_PAPERSIZE, (LPSTR)ppi, NULL)) != l)
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- GetPaperList, DeviceCapabilities(DC_PAPERSIZE, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
        }
        else
        {
            for (i=0, pp=(POINT *)ppi; i<n; i++, pp++)
            {
                pList->PtrDataInfo[i].x = pp->x;
                pList->PtrDataInfo[i].y = pp->y;
            }
        }
    }

    // *** paper names
    ppi = B._allocMem(papers*sizeof(NAME_64BYTES));
    if (!ppi)
    {
        Log(LOG_DEBUG,__LINE__,"-- GetPaperList, <%s> new DC_PAPERNAMES mem null",PrinterName);
    }
    else
    {
        if ((n = DeviceCapabilities(PrinterName, PortName, DC_PAPERNAMES, (LPSTR)ppi, NULL)) != l)
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- GetPaperList, DeviceCapabilities(DC_PAPERNAMES, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
        }
        else
        {
            NAME_64BYTES *pn64 = NULL;
            for (i=0, pn64=(NAME_64BYTES *)ppi; i<n; i++, pn64++)
            {
                memcpy(pList->PtrDataInfo[i].name,pn64->name,sizeof(NAME_64BYTES));
            }
        }
    }

    Log(LOG_DEBUG,__LINE__,"<< GetPaperList, List %p",pList);
    return pList;
}
LP_PTRDATA_INFO_LIST GetMediaTypeList(const char *PrinterName,const char *PortName)
{
    int l = 0, n = 0, i = 0, mediaTypes = 0;
    LP_PTRDATA_INFO_LIST pList = NULL;

    DWORD *pdw = NULL;
    BYTE *ppi = NULL;
    PBuffer B;

    DWORD dwLastError = 0;
    char szLastError[_MAX_PATH] = {0};

    Log(LOG_DEBUG,__LINE__,">> GetMediaTypeList, Name %s, Port %s",PrinterName,PortName);

    if ((l = DeviceCapabilities(PrinterName, PortName, DC_MEDIATYPES, NULL, NULL)) <= 0)
    {
        dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
        Log(LOG_DEBUG,__LINE__,"<< GetMediaTypeList, DeviceCapabilities(DC_MEDIATYPES, null) Err %d Msg %s",dwLastError,szLastError);
        return NULL;
    }
    else
    {
        ppi = B._allocMem(l*sizeof(DWORD));
        if (!ppi)
        {
            Log(LOG_DEBUG,__LINE__,"-- GetMediaTypeList, <%s> new DC_MEDIATYPES mem null",PrinterName);
        }
        else
        {
            mediaTypes = l;
            size_t size = sizeof(PTRDATA_INFO_LIST)+((l-1)*sizeof(PTRDATA_INFO));
            pList = (LP_PTRDATA_INFO_LIST)new BYTE[size];
            if (!pList)
            {
                Log(LOG_DEBUG,__LINE__,"<< GetMediaTypeList, <%s> new PTRDATA_INFO_LIST mem null",PrinterName);
                return NULL;
            }
            memset(pList,0x00,size);
            pList->num = mediaTypes;

            if ((n = DeviceCapabilities(PrinterName, PortName, DC_MEDIATYPES, (LPSTR)ppi, NULL)) != l)
            {
                dwLastError = GetLastError();
                GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
                Log(LOG_DEBUG,__LINE__,"<< GetMediaTypeList, DeviceCapabilities(DC_MEDIATYPES, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
                delete [] pList;
                return NULL;
            }
            else
            {
                for (i=0, pdw=(DWORD *)ppi; i<n; i++, pdw++)
                {
                    pList->PtrDataInfo[i].id = *pdw;
                }
            }
        }
    }

    // *** media type names
    ppi = B._allocMem(mediaTypes*sizeof(NAME_64BYTES));
    if (!ppi)
    {
        Log(LOG_DEBUG,__LINE__,"-- GetMediaTypeList, <%s> new DC_MEDIATYPENAMES mem null",PrinterName);
    }
    else
    {
        if ((n = DeviceCapabilities(PrinterName, PortName, DC_MEDIATYPENAMES, (LPSTR)ppi, NULL)) != l)
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- GetMediaTypeList, DeviceCapabilities(DC_MEDIATYPENAMES, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
        }
        else
        {
            NAME_64BYTES *pn64 = NULL;
            for (i=0, pn64=(NAME_64BYTES *)ppi; i<n; i++, pn64++)
            {
                memcpy(pList->PtrDataInfo[i].name,pn64->name,sizeof(NAME_64BYTES));
            }
        }
    }

    Log(LOG_DEBUG,__LINE__,"<< GetMediaTypeList, List %p",pList);
    return pList;
}
unsigned WINAPI PrinterInfo(LPVOID lpData)
{
    int l = 0, n = 0, i = 0;
    DWORD *pdw = NULL;
    WORD *pw = NULL;
    BYTE *ppi = NULL;
    POINT *pp = NULL;
    PBuffer B;

    char PrinterName[_MAX_PATH] = {0};
    char DriverName[_MAX_PATH] = {0};
    char PortName[_MAX_PATH] = {0};

    DWORD dwLastError = 0;
    char szLastError[_MAX_PATH] = {0};

    NAME_32BYTES *pn32 = NULL;
    NAME_64BYTES *pn64 = NULL;

    unsigned __int64 tickStart = SysTick();

    Log(LOG_DEBUG,__LINE__,">> PtrInfo");
    if(GetPrintersList()==0)
    {
        Log(LOG_DEBUG,__LINE__,"<< PtrInfo, No Printer");
        _endthreadex(0);
        return 0;
    }

    if(!gpPrinterInfoList)
    {
        Log(LOG_DEBUG,__LINE__,"<< PtrInfo, PtrInfoList null");
        _endthreadex(ERROR_OUTOFMEMORY);
        return ERROR_OUTOFMEMORY;
    }

    for(int printerCnt=0;printerCnt<gpPrinterInfoList->num;printerCnt++)
    {
        memset(PrinterName,0x00,sizeof(PrinterName));
        memset(PortName,0x00,sizeof(PortName));
        memset(DriverName,0x00,sizeof(DriverName));

        strncpy(PrinterName,gpPrinterInfoList->PrinterInfo[printerCnt].PrinterName,_MAX_PATH-1);
        strncpy(PortName,gpPrinterInfoList->PrinterInfo[printerCnt].PortName,_MAX_PATH-1);
        strncpy(DriverName,gpPrinterInfoList->PrinterInfo[printerCnt].DriverName,_MAX_PATH-1);

        Log(LOG_HEADER,__LINE__,"Info from %s, Port %s, Driver %s (%d)",PrinterName,PortName,DriverName,printerCnt);

        //GET PRINTER CAPABILITIES
        // *** resolution(s)
        if ((l = DeviceCapabilities(PrinterName,PortName,DC_ENUMRESOLUTIONS,NULL,NULL)) <= 0)
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_ENUMRESOLUTIONS, null) Err %d Msg %s",dwLastError,szLastError);
        }
        else
        {
            ppi = B._allocMem(l*sizeof(POINT));
            if (!ppi)
            {
                Log(LOG_DEBUG,__LINE__,"-- PtrInfo, <%s> new DC_ENUMRESOLUTIONS mem null",PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_ENUMRESOLUTIONS, (LPSTR)ppi, NULL)) != l)
                {
                    dwLastError = GetLastError();
                    GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
                    Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_ENUMRESOLUTIONS, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
                }
                else
                {
                    Log(LOG_MESSAGE,__LINE__,"DC_ENUMRESOLUTIONS (%d):",n);
                    for(i=0, pdw=(DWORD*)ppi;i<n;i++)
                    {
                        Log(LOG_MESSAGE,__LINE__,">%.2d: %u x %u",i+1,pdw[i*2],pdw[i*2+1]);
                    }
                }
            }
        }

        // *** bins & binnames
        try
        {
            LP_PTRDATA_INFO_LIST pBinList = GetBinList(PrinterName,PortName);
            if(pBinList)
            {
                Log(LOG_MESSAGE,__LINE__,"DC_BINS, DC_BINNAMES (%d):",pBinList->num);
                for(i=0;i<pBinList->num;i++)
                {
                    Log(LOG_MESSAGE,__LINE__,">%.2d: %u, %s",i+1,pBinList->PtrDataInfo[i].id,pBinList->PtrDataInfo[i].name);
                }
                delete [] pBinList;
                pBinList = NULL;
            }
        }
        catch(...)
        {
            Log(LOG_DEBUG,__LINE__,"-- PtrInfo, Catch unhndld excpetion on BinList");
        }

        // *** papers & paper names & paper sizes
        try
        {
            LP_PTRDATA_INFO_LIST pPaperList = GetPaperList(PrinterName,PortName);
            if(pPaperList)
            {
                Log(LOG_MESSAGE,__LINE__,"DC_PAPERS, DC_PAPERNAMES, DC_PAPERSIZE (%d):",pPaperList->num);
                for(i=0;i<pPaperList->num;i++)
                {
                    Log(LOG_MESSAGE,__LINE__,">%.2d: %u, %s, %.5d %.5d",i+1,pPaperList->PtrDataInfo[i].id,pPaperList->PtrDataInfo[i].name,pPaperList->PtrDataInfo[i].x,pPaperList->PtrDataInfo[i].y);
                }
                delete [] pPaperList;
                pPaperList = NULL;
            }
        }
        catch(...)
        {
            Log(LOG_DEBUG,__LINE__,"-- PtrInfo, Catch unhndld excpetion on PaperList");
        }

        // *** portrait - landscape
        l = DeviceCapabilities(PrinterName, PortName, DC_ORIENTATION, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_ORIENTATION %d",l);

        // *** maximum number of copies supported
        l = DeviceCapabilities(PrinterName, PortName, DC_COPIES, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_COPIES %d",l);

        // *** collate
        l = DeviceCapabilities(PrinterName, PortName, DC_COLLATE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_COLLATE %d",l);

        // *** color support
        l = DeviceCapabilities(PrinterName, PortName, DC_COLORDEVICE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_COLORDEVICE %d",l);

        // *** duplex support
        l = DeviceCapabilities(PrinterName, PortName, DC_DUPLEX, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_DUPLEX %d",l);

        // *** driver version
        l = DeviceCapabilities(PrinterName, PortName, DC_DRIVER, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_DRIVER %d",l);

        // *** spec driver version
        l = DeviceCapabilities(PrinterName, PortName, DC_VERSION, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_VERSION %d",l);

        // *** fields
        l = DeviceCapabilities(PrinterName, PortName, DC_FIELDS, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_FIELDS %u",l);

        // *** maximum paper size
        l = DeviceCapabilities(PrinterName, PortName, DC_MAXEXTENT, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_MAXEXTENT: Lenght %u, Width %u",HIWORD((DWORD)l),LOWORD((DWORD)l));

        // *** minimum paper size
        l = DeviceCapabilities(PrinterName, PortName, DC_MINEXTENT, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_MINEXTENT: Lenght %u, Width %u",HIWORD((DWORD)l),LOWORD((DWORD)l));

        // *** size
        l = DeviceCapabilities(PrinterName, PortName, DC_SIZE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_SIZE %d",l);

        // *** staple
        l = DeviceCapabilities(PrinterName, PortName, DC_STAPLE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_STAPLE %d",l);

        // *** TrueType
        l = DeviceCapabilities(PrinterName, PortName, DC_TRUETYPE, (LPSTR)ppi, NULL);
        Log(LOG_MESSAGE,__LINE__,"DC_TRUETYPE %d",l);

        // *** multiple document pages per printed page
        if ((l = DeviceCapabilities(PrinterName, PortName, DC_NUP, NULL, NULL)) <= 0)
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_NUP, null) Err %d Msg %s",dwLastError,szLastError);
        }
        else
        {
            ppi = B._allocMem(l*sizeof(DWORD));
            if (!ppi)
            {
                Log(LOG_DEBUG,__LINE__,"-- PtrInfo, <%s> new DC_NUP mem null",PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_NUP, (LPSTR)ppi, NULL)) != l)
                {
                    dwLastError = GetLastError();
                    GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
                    Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_NUP, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
                }
                else
                {
                    Log(LOG_MESSAGE,__LINE__,"DC_NUP (%d):",n);
                    for (i=0, pdw=(DWORD *)ppi; i<n; i++, pdw++)
                    {
                        Log(LOG_MESSAGE,__LINE__,">%.2d: %u",i+1,*pdw);
                    }
                }
            }
        }

        // *** field dependencies
        if ((l = DeviceCapabilities(PrinterName, PortName, DC_FILEDEPENDENCIES, NULL, NULL)) <= 0)
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_FILEDEPENDENCIES, null) Err %d Msg %s",dwLastError,szLastError);
        }
        else
        {
            ppi = B._allocMem(l*sizeof(NAME_64BYTES));
            if (!ppi)
            {
                Log(LOG_DEBUG,__LINE__,"-- PtrInfo, <%s> new DC_FILEDEPENDENCIES mem null",PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_FILEDEPENDENCIES, (LPSTR)ppi, NULL)) != l)
                {
                    dwLastError = GetLastError();
                    GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
                    Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_FILEDEPENDENCIES, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
                }
                else
                {
                    pn64 = NULL;
                    Log(LOG_MESSAGE,__LINE__,"DC_FILEDEPENDENCIES (%d):",n);
                    for (i=0, pn64=(NAME_64BYTES *)ppi; i<n; i++, pn64++)
                    {
                        pn64->name[63] = 0x00;      //avoid memory over-read if the whole buffer is filled
                        Log(LOG_MESSAGE,__LINE__,">%.2d: %s",i+1,pn64->name);
                    }
                }
            }
        }

        // *** paper forms
        if ((l = DeviceCapabilities(PrinterName, PortName, DC_MEDIAREADY, NULL, NULL)) <= 0)
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_MEDIAREADY, null) Err %d Msg %s",dwLastError,szLastError);
        }
        else
        {
            ppi = B._allocMem(l*sizeof(NAME_64BYTES));
            if (!ppi)
            {
                Log(LOG_DEBUG,__LINE__,"-- PtrInfo, <%s> new DC_MEDIAREADY mem null",PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_MEDIAREADY, (LPSTR)ppi, NULL)) != l)
                {
                    dwLastError = GetLastError();
                    GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
                    Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_MEDIAREADY, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
                }
                else
                {
                    pn64 = NULL;
                    Log(LOG_MESSAGE,__LINE__,"DC_MEDIAREADY (%d):",n);
                    for (i=0, pn64=(NAME_64BYTES *)ppi; i<n; i++, pn64++)
                    {
                        pn64->name[63] = 0x00;      //avoid memory over-read if the whole buffer is filled
                        Log(LOG_MESSAGE,__LINE__,">%.2d: %s",i+1,pn64->name);
                    }
                }
            }
        }

        if(GetWinVer()>5)
        {
            // *** media types & media type names
            try
            {
                LP_PTRDATA_INFO_LIST pMediaTypeList = GetMediaTypeList(PrinterName,PortName);
                if(pMediaTypeList)
                {
                    Log(LOG_MESSAGE,__LINE__,"DC_MEDIATYPES, DC_MEDIATYPENAMES (%d):",pMediaTypeList->num);
                    for(i=0;i<pMediaTypeList->num;i++)
                    {
                        Log(LOG_MESSAGE,__LINE__,">%.2d: %u, %s",i+1,pMediaTypeList->PtrDataInfo[i].id,pMediaTypeList->PtrDataInfo[i].name);
                    }
                    delete [] pMediaTypeList;
                    pMediaTypeList = NULL;
                }
            }
            catch(...)
            {
                Log(LOG_DEBUG,__LINE__,"-- PtrInfo, Catch unhndld excpetion on MediaTypeList");
            }
        }

        // *** list of printer description languages supported
        if ((l = DeviceCapabilities(PrinterName, PortName, DC_PERSONALITY, NULL, NULL)) <= 0)
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_PERSONALITY, null) Err %d Msg %s",dwLastError,szLastError);
        }
        else
        {
            ppi = B._allocMem(l*sizeof(NAME_32BYTES));
            if (!ppi)
            {
                Log(LOG_DEBUG,__LINE__,"-- PtrInfo, <%s> new DC_PERSONALITY mem null",PrinterName);
            }
            else
            {
                if ((n = DeviceCapabilities(PrinterName, PortName, DC_PERSONALITY, (LPSTR)ppi, NULL)) != l)
                {
                    dwLastError = GetLastError();
                    GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
                    Log(LOG_DEBUG,__LINE__,"-- PtrInfo, DeviceCapabilities(DC_PERSONALITY, %p) Err %d Msg %s",ppi,dwLastError,szLastError);
                }
                else
                {
                    pn32 = NULL;
                    Log(LOG_MESSAGE,__LINE__,"DC_PERSONALITY (%d):",n);
                    for (i=0, pn32=(NAME_32BYTES *)ppi; i<n; i++, pn32++)
                    {
                        pn32->name[31] = 0x00;      //avoid memory over-read if the whole buffer is filled
                        Log(LOG_MESSAGE,__LINE__,">%.2d: %s",i+1,pn32->name);
                    }
                }
            }
        }

        // *** document properties
        HANDLE hPrinter = NULL;
        if(OpenPrinter(PrinterName,&hPrinter,NULL))
        {
            l = DocumentProperties(NULL,hPrinter,DriverName,NULL,NULL,0);
            DEVMODE *pdm = (DEVMODE *)new char[l];
            if(pdm)
            {
                memset(pdm,0x00,sizeof(char)*l);
                DocumentProperties(NULL,hPrinter,DriverName,pdm,NULL,DM_OUT_BUFFER);
                Log(LOG_MESSAGE,__LINE__,"DEVMODE:");
                Log(LOG_MESSAGE,__LINE__,"> DeviceName %s",pdm->dmDeviceName);
                Log(LOG_MESSAGE,__LINE__,"> SpecVersion %d",pdm->dmSpecVersion);
                Log(LOG_MESSAGE,__LINE__,"> DriverVersion %d",pdm->dmDriverVersion);
                Log(LOG_MESSAGE,__LINE__,"> Size %d",pdm->dmSize);
                Log(LOG_MESSAGE,__LINE__,"> DriverExtra %d",pdm->dmDriverExtra);
                Log(LOG_MESSAGE,__LINE__,"> DriverFields 0x%.8X",pdm->dmFields);
                Log(LOG_MESSAGE,__LINE__,"> Orient %d",pdm->dmOrientation);
                Log(LOG_MESSAGE,__LINE__,"> PaperSize %d",pdm->dmPaperSize);
                Log(LOG_MESSAGE,__LINE__,"> PaperLenght %d",pdm->dmPaperLength);
                Log(LOG_MESSAGE,__LINE__,"> PaperWidth %d",pdm->dmPaperWidth);
                Log(LOG_MESSAGE,__LINE__,"> Scale %d",pdm->dmScale);
                Log(LOG_MESSAGE,__LINE__,"> Copies %d",pdm->dmCopies);
                Log(LOG_MESSAGE,__LINE__,"> DefaultSource %d",pdm->dmDefaultSource);
                Log(LOG_MESSAGE,__LINE__,"> PrintQulity %d",pdm->dmPrintQuality);
                Log(LOG_MESSAGE,__LINE__,"> Color %d",pdm->dmColor);
                Log(LOG_MESSAGE,__LINE__,"> Duplex %d",pdm->dmDuplex);
                Log(LOG_MESSAGE,__LINE__,"> YResolution %d",pdm->dmYResolution);
                Log(LOG_MESSAGE,__LINE__,"> TTOption %d",pdm->dmTTOption);
                Log(LOG_MESSAGE,__LINE__,"> Collate %d",pdm->dmCollate);
                Log(LOG_MESSAGE,__LINE__,"> FormName %s",pdm->dmFormName);
                Log(LOG_MESSAGE,__LINE__,"> LogPixels %d",pdm->dmLogPixels);
                Log(LOG_MESSAGE,__LINE__,"> BitsPerPel %u",pdm->dmBitsPerPel);
                Log(LOG_MESSAGE,__LINE__,"> PelsWidth %u",pdm->dmPelsWidth);
                Log(LOG_MESSAGE,__LINE__,"> PelsHeight %d",pdm->dmPelsHeight);
                if(GetWinVer()>=4)
                {
                    Log(LOG_MESSAGE,__LINE__,"> ICMMethod %u",pdm->dmICMMethod);
                    Log(LOG_MESSAGE,__LINE__,"> ICMIntent %u",pdm->dmICMIntent);
                    Log(LOG_MESSAGE,__LINE__,"> MediaType %u",pdm->dmMediaType);
                    Log(LOG_MESSAGE,__LINE__,"> DitherType %u",pdm->dmDitherType);
                    Log(LOG_MESSAGE,__LINE__,"> Reserved1 %u",pdm->dmReserved1);
                    Log(LOG_MESSAGE,__LINE__,"> Reserved2 %u",pdm->dmReserved2);
                    if(GetWinVer()>=5)
                    {
                        Log(LOG_MESSAGE,__LINE__,"> PanningWidth %u",pdm->dmPanningWidth);
                        Log(LOG_MESSAGE,__LINE__,"> PanningHeight %u",pdm->dmPanningHeight);
                    }
                }

                delete [] pdm;
                pdm = NULL;
            }
            ClosePrinter(hPrinter);
        }
        else
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- PtrInfo, OpenPrinter Err %d Msg %s",dwLastError,szLastError);
        }

        // *** fonts information
        HDC hdc = NULL;
        if(hdc = CreateIC(DriverName, PrinterName, NULL, NULL))
        {
            Log(LOG_MESSAGE,__LINE__,"DeviceCaps:");

            l = GetDeviceCaps(hdc,DRIVERVERSION);
            Log(LOG_MESSAGE,__LINE__,"> DRIVERVERSION %d",l);

            l = GetDeviceCaps(hdc,TECHNOLOGY);
            Log(LOG_MESSAGE,__LINE__,"> TECHNOLOGY %d",l);

            l = GetDeviceCaps(hdc,HORZSIZE);
            Log(LOG_MESSAGE,__LINE__,"> HORZSIZE %d",l);

            l = GetDeviceCaps(hdc,VERTSIZE);
            Log(LOG_MESSAGE,__LINE__,"> VERTSIZE %d",l);

            l = GetDeviceCaps(hdc,HORZRES);
            Log(LOG_MESSAGE,__LINE__,"> HORZRES %d",l);

            l = GetDeviceCaps(hdc,VERTRES);
            Log(LOG_MESSAGE,__LINE__,"> VERTRES %d",l);

            l = GetDeviceCaps(hdc,BITSPIXEL);
            Log(LOG_MESSAGE,__LINE__,"> BITSPIXEL %d",l);

            l = GetDeviceCaps(hdc,PLANES);
            Log(LOG_MESSAGE,__LINE__,"> PLANES %d",l);

            l = GetDeviceCaps(hdc,NUMBRUSHES);
            Log(LOG_MESSAGE,__LINE__,"> NUMBRUSHES %d",l);

            l = GetDeviceCaps(hdc,NUMPENS);
            Log(LOG_MESSAGE,__LINE__,"> NUMPENS %d",l);

            l = GetDeviceCaps(hdc,NUMMARKERS);
            Log(LOG_MESSAGE,__LINE__,"> NUMMARKERS %d",l);

            l = GetDeviceCaps(hdc,NUMFONTS);
            Log(LOG_MESSAGE,__LINE__,"> NUMFONTS %d",l);

            l = GetDeviceCaps(hdc,NUMCOLORS);
            Log(LOG_MESSAGE,__LINE__,"> NUMCOLORS %d",l);

            l = GetDeviceCaps(hdc,PDEVICESIZE);
            Log(LOG_MESSAGE,__LINE__,"> PDEVICESIZE %d",l);

            l = GetDeviceCaps(hdc,CURVECAPS);
            Log(LOG_MESSAGE,__LINE__,"> CURVECAPS %d",l);

            l = GetDeviceCaps(hdc,LINECAPS);
            Log(LOG_MESSAGE,__LINE__,"> LINECAPS %d",l);

            l = GetDeviceCaps(hdc,POLYGONALCAPS);
            Log(LOG_MESSAGE,__LINE__,"> POLYGONALCAPS %d",l);

            l = GetDeviceCaps(hdc,TEXTCAPS);
            Log(LOG_MESSAGE,__LINE__,"> TEXTCAPS %d",l);

            l = GetDeviceCaps(hdc,CLIPCAPS);
            Log(LOG_MESSAGE,__LINE__,"> CLIPCAPS %d",l);

            l = GetDeviceCaps(hdc,RASTERCAPS);
            Log(LOG_MESSAGE,__LINE__,"> RASTERCAPS %d",l);

            l = GetDeviceCaps(hdc,ASPECTX);
            Log(LOG_MESSAGE,__LINE__,"> ASPECTX %d",l);

            l = GetDeviceCaps(hdc,ASPECTY);
            Log(LOG_MESSAGE,__LINE__,"> ASPECTY %d",l);

            l = GetDeviceCaps(hdc,ASPECTXY);
            Log(LOG_MESSAGE,__LINE__,"> ASPECTXY %d",l);

            l = GetDeviceCaps(hdc,LOGPIXELSX);
            Log(LOG_MESSAGE,__LINE__,"> LOGPIXELSX %d",l);

            l = GetDeviceCaps(hdc,LOGPIXELSY);
            Log(LOG_MESSAGE,__LINE__,"> LOGPIXELSY %d",l);

            l = GetDeviceCaps(hdc,SIZEPALETTE);
            Log(LOG_MESSAGE,__LINE__,"> SIZEPALETTE %d",l);

            l = GetDeviceCaps(hdc,NUMRESERVED);
            Log(LOG_MESSAGE,__LINE__,"> NUMRESERVED %d",l);

            l = GetDeviceCaps(hdc,COLORRES);
            Log(LOG_MESSAGE,__LINE__,"> COLORRES %d",l);

            l = GetDeviceCaps(hdc,PHYSICALWIDTH);
            Log(LOG_MESSAGE,__LINE__,"> PHYSICALWIDTH %d",l);

            l = GetDeviceCaps(hdc,PHYSICALHEIGHT);
            Log(LOG_MESSAGE,__LINE__,"> PHYSICALHEIGHT %d",l);

            l = GetDeviceCaps(hdc,PHYSICALOFFSETX);
            Log(LOG_MESSAGE,__LINE__,"> PHYSICALOFFSETX %d",l);

            l = GetDeviceCaps(hdc,PHYSICALOFFSETY);
            Log(LOG_MESSAGE,__LINE__,"> PHYSICALOFFSETY %d",l);

            l = GetDeviceCaps(hdc,SCALINGFACTORX);
            Log(LOG_MESSAGE,__LINE__,"> SCALINGFACTORX %d",l);

            l = GetDeviceCaps(hdc,SCALINGFACTORY);
            Log(LOG_MESSAGE,__LINE__,"> SCALINGFACTORY %d",l);

            l = GetDeviceCaps(hdc,VREFRESH);
            Log(LOG_MESSAGE,__LINE__,"> VREFRESH %d",l);

            l = GetDeviceCaps(hdc,DESKTOPVERTRES);
            Log(LOG_MESSAGE,__LINE__,"> DESKTOPVERTRES %d",l);

            l = GetDeviceCaps(hdc,DESKTOPHORZRES);
            Log(LOG_MESSAGE,__LINE__,"> DESKTOPHORZRES %d",l);

            l = GetDeviceCaps(hdc,BLTALIGNMENT);
            Log(LOG_MESSAGE,__LINE__,"> BLTALIGNMENT %d",l);

            if(GetWinVer()>=5)
            {
                l = GetDeviceCaps(hdc,SHADEBLENDCAPS);
                Log(LOG_MESSAGE,__LINE__,"> SHADEBLENDCAPS %d",l);

                l = GetDeviceCaps(hdc,COLORMGMTCAPS);
                Log(LOG_MESSAGE,__LINE__,"> COLORMGMTCAPS %d",l);
            }

            //*** device context layout
            DWORD dw = GetLayout(hdc);
            Log(LOG_MESSAGE,__LINE__,"Layout %u",dw);

            //*** printer to the default FONT
            HGDIOBJ hGdi = NULL;
            if((hGdi = GetCurrentObject(hdc,OBJ_FONT))!= NULL)
            {
                int iBufferSize = 0;

                if( iBufferSize = GetObject(hGdi,0,NULL))
                {
                    LOGFONT *pLogFont = (LOGFONT *)new char[iBufferSize];
                    if(pLogFont)
                    {
                        if(GetObject(hGdi,iBufferSize,pLogFont))
                        {
                            Log(LOG_MESSAGE,__LINE__,"DEFAULT FONT:");
                            Log(LOG_MESSAGE,__LINE__,"> Height %d",pLogFont->lfHeight);
                            Log(LOG_MESSAGE,__LINE__,"> Width %d",pLogFont->lfWidth);
                            Log(LOG_MESSAGE,__LINE__,"> Escapment %d",pLogFont->lfEscapement);
                            Log(LOG_MESSAGE,__LINE__,"> Orientation %d",pLogFont->lfOrientation);
                            Log(LOG_MESSAGE,__LINE__,"> Weight %d",pLogFont->lfWeight);
                            Log(LOG_MESSAGE,__LINE__,"> Italic %.2Xh",pLogFont->lfItalic);
                            Log(LOG_MESSAGE,__LINE__,"> Underline %.2Xh",pLogFont->lfUnderline);
                            Log(LOG_MESSAGE,__LINE__,"> StrikeOut %.2Xh",pLogFont->lfStrikeOut);
                            Log(LOG_MESSAGE,__LINE__,"> CharSet %.2Xh",pLogFont->lfCharSet);
                            Log(LOG_MESSAGE,__LINE__,"> OutPrecision %.2Xh",pLogFont->lfOutPrecision);
                            Log(LOG_MESSAGE,__LINE__,"> ClipPrecision %.2Xh",pLogFont->lfClipPrecision);
                            Log(LOG_MESSAGE,__LINE__,"> Quality %.2Xh",pLogFont->lfQuality);
                            Log(LOG_MESSAGE,__LINE__,"> PitchAndFamily %.2Xh",pLogFont->lfPitchAndFamily);
                            Log(LOG_MESSAGE,__LINE__,"> FaceName %s",pLogFont->lfFaceName);
                        }
                        delete [] pLogFont;
                    }
                    else
                    {
                        Log(LOG_DEBUG,__LINE__,"-- PtrInfo, new LOGFONT null");
                    }
                }
            }
            DeleteDC(hdc);
        }
        else
        {
            dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,_MAX_PATH-1);
            Log(LOG_DEBUG,__LINE__,"-- PtrInfo, CreateIC Err %d Msg %s",dwLastError,szLastError);
        }
    }   //END: for(int printerCnt=0;printerCnt<gpPrinterInfoList->num;printerCnt++)

    //release printer info list
    if(gpPrinterInfoList)
    {
        delete [] gpPrinterInfoList;
        gpPrinterInfoList = NULL;
    }

    LogElapsedTime(__LINE__,tickStart);

    Log(LOG_DEBUG,__LINE__,"<< PtrInfo");
    _endthreadex(0);
    return 0;
}

/*
** GetSystemIPAddresses: list all IP adresses in the system, if possible
*/
void GetSystemIPAddresses(MonitorIPs *monIps,bool bMonIps)
{
    Log(LOG_DEBUG,__LINE__,">> GetSysIPAddrs, %p, %s",monIps,(bMonIps?"True":"False"));

    if(bMonIps && monIps)
    {
        unsigned __int64 tickStart = SysTick();
        vector<string> ips;
        monIps->GetIPs(ips);

        if(ips.size())
        {
            Log(LOG_HEADER,__LINE__,"IP Addresses (%u):",ips.size());

            for(unsigned int cnt=0;cnt<ips.size();cnt++)
            {
                Log(LOG_MESSAGE,__LINE__,"> %02u %s",cnt+1,ips.at(cnt).c_str());
            }
        }

        LogElapsedTime(__LINE__,tickStart);
    }
    Log(LOG_DEBUG,__LINE__,"<< GetSysIPAddrs");
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
    Log(LOG_DEBUG,__LINE__,">> GetSysDets");

    /* Hardware Profile */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("HwProfile",HwProfile,NULL,MINUTE);
    }

    /* Computer */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("SysInfo",SystemInfo,NULL,MINUTE);
    }

    /* OSInfo */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("OSInfo",OSInfo,NULL,MINUTE);
    }

    /* Logical Processor(s) Information */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("SysLogPrcsrInfo",SystemLogicalProcessorInforamtion,NULL,MINUTE);
    }

    /* System Directories */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("SysDirs",SystemDirs,NULL,MINUTE);
    }

    Log(LOG_DEBUG,__LINE__,"<< GetSysDets");
}

/*
** GetSystemStatus: Performance system information
*/
void GetSystemStatus(void)
{
    Log(LOG_DEBUG,__LINE__,">> GetSysSts");

    /* System Times */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("SysTimes",SystemTimes,NULL,MINUTE);
    }

    /* System Memory */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("SysMem",SystemMemory,NULL,MINUTE);
    }

    /* Performance Information */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("PerfInfo",PerformanceInfo,NULL,MINUTE);
    }

    /* Processes Informaton */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("ProcInfo",ProcessInfo,NULL,MINUTE);
    }

    Log(LOG_DEBUG,__LINE__,"<< GetSysSts");
}

/*
** GetSystemStatusChanges: Runtime changable system information
*/
void GetSystemStatusChanges(void)
{
    /* Logical Drivers */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("LogDrvs",LogicalDrives,NULL,MINUTE);
    }

    /* Enumerate USB */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("USB",ThreadUSB,NULL,MINUTE);
    }

    /* Device Drivers */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("DevDrvrs",DeviceDrivers,NULL,MINUTE);
    }

    /* Printers Information */
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("PtrInfo",PrinterInfo,NULL,MINUTE);
    }
}

/*
** GetWMIStatus
*/
//thread for system performance
unsigned WINAPI ThreadWMISystemPerformance(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> ThrdWMISysPerf");

    WMISystemPerformance();

    Log(LOG_DEBUG,__LINE__,"<< ThrdWMISysPerf");
    _endthreadex(0);
    return 0;
}

//thread for hardware sensor information
unsigned WINAPI ThreadWMIHardwareSensor(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> ThrdWMIHwSnsr");

    WMIHardwareSensor();

    Log(LOG_DEBUG,__LINE__,"<< ThrdWMIHwSnsr");
    _endthreadex(0);
    return 0;
}

//thread for all system volume details
unsigned WINAPI ThreadWMISystemVolumes(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> ThrdWMISysVols");

    WMISystemVolumes();

    Log(LOG_DEBUG,__LINE__,"<< ThrdWMISysVols");
    _endthreadex(0);
    return 0;
}

#ifdef _GET_WMI_USBINFO
//thread for all system usb details
unsigned WINAPI ThreadWMISystemUsb(LPVOID lpData)
{
    Log(LOG_DEBUG,__LINE__,">> ThrdWMISysUsb");

    WMISystemUsb();

    Log(LOG_DEBUG,__LINE__,"<< ThrdWMISysUsb");
    _endthreadex(0);
    return 0;
}
#endif

void GetWMIStatus(void)
{
    Log(LOG_DEBUG,__LINE__,">> GetWMISts");

    //get system performance
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("WMISysPerf",ThreadWMISystemPerformance,NULL,MINUTE*5);
    }

    //get hardware sensor information
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("WMIHwSnsr",ThreadWMIHardwareSensor,NULL,MINUTE*5);
    }

    //get all system volume details
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("WMISysVols",ThreadWMISystemVolumes,NULL,MINUTE*5);
    }

#ifdef _GET_WMI_USBINFO
    //get all system usb details
    if(_thGetInt(&gbShutdown)==FALSE)
    {
        StartThread("WMISysUsb",ThreadWMISystemUsb,NULL,MINUTE*5);
    }
#endif
    Log(LOG_DEBUG,__LINE__,"<< GetWMISts");
}

/*
** WinMain:	Main program function
*/
int __stdcall WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nShowCmd)
{
    HANDLE hThreadWMI = NULL;
    HANDLE hThreadMSG = NULL;
    DWORD dwTimer = (MINUTE);       //default 1 minute
	DWORD dwLastState = 0;
	DWORD dwRet = 0;
    DWORD dwLogSize = (MBYTES*5);   //default 5 MB

    unsigned __int64 ui64Wait = 0;

    DWORD dwNetType;
    BOOL bNet;

    bool bShowWindow = true;
    bool bRunWMI = false;
    bool bRunOnce = false;
    bool bWMIThreadRunning = false;

    LPTOP_LEVEL_EXCEPTION_FILTER pPreviousExceptionFilter = SetUnhandledExceptionFilter(AppUnhandledExceptionFilter);
    RedirectSetUnhandledExceptionFilter();

    ghInstance = hInstance;

    //check whether or not it to run once
    if(lpCmdLine)
    {
        //convert command line to be checked
        _strlwr(lpCmdLine);

        //check whether the app should run only once
        if(strstr(lpCmdLine,"runonce")!=NULL)
        {
            bRunOnce = true;
        }
        else
        {
            bRunOnce = false;
        }

        //check whether the app should get information details about the system thru WMI
        if(strstr(lpCmdLine,"sysinfo")!=NULL)
        {
            bRunWMI = true;
        }
        else
        {
            bRunWMI = false;
        }

        //check whether the app should not show the window
        if(strstr(lpCmdLine,"nowindow")!=NULL)
        {
            bShowWindow = false;
        }

        //check the wait time between exeutions
        char *timer = strstr(lpCmdLine,"timer");
        if(timer)
        {
            timer += 6;
            dwTimer = (DWORD)atoi(timer);

            //timer from 1 to 360 minutes for checking the system status
            DWORD minTimer = 1, maxTimer = 360;
            if(dwTimer>=minTimer && dwTimer<=maxTimer)
            {
                dwTimer *= MINUTE;      //number of minutes specified in milliseconds
            }
        }

        //check the wait time between exeutions
        char *logsize = strstr(lpCmdLine,"logsize");
        if(logsize)
        {
            logsize += 8;
            dwLogSize = (DWORD)(atoi(logsize)*KBYTES);
            //maximum log file size should be 15 MB
            if(dwLogSize>(MBYTES*15))
            {
                dwLogSize = (MBYTES*15);
            }
        }

        char *logdir = strstr(lpCmdLine,"logdir");
        if(logdir)
        {
            //remove 'logdir:'
            logdir += 7;
            
            //add '\' if last by doesn't
            if(strlen(logdir)>0)
            {
                if(logdir[strlen(logdir)-1]!='\\')
                {
                    _snprintf(gszLogFilePrefix,sizeof(gszLogFilePrefix)-1,"%s\\SysStatus",logdir);
                }
                else
                {
                    _snprintf(gszLogFilePrefix,sizeof(gszLogFilePrefix)-1,"%sSysStatus",logdir);
                }
            }
            else
            {
                //get log file prefix
	            if (GetModuleBaseName(GetCurrentProcess(),NULL,gszLogFilePrefix,sizeof(gszLogFilePrefix)) > 0)
	            {
		            //remove log file extension
		            PathRemoveExtension(gszLogFilePrefix);
	            }
	            else
	            {
		            //copy default name
		            strcpy(gszLogFilePrefix,"SysStatus");
	            }
            }
        }
        else
        {
            //get log file prefix
	        if (GetModuleBaseName(GetCurrentProcess(),NULL,gszLogFilePrefix,sizeof(gszLogFilePrefix)) > 0)
	        {
		        //remove log file extension
		        PathRemoveExtension(gszLogFilePrefix);
	        }
	        else
	        {
		        //copy default name
		        strcpy(gszLogFilePrefix,"SysStatus");
	        }
        }
    }

    gTickStart = SysTick();
    Log(LOG_DEBUG,__LINE__,">> WinMain");

    PendingThreads.clear();

    //start new log
    CheckLogFileSize(0);

    Log(LOG_HEADER,__LINE__,"SysStatus, CmdLine %s",lpCmdLine);

    //Start window thread
    StartThread("ThrdMsg",ThreadMessage,&bShowWindow,0,&hThreadMSG);

    if(bRunWMI)
    {
        //Start WMI main thread
        bWMIThreadRunning = StartThread("ThrWMI",ThreadWMI,NULL,0,&hThreadWMI);
    }

    //Start IPs monitor
    MonitorIPs monIps;
    bool bMonIps = monIps.Initialize();

    if((bRunOnce==false) || (bRunOnce==true && bWMIThreadRunning==true))
    {
        //get unchangable system information
        GetSystemDetails();

        //get runtime changable system information
        GetSystemStatusChanges();

        //get IPs if possible
        GetSystemIPAddresses(&monIps,bMonIps);
    }

    float timeElapsed;
    unsigned long seconds;
    unsigned __int64 tickEnd;
    char wndText[_MAX_PATH];

    //run while:
    // 1. close or end session has been requested AND 
    //    running mode is continuous
    // OR
    // 2. close or end session has been requested AND 
    //    running mode is simple AND
    //    WMI thread is still running
    while(_thGetInt(&gbTerminate)==FALSE && 
          ((bRunOnce==false) || (bRunOnce==true && bWMIThreadRunning==true))
         )
    {
        if(bRunWMI)
        {
            if(WaitForSingleObject(hThreadWMI,(MILLISECOND*100))==WAIT_TIMEOUT)
            {
                bWMIThreadRunning = true;
            }
            else
            {
                bWMIThreadRunning = false;
            }
        }

        if(ui64Wait>SysTick() && _thGetInt(&gbForceChecking)==FALSE)
        {
            //Wait a second and then continue
            Sleep(SECOND);
            continue;
        }

        if(_thGetInt(&gbForceChecking)==TRUE)
        {
            //get runtime changable system information
            GetSystemStatusChanges();

            //stop force checking
            _thSetInt(&gbForceChecking,FALSE);
        }

        //get system information
        GetSystemStatus();

        //get WMI status information if WMI system info thread has been completed
        if(!bWMIThreadRunning && bRunWMI)
        {
            //get WMI status information
            GetWMIStatus();
        }

        //Is network alive?
        bNet = IsNetworkAlive(&dwNetType);
        dwRet = GetLastError();
        
        //Was function executed successfully?
        if(ERROR_SUCCESS==dwRet)
        {
            Log(LOG_HEADER,__LINE__,"Net Alive? %s, Type %u",(bNet?"Yes":"No"),dwNetType);
        }
        else
        {
            Log(LOG_HEADER,__LINE__,"Net Chkg Err %u",dwRet);
        }

        //Get IPs if possible and changed
        if(monIps.IsChanged())
        {
            GetSystemIPAddresses(&monIps,bMonIps);
        }

        CalcElapsedTime(gTickStart,tickEnd,timeElapsed,seconds);
        Log(LOG_DEBUG,__LINE__,"-- %02d:%02d:%02d, %f s",seconds/3600,(seconds % 3600)/60,seconds % 60,timeElapsed);

        if(bShowWindow)
        {
            //Update the window name with the time app is running
            memset(wndText,0x00,sizeof(wndText));
            _snprintf(wndText,sizeof(wndText)-1,"SysStatus - Running for %02d:%02d",seconds/3600,(seconds % 3600)/60);
            SetWindowText(ghWnd,(LPCTSTR)wndText);
        }

        //check de log file size
        CheckLogFileSize(dwLogSize);

        //set timer for next checking
        ui64Wait = SysTick() + dwTimer;
    }   //END: while(_thGetInt(&gbTerminate)==FALSE && bRunOnce==false)

    //wait for WMI Ascii thread completion
    if(hThreadWMI)
    {
        if(bRunOnce)
        {
            //wait until it is completed
            WaitForSingleObject(hThreadWMI,INFINITE);
        }
        else
        {
            //quickly wait while the thread has not completed
            //and, when timeout is completed, force terminate
            //the WMI thread if the thread is still runing
            if(WaitForSingleObject(hThreadWMI,(MINUTE*10))==WAIT_TIMEOUT)
            {
                EndPendingThread(hThreadWMI);
            }
        }
        CloseHandle(hThreadWMI);
    }

    //get unchangable system information
    GetSystemDetails();

    //get runtime changable system information
    GetSystemStatusChanges();

    //get IPs if possible
    GetSystemIPAddresses(&monIps,bMonIps);

    //get system information
    GetSystemStatus();

    if(bRunWMI)
    {
        //get WMI status information
        GetWMIStatus();
    }

    //Close window
    if(ghWnd)
    {
        PostMessage(ghWnd,TERMINATE_DLL_MSG,0,0);
	    Log(LOG_DEBUG,__LINE__,"-- WinMain, Wait ThrdMsg %u",WaitForSingleObject(hThreadMSG,MINUTE));
	    CloseHandle(hThreadMSG);
    }

    //force terminate all pending threads
    if(PendingThreads.size()>0)
    {
        for(unsigned int u=0;u<PendingThreads.size();u++)
        {
            if(WaitForSingleObject(PendingThreads.at(u),(MILLISECOND*2))==WAIT_TIMEOUT)
            {
                EndPendingThread(PendingThreads.at(u)); 
            }
            CloseHandle(PendingThreads.at(u));
        }
        PendingThreads.clear();
    }

    SetUnhandledExceptionFilter(pPreviousExceptionFilter);
    LogElapsedTime(__LINE__,gTickStart,"SysStatus");
    return 0;
}
