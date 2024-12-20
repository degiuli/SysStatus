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

#include "SysStatusInc.h"

#ifndef _SYS_STATUS_INCLUDE_
#define _SYS_STATUS_INCLUDE_

//WMI DBG - Use only for test
#ifdef _DEBUG
#define _GET_WMI_USBINFO            //USB information also retrieved by EnumerateUSB function
#define _GET_WMI_LOGICALDISK        //Logical Disk information also retrieved by LogicalDrives function
//#define _GET_WMI_PRINTER            //Printer information also retrieved by PrinterInfo function
//#define _GET_WMI_ACCOUNTS           //All user and groups which includes the full domain - which can be thousands and depending on the system can spend 'years' to be processed
//#define _GET_WMI_COMCLASS           //All COM class - which can be thousands - which can be thousands and depending on the system can spend 'years' to be processed
//#define _GET_WMI_SOFTWARE_DETAILS   //All software element, part of a software feature - which can be thousands and depending on the system can spend 'years' to be processed
#endif

//sizes definiitions
#define KBYTES              (1024)
#define MBYTES              (KBYTES*KBYTES)
#define GBYTES              (MBYTES*KBYTES)
#define SIZE_KB(size)       ((DWORD)((size/KBYTES)+0.5))
#define SIZE_MB(size)       ((DWORD)((size/MBYTES)+0.5))
#define SIZE_GB(size)       ((DWORD)((size/GBYTES)+0.5))

//time definitions
#define MILLISECOND         (1L)
#define SECOND              (MILLISECOND*1000L)
#define MINUTE              (SECOND*60L)
#define HOUR                (MINUTE*60L)
#define DAY                 (HOUR*24)
#define YEAR                (DAY*365)

//frequency definitions
#define Hz                  (1L)
#define KHz                 (Hz*1000L)
#define MHz                 (KHz*1000L)
#define GHz                 (MHz*1000L)

//version definitions
#define MAJOR_VERSION(ver)  (DWORD)(LOBYTE(LOWORD(ver)))
#define MINOR_VERSION(ver)  (DWORD)(HIBYTE(LOWORD(ver)))
#define BUILD_VERSION(ver)  (ver<0x80000000?(DWORD)(HIWORD(ver)):0)

#define TERMINATE_WINDOW_MSG   (WM_USER+1000)

//logical processor information API functions
typedef BOOL (WINAPI *LPFN_GLPI)(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION,PDWORD);
typedef DWORD (WINAPI *LPFN_GCPN)(VOID);

//log type
#define LOG_NONE        0x0000
#define LOG_MESSAGE     0x0001
#define LOG_HEADER      0x0002
#define LOG_DEBUG       0x0010
#define LOG_DEBUG_WND   0x0020
#define LOG_DEBUG_WMI   0x0040

#define LOG_DEBUG_ALL   (LOG_DEBUG|LOG_DEBUG_WND|LOG_DEBUG_WMI)

//auxiliary function definitions
void _thSetInt(int *piProtectedVar,int iValue);
int _thGetInt(int *piProtectedVar);
void DebugStringToFile(char *message,int typeDebug);
void Log(int type,int id,const char*format,...);
void CheckLogFileSize(DWORD dwMaxSize);
PCHAR WideStrToMultiStr(PWCHAR WideStr);
void LogElapsedTime(unsigned long const line, uint64_t const tickStart, char const* lpszAdditionalMsg = nullptr);
void CalcElapsedTime(uint64_t const tickStart, uint64_t& tickEnd, double& timeElapsed, uint64_t& seconds);
void USBTraceInfo(PCHAR StartString, PCHAR DeviceInterfaceName);
DWORD GetWinVer();

/*
** Running Thread
*/
bool StartThread(std::string const& threadName, unsigned(__stdcall *threadFunction)(void*), void *threadData, DWORD threadTimeout, HANDLE *pthreadHandle = nullptr);

/*
** PBuffer: Memory simple class
*/
class PBuffer
{
private:
    byte* pMem;
    size_t lMem;

public:
    PBuffer()
    {
        pMem = nullptr;
        lMem = 0;
    };
    ~PBuffer()
    {
        _clear();
    };

    PBuffer(const PBuffer& p) = delete;
    PBuffer& PBuffer::operator=(const PBuffer& p) = delete;
    PBuffer(const PBuffer&& p) = delete;
    PBuffer&& PBuffer::operator=(PBuffer&& p) = delete;

    byte* _allocMem(size_t len)
    {
        if (len > lMem)
        {
            if (pMem)
                delete[] pMem;
            lMem = len;
            pMem = new byte[lMem];
            memset(pMem, 0x00, lMem);
        }
        return pMem;
    };

    byte* _allocMem(size_t len, byte* mem)
    {
        if (len > lMem)
        {
            if (pMem)
                delete[] pMem;
            lMem = len;
            pMem = new BYTE[lMem];
            memset(pMem, 0x00, lMem);

            //copy new data
            memcpy(pMem, mem, lMem);
        }
        return pMem;
    };

    size_t _sizeofMem()
    {
        return lMem;
    };

    byte* _getMem()
    {
        return pMem;
    };

    void _clear()
    {
        if (pMem)
        {
            delete[] pMem;
            pMem = nullptr;
        }
        lMem = 0;
    }
};

#endif  //_SYS_STATUS_INCLUDE_
