#include "SysStatusInc.h"

#ifndef _SYS_STATUS_INCLUDE_
#define _SYS_STATUS_INCLUDE_

//WMI DBG - Use only for test
//#define _GET_WMI_USBINFO            //USB information also retrived by EnumerateUSB function
//#define _GET_WMI_LOGICALDISK        //Logical Disk information also retrieved by LogicalDrives function
//#define _GET_WMI_PRINTER            //Printer information also retrived by PrinterInfo function
//#define _GET_WMI_ACCOUNTS           //All user and groups which includes the full domain - which can be thousands and depending on the system can spend 'years' to be processed
//#define _GET_WMI_COMCLASS           //All COM class - which can be thousands - which can be thousands and depending on the system can spend 'years' to be processed
//#define _GET_WMI_SOFTWARE_DETAILS   //All software element, part of a software feature - which can be thousands and depending on the system can spend 'years' to be processed

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

#define TERMINATE_DLL_MSG   (WM_USER+1000)

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
char * GetLastErrorMessage(DWORD dwLastError, char * lpBuffer, DWORD nSize);
LPSTR GUID2Str(LPGUID lpGuid, LPSTR lpStr);
vector<string> parseNullTerminatedStrings(char* input);
PCHAR WideStrToMultiStr(PWCHAR WideStr);
void CalcElapsedTime(unsigned __int64 tickStart,unsigned __int64 &tickEnd,float &timeElapsed,unsigned long &seconds);
void LogElapsedTime(unsigned long line,unsigned __int64 tickStart,char *lpszAdditionalMsg = NULL);
void USBTraceInfo(PCHAR StartString, PCHAR DeviceInterfaceName);
DWORD GetWinVer();

/*
** Running Thread
*/
bool StartThread(string threadName,unsigned (__stdcall *threadFunction)(void*),void *threadData,DWORD threadTimeout,HANDLE *pthreadHandle = NULL);

/*
** PBuffer: Memory simple class
*/
class PBuffer
{
private:
    BYTE *pMem;
    int lMem;

public:
    PBuffer()
    {
        pMem = NULL;
        lMem = 0;
    };
    ~PBuffer()
    {
        _clear();
    };

    BYTE *_allocMem(int len)
    {
        if(len > lMem)
        {
            if(pMem)
                delete [] pMem;
            lMem = len;
            pMem = new BYTE[lMem];
            memset(pMem,0x00,lMem);
        }
        return pMem;
    };

    BYTE *_allocMem(int len,BYTE *mem)
    {
        if (len > lMem)
        {
            if (pMem)
                delete [] pMem;
            lMem = len;
            pMem = new BYTE[lMem];
            memset(pMem,0x00,lMem);
            
            //copy new data
            memcpy(pMem,mem,lMem);
        }
        return pMem;
    };

    int _sizeofMem()
    {
        return lMem;
    };

    BYTE *_getMem()
    {
        return pMem;
    };

    void _clear()
    {
        if(pMem)
        {
            delete [] pMem;
            pMem = NULL;
        }
        lMem = 0;
    }

private:
             PBuffer(const PBuffer &p);
    PBuffer &PBuffer::operator=(const PBuffer &p);
};

#endif  //_SYS_STATUS_INCLUDE_
