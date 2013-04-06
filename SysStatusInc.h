#include <windows.h>
#include <process.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <DbgHelp.h>
#include <Dbt.h>
#include <lmerr.h>
#include <Sensapi.h>

#pragma warning(disable:4200)
//NEW DDK #include <wdm.h>
//#include <basetyps.h>
//#include <winioctl.h>
//#include <windowsx.h>
#include <initguid.h>
//#include <devioctl.h>
//#include <exception>
//#include <tlhelp32.h>
#include <usbioctl.h>
#include <usb200.h>
#include <cfgmgr32.h>

#ifndef _WIN32_DCOM
#define _WIN32_DCOM
#endif

#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <atlsafe.h>

//System tick cound
unsigned __int64 SysTick();

//STD
using namespace std;
