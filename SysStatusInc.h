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
//#include <atlsafe.h>

//System tick cound
uint64_t SysTick();
