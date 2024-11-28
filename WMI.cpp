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
#include "WMI.h"

#include <atlsafe.h>

extern BOOL gbTerminate;
extern char gszLogFilePrefix[1024];

#ifdef _GET_WMI_USBINFO
extern BOOL gbUsbChanged;
#endif

/*
** FromVariant: Template class to convert VARIANT type into C++ type
*/
template<typename T> void FromVariant(VARIANT Var, std::vector<T>& Vec)
{
    CComSafeArray<T> SafeArray;
    SafeArray.Attach(Var.parray);
    ULONG Count = SafeArray.GetCount();
    Vec.resize(Count);
    for (ULONG Index = 0; Index < Count; Index++)
    {
        Vec[Index] = SafeArray.GetAt(Index);
    }
}

/*
** WMI: Windows Management Instrumentation (ASCII)
** --> Monitor (and manage) system hardware and features
*/
bool WMIex(char const *lpszOption, xmlwriter *xml, unsigned long *lpulProperties = nullptr)
{
    unsigned long properties = 0;
    HRESULT hres;

    if (_thGetInt(&gbTerminate) == TRUE)
    {
        //process is ending - do not process because it spends to much time
        return true;
    }

    Log(LOG_DEBUG_WMI, __LINE__, ">> WMI, %s", lpszOption);

    if (!lpszOption)
    {
        Log(LOG_DEBUG, __LINE__, "<< WMI, Null class name");
        return true;
    }

    HANDLE hWmiMutex = CreateMutex(NULL, FALSE, "SysStatus_WMI_Mutex");
    if (WaitForSingleObject(hWmiMutex, MINUTE) != WAIT_OBJECT_0)
    {
        //need to be restarted
        Log(LOG_DEBUG_WMI, __LINE__, "<< WMI, %s Mutex 0x%p timeout", lpszOption, hWmiMutex);
        CloseHandle(hWmiMutex);
        return false;
    }

    uint64_t tickStart = SysTick();

    // Initialize COM.
    hres = CoInitializeEx(0, COINIT_MULTITHREADED | COINIT_SPEED_OVER_MEMORY);
    if (FAILED(hres))
    {
        Log(LOG_DEBUG_WMI, __LINE__, "<< WMI, Failed to initialize COM library, 0x%.8X", hres);
        ReleaseMutex(hWmiMutex);
        CloseHandle(hWmiMutex);
        return true;
    }

    static bool secInitialized{ false };

    if (!secInitialized)
    {
        //// Initialize 
        //SECURITY_DESCRIPTOR sd = { 0 };
        //InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        //SetSecurityDescriptorDacl(&sd, TRUE, (PACL) nullptr, FALSE);

        hres = CoInitializeSecurity(
            NULL, //&sd,
            -1,      // COM negotiates service
            NULL,    // Authentication services
            NULL,    // Reserved
            RPC_C_AUTHN_LEVEL_NONE, //RPC_C_AUTHN_LEVEL_PKT, //RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
            RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
            NULL,             // Authentication info 
            EOAC_NONE,        // Additional capabilities
            NULL              // Reserved
        );

        if (FAILED(hres))
        {
            Log(LOG_DEBUG_WMI, __LINE__, "<< WMI, Failed to initialize security, 0x%.8x", hres);
            CoUninitialize();
            ReleaseMutex(hWmiMutex);
            CloseHandle(hWmiMutex);
            return true;
        }

        secInitialized = true;
    }

    // Obtain the initial locater to Windows Management
    // on a particular host computer.
    IWbemLocator *pLoc = 0;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres))
    {
        Log(LOG_DEBUG_WMI, __LINE__, "<< WMI, Failed to create IWbemLocator object,0x%.8x", hres);
        CoUninitialize();
        ReleaseMutex(hWmiMutex);
        CloseHandle(hWmiMutex);
        return true;
    }

    IWbemServices *pSvc = 0;

    // Connect to the root\cimv2 namespace with the
    // current user and obtain pointer pSvc
    // to make IWbemServices calls.

    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        0,                       // Locale
        NULL,                    // Security flags                 
        0,                       // Authority       
        0,                       // Context object
        &pSvc                    // IWbemServices proxy
    );

    if (FAILED(hres))
    {
        Log(LOG_DEBUG_WMI, __LINE__, "<< WMI, Could not connect, 0x%.8x", hres);
        pLoc->Release();
        CoUninitialize();
        ReleaseMutex(hWmiMutex);
        CloseHandle(hWmiMutex);
        return true;
    }

    Log(LOG_DEBUG_WMI, __LINE__, "-- WMI, Connected to ROOT\\CIMV2 WMI namespace");

    // Set the IWbemServices proxy so that impersonation
    // of the user (client) occurs.
    hres = CoSetProxyBlanket(
        pSvc,                         // the proxy to set
        RPC_C_AUTHN_WINNT,            // authentication service
        RPC_C_AUTHZ_NONE,             // authorization service
        NULL,                         // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,       // authentication level
        RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
        NULL,                         // client identity 
        EOAC_NONE                     // proxy capabilities     
    );

    if (FAILED(hres))
    {
        Log(LOG_DEBUG_WMI, __LINE__, "<< WMI, Could not set proxy blanket, 0x%.8x", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        ReleaseMutex(hWmiMutex);
        CloseHandle(hWmiMutex);
        return true;
    }

    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:

    char szSelect[_MAX_PATH] = { 0 };
    _snprintf(szSelect, sizeof(szSelect), "SELECT * FROM %s", lpszOption);
    Log(LOG_DEBUG_WMI, __LINE__, "-- WMI, Querying properties for %s", lpszOption);

    // Query for all properties
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(szSelect),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (xml)
    {
        std::string tag;
        tag.assign(&lpszOption[6]); //minus: Win32_
        xml->Createtag(tag);

        tag.clear();
        tag.assign(lpszOption);
        xml->AddComment(tag);
    }
    else
    {
        Log(LOG_HEADER, __LINE__, lpszOption);
    }

    if (FAILED(hres))
    {
        Log(LOG_DEBUG_WMI, __LINE__, "-- WMI, Query for %s failed, 0x%.8x", lpszOption, hres);
    }
    else
    {
        IWbemClassObject *pclsObj;
        ULONG uReturn = 0;

        while (pEnumerator && _thGetInt(&gbTerminate) == FALSE)
        {
            hres = pEnumerator->Next(WBEM_INFINITE, 1,
                &pclsObj, &uReturn);

            if (0 == uReturn)
            {
                break;
            }

            //line.clear();
            for (int x = 0; wmiClasses[x].pClass != NULL && _thGetInt(&gbTerminate) == FALSE; x++)
            {
                if (strcmp(wmiClasses[x].pClass, lpszOption) != 0)
                {
                    Sleep(MILLISECOND);
                    continue;
                }
                VARIANT vtProp;
                WCHAR tszProperty[10000]{};
                CHAR szValue[10000]{};

                properties++;
                Log(LOG_DEBUG_WMI, __LINE__, "-- WMI, Processing %.5u %s (%i) %s", properties, wmiClasses[x].pClass, x + 1, wmiClasses[x].pProperty);

                //Convert Name Property to Unicode
                MultiByteToWideChar(CP_ACP, 0, (LPCSTR)wmiClasses[x].pProperty, -1, (LPWSTR)tszProperty, sizeof(tszProperty));

                // Get the value of the Name property
                hres = pclsObj->Get(tszProperty, 0, &vtProp, 0, 0);
                if (FAILED(hres))
                {
                    //read next property of option
                    continue;
                }

                try
                {
                    std::string value;
                    char temp[_MAX_PATH] = { 0 };

                    switch (vtProp.vt)
                    {
                    case VT_I1:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "0x%.2X", vtProp.cVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = 0x%.2X", wmiClasses[x].pProperty, vtProp.cVal);
                        }
                        break;

                    case VT_UI1:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "0x%.2X", vtProp.bVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = 0x%.2X", wmiClasses[x].pProperty, vtProp.bVal);
                        }
                        break;

                    case VT_I2:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "0x%.4X", vtProp.iVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = 0x%.4X", wmiClasses[x].pProperty, vtProp.iVal);
                        }
                        break;

                    case VT_UI2:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "0x%.4X", vtProp.uiVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = 0x%.4X", wmiClasses[x].pProperty, vtProp.uiVal);
                        }
                        break;

                    case VT_I4:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "0x%.8X", vtProp.lVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = 0x%.8X", wmiClasses[x].pProperty, vtProp.lVal);
                        }
                        break;

                    case VT_UI4:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "0x%.8X", vtProp.ulVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = 0x%.8X", wmiClasses[x].pProperty, vtProp.ulVal);
                        }
                        break;

                    case VT_I8:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "0x%llX", vtProp.llVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = 0x%.16X", wmiClasses[x].pProperty, vtProp.llVal);
                        }
                        break;

                    case VT_UI8:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "0x%.16llX", vtProp.ullVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = 0x%.16llX", wmiClasses[x].pProperty, vtProp.ullVal);
                        }
                        break;

                    case VT_R4:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "%f", vtProp.fltVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = %f", wmiClasses[x].pProperty, vtProp.fltVal);
                        }
                        break;

                    case VT_R8:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "%e", vtProp.dblVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = %e", wmiClasses[x].pProperty, vtProp.dblVal);
                        }
                        break;

                    case VT_BOOL:
                        if (xml)
                        {
                            value.assign(vtProp.boolVal == VARIANT_TRUE ? "True" : "False");
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = %s", wmiClasses[x].pProperty, vtProp.boolVal == VARIANT_TRUE ? "True" : "False");
                        }
                        break;

                    case VT_BSTR:
                        if (vtProp.bstrVal)
                        {
                            WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)vtProp.bstrVal, -1, (LPSTR)szValue, sizeof(szValue), NULL, NULL);
                            if (xml)
                            {
                                value.assign(szValue);
                                xml->CreateChild(wmiClasses[x].pProperty, value);
                            }
                            else
                            {
                                Log(LOG_MESSAGE, __LINE__, "%s = %s", wmiClasses[x].pProperty, szValue);
                            }
                        }
                        break;

                    case VT_DATE:
                        if (xml)
                        {
                            _snprintf(temp, sizeof(temp), "%lu", (unsigned long)vtProp.date);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty, value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE, __LINE__, "%s = %lu", wmiClasses[x].pProperty, (unsigned long)vtProp.date);
                        }
                        break;

                    default:
                        if (vtProp.vt & VT_BYREF)
                        {
                            if (xml)
                            {
                                xml->Createtag(wmiClasses[x].pProperty);
                            }
                            unsigned short type = (vtProp.vt - VT_BYREF);
                            char idx[_MAX_PATH] = { 0 };
                            std::string id;

                            switch (type)
                            {
                            case VT_I1:
                            case VT_UI1:
                            {
                                std::vector<BYTE> vui1;
                                FromVariant(vtProp, vui1);
                                for (unsigned int i = 0; i < vui1.size(); i++)
                                {
                                    if (xml)
                                    {
                                        _snprintf(idx, sizeof(idx), "%.3u", i + 1);
                                        _snprintf(szValue, sizeof(szValue), "0x%.2X", vui1[i]);

                                        id.assign(idx);
                                        value.assign(szValue);
                                        xml->CreateChild(idx, value);
                                    }
                                    else
                                    {
                                        _snprintf(szValue, sizeof(szValue), "%s.0x%.2X", szValue, vui1[i]);
                                    }
                                }
                                vui1.clear();
                            }
                            break;

                            case VT_I2:
                            case VT_UI2:
                            {
                                std::vector<USHORT> vui2;
                                FromVariant(vtProp, vui2);
                                for (unsigned int i = 0; i < vui2.size(); i++)
                                {
                                    if (xml)
                                    {
                                        _snprintf(idx, sizeof(idx), "%.3u", i + 1);
                                        _snprintf(szValue, sizeof(szValue), "0x%.4X", vui2[i]);

                                        id.assign(idx);
                                        value.assign(szValue);
                                        xml->CreateChild(idx, value);
                                    }
                                    else
                                    {
                                        _snprintf(szValue, sizeof(szValue), "%s.0x%.4X", szValue, vui2[i]);
                                    }
                                }
                                vui2.clear();
                            }
                            break;

                            case VT_I4:
                            case VT_UI4:
                            {
                                std::vector<ULONG> vui4;
                                FromVariant(vtProp, vui4);
                                for (unsigned int i = 0; i < vui4.size(); i++)
                                {
                                    if (xml)
                                    {
                                        _snprintf(idx, sizeof(idx), "%.3u", i + 1);
                                        _snprintf(szValue, sizeof(szValue), "0x%.8lX", vui4[i]);

                                        id.assign(idx);
                                        value.assign(szValue);
                                        xml->CreateChild(idx, value);
                                    }
                                    else
                                    {
                                        _snprintf(szValue, sizeof(szValue), "%s.0x%.8lX", szValue, vui4[i]);
                                    }
                                }
                                vui4.clear();
                            }
                            break;

                            case VT_I8:
                            case VT_UI8:
                            {
                                std::vector<ULONGLONG> vui8;
                                FromVariant(vtProp, vui8);
                                for (unsigned int i = 0; i < vui8.size(); i++)
                                {
                                    if (xml)
                                    {
                                        _snprintf(idx, sizeof(idx), "%.3u", i + 1);
                                        _snprintf(szValue, sizeof(szValue), "0x%.16llX", vui8[i]);

                                        id.assign(idx);
                                        value.assign(szValue);
                                        xml->CreateChild(idx, value);
                                    }
                                    else
                                    {
                                        _snprintf(szValue, sizeof(szValue), "%s.0x%.16llX", szValue, vui8[i]);
                                    }
                                }
                                vui8.clear();
                            }
                            break;

                            case VT_R4:
                            {
                                std::vector<float> vr4;
                                FromVariant(vtProp, vr4);
                                for (unsigned int i = 0; i < vr4.size(); i++)
                                {
                                    if (xml)
                                    {
                                        _snprintf(idx, sizeof(idx), "%.3u", i + 1);
                                        _snprintf(szValue, sizeof(szValue), "%f", vr4[i]);

                                        id.assign(idx);
                                        value.assign(szValue);
                                        xml->CreateChild(idx, value);
                                    }
                                    else
                                    {
                                        _snprintf(szValue, sizeof(szValue), "%s.%f", szValue, vr4[i]);
                                    }
                                }
                                vr4.clear();
                            }
                            break;

                            case VT_R8:
                            case VT_DATE:
                            {
                                std::vector<double> vr8;
                                FromVariant(vtProp, vr8);
                                for (unsigned int i = 0; i < vr8.size(); i++)
                                {
                                    if (xml)
                                    {
                                        _snprintf(idx, sizeof(idx), "%.3u", i + 1);
                                        _snprintf(szValue, sizeof(szValue), "%e", vr8[i]);

                                        id.assign(idx);
                                        value.assign(szValue);
                                        xml->CreateChild(idx, value);
                                    }
                                    else
                                    {
                                        _snprintf(szValue, sizeof(szValue), "%s.%e", szValue, vr8[i]);
                                    }
                                }
                                vr8.clear();
                            }
                            break;

                            case VT_BSTR:
                            {
                                std::vector<BSTR> vbstr;
                                FromVariant(vtProp, vbstr);

                                Log(LOG_MESSAGE, __LINE__, "%s, %d:", wmiClasses[x].pProperty, vbstr.size());
                                for (unsigned int i = 0; i < vbstr.size(); i++)
                                {
                                    WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)vbstr[i], -1, (LPSTR)szValue, sizeof(szValue), NULL, NULL);
                                    if (xml)
                                    {
                                        _snprintf(idx, sizeof(idx), "%.3u", i + 1);

                                        id.assign(idx);
                                        value.assign(szValue);
                                        xml->CreateChild(idx, value);
                                    }
                                    else
                                    {
                                        Log(LOG_MESSAGE, __LINE__, "\t> %.3d %s", i + 1, szValue);
                                    }
                                    memset(szValue, 0x00, sizeof(szValue));
                                }
                                vbstr.clear();
                            }
                            break;
                            }
                            if (xml)
                            {
                                xml->CloseLasttag();
                            }
                            else
                            {
                                if (strlen(szValue) > 0)
                                {
                                    Log(LOG_MESSAGE, __LINE__, "%s = %d", wmiClasses[x].pProperty, szValue);
                                }
                            }
                        }   //END: if(vtProp.vt & VT_BYREF)
                        break;
                    }   //END: switch(vtProp.vt)

                    VariantClear(&vtProp);
                }   //END: try
                catch (...)
                {
                    Log(LOG_DEBUG_WMI, __LINE__, "-- WMI, Catch unhndld excpetion on %.5u %s (%i) %s", properties, wmiClasses[x].pClass, x + 1, wmiClasses[x].pProperty);
                }
            }
            pclsObj->Release();
        }   //END: while (pEnumerator)
    }

    //process the number of properties processed
    if (lpulProperties) {
        *lpulProperties = properties;
    }

    char processed[_MAX_PATH] = { 0 };
    _snprintf(processed, sizeof(processed), "%lu properties processed", properties);

    if (xml)
    {
        std::string temp;
        temp.append(processed);
        xml->AddComment(temp);
    }
    else
    {
        Log(LOG_MESSAGE, __LINE__, processed);
    }

    // Cleanup
    // ========

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    if (xml)
    {
        std::string temp;
        char elapsedTime[_MAX_PATH] = { 0 };
        uint64_t tickEnd{};
        double timeElapsed{};
        uint64_t seconds{};
        CalcElapsedTime(tickStart, tickEnd, timeElapsed, seconds);

        _snprintf(elapsedTime, sizeof(elapsedTime), "Elapsed Time: %02llu:%02llu:%02llu, %.3f s", seconds / 3600, (seconds % 3600) / 60, seconds % 60, timeElapsed);
        temp.assign(elapsedTime);

        xml->AddComment(temp);
        xml->CloseLasttag();
    }
    else
    {
        LogElapsedTime(__LINE__, tickStart);
    }
    ReleaseMutex(hWmiMutex);
    CloseHandle(hWmiMutex);

    Log(LOG_DEBUG_WMI, __LINE__, "<< WMI, ret True");
    return true;
}

void WMI(char const *lpszOption, unsigned long *lpulProperties = nullptr)
{
    WMIex(lpszOption, nullptr, lpulProperties);
}

/*
** ThreadWMIClass: Thread function for the specific group of WMI classes
*/
unsigned WINAPI ThreadWMIClass(LPVOID lpData)
{
    std::vector<std::string>* plist = (std::vector<std::string>*)lpData;

    Log(LOG_DEBUG_WMI, __LINE__, ">> ThrdWMICls, 0x%p", lpData);

    if (nullptr == lpData)
    {
        Log(LOG_DEBUG_WMI, __LINE__, "<< ThrdWMICls, Input null", lpData);
        _endthreadex(ERROR_INVALID_DATA);
        return ERROR_INVALID_DATA;
    }

    std::vector<std::string> const list = *plist;

    //find the last file
    HANDLE hXmlFile = NULL;
    int x;
    for (x = 9; x >= 0; x--)
    {
        char temp[_MAX_PATH] = { 0 };
        _snprintf(temp, sizeof(temp), "%s_%s_%.1d.xml", gszLogFilePrefix, list[0].c_str(), x);
        Log(LOG_DEBUG_WMI, __LINE__, "-- ThrdWMICls, Trying opng %s", temp);
        hXmlFile = CreateFile(temp, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hXmlFile != INVALID_HANDLE_VALUE)
        {
            Log(LOG_DEBUG_WMI, __LINE__, "-- ThrdWMICls, Last file fnd: %s", temp);
            CloseHandle(hXmlFile);
            hXmlFile = NULL;

            //all file were filled, removed the last one
            if (x == 9) {
                Log(LOG_DEBUG_WMI, __LINE__, "-- ThrdWMICls, Removing %s - oldest file", temp);
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
        //rename the _<x>.xml to _<x+1>.xml
        _snprintf(newFile, sizeof(newFile), "%s_%s_%.1d.xml", gszLogFilePrefix, list[0].c_str(), x + 1);
        _snprintf(oldFile, sizeof(oldFile), "%s_%s_%.1d.xml", gszLogFilePrefix, list[0].c_str(), x);

        Log(LOG_DEBUG_WMI, __LINE__, "-- ThrdWMICls, Renaming %s -> %s", oldFile, newFile);
        static_cast<void>(rename((const char*)oldFile, (const char*)newFile));
    }

    //rename the .xml to _0.xml
    _snprintf(newFile, sizeof(newFile), "%s_%s_0.xml", gszLogFilePrefix, list[0].c_str());
    _snprintf(oldFile, sizeof(oldFile), "%s_%s.xml", gszLogFilePrefix, list[0].c_str());
    Log(LOG_DEBUG_WMI, __LINE__, "-- ThrdWMICls, Remaining %s -> %s", oldFile, newFile);
    static_cast<void>(rename((const char*)oldFile, (const char*)newFile));

    uint64_t tickStart = SysTick();
    {   std::string fileName;
        fileName.assign(oldFile);
        xmlwriter xml(fileName, DebugStringToFile);

        xml.Createtag(list[1]);
        xml.AddComment(list[2]);

        auto size = plist->size();
        for (decltype(size) cnt = 3; cnt < size && _thGetInt(&gbTerminate) == FALSE; ++cnt)
        {
            while (WMIex(list[cnt].c_str(), &xml) == false);
        }
        xml.CloseAlltags();
    }
    uint64_t tickEnd{};
    double timeElapsed{};
    uint64_t seconds{};
    CalcElapsedTime(tickStart, tickEnd, timeElapsed, seconds);

    Log(LOG_DEBUG_WMI, __LINE__, "<< ThrdWMICls, %s, %02llu:%02llu:%02llu, %.3f s", plist->at(0).c_str(), seconds / 3600, (seconds % 3600) / 60, seconds % 60, timeElapsed);
    _endthreadex(0);
    return 0;
}

/*
** ThreadWMI: Thread function for the WMI processing
*/
unsigned WINAPI ThreadWMI(LPVOID lpData)
{
    DWORD threads = 0;
    HANDLE ahThreads[20] = { 0 };

    Log(LOG_DEBUG_WMI, __LINE__, ">> ThrdWMI, In (%p)", lpData);

    uint64_t tickStart = SysTick();

    //HW ************
    std::vector<std::string> hwInfo{ "hwi",
        "HardwareInfo", "Hardware Information",
        "Win32_1394Controller", "Win32_BaseBoard",
        "Win32_Battery", "Win32_BIOS", "Win32_Bus",
        "Win32_CDROMDrive", "Win32_DMAChannel",
        "Win32_DriverVXD", "Win32_FloppyController",
        "Win32_FloppyDrive", "Win32_HeatPipe",
        "Win32_Keyboard", "Win32_MotherboardDevice",
        "Win32_OnBoardDevice", "Win32_IDEController",
        "Win32_InfraredDevice", "Win32_IRQResource",
        "Win32_PCMCIAController", "Win32_PointingDevice",
        "Win32_PortConnector", "Win32_PortResource",
        "Win32_PnPEntity", "Win32_PrinterDriver",
        "Win32_Processor", "Win32_SCSIController",
        "Win32_SerialPort", "Win32_SerialPortConfiguration",
        "Win32_SoundDevice", "Win32_USBController",
        "Win32_VideoController"
    };
#ifdef _GET_WMI_PRINTER
    hwInfo.push_back("Win32_Printer");
#endif

    if (StartThread(hwInfo[1], ThreadWMIClass, (LPVOID)&hwInfo, 0, &ahThreads[threads]))
    {
        ++threads;
    }

    //HW ************

    //DATA **********
    std::vector<std::string> data{ "ds",
        "DataStorage", "Disk and Partitions Information",
        "Win32_DiskDrive", "Win32_DiskPartition",
        "Win32_PhysicalMedia", "Win32_TapeDrive"
    };

    if (StartThread(data[1], ThreadWMIClass, (LPVOID)&data, 0, &ahThreads[threads]))
    {
        ++threads;
    }
    //DATA **********

    //MEM ***********
    std::vector<std::string> memory{ "mem",
        "Memory", "Memory Information",
        "Win32_CacheMemory", "Win32_DeviceMemoryAddress",
        "Win32_MemoryArray", "Win32_MemoryDevice",
        "Win32_PhysicalMemory", "Win32_PhysicalMemoryArray",
        "Win32_SMBIOSMemory", "Win32_SystemMemoryResource"
    };

    if (StartThread(memory[1], ThreadWMIClass, (LPVOID)&memory, 0, &ahThreads[threads]))
    {
        ++threads;
    }
    //MEM ***********

    //SYS ***********
    std::vector<std::string> sysInfo{ "sysi",
        "SystemInfo", "System Information",
        //"Win32_ApplicationService",
        "Win32_ComputerSystem", "Win32_ComputerSystemProduct",
        "Win32_Product", //"Win32_ProgIDSpecification",
        "Win32_QuickFixEngineering", "Win32_Refrigeration",
        "Win32_Registry", "Win32_SystemAccount",
        "Win32_SystemDriver", "Win32_SystemEnclosure",
        "Win32_SystemSlot"
    };

    if (StartThread(sysInfo[1], ThreadWMIClass, (LPVOID)&sysInfo, 0, &ahThreads[threads]))
    {
        ++threads;
    }
    //SYS ***********

    //NET ***********
    std::vector<std::string> net{ "net",
        "Network", "Network Information",
        "Win32_NetworkAdapter", "Win32_NetworkAdapterConfiguration",
        "Win32_NetworkLoginProfile", "Win32_NetworkProtocol"
    };

    if (StartThread(net[1], ThreadWMIClass, (LPVOID)&net, 0, &ahThreads[threads]))
    {
        ++threads;
    }
    //NET ***********

    //USER **********
#ifdef _GET_WMI_ACCOUNTS
    std::vector<std::string> user{ "user", "UserAccountAndSecurity",
        "User Account and Security Information", "Win32_Account"
    };

    if (StartThread(user[1], ThreadWMIClass, (LPVOID)&user, 0, &ahThreads[threads]))
    {
        ++threads;
    }
    //USER **********
#endif

    //DEV ***********
    std::vector<std::string> dev{ "dev",
        "Developer", "Developer Information",
        "Win32_CodecFile", "Win32_SoftwareFeature"
    };
#ifdef _GET_WMI_COMCLASS    //get all COM class - which can be thousands
    dev.push_back("Win32_COMClass");
#endif
#ifdef _GET_WMI_SOFTWARE_DETAILS    //get all software element, part of a software feature
    //(a distinct subset of a product which may contain one 
    //or more elements) - which can be thousands
    dev.push_back("Win32_SoftwareElement");
#endif

    if (StartThread(dev[1], ThreadWMIClass, (LPVOID)&dev, 0, &ahThreads[threads]))
    {
        ++threads;
    }
    //DEV ***********

    //UTIL **********
    std::vector<std::string> util{ "util",
        "Utility", "Utility Information",
        "Win32_BaseService", "Win32_BootConfiguration",
        "Win32_Desktop", "Win32_DesktopMonitor",
        "Win32_Fan", "Win32_OperatingSystem",
        "Win32_PageFile", "Win32_ParallelPort",
        "Win32_Proxy", "Win32_Share",
        "Win32_WindowsProductActivation", "Win32_WMISetting",
        "Win32_PrinterConfiguration"
    };

    if (StartThread(util[1], ThreadWMIClass, (LPVOID)&util, 0, &ahThreads[threads]))
    {
        ++threads;
    }
    //UTIL **********

    Log(LOG_DEBUG_WMI, __LINE__, "-- ThrdWMI, Waitg %u thrs", threads);
    WaitForMultipleObjects(threads, ahThreads, TRUE, INFINITE);
    for (DWORD x = 0; x < threads; x++)
    {
        CloseHandle(ahThreads[x]);
    }

    uint64_t tickEnd{};
    double timeElapsed{};
    uint64_t seconds{};
    CalcElapsedTime(tickStart, tickEnd, timeElapsed, seconds);

    Log(LOG_DEBUG_WMI, __LINE__, "<< ThrdWMI, Out, %02llu:%02llu:%02llu, %.3f s", seconds / 3600, (seconds % 3600) / 60, seconds % 60, timeElapsed);
    _endthreadex(0);
    return 0;
}

/*
** WMISystemVolumes: get all system volumes details
** device arrival/remove: DBT_DEVTYP_VOLUME
*/
void WMISystemVolumes(void)
{
    static unsigned long Volume = (unsigned long)-1;

    Log(LOG_DEBUG_WMI, __LINE__, ">> WMISysVols");

    //always check both because there may be moments system cannot
    //detect a network connection and it always exist at least one 
    //logical disk
#ifdef _GET_WMI_LOGICALDISK
    WMI("Win32_LogicalDisk");
#endif

    WMI("Win32_NetworkConnection");

    if (Volume != 0)
    {
        WMI("Win32_Volume", &Volume);
    }

    Log(LOG_DEBUG_WMI, __LINE__, "<< WMISysVols");
}

#ifdef _GET_WMI_USBINFO
/*
** WMISystemUsb: get all system usb details
** device arrival/remove: DBT_DEVTYP_DEVICEINTERFACE
*/
void WMISystemUsb(void)
{
    Log(LOG_DEBUG_WMI, __LINE__, ">> WMISysUsb");

    WMI("Win32_USBHub");

    Log(LOG_DEBUG_WMI, __LINE__, "<< WMISysUsb");
}
#endif

/*
** WMISystemPerformance: get system performance information
*/
void WMISystemPerformance(void)
{
    static unsigned long PerfRawData_PerfDisk_PhysicalDisk = (unsigned long)-1;
    static unsigned long PerfRawData_PerfNet_Redirector = (unsigned long)-1;
    static unsigned long PerfRawData_PerfOS_Cache = (unsigned long)-1;
    static unsigned long PerfRawData_PerfOS_Memory = (unsigned long)-1;
    static unsigned long PerfRawData_PerfOS_Objects = (unsigned long)-1;
    static unsigned long PerfRawData_PerfOS_PagingFile = (unsigned long)-1;
    static unsigned long PerfRawData_PerfOS_Processor = (unsigned long)-1;
    static unsigned long PerfRawData_PerfOS_System = (unsigned long)-1;

    Log(LOG_DEBUG_WMI, __LINE__, ">> WMISysPerf");

    if (PerfRawData_PerfDisk_PhysicalDisk != 0)
    {
        WMI("Win32_PerfRawData_PerfDisk_PhysicalDisk", &PerfRawData_PerfDisk_PhysicalDisk);
    }

    if (PerfRawData_PerfNet_Redirector != 0)
    {
        WMI("Win32_PerfRawData_PerfNet_Redirector", &PerfRawData_PerfNet_Redirector);
    }

    if (PerfRawData_PerfOS_Cache != 0)
    {
        WMI("Win32_PerfRawData_PerfOS_Cache", &PerfRawData_PerfOS_Cache);
    }

    if (PerfRawData_PerfOS_Memory != 0)
    {
        WMI("Win32_PerfRawData_PerfOS_Memory", &PerfRawData_PerfOS_Memory);
    }

    if (PerfRawData_PerfOS_Objects != 0)
    {
        WMI("Win32_PerfRawData_PerfOS_Objects", &PerfRawData_PerfOS_Objects);
    }

    if (PerfRawData_PerfOS_PagingFile != 0)
    {
        WMI("Win32_PerfRawData_PerfOS_PagingFile", &PerfRawData_PerfOS_PagingFile);
    }

    if (PerfRawData_PerfOS_Processor != 0)
    {
        WMI("Win32_PerfRawData_PerfOS_Processor", &PerfRawData_PerfOS_Processor);
    }

    if (PerfRawData_PerfOS_System != 0)
    {
        WMI("Win32_PerfRawData_PerfOS_System", &PerfRawData_PerfOS_System);
    }

    Log(LOG_DEBUG_WMI, __LINE__, "<< WMISysPerf");
}

/*
** WMIHardwareSensor: get system performance information
*/
void WMIHardwareSensor(void)
{
    static unsigned long CurrentProbe = (unsigned long)-1;
    static unsigned long PortableBattery = (unsigned long)-1;
    static unsigned long TemperatureProbe = (unsigned long)-1;
    static unsigned long VoltageProbe = (unsigned long)-1;

    Log(LOG_DEBUG_WMI, __LINE__, ">> WMIHwSnsr");

    if (CurrentProbe != 0)
    {
        WMI("Win32_CurrentProbe", &CurrentProbe);
    }

    if (PortableBattery != 0)
    {
        WMI("Win32_PortableBattery", &PortableBattery);
    }

    if (TemperatureProbe != 0)
    {
        WMI("Win32_TemperatureProbe", &TemperatureProbe);
    }

    if (VoltageProbe != 0)
    {
        WMI("Win32_VoltageProbe", &VoltageProbe);
    }

    Log(LOG_DEBUG_WMI, __LINE__, "<< WMIHwSnsr");
}
