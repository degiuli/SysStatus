#include "SysStatus.h"
#include "WMI.h"

extern BOOL gbTerminate;
extern char gszLogFilePrefix[1024];

#ifdef _GET_WMI_USBINFO
extern BOOL gbUsbChanged;
#endif

/*
** FromVariant: Template class to converte VARIANT type into C++ type
*/
template<typename T> void FromVariant(VARIANT Var, std::vector<T>& Vec)
{
    CComSafeArray<T> SafeArray;
    SafeArray.Attach(Var.parray);
    ULONG Count = SafeArray.GetCount();
    Vec.resize(Count);
    for(ULONG Index = 0; Index < Count; Index++)
    {
        Vec[Index] = SafeArray.GetAt(Index);
    }
}

/*
** WMI: Windows Management Instrumentation (ASCII)
** --> Monitor (and manage) system hardware and features
*/
bool WMIex(char *lpszOption,xmlwriter *xml,unsigned long *lpulProperties=NULL)
{
    unsigned long properties = 0;
    HRESULT hres;

    if(_thGetInt(&gbTerminate)==TRUE)
    {
        //process is ending - do not process because it spends to much time
        return true;
    }

    Log(LOG_DEBUG_WMI,__LINE__,">> WMI, %s",lpszOption);

    if(!lpszOption)
    {
        Log(LOG_DEBUG,__LINE__,"<< WMI, Null class name");
        return true;
    }

    HANDLE hWmiMutex = CreateMutex(NULL,FALSE,"SysStatus_WMI_Mutex");
    if(WaitForSingleObject(hWmiMutex,MINUTE)!=WAIT_OBJECT_0)
    {
        //need to be restarted
        Log(LOG_DEBUG_WMI,__LINE__,"<< WMI, %s Mutex 0x%p timeout",lpszOption,hWmiMutex);
        CloseHandle(hWmiMutex);
        return false;
    }

    unsigned __int64 tickStart = SysTick();

    // Initialize COM.
    hres =  CoInitializeEx(0, COINIT_MULTITHREADED|COINIT_SPEED_OVER_MEMORY); 
    if (FAILED(hres))
    {
        Log(LOG_DEBUG_WMI,__LINE__,"<< WMI, Failed to initialize COM library, 0x%.8X",hres);
        ReleaseMutex(hWmiMutex);
        CloseHandle(hWmiMutex);
        return true;
    }

    // Initialize 
    hres =  CoInitializeSecurity(
        NULL,     
        -1,      // COM negotiates service                  
        NULL,    // Authentication services
        NULL,    // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
        RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
        NULL,             // Authentication info 
        EOAC_NONE,        // Additional capabilities
        NULL              // Reserved
        );

                      
    if (FAILED(hres))
    {
        Log(LOG_DEBUG_WMI,__LINE__,"<< WMI, Failed to initialize security, 0x%.8x",hres);
        CoUninitialize();
        ReleaseMutex(hWmiMutex);
        CloseHandle(hWmiMutex);
        return true;
    }

    // Obtain the initial locator to Windows Management
    // on a particular host computer.
    IWbemLocator *pLoc = 0;

    hres = CoCreateInstance(
        CLSID_WbemLocator,             
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres))
    {
        Log(LOG_DEBUG_WMI,__LINE__,"<< WMI, Failed to create IWbemLocator object,0x%.8x",hres);
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
        Log(LOG_DEBUG_WMI,__LINE__,"<< WMI, Could not connect, 0x%.8x",hres);
        pLoc->Release();     
        CoUninitialize();
        ReleaseMutex(hWmiMutex);
        CloseHandle(hWmiMutex);
        return true;
    }

    Log(LOG_DEBUG_WMI,__LINE__,"-- WMI, Connected to ROOT\\CIMV2 WMI namespace");

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
        Log(LOG_DEBUG_WMI,__LINE__,"<< WMI, Could not set proxy blanket, 0x%.8x",hres);
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        ReleaseMutex(hWmiMutex);
        CloseHandle(hWmiMutex);
        return true;
    }


    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:

    char szSelect[_MAX_PATH] = {0};
    _snprintf(szSelect,sizeof(szSelect),"SELECT * FROM %s",lpszOption);
    Log(LOG_DEBUG_WMI,__LINE__,"-- WMI, Querying properties for %s",lpszOption);

    // Query for all properties
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"), 
        bstr_t(szSelect),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
        NULL,
        &pEnumerator);
    
    if(xml)
    {
        string tag;
        tag.assign(&lpszOption[6]); //minus: Win32_
        xml->Createtag(tag);

        tag.clear();
        tag.assign(lpszOption);
        xml->AddComment(tag);
    }
    else
    {
        Log(LOG_HEADER,__LINE__,lpszOption);
    }

    if (FAILED(hres))
    {
        Log(LOG_DEBUG_WMI,__LINE__,"-- WMI, Query for %s failed, 0x%.8x",lpszOption,hres);
    }
    else
    { 
        IWbemClassObject *pclsObj;
        ULONG uReturn = 0;

        while (pEnumerator && _thGetInt(&gbTerminate)==FALSE)
        {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, 
                &pclsObj, &uReturn);

            if(0 == uReturn)
            {
                break;
            }

            //line.clear();
            for(int x=0;wmiClasses[x].pClass!=NULL && _thGetInt(&gbTerminate)==FALSE;x++)
            {
                if(strcmp(wmiClasses[x].pClass,lpszOption)!=0)
                {
                    Sleep(MILLISECOND);
                    continue;
                }
                VARIANT vtProp;
                WCHAR tszProperty[10000];
                CHAR szValue[10000];

                properties++;
                Log(LOG_DEBUG_WMI,__LINE__,"-- WMI, Processing %.5u %s (%i) %s",properties,wmiClasses[x].pClass,x+1,wmiClasses[x].pProperty);

                memset(tszProperty,0x00,sizeof(tszProperty));
                memset(szValue,0x00,sizeof(szValue));

                //Convert Name Poperty to Unicode
                MultiByteToWideChar(CP_ACP,0,(LPCSTR)wmiClasses[x].pProperty,-1,(LPWSTR)tszProperty,sizeof(tszProperty));

                // Get the value of the Name property
                hres = pclsObj->Get(tszProperty, 0, &vtProp, 0, 0);
                if(FAILED(hres))
                {
                    //read next property of option
                    continue;
                }

                try
                {
                    string value;
                    char temp[_MAX_PATH] = {0};

                    switch(vtProp.vt)
                    {
                    case VT_I1:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"0x%.2X",vtProp.cVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = 0x%.2X",wmiClasses[x].pProperty,vtProp.cVal);
                        }
                        break;

                    case VT_UI1:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"0x%.2X",vtProp.bVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = 0x%.2X",wmiClasses[x].pProperty,vtProp.bVal);
                        }
                        break;

                    case VT_I2:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"0x%.4X",vtProp.iVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = 0x%.4X",wmiClasses[x].pProperty,vtProp.iVal);
                        }
                        break;

                    case VT_UI2:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"0x%.4X",vtProp.uiVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = 0x%.4X",wmiClasses[x].pProperty,vtProp.uiVal);
                        }
                        break;

                    case VT_I4:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"0x%.8X",vtProp.lVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = 0x%.8X",wmiClasses[x].pProperty,vtProp.lVal);
                        }
                        break;

                    case VT_UI4:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"0x%.8X",vtProp.ulVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = 0x%.8X",wmiClasses[x].pProperty,vtProp.ulVal);
                        }
                        break;

                    case VT_I8:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"0x%.16X",vtProp.llVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = 0x%.16X",wmiClasses[x].pProperty,vtProp.llVal);
                        }
                        break;

                    case VT_UI8:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"0x%.16X",vtProp.ullVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = 0x%.16X",wmiClasses[x].pProperty,vtProp.ullVal);
                        }
                        break;

                    case VT_R4:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"%f",vtProp.fltVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = %f",wmiClasses[x].pProperty,vtProp.fltVal);
                        }
                        break;

                    case VT_R8:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"%e",vtProp.dblVal);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = %e",wmiClasses[x].pProperty,vtProp.dblVal);
                        }
                        break;

                    case VT_BOOL:
                        if(xml)
                        {
                            value.assign(vtProp.boolVal==VARIANT_TRUE?"True":"False");
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = %s",wmiClasses[x].pProperty,vtProp.boolVal==VARIANT_TRUE?"True":"False");
                        }
                        break;

                    case VT_BSTR:
                        if(vtProp.bstrVal)
                        {
                            WideCharToMultiByte(CP_ACP,0,(LPCWSTR)vtProp.bstrVal,-1,(LPSTR)szValue,sizeof(szValue),NULL,NULL);
                            if(xml)
                            {
                                value.assign(szValue);
                                xml->CreateChild(wmiClasses[x].pProperty,value);
                            }
                            else
                            {
                                Log(LOG_MESSAGE,__LINE__,"%s = %s",wmiClasses[x].pProperty,szValue);
                            }
                        }
                        break;

                    case VT_DATE:
                        if(xml)
                        {
                            _snprintf(temp,sizeof(temp),"%u",(unsigned long)vtProp.date);
                            value.assign(temp);
                            xml->CreateChild(wmiClasses[x].pProperty,value);
                        }
                        else
                        {
                            Log(LOG_MESSAGE,__LINE__,"%s = %u",wmiClasses[x].pProperty,(unsigned long)vtProp.date);
                        }
                        break;

                    default:
                        if(vtProp.vt & VT_BYREF)
                        {
                            if(xml)
                            {
                                xml->Createtag(wmiClasses[x].pProperty);
                            }
                            unsigned short type = (vtProp.vt-VT_BYREF);
                            char idx[_MAX_PATH] = {0};
                            string id;

                            switch(type)
                            {
                            case VT_I1:
                            case VT_UI1:
                                {
                                    vector<BYTE> vui1;
                                    FromVariant(vtProp,vui1);
                                    for(unsigned int i=0;i<vui1.size();i++)
                                    {
                                        if(xml)
                                        {
                                            _snprintf(idx,sizeof(idx),"%.3u",i+1);
                                            _snprintf(szValue,sizeof(szValue),"0x%.2X",vui1[i]);

                                            id.assign(idx);
                                            value.assign(szValue);
                                            xml->CreateChild(idx,value);
                                        }
                                        else
                                        {
                                            _snprintf(szValue,sizeof(szValue),"%s.0x%.2X",szValue,vui1[i]);
                                        }
                                    }
                                    vui1.clear();
                                }
                                break;

                            case VT_I2:
                            case VT_UI2:
                                {
                                    vector<USHORT> vui2;
                                    FromVariant(vtProp,vui2);
                                    for(unsigned int i=0;i<vui2.size();i++)
                                    {
                                        if(xml)
                                        {
                                            _snprintf(idx,sizeof(idx),"%.3u",i+1);
                                            _snprintf(szValue,sizeof(szValue),"0x%.4X",vui2[i]);

                                            id.assign(idx);
                                            value.assign(szValue);
                                            xml->CreateChild(idx,value);
                                        }
                                        else
                                        {
                                            _snprintf(szValue,sizeof(szValue),"%s.0x%.4X",szValue,vui2[i]);
                                        }
                                    }
                                    vui2.clear();
                                }
                                break;

                            case VT_I4:
                            case VT_UI4:
                                {
                                    vector<ULONG> vui4;
                                    FromVariant(vtProp,vui4);
                                    for(unsigned int i=0;i<vui4.size();i++)
                                    {
                                        if(xml)
                                        {
                                            _snprintf(idx,sizeof(idx),"%.3u",i+1);
                                            _snprintf(szValue,sizeof(szValue),"0x%.8X",vui4[i]);

                                            id.assign(idx);
                                            value.assign(szValue);
                                            xml->CreateChild(idx,value);
                                        }
                                        else
                                        {
                                            _snprintf(szValue,sizeof(szValue),"%s.0x%.8X",szValue,vui4[i]);
                                        }
                                    }
                                    vui4.clear();
                                }
                                break;

                            case VT_I8:
                            case VT_UI8:
                                {
                                    vector<ULONGLONG> vui8;
                                    FromVariant(vtProp,vui8);
                                    for(unsigned int i=0;i<vui8.size();i++)
                                    {
                                        if(xml)
                                        {
                                            _snprintf(idx,sizeof(idx),"%.3u",i+1);
                                            _snprintf(szValue,sizeof(szValue),"0x%.16X",vui8[i]);

                                            id.assign(idx);
                                            value.assign(szValue);
                                            xml->CreateChild(idx,value);
                                        }
                                        else
                                        {
                                            _snprintf(szValue,sizeof(szValue),"%s.0x%.16X",szValue,vui8[i]);
                                        }
                                    }
                                    vui8.clear();
                                }
                                break;

                            case VT_R4:
                                {
                                    vector<float> vr4;
                                    FromVariant(vtProp,vr4);
                                    for(unsigned int i=0;i<vr4.size();i++)
                                    {
                                        if(xml)
                                        {
                                            _snprintf(idx,sizeof(idx),"%.3u",i+1);
                                            _snprintf(szValue,sizeof(szValue),"%f",vr4[i]);

                                            id.assign(idx);
                                            value.assign(szValue);
                                            xml->CreateChild(idx,value);
                                        }
                                        else
                                        {
                                            _snprintf(szValue,sizeof(szValue),"%s.%f",szValue,vr4[i]);
                                        }
                                    }
                                    vr4.clear();
                                }
                                break;

                            case VT_R8:
                            case VT_DATE:
                                {
                                    vector<double> vr8;
                                    FromVariant(vtProp,vr8);
                                    for(unsigned int i=0;i<vr8.size();i++)
                                    {
                                        if(xml)
                                        {
                                            _snprintf(idx,sizeof(idx),"%.3u",i+1);
                                            _snprintf(szValue,sizeof(szValue),"%e",vr8[i]);

                                            id.assign(idx);
                                            value.assign(szValue);
                                            xml->CreateChild(idx,value);
                                        }
                                        else
                                        {
                                            _snprintf(szValue,sizeof(szValue),"%s.%e",szValue,vr8[i]);
                                        }
                                    }
                                    vr8.clear();
                                }
                                break;

                            case VT_BSTR:
                                {
                                    vector<BSTR> vbstr;
                                    FromVariant(vtProp,vbstr);

                                    Log(LOG_MESSAGE,__LINE__,"%s, %d:",wmiClasses[x].pProperty,vbstr.size());
                                    for(unsigned int i=0;i<vbstr.size();i++)
                                    {
                                        WideCharToMultiByte(CP_ACP,0,(LPCWSTR)vbstr[i],-1,(LPSTR)szValue,sizeof(szValue),NULL,NULL);
                                        if(xml)
                                        {
                                            _snprintf(idx,sizeof(idx),"%.3u",i+1);

                                            id.assign(idx);
                                            value.assign(szValue);
                                            xml->CreateChild(idx,value);
                                        }
                                        else
                                        {
                                            Log(LOG_MESSAGE,__LINE__,"\t> %.3d %s",i+1,szValue);
                                        }
                                        memset(szValue,0x00,sizeof(szValue));
                                    }
                                    vbstr.clear();
                                }
                                break;
                            }
                            if(xml)
                            {
                                xml->CloseLasttag();
                            }
                            else
                            {
                                if(strlen(szValue)>0)
                                {
                                    Log(LOG_MESSAGE,__LINE__,"%s = %d",wmiClasses[x].pProperty,szValue);
                                }
                            }
                        }   //END: if(vtProp.vt & VT_BYREF)
                        break;
                    }   //END: switch(vtProp.vt)

                    VariantClear(&vtProp);
                }   //END: try
                catch(...)
                {
                    Log(LOG_DEBUG_WMI,__LINE__,"-- WMI, Catch unhndld excpetion on %.5u %s (%i) %s",properties,wmiClasses[x].pClass,x+1,wmiClasses[x].pProperty);
                }
            }
            pclsObj->Release();
        }   //END: while (pEnumerator)
    }
 
    //process the number of properties processed
    if(lpulProperties) {
        *lpulProperties = properties;
    }

    char processed[_MAX_PATH] = {0};
    if(properties==0)
    {
        _snprintf(processed,sizeof(processed),"No properties processed");
    }
    else
    {
        _snprintf(processed,sizeof(processed),"%u properties processed",properties);
    }
    if(xml)
    {
        string temp;
        temp.append(processed);
        xml->AddComment(temp);
    }
    else
    {
        Log(LOG_MESSAGE,__LINE__,processed);
    }

    // Cleanup
    // ========

    pSvc->Release();
    pLoc->Release();     
    CoUninitialize();
    if(xml)
    {
        string temp;
        char elapsedTime[_MAX_PATH] = {0};
        unsigned __int64 tickEnd;
        float timeElapsed;
        unsigned long seconds;
        CalcElapsedTime(tickStart,tickEnd,timeElapsed,seconds);

        _snprintf(elapsedTime,sizeof(elapsedTime),"Elapsed Time: %02d:%02d:%02d, %f s",seconds/3600,(seconds % 3600)/60,seconds % 60,timeElapsed);
        temp.assign(elapsedTime);

        xml->AddComment(temp);
        xml->CloseLasttag();
    }
    else
    {
        LogElapsedTime(__LINE__,tickStart);
    }
    ReleaseMutex(hWmiMutex);
    CloseHandle(hWmiMutex);

    Log(LOG_DEBUG_WMI,__LINE__,"<< WMI, ret True");
    return true;
}
void WMI(char *lpszOption,unsigned long *lpulProperties=NULL)
{
    WMIex(lpszOption,NULL,lpulProperties);
}

/*
** ThreadWMIClass: Thread function for the specific group of WMI classes
*/
unsigned WINAPI ThreadWMIClass(LPVOID lpData)
{
    vector<string> * plist = (vector<string>*)lpData;

	Log(LOG_DEBUG_WMI,__LINE__,">> ThrdWMICls, 0x%p",lpData);

    if(NULL==lpData)
    {
        Log(LOG_DEBUG_WMI,__LINE__,"<< ThrdWMICls, Input null",lpData);
        _endthreadex(ERROR_INVALID_DATA);
        return ERROR_INVALID_DATA;
    }

    //find the last file
    HANDLE hXmlFile = NULL;
    int x;
    for(x=9;x>=0;x--)
    {
        char temp[_MAX_PATH] = {0};
        _snprintf(temp,sizeof(temp),"%s_%s_%.1d.xml",gszLogFilePrefix,plist->at(0).c_str(),x);
        Log(LOG_DEBUG_WMI,__LINE__,"-- ThrdWMICls, Trying opng %s",temp);
        hXmlFile = CreateFile(temp,GENERIC_READ|GENERIC_WRITE,
                                      FILE_SHARE_READ|FILE_SHARE_WRITE,
                                      NULL,
                                      OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL,
                                      NULL);
        if(hXmlFile!=INVALID_HANDLE_VALUE)
        {
            Log(LOG_DEBUG_WMI,__LINE__,"-- ThrdWMICls, Last file fnd: %s",temp);
            CloseHandle(hXmlFile);
            hXmlFile = NULL;

            //all file were filled, removed the last one
            if(x==9) {
                Log(LOG_DEBUG_WMI,__LINE__,"-- ThrdWMICls, Removing %s - oldest file",temp);
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
        //rename the _<x>.xml to _<x+1>.xml
        _snprintf(newFile,sizeof(newFile),"%s_%s_%.1d.xml",gszLogFilePrefix,plist->at(0).c_str(),x+1);
        _snprintf(oldFile,sizeof(oldFile),"%s_%s_%.1d.xml",gszLogFilePrefix,plist->at(0).c_str(),x);

        Log(LOG_DEBUG_WMI,__LINE__,"-- ThrdWMICls, Renaming %s -> %s",oldFile,newFile);
        rename((const char*)oldFile,(const char*)newFile);
    }

    //rename the .xml to _0.xml
    _snprintf(newFile,sizeof(newFile),"%s_%s_0.xml",gszLogFilePrefix,plist->at(0).c_str());
    _snprintf(oldFile,sizeof(oldFile),"%s_%s.xml",gszLogFilePrefix,plist->at(0).c_str());
    Log(LOG_DEBUG_WMI,__LINE__,"-- ThrdWMICls, Remaning %s -> %s",oldFile,newFile);
    rename((const char*)oldFile,(const char*)newFile);

    string fileName;
    fileName.assign(oldFile);
    xmlwriter *xml = new xmlwriter(fileName,DebugStringToFile);
    if(!xml)
    {
        Log(LOG_DEBUG_WMI,__LINE__,"<< ThrdWMICls, New XmlWriter(%s) class null",oldFile);
        _endthreadex(ERROR_OUTOFMEMORY);
        return ERROR_OUTOFMEMORY;
    }

    unsigned __int64 tickStart = SysTick();

    xml->Createtag(plist->at(0));
    xml->AddComment(plist->at(1));

    for(unsigned long x=2;x<plist->size() && _thGetInt(&gbTerminate)==FALSE;x++)
    {
        while(WMIex((char*)plist->at(x).c_str(),xml)==false);
    }
    xml->CloseAlltags();

    delete xml;
    xml = NULL;

    unsigned __int64 tickEnd;
    float timeElapsed;
    unsigned long seconds;
    CalcElapsedTime(tickStart,tickEnd,timeElapsed,seconds);

    Log(LOG_DEBUG_WMI,__LINE__,"<< ThrdWMICls, %s, %02d:%02d:%02d, %f s",plist->at(0).c_str(),seconds/3600,(seconds % 3600)/60,seconds % 60,timeElapsed);
	_endthreadex(0);
	return 0;
}

/*
** ThreadWMI: Thread function for the WMI processing
*/
unsigned WINAPI ThreadWMI(LPVOID lpData)
{
    DWORD threads = 0;
    unsigned int uiThreadId = 0;
    HANDLE ahThreads[20] = {0};

	Log(LOG_DEBUG_WMI,__LINE__,">> ThrdWMI, In");

    unsigned __int64 tickStart = SysTick();

    //HW ************
    vector<string> hwInfo(32);

    hwInfo[0] = "HardwareInfo";
    hwInfo[1] = "Hardware Information";

    hwInfo[2] = "Win32_1394Controller";
    hwInfo[3] = "Win32_BaseBoard";
    hwInfo[4] = "Win32_Battery";
    hwInfo[5] = "Win32_BIOS";
    hwInfo[6] = "Win32_Bus";
    hwInfo[7] = "Win32_CDROMDrive";
    hwInfo[8] = "Win32_DMAChannel";
    hwInfo[9] = "Win32_DriverVXD";
    hwInfo[10] = "Win32_FloppyController";
    hwInfo[11] = "Win32_FloppyDrive";
    hwInfo[12] = "Win32_HeatPipe";
    hwInfo[13] = "Win32_Keyboard";
    hwInfo[14] = "Win32_MotherboardDevice";
    hwInfo[15] = "Win32_OnBoardDevice";
    hwInfo[16] = "Win32_IDEController";
    hwInfo[17] = "Win32_InfraredDevice";
    hwInfo[18] = "Win32_IRQResource";
    hwInfo[19] = "Win32_PCMCIAController";
    hwInfo[20] = "Win32_PointingDevice";
    hwInfo[21] = "Win32_PortConnector";
    hwInfo[22] = "Win32_PortResource";
    hwInfo[23] = "Win32_PnPEntity";
#ifdef _GET_WMI_PRINTER
    hwInfo[] = "Win32_Printer";
#endif
    hwInfo[24] = "Win32_PrinterDriver";
    hwInfo[25] = "Win32_Processor";
    hwInfo[26] = "Win32_SCSIController";
    hwInfo[27] = "Win32_SerialPort";
    hwInfo[28] = "Win32_SerialPortConfiguration";
    hwInfo[29] = "Win32_SoundDevice";
    hwInfo[30] = "Win32_USBController";
    hwInfo[31] = "Win32_VideoController";

    if(StartThread(hwInfo[0],ThreadWMIClass,(LPVOID)&hwInfo,0,&ahThreads[threads]))
    {
        threads++;
    }

    //HW ************

    //DATA **********
    vector<string> data(6);

    data[0] = "DataStorage";
    data[1] = "Disk and Partitions Information";

    data[2] = "Win32_DiskDrive";
    data[3] = "Win32_DiskPartition";
    data[4] = "Win32_PhysicalMedia";
    data[5] = "Win32_TapeDrive";

    if(StartThread(data[0],ThreadWMIClass,(LPVOID)&data,0,&ahThreads[threads]))
    {
        threads++;
    }
    //DATA **********

    //MEM ***********
    vector<string> memory(10);

    memory[0] = "Memory";
    memory[1] = "Memory Information";

    memory[2] = "Win32_CacheMemory";
    memory[3] = "Win32_DeviceMemoryAddress";
    memory[4] = "Win32_MemoryArray";
    memory[5] = "Win32_MemoryDevice";
    memory[6] = "Win32_PhysicalMemory";
    memory[7] = "Win32_PhysicalMemoryArray";
    memory[8] = "Win32_SMBIOSMemory";
    memory[9] = "Win32_SystemMemoryResource";

    if(StartThread(memory[0],ThreadWMIClass,(LPVOID)&memory,0,&ahThreads[threads]))
    {
        threads++;
    }
    //MEM ***********

    //SYS ***********
    vector<string> sysInfo(12);

    sysInfo[0] = "SystemInfo";
    sysInfo[1] = "System Information";

    //sysInfo[] = "Win32_ApplicationService";
    sysInfo[2] = "Win32_ComputerSystem";
    sysInfo[3] = "Win32_ComputerSystemProduct";
    sysInfo[4] = "Win32_Product";
    //sysInfo[] = "Win32_ProgIDSpecification";
    sysInfo[5] = "Win32_QuickFixEngineering";
    sysInfo[6] = "Win32_Refrigeration";
    sysInfo[7] = "Win32_Registry";
    sysInfo[8] = "Win32_SystemAccount";
    sysInfo[9] = "Win32_SystemDriver";
    sysInfo[10] = "Win32_SystemEnclosure";
    sysInfo[11] = "Win32_SystemSlot";

    if(StartThread(sysInfo[0],ThreadWMIClass,(LPVOID)&sysInfo,0,&ahThreads[threads]))
    {
        threads++;
    }
    //SYS ***********

    //NET ***********
    vector<string> net(6);

    net[0] = "Network";
    net[1] = "Network Information";

    net[2] = "Win32_NetworkAdapter";
    net[3] = "Win32_NetworkAdapterConfiguration";
    net[4] = "Win32_NetworkLoginProfile";
    net[5] = "Win32_NetworkProtocol";

    if(StartThread(net[0],ThreadWMIClass,(LPVOID)&net,0,&ahThreads[threads]))
    {
        threads++;
    }
    //NET ***********

    //USER **********
    vector<string> user(2);

    user[0] = "UserAccountAndSecurity";
    user[1] = "User Account and Security Information";

#ifdef _GET_WMI_ACCOUNTS    //user and groups which includes the full domain
    user[] = "Win32_Account";
#endif

    if(StartThread(user[0],ThreadWMIClass,(LPVOID)&user,0,&ahThreads[threads]))
    {
        threads++;
    }
    //USER **********

    //DEV ***********
    vector<string> dev(4);

    dev[0] = "Developer";
    dev[1] = "Developer Information";

    dev[2] = "Win32_CodecFile";
#ifdef _GET_WMI_COMCLASS    //get all COM class - which can be thousands
    dev[] = "Win32_COMClass";
#endif
#ifdef _GET_WMI_SOFTWARE_DETAILS    //get all software element, part of a software feature
                                    //(a distinct subset of a product which may contain one 
                                    //or more elements) - which can be thousands
    dev[] = "Win32_SoftwareElement";
#endif
    dev[3] = "Win32_SoftwareFeature";

    if(StartThread(dev[0],ThreadWMIClass,(LPVOID)&dev,0,&ahThreads[threads]))
    {
        threads++;
    }
    //DEV ***********

    //UTIL **********
    vector<string> util(14);

    util[0] = "Utility";
    util[1] = "Utility Information";

    util[2] = "Win32_BaseService";
    util[3] = "Win32_BootConfiguration";
    util[4] = "Win32_Desktop";
    util[5] = "Win32_DesktopMonitor";
    util[6] = "Win32_Fan";
    util[7] = "Win32_OperatingSystem";
    util[8] = "Win32_PageFile";
    util[9] = "Win32_ParallelPort";
    util[10] = "Win32_Proxy";
    util[11] = "Win32_Share";
    util[12] = "Win32_WindowsProductActivation";
    util[13] = "Win32_WMISetting";

    if(StartThread(util[0],ThreadWMIClass,(LPVOID)&util,0,&ahThreads[threads]))
    {
        threads++;
    }
    //UTIL **********

    Log(LOG_DEBUG_WMI,__LINE__,"-- ThrdWMI, Waitg %u thrs",threads);
    WaitForMultipleObjects(threads,ahThreads,TRUE,INFINITE);
    for(DWORD x=0;x<threads;x++)
    {
        CloseHandle(ahThreads[x]);
    }
    hwInfo.clear();
    data.clear();
    memory.clear();
    sysInfo.clear();
    net.clear();
    user.clear();
    dev.clear();
    util.clear();

    unsigned __int64 tickEnd;
    float timeElapsed;
    unsigned long seconds;
    CalcElapsedTime(tickStart,tickEnd,timeElapsed,seconds);

    Log(LOG_DEBUG_WMI,__LINE__,"<< ThrdWMI, Out, %02d:%02d:%02d, %f s",seconds/3600,(seconds % 3600)/60,seconds % 60,timeElapsed);
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

    Log(LOG_DEBUG_WMI,__LINE__,">> WMISysVols");

    //always check both because there may be moments system cannot
    //detect a network connection and it always exist at least one 
    //logical disk
#ifdef _GET_WMI_LOGICALDISK
    WMI("Win32_LogicalDisk");
#endif

    WMI("Win32_NetworkConnection");

    if(Volume!=0)
    {
        WMI("Win32_Volume",&Volume);
    }

    Log(LOG_DEBUG_WMI,__LINE__,"<< WMISysVols");
}

#ifdef _GET_WMI_USBINFO
/*
** WMISystemUsb: get all system usb details
** device arrival/remove: DBT_DEVTYP_DEVICEINTERFACE
*/
void WMISystemUsb(void)
{
    Log(LOG_DEBUG_WMI,__LINE__,">> WMISysUsb");

    WMI("Win32_USBHub");

    Log(LOG_DEBUG_WMI,__LINE__,"<< WMISysUsb");
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

    Log(LOG_DEBUG_WMI,__LINE__,">> WMISysPerf");

    if(PerfRawData_PerfDisk_PhysicalDisk!=0)
    {
        WMI("Win32_PerfRawData_PerfDisk_PhysicalDisk",&PerfRawData_PerfDisk_PhysicalDisk);
    }

    if(PerfRawData_PerfNet_Redirector!=0)
    {
        WMI("Win32_PerfRawData_PerfNet_Redirector",&PerfRawData_PerfNet_Redirector);
    }

    if(PerfRawData_PerfOS_Cache!=0)
    {
        WMI("Win32_PerfRawData_PerfOS_Cache",&PerfRawData_PerfOS_Cache);
    }

    if(PerfRawData_PerfOS_Memory!=0)
    {
        WMI("Win32_PerfRawData_PerfOS_Memory",&PerfRawData_PerfOS_Memory);
    }

    if(PerfRawData_PerfOS_Objects!=0)
    {
        WMI("Win32_PerfRawData_PerfOS_Objects",&PerfRawData_PerfOS_Objects);
    }

    if(PerfRawData_PerfOS_PagingFile!=0)
    {
        WMI("Win32_PerfRawData_PerfOS_PagingFile",&PerfRawData_PerfOS_PagingFile);
    }

    if(PerfRawData_PerfOS_Processor!=0)
    {
        WMI("Win32_PerfRawData_PerfOS_Processor",&PerfRawData_PerfOS_Processor);
    }

    if(PerfRawData_PerfOS_System!=0)
    {
        WMI("Win32_PerfRawData_PerfOS_System",&PerfRawData_PerfOS_System);
    }

    Log(LOG_DEBUG_WMI,__LINE__,"<< WMISysPerf");
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

    Log(LOG_DEBUG_WMI,__LINE__,">> WMIHwSnsr");

    if(CurrentProbe!=0)
    {
        WMI("Win32_CurrentProbe",&CurrentProbe);
    }

    if(PortableBattery!=0)
    {
        WMI("Win32_PortableBattery",&PortableBattery);
    }

    if(TemperatureProbe!=0)
    {
        WMI("Win32_TemperatureProbe",&TemperatureProbe);
    }

    if(VoltageProbe!=0)
    {
        WMI("Win32_VoltageProbe",&VoltageProbe);
    }

    Log(LOG_DEBUG_WMI,__LINE__,"<< WMIHwSnsr");
}
