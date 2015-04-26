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

#include "MonitorIPs.h"

bool MonitorIPs::Initialize()
{
    Log(LOG_DEBUG,__LINE__,">> MonIPs.Init");

    m_hSync = CreateMutex(NULL,FALSE,NULL);
    if(!m_hSync)
    {
        Log(LOG_DEBUG,__LINE__,"<< MonIPs.Init, Sync Obj %u",GetLastError());
        return false;
    }

    m_o.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!m_o.hEvent)
    {
        Log(LOG_DEBUG,__LINE__,"<< MonIPs.Init, CreateEv %u",GetLastError());
        return false;
    }

    if(!RegisterWaitForSingleObject(&m_hWait,m_o.hEvent,s_OnChange,this,INFINITE,0))
    {
        Log(LOG_DEBUG,__LINE__,"<< MonIPs.Init, RegWaitForSnglObj %u",GetLastError());
        return false;
    }

    CheckIPAddress();

    Log(LOG_DEBUG,__LINE__,"<< MonIPs.Init, Ev 0x%p, ret True",m_o.hEvent);
    return true;
}

void MonitorIPs::CheckIPAddress()
{
    ULONG ulSize = 0;

    Log(LOG_DEBUG,__LINE__,">> MonIPs.ChkIPAddrs");

    //Get number of bytes required
    if(GetIpAddrTable(NULL,&ulSize,0)==ERROR_INSUFFICIENT_BUFFER)
    {
        //Aloocate required memory
        PMIB_IPADDRTABLE piat = reinterpret_cast<PMIB_IPADDRTABLE>(LocalAlloc(LMEM_FIXED,ulSize));
        if(piat)
        {
            //Retrive the list of IPs
            if(GetIpAddrTable(piat,&ulSize,0)==ERROR_SUCCESS)
            {
                WaitForSingleObject(m_hSync,MINUTE);
                m_ips.clear();

                for(DWORD dwIndex=0;dwIndex<piat->dwNumEntries;dwIndex++)
                {
                    //Trace all IPs
                    string strip;
                    char ip[_MAX_PATH] = {0};

                    PMIB_IPADDRROW prow = &piat->table[dwIndex];
                    _snprintf(ip,sizeof(ip)-1,"Addr %u, Idx %u, Mask %u, BCastAddr %u, ReasmSz %u, Tp %X.",
                                 prow->dwAddr,prow->dwIndex,prow->dwMask,prow->dwBCastAddr,prow->dwReasmSize,prow->wType);
                    strip.assign(ip);
                    if(prow->wType&MIB_IPADDR_PRIMARY)
                        strip.append("Primary.");
                    if(prow->wType&MIB_IPADDR_DYNAMIC)
                        strip.append("Dynamic.");
                    if(prow->wType&MIB_IPADDR_DISCONNECTED)
                        strip.append("Disconnected.");
                    if(prow->wType&MIB_IPADDR_DELETED)
                        strip.append("Deleted.");
                    if(prow->wType&MIB_IPADDR_TRANSIENT)
                        strip.append("Transient.");
                    if(prow->wType&MIB_IPADDR_DNS_ELIGIBLE)
                        strip.append("Published in DNS.");

                    m_ips.push_back(strip);
                }
                ReleaseMutex(m_hSync);
            }
            LocalFree(piat);
        }
    }

    HANDLE h;
    NotifyAddrChange(&h, &m_o);

    Log(LOG_DEBUG,__LINE__,"<< MonIPs.ChkIPAddrs");
}
