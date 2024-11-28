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

#include "MonitorIPs.h"

#include <sstream>

bool MonitorIPs::Initialize()
{
    Log(LOG_DEBUG, __LINE__, ">> MonIPs.Init");

    m_hSync = CreateMutex(nullptr, FALSE, nullptr);
    if (!m_hSync)
    {
        Log(LOG_DEBUG, __LINE__, "<< MonIPs.Init, Sync Obj %u", GetLastError());
        return false;
    }

    m_o.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!m_o.hEvent)
    {
        Log(LOG_DEBUG, __LINE__, "<< MonIPs.Init, CreateEv %u", GetLastError());
        return false;
    }

    if (!RegisterWaitForSingleObject(&m_hWait, m_o.hEvent, s_OnChange, this, INFINITE, 0))
    {
        Log(LOG_DEBUG, __LINE__, "<< MonIPs.Init, RegWaitForSnglObj %u", GetLastError());
        return false;
    }

    CheckIPAddress();

    Log(LOG_DEBUG, __LINE__, "<< MonIPs.Init, Ev 0x%p, ret True", m_o.hEvent);
    return true;
}

void MonitorIPs::CheckIPAddress()
{
    ULONG ulSize = 0;

    Log(LOG_DEBUG, __LINE__, ">> MonIPs.ChkIPAddrs");

    //Get number of bytes required
    if (GetIpAddrTable(nullptr, &ulSize, 0) == ERROR_INSUFFICIENT_BUFFER)
    {
        //Allocate required memory
        HANDLE const hDefaultProcessHeap = GetProcessHeap();
        PMIB_IPADDRTABLE piat = reinterpret_cast<PMIB_IPADDRTABLE>(HeapAlloc(hDefaultProcessHeap, HEAP_ZERO_MEMORY, ulSize));
        if (piat)
        {
            //Retrieve the list of IPs
            if (GetIpAddrTable(piat, &ulSize, 0) == ERROR_SUCCESS)
            {
                WaitForSingleObject(m_hSync, MINUTE);
                m_ips.clear();

                for (DWORD dwIndex = 0; dwIndex < piat->dwNumEntries; dwIndex++)
                {
                    //Trace all IPs
                    std::stringstream ss;
                    PMIB_IPADDRROW prow = &piat->table[dwIndex];
                    IN_ADDR IPAddr{};

                    IPAddr.S_un.S_addr = static_cast<ULONG>(prow->dwAddr);
                    ss << "Address " << inet_ntoa(IPAddr) << ", Index " << prow->dwIndex;
                    
                    IPAddr.S_un.S_addr = static_cast<ULONG>(prow->dwMask);
                    ss << ", Subnet Mask " << inet_ntoa(IPAddr);

                    IPAddr.S_un.S_addr = static_cast<ULONG>(prow->dwBCastAddr);
                    ss << ", BroadCast " << inet_ntoa(IPAddr)
                       << ", Reasm " << prow->dwReasmSize;

                    ss << ", Type " << std::hex << prow->wType << "(.";

                    if (prow->wType & MIB_IPADDR_PRIMARY)
                        ss << "Primary.";

                    if (prow->wType & MIB_IPADDR_DYNAMIC)
                        ss << "Dynamic.";

                    if (prow->wType & MIB_IPADDR_DISCONNECTED)
                        ss << "Disconnected.";

                    if (prow->wType & MIB_IPADDR_DELETED)
                        ss << "Deleted.";

                    if (prow->wType & MIB_IPADDR_TRANSIENT)
                        ss << "Transient.";

                    if (prow->wType & MIB_IPADDR_DNS_ELIGIBLE)
                        ss << "Published in DNS.";

                    ss << ")";
                    m_ips.push_back(ss.str());
                }
                ReleaseMutex(m_hSync);
            }
            HeapFree(hDefaultProcessHeap, 0UL, piat);
        }
    }

    HANDLE h;
    NotifyAddrChange(&h, &m_o);

    Log(LOG_DEBUG, __LINE__, "<< MonIPs.ChkIPAddrs");
}
