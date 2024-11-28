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
//#include <winsock2.h>
//#include <ws2tcpip.h>
#include <iphlpapi.h>

#ifndef _MONITOR_IPS_INCLUDE_
#define _MONITOR_IPS_INCLUDE_

class MonitorIPs
{
private:
    HANDLE m_hSync;
    HANDLE m_hWait;
    OVERLAPPED m_o;
    std::vector<std::string> m_ips;
    bool m_changed;

public:
    MonitorIPs() : m_hSync(nullptr), m_hWait(nullptr), m_changed(false)
    {
        Log(LOG_DEBUG, __LINE__, ">> MonIPs");
        ZeroMemory(&m_o, sizeof(m_o));
        m_ips.clear();
    }

    MonitorIPs(const MonitorIPs& monIps) = delete;
    MonitorIPs& MonitorIPs::operator=(const MonitorIPs& monIps) = delete;
    MonitorIPs(const MonitorIPs&& monIps) = delete;
    MonitorIPs&& MonitorIPs::operator=(const MonitorIPs&& monIps) = delete;

    ~MonitorIPs()
    {
        if (m_hWait) static_cast<void>(UnregisterWaitEx(m_hWait, INVALID_HANDLE_VALUE));
        if (m_o.hEvent) CloseHandle(m_o.hEvent);
        if (m_hSync) CloseHandle(m_hSync);

        Log(LOG_DEBUG, __LINE__, "<< MonIPs");
    }

    bool Initialize();

    void GetIPs(std::vector<std::string>& ips)
    {
        WaitForSingleObject(m_hSync, MINUTE);

        ips = m_ips;

        ReleaseMutex(m_hSync);
    }

    bool IsChanged()
    {
        WaitForSingleObject(m_hSync, MINUTE);

        bool ret = m_changed;
        m_changed = false;

        ReleaseMutex(m_hSync);
        return ret;
    }

protected:
    static void CALLBACK s_OnChange(PVOID lpParameter, BOOLEAN b)
    {
        Log(LOG_DEBUG, __LINE__, "-- MonIPs.OnChng, 0x%p %.2X", lpParameter, b);
        MonitorIPs *self = reinterpret_cast<MonitorIPs*>(lpParameter);
        self->CheckIPAddress();     // something changed - check it again
        self->SetChange();
    }

    void CheckIPAddress();
    void SetChange()
    {
        WaitForSingleObject(m_hSync, MINUTE);
        m_changed = true;
        ReleaseMutex(m_hSync);
    }
};

#endif  //_MONITOR_IPS_INCLUDE_
