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
    vector<string> m_ips;
    bool m_changed;

public:
    MonitorIPs() : m_hSync(NULL), m_hWait(NULL), m_changed(false)
    {
        Log(LOG_DEBUG,__LINE__,">> MonIPs");

        ZeroMemory(&m_o, sizeof(m_o));

        m_ips.clear();
    }

    ~MonitorIPs()
    {
        if (m_hWait) UnregisterWaitEx(m_hWait, INVALID_HANDLE_VALUE);
        if (m_o.hEvent) CloseHandle(m_o.hEvent);
        if (m_hSync) CloseHandle(m_hSync);

        m_ips.clear();

        Log(LOG_DEBUG,__LINE__,"<< MonIPs");
    }

    bool Initialize();

    void GetIPs(vector<string>& ips)
    {
        WaitForSingleObject(m_hSync,MINUTE);
        
        ips = m_ips;
        
        ReleaseMutex(m_hSync);
    }

    bool IsChanged()
    {
        WaitForSingleObject(m_hSync,MINUTE);

        bool ret = m_changed;
        m_changed = false;

        ReleaseMutex(m_hSync);
        return ret;
    }

protected:
    static void CALLBACK s_OnChange(PVOID lpParameter,BOOLEAN b)
    {
        Log(LOG_DEBUG,__LINE__,"-- MonIPs.OnChng, 0x%p %.2X",lpParameter,b);
        MonitorIPs *self = reinterpret_cast<MonitorIPs*>(lpParameter);
        self->CheckIPAddress();     // something changed - check it again
        self->SetChange();
    }

    void CheckIPAddress();
    void SetChange()
    {
        WaitForSingleObject(m_hSync,MINUTE);
        m_changed = true;
        ReleaseMutex(m_hSync);
    }

private:
    MonitorIPs(const MonitorIPs &monIps);
    MonitorIPs &MonitorIPs::operator=(const MonitorIPs &monIps);
};

#endif  //_MONITOR_IPS_INCLUDE_
