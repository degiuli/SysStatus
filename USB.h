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
#include "vndrlist.h"
#include "usbdesc.h"

#ifndef _USB_INCLUDE_
#define _USB_INCLUDE_

//USB Windows Functions
typedef CMAPI CONFIGRET (WINAPI *CMGETPARENT)(PDEVINST, DEVINST, ULONG);
typedef CMAPI CONFIGRET (WINAPI *CMGETSIBLING) (PDEVINST, DEVINST, ULONG);
typedef CMAPI CONFIGRET (WINAPI *CMGETCHILD) (PDEVINST, DEVINST, ULONG);
typedef CMAPI CONFIGRET (WINAPI *CMGETDEVNODEREGISTRYPROPERTYA) (DEVINST, ULONG, PULONG, PVOID, PULONG, ULONG);
typedef CMAPI CONFIGRET (WINAPI *CMLOCATEDEVNODEA) (PDEVINST,DEVINSTID_A, ULONG);

//USB Types
#define NUM_HCS_TO_CHECK	10

#pragma warning( disable : 4201 )
typedef union _USB_HUB_CAP_FLAGS {
    ULONG ul;
    struct {
        ULONG HubIsHighSpeedCapable:1;
        ULONG HubIsHighSpeed:1;
        ULONG HubIsMultiTtCapable:1;
        ULONG HubIsMultiTt:1;
        ULONG HubIsRoot:1;
        ULONG HubIsArmedWakeOnConnect:1;
        ULONG HubIsBusPowered:1;
        ULONG ReservedMBZ:25;
    };

} USB_HUB_CAP_FLAGS, *PUSB_HUB_CAP_FLAGS;

#pragma warning( default : 4201 )

C_ASSERT(sizeof(USB_HUB_CAP_FLAGS) == sizeof(ULONG));

typedef struct _USB_HUB_CAPABILITIES_EX {

    USB_HUB_CAP_FLAGS CapabilityFlags;

} USB_HUB_CAPABILITIES_EX, *PUSB_HUB_CAPABILITIES_EX;

typedef struct _STRING_DESCRIPTOR_NODE
{
    struct _STRING_DESCRIPTOR_NODE *Next;
    UCHAR                           DescriptorIndex;
    USHORT                          LanguageID;
    USB_STRING_DESCRIPTOR           StringDescriptor[0];
} STRING_DESCRIPTOR_NODE, *PSTRING_DESCRIPTOR_NODE;

typedef struct
{
    PUSB_NODE_INFORMATION               HubInfo;        // NULL if not a HUB
    PCHAR                               HubName;        // NULL if not a HUB
    PUSB_NODE_CONNECTION_INFORMATION_EX ConnectionInfo; // NULL if root HUB
    PUSB_DESCRIPTOR_REQUEST             ConfigDesc;     // NULL if root HUB
    PSTRING_DESCRIPTOR_NODE             StringDescs;
} USBDEVICEINFO, *PUSBDEVICEINFO;

class USB {
protected:
    WORD wPortsNumber;
    ULONG ulTotalDevicesConnected;
    int NestedLevel;
    CHAR buf[512];

    std::vector<std::string> usbDevDetails;

    CMGETPARENT lpfnCM_Get_Parent;
    CMGETSIBLING lpfnCM_Get_Sibling;
    CMGETCHILD lpfnCM_Get_Child;
    CMGETDEVNODEREGISTRYPROPERTYA lpfnCM_Get_DevNode_Registry_PropertyA;
    CMLOCATEDEVNODEA lpfnCM_Locate_DevNodeA;

    PSTRING_DESCRIPTOR_NODE GetStringDescriptor(HANDLE hHubDevice, ULONG ConnectionIndex, UCHAR DescriptorIndex, USHORT LanguageID);
    PSTRING_DESCRIPTOR_NODE GetAllStringDescriptors(HANDLE hHubDevice, ULONG ConnectionIndex, PUSB_DEVICE_DESCRIPTOR DeviceDesc, PUSB_CONFIGURATION_DESCRIPTOR ConfigDesc);
    PSTRING_DESCRIPTOR_NODE GetStringDescriptors(HANDLE hHubDevice, ULONG ConnectionIndex, UCHAR DescriptorIndex, ULONG NumLanguageIDs, USHORT *LanguageIDs, PSTRING_DESCRIPTOR_NODE StringDescNodeTail);
    PUSB_DESCRIPTOR_REQUEST GetConfigDescriptor(HANDLE hHubDevice, ULONG ConnectionIndex, UCHAR DescriptorIndex);

    PCHAR GetRootHubName(HANDLE HostController);
    PCHAR GetHCDDriverKeyName(HANDLE HCD);
    PCHAR GetDriverKeyName(HANDLE Hub, ULONG ConnectionIndex);
    PCHAR GetExternalHubName(HANDLE Hub, ULONG ConnectionIndex);
    PCHAR DriverNameToDeviceDesc(PCHAR DriverName);

    VOID EnumerateHubPorts(HANDLE hHubDevice, ULONG NumPorts);
    VOID EnumerateHub(PCHAR HubName, PUSB_NODE_CONNECTION_INFORMATION_EX ConnectionInfo, PUSB_DESCRIPTOR_REQUEST ConfigDesc, PSTRING_DESCRIPTOR_NODE StringDescs, PCHAR DeviceDesc);

    BOOL AreThereStringDescriptors(PUSB_DEVICE_DESCRIPTOR DeviceDesc, PUSB_CONFIGURATION_DESCRIPTOR ConfigDesc);

    VOID HubInfo(PUSB_HUB_INFORMATION HubInfo);
    VOID HubCaps(PUSB_HUB_CAPABILITIES_EX HubCapsEx,PUSB_HUB_CAPABILITIES HubCaps);
    VOID ConnectionInfo(PUSB_NODE_CONNECTION_INFORMATION_EX ConnectInfo,PSTRING_DESCRIPTOR_NODE StringDescs);
    VOID PipeInfo(ULONG NumPipes,USB_PIPE_INFO *PipeInfo);
    VOID ConfigDesc(PUSB_CONFIGURATION_DESCRIPTOR ConfigDesc,PSTRING_DESCRIPTOR_NODE StringDescs);
    VOID ConfigurationDescriptor(PUSB_CONFIGURATION_DESCRIPTOR ConfigDesc,PSTRING_DESCRIPTOR_NODE StringDescs);
    VOID InterfaceDescriptor(PUSB_INTERFACE_DESCRIPTOR InterfaceDesc,PSTRING_DESCRIPTOR_NODE StringDescs);
    VOID EndpointDescriptor(PUSB_ENDPOINT_DESCRIPTOR EndpointDesc);
    VOID HidDescriptor(PUSB_HID_DESCRIPTOR HidDesc);
    VOID StringDescriptor(UCHAR Index,PSTRING_DESCRIPTOR_NODE StringDescs);
    VOID UnknownDescriptor(PUSB_COMMON_DESCRIPTOR CommonDesc);

    void PushBackDetails(const char*format, ...)
    {
        char buffer[2048] = { 0 };
        va_list argptr;
        va_start(argptr, format);
        _vsnprintf(buffer, sizeof(buffer) - 1, format, argptr);
        va_end(argptr);

        Log(LOG_DEBUG,__LINE__,"-- USB.PushBackDets, %s", buffer);
        usbDevDetails.push_back(buffer);
    }

public:
    USB() : 
        wPortsNumber(0),
        ulTotalDevicesConnected(0),
        NestedLevel(0),
        lpfnCM_Get_Parent(nullptr),
        lpfnCM_Get_Sibling(nullptr),
        lpfnCM_Get_Child(nullptr),
        lpfnCM_Get_DevNode_Registry_PropertyA(nullptr),
        lpfnCM_Locate_DevNodeA(nullptr)
    {
        memset(buf,0x00,sizeof(buf));
        usbDevDetails.clear();
    };

    ~USB()
    {
        usbDevDetails.clear();
    };

    USB(const USB& usb) = delete;
    USB& USB::operator=(const USB& usb) = delete;
    USB(const USB&& usb) = delete;
    USB&& USB::operator=(const USB&& usb) = delete;

    void EnumerateUSB();
    void USBDevicesDetails();

    static std::string GetVendorString(uint64_t const idVendor)
    {
        if (idVendor != 0x0000)
        {
            auto const usbit = usbNames.find(idVendor);
            if (usbit != usbNames.cend())
                return usbit->second;
        }
        return "";
    }
};

#endif  //_USB_INCLUDE_
