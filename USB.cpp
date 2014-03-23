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

#include "SysStatus.h"
#include "USB.h"

PCHAR ConnectionStatuses[] =
{
    "NoDeviceConnected",
    "DeviceConnected",
    "DeviceFailedEnumeration",
    "DeviceGeneralFailure",
    "DeviceCausedOvercurrent",
    "DeviceNotEnoughPower",
	"DeviceNotEnoughBandwidth",
	"DeviceHubNestedTooDeeply",
	"DeviceInLegacyHub"
};

PCHAR UsbViewIndent[] =
{
	"",
	"  ",
	"    ",
	"      ",
	"        ",
	"          "
};

extern BOOL gbTerminate;
extern BOOL gbShutdown;

/*
** EnumerateUSB
*/
void USB::EnumerateUSB()
{
    char        HCName[16];
    int         HCNum = 0;
    HANDLE      hHCDev = 0;
    PCHAR       rootHubName = NULL;
    PCHAR       leafName = NULL;

    unsigned __int64 tickStart = SysTick();

	Log(LOG_DEBUG,__LINE__,">> USB.EnumUSB");

    ulTotalDevicesConnected = 0;
	wPortsNumber = 0;
    NestedLevel = 0;
    memset(buf,0x00,sizeof(buf));

    usbDevDetails.clear();

    lpfnCM_Get_Parent = NULL;
    lpfnCM_Get_Sibling = NULL;
    lpfnCM_Get_Child = NULL;
    lpfnCM_Get_DevNode_Registry_PropertyA = NULL;
    lpfnCM_Locate_DevNodeA = NULL;

	HMODULE hPnpDll = LoadLibrary ("cfgmgr32.dll");
	if (hPnpDll == NULL)
	{
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
        Log(LOG_DEBUG,__LINE__,"<< USB.EnumUSB, LoadLib cfgmgr32.dll failed: %u, %s",dwLastError,szLastError);
		return;
	}

	if ((lpfnCM_Get_Parent = (CMGETPARENT) GetProcAddress (hPnpDll, "CM_Get_Parent")) == NULL)
	{
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
		FreeLibrary (hPnpDll);
        Log(LOG_DEBUG,__LINE__,"<< USB.EnumUSB, GetProcAdr CM_Get_Parent failed: %u, %s",dwLastError,szLastError);
		return;
	}

	if ((lpfnCM_Get_Sibling = (CMGETSIBLING) GetProcAddress (hPnpDll, "CM_Get_Sibling")) == NULL)
	{
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
		FreeLibrary (hPnpDll);
		Log(LOG_DEBUG,__LINE__,"<< USB.EnumUSB, GetProcAdr CM_Get_Sibling failed: %u, %s",dwLastError,szLastError);
		return;
	}

	if ((lpfnCM_Get_Child = (CMGETCHILD) GetProcAddress (hPnpDll, "CM_Get_Child")) == NULL)
	{
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
		FreeLibrary (hPnpDll);
		Log(LOG_DEBUG,__LINE__,"<< USB.EnumUSB, GetProcAdr CM_Get_Child failed: %u, %s",dwLastError,szLastError);
		return;
	}

	if ((lpfnCM_Get_DevNode_Registry_PropertyA = (CMGETDEVNODEREGISTRYPROPERTYA) GetProcAddress (hPnpDll, "CM_Get_DevNode_Registry_PropertyA"))  == NULL)
	{
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
		FreeLibrary (hPnpDll);
		Log(LOG_DEBUG,__LINE__,"<< USB.EnumUSB, GetProcAdr CM_Get_DevNode_Registry_Property failed: %u, %s",dwLastError,szLastError);
		return;
	}

	if ((lpfnCM_Locate_DevNodeA = (CMLOCATEDEVNODEA) GetProcAddress (hPnpDll, "CM_Locate_DevNodeA")) == NULL)
	{
        char szLastError[1024] = {0};
        DWORD dwLastError = GetLastError();
        GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
		FreeLibrary (hPnpDll);
		Log(LOG_DEBUG,__LINE__,"<< USB.EnumUSB, GetProcAdr CM_Locate_DevNode failed: %u, %s",dwLastError,szLastError);
        return;
	}

    Log(LOG_HEADER,__LINE__,"Enumerate USB");

    // Iterate over some Host Controller names and try to open them.
    //
    for (HCNum = 0; HCNum < NUM_HCS_TO_CHECK; HCNum++)
    {
        sprintf(HCName, "\\\\.\\HCD%d", HCNum);

        hHCDev = CreateFile(HCName,
                            GENERIC_WRITE,
                            FILE_SHARE_WRITE,
                            NULL,
                            OPEN_EXISTING,
                            0,
                            NULL);

        // If the handle is valid, then we've successfully opened a Host
        // Controller.  Display some info about the Host Controller itself,
        // then enumerate the Root Hub attached to the Host Controller.
        //
        if (hHCDev != INVALID_HANDLE_VALUE)
        {
            PCHAR driverKeyName = NULL, deviceDesc = NULL;

            driverKeyName = GetHCDDriverKeyName(hHCDev);

            leafName = HCName + sizeof("\\\\.\\") - sizeof("");

            if (driverKeyName)
            {
                deviceDesc = DriverNameToDeviceDesc(driverKeyName);

                if (deviceDesc)
                {
                    leafName = deviceDesc;
               }

                free(driverKeyName);
            }

			Log(LOG_MESSAGE,__LINE__,"RootHub : %s",leafName);

            rootHubName = GetRootHubName(hHCDev);

            if (rootHubName != NULL)
            {
                EnumerateHub(rootHubName,
                             NULL,      // ConnectionInfo
                             NULL,      // ConfigDesc
                             NULL,      // StringDescs
                             "RootHub"  // DeviceDesc
                            );
            }

            CloseHandle(hHCDev);
			hHCDev = 0;
        }
    }

    Log(LOG_MESSAGE,__LINE__,"Total Devices Connected %u",ulTotalDevicesConnected);
	FreeLibrary (hPnpDll);
    LogElapsedTime(__LINE__,tickStart);
	Log(LOG_DEBUG,__LINE__,"<< USB.EnumUSB");
}

/*
** USBDevicesDetails
*/
void USB::USBDevicesDetails()
{
	Log(LOG_DEBUG,__LINE__,">> USB.DevsDets");

    unsigned __int64 tickStart = SysTick();

    Log(LOG_HEADER,__LINE__,"USB Device Details");

    for(unsigned int x=0;x<usbDevDetails.size();x++)
    {
        Log(LOG_MESSAGE,__LINE__,"%s",usbDevDetails[x].c_str());
    }

    LogElapsedTime(__LINE__,tickStart);

	Log(LOG_DEBUG,__LINE__,"<< USB.DevsDets");
}

/******************************************************************************
*
*  ENUMERATE USB AUXILIARY METHODS
*
******************************************************************************/
PSTRING_DESCRIPTOR_NODE USB::GetStringDescriptor(HANDLE hHubDevice, ULONG ConnectionIndex, UCHAR DescriptorIndex, USHORT LanguageID)
{
    BOOL    success;
    ULONG   nBytes = 0;
    ULONG   nBytesReturned = 0;

	Log(LOG_DEBUG,__LINE__,">> USB.GetStrDesc");

    UCHAR   stringDescReqBuf[sizeof(USB_DESCRIPTOR_REQUEST) + MAXIMUM_USB_STRING_LENGTH];

    PUSB_DESCRIPTOR_REQUEST stringDescReq = NULL;
    PUSB_STRING_DESCRIPTOR  stringDesc = NULL;
    PSTRING_DESCRIPTOR_NODE stringDescNode = NULL;

    nBytes = sizeof(stringDescReqBuf);

    stringDescReq = (PUSB_DESCRIPTOR_REQUEST)stringDescReqBuf;
    stringDesc = (PUSB_STRING_DESCRIPTOR)(stringDescReq+1);

    // Zero fill the entire request structure
    //
    memset(stringDescReq, 0, nBytes);

    // Indicate the port from which the descriptor will be requested
    //
    stringDescReq->ConnectionIndex = ConnectionIndex;

    //
    // USBHUB uses URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE to process this
    // IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION request.
    //
    // USBD will automatically initialize these fields:
    //     bmRequest = 0x80
    //     bRequest  = 0x06
    //
    // We must inititialize these fields:
    //     wValue    = Descriptor Type (high) and Descriptor Index (low byte)
    //     wIndex    = Zero (or Language ID for String Descriptors)
    //     wLength   = Length of descriptor buffer
    //
    stringDescReq->SetupPacket.wValue = (USB_STRING_DESCRIPTOR_TYPE << 8)
                                        | DescriptorIndex;

    stringDescReq->SetupPacket.wIndex = LanguageID;

    stringDescReq->SetupPacket.wLength = (USHORT)(nBytes - sizeof(USB_DESCRIPTOR_REQUEST));

    // Now issue the get descriptor request.
    //
    success = DeviceIoControl(hHubDevice,
                              IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
                              stringDescReq,
                              nBytes,
                              stringDescReq,
                              nBytes,
                              &nBytesReturned,
                              NULL);

    //
    // Do some sanity checks on the return from the get descriptor request.
    //

    if (!success)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetStrDesc, DeviceIoControl False");
        return NULL;
    }

    if (nBytesReturned < 2)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetStrDesc, Bytes Ret %u",nBytesReturned);
        return NULL;
    }

    if (stringDesc->bDescriptorType != USB_STRING_DESCRIPTOR_TYPE)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetStrDesc, Inv DescriptorTp %d",stringDesc->bDescriptorType);
        return NULL;
    }

    if (stringDesc->bLength != nBytesReturned - sizeof(USB_DESCRIPTOR_REQUEST))
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetStrDesc, Inv Sz %d <> %d",(int)stringDesc->bLength,nBytesReturned - sizeof(USB_DESCRIPTOR_REQUEST));
        return NULL;
    }

    if (stringDesc->bLength % 2 != 0)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetStrDesc, Odd Sz %d",(int)stringDesc->bLength);
        return NULL;
    }

    //
    // Looks good, allocate some (zero filled) space for the string descriptor
    // node and copy the string descriptor to it.
    //

    stringDescNode = (PSTRING_DESCRIPTOR_NODE)malloc(sizeof(STRING_DESCRIPTOR_NODE)+stringDesc->bLength);

    if (stringDescNode == NULL)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetStrDesc, new DescNode null");
        return NULL;
    }

    memset(stringDescNode,0x00,sizeof(STRING_DESCRIPTOR_NODE)+stringDesc->bLength);

    stringDescNode->DescriptorIndex = DescriptorIndex;
    stringDescNode->LanguageID = LanguageID;

    memcpy(stringDescNode->StringDescriptor,stringDesc,stringDesc->bLength);

	if(LanguageID)
	{
		nBytes = WideCharToMultiByte(
					CP_ACP,     // CodePage
					0,          // CodePage
					stringDescNode->StringDescriptor->bString,
					(stringDescNode->StringDescriptor->bLength - 2) / 2,
					(char *)stringDescReqBuf,
					sizeof(USB_DESCRIPTOR_REQUEST) + MAXIMUM_USB_STRING_LENGTH,
					NULL,       // lpDefaultChar
					NULL);      // pUsedDefaultChar
		if (!nBytes)
        {
            char szLastError[1024] = {0};
            DWORD dwLastError = GetLastError();
            GetLastErrorMessage(dwLastError,szLastError,sizeof(szLastError));
            Log(LOG_DEBUG,__LINE__,"-- USB.GetStrDesc, WideCharToMultiByte failed %u, %s",dwLastError,szLastError);
        }
		else 
		{
			memset(stringDescNode->StringDescriptor->bString, 0x00, (stringDescNode->StringDescriptor->bLength - 2));
			memcpy(stringDescNode->StringDescriptor->bString, stringDescReqBuf, nBytes);
		}
	}
    Log(LOG_DEBUG,__LINE__,"<< USB.GetStrDesc, DescNode 0x%p",stringDescNode);
    return stringDescNode;
}

BOOL USB::AreThereStringDescriptors(PUSB_DEVICE_DESCRIPTOR DeviceDesc, PUSB_CONFIGURATION_DESCRIPTOR ConfigDesc)
{
    PUCHAR descEnd = NULL;
//    PUSB_COMMON_DESCRIPTOR commonDesc = NULL;
    PUCHAR commonDesc = NULL;

    Log(LOG_DEBUG,__LINE__,">> USB.AreThrStrDesc");

    //
    // Check Device Descriptor strings
    //
    if (DeviceDesc->iManufacturer || DeviceDesc->iProduct || DeviceDesc->iSerialNumber)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.AreThrStrDesc, Manufact %d, Prod %d, SN %d",(int)DeviceDesc->iManufacturer,(int)DeviceDesc->iProduct,(int)DeviceDesc->iSerialNumber);
        return TRUE;
    }

    //
    // Check the Configuration and Interface Descriptor strings
    //
    descEnd = (PUCHAR)ConfigDesc + ConfigDesc->wTotalLength;

//    (USB_COMMON_DESCRIPTOR far *)commonDesc = (PUSB_COMMON_DESCRIPTOR)ConfigDesc;
    commonDesc = (PUCHAR)ConfigDesc;

    while ((PUCHAR)commonDesc + sizeof(USB_COMMON_DESCRIPTOR) < descEnd &&
           (PUCHAR)commonDesc + ((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength <= descEnd)
    {
        switch (((PUSB_COMMON_DESCRIPTOR)commonDesc)->bDescriptorType)
        {
            case USB_CONFIGURATION_DESCRIPTOR_TYPE:
                if (((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength != sizeof(USB_CONFIGURATION_DESCRIPTOR))
                {
                    break;
                }
                if (((PUSB_CONFIGURATION_DESCRIPTOR)commonDesc)->iConfiguration)
                {
                    Log(LOG_DEBUG,__LINE__,"<< USB.AreThrStrDesc, Cfg %d",(int)((PUSB_CONFIGURATION_DESCRIPTOR)commonDesc)->iConfiguration);
                    return TRUE;
                }
                (PUCHAR)commonDesc += ((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength;
                continue;

            case USB_INTERFACE_DESCRIPTOR_TYPE:
//                if (commonDesc->bLength != sizeof(USB_INTERFACE_DESCRIPTOR) &&
//                    commonDesc->bLength != sizeof(USB_INTERFACE_DESCRIPTOR2))
                if (((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength != sizeof(USB_INTERFACE_DESCRIPTOR))
                {
                    break;
                }
                if (((PUSB_INTERFACE_DESCRIPTOR)commonDesc)->iInterface)
                {
                    Log(LOG_DEBUG,__LINE__,"<< USB.AreThrStrDesc, Interface %d",(int)((PUSB_INTERFACE_DESCRIPTOR)commonDesc)->iInterface);
                    return TRUE;
                }
                (PUCHAR)commonDesc += ((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength;
                continue;

            default:
                (PUCHAR)commonDesc += ((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength;
                continue;
        }
        break;
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.AreThrStrDesc, Ret False");
    return FALSE;
}

PSTRING_DESCRIPTOR_NODE USB::GetAllStringDescriptors(HANDLE hHubDevice, ULONG ConnectionIndex, PUSB_DEVICE_DESCRIPTOR DeviceDesc, PUSB_CONFIGURATION_DESCRIPTOR ConfigDesc)
{
    PSTRING_DESCRIPTOR_NODE supportedLanguagesString = NULL;
    PSTRING_DESCRIPTOR_NODE stringDescNodeTail = NULL;
    ULONG                   numLanguageIDs = 0;
    USHORT                  *languageIDs = NULL;

    PUCHAR                  descEnd = NULL;
//    PUSB_COMMON_DESCRIPTOR  commonDesc = NULL;
    PUCHAR  commonDesc = NULL;

    Log(LOG_DEBUG,__LINE__,">> USB.GetAllStrDescs");

    //
    // Get the array of supported Language IDs, which is returned
    // in String Descriptor 0
    //
    supportedLanguagesString = GetStringDescriptor(hHubDevice,ConnectionIndex,0,0);
    if (supportedLanguagesString == NULL)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetAllStrDescs, SuppLangsStr null");
        return NULL;
    }

    numLanguageIDs = (supportedLanguagesString->StringDescriptor->bLength - 2) / 2;

    languageIDs = (USHORT*)&supportedLanguagesString->StringDescriptor->bString[0];

    stringDescNodeTail = supportedLanguagesString;

    //
    // Get the Device Descriptor strings
    //
    if (DeviceDesc->iManufacturer)
    {
        stringDescNodeTail = GetStringDescriptors(hHubDevice,
                                                  ConnectionIndex,
                                                  DeviceDesc->iManufacturer,
                                                  numLanguageIDs,
                                                  languageIDs,
                                                  stringDescNodeTail);
    }

    if (DeviceDesc->iProduct)
    {
        stringDescNodeTail = GetStringDescriptors(hHubDevice,
                                                  ConnectionIndex,
                                                  DeviceDesc->iProduct,
                                                  numLanguageIDs,
                                                  languageIDs,
                                                  stringDescNodeTail);
    }

    if (DeviceDesc->iSerialNumber)
    {
        stringDescNodeTail = GetStringDescriptors(hHubDevice,
                                                  ConnectionIndex,
                                                  DeviceDesc->iSerialNumber,
                                                  numLanguageIDs,
                                                  languageIDs,
                                                  stringDescNodeTail);
    }


    //
    // Get the Configuration and Interface Descriptor strings
    //
    descEnd = (PUCHAR)ConfigDesc + ConfigDesc->wTotalLength;
//    commonDesc = (PUSB_COMMON_DESCRIPTOR)ConfigDesc;
    commonDesc = (PUCHAR)ConfigDesc;

    while ((DWORD)((PUCHAR)commonDesc + sizeof(USB_COMMON_DESCRIPTOR)) < (DWORD)descEnd &&
           (DWORD)((PUCHAR)commonDesc + ((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength) <= (DWORD)descEnd)
    {
        switch (((PUSB_COMMON_DESCRIPTOR)commonDesc)->bDescriptorType)
        {
            case USB_CONFIGURATION_DESCRIPTOR_TYPE:
                if (((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength != sizeof(USB_CONFIGURATION_DESCRIPTOR))
                {
                    break;
                }
                if (((PUSB_CONFIGURATION_DESCRIPTOR)commonDesc)->iConfiguration)
                {
                    stringDescNodeTail = GetStringDescriptors(
                                             hHubDevice,
                                             ConnectionIndex,
                                             ((PUSB_CONFIGURATION_DESCRIPTOR)commonDesc)->iConfiguration,
                                             numLanguageIDs,
                                             languageIDs,
                                             stringDescNodeTail);
                }
                (PUCHAR)commonDesc += ((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength;
                continue;

            case USB_INTERFACE_DESCRIPTOR_TYPE:
//                if (commonDesc->bLength != sizeof(USB_INTERFACE_DESCRIPTOR) &&
//                    commonDesc->bLength != sizeof(USB_INTERFACE_DESCRIPTOR2))
                if (((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength != sizeof(USB_INTERFACE_DESCRIPTOR))
                {
                    break;
                }
                if (((PUSB_INTERFACE_DESCRIPTOR)commonDesc)->iInterface)
                {
                    stringDescNodeTail = GetStringDescriptors(
                                             hHubDevice,
                                             ConnectionIndex,
                                             ((PUSB_INTERFACE_DESCRIPTOR)commonDesc)->iInterface,
                                             numLanguageIDs,
                                             languageIDs,
                                             stringDescNodeTail);
                }
                (PUCHAR)commonDesc += ((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength;
                continue;

            default:
                (PUCHAR)commonDesc += ((PUSB_COMMON_DESCRIPTOR)commonDesc)->bLength;
                continue;
        }
        break;
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.GetAllStrDescs, SuppLangsStr 0x%p",supportedLanguagesString);
    return supportedLanguagesString;
}

PCHAR USB::GetDriverKeyName(HANDLE Hub, ULONG ConnectionIndex)
{
    BOOL                                success;
    ULONG                               nBytes = 0;
    USB_NODE_CONNECTION_DRIVERKEY_NAME  driverKeyName;
    PUSB_NODE_CONNECTION_DRIVERKEY_NAME driverKeyNameW = NULL;
    PCHAR                               driverKeyNameA = NULL;

    Log(LOG_DEBUG,__LINE__,">> USB.GetDrvKeyName");

    // Get the length of the name of the driver key of the device attached to
    // the specified port.
    //
	memset (&driverKeyName, 0, sizeof(driverKeyName));
    driverKeyName.ConnectionIndex = ConnectionIndex;

    success = DeviceIoControl(Hub,
                              IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME,
                              &driverKeyName,
                              sizeof(driverKeyName),
                              &driverKeyName,
                              sizeof(driverKeyName),
                              &nBytes,
                              NULL);

    if (success)
    {
		// Allocate space to hold the driver key name
		//
		nBytes = driverKeyName.ActualLength;

		if (nBytes > sizeof(driverKeyName))
		{
			driverKeyNameW = (struct _USB_NODE_CONNECTION_DRIVERKEY_NAME *)malloc(nBytes);
            if(driverKeyNameW)
            {
                memset(driverKeyNameW,0x00,nBytes);

			    // Get the name of the driver key of the device attached to
			    // the specified port.
			    //
			    driverKeyNameW->ConnectionIndex = ConnectionIndex;

			    success = DeviceIoControl(Hub,
									      IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME,
									      driverKeyNameW,
									      nBytes,
									      driverKeyNameW,
									      nBytes,
									      &nBytes,
									      NULL);

			    if (success)
			    {
				    // Convert the driver key name
				    //
				    driverKeyNameA = WideStrToMultiStr(driverKeyNameW->DriverKeyName);
			    }
			    free(driverKeyNameW);
            }
            else
            {
                Log(LOG_DEBUG,__LINE__,"-- USB.GetDriverKeyName, new KeyNameW (%u) null",nBytes);
            }
		}
	}
    Log(LOG_DEBUG,__LINE__,"<< USB.GetDrvKeyName, AName %s",driverKeyNameA);
	return driverKeyNameA;
}

PCHAR USB::GetExternalHubName(HANDLE Hub, ULONG ConnectionIndex)
{
    BOOL                        success;
    ULONG                       nBytes = 0;
    USB_NODE_CONNECTION_NAME    extHubName;
    PUSB_NODE_CONNECTION_NAME   extHubNameW = NULL;
    PCHAR                       extHubNameA = NULL;

    Log(LOG_DEBUG,__LINE__,">> USB.GetExternHub");

    // Get the length of the name of the external hub attached to the
    // specified port.
    //
	memset (&extHubName, 0, sizeof(extHubName));
    extHubName.ConnectionIndex = ConnectionIndex;

    success = DeviceIoControl(Hub,
                              IOCTL_USB_GET_NODE_CONNECTION_NAME,
                              &extHubName,
                              sizeof(extHubName),
                              &extHubName,
                              sizeof(extHubName),
                              &nBytes,
                              NULL);

    if (success)
    {
		// Allocate space to hold the external hub name
		//
		nBytes = extHubName.ActualLength;

		if (nBytes > sizeof(extHubName))
		{
			extHubNameW = (struct _USB_NODE_CONNECTION_NAME *)malloc(nBytes);
            if(extHubNameW)
            {
                memset(extHubNameW,0x00,nBytes);

			    // Get the name of the external hub attached to the specified port
			    //
			    extHubNameW->ConnectionIndex = ConnectionIndex;

			    success = DeviceIoControl(Hub,
									      IOCTL_USB_GET_NODE_CONNECTION_NAME,
									      extHubNameW,
									      nBytes,
									      extHubNameW,
									      nBytes,
									      &nBytes,
									      NULL);

			    if (success)
			    {
				    // Convert the External Hub name
				    //
				    extHubNameA = WideStrToMultiStr(extHubNameW->NodeName);
			    }
			    free(extHubNameW);
            }
            else
            {
                Log(LOG_DEBUG,__LINE__,"-- USB.GetExtHubName, new extHubNameW (%u) null",nBytes);
            }
		}
	}
    Log(LOG_DEBUG,__LINE__,"<< USB.GetExternHub, HubName %s",extHubNameA);
	return extHubNameA;
}

VOID USB::EnumerateHubPorts(HANDLE hHubDevice, ULONG NumPorts)
{
    ULONG       index = 0;
    BOOL        success;

    PUSB_NODE_CONNECTION_INFORMATION_EX connectionInfo = NULL;
    PUSB_DESCRIPTOR_REQUEST             configDesc = NULL;
    PSTRING_DESCRIPTOR_NODE             stringDescs = NULL;
	PSTRING_DESCRIPTOR_NODE				Next = NULL;
    PUSBDEVICEINFO                      info = NULL;

    PCHAR driverKeyName = NULL;
    PCHAR deviceDesc = NULL;
    CHAR  leafName[512] = {0};
    char deviceSpeed[5] = {0};
    char deviceInfo[1000] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.EnumHubPorts");

	NestedLevel++;
    // Loop over all ports of the hub.
    //
    // Port indices are 1 based, not 0 based.
    //
   
	// for (index=1; index <= NumPorts; index++)
	for (index=1; index <= NumPorts; index++)
    {
        ULONG nBytes = 0;

        // Allocate space to hold the connection info for this port.
        // For now, allocate it big enough to hold info for 30 pipes.
        //
        // Endpoint numbers are 0-15.  Endpoint number 0 is the standard
        // control endpoint which is not explicitly listed in the Configuration
        // Descriptor.  There can be an IN endpoint and an OUT endpoint at
        // endpoint numbers 1-15 so there can be a maximum of 30 endpoints
        // per device configuration.
        //
        // Should probably size this dynamically at some point.
        //
        nBytes = sizeof(USB_NODE_CONNECTION_INFORMATION_EX) +
                 sizeof(USB_PIPE_INFO) * 30;

        connectionInfo = (PUSB_NODE_CONNECTION_INFORMATION_EX)malloc(nBytes);
        if(connectionInfo)
        {
            memset(connectionInfo,0x00,nBytes);

            //
            // Now query USBHUB for the USB_NODE_CONNECTION_INFORMATION_EX structure
            // for this port.  This will tell us if a device is attached to this
            // port, among other things.
            //
            connectionInfo->ConnectionIndex = index;

            success = DeviceIoControl(hHubDevice,
                                      IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
                                      connectionInfo,
                                      nBytes,
                                      connectionInfo,
                                      nBytes,
                                      &nBytes,
                                      NULL);

            if (!success)
            {
                free(connectionInfo);
                continue;
            }
        }
        else
        {
            Log(LOG_DEBUG,__LINE__,"-- USB.EnumHubPorts, new Port %d ConnInfo (%u) null",index,nBytes);
            continue;
        }

        // Update the count of connected devices
        //
        if (connectionInfo->ConnectionStatus == DeviceConnected)
        {
            ulTotalDevicesConnected++;
        }

        // If there is a device connected, get the Device Description
        //
        deviceDesc = NULL;
        if (connectionInfo->ConnectionStatus != NoDeviceConnected)
        {
            driverKeyName = GetDriverKeyName(hHubDevice,
                                             index);

            if (driverKeyName)
            {
                deviceDesc = DriverNameToDeviceDesc(driverKeyName);
                free(driverKeyName);
            }
        }

        // If there is a device connected to the port, try to retrieve the
        // Configuration Descriptor from the device.
        //
        if (connectionInfo->ConnectionStatus == DeviceConnected)
        {
            configDesc = GetConfigDescriptor(hHubDevice,index,0);
        }
        else
        {
            configDesc = NULL;
        }

        if (configDesc != NULL &&
            AreThereStringDescriptors(&connectionInfo->DeviceDescriptor,
                                      (PUSB_CONFIGURATION_DESCRIPTOR)(configDesc+1)))
        {
            stringDescs = GetAllStringDescriptors(hHubDevice,index,
                                  &connectionInfo->DeviceDescriptor,
                                  (PUSB_CONFIGURATION_DESCRIPTOR)(configDesc+1));
        }
        else
        {
            stringDescs = NULL;
        }

        // If the device connected to the port is an external hub, get the
        // name of the external hub and recursively enumerate it.
        //
        if (connectionInfo->DeviceIsHub)
        {
            PCHAR extHubName = GetExternalHubName(hHubDevice,index);
            if (extHubName != NULL)
            {
		        wsprintf(leafName, "%s[Port%d] ", UsbViewIndent[NestedLevel],index);
		        strcat(leafName, ConnectionStatuses[connectionInfo->ConnectionStatus]);
				if (deviceDesc)
				{
					strcat(leafName, " : ");
					strcat(leafName, deviceDesc);
				}
				USBTraceInfo(leafName,extHubName);

                EnumerateHub(extHubName,
                             connectionInfo,
                             configDesc,
                             stringDescs,
                             deviceDesc);

			    if (configDesc != NULL)
				    free(configDesc);

			    if (connectionInfo != NULL)
				    free(connectionInfo);

			    while (stringDescs != NULL)
			    {
				    Next = stringDescs->Next;
				    free(stringDescs);
				    stringDescs = Next;
			    }

                // On to the next port
                //
                continue;
            }
        }

        // Allocate some space for a USBDEVICEINFO structure to hold the
        // hub info, hub name, and connection info pointers.  GPTR zero
        // initializes the structure for us.
        //
        info = (PUSBDEVICEINFO) malloc(sizeof(USBDEVICEINFO));
        if(info)
        {
            memset(info,0x00,sizeof(USBDEVICEINFO));

            info->ConnectionInfo = connectionInfo;
            info->ConfigDesc = configDesc;
            info->StringDescs = stringDescs;

            wsprintf(leafName, "[Port%d] ", index);
            strcat(leafName, ConnectionStatuses[connectionInfo->ConnectionStatus]);
            if (deviceDesc)
            {
                strcat(leafName, " : ");
            }

            memset(deviceInfo,0x00,sizeof(deviceInfo));
		    if (info->ConnectionInfo->ConnectionStatus == DeviceConnected)
		    {
			    PSTRING_DESCRIPTOR_NODE pDescNode = NULL;

			    //get speed of device - Low/Full/High
			    memset(deviceSpeed,0x0,5);
			    strcpy(deviceSpeed, "???");

			    if(info->ConnectionInfo->Speed == UsbHighSpeed)
			    {
				    strcpy(deviceSpeed,"HIGH");
			    }
			    else if(info->ConnectionInfo->Speed == UsbLowSpeed)
			    {
				    strcpy(deviceSpeed, "LOW");
			    }
			    else if(info->ConnectionInfo->Speed == UsbFullSpeed)
			    {
				    strcpy(deviceSpeed, "FULL");
			    }
    			
			    if(info->ConnectionInfo->DeviceDescriptor.iSerialNumber)
			    {
				    pDescNode = info->StringDescs;
				    while (pDescNode)
				    {
					    if (pDescNode->DescriptorIndex == info->ConnectionInfo->DeviceDescriptor.iSerialNumber)
						    break;
					    pDescNode = pDescNode->Next;
				    }
				    // Modified to fix the SCR 3176
				    if (pDescNode)
                        _snprintf(deviceInfo,sizeof(deviceInfo)-1,"%s [VID:%.4X PID:%.4X SN:%s Spd: %s]",deviceDesc,
                                        info->ConnectionInfo->DeviceDescriptor.idVendor,
                                        info->ConnectionInfo->DeviceDescriptor.idProduct,
                                        (const char *)pDescNode->StringDescriptor->bString,deviceSpeed);
				    else
                        _snprintf(deviceInfo,sizeof(deviceInfo)-1,"%s [VID:%.4X PID:%.4X SN:%s Spd: %s]",deviceDesc,
                                        info->ConnectionInfo->DeviceDescriptor.idVendor,
                                        info->ConnectionInfo->DeviceDescriptor.idProduct,
                                        "Not Initialized",deviceSpeed);
			    }
			    else
				    _snprintf(deviceInfo,sizeof(deviceInfo)-1,"%s [VID:%.4X PID:%.4X SN:%s Spd: %s]",deviceDesc,
								    info->ConnectionInfo->DeviceDescriptor.idVendor,
								    info->ConnectionInfo->DeviceDescriptor.idProduct,
								    "Not Found",deviceSpeed);
    			
		        Log(LOG_MESSAGE,__LINE__,"%s%s%s",UsbViewIndent[NestedLevel],leafName,deviceInfo);

                PushBackDetails(deviceInfo);
                if(info->ConnectionInfo)
                    ConnectionInfo(info->ConnectionInfo,info->StringDescs);
                if(info->ConfigDesc)
                    ConfigDesc((PUSB_CONFIGURATION_DESCRIPTOR)(info->ConfigDesc + 1),info->StringDescs);
		    }
    		else
		    {
			    Log(LOG_MESSAGE,__LINE__,"%s%s",UsbViewIndent[NestedLevel],leafName);
		    }
            free(info);
            info = NULL;
        }   //END: if(info)

	    if (configDesc != NULL)
		    free(configDesc);

	    if (connectionInfo != NULL)
		    free(connectionInfo);

        while (stringDescs != NULL)
	    {
		    Next = stringDescs->Next;
		    free(stringDescs);
		    stringDescs = Next;
	    }
    }

	if(NestedLevel)			// only for prevent bugs
		NestedLevel--;

    Log(LOG_DEBUG,__LINE__,"<< USB.EnumHubPorts");
}

PCHAR USB::DriverNameToDeviceDesc(PCHAR DriverName)
{
    DEVINST     devInst = 0;
    DEVINST     devInstNext = 0;
    CONFIGRET   cr = 0;
    ULONG       walkDone = 0;
    ULONG       len = 0;

    Log(LOG_DEBUG,__LINE__,">> USB.DrvName2DevDesc, Drv %s",DriverName);

    // Get Root DevNode
    //
    cr = (*lpfnCM_Locate_DevNodeA)(&devInst,NULL,0);
    if (cr != CR_SUCCESS)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.DrvName2DevDesc, LocateDevNote %u",cr);
        return NULL;
    }

    // Do a depth first search for the DevNode with a matching
    // DriverName value
    //
    while (!walkDone)
    {
        // Get the DriverName value
        //
        len = sizeof(buf);
        cr = (*lpfnCM_Get_DevNode_Registry_PropertyA)(devInst,
                                              CM_DRP_DRIVER,
                                              NULL,
                                              buf,
                                              &len,
                                              0);

        // If the DriverName value matches, return the DeviceDescription
        //
        if (cr == CR_SUCCESS && strcmp(DriverName, buf) == 0)
        {
            len = sizeof(buf);
            cr = (*lpfnCM_Get_DevNode_Registry_PropertyA)(devInst,
                                                  CM_DRP_DEVICEDESC,
                                                  NULL,
                                                  buf,
                                                  &len,
                                                  0);

            if (cr == CR_SUCCESS)
            {
                Log(LOG_DEBUG,__LINE__,"<< USB.DrvName2DevDesc, ret %s",buf);
                return buf;
            }
            else
            {
                Log(LOG_DEBUG,__LINE__,"<< USB.DrvName2DevDesc, GetDevNodeRegProps %u",cr);
                return NULL;
            }
        }

        // This DevNode didn't match, go down a level to the first child.
        //
        cr = (*lpfnCM_Get_Child)(&devInstNext,devInst,0);
        if (cr == CR_SUCCESS)
        {
            devInst = devInstNext;
            continue;
        }

        // Can't go down any further, go across to the next sibling.  If
        // there are no more siblings, go back up until there is a sibling.
        // If we can't go up any further, we're back at the root and we're
        // done.
        //
        for (;;)
        {
            cr = (*lpfnCM_Get_Sibling)(&devInstNext,devInst,0);
            if (cr == CR_SUCCESS)
            {
                devInst = devInstNext;
                break;
            }

            cr = (*lpfnCM_Get_Parent)(&devInstNext,devInst,0);
            if (cr == CR_SUCCESS)
            {
                devInst = devInstNext;
            }
            else
            {
                walkDone = 1;
                break;
            }
        }
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.DrvName2DevDesc, Ret Null");
    return NULL;
}

VOID USB::EnumerateHub(PCHAR HubName, PUSB_NODE_CONNECTION_INFORMATION_EX ConnectionInfo, PUSB_DESCRIPTOR_REQUEST ConfigDesc, PSTRING_DESCRIPTOR_NODE StringDescs, PCHAR DeviceDesc)
{
    HANDLE          hHubDevice = NULL;
    PCHAR           deviceName = NULL;
    BOOL            success;
    ULONG           nBytes = 0;
    PUSBDEVICEINFO  info = NULL;
    CHAR            leafName[512] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.EnumHub");

    // Allocate some space for a USBDEVICEINFO structure to hold the
    // hub info, hub name, and connection info pointers.  GPTR zero
    // initializes the structure for us.
    //
    info = (PUSBDEVICEINFO) malloc(sizeof(USBDEVICEINFO));
    if(info)
    {
        memset(info,0x00,sizeof(USBDEVICEINFO));

        // Keep copies of the Hub Name, Connection Info, and Configuration
        // Descriptor pointers
        //
        info->HubName = HubName;
        info->ConnectionInfo = ConnectionInfo;
        info->ConfigDesc = ConfigDesc;
        info->StringDescs = StringDescs;

        // Allocate some space for a USB_NODE_INFORMATION structure for this Hub,
        //
        info->HubInfo = (PUSB_NODE_INFORMATION)malloc(sizeof(USB_NODE_INFORMATION));
        if(info->HubInfo)
        {
            memset(info->HubInfo,0x00,sizeof(USB_NODE_INFORMATION));

            // Allocate a temp buffer for the full hub device name.
            //
            deviceName = (PCHAR)malloc(strlen(HubName) + sizeof("\\\\.\\"));
            if(deviceName)
            {
                memset(deviceName,0x00,strlen(HubName) + sizeof("\\\\.\\"));

                // Create the full hub device name
                //
                strcpy(deviceName, "\\\\.\\");
                strcpy(deviceName + sizeof("\\\\.\\") - 1, HubName);

                // Try to hub the open device
                //
                hHubDevice = CreateFile(deviceName,
                                        GENERIC_WRITE,
                                        FILE_SHARE_WRITE,
                                        NULL,
                                        OPEN_EXISTING,
                                        0,
                                        NULL);

                // Done with temp buffer for full hub device name
                //
                free(deviceName);
            }
            else
            {
                Log(LOG_DEBUG,__LINE__,"-- USB.EnumHub, new Pntr for DevName \\\\.\\%s null",HubName);
                hHubDevice = INVALID_HANDLE_VALUE;
            }

            if (hHubDevice != INVALID_HANDLE_VALUE)
            {
	            //
		        // Now query USBHUB for the USB_NODE_INFORMATION structure for this hub.
	            // This will tell us the number of downstream ports to enumerate, among
		        // other things.
	            //
		        success = DeviceIoControl(hHubDevice,
			                              IOCTL_USB_GET_NODE_INFORMATION,
				                          info->HubInfo,
					                      sizeof(USB_NODE_INFORMATION),
						                  info->HubInfo,
							              sizeof(USB_NODE_INFORMATION),
								          &nBytes,
	                                      NULL);

		        if (success)
		        {
	            // Build the leaf name from the port number and the device description
		        //
		            leafName[0] = 0;
			        if (ConnectionInfo)
			        {
				        wsprintf(leafName, "[Port%d] ", ConnectionInfo->ConnectionIndex);
		                strcat(leafName, ConnectionStatuses[ConnectionInfo->ConnectionStatus]);
			            strcat(leafName, " :  ");
			        }

		            if (DeviceDesc != NULL)
				        strcat(leafName, DeviceDesc);
			        else
				        strcat(leafName, info->HubName);

		            // Now recursively enumerate the ports of this hub.
			        //
                    PushBackDetails(info->HubName);
                    HubInfo(&info->HubInfo->u.HubInformation);
		            EnumerateHubPorts (hHubDevice,
						           info->HubInfo->u.HubInformation.HubDescriptor.bNumberOfPorts);

			        wPortsNumber += info->HubInfo->u.HubInformation.HubDescriptor.bNumberOfPorts;
		        }
		        CloseHandle(hHubDevice);
	        }
            //
            // Clean up any stuff that got allocated
            //
	        free(HubName);

	        if (info->HubInfo != NULL)
		        free(info->HubInfo);
        }
        else
        {
            Log(LOG_DEBUG,__LINE__,"-- USB.EnumHub, new HubInfo (%u) null",sizeof(USB_NODE_INFORMATION));
        }
	    free(info);
    }
    else
    {
        Log(LOG_DEBUG,__LINE__,"-- USB.EnumHub, new Info (%u) null",sizeof(USBDEVICEINFO));
    }
    Log(LOG_DEBUG,__LINE__,"<< USB.EnumHub");
    return;
}

PCHAR USB::GetRootHubName(HANDLE HostController)
{
    BOOL                success;
    ULONG               nBytes = 0;
    USB_ROOT_HUB_NAME   rootHubName;
    PUSB_ROOT_HUB_NAME  rootHubNameW = NULL;
    PCHAR               rootHubNameA = NULL;

    Log(LOG_DEBUG,__LINE__,">> USB.GetRootHub");

    memset(&rootHubName,0x00,sizeof(rootHubName));

    // Get the length of the name of the Root Hub attached to the
    // Host Controller
    //
    success = DeviceIoControl(HostController,
                              IOCTL_USB_GET_ROOT_HUB_NAME,
                              0,
                              0,
                              &rootHubName,
                              sizeof(rootHubName),
                              &nBytes,
                              NULL);
    if (success)
    {
		// Allocate space to hold the Root Hub name
		//
		nBytes = rootHubName.ActualLength;

		rootHubNameW = (struct _USB_ROOT_HUB_NAME *)malloc(nBytes);
        if(rootHubNameW)
        {
            memset(rootHubNameW,0x00,nBytes);

		    // Get the name of the Root Hub attached to the Host Controller
		    //
		    success = DeviceIoControl(HostController,
								      IOCTL_USB_GET_ROOT_HUB_NAME,
								      NULL,
								      0,
								      rootHubNameW,
								      nBytes,
								      &nBytes,
								      NULL);

		    if (success)
		    {
			    // Convert the Root Hub name
			    //
			    rootHubNameA = WideStrToMultiStr(rootHubNameW->RootHubName);
		    }
		    free(rootHubNameW);
        }
	}
    Log(LOG_DEBUG,__LINE__,"<< USB.GetRootHub, HubName %s",rootHubNameA);
	return rootHubNameA;
}

PCHAR USB::GetHCDDriverKeyName(HANDLE HCD)
{
    BOOL                    success;
    ULONG                   nBytes = 0;
    USB_HCD_DRIVERKEY_NAME  driverKeyName;
    PUSB_HCD_DRIVERKEY_NAME driverKeyNameW = NULL;
    PCHAR                   driverKeyNameA = NULL;

    Log(LOG_DEBUG,__LINE__,">> USB.GetHCDDrvKeyName");

    // Get the length of the name of the driver key of the HCD
    //
	memset (&driverKeyName, 0, sizeof(driverKeyName));
    success = DeviceIoControl(HCD,
                              IOCTL_GET_HCD_DRIVERKEY_NAME,
                              &driverKeyName,
                              sizeof(driverKeyName),
                              &driverKeyName,
                              sizeof(driverKeyName),
                              &nBytes,
                              NULL);
    if (success)
    {

		// Allocate space to hold the driver key name
		//
		nBytes = driverKeyName.ActualLength;

		if (nBytes > sizeof(driverKeyName))
		{
			driverKeyNameW = (struct _USB_HCD_DRIVERKEY_NAME *)malloc(nBytes);
            if(driverKeyNameW)
            {
                memset(driverKeyNameW,0x00,nBytes);

			    // Get the name of the driver key of the device attached to
			    // the specified port.
			    //
			    success = DeviceIoControl(HCD,
									      IOCTL_GET_HCD_DRIVERKEY_NAME,
									      driverKeyNameW,
									      nBytes,
									      driverKeyNameW,
									      nBytes,
									      &nBytes,
									      NULL);

			    if (success)
			    {
				    // Convert the driver key name
				    //
				    driverKeyNameA = WideStrToMultiStr(driverKeyNameW->DriverKeyName);
			    }
			    free(driverKeyNameW);
		    }
        }
	}
    Log(LOG_DEBUG,__LINE__,"<< USB.GetHCDDrvKeyName, DrvKeyName %s",driverKeyNameA);
	return driverKeyNameA;
}

PSTRING_DESCRIPTOR_NODE USB::GetStringDescriptors(HANDLE hHubDevice, ULONG ConnectionIndex, UCHAR DescriptorIndex, ULONG NumLanguageIDs, USHORT *LanguageIDs, PSTRING_DESCRIPTOR_NODE StringDescNodeTail)
{
    ULONG i;

    Log(LOG_DEBUG,__LINE__,">> USB.GetStrDescs");

    for (i=0; i<NumLanguageIDs; i++)
    {
        StringDescNodeTail->Next = GetStringDescriptor(hHubDevice,
                                                       ConnectionIndex,
                                                       DescriptorIndex,
                                                       *LanguageIDs);

        if (StringDescNodeTail->Next)
        {
            StringDescNodeTail = StringDescNodeTail->Next;
        }

        LanguageIDs++;
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.GetStrDescs, StrDescNodeTail 0x%p",StringDescNodeTail);
    return StringDescNodeTail;
}

PUSB_DESCRIPTOR_REQUEST USB::GetConfigDescriptor(HANDLE hHubDevice, ULONG ConnectionIndex, UCHAR DescriptorIndex)
{
    BOOL    success;
    ULONG   nBytes = 0;
    ULONG   nBytesReturned = 0;

    UCHAR   configDescReqBuf[sizeof(USB_DESCRIPTOR_REQUEST) + sizeof(USB_CONFIGURATION_DESCRIPTOR)];

    PUSB_DESCRIPTOR_REQUEST         configDescReq = NULL;
    PUSB_CONFIGURATION_DESCRIPTOR   configDesc = NULL;

    Log(LOG_DEBUG,__LINE__,">> USB.GetCfgDesc");

    // Request the Configuration Descriptor the first time using our
    // local buffer, which is just big enough for the Cofiguration
    // Descriptor itself.
    //
    nBytes = sizeof(configDescReqBuf);

    configDescReq = (PUSB_DESCRIPTOR_REQUEST)configDescReqBuf;
    configDesc = (PUSB_CONFIGURATION_DESCRIPTOR)(configDescReq+1);

    // Zero fill the entire request structure
    //
    memset(configDescReq, 0x00, nBytes);

    // Indicate the port from which the descriptor will be requested
    //
    configDescReq->ConnectionIndex = ConnectionIndex;

    //
    // USBHUB uses URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE to process this
    // IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION request.
    //
    // USBD will automatically initialize these fields:
    //     bmRequest = 0x80
    //     bRequest  = 0x06
    //
    // We must inititialize these fields:
    //     wValue    = Descriptor Type (high) and Descriptor Index (low byte)
    //     wIndex    = Zero (or Language ID for String Descriptors)
    //     wLength   = Length of descriptor buffer
    //
    configDescReq->SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8)
                                        | DescriptorIndex;

    configDescReq->SetupPacket.wLength = (USHORT)(nBytes - sizeof(USB_DESCRIPTOR_REQUEST));

    // Now issue the get descriptor request.
    //
    success = DeviceIoControl(hHubDevice,
                              IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
                              configDescReq,
                              nBytes,
                              configDescReq,
                              nBytes,
                              &nBytesReturned,
                              NULL);
    if (!success)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetCfgDesc, DeviceIoControl False");
        return NULL;
    }

    if (nBytes != nBytesReturned)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetCfgDesc, Bytes %u <> BytesRet %u",nBytes,nBytesReturned);
        return NULL;
    }

    if (configDesc->wTotalLength < sizeof(USB_CONFIGURATION_DESCRIPTOR))
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.GetCfgDesc, Total %d < Sz struct %d",configDesc->wTotalLength,sizeof(USB_CONFIGURATION_DESCRIPTOR));
        return NULL;
    }

    // Now request the entire Configuration Descriptor using a dynamically
    // allocated buffer which is sized big enough to hold the entire descriptor
    //
    nBytes = sizeof(USB_DESCRIPTOR_REQUEST) + configDesc->wTotalLength;

    configDescReq = (PUSB_DESCRIPTOR_REQUEST)malloc(nBytes);
    if(configDescReq)
    {
        memset(configDescReq,0x00,nBytes);

        configDesc = (PUSB_CONFIGURATION_DESCRIPTOR)(configDescReq+1);

        // Indicate the port from which the descriptor will be requested
        //
        configDescReq->ConnectionIndex = ConnectionIndex;

        //
        // USBHUB uses URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE to process this
        // IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION request.
        //
        // USBD will automatically initialize these fields:
        //     bmRequest = 0x80
        //     bRequest  = 0x06
        //
        // We must inititialize these fields:
        //     wValue    = Descriptor Type (high) and Descriptor Index (low byte)
        //     wIndex    = Zero (or Language ID for String Descriptors)
        //     wLength   = Length of descriptor buffer
        //
        configDescReq->SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8)
                                            | DescriptorIndex;

        configDescReq->SetupPacket.wLength = (USHORT)(nBytes - sizeof(USB_DESCRIPTOR_REQUEST));

        // Now issue the get descriptor request.
        //
        success = DeviceIoControl(hHubDevice,
                                  IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
                                  configDescReq,
                                  nBytes,
                                  configDescReq,
                                  nBytes,
                                  &nBytesReturned,
                                  NULL);
        if (!success)
        {
            Log(LOG_DEBUG,__LINE__,"<< USB.GetCfgDesc, Req DeviceIoControl False");
            free(configDescReq);
            return NULL;
        }

        if (nBytes != nBytesReturned)
        {
            Log(LOG_DEBUG,__LINE__,"<< USB.GetCfgDesc, Req Bytes %u <> BytesRet %u",nBytes,nBytesReturned);
            free(configDescReq);
            return NULL;
        }

        if (configDesc->wTotalLength != (nBytes - sizeof(USB_DESCRIPTOR_REQUEST)))
        {
            Log(LOG_DEBUG,__LINE__,"<< USB.GetCfgDesc, Req Total %d < Sz %d",configDesc->wTotalLength,(nBytes - sizeof(USB_DESCRIPTOR_REQUEST)));
            free(configDescReq);
            return NULL;
        }
    }
    else
    {
        Log(LOG_DEBUG,__LINE__,"-- USB.GetCfgDescriptor, new Buf (%u) null",nBytes);
    }
    Log(LOG_DEBUG,__LINE__,"<< USB.GetCfgDesc, 0x%p",configDescReq);
    return configDescReq;
}

/******************************************************************************
*
*  USB DEVICE DETAILS HELPER METHODS
*
******************************************************************************/
// HubInfo - Info about the hub.
VOID USB::HubInfo(PUSB_HUB_INFORMATION HubInfo)
{
    USHORT wHubChar = 0;
    char format[1024] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.HubInfo");

    _snprintf(format,sizeof(format)-1,"> Hub Power: %s",HubInfo->HubIsBusPowered ? "Bus Power" : "Self Power");
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,"> Number of Ports: %d",HubInfo->HubDescriptor.bNumberOfPorts);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    wHubChar = HubInfo->HubDescriptor.wHubCharacteristics;

    switch (wHubChar & 0x0003)
    {
        case 0x0000:
            PushBackDetails("> Power switching: Ganged");
            break;

        case 0x0001:
            PushBackDetails("> Power switching: Individual");
            break;

        case 0x0002:
        case 0x0003:
            PushBackDetails("> Power switching: None");
            break;
    }

    switch (wHubChar & 0x0004)
    {
        case 0x0000:
            PushBackDetails("> Compound device: No");
            break;

        case 0x0004:
            PushBackDetails("> Compound device: Yes");
            break;
    }

    switch (wHubChar & 0x0018)
    {
        case 0x0000:
            PushBackDetails("> Over-current Protection: Global");
            break;

        case 0x0008:
            PushBackDetails("> Over-current Protection: Individual");
            break;

        case 0x0010:
        case 0x0018:
            PushBackDetails("> No Over-current Protection (Bus Power Only)");
            break;
    }
    Log(LOG_DEBUG,__LINE__,"<< USB.HubInfo");
}

// HubCaps()
//
// HubCapsEx - Extended Capabilities
// HubCaps - Basic capabilities
VOID USB::HubCaps(PUSB_HUB_CAPABILITIES_EX HubCapsEx,PUSB_HUB_CAPABILITIES HubCaps)
{
    char format[1024] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.HubCaps");

    if (HubCapsEx) {
#if (_WIN32_WINNT >= 0x0600) 
        // Only available on Vista + 
        PUSB_HUB_CAP_FLAGS HubCapFlags = (PUSB_HUB_CAP_FLAGS) &(HubCapsEx->CapabilityFlags);

        _snprintf(format,sizeof(format)-1,"> Extended Hub Capability Flags: %0#8lx",HubCapFlags->ul);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   High speed Capable: %s",(HubCapFlags->HubIsHighSpeedCapable? "Yes":"No"));
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   High speed: %s",(HubCapFlags->HubIsHighSpeed?"Yes":"No"));
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   Mulit-transaction Capable: %s",(HubCapFlags->HubIsMultiTtCapable?"Yes":"No"));
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   Mulit-transaction: %s",(HubCapFlags->HubIsMultiTt?"On":"Off"));
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   Root hub: %s",(HubCapFlags->HubIsRoot?"Yes":"No"));
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   Armed for wake on connect: %s",(HubCapFlags->HubIsArmedWakeOnConnect?"Yes":"No"));
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   Reserved (26 bits): %0#6lx",HubCapFlags->ReservedMBZ);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));
        
        // Don't display un-extended caps if extended caps are available, they don't appear to be correct.
#endif
    } else {
        PushBackDetails("Extended Hub Capabilities UNAVAILABLE");
        // Pre-Vista this is all we've got
        if (HubCaps) {
            _snprintf(format,sizeof(format)-1,"> Hub Capabilities: %0#8lx (%s)",HubCaps->HubIs2xCapable,(HubCaps->HubIs2xCapable?"High speed":"Not high speed"));
            PushBackDetails(format);
        } else {
            PushBackDetails("Hub Capabilities UNAVAILABLE");
        }
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.HubCaps");
}

// ConnectionInfo()
// ConnectInfo - Info about the connection.
VOID USB::ConnectionInfo(PUSB_NODE_CONNECTION_INFORMATION_EX ConnectInfo,PSTRING_DESCRIPTOR_NODE StringDescs)
{
    char format[1024] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.ConnInfo");

    if(!ConnectInfo)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.ConnInfo, Input null");
        return;
    }

    if (ConnectInfo->ConnectionStatus == NoDeviceConnected)
    {
        PushBackDetails("> ConnectionStatus: NoDeviceConnected");
    }
    else
    {
        PushBackDetails("> Device Descriptor:");

        _snprintf(format,sizeof(format)-1,">   bcdUSB: 0x%04X",ConnectInfo->DeviceDescriptor.bcdUSB);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   bDeviceClass: 0x%02X",ConnectInfo->DeviceDescriptor.bDeviceClass);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   bDeviceSubClass: 0x%02X",ConnectInfo->DeviceDescriptor.bDeviceSubClass);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   bDeviceProtocol: 0x%02X",ConnectInfo->DeviceDescriptor.bDeviceProtocol);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   bMaxPacketSize0: 0x%02X (%d)",ConnectInfo->DeviceDescriptor.bMaxPacketSize0,
                                                                             ConnectInfo->DeviceDescriptor.bMaxPacketSize0);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   idVendor: 0x%04X (%s)",ConnectInfo->DeviceDescriptor.idVendor,
                                                      GetVendorString(ConnectInfo->DeviceDescriptor.idVendor));
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   idProduct: 0x%04X",ConnectInfo->DeviceDescriptor.idProduct);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   bcdDevice: 0x%04X",ConnectInfo->DeviceDescriptor.bcdDevice);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   iManufacturer: 0x%02X",ConnectInfo->DeviceDescriptor.iManufacturer);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        if (ConnectInfo->DeviceDescriptor.iManufacturer)
        {
            StringDescriptor(ConnectInfo->DeviceDescriptor.iManufacturer,StringDescs);
        }

        _snprintf(format,sizeof(format)-1,">   iProduct: 0x%02X",ConnectInfo->DeviceDescriptor.iProduct);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        if (ConnectInfo->DeviceDescriptor.iProduct)
        {
            StringDescriptor(ConnectInfo->DeviceDescriptor.iProduct,StringDescs);
        }

        _snprintf(format,sizeof(format)-1,">   iSerialNumber: 0x%02X",ConnectInfo->DeviceDescriptor.iSerialNumber);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        if (ConnectInfo->DeviceDescriptor.iSerialNumber)
        {
            StringDescriptor(ConnectInfo->DeviceDescriptor.iSerialNumber,StringDescs);
        }

        _snprintf(format,sizeof(format)-1,">   bNumConfigurations: 0x%02X",ConnectInfo->DeviceDescriptor.bNumConfigurations);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   ConnectionStatus: %s",ConnectionStatuses[ConnectInfo->ConnectionStatus]);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   Current Config Value: 0x%02X",ConnectInfo->CurrentConfigurationValue);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        switch	(ConnectInfo->Speed)
        {
            case UsbLowSpeed:
                PushBackDetails(">   Device Bus Speed: Low");
                break;
            case UsbFullSpeed:
                PushBackDetails(">   Device Bus Speed: Full");
                break;
            case UsbHighSpeed:
                PushBackDetails(">   Device Bus Speed: High");
                break;
            default:
                PushBackDetails(">   Device Bus Speed: Unknown");
        }

        _snprintf(format,sizeof(format)-1,">   Device Address: 0x%02X",ConnectInfo->DeviceAddress);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   Open Pipes: %02d",ConnectInfo->NumberOfOpenPipes);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        if (ConnectInfo->NumberOfOpenPipes)
        {
            PipeInfo(ConnectInfo->NumberOfOpenPipes,ConnectInfo->PipeList);
        }
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.ConnInfo");
}

// PipeInfo()
// NumPipes - Number of pipe for we info should be displayed.
// PipeInfo - Info about the pipes.
VOID USB::PipeInfo(ULONG NumPipes,USB_PIPE_INFO *PipeInfo)
{
    ULONG i;

    Log(LOG_DEBUG,__LINE__,">> USB.PipeInfo, %u",NumPipes);
    for (i=0; i<NumPipes; i++)
    {
        EndpointDescriptor(&PipeInfo[i].EndpointDescriptor);
    }
    Log(LOG_DEBUG,__LINE__,"<< USB.PipeInfo");
}

// ConfigDesc()
// ConfigDesc - The Configuration Descriptor, and associated Interface and
// EndpointDescriptors
VOID USB::ConfigDesc(PUSB_CONFIGURATION_DESCRIPTOR ConfigDesc,PSTRING_DESCRIPTOR_NODE StringDescs)
{
    PUCHAR                  descEnd = NULL;
    PUSB_COMMON_DESCRIPTOR  commonDesc = NULL;
    UCHAR                   bInterfaceClass;
    UCHAR                   bInterfaceSubClass;
    BOOL                    displayUnknown;

    Log(LOG_DEBUG,__LINE__,">> USB.ConnDesc");

    if(!ConfigDesc)
    {
        Log(LOG_DEBUG,__LINE__,"<< USB.ConnDesc, Input null");
        return;
    }

    bInterfaceClass = 0;

    descEnd = (PUCHAR)ConfigDesc + ConfigDesc->wTotalLength;

    commonDesc = (PUSB_COMMON_DESCRIPTOR)ConfigDesc;

    while ((PUCHAR)commonDesc + sizeof(USB_COMMON_DESCRIPTOR) < descEnd &&
           (PUCHAR)commonDesc + commonDesc->bLength <= descEnd)
    {
        displayUnknown = FALSE;

        switch (commonDesc->bDescriptorType)
        {
            case USB_CONFIGURATION_DESCRIPTOR_TYPE:
                if (commonDesc->bLength != sizeof(USB_CONFIGURATION_DESCRIPTOR))
                {
                    displayUnknown = TRUE;
                    break;
                }
                ConfigurationDescriptor((PUSB_CONFIGURATION_DESCRIPTOR)commonDesc,StringDescs);
                break;

            case USB_INTERFACE_DESCRIPTOR_TYPE:
                if ((commonDesc->bLength != sizeof(USB_INTERFACE_DESCRIPTOR)) &&
                    (commonDesc->bLength != sizeof(USB_INTERFACE_DESCRIPTOR2)))
                {
                    displayUnknown = TRUE;
                    break;
                }
                bInterfaceClass = ((PUSB_INTERFACE_DESCRIPTOR)commonDesc)->bInterfaceClass;
                bInterfaceSubClass = ((PUSB_INTERFACE_DESCRIPTOR)commonDesc)->bInterfaceSubClass;

                InterfaceDescriptor((PUSB_INTERFACE_DESCRIPTOR)commonDesc,StringDescs);
                break;

            case USB_ENDPOINT_DESCRIPTOR_TYPE:
                if ((commonDesc->bLength != sizeof(USB_ENDPOINT_DESCRIPTOR)) &&
                    (commonDesc->bLength != sizeof(USB_ENDPOINT_DESCRIPTOR2)))
                {
                    displayUnknown = TRUE;
                    break;
                }
                EndpointDescriptor((PUSB_ENDPOINT_DESCRIPTOR)commonDesc);
                break;

            case USB_HID_DESCRIPTOR_TYPE:
                if (commonDesc->bLength < sizeof(USB_HID_DESCRIPTOR))
                {
                    displayUnknown = TRUE;
                    break;
                }
                HidDescriptor((PUSB_HID_DESCRIPTOR)commonDesc);
                break;

            default:
                //if(bInterfaceClass==USB_DEVICE_CLASS_AUDIO)
                //    displayUnknown = !AudioDescriptor((PUSB_AUDIO_COMMON_DESCRIPTOR)commonDesc,bInterfaceSubClass);
                //else
                    displayUnknown = TRUE;
                break;
        }

        if (displayUnknown)
        {
            UnknownDescriptor(commonDesc);
        }

        if(commonDesc->bLength==0x00)
            break;  //no more data

        commonDesc += commonDesc->bLength;
    }
    Log(LOG_DEBUG,__LINE__,"<< USB.ConnDesc");
}

// ConfigurationDescriptor()
VOID USB::ConfigurationDescriptor(PUSB_CONFIGURATION_DESCRIPTOR ConfigDesc,PSTRING_DESCRIPTOR_NODE StringDescs)
{
    char format[1024] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.CfgDesc");

    PushBackDetails("> Configuration Descriptor:");

    _snprintf(format,sizeof(format)-1,">   wTotalLength: 0x%04X",ConfigDesc->wTotalLength);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   bNumInterfaces: 0x%02X",ConfigDesc->bNumInterfaces);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   bConfigurationValue: 0x%02X",ConfigDesc->bConfigurationValue);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   iConfiguration: 0x%02X",ConfigDesc->iConfiguration);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    if (ConfigDesc->iConfiguration)
    {
        StringDescriptor(ConfigDesc->iConfiguration,StringDescs);
    }

    _snprintf(format,sizeof(format)-1,">   bmAttributes: 0x%02X (%s)",ConfigDesc->bmAttributes,
                     (ConfigDesc->bmAttributes & 0x80?"Bus Powered":
                      (ConfigDesc->bmAttributes & 0x40?"Self Powered":
                       (ConfigDesc->bmAttributes & 0x20?"Remote Wakeup":"?"))));
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   MaxPower: 0x%02X (%d mA)",ConfigDesc->MaxPower,
                                                                     ConfigDesc->MaxPower * 2);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    Log(LOG_DEBUG,__LINE__,"<< USB.CfgDesc");
}

// InterfaceDescriptor()
VOID USB::InterfaceDescriptor(PUSB_INTERFACE_DESCRIPTOR InterfaceDesc,PSTRING_DESCRIPTOR_NODE StringDescs)
{
    char format[1024] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.InterfaceDesc");

    PushBackDetails("> Interface Descriptor:");

    _snprintf(format,sizeof(format)-1,">   bInterfaceNumber: 0x%02X",InterfaceDesc->bInterfaceNumber);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   bAlternateSetting: 0x%02X",InterfaceDesc->bAlternateSetting);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   bNumEndpoints: 0x%02X",InterfaceDesc->bNumEndpoints);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   bInterfaceClass: 0x%02X (%s)",InterfaceDesc->bInterfaceClass,
                     (InterfaceDesc->bInterfaceClass==USB_DEVICE_CLASS_AUDIO?"Audio":
                      (InterfaceDesc->bInterfaceClass==USB_DEVICE_CLASS_HUMAN_INTERFACE?"HID":
                       (InterfaceDesc->bInterfaceClass==USB_DEVICE_CLASS_HUB?"Hub":"?"))));
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    if(InterfaceDesc->bInterfaceClass==USB_DEVICE_CLASS_AUDIO)
    {
        _snprintf(format,sizeof(format)-1,">   bInterfaceSubClass: 0x%02X (%s)",InterfaceDesc->bInterfaceSubClass,
                         (InterfaceDesc->bInterfaceSubClass==USB_AUDIO_SUBCLASS_AUDIOCONTROL?"Audio Control":
                          (InterfaceDesc->bInterfaceSubClass==USB_AUDIO_SUBCLASS_AUDIOSTREAMING?"Audio Streaming":
                           (InterfaceDesc->bInterfaceSubClass==USB_AUDIO_SUBCLASS_MIDISTREAMING?"MIDI Streaming":"?"))));
    }
    else
        _snprintf(format,sizeof(format)-1,">   bInterfaceSubClass: 0x%02X",InterfaceDesc->bInterfaceSubClass);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   bInterfaceProtocol: 0x%02X",InterfaceDesc->bInterfaceProtocol);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   iInterface: 0x%02X",InterfaceDesc->iInterface);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    if (InterfaceDesc->iInterface)
    {
        StringDescriptor(InterfaceDesc->iInterface,StringDescs);
    }

    if (InterfaceDesc->bLength == sizeof(USB_INTERFACE_DESCRIPTOR2))
    {
        PUSB_INTERFACE_DESCRIPTOR2 interfaceDesc2 = (PUSB_INTERFACE_DESCRIPTOR2)InterfaceDesc;

        _snprintf(format,sizeof(format)-1,">   wNumClasses: 0x%04X",interfaceDesc2->wNumClasses);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.InterfaceDesc");
}

// EndpointDescriptor()
VOID USB::EndpointDescriptor(PUSB_ENDPOINT_DESCRIPTOR EndpointDesc)
{
    char format[1024] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.EndpointDesc");

    PushBackDetails("> Endpoint Descriptor:");

    if (USB_ENDPOINT_DIRECTION_IN(EndpointDesc->bEndpointAddress))
    {
        _snprintf(format,sizeof(format)-1,">   bEndpointAddress: 0x%02X IN",EndpointDesc->bEndpointAddress);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));
    }
    else
    {
        _snprintf(format,sizeof(format)-1,">   bEndpointAddress: 0x%02X OUT",EndpointDesc->bEndpointAddress);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));
    }

    switch (EndpointDesc->bmAttributes & 0x03)
    {
        case 0x00:
            PushBackDetails(">   Transfer Type: Control");
            break;

        case 0x01:
            PushBackDetails(">   Transfer Type: Isochronous");
            break;

        case 0x02:
            PushBackDetails(">   Transfer Type: Bulk");
            break;

        case 0x03:
            PushBackDetails(">   Transfer Type: Interrupt");
            break;

    }

    _snprintf(format,sizeof(format)-1,">   wMaxPacketSize: 0x%04X (%d)",EndpointDesc->wMaxPacketSize,EndpointDesc->wMaxPacketSize);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    if (EndpointDesc->bLength == sizeof(USB_ENDPOINT_DESCRIPTOR))
    {
        _snprintf(format,sizeof(format)-1,">   bInterval: 0x%02X",EndpointDesc->bInterval);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));
    }
    else
    {
        PUSB_ENDPOINT_DESCRIPTOR2 endpointDesc2 = (PUSB_ENDPOINT_DESCRIPTOR2)EndpointDesc;

        _snprintf(format,sizeof(format)-1,">   wInterval: 0x%04X",endpointDesc2->wInterval);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));

        _snprintf(format,sizeof(format)-1,">   bSyncAddress: 0x%02X",endpointDesc2->bSyncAddress);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.EndpointDesc");
}


// HidDescriptor()
VOID USB::HidDescriptor(PUSB_HID_DESCRIPTOR HidDesc)
{
    UCHAR i;
    char format[1024] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.HidDesc");

    PushBackDetails("> HID Descriptor:");

    _snprintf(format,sizeof(format)-1,">   bcdHID: 0x%04X",HidDesc->bcdHID);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   bCountryCode: 0x%02X",HidDesc->bCountryCode);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   bNumDescriptors: 0x%02X",HidDesc->bNumDescriptors);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    for (i=0; i<HidDesc->bNumDescriptors; i++)
    {
        _snprintf(format,sizeof(format)-1,">   %.3i, bDescriptorType: 0x%02X, wDescriptorLength: 0x%04X",
                                          HidDesc->OptionalDescriptors[i].bDescriptorType,
                                          HidDesc->OptionalDescriptors[i].wDescriptorLength);
        PushBackDetails(format);
        memset(format,0x00,sizeof(format));
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.HidDesc");
}

// StringDescriptor()
VOID USB::StringDescriptor(UCHAR Index,PSTRING_DESCRIPTOR_NODE StringDescs)
{
    char format[10000] = {0};

    Log(LOG_DEBUG,__LINE__,">> USB.StrDesc, Idx %d",(int)Index);

    // Use an actual "int" here because it's passed as a printf * precision
    int descChars = 0;

    while (StringDescs)
    {
        if (StringDescs->DescriptorIndex == Index)
        {
            //
            // bString from USB_STRING_DESCRIPTOR isn't NULL-terminated, so 
            // calculate the number of characters.  
            // 
            // bLength is the length of the whole structure, not just the string.  
            // 
            // bLength is bytes, bString is WCHARs
            // 
            descChars = 
                ( (int) StringDescs->StringDescriptor->bLength - 
                offsetof(USB_STRING_DESCRIPTOR, bString) ) /
                sizeof(WCHAR);
            //
            // Use the * precision and pass the number of characters just caculated.
            // bString is always WCHAR so specify widestring regardless of what TCHAR resolves to
            // 
            _snprintf(format,sizeof(format)-1,">   0x%04X: %s",StringDescs->LanguageID,(const char *)StringDescs->StringDescriptor->bString);
            PushBackDetails(format);
            memset(format,0x00,sizeof(format));
            break;
        }

        StringDescs = StringDescs->Next;
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.StrDesc");
}

// UnknownDescriptor()
VOID USB::UnknownDescriptor(PUSB_COMMON_DESCRIPTOR CommonDesc)
{
    char format[1024] = {0};
    UCHAR   i;

    Log(LOG_DEBUG,__LINE__,">> USB.UnknownDesc");

    PushBackDetails("> Unknown Descriptor:");

    _snprintf(format,sizeof(format)-1,">   bDescriptorType: 0x%02X",CommonDesc->bDescriptorType);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   bLength: 0x%02X",CommonDesc->bLength);
    PushBackDetails(format);
    memset(format,0x00,sizeof(format));

    _snprintf(format,sizeof(format)-1,">   ");
    for (i = 0; i < CommonDesc->bLength; i++)
    {
        _snprintf(format,sizeof(format)-1,"%s.%02X",format,((PUCHAR)CommonDesc)[i]);

        if (i % 16 == 15)
        {
            PushBackDetails(format);
            memset(format,0x00,sizeof(format));
            _snprintf(format,sizeof(format)-1,">   ");
        }
    }

    if (i % 16 != 0)
    {
        PushBackDetails(format);
    }

    Log(LOG_DEBUG,__LINE__,"<< USB.UnknownDesc");
}
