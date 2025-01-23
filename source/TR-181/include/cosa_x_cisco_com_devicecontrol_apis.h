/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/**************************************************************************

    module: cosa_x_cisco_com_devicecontrol_apis.h

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file defines the apis for objects to support Data Model Library.

    -------------------------------------------------------------------


    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        07/15/2011    initial revision.

**************************************************************************/


#ifndef  _COSA_X_CISCO_COM_DEVICECONTROL_APIS_H
#define  _COSA_X_CISCO_COM_DEVICECONTROL_APIS_H

#include "cosa_apis.h"
#include "plugin_main_apis.h"

#include <sys/sysinfo.h>


#define CONFIG_AVAHI_DAEMON_FILENAME    "/var/tmp/avahi/avahi-daemon.conf"

#define CMD_START_AVAHI_DAEMON          "avahi-daemon -D"
#define CMD_START_AVAHI_AUTOIPD         "avahi-autoipd -D --force brlan0"
#define CMD_STOP_AVAHI_DAEMON           "avahi-daemon -k"
#define CMD_STOP_AVAHI_AUTOIPD          "avahi-autoipd -k brlan0"

#define UTOPIA_AVAHI_ENABLED            "ccsp_zeroconf_enabled"

/**********************************************************************
                STRUCTURE AND CONSTANT DEFINITIONS
**********************************************************************/
enum
{
    PRIMARY_MODE=1,
    BYOI_MODE,
    NONE_MODE
};

typedef enum
_COSA_DML_WanAddrMode
{
    COSA_DML_WanAddrMode_DHCP       = 1,
    COSA_DML_WanAddrMode_Static,
    COSA_DML_WanAddrMode_DHALIP,
}
COSA_DML_WanAddrMode, *PCOSA_DML_WanAddrMode;


typedef enum
_COSA_DML_LanMode
{
    COSA_DML_LanMode_BridgeDHCP = 1,
    COSA_DML_LanMode_BridgeStatic = 2,
    COSA_DML_LanMode_Router = 3,
    COSA_DML_LanMode_FullBridgeStatic = 4
}
COSA_DML_LanMode, *PCOSA_DML_LanMode;

typedef enum
_COSA_DML_LanNetworksAllow
{
    COSA_DML_LanNetworksAllow_Default = 0,
    COSA_DML_LanNetworksAllow_AnyPrivateClass,
    COSA_DML_LanNetworksAllow_AnyClass,
}
COSA_DML_LanNetworksAllow, *PCOSA_DML_LanNetworksAllow;

typedef enum
_COSA_DML_LanNapt
{
//    COSA_DML_LanNapt_Disable = 0,
    COSA_DML_LanNapt_DHCP =1,
    COSA_DML_LanNapt_StaticIP,
}COSA_DML_LanNapt, *PCOSA_DML_LanNapt;

typedef struct 
_COSA_DML_LAN_MANAGEMENT
{
    ULONG                       InstanceNumber;
    char                        Alias[COSA_DML_IF_NAME_LENGTH];

    COSA_DML_LanMode            LanMode;
    ANSC_IPV4_ADDRESS           LanNetwork;
    COSA_DML_LanNetworksAllow   LanNetworksAllow;
    ANSC_IPV4_ADDRESS           LanSubnetMask;
    ANSC_IPV4_ADDRESS           LanIPAddress;
    BOOLEAN                     LanDhcpServer;
    COSA_DML_LanNapt            LanNaptType;
    BOOLEAN                     LanNaptEnable;
    ULONG                       LanTos;
    BOOLEAN                     LanDhcp125;
    BOOLEAN                     LanHnap;
    BOOLEAN                     LanUpnp;
}
COSA_DML_LAN_MANAGEMENT, *PCOSA_DML_LAN_MANAGEMENT;

typedef struct
_COSA_NOTIFY_WIFI
{
    int flag;
    int ticket;
}
COSA_NOTIFY_WIFI, *PCOSA_NOTIFY_WIFI;

#define FACTORY_RESET_KEY "factory_reset"
#define FACTORY_RESET_WIFI_VALUE "w"
#define FACTORY_RESET_ROUTER_VALUE "y"

/**********************************************************************
                FUNCTION PROTOTYPES
**********************************************************************/

ANSC_STATUS
CosaDmlDcSetWanNameServer
    (
        ANSC_HANDLE                 hContext,
        uint32_t                    ipAddr,
        int                         nameServerNo
    );

ULONG
CosaDmlLanMngm_GetNumberOfEntries
    (
        void
    );

ANSC_STATUS
CosaDmlLanMngm_GetEntryByIndex
    (
        ULONG index, 
        PCOSA_DML_LAN_MANAGEMENT pLanMngm
    );

ANSC_STATUS
CosaDmlLanMngm_SetValues
    (
        ULONG index, 
        ULONG ins, 
        const char *alias
    );

ANSC_STATUS
CosaDmlLanMngm_GetConf
    (
        ULONG ins, 
        PCOSA_DML_LAN_MANAGEMENT pLanMngm
    );

ANSC_STATUS
CosaDmlLanMngm_SetConf
    (
        ULONG ins, 
        PCOSA_DML_LAN_MANAGEMENT pLanMngm
    );

void _CosaDmlDcStartZeroConfig();

int CheckAndGetDevicePropertiesEntry( char *pOutput, int size, char *sDevicePropContent );
INT cm_hal_ReinitMac();
BOOL moca_HardwareEquipped(void);

#endif

