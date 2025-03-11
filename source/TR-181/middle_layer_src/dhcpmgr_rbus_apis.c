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

#include <stdio.h>
#include <stdlib.h>
#include "dhcpmgr_rbus_apis.h"
#include "cosa_dhcpv4_apis.h"
#include "util.h"

#define  ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))
#define  MAC_ADDR_SIZE 18
static rbusHandle_t rbusHandle;
char *componentName = "DHCPMANAGER";

rbusError_t DhcpMgr_Rbus_SubscribeHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish);


/***********************************************************************

  Data Elements declaration:

 ***********************************************************************/
rbusDataElement_t DhcpMgrRbusDataElements[] = {
    {DHCP_MGR_DHCPv4_IFACE, RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, NULL, NULL, NULL, NULL}},
    {DHCP_MGR_DHCPv4_STATUS,  RBUS_ELEMENT_TYPE_PROPERTY, {NULL, NULL, NULL, NULL, DhcpMgr_Rbus_SubscribeHandler, NULL}},
};


ANSC_STATUS DhcpMgr_Rbus_Init()
{
    DHCPMGR_LOG_INFO("%s %d: rbus init called\n",__FUNCTION__, __LINE__);
    int rc = ANSC_STATUS_FAILURE;
    rc = rbus_open(&rbusHandle, componentName);
    if (rc != RBUS_ERROR_SUCCESS)
    {
        DHCPMGR_LOG_ERROR("WanMgr_Rbus_Init rbus initialization failed\n");
        return rc;
    }

    
    // Register data elements
    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(DhcpMgrRbusDataElements), DhcpMgrRbusDataElements);

    if (rc != RBUS_ERROR_SUCCESS)
    {
        DHCPMGR_LOG_WARNING("rbus register data elements failed\n");
        rbus_close(rbusHandle);
        return rc;
    }

    char AliasName[64] = {0};
    ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);

    for (ULONG i = 0; i < clientCount; i++)
    {
        rc = rbusTable_registerRow(rbusHandle, DHCP_MGR_DHCPv4_TABLE, (i+1), NULL);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            DHCPMGR_LOG_ERROR("%s %d - Iterface(%lu) Table (%s) Registartion failed, Error=%d \n", __FUNCTION__, __LINE__, i, DHCP_MGR_DHCPv4_TABLE, rc);
            return rc;
        }
        else
        {
            DHCPMGR_LOG_INFO("%s %d - Iterface(%lu) Table (%s) Registartion Successfully, AliasName(%s)\n", __FUNCTION__, __LINE__, i, DHCP_MGR_DHCPv4_TABLE, AliasName);
        }

        memset(AliasName,0,64);
     }

    return ANSC_STATUS_SUCCESS;
}

rbusError_t DhcpMgr_Rbus_SubscribeHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char *eventName, rbusFilter_t filter, int32_t interval, bool *autoPublish)
{
    (void)handle;
    (void)filter;
    (void)(interval);
    (void)(autoPublish);

    char *subscribe_action = action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribed" : "unsubscribed";
    DHCPMGR_LOG_INFO("%s %d - Event %s has been  %s \n", __FUNCTION__, __LINE__,eventName, subscribe_action );

    return RBUS_ERROR_SUCCESS;
}