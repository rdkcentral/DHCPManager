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
#include "dhcpv4_interface.h"


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

void DhcpMgr_createLeaseInfoMsg(DHCPv4_PLUGIN_MSG *src, DHCP_MGR_IPV4_MSG *dest) 
{
    strncpy(dest->ifname, src->ifname, sizeof(dest->ifname) - 1);
    strncpy(dest->address, src->address, sizeof(dest->address) - 1);
    strncpy(dest->netmask, src->netmask, sizeof(dest->netmask) - 1);
    strncpy(dest->gateway, src->gateway, sizeof(dest->gateway) - 1);
    strncpy(dest->dnsServer, src->dnsServer, sizeof(dest->dnsServer) - 1);
    strncpy(dest->dnsServer1, src->dnsServer1, sizeof(dest->dnsServer1) - 1);
    strncpy(dest->timeZone, src->timeZone, sizeof(dest->timeZone) - 1);
    dest->mtuSize = src->mtuSize;
    dest->timeOffset = src->timeOffset;
    dest->isTimeOffsetAssigned = src->isTimeOffsetAssigned;
    dest->upstreamCurrRate = src->upstreamCurrRate;
    dest->downstreamCurrRate = src->downstreamCurrRate;
}

int DhcpMgr_PublishDhcpV4Event(PCOSA_DML_DHCPC_FULL pDhcpc, DHCP_MESSAGE_TYPE msgType)
{
    if(pDhcpc == NULL)
    {
        DHCPMGR_LOG_ERROR("%s : pDhcpc is NULL\n",__FUNCTION__);
        return -1;
    }

    int rc = -1;
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t ifNameVal , typeVal, leaseInfoVal;

    /*Set Interface Name */
    rbusObject_Init(&rdata, NULL);
    rbusValue_Init(&ifNameVal);
    rbusValue_SetString(ifNameVal, (char*)pDhcpc->Cfg.Interface);
    rbusObject_SetValue(rdata, "IfName", ifNameVal);

    /*Set Msg type Name */
    rbusValue_Init(&typeVal);
    rbusValue_SetUInt64(typeVal, msgType);
    rbusObject_SetValue(rdata, "MsgType", typeVal);

    /*Set the lease deatails */
    if(msgType == DHCP_LEASE_UPDATE)
    { 
        DHCP_MGR_IPV4_MSG leaseInfo;
        uint8_t byteArray[sizeof(DHCP_MGR_IPV4_MSG)];
        memcpy(byteArray, &leaseInfo, sizeof(DHCP_MGR_IPV4_MSG));
        DhcpMgr_createLeaseInfoMsg(&leaseInfo, pDhcpc->currentLease);

        rbusValue_Init(&leaseInfoVal);
        rbusValue_SetBytes(leaseInfoVal, byteArray, sizeof(DHCP_MGR_IPV4_MSG));
        rbusObject_SetValue(rdata, "LeaseInfo", leaseInfoVal);
    }

    

    int index = 2;//TODO get the index num
    char eventStr[64] = {0};
    snprintf(eventStr,sizeof(eventStr), DHCPv4_EVENT_FORMAT, index);


    event.name = eventStr;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rbusError_t rt = rbusEvent_Publish(rbusHandle, &event); 
    
    if( rt != RBUS_ERROR_SUCCESS && rt != RBUS_ERROR_NOSUBSCRIBERS)
    {
        DHCPMGR_LOG_WARNING("%s %d - Event %s Publish Failed \n", __FUNCTION__, __LINE__,eventStr );
    }
    else
    {
        DHCPMGR_LOG_INFO("%s %d - Event %s Published \n", __FUNCTION__, __LINE__,eventStr );
        rc = 0;
    }


    rbusValue_Release(ifNameVal);
    rbusValue_Release(typeVal);
    rbusObject_Release(rdata);

    return rc;

}