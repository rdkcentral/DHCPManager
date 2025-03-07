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

/* ---- Include Files ---------------------------------------- */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include "ansc_platform.h"
#include "cosa_apis.h"
#include "cosa_dml_api_common.h"
#include "cosa_dhcpv4_apis.h"
#include "cosa_dhcpv4_internal.h"
#include "cosa_dhcpv4_dml.h"
#include "dhcpv4_interface.h"
#include "dhcpmgr_controller.h"
#include "dhcp_lease_monitor_thrd.h"
#include "dhcp_client_common_utils.h"

#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>


/* ---- Global Constants -------------------------- */

/**
 * @brief Updates the TR-181 DML structure from the DHCPv4 response.
 *
 * This function updates the TR-181 Data Model Layer (DML) structure with information obtained from the DHCPv4 response.
 *
 * @param[in] pDhcpc Pointer to the DHCP client structure containing the DHCPv4 response data.
 *
 * @return ANSC_STATUS Status of the update operation.
 */
static ANSC_STATUS DhcpMgr_updateDHCPv4DML(PCOSA_DML_DHCPC_FULL pDhcpc)
{

    DHCPv4_PLUGIN_MSG *current = pDhcpc->currentLease;
    if (current == NULL) 
    {
        DHCPMGR_LOG_ERROR("%s %d: lease parsing failed %s \n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
        return ANSC_STATUS_FAILURE;

    }
    if (current->addressAssigned == 1)
    {
        /* Updatet the status */
        pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Enabled;
        /* Update the DHCPCStatus */
        pDhcpc->Info.DHCPStatus = COSA_DML_DHCPC_STATUS_Bound;
        /* Update the IP address assigned */
        AnscWriteUlong(&pDhcpc->Info.IPAddress.Value, _ansc_inet_addr(current->address));
        /* Update the Subnet Mask */
        AnscWriteUlong(&pDhcpc->Info.SubnetMask.Value, _ansc_inet_addr(current->netmask));
        /* Update the leaseTime */
        pDhcpc->Info.LeaseTimeRemaining = current->leaseTime;
        pDhcpc->Info.NumDnsServers = 0;
        pDhcpc->Info.NumIPRouters = 0;
        /* Update the DNS Servers */
        if(strlen(current->dnsServer)>0)
        {
            AnscWriteUlong(&pDhcpc->Info.DNSServers[pDhcpc->Info.NumDnsServers].Value, _ansc_inet_addr(current->dnsServer));
            pDhcpc->Info.NumDnsServers++;
        }
        if(strlen(current->dnsServer1)>0)
        {
            AnscWriteUlong(&pDhcpc->Info.DNSServers[pDhcpc->Info.NumDnsServers].Value, _ansc_inet_addr(current->dnsServer1));
            pDhcpc->Info.NumDnsServers++;
        }

        /* Update the IPRouters */
        char *tok = strtok (current->gateway, " ");
        while (tok != NULL)
        {
            AnscWriteUlong(&pDhcpc->Info.IPRouters[pDhcpc->Info.NumIPRouters].Value, _ansc_inet_addr(tok));
            pDhcpc->Info.NumIPRouters++;
            tok = strtok (NULL, " ");
        }
        //Update the DHCP Server
        AnscWriteUlong(&pDhcpc->Info.DHCPServer.Value, _ansc_inet_addr(current->dhcpServerId));
    }
    /*
    //TODO : check the sip server options
    noOfReqOpt = CosaDmlDhcpcGetNumberOfReqOption(pDhcpCxtLink->hContext, pDhcpc->Cfg.InstanceNumber);
    for (unsigned int reqIdx = 0; reqIdx < noOfReqOpt; reqIdx++)
    {
        pDhcpReqOpt = CosaDmlDhcpcGetReqOption_Entry(pDhcpCxtLink, reqIdx);
        if (!pDhcpReqOpt)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcpReqOpt is NULL",__FUNCTION__);
            return ANSC_STATUS_FAILURE;
        }
        if (pDhcpReqOpt->Tag == DHCPV4_OPT_120)
        {
            STRCPY_S_NOCLOBBER((char *)pDhcpReqOpt->Value, sizeof(pDhcpReqOpt->Value), current->sipSrv);
        }
        if (pDhcpReqOpt->Tag == DHCPV4_OPT_121)
        {
            STRCPY_S_NOCLOBBER((char *)pDhcpReqOpt->Value, sizeof(pDhcpReqOpt->Value), current->staticRoutes);
        }
    }
    */
    return ANSC_STATUS_SUCCESS;
}

int DhcpMgr_GetBCastFromIpSubnetMask(const char* inIpStr, const char* inSubnetMaskStr, char *outBcastStr)
{
   struct in_addr ip;
   struct in_addr subnetMask;
   struct in_addr bCast;
   int ret = RETURN_OK;

   if (inIpStr == NULL || inSubnetMaskStr == NULL || outBcastStr == NULL)
   {
      return RETURN_ERR;
   }

   ip.s_addr = inet_addr(inIpStr);
   subnetMask.s_addr = inet_addr(inSubnetMaskStr);
   bCast.s_addr = ip.s_addr | ~subnetMask.s_addr;
   strncpy(outBcastStr, inet_ntoa(bCast),strlen(inet_ntoa(bCast))+1);

   return ret;
}

int configureNetworkInterface(PCOSA_DML_DHCPC_FULL pDhcpc) 
{
    DHCPv4_PLUGIN_MSG *current = pDhcpc->currentLease;
    if(current == NULL)
    {
        return -1;
    }

    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in* addr;

    // Create a socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    // Set the interface name
    strncpy(ifr.ifr_name, pDhcpc->Cfg.Interface, IFNAMSIZ);

    // Set the IP address
    addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, current->address, &addr->sin_addr);
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR)");
        close(sockfd);
        return -1;
    }

    // Set the netmask
    inet_pton(AF_INET, current->netmask, &addr->sin_addr);
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl(SIOCSIFNETMASK)");
        close(sockfd);
        return -1;
    }

    char broadcast[BUFLEN_32] = {0};
    DhcpMgr_GetBCastFromIpSubnetMask(current->address, current->netmask, broadcast);
    
    // Set the broadcast address
    inet_pton(AF_INET, broadcast, &addr->sin_addr);
    if (ioctl(sockfd, SIOCSIFBRDADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFBRDADDR)");
        close(sockfd);
        return -1;
    }

    // Set the MTU
    ifr.ifr_mtu = current->mtuSize;
    if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
        perror("ioctl(SIOCSIFMTU)");
        close(sockfd);
        return -1;
    }

    // Bring the interface up
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCGIFFLAGS)");
        close(sockfd);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS)");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

/**
 * @brief Processes new DHCPv4 leases.
 *
 * This function checks for the availability of new leases in the list and processes them if found.
 *
 * @param[in] pDhcpc Pointer to the DHCP client structure containing lease information.
 *
 * @return void
 */
void DhcpMgr_ProcessV4Lease(PCOSA_DML_DHCPC_FULL pDhcpc) 
{
    BOOL leaseChanged = false;
    while (pDhcpc->NewLeases != NULL) 
    {
        // Compare  parameters of currentLease and NewLeases
        DHCPv4_PLUGIN_MSG *current = pDhcpc->currentLease;
        DHCPv4_PLUGIN_MSG *newLease = pDhcpc->NewLeases;
        DHCPMGR_LOG_INFO("%s %d: New Lease found for %s current addr %p newLease %p \n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, current , newLease);


        if (current == NULL) 
        {
            DHCPMGR_LOG_INFO("%s %d: lease updated for %s \n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
            leaseChanged = TRUE;
        }
        else if ((current != NULL) &&
            ((current->addressAssigned != newLease->addressAssigned)||
            (current->isExpired != newLease->isExpired) ||
            (strcmp(current->address, newLease->address) != 0) ||
            (strcmp(current->netmask, newLease->netmask) != 0) ||
            (strcmp(current->gateway, newLease->gateway) != 0) ||
            (strcmp(current->dnsServer, newLease->dnsServer) != 0) ||
            (strcmp(current->dnsServer1, newLease->dnsServer1) != 0) 
        ))
        {
            DHCPMGR_LOG_INFO("%s %d: lease updated for %s \n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
            leaseChanged = TRUE;
        }
        else if (newLease->isExpired == FALSE && newLease->addressAssigned == TRUE )
        {
            DHCPMGR_LOG_INFO("%s %d: lease renewed for %s \n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
        }

        //TODO: check for renew
        DHCPMGR_LOG_INFO("%s %d: New lease  : %s \n",__FUNCTION__, __LINE__, newLease->isExpired?"Expired" : "Valid");

        // Free the current lease
        if(pDhcpc->currentLease)
        {
            free(pDhcpc->currentLease);
            pDhcpc->currentLease = NULL;
        }
        
        // Update currentLease to point to NewLeases
        pDhcpc->currentLease = newLease;

        // Update NewLeases to point to the next lease
        pDhcpc->NewLeases = newLease->next;

        // Clear the next pointer of the new current lease
        pDhcpc->currentLease->next = NULL;
        
        if(leaseChanged)
        {
            if(newLease->isExpired == TRUE)
            {
                //TODO: Handle lease delete
                continue;
            }
            DHCPMGR_LOG_INFO("%s %d: NewLease->address %s  \n",__FUNCTION__, __LINE__, newLease->address);
            DHCPMGR_LOG_INFO("%s %d: NewLease->netmask %s  \n",__FUNCTION__, __LINE__, newLease->netmask);
            DHCPMGR_LOG_INFO("%s %d: NewLease->gateway %s  \n",__FUNCTION__, __LINE__, newLease->gateway );
            DHCPMGR_LOG_INFO("%s %d: NewLease->dnsServer %s  \n",__FUNCTION__, __LINE__, newLease->dnsServer );
            DHCPMGR_LOG_INFO("%s %d: NewLease->dnsServer1 %s  \n",__FUNCTION__, __LINE__,  newLease->dnsServer1 );
            configureNetworkInterface(pDhcpc);
            DhcpMgr_updateDHCPv4DML(pDhcpc);

            //TODO: Send rbus event
            
        }

    }
}


/**
 * @brief Clears all parameters in the TR-181 DML structure.
 *
 * This function resets all the fields in the TR-181 Data Model Layer (DML) structure to their default values.
 *
 * @param[in] pDhcpc Pointer to the DHCP client structure to be cleared.
 *
 * @return void
 */
void DhcpMgr_clearDHCPv4Lease(PCOSA_DML_DHCPC_FULL pDhcpc) 
{
    
    if (pDhcpc == NULL) 
    {
        return;
    }

    pDhcpc->Info.DHCPStatus = COSA_DML_DHCPC_STATUS_Init;
    AnscWriteUlong(&pDhcpc->Info.IPAddress.Value, 0);
    AnscWriteUlong(&pDhcpc->Info.SubnetMask.Value, 0);
    pDhcpc->Info.LeaseTimeRemaining = 0;
    
    
    AnscWriteUlong(&pDhcpc->Info.DHCPServer.Value, 0);

    // Clear DNS Servers
    for (ULONG i = 0; i < pDhcpc->Info.NumDnsServers; i++)
    {
        AnscWriteUlong(&pDhcpc->Info.DNSServers[i].Value, 0);
    }
    pDhcpc->Info.NumDnsServers = 0;

    // Clear IP Routers
    for (ULONG i = 0; i < pDhcpc->Info.NumIPRouters; i++) 
    {
        AnscWriteUlong(&pDhcpc->Info.IPRouters[i].Value, 0);
    }
    pDhcpc->Info.NumIPRouters = 0;
}