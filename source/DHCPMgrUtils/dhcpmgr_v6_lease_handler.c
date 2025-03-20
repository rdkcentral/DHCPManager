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

#include "cosa_dhcpv6_apis.h"
#include "dhcpv6_interface.h"


/**
 * @brief Compares two DHCPv6 plugin messages to determine if they are identical.
 *
 * @param currentLease Pointer to the current DHCPv6 plugin message.
 * @param newLease Pointer to the new DHCPv6 plugin message to compare against.
 * 
 * @return true if the two messages are identical, false otherwise.
 */
static bool compare_dhcpv6_plugin_msg(const DHCPv6_PLUGIN_MSG *currentLease, const DHCPv6_PLUGIN_MSG *newLease) 
{
    if (currentLease == NULL || newLease == NULL) 
    {
        return false; // Null pointers cannot be compared
    }

    // Compare all fields except the `next` pointer
    if (currentLease->isExpired != newLease->isExpired ||
        memcmp(&currentLease->ia_na, &newLease->ia_na, sizeof(currentLease->ia_na)) != 0 ||
        memcmp(&currentLease->ia_pd, &newLease->ia_pd, sizeof(currentLease->ia_pd)) != 0 ||
        memcmp(&currentLease->dns, &newLease->dns, sizeof(currentLease->dns)) != 0 ||
        memcmp(&currentLease->mapt, &newLease->mapt, sizeof(currentLease->mapt)) != 0 ||
        strcmp(currentLease->domainName, newLease->domainName) != 0 ||
        strcmp(currentLease->ntpserver, newLease->ntpserver) != 0 ||
        strcmp(currentLease->aftr, newLease->aftr) != 0) 
    {
        return false; // Structures are not equal
    }

    return true; // Structures are equal (ignoring `next`)
}


/**
 * @brief Processes new DHCPv6 leases.
 *
 * This function checks for the availability of new leases in the list and processes them if found.
 *
 * @param[in] pDhcp6c Pointer to the DHCP client structure containing lease information.
 *
 * @return void
 */
void DhcpMgr_ProcessV6Lease(PCOSA_DML_DHCPCV6_FULL pDhcp6c) 
{
    BOOL leaseChanged = false;
    while (pDhcp6c->NewLeases != NULL) 
    {
        // Compare  parameters of currentLease and NewLeases
        DHCPv6_PLUGIN_MSG *current = pDhcp6c->currentLease;
        DHCPv6_PLUGIN_MSG *newLease = pDhcp6c->NewLeases;

        if (current == NULL) 
        {
            DHCPMGR_LOG_INFO("%s %d: lease updated for %s \n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
            leaseChanged = TRUE;
        }
        else if(current->isExpired == TRUE && newLease->isExpired == FALSE)
        {
            //DhcpMgr_PublishDhcpV4Event(pDhcp6c, DHCP_LEASE_DEL);
            DHCPMGR_LOG_INFO("%s %d: lease expired  for %s \n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
        }
        else if (newLease->isExpired == FALSE && (newLease->ia_na.assigned == TRUE ||newLease->ia_pd.assigned == TRUE))
        {
            //DhcpMgr_PublishDhcpV4Event(pDhcp6c, DHCP_LEASE_RENEW);
            DHCPMGR_LOG_INFO("%s %d: lease renewed for %s \n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
        }
        else 
        {
            /* In an IPv6 lease, both IANA and IAPD details are sent together in a struct. 
             * If only one of them is renewed, the other field will be set to its default value. Copy the previous value to the new lease.
             */
            if(newLease->ia_na.assigned == FALSE && current->ia_na.assigned == TRUE)
            {
                //If we reach this point, only IAPD has been renewed. Use the previous IANA details.
                DHCPMGR_LOG_INFO("%s %d: IANA is not assigned in this msg. Assuming only IAPD renewed. Using previous IANA details for %s \n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
                memcpy(&newLease->ia_na, &current->ia_na, sizeof(current->ia_na));
            }

            if(newLease->ia_pd.assigned == FALSE && current->ia_pd.assigned == TRUE)
            {
                // If we reach this point, only IANA has been renewed. Use the previous IAPD details.
                DHCPMGR_LOG_INFO("%s %d: IAPD is not assigned in this msg. Assuming only IANA renewed. Using previous IAPD details for %s \n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
                memcpy(&newLease->ia_pd, &current->ia_pd, sizeof(current->ia_pd));
                //mapt is part of IAPD. If IAPD is renewed, mapt is also renewed.
                memcpy(&newLease->mapt, &current->mapt, sizeof(current->mapt));
            }
            
            if(compare_dhcpv6_plugin_msg(current, newLease) == FALSE)
            {
                DHCPMGR_LOG_INFO("%s %d: lease changed  for %s \n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
                leaseChanged = TRUE;
            }
            
        }


        DHCPMGR_LOG_INFO("%s %d: New lease  : %s \n",__FUNCTION__, __LINE__, newLease->isExpired?"Expired" : "Valid");

        // Free the current lease
        if(pDhcp6c->currentLease)
        {
            free(pDhcp6c->currentLease);
            pDhcp6c->currentLease = NULL;
        }
        
        // Update currentLease to point to NewLeases
        pDhcp6c->currentLease = newLease;

        // Update NewLeases to point to the next lease
        pDhcp6c->NewLeases = newLease->next;

        // Clear the next pointer of the new current lease
        pDhcp6c->currentLease->next = NULL;
        
        if(leaseChanged)
        {
            DHCPMGR_LOG_INFO("%s %d: NewLease address %s  \n", __FUNCTION__, __LINE__, newLease->ia_na.address);
            DHCPMGR_LOG_INFO("%s %d: NewLease prefix %s  \n", __FUNCTION__, __LINE__, newLease->ia_pd.Prefix);
            DHCPMGR_LOG_INFO("%s %d: NewLease PrefixLength %d  \n", __FUNCTION__, __LINE__, newLease->ia_pd.PrefixLength);
            DHCPMGR_LOG_INFO("%s %d: NewLease nameserver %s  \n", __FUNCTION__, __LINE__, newLease->dns.nameserver);
            DHCPMGR_LOG_INFO("%s %d: NewLease nameserver2 %s  \n", __FUNCTION__, __LINE__, newLease->dns.nameserver1);
            DHCPMGR_LOG_INFO("%s %d: NewLease PreferedLifeTime %d  \n", __FUNCTION__, __LINE__, newLease->ia_pd.PreferedLifeTime);
            DHCPMGR_LOG_INFO("%s %d: NewLease ValidLifeTime %d  \n", __FUNCTION__, __LINE__, newLease->ia_pd.ValidLifeTime);
            //configureNetworkInterface(pDhcp6c);
            //DhcpMgr_updateDHCPv4DML(pDhcp6c);

            //DhcpMgr_PublishDhcpV4Event(pDhcp6c, DHCP_LEASE_UPDATE);
            
        }

    }
}