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
#include "secure_wrapper.h"
#include "dhcpmgr_rbus_apis.h"

static void configureNetworkInterface(PCOSA_DML_DHCPCV6_FULL pDhcp6c);

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
            DhcpMgr_PublishDhcpV6Event(pDhcp6c, DHCP_LEASE_DEL);
            DHCPMGR_LOG_INFO("%s %d: lease expired  for %s \n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
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
            else if (newLease->isExpired == FALSE && (newLease->ia_na.assigned == TRUE ||newLease->ia_pd.assigned == TRUE))
            {
                DhcpMgr_PublishDhcpV6Event(pDhcp6c, DHCP_LEASE_RENEW);
                DHCPMGR_LOG_INFO("%s %d: lease renewed for %s \n",__FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
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
            configureNetworkInterface(pDhcp6c);
            
            DhcpMgr_PublishDhcpV6Event(pDhcp6c, DHCP_LEASE_UPDATE);
            
        }

    }
}
/**
 * @brief Configures the network interface with the IPv6 address from the current lease.
 *
 * This function assigns the IPv6 address from the current lease to the specified network interface
 * and sets the associated timeout values.
 *
 * @param[in] pDhcp6c Pointer to the DHCP client structure containing lease information.
 *
 * @return void
 */
static void configureNetworkInterface(PCOSA_DML_DHCPCV6_FULL pDhcp6c)
{
    if (pDhcp6c == NULL || pDhcp6c->currentLease == NULL) 
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid DHCP client structure or current lease is NULL.\n", __FUNCTION__, __LINE__);
        return;
    }

    const char *interface = pDhcp6c->Cfg.Interface;
    const char *ipv6Address = pDhcp6c->currentLease->ia_na.address;
    uint32_t preferedLifeTime = pDhcp6c->currentLease->ia_na.PreferedLifeTime;
    uint32_t validLifeTime = pDhcp6c->currentLease->ia_na.ValidLifeTime;
    // Set lifetime strings based on timeout values
    char preferredLftStr[20] = {0};
    char validLftStr[20] = {0};

    if (preferedLifeTime == 0 || preferedLifeTime == UINT32_MAX) 
    {
        strncpy(preferredLftStr, "forever", sizeof(preferredLftStr) - 1); // Infinite preferred lifetime
    }
    else
    {
        snprintf(preferredLftStr, sizeof(preferredLftStr), "%u", preferedLifeTime);
    }

    if (validLifeTime == 0 || validLifeTime == UINT32_MAX) 
    {
        strncpy(validLftStr, "forever", sizeof(validLftStr) - 1); // Infinite preferred lifetime
    }
    else
    {
        snprintf(validLftStr, sizeof(validLftStr), "%u", validLifeTime);
    }

    // Log the configuration details
    DHCPMGR_LOG_INFO("%s %d: Configuring interface %s with IPv6 address %s\n", __FUNCTION__, __LINE__, interface, ipv6Address);
    DHCPMGR_LOG_INFO("%s %d: PreferedLifeTime: %s, ValidLifeTime: %s\n", __FUNCTION__, __LINE__, preferredLftStr, validLftStr);

    // Use system calls or platform-specific APIs to configure the network interface
    char command[256];
    snprintf(command, sizeof(command), "ip -6 addr add %s dev %s preferred_lft %s valid_lft %s", ipv6Address, interface, preferredLftStr, validLftStr);
    int ret = v_secure_system("ip -6 addr add %s dev %s preferred_lft %s valid_lft %s", ipv6Address, interface, preferredLftStr, validLftStr);
    if (ret != 0) 
    {
        DHCPMGR_LOG_ERROR("%s %d: Failed to configure IPv6 address on interface %s. Command: %s\n", __FUNCTION__, __LINE__, interface, command);
    }

    return;
}

/**
 * @brief Clears the current DHCPv6 lease information.
 *
 * This function frees the memory allocated for the current DHCPv6 lease and resets
 * the lease-related fields in the DHCP client structure.
 *
 * @param[in] pDhcp6c Pointer to the DHCPv6 client structure containing lease information.
 *
 * @return void
 */
void DhcpMgr_clearDHCPv6Lease(PCOSA_DML_DHCPCV6_FULL pDhcp6c)
{
    if (pDhcp6c == NULL) 
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid DHCPv6 client structure.\n", __FUNCTION__, __LINE__);
        return;
    }

    if (pDhcp6c->currentLease != NULL) 
    {
        DHCPMGR_LOG_INFO("%s %d: Clearing current DHCPv6 lease for interface %s.\n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);

        // Free the memory allocated for the current lease
        free(pDhcp6c->currentLease);
        pDhcp6c->currentLease = NULL;
    }

    DHCPMGR_LOG_INFO("%s %d: Clearing NewLeases linked list for %s \n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
    // Free all leases in the NewLeases linked list
    DHCPv6_PLUGIN_MSG *lease = pDhcp6c->NewLeases;
    while (lease != NULL) 
    {
        DHCPv6_PLUGIN_MSG *nextLease = lease->next;
        free(lease);
        lease = nextLease;
    }
    pDhcp6c->NewLeases = NULL;

    DHCPMGR_LOG_INFO("%s %d: DHCPv6 lease cleared for interface %s.\n", __FUNCTION__, __LINE__, pDhcp6c->Cfg.Interface);
}
