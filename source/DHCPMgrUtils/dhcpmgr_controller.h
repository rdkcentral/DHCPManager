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

#ifndef _DHCP_CONTROLLER_H_
#define _DHCP_CONTROLLER_H_

#include "cosa_dhcpv4_apis.h"
#include "dhcpv4_interface.h"
#include "cosa_dhcpv6_apis.h"
#include "dhcpv6_interface.h"

/**
 * @brief Starts the main controller thread.
 *
 * This function initializes and starts the main controller thread for the DHCP Manager.
 *
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int DhcpMgr_StartMainController();

/**
 * @brief Adds a new DHCPv4 lease.
 *
 * This function locates the DHCPv4 client interface using the provided interface name (`ifName`) and updates the `pDhcpc->NewLeases` linked list with the new lease information.
 *  If the operation fails, it frees the memory allocated for the new lease.
 *
 * @param[in] ifName The name of the interface.
 * @param[in] newLease A pointer to the new DHCPv4 lease information.
 */
void DHCPMgr_AddDhcpv4Lease(char * ifName, DHCPv4_PLUGIN_MSG *newLease);

/**
 * @brief Processes new DHCPv4 leases.
 *
 * This function checks for the availability of new leases in the list and processes them if found.
 *
 * @param[in] pDhcpc Pointer to the DHCP client structure containing lease information.
 *
 * @return void
 */
void DhcpMgr_ProcessV4Lease(PCOSA_DML_DHCPC_FULL pDhcpc);

/**
 * @brief Clears all parameters in the TR-181 DML structure.
 *
 * This function resets all the fields in the TR-181 Data Model Layer (DML) structure to their default values.
 *
 * @param[in] pDhcpc Pointer to the DHCP client structure to be cleared.
 *
 * @return void
 */
void DhcpMgr_clearDHCPv4Lease(PCOSA_DML_DHCPC_FULL pDhcpc) ;

/**
 * @brief Adds a new DHCPv6 lease.
 *
 * This function locates the DHCPv6 client interface using the provided interface name (`ifName`) and updates the `pDhcp6c->NewLeases` linked list with the new lease information.
 *  If the operation fails, it frees the memory allocated for the new lease.
 *
 * @param[in] ifName The name of the interface.
 * @param[in] newLease A pointer to the new DHCPv6 lease information.
 */
void DHCPMgr_AddDhcpv6Lease(char * ifName, DHCPv6_PLUGIN_MSG *newLease);

/**
 * @brief Processes new DHCPv6 leases.
 *
 * This function checks for the availability of new leases in the list and processes them if found.
 *
 * @param[in] pDhcpc Pointer to the DHCP client structure containing lease information.
 *
 * @return void
 */
void DhcpMgr_ProcessV6Lease(PCOSA_DML_DHCPCV6_FULL pDhcp6c);

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
void DhcpMgr_clearDHCPv6Lease(PCOSA_DML_DHCPCV6_FULL pDhcp6c);
#endif //_DHCP_CONTROLLER_H_