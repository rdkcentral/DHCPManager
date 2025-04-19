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

#ifndef _DHCPMGR_RECOVERY_HANDLER_H_
#define _DHCPMGR_RECOVERY_HANDLER_H_

#define DHCP_v4 0
#define DHCP_v6 1

//give brief for DhcpMgr_Dhcp_Recovery_Start

/*
 * @brief Starts the DHCP recovery process.
 * This function initializes and starts the DHCP recovery process for the DHCP Manager.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int DhcpMgr_Dhcp_Recovery_Start();

/*
    * @brief Stores the DHCP lease information in a file.
    * This function stores the DHCP lease information in a file for later retrieval.
    * @param newLease A pointer to the new DHCP lease information.
    * @return int Returns 0 on success, or a negative error code on failure.
    */
int DHCPMgr_storeDhcpv4Lease(PCOSA_DML_DHCPC_FULL  data);
int DHCPMgr_storeDhcpv6Lease(PCOSA_DML_DHCPCV6_FULL  data);

/* 
     *@brief remove the DHCP lease file
     *This function removes the DHCP lease file
     *@param pid of the client process
*/
void remove_dhcp_lease_file(int instanceNumber,int dhcpVersion);


#endif /* _DHCPMGR_RECOVERY_HANDLER_H_ */
