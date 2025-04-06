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
    * @param ifname The name of the interface.
    * @param newLease A pointer to the new DHCP lease information.
    * @param dhcpVersion The version of DHCP (4 or 6).
    * @param instanceNum The instance number of the DHCP client.
    * @return int Returns 0 on success, or a negative error code on failure.
    */
int DHCPMgr_storeDhcpLease(char* ifname, void*  newLease, int dhcpVersion);

#endif /* _DHCPMGR_RECOVERY_HANDLER_H_ */
