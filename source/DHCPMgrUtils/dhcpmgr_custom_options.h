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

#ifndef DHCP_CUSTOM_OPTIONS_H
#define DHCP_CUSTOM_OPTIONS_H

/**
 * @brief Creates a custom DHCPv4 Option 60 (Vendor Class Identifier) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV4_CustomOption60(const char *ifName, char *OptionValue);

/**
 * @brief Creates a custom DHCPv4 Option 61 (Client Identifier) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV4_CustomOption61(const char *ifName, char *OptionValue);

/**
 * @brief Creates a custom DHCPv6 Option 15 (User Class Option) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV6_CustomOption15(const char *ifName, char *OptionValue);

/**
 * @brief Creates a custom DHCPv6 Option 16 (Vendor Class Option) at runtime.
 *
 * @param[in] ifName The name of the network interface.
 * @param[out] OptionValue The buffer to store the hex-binary encoded option data.
 * @return int 0 on success, non-zero on failure.
 */
int Get_DhcpV6_CustomOption16(const char *ifName, char *OptionValue);


#endif // DHCP_CUSTOM_OPTIONS_H
