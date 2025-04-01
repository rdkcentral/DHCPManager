
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

#include "dhcpmgr_custom_options.h"
#include "util.h"

static int DhcpMgr_Option17Set_Common(const char *ifName, const char *OptionValue);

// Weak function implementations
__attribute__((weak)) int Get_DhcpV4_CustomOption60(const char *ifName, char *OptionValue) 
{
    (void)ifName;
    (void)OptionValue;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV4_CustomOption60 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Get_DhcpV4_CustomOption61(const char *ifName, char *OptionValue) 
{
    (void)ifName;
    (void)OptionValue;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV4_CustomOption61 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Get_DhcpV6_CustomOption15(const char *ifName, char *OptionValue) 
{
    (void)ifName;
    (void)OptionValue;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV6_CustomOption15 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Get_DhcpV6_CustomOption16(const char *ifName, char *OptionValue) 
{
    (void)ifName;
    (void)OptionValue;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV6_CustomOption16 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Get_DhcpV6_CustomOption17(const char *ifName, char *OptionValue) 
{
    (void)ifName;
    (void)OptionValue;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV6_CustomOption17 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Set_DhcpV6_CustomOption17(const char *ifName, const char *OptionValue)
{
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Set_DhcpV6_CustomOption17 \n", __FUNCTION__, __LINE__);
    return DhcpMgr_Option17Set_Common(ifName, OptionValue);
}

__attribute__((weak)) int Get_DhcpV4_CustomOption43(const char *ifName, char *OptionValue) 
{
    (void)ifName;
    (void)OptionValue;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Get_DhcpV4_CustomOption43 \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int Set_DhcpV4_CustomOption43(const char *ifName, const char *OptionValue)
{
    (void)ifName;
    (void)OptionValue;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of Set_DhcpV4_CustomOption43 \n", __FUNCTION__, __LINE__);
    return -1;
}


/**
 * @brief Processes and sets DHCP Option 17 suboptions for a given interface.
 *
 * This function parses the provided OptionValue string, extracts suboptions, 
 * and sets corresponding system events based on the suboption type and value.
 *
 * @param[in] ifName The name of the network interface. Must not be NULL.
 * @param[in] OptionValue The DHCP Option 17 value string. Must not be NULL.
 *
 * @return 0 on success, -1 on failure (e.g., invalid arguments or memory allocation failure).
 *
 * @details
 * - The function expects the OptionValue string to contain suboptions in the format 
 *   "suboption=value", separated by spaces.
 * - Supported suboptions include:
 *   - "vendor": Sets the "ipv6-vendor-id" system event.
 *   - "38": Sets the "ipv6-timeoffset" system event.
 *   - "39": Sets the "wan6_ippref" and optionally "MTA_IP_PREF" system events.
 *   - "2": Sets the "ipv6-device-type" system event.
 *   - "3": Sets the "ipv6-embd-comp-in-device" system event.
 *   - "2170" and "2171": Parses nested suboptions and sets primary/secondary 
 *     address system events for IPv4 or IPv6.
 * - If any MTA-related DHCP options are received, the "dhcp_mta_option" system 
 *   event is set to "received".
 * - Memory allocated for tokenization is freed before returning.
 *
 */
//TODO: This function directly sets generic system events. If multiple WAN leases share this information, it may cause conflicts. These system events should be configured specifically for the active interface only.
static int DhcpMgr_Option17Set_Common(const char *ifName, const char *OptionValue)
{
    if (ifName == NULL || OptionValue == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }

    char *token, *suboption, *suboption_data;
    char *srv_option17 = strdup(OptionValue); // Duplicate OptionValue to tokenize
    int mta_dhcp_option_received = 0;

    if (srv_option17 == NULL) {
        DHCPMGR_LOG_ERROR("%s %d: Memory allocation failed..\n", __FUNCTION__, __LINE__);
        return -1;
    }

    token = strtok(srv_option17, " ");
    while (token != NULL) 
    {
        suboption = strtok(token, "=");
        suboption_data = strtok(NULL, "=");

        if (suboption && suboption_data) 
        {
            if (strcmp(suboption, "vendor") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption vendor-id is %s in option %s\n", suboption_data, OptionValue);
                sysevent_set("ipv6-vendor-id", suboption_data);
            } else if (strcmp(suboption, "38") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption TimeOffset is %s in option %s\n", suboption_data, OptionValue);
                sysevent_set("ipv6-timeoffset", suboption_data);
                // Additional processing for TimeOffset can be added here
            } else if (strcmp(suboption, "39") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption IP Mode Preference is %s in option %s\n", suboption_data, OptionValue);
                sysevent_set("wan6_ippref", suboption_data);
                char *mta_ip_pref = sysevent_get("MTA_IP_PREF");
                if (mta_ip_pref == NULL || strlen(mta_ip_pref) == 0) 
                {
                    DHCPMGR_LOG_INFO("Setting MTA_IP_PREF value to %s\n", suboption_data);
                    sysevent_set("MTA_IP_PREF", suboption_data);
                    mta_dhcp_option_received = 1;
                } else 
                {
                    DHCPMGR_LOG_INFO("Mta_Ip_Pref value is already set to %s\n", mta_ip_pref);
                }
            } else if (strcmp(suboption, "2") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption Device Type is %s in option %s\n", suboption_data, OptionValue);
                sysevent_set("ipv6-device-type", suboption_data);
            } else if (strcmp(suboption, "3") == 0) 
            {
                DHCPMGR_LOG_INFO("Suboption List of Embedded Components in eDOCSIS Device is %s in option %s\n", suboption_data, OptionValue);
                sysevent_set("ipv6-embd-comp-in-device", suboption_data);
            } else if (strcmp(suboption, "2170") == 0 || strcmp(suboption, "2171") == 0) 
            {
                char *parsed_value = parse_dhcp_option(suboption_data, "v6");
                if (parsed_value) 
                {
                    char *val_token = strtok(parsed_value, " ");
                    while (val_token != NULL) 
                    {
                        char *subopt = strtok(val_token, "=");
                        char *subopt_data = strtok(NULL, "=");
                        if (subopt && subopt_data) {
                            if (strcmp(subopt, "0001") == 0) 
                            {
                                char *primary_address = (strcmp(suboption, "2170") == 0) ? 
                                    sysevent_get("MTA_DHCPv4_PrimaryAddress") : sysevent_get("MTA_DHCPv6_PrimaryAddress");
                                
                                    if (primary_address == NULL || strlen(primary_address) == 0) 
                                {
                                    DHCPMGR_LOG_INFO("Setting PrimaryAddress value as %s\n", subopt_data);
                                    sysevent_set((strcmp(suboption, "2170") == 0) ? "MTA_DHCPv4_PrimaryAddress" : "MTA_DHCPv6_PrimaryAddress", subopt_data);
                                    mta_dhcp_option_received = 1;
                                }
                            } else if (strcmp(subopt, "0002") == 0) 
                            {
                                char *secondary_address = (strcmp(suboption, "2170") == 0) ? 
                                    sysevent_get("MTA_DHCPv4_SecondaryAddress") : sysevent_get("MTA_DHCPv6_SecondaryAddress");
                                
                                    if (secondary_address == NULL || strlen(secondary_address) == 0) 
                                {
                                    DHCPMGR_LOG_INFO("Setting SecondaryAddress value as %s\n", subopt_data);
                                    sysevent_set((strcmp(suboption, "2170") == 0) ? "MTA_DHCPv4_SecondaryAddress" : "MTA_DHCPv6_SecondaryAddress", subopt_data);
                                    mta_dhcp_option_received = 1;
                                }
                            }
                        }
                        val_token = strtok(NULL, " ");
                    }
                    free(parsed_value);
                }
            }
        }
        token = strtok(NULL, " ");
    }

    if (mta_dhcp_option_received) 
    {
        DHCPMGR_LOG_INFO("Setting dhcp_mta_option event as received\n");
        sysevent_set("dhcp_mta_option", "received");
    }

    free(srv_option17);
    return 0;
}