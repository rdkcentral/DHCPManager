
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
