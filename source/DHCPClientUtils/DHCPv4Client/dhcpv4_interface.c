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

#include "dhcpv4_interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

// Weak function implementations
__attribute__((weak)) pid_t start_dhcpv4_client(char *interfaceName, dhcp_opt_list *req_opt_list, dhcp_opt_list *send_opt_list) 
{
    (void)interfaceName;
    (void)req_opt_list;
    (void)send_opt_list;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of start_dhcpv4_client \n", __FUNCTION__, __LINE__);
    return 1;
}

__attribute__((weak)) int send_dhcpv4_renew(pid_t processID) 
{
    (void)processID;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of send_dhcpv4_renew \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int send_dhcpv4_release(pid_t processID) 
{
    (void)processID;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of send_dhcpv4_release \n", __FUNCTION__, __LINE__);
    return -1;

}

__attribute__((weak)) int stop_dhcpv4_client(pid_t processID) 
{
    (void)processID;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of stop_dhcpv4_client \n", __FUNCTION__, __LINE__);
    return -1;
}
