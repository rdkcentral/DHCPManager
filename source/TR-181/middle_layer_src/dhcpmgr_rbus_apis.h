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

#ifndef _DHCPMGR_RBUS_H_
#define _DHCPMGR_RBUS_H_
#include <rbus/rbus.h>
#include "cosa_apis.h"


#define DHCP_MGR_DHCPv4_STATUS "Device.DHCPv4.Client.{i}.Status"

ANSC_STATUS DhcpMgr_Rbus_Init();

#endif// _DHCPMGR_RBUS_H_
