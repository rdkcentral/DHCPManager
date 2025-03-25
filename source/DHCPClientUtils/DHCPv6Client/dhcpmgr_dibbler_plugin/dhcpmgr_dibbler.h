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

#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>
#include "dhcp_lease_monitor_thrd.h"

#define LEASE_MONITOR_SOCKET                 "tcp://127.0.0.1:50324"
#define MAX_SEND_THRESHOLD                   5
#define BUFLEN_128                           128
 
#define DHCPv6_INTERFACE_NAME                "IFACE"
#define DHCPv6_IANA_ADDRESS                  "ADDR1"
#define DHCPv6_IANA_IAID                     "ADDR1IAID"
#define DHCPv6_IANA_PREF_LIFETIME            "ADDR1PREF"
#define DHCPv6_IANA_VALID_LIFETIME           "ADDR1VALID"
#define DHCPv6_IANA_T1                       "ADDR1T1"
#define DHCPv6_IANA_T2                       "ADDR1T2"
#define DHCPv6_IAPD_PREFIX                   "PREFIX1"
#define DHCPv6_IAPD_PREFIXLEN                "PREFIX1LEN"
#define DHCPv6_IAPD_IAID                     "PREFIX1IAID"
#define DHCPv6_IAPD_PREF_LIFETIME            "PREFIX1PREF"
#define DHCPv6_IAPD_VALID_LIFETIME           "PREFIX1VALID"
#define DHCPv6_IAPD_T1                       "PREFIX1T1"
#define DHCPv6_IAPD_T2                       "PREFIX1T2"
#define DHCPv6_OPTION_DNS                    "SRV_OPTION23"
#define DHCPv6_OPTION_DOMAIN                 "SRV_OPTION24"
#define DHCPv6_OPTION_NTP                    "SRV_OPTION31"
#define DHCPv6_OPTION_DSLITE                 "SRV_OPTION64"
#define DHCPv6_OPTION_MAPT                   "SRV_OPTION95" 
