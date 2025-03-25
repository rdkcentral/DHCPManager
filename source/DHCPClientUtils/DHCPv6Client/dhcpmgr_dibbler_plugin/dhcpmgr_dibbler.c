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

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "dhcp_lease_monitor_thrd.h"
#include "dhcpmgr_dibbler.h"
 
typedef struct dibbler_env_t
{
    char *input_option;
}dibbler_env_t;
 
static int init_dibbler_env(dibbler_env_t *pinfo, char *option)
{
    if (!pinfo) 
    {
        return -1;
    }

    memset(pinfo, 0, sizeof(struct dibbler_env_t));
    pinfo->input_option = option;
 
    return 0;
}
 
static int get_and_fill_env_data_dhcp6(DHCPv6_PLUGIN_MSG *dhcpv6_data, dibbler_env_t *pinfo)
{
    char *env;
 
    if (dhcpv6_data == NULL || pinfo == NULL)
    {
        DHCPMGR_LOG_INFO("[%s-%d] Invalid argument", __FUNCTION__, __LINE__);
        return -1;
    }
 
    /** Interface name */
    if ((env = getenv(DHCPv6_INTERFACE_NAME)) != NULL)
    {
        strncpy(dhcpv6_data->ifname, env, sizeof(dhcpv6_data->ifname));
    }
    else
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Interface name is missing\n", __FUNCTION__, __LINE__);
    }
 
    /** DHCP Lease state */
    if (pinfo->input_option != NULL)
    {
        if (strcmp(pinfo->input_option, "bound") == 0 || strcmp(pinfo->input_option, "renew") == 0 || strcmp(pinfo->input_option, "rebind") == 0)
        {
            dhcpv6_data->isExpired = false;
        }
        else if (strcmp(pinfo->input_option, "decline") == 0 || strcmp(pinfo->input_option, "expire") == 0 || strcmp(pinfo->input_option, "release") == 0)
        {
            dhcpv6_data->isExpired = true;
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Unknown DHCPv6 state: %s\n", __FUNCTION__, __LINE__, pinfo->input_option);
        }
    }
    else
    {
        DHCPMGR_LOG_ERROR("[%s-%d] DHCPv6 state is missing\n", __FUNCTION__, __LINE__);
    }
 
    /** IA_NA (Non-temporary address) */
    if ((env = getenv(DHCPv6_IANA_ADDRESS)) != NULL)
    {
        strncpy(dhcpv6_data->ia_na.address, env, sizeof(dhcpv6_data->ia_na.address));
    }
 
    if ((env = getenv(DHCPv6_IANA_IAID)) != NULL)
    {
        dhcpv6_data->ia_na.IA_ID = (uint32_t) strtol(env, NULL, 10);
    }

    if ((env = getenv(DHCPv6_IANA_PREF_LIFETIME)) != NULL)
    {
        dhcpv6_data->ia_na.PreferedLifeTime = (uint32_t) strtol(env, NULL, 10);
    }
 
    if ((env = getenv(DHCPv6_IANA_VALID_LIFETIME)) != NULL)
    {
        dhcpv6_data->ia_na.ValidLifeTime = (uint32_t) strtol(env, NULL, 10);
    }
 
    if ((env = getenv(DHCPv6_IANA_T1)) != NULL)
    {
        dhcpv6_data->ia_na.T1 = (uint32_t) strtol(env, NULL, 10);
    }
 
    if ((env = getenv(DHCPv6_IANA_T2)) != NULL)
    {
        dhcpv6_data->ia_na.T2 = (uint32_t) strtol(env, NULL, 10);
    }
 
    /** IA_PD (Prefix delegation) */
    if ((env = getenv(DHCPv6_IAPD_PREFIX)) != NULL)
    {
        strncpy(dhcpv6_data->ia_pd.Prefix, env, sizeof(dhcpv6_data->ia_pd.Prefix));
    }
 
    if ((env = getenv(DHCPv6_IAPD_PREFIXLEN)) != NULL)
    {
        dhcpv6_data->ia_pd.PrefixLength = (uint32_t) strtol(env, NULL, 10);
    }
 
    if ((env = getenv(DHCPv6_IAPD_IAID)) != NULL)
    {
        dhcpv6_data->ia_pd.IA_ID = (uint32_t) strtol(env, NULL, 10);
    }
 
    if ((env = getenv(DHCPv6_IAPD_PREF_LIFETIME)) != NULL)
    {
        dhcpv6_data->ia_pd.PreferedLifeTime = (uint32_t) strtol(env, NULL, 10);
    }
 
    if ((env = getenv(DHCPv6_IAPD_VALID_LIFETIME)) != NULL)
    {
        dhcpv6_data->ia_pd.ValidLifeTime = (uint32_t) strtol(env, NULL, 10);
    }
 
    if ((env = getenv(DHCPv6_IAPD_T1)) != NULL)
    {
        dhcpv6_data->ia_pd.T1 = (uint32_t) strtol(env, NULL, 10);
    }
 
    if ((env = getenv(DHCPv6_IAPD_T2)) != NULL)
    {
        dhcpv6_data->ia_pd.T2 = (uint32_t) strtol(env, NULL, 10);
    }
 
    /** DNS servers */
    if ((env = getenv("DNS_SERVERS")) != NULL) 
    {
        char dns[256];
        char *tok = NULL, *saveptr = NULL;
        snprintf(dns, sizeof(dns), "%s", env);
 
        tok = strtok_r(dns, " ", &saveptr);
        if (tok) 
        {
            strncpy(dhcpv6_data->dns.nameserver, tok, sizeof(dhcpv6_data->dns.nameserver));
        }
         
	tok = strtok_r(NULL, " ", &saveptr);
        if (tok) 
	{
            strncpy(dhcpv6_data->dns.nameserver1, tok, sizeof(dhcpv6_data->dns.nameserver1));
        }
        dhcpv6_data->dns.assigned = true;
    }
    else
    {
        DHCPMGR_LOG_INFO("[%s-%d] DNS servers are missing\n", __FUNCTION__, __LINE__);
    }
 
    /** Domain Name */
    if ((env = getenv(DHCPv6_OPTION_DOMAIN)) != NULL)
    {
        strncpy(dhcpv6_data->domainName, env, sizeof(dhcpv6_data->domainName));
    }
    else
    {
        DHCPMGR_LOG_INFO("[%s-%d] Domain name is missing\n", __FUNCTION__, __LINE__);
    }
 
    /** NTP Server */
    if ((env = getenv(DHCPv6_OPTION_NTP)) != NULL)
    {
        strncpy(dhcpv6_data->ntpserver, env, sizeof(dhcpv6_data->ntpserver));
    }
    else
    {
        DHCPMGR_LOG_INFO("[%s-%d] NTP server is missing\n", __FUNCTION__, __LINE__);
    }
 
    /** AFTR (Access Gateway for DS-Lite) */
    if ((env = getenv(DHCPv6_OPTION_DSLITE)) != NULL)
    {
        strncpy(dhcpv6_data->aftr, env, sizeof(dhcpv6_data->aftr));
    }
    else
    {
        DHCPMGR_LOG_INFO("[%s-%d] AFTR name is missing\n", __FUNCTION__, __LINE__);
    }
 
    /** MAP-T Configuration */
    if ((env = getenv(DHCPv6_OPTION_MAPT)) != NULL)
    {
        strncpy((char *) dhcpv6_data->mapt.Container, env, sizeof(dhcpv6_data->mapt.Container));
        dhcpv6_data->mapt.Assigned = true;
    }
    else
    {
        DHCPMGR_LOG_INFO("[%s-%d] MAP-T configuration is missing\n", __FUNCTION__, __LINE__);
    }
 
    return 0;
}
 
static  int send_dhcp6_data_to_leaseMonitor (DHCPv6_PLUGIN_MSG *dhcpv6_data)
{
    if ( NULL == dhcpv6_data)
    {
        DHCPMGR_LOG_INFO ("[%s-%d] Invalid argument\n", __FUNCTION__, __LINE__);
        return -1;
    }

    /**
     * Send data to dhcpmanager.
     */
    PLUGIN_MSG msg;
    memset(&msg, 0, sizeof(PLUGIN_MSG));

    strcpy(msg.ifname, dhcpv6_data->ifname);
    msg.version = DHCP_VERSION_6;
    memcpy(&msg.data.dhcpv6, dhcpv6_data, sizeof(DHCPv6_PLUGIN_MSG));
 
    int sock   = -1;
    int conn   = -1;
    int bytes  = -1;
    int sz_msg = sizeof(PLUGIN_MSG);
 
    sock = nn_socket(AF_SP, NN_PUSH);
    if (sock < 0)
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to create the socket , error = [%d][%s]\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        return -1;
    }
 
    DHCPMGR_LOG_INFO("[%s-%d] Created socket endpoint \n", __FUNCTION__, __LINE__);
 
    conn = nn_connect(sock, LEASE_MONITOR_SOCKET);
    if (conn < 0)
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to connect to the dhcpmanager [%s], error= [%d][%s] \n", __FUNCTION__, __LINE__, LEASE_MONITOR_SOCKET,errno, strerror(errno));
        nn_close(sock);
        return -1;
    }
 
    DHCPMGR_LOG_INFO("[%s-%d] Connected to server socket [%s] \n", __FUNCTION__, __LINE__,LEASE_MONITOR_SOCKET);
 
    for (int i = 0; i < MAX_SEND_THRESHOLD; i++)
    {
        bytes = nn_send(sock, (char *) &msg, sz_msg, 0);
        if (bytes < 0)
        {
            sleep(1);
            DHCPMGR_LOG_ERROR("[%s-%d] Failed to send data to the dhcpmanager error=[%d][%s] \n", __FUNCTION__, __LINE__,errno, strerror(errno));
        }
        else
            break;
    }

    DHCPMGR_LOG_INFO("Successfully send %d bytes to dhcpmanager \n", bytes);
    nn_close(sock);
    return 0;
}
 
static int handle_dibbler_event(dibbler_env_t *pinfo)
{
    if (pinfo == NULL)
    {
        DHCPMGR_LOG_ERROR("[%s][%d] Invalid argument error!!! \n", __FUNCTION__, __LINE__);
        return -1;
    }

    DHCPMGR_LOG_INFO("[%s][%d] Received [%s] event from Dibbler \n", __FUNCTION__, __LINE__, pinfo->input_option);
 
    int ret = 0;
    DHCPv6_PLUGIN_MSG data;
    memset(&data, 0, sizeof(data));
 
    ret = get_and_fill_env_data_dhcp6(&data, pinfo);
    if (ret != 0)
    {
        DHCPMGR_LOG_ERROR("[%s][%d] Failed to get DHCPv6 data from environment \n", __FUNCTION__, __LINE__);
        return -1;
    }
 
    // Send DHCPv6 data to lease monitor
    ret = send_dhcp6_data_to_leaseMonitor(&data);
    if (ret != 0)
    {
        DHCPMGR_LOG_ERROR("[%s][%d] Failed to send DHCPv6 data to leaseMonitor \n", __FUNCTION__, __LINE__);
        return -1;
    }
 
    return ret;
}
 
int main(int argc, char *argv[])
{
    dibbler_env_t info;
 
    // Validate arguments
    if (argc < 2 || !argv || !argv[1] || strlen(argv[1]) == 0)
    {
        DHCPMGR_LOG_ERROR ("%s:%d Invalid arguments\n", __FUNCTION__,__LINE__);
        return -1;
    }
 
    printf("Dibbler Plugin: Received event %s\n", argv[1]);
 
    // Initialize the Dibbler environment structure
    if (init_dibbler_env(&info, argv[1]) != 0)
    {
        DHCPMGR_LOG_ERROR ("%s:%d Failed to initialize dibbler environment\n",__FUNCTION__,__LINE__);
        return -1;
    }
 
    // Handle specific DHCPv6 events // Need to review the DHCPv6 states
    if (!strcmp(argv[1], "bound") || !strcmp(argv[1], "renew") || !strcmp(argv[1], "release") || !strcmp(argv[1], "decline") || !strcmp(argv[1], "rebind") || !strcmp(argv[1], "expire"))
    {
 
        if (handle_dibbler_event(&info) != 0)
        {
            DHCPMGR_LOG_INFO ("%s:%d handle_event failed for %s\n",__FUNCTION__,__LINE__,argv[1]);
        }
    }
 
    return 0;
} 
