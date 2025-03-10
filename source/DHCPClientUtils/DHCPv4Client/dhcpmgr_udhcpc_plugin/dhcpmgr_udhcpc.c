#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "udhcpc_msg.h"

typedef struct udhcpc_env_t
{
    char *wan_type;
    char *box_type;
    char *model_num;
    char *input_option; 
    char *dns;
    char *router;
    bool broot_is_nfs;
}udhcpc_env_t;

static char *GetDeviceProperties (char *param)
{
    FILE *fp1=NULL;
    char *valPtr = NULL;
    char out_val[BUFLEN_128]={0};
    if (!param)
        return NULL;
    fp1 = fopen("/etc/device.properties", "r");
    if (fp1 == NULL)
    {
        DHCPMGR_LOG_INFO("Error opening properties file!");
        return NULL;
    }

    while (fgets(out_val,BUFLEN_128, fp1) != NULL)
    {
        if (strstr(out_val, param) != NULL)
        {
            out_val[strcspn(out_val, "\r\n")] = 0; // Strip off any carriage returns

            valPtr = strstr(out_val, "=");
            if (valPtr != NULL)
            {
               valPtr++;
               break;
            }
        }
    }
    fclose(fp1);
    if (valPtr)
    {
       return strdup(valPtr);
    }
    return valPtr;
}

static uint32_t hex2dec(char *hex)
{
    uint32_t decimal = 0, base = 1;
    int length = strlen(hex);
    for(int i = length--; i >= 0; i--)
    {
        if(hex[i] >= '0' && hex[i] <= '9')
        {
            decimal += (hex[i] - 48) * base;
            base *= 16;
        }
        else if(hex[i] >= 'A' && hex[i] <= 'F')
        {
            decimal += (hex[i] - 55) * base;
            base *= 16;
        }
        else if(hex[i] >= 'a' && hex[i] <= 'f')
        {
            decimal += (hex[i] - 87) * base;
            base *= 16;
        }
    }
    DHCPMGR_LOG_INFO("hex[%s] decimal[%u]\n", hex, decimal);
    return decimal;
}

static int read_cmd_output(char *cmd, char *output_buf, int size_buf)
{
    FILE *f = NULL;
    char *pos = NULL;

    if (!cmd || (!output_buf) || (size_buf <= 0))
        return -1;

    f = popen(cmd,"r");
    if(f==NULL){
        return -1;
    }

    fgets(output_buf,size_buf,f);
    /* remove trailing newline */
    if((pos = strrchr(output_buf, '\n')) != NULL)
        *pos = '\0';
     pclose(f);
    return 0;
}

static bool root_is_nfs (void)
{
    int result = -1;
    char out[BUFLEN_128];
    memset(out,0,sizeof(out));
    result = read_cmd_output("sed -n 's/^[^ ]* \([^ ]*) \([^ ]*) .*$/\1 \2/p' /proc/mounts | grep \"^/ \\(nfs\\|smbfs\\|ncp\\|coda\\)$\"",out,BUFLEN_128);
    if ((0 == result) && (strlen(out) > 0))
        return true;
    return false;
}

static int init_udhcpc_env (udhcpc_env_t *pinfo, char *option)
{
    char *dns = NULL;
    char *router = NULL;
    if (!pinfo)
        return -1;
    memset(pinfo,0,sizeof(struct udhcpc_env_t));

    pinfo->broot_is_nfs = root_is_nfs();
    DHCPMGR_LOG_INFO("rootfs %d",pinfo->broot_is_nfs);
    pinfo->input_option = option;
    pinfo->wan_type = GetDeviceProperties("WAN_TYPE");
    pinfo->box_type = GetDeviceProperties("BOX_TYPE");
    pinfo->model_num = GetDeviceProperties("MODEL_NUM");
    dns = getenv("dns");
    router = getenv("router");
    if (dns)
    {
        pinfo->dns = strdup(dns);
    }
    if (router)
    {
        pinfo->router = strdup(router);
    }
    if (pinfo->wan_type)
    {
        DHCPMGR_LOG_INFO("wan_type %s",pinfo->wan_type);
    }
 
    if (pinfo->box_type)
    {
	    DHCPMGR_LOG_INFO("box_type %s",pinfo->box_type);
    }
    return 0;
}

static int get_and_fill_env_data (DHCPv4_PLUGIN_MSG *dhcpv4_data, udhcpc_env_t* pinfo)
{
    char *env;

    if (dhcpv4_data == NULL || pinfo == NULL)
    {
        DHCPMGR_LOG_INFO(" %d Invalid argument",__LINE__);
        return -1;
    }

    if ((env = getenv(DHCP_INTERFACE_NAME)) != NULL)
    {
        strncpy(dhcpv4_data->ifname, env, sizeof(dhcpv4_data->ifname));
    }
	
    //need to handle the else case incase of interface name is null

    if ((env = getenv(DHCP_SIPSRV)) != NULL)
    {
        strncpy(dhcpv4_data->sipSrv, env, sizeof(dhcpv4_data->sipSrv));
    }
 
  //need to handle the else case incase of DHCP_SIPSRV name is null
    if ((env = getenv(DHCP_STATIC_ROUTES)) != NULL)
    {
        strncpy(dhcpv4_data->staticRoutes, env, sizeof(dhcpv4_data->staticRoutes));
    }
   
    //need to handle the else case incase of DHCP_STATIC_ROUTES name is null

    /** DHCP server id */
    if ((env = getenv(DHCP_SERVER_ID)) != NULL)
    {
        strncpy(dhcpv4_data->dhcpServerId, env, sizeof(dhcpv4_data->dhcpServerId));
    }
    else
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Server id is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
    }

    /** DHCP State */
    if (pinfo->input_option != NULL)
    {
        strncpy(dhcpv4_data->dhcpState, pinfo->input_option, sizeof(dhcpv4_data->dhcpState));
    }
    else
    {
        DHCPMGR_LOG_ERROR("[%s-%d] dhcp state is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
    }

    if ( (strcmp(pinfo->input_option, "bound") == 0) || (strcmp(pinfo->input_option, "renew") == 0))
    {
        dhcpv4_data->addressAssigned = 1;
        dhcpv4_data->isExpired = 0;
        /** IP */
        if ((env = getenv(DHCP_IP_ADDRESS)) != NULL)
        {
            strncpy(dhcpv4_data->address, env, sizeof(dhcpv4_data->address));
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] IP address is not available \n", __FUNCTION__,__LINE__);
        }

        /** Subnet mask. */
        if ((env = getenv(DHCP_SUBNET)) != NULL)
        {
            strncpy(dhcpv4_data->netmask, env, sizeof(dhcpv4_data->netmask));
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Subnet is not available \n", __FUNCTION__,__LINE__);
        }

        /** Gateway. */
        if (pinfo->router != NULL)
        {
            strncpy(dhcpv4_data->gateway, pinfo->router, sizeof(dhcpv4_data->gateway));
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] GW address is not available in dhcp ack \n", __FUNCTION__,__LINE__);
        }


        /** DNS server. */
        if (pinfo->dns != NULL)
        {
            char dns[256];
            char *tok = NULL;
            snprintf(dns, sizeof(dns), "%s", pinfo->dns);
            fprintf(stderr, "[%s][%s] \n", dns, getenv(DHCP_DNS_SERVER));

            /** dns server1 */
            tok = strtok (dns, " ");
            if (tok)
            {
                strncpy(dhcpv4_data->dnsServer, tok, sizeof(dhcpv4_data->dnsServer));
            }
            /** dnsserver2 */
            tok = strtok(NULL, " ");
            if (tok)
            {
                strncpy(dhcpv4_data->dnsServer1, tok, sizeof(dhcpv4_data->dnsServer1));
            }
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] DNS server is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** Lease time. */
        if ((env = getenv(DHCP_LEASETIME)) != NULL)
        {
            dhcpv4_data->leaseTime = (uint32_t) atoi(env);
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Lease time is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** Renewel time. */
        if ((env = getenv(DHCP_RENEWL_TIME)) != NULL)
        {
            dhcpv4_data->renewalTime = (uint32_t) atoi(env);
        }
        else if (getenv(DHCP_ACK_OPT58) != NULL)
        {
            dhcpv4_data->renewalTime = (uint32_t) hex2dec(getenv(DHCP_ACK_OPT58));
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Renewl time is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** Rebinding time. */
        if ((env = getenv(DHCP_REBINDING_TIME)) != NULL)
        {
            dhcpv4_data->rebindingTime = (uint32_t) atoi(env);
        }
        else if (getenv(DHCP_ACK_OPT59) != NULL)
        {
            dhcpv4_data->rebindingTime = (uint32_t) hex2dec(getenv(DHCP_ACK_OPT59));
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Rebinding time is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** TimeZone. */
        if ((env = getenv(DHCP_TIMEZONE)) != NULL)
        {
            strncpy(dhcpv4_data->timeZone, env, sizeof(dhcpv4_data->timeZone));
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Timezone is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** Timeoffset. */
        if ((env = getenv(DHCP_TIMEOFFSET)) != NULL)
        {
            dhcpv4_data->timeOffset = (int32_t) atoi(env);
            dhcpv4_data->isTimeOffsetAssigned = 1;
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Timeoffset is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** UpstreamCurrRate. **/
        if ((env = getenv(DHCP_UPSTREAMRATE)) != NULL)
        {
            dhcpv4_data->upstreamCurrRate = (uint32_t) atoi(env);
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Upstreamrate is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** DownsteamCurRrate */
        if ((env = getenv(DHCP_DOWNSTREAMRATE)) != NULL)
        {
            dhcpv4_data->downstreamCurrRate  = (uint32_t) atoi(env);
        }
        else
        {
            DHCPMGR_LOG_ERROR("[%s-%d] Upstreamrate is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }
    }
    else if ((strcmp(pinfo->input_option, "leasefail") == 0))
    {
        /**
         * Lease failed event.
         * Send an expired event since there is no reply from DHCP server.
         */
        dhcpv4_data->isExpired = 1;
        dhcpv4_data->addressAssigned = 0;
    }
    else if ((strcmp(pinfo->input_option, "deconfig") == 0))
    {
        /**
         * Send an expired event since there is no reply from DHCP server.
         */
        dhcpv4_data->isExpired = 1;
        dhcpv4_data->addressAssigned = 0;
    }    

    return 0;
}

static int send_dhcp4_data_to_leaseMonitor (DHCPv4_PLUGIN_MSG *dhcpv4_data)
{
    if ( NULL == dhcpv4_data)
    {
        DHCPMGR_LOG_INFO ("%d Invalid argument",__LINE__);
        return -1;
    }

    /**
     * Send data to dhcpmanager.
     */
    PLUGIN_MSG msg;
    memset(&msg, 0, sizeof(PLUGIN_MSG));

    strcpy(msg.ifname, dhcpv4_data->ifname);
    msg.version = DHCP_VERSION_4;
    memcpy(&msg.data.dhcpv4, dhcpv4_data, sizeof(DHCPv4_PLUGIN_MSG));

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

    conn = nn_connect(sock, DHCP_MANAGER_ADDR);
    if (conn < 0)
    {
        DHCPMGR_LOG_ERROR("[%s-%d] Failed to connect to the dhcpmanager [%s], error= [%d][%s] \n", __FUNCTION__, __LINE__, DHCP_MANAGER_ADDR,errno, strerror(errno));
        nn_close(sock);
        return -1;
    }

    DHCPMGR_LOG_INFO("[%s-%d] Connected to server socket [%s] \n", __FUNCTION__, __LINE__,DHCP_MANAGER_ADDR);

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

static int handle_events (udhcpc_env_t *pinfo)
{
    /**
     * This argument is used when state moves to bound/renew.
     */
    if (pinfo == NULL)
    {
        DHCPMGR_LOG_ERROR("[%s][%d] Invalid argument error!!! \n", __FUNCTION__,__LINE__);
        return -1;
    }
 
    DHCPMGR_LOG_INFO("[%s][%d] Received [%s] event from udhcpc \n", __FUNCTION__,__LINE__,pinfo->input_option);
    int ret = 0;
    DHCPv4_PLUGIN_MSG data;
    memset (&data, 0, sizeof(data));

    ret = get_and_fill_env_data (&data, pinfo);
    if (ret != 0)
    {
        DHCPMGR_LOG_ERROR("[%s][%d] Failed to get dhcpv4 data from envoironment \n", __FUNCTION__,__LINE__);
         return -1;
    }

    /**
     * Print data.
     */
    if(strcmp (pinfo->input_option, "leasefail") || strcmp (pinfo->input_option, "deconfig"))
    {
        DHCPMGR_LOG_INFO("[%s][%d] ===============DHCPv4 Configuration Received==============================\n",__FUNCTION__, __LINE__);
        DHCPMGR_LOG_INFO("[%s][%d] Address assigned = %d \n", __FUNCTION__, __LINE__, data.addressAssigned);
        DHCPMGR_LOG_INFO("[%s][%d] is expired      = %d \n", __FUNCTION__, __LINE__, data.isExpired);
        DHCPMGR_LOG_INFO("[%s][%d] ip              = %s\n",__FUNCTION__, __LINE__, data.address);
        DHCPMGR_LOG_INFO("[%s][%d] mask            = %s \n", __FUNCTION__, __LINE__,data.netmask);
        DHCPMGR_LOG_INFO("[%s][%d] gateway         = %s \n",__FUNCTION__, __LINE__,data.gateway);
        DHCPMGR_LOG_INFO("[%s][%d] dnsserver1      = %s \n",__FUNCTION__, __LINE__, data.dnsServer);
        DHCPMGR_LOG_INFO("[%s][%d] dnsserver2      = %s \n", __FUNCTION__, __LINE__,data.dnsServer1);
        DHCPMGR_LOG_INFO("[%s][%d] Interface       = %s \n",  __FUNCTION__, __LINE__,data.ifname);
        DHCPMGR_LOG_INFO("[%s][%d] Lease time      = %d \n",__FUNCTION__, __LINE__, data.leaseTime);
        DHCPMGR_LOG_INFO("[%s][%d] Renewal Time    = %d \n", __FUNCTION__, __LINE__, data.renewalTime);
        DHCPMGR_LOG_INFO("[%s][%d] Rebinding Time  = %d \n", __FUNCTION__, __LINE__, data.rebindingTime);
        DHCPMGR_LOG_INFO("[%s][%d] Time offset     = %d \n", __FUNCTION__, __LINE__, data.timeOffset);
        DHCPMGR_LOG_INFO("[%s][%d] TimeZone        = %s \n", __FUNCTION__, __LINE__, data.timeZone);
        DHCPMGR_LOG_INFO("[%s][%d] DHCP Server ID  = %s \n", __FUNCTION__, __LINE__, data.dhcpServerId);
        DHCPMGR_LOG_INFO("[%s][%d] DHCP State      = %s \n", __FUNCTION__, __LINE__, data.dhcpState);
    }

    ret = send_dhcp4_data_to_leaseMonitor(&data);
    if (ret != 0)
    {
        DHCPMGR_LOG_ERROR("[%s][%d] Failed to send dhcpv4 data to leaseMonitor \n", __FUNCTION__,__LINE__);
         return -1;
    }
    return ret;
}

int main(int argc, char *argv[])
{
    udhcpc_env_t info;

    if ((argc < 2) || !argv) {
        return -1;
    }
    if (!argv[1])
    {
        return -1;
    }

    DHCPMGR_LOG_INFO ("service_udhcpc arg %s",argv[1]);

    init_udhcpc_env(&info,argv[1]);

    if ((!strcmp (argv[1],"bound")) || (!strcmp (argv[1],"renew")) || !strcmp (argv[1], "leasefail") || !strcmp (argv[1], "deconfig"))
    {    
        if (handle_events(&info) != 0)
        {
            DHCPMGR_LOG_ERROR("%s:%d handle_event failed for %s\n",__FUNCTION__,__LINE__,argv[1]);
        }
    }

    if (info.wan_type)
        free(info.wan_type);
    if (info.box_type)
        free(info.box_type);
    if (info.dns)
        free(info.dns);
    if (info.router)
        free(info.router);

    return 0;
}
