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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/**
 * C version of "service_wan" scripts:
 * service_wan.sh/dhcp_link.sh/dhcp_wan.sh/static_link.sh/static_wan.sh
 *
 * The reason to re-implement service_wan with C is for boot time,
 * shell scripts is too slow.
 */

/* 
 * since this utility is event triggered (instead of daemon),
 * we have to use some global var to (sysevents) mark the states. 
 * I prefer daemon, so that we can write state machine clearly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "sysevent/sysevent.h"
#include "syscfg/syscfg.h"
#include "util.h"
#include "errno.h"
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <regex.h>
#include <telemetry_busmessage_sender.h>
#include <stdint.h>
#include "secure_wrapper.h"
#include <libnet.h>

#ifdef FEATURE_SUPPORT_ONBOARD_LOGGING
#include <rdk_debug.h>
#define LOGGING_MODULE "Utopia"
#define OnboardLog(...)     rdk_log_onboard(LOGGING_MODULE, __VA_ARGS__)
#else
#define OnboardLog(...)
#endif
#include "print_uptime.h"

#include "ipc_msg.h"

#define RESOLVE_CONF_BIN_FULL_PATH  "/sbin/resolvconf"
#define IP_UTIL_BIN_FULL_PATH "/sbin/ip.iproute2"
#if defined (_XB6_PRODUCT_REQ_) || defined(_CBR_PRODUCT_REQ_) || defined (_XB7_PRODUCT_REQ_)
#define CONSOLE_LOG_FILE "/rdklogs/logs/Consolelog.txt.0"
#else
#define CONSOLE_LOG_FILE   "/rdklogs/logs/ArmConsolelog.txt.0"
#endif

#define RESOLV_CONF "/etc/resolv.conf"
#define RESOLV_CONF_TMP "/tmp/resolv_temp.conf"
#define  BUFSIZE 4196
#define MAX_SEND_THRESHOLD 5

static int            sysevent_fd = -1;
static char          *sysevent_name = "udhcpc";
static token_t        sysevent_token;
static unsigned short sysevent_port;
static char           sysevent_ip[19];
static bool           dns_changed = false;

typedef struct udhcpc_script_t
{
    char *wan_type;
    char *box_type;
    char *model_num;
    char *input_option; 
    char *dns;
    char *router;
    bool resconf_exist; // resolvconf bin
    bool ip_util_exist;
    bool broot_is_nfs;
}udhcpc_script_t;

#define DHCP_INTERFACE_NAME "interface"
#define DHCP_IP_ADDRESS "ip"
#define DHCP_SUBNET "subnet"
#define DHCP_SUBNET_MASK "mask"
#define DHCP_ROUTER_GW "router"
#define DHCP_DNS_SERVER "dns"
#define DHCP_UPSTREAMRATE "upstreamrate"
#define DHCP_DOWNSTREAMRATE "downstreamrate"
#define DHCP_TIMEZONE "timezone"
#define DHCP_TIMEOFFSET "timeoffset"
#define DHCP_LEASETIME "lease"
#define DHCP_RENEWL_TIME "renewaltime"
#define DHCP_ACK_OPT58 "opt58"
#define DHCP_ACK_OPT59 "opt59"
#define DHCP_REBINDING_TIME "rebindingtime"
#define DHCP_SERVER_ID "serverid"
#define DHCP_SIPSRV "sipsrv"
#define DHCP_STATIC_ROUTES "staticroutes"

/**
 * @brief Retrieve DHCPv4 data from environment variables and fill
 * the data structure.
 * @param dhcpv4_data Pointer to ipc_dhcpv4_data_t structure hold data
 * @param pinfo Pointer to udhcpc_script_t contains basic ipv4 info
 * @return 0 on success else returns -1.
 */
static int get_and_fill_env_data (ipc_dhcpv4_data_t *dhcpv4_data, udhcpc_script_t* pinfo);

static int send_dhcp_data_to_dhcpmanager (ipc_dhcpv4_data_t *dhcpv4_data);

static void compare_and_delete_old_dns (udhcpc_script_t *pinfo);
static int read_cmd_output (char *cmd, char *output_buf, int size_buf);
static int set_dns_sysevents (udhcpc_script_t *pinfo);
static int set_router_sysevents (udhcpc_script_t *pinfo);

struct dns_server{
 char data[BUFSIZE+30];

};

static int sysevent_init (void)
{
    snprintf(sysevent_ip, sizeof(sysevent_ip),"%s","127.0.0.1");
    sysevent_port = SE_SERVER_WELL_KNOWN_PORT;
    sysevent_fd =  sysevent_open(sysevent_ip, sysevent_port, SE_VERSION, sysevent_name, &sysevent_token);
    if (sysevent_fd < 0)
        return -1;
    return 0;
}

static void udhcpc_sysevent_close (void)
{
    if (0 <= sysevent_fd)
    {
        sysevent_close(sysevent_fd, sysevent_token);
    }
}

static char *GetDeviceProperties (char *param)
{
    FILE *fp1=NULL;
    char *valPtr = NULL;
    char out_val[100]={0};
    if (!param)
        return NULL;
    fp1 = fopen("/etc/device.properties", "r");
    if (fp1 == NULL)
    {
        DHCPMGR_LOG_INFO("Error opening properties file!");
        return NULL;
    }

    while (fgets(out_val,100, fp1) != NULL)
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

static int handle_defconfig (udhcpc_script_t *pinfo)
{
    int ret = 0;    
#ifdef FEATURE_RDKB_WAN_MANAGER
    /**
     * This argument is used when udhcpc starts, and when a leases is lost.
     */
    if (pinfo == NULL)
    {
        OnboardLog("[%s][%d] Invalid argument error!!! \n", __FUNCTION__,__LINE__);
        return -1;
    }

    OnboardLog("[%s][%d] Received [%s] event from udhcpc \n", __FUNCTION__,__LINE__,pinfo->input_option);
    ipc_dhcpv4_data_t data;
    memset (&data, 0, sizeof(data));

    ret = get_and_fill_env_data (&data, pinfo);
    if (ret != 0)
    {
         OnboardLog("[%s][%d] Failed to get dhcpv4 data from enviornment \n", __FUNCTION__,__LINE__);
         return -1;
    }

    /**
     * Send data to the WanManager.
     */
    ret = send_dhcp_data_to_dhcpmanager(&data);
    if (ret != 0)
    {
         OnboardLog("[%s][%d] Failed to send dhcpv4 data to wanmanager \n", __FUNCTION__,__LINE__);
         return -1;
    }    
#else
    
    if (!pinfo)
        return -1;
  
    char *interface = getenv("interface");
    if (!interface) {
        fprintf(stderr, "getenv interface returned NULL\n");
        return -1;
    }
    if (pinfo->resconf_exist)
    {
        v_secure_system("/sbin/resolvconf -d %s.udhcpc",interface);
    }

    if (!pinfo->broot_is_nfs)
    {
        if (pinfo->ip_util_exist)
        {
            addr_delete_va_arg("-4 dev %s",interface);
            interface_up(interface);
        
        }
        else
        {
		interface_set_ip(interface ,"0.0.0.0");
        }    
    }
#endif
    return ret;
}

int save_dhcp_offer (udhcpc_script_t *pinfo)
{
    char eventname[256];
    char buf[128];
    int result = -1;
    char *interface;
    if (!pinfo)
        return -1;

// Enable for Debugging
#if 0
    DHCPMGR_LOG_INFO("\n interface: %s \n",getenv("interface"));
    DHCPMGR_LOG_INFO("\n ip: %s \n",getenv("ip"));
    DHCPMGR_LOG_INFO("\n subnet: %s \n",getenv("subnet"));
    DHCPMGR_LOG_INFO("\n broadcast: %s \n",getenv("broadcast"));
    DHCPMGR_LOG_INFO("\n lease: %s \n",getenv("lease"));
    DHCPMGR_LOG_INFO("\n router: %s \n",getenv("router"));
    DHCPMGR_LOG_INFO("\n hostname: %s \n",getenv("hostname"));
    DHCPMGR_LOG_INFO("\n domain: %s \n",getenv("domain"));
    DHCPMGR_LOG_INFO("\n siaddr: %s \n",getenv("siaddr"));
    DHCPMGR_LOG_INFO("\n sname: %s \n",getenv("sname"));
    DHCPMGR_LOG_INFO("\n serverid: %s \n",getenv("serverid"));
    DHCPMGR_LOG_INFO("\n tftp: %s \n",getenv("tftp"));
    DHCPMGR_LOG_INFO("\n timezone: %s \n",getenv("timezone"));
    DHCPMGR_LOG_INFO("\n timesvr: %s \n",getenv("timesvr"));
    DHCPMGR_LOG_INFO("\n namesvr: %s \n",getenv("namesvr"));
    DHCPMGR_LOG_INFO("\n ntpsvr: %s \n",getenv("ntpsvr"));
    DHCPMGR_LOG_INFO("\n dns: %s \n",getenv("dns"));
    DHCPMGR_LOG_INFO("\n wins: %s \n",getenv("wins"));
    DHCPMGR_LOG_INFO("\n logsvr: %s \n",getenv("logsvr"));
    DHCPMGR_LOG_INFO("\n cookiesvr: %s \n",getenv("cookiesvr"));
    DHCPMGR_LOG_INFO("\n lprsvr: %s \n",getenv("lprsvr"));
    DHCPMGR_LOG_INFO("\n swapsvr: %s \n",getenv("swapsvr"));
    DHCPMGR_LOG_INFO("\n boot_file: %s \n",getenv("boot_file"));
    DHCPMGR_LOG_INFO("\n bootfile: %s \n",getenv("bootfile"));
    DHCPMGR_LOG_INFO("\n bootsize: %s \n",getenv("bootsize"));
    DHCPMGR_LOG_INFO("\n rootpath: %s \n",getenv("rootpath"));
    DHCPMGR_LOG_INFO("\n ipttl: %s \n",getenv("ipttl"));
    DHCPMGR_LOG_INFO("\n mtuipttl: %s \n",getenv("mtuipttl"));
    DHCPMGR_LOG_INFO("\n vendorspecific: %s \n",getenv("vendorspecific"));
#endif

    interface = getenv("interface");

    compare_and_delete_old_dns(pinfo); //compare and remove old dns configuration from resolv.conf
    snprintf(eventname,sizeof(eventname),"ipv4_%s_ipaddr",interface);
    sysevent_set(sysevent_fd, sysevent_token, eventname, getenv("ip"), 0);

    snprintf(eventname,sizeof(eventname),"ipv4_%s_subnet",interface);
    sysevent_set(sysevent_fd, sysevent_token, eventname, getenv("mask"), 0);

    snprintf(eventname,sizeof(eventname),"ipv4_%s_lease_time",interface);
    sysevent_set(sysevent_fd, sysevent_token, eventname, getenv("lease"), 0);

    snprintf(eventname,sizeof(eventname),"ipv4_%s_dhcp_server",interface);
    sysevent_set(sysevent_fd, sysevent_token, eventname, getenv("serverid"), 0);

    snprintf(eventname,sizeof(eventname),"ipv4_%s_dhcp_state",interface);
    if (pinfo->input_option)
        sysevent_set(sysevent_fd, sysevent_token, eventname, pinfo->input_option, 0);

    snprintf(eventname,sizeof(eventname),"ipv4_%s_start_time",interface);
    memset(buf,0,sizeof(buf));
    result = read_cmd_output("cut -d. -f1 /proc/uptime",buf,sizeof(buf));
    if (result == 0)
    {
        DHCPMGR_LOG_INFO("uptime: %s",buf);
        sysevent_set(sysevent_fd, sysevent_token, eventname, buf, 0);
    }
    set_dns_sysevents(pinfo);
    set_router_sysevents(pinfo);
    return 0;
}

static int set_dns_sysevents (udhcpc_script_t *pinfo)
{
    char dns[256] ;
    char *tok = NULL;
    int dns_n = 0;    
    char eventname[256];
    char val[32];
    char *interface;

    if (!pinfo)
        return -1;
    if (!pinfo->dns)
        return -1;

    interface = getenv("interface");

    snprintf(dns,sizeof(dns),"%s",pinfo->dns);
    tok = strtok(dns, " ");
    if (tok)
    {        
        snprintf(eventname,sizeof(eventname),"ipv4_%s_dns_%d",interface,dns_n);
        sysevent_set(sysevent_fd, sysevent_token, eventname, tok, 0);
        ++dns_n;
    }
    while (NULL != tok)
    {
        tok = strtok(NULL, " ");
        if (tok)
        {
            snprintf(eventname,sizeof(eventname),"ipv4_%s_dns_%d",interface,dns_n);
            sysevent_set(sysevent_fd, sysevent_token, eventname, tok, 0);       
            ++dns_n;
        }
    }
    snprintf(eventname,sizeof(eventname),"ipv4_%s_dns_number",interface);
    snprintf(val,sizeof(val),"%d",dns_n);
    sysevent_set(sysevent_fd, sysevent_token, eventname,val, 0);
    return 0;
}


static int update_ipv4dns (udhcpc_script_t *pinfo)
{
    FILE *fp = NULL;
    char *tok = NULL;
    char *dns = getenv("dns");

    if (!pinfo)
        return -1;

    if (!dns)
        return -1;

    fp = fopen("/tmp/.ipv4dnsserver","w");
    if (NULL == fp)
        return -1;

    DHCPMGR_LOG_INFO ("update resolv confg dns :%s", dns);

    dns = strdup(dns);
    tok = strtok(dns, " ");
    while (NULL != tok)
    {
        DHCPMGR_LOG_INFO ("tok :%s",tok);
        fprintf(fp,"%s\n",tok);
        tok = strtok(NULL, " ");
    }
    fclose(fp);
    free(dns);

    return 0;
}

int update_dns_tofile (udhcpc_script_t *pinfo)
{
    char dns[256];
    char *tok = NULL;
    char buf[256];
    char val[64];
    int result = -1;
  
    if (!pinfo)
        return -1;

    if (!pinfo->dns)
        return -1;
    snprintf(dns,sizeof(dns),"%s",pinfo->dns);
    if ((access("/tmp/.ipv4dnsserver", F_OK) == 0))
    {
        tok = strtok(dns, " ");
        DHCPMGR_LOG_INFO ("dns:%s", pinfo->dns);
        while (NULL != tok)
        {
            snprintf(buf,sizeof(buf),"grep %s /tmp/.ipv4dnsserver",tok);
            memset(val,0,sizeof(val));
            result = read_cmd_output(buf,val,sizeof(val));
	    DHCPMGR_LOG_INFO ("result %d grep:%s",result,val);
            if (0 == result)
            {
                if (strlen(val) <= 0)
                {
                    char utc_time[64];
                    char uptime[64];                
		    result = read_cmd_output("date -u",utc_time,sizeof(utc_time));
                    if (result < 0)
                    {
                        DHCPMGR_LOG_INFO ("[date -u] cmd failed");            
                    }
                    result = read_cmd_output("cut -d. -f1 /proc/uptime", uptime, sizeof(uptime));
	            if (0 == result)
                    {
                        DHCPMGR_LOG_INFO ("uptime  %s tok : %s",uptime,tok);
			OnboardLog("DNS_server_IP_changed:%s\n",uptime);
                        t2_event_s("bootuptime_dnsIpChanged_split", uptime);
                        v_secure_system("echo %s DNS_server_IP_changed:%s >> "CONSOLE_LOG_FILE,utc_time,uptime);
                        v_secure_system("echo %s >> /tmp/.ipv4dnsserver",tok);
                    }

                }
            }
            tok = strtok(NULL, " ");
        }
    }
    else
    {
        update_ipv4dns(pinfo);
    }
    return 0;
}

int add_route (udhcpc_script_t *pinfo)
{
    char router[256];
    char *tok = NULL;
    int metric = 0;
    char *interface;

    if (!pinfo)
        return -1;
    if (!pinfo->router)
        return -1;

    interface = getenv("interface");

    snprintf(router,sizeof(router),"%s",pinfo->router);
    tok = strtok(router, " ");
    if (tok)
    {      
        if (pinfo->ip_util_exist)
        {
            route_add_va_arg("default 0.0.0.0/0 via %s dev %s",tok, interface);
            DHCPMGR_LOG_INFO("route_add_va_arg default 0.0.0.0/0 via %s dev %s",tok, interface);
        }
        else
        {
            route_add_va_arg("default gw %s dev %s metric %d",tok,interface,metric);
	        DHCPMGR_LOG_INFO("router:%s buf: route add default gw %s dev %s metric %d 2>/dev/null",router,tok,interface,metric);
        }
        ++metric;
    }
    while (NULL != tok)
    {
        tok = strtok(NULL, " ");
        if (tok)
        {
            if (pinfo->ip_util_exist)
            {
                route_add_va_arg("default via %s metric %d",tok,metric);
                DHCPMGR_LOG_INFO("router:%s buf:ip route add default via %s metric %d",router,tok,metric);
            }
            else
            {
                route_add_va_arg("default gw %s dev %s metric %d",tok,interface,metric);
                DHCPMGR_LOG_INFO("router:%s buf:route add default gw %s dev %s metric %d 2>/dev/null",router,tok,interface,metric);
            }
            ++metric;
        }
    }
    return 0;
}

int set_wan_sysevents (void)
{
    char *serverid = getenv("serverid");
    char *lease = getenv("lease");
    char *opt58 = getenv("opt58");
    char *opt59 = getenv("opt59");
    char *subnet = getenv("subnet");
    int result = -1;
    if (serverid && strlen(serverid) > 0)
    {
        sysevent_set(sysevent_fd, sysevent_token, "wan_dhcp_svr", serverid, 0);
    }

    if (lease && strlen(lease) > 0)
    {
        char lease_date[64];
        char lease_exp[128];
        char buf[128];
        sysevent_set(sysevent_fd, sysevent_token, "wan_lease_time", lease, 0);        
        result = read_cmd_output("date +\"\%Y.\%m.\%d-\%T\"",lease_date,sizeof(lease_date));
        if (0 == result)
        {
            snprintf(buf,sizeof(buf),"date -d\"%s:%s\" +\"%%Y.%%m.%%d-%%T %%Z\"",lease_date,lease);
            result = read_cmd_output(buf,lease_exp,sizeof(lease_exp));
            if (0 == result)
            {                
                sysevent_set(sysevent_fd, sysevent_token, "wan_lease_expiry", lease_exp, 0);        
            }            
        }
    }

    if (opt58 && strlen(opt58) > 0)
    {
        char lease_date[64];
        char lease_renew[128];
        char buf[128];
        sysevent_set(sysevent_fd, sysevent_token, "wan_renew_time", opt58, 0);        
        result = read_cmd_output("date +\"\%Y.\%m.\%d-\%T\"",lease_date,sizeof(lease_date));
        if (0 == result)
        {
            snprintf(buf,sizeof(buf),"date -d\"%s:0x%s\" +\"%%Y.%%m.%%d-%%T %%Z\"",lease_date,opt58);
            result = read_cmd_output(buf,lease_renew,sizeof(lease_renew));
            if (0 == result)
            {                
                sysevent_set(sysevent_fd, sysevent_token, "wan_lease_renew", lease_renew, 0);
            }            
        }
    }

    if (opt59 && strlen(opt59) > 0)
    {
        char lease_date[64];
        char lease_bind[128];
        char buf[128];
        sysevent_set(sysevent_fd, sysevent_token, "wan_rebind_time", opt59, 0);        
        result = read_cmd_output("date +\"\%Y.\%m.\%d-\%T\"",lease_date,sizeof(lease_date));
        if (0 == result)
        {
            snprintf(buf,sizeof(buf),"date -d\"%s:0x%s\" +\"%%Y.%%m.%%d-%%T %%Z\"",lease_date,opt59);
            result = read_cmd_output(buf,lease_bind,sizeof(lease_bind));
            if (0 == result)
            {                
                sysevent_set(sysevent_fd, sysevent_token, "wan_lease_rebind", lease_bind, 0);
            }            
        }
    }

    if (subnet && strlen(subnet) > 0)
    {
        sysevent_set(sysevent_fd, sysevent_token, "wan_mask", subnet, 0);
    }

    return 0;
}

static int set_router_sysevents (udhcpc_script_t *pinfo)
{
    char router[256];
    char *tok = NULL;
    int gw_n = 0;    
    char eventname[256];
    char val[32];
    char *interface;

    if (!pinfo)
        return -1;

    if (!pinfo->router)
        return -1;

    interface = getenv("interface");

    snprintf(router,sizeof(router),"%s",pinfo->router);
    tok = strtok(router, " ");
    if (tok)
    {        
        snprintf(eventname,sizeof(eventname),"ipv4_%s_gw_%d",interface,gw_n);
        sysevent_set(sysevent_fd, sysevent_token, "default_router", tok, 0);
        sysevent_set(sysevent_fd, sysevent_token, eventname, tok, 0);
        ++gw_n;
    }
    while (NULL != tok)
    {
        tok = strtok(NULL, " ");
        if (tok)
        {
            snprintf(eventname,sizeof(eventname),"ipv4_%s_gw_%d",interface,gw_n);
            sysevent_set(sysevent_fd, sysevent_token, "default_router", tok, 0);
            sysevent_set(sysevent_fd, sysevent_token, eventname, tok, 0);       
            ++gw_n;
        }
    }
    snprintf(eventname,sizeof(eventname),"ipv4_%s_gw_number",interface);
    snprintf(val,sizeof(val),"%d",gw_n);
    sysevent_set(sysevent_fd, sysevent_token, eventname,val, 0);
    return 0;
}

static void compare_and_delete_old_dns (udhcpc_script_t *pinfo)
{
  FILE* fptr = NULL;
  FILE* ftmp = NULL;
  char*  buffer = NULL;
  char *tok = NULL;
  char dns[256]={0};
  int read = 0;
  size_t size = BUFSIZE;
  char INTERFACE[BUFSIZE]={0};
  char dns_server_no_query[BUFSIZE+30]={0};
  char dns_servers_number[BUFSIZE]={0};
  int dns_server_no;
  int i;

  sysevent_get(sysevent_fd, sysevent_token, "wan_ifname", INTERFACE, sizeof(INTERFACE));
  snprintf(dns_server_no_query, sizeof(dns_server_no_query), "ipv4_%s_dns_number", INTERFACE);
  sysevent_get(sysevent_fd, sysevent_token, dns_server_no_query , dns_servers_number, sizeof(dns_servers_number));
  dns_server_no=atoi(dns_servers_number);

  if(!dns_server_no)
  {
        dns_changed=true;
  }

  struct dns_server* dns_server_list = malloc(sizeof(struct dns_server) * dns_server_no);
  for(i=0;i<dns_server_no;i++)
  {
     char nameserver_ip_query[BUFSIZE+30]={0};
     char nameserver_ip[BUFSIZE]={0};
     snprintf(nameserver_ip_query, sizeof(nameserver_ip_query), "ipv4_%s_dns_%d", INTERFACE,i);
     sysevent_get(sysevent_fd, sysevent_token, nameserver_ip_query , nameserver_ip, sizeof(nameserver_ip));
     snprintf(dns_server_list[i].data , sizeof(dns_server_list[i].data),"nameserver %s",nameserver_ip);
  }

  snprintf(dns,sizeof(dns),"%s",pinfo->dns);
  DHCPMGR_LOG_INFO("Comparing old and new ipv4 dns config dns=%s",dns);
  tok = strtok(dns, " ");
  while (NULL != tok && dns_server_no != 0)
  {
        char new_nameserver[BUFSIZE]={0};
        snprintf(new_nameserver,sizeof(new_nameserver),"nameserver %s",tok);
        for(i=0;i<dns_server_no;i++)
        {
                if(strncmp(dns_server_list[i].data,new_nameserver,sizeof(new_nameserver)) !=0)
                {
                        dns_changed=true;
                        DHCPMGR_LOG_INFO("%s is not present in old dns config so resolv_conf file overide form service_udhcp",new_nameserver);
                        break;
                }
        }
        tok = strtok(NULL, " ");
  }

  if(dns_changed)
  {

  fptr  =  fopen(RESOLV_CONF,"r");
  if (fptr  ==  NULL)
  {
    DHCPMGR_LOG_ERROR("Error in opening resolv.conf file in read mode ");
    exit(1);
  }

  ftmp =  fopen(RESOLV_CONF_TMP,"w");
  if (ftmp  ==  NULL)
  {
    DHCPMGR_LOG_ERROR("Error in opening resolv_temp.conf file in write mode");
    exit(1);
  }

  while((read = getline(&buffer, &size, fptr)) != -1)
  {
      char* search_domain = NULL;
      char* search_domain_altrnte = NULL;
      int search_ipv4_dns = 0;

      for(i=0;i<dns_server_no;i++)
      {
              if(strstr(buffer,dns_server_list[i].data) || strstr(buffer,"nameserver 127.0.0.1"))
              {
                      search_ipv4_dns=1;
              }

      }
      if(!dns_server_no && strstr(buffer,"nameserver 127.0.0.1") != NULL)
      {
                search_ipv4_dns=1;
      }



      search_domain = strstr(buffer,"domain");
      search_domain_altrnte = strstr(buffer,"search");
      if(search_domain == NULL && search_domain_altrnte == NULL && !search_ipv4_dns)
      {
          fprintf(ftmp, "%s",buffer);
      }
   }

      fclose(fptr);
      fclose(ftmp);
      buffer = NULL;
      read = 0;
      FILE* fIN = NULL;
      FILE* fout = NULL;

      fout = fopen(RESOLV_CONF,"w");
      if (fout  ==  NULL)
      {
        DHCPMGR_LOG_ERROR("Error in opening resolv.conf file in write mode");
        exit(1);
      }

    fIN =  fopen(RESOLV_CONF_TMP,"r");
    if (fIN  ==  NULL)
    {
      DHCPMGR_LOG_ERROR("Error in opening resolv_temp.conf file in read mode");
      exit(1);
    }
      while((read = getline(&buffer, &size, fIN)) != -1)
      {

            fprintf(fout, "%s",buffer);
      }

      fclose(fout);
      fclose(fIN);
      /* CID 118955: Unchecked return value from library */
      if (remove(RESOLV_CONF_TMP) != 0)
      {
         DHCPMGR_LOG_ERROR("removing resolve_conf_tmp file is failed \n");
         OnboardLog("%s: Unable to delete a file.",__FUNCTION__);
      }
   }
   /* CID 118956: Resource leak */
   if(dns_server_list != NULL)
   {
      free(dns_server_list);
      dns_server_list = NULL;
   }
}

int update_resolveconf (udhcpc_script_t *pinfo)
{
    FILE *fp = NULL;
    char *tok = NULL;
    char dns[256];

    if (!pinfo)
        return -1;

    if (!pinfo->dns)
        return -1;
    snprintf(dns,sizeof(dns),"%s",pinfo->dns);
    fp = fopen(RESOLV_CONF,"a");
    if (NULL == fp)
        {
        DHCPMGR_LOG_ERROR("Error in opening resolv.conf file in append mode");
        return -1;
        }

    fprintf(fp,"domain %s\n",getenv("domain"));
    DHCPMGR_LOG_INFO ("update resolv confg dns :%s", pinfo->dns);
    tok = strtok(dns, " ");
    while (NULL != tok)
    {
        DHCPMGR_LOG_INFO ("tok :%s",tok);
        fprintf(fp,"nameserver %s\n",tok);
        tok = strtok(NULL, " ");
    }
    fclose(fp);
    return 0;
}

#ifdef FEATURE_RDKB_WAN_MANAGER
static int handle_leasefail (udhcpc_script_t *pinfo)
{
    /**
     * This argument is used when udhcpc starts, and when a leases is lost.
     */
    if (pinfo == NULL)
    {
        OnboardLog("[%s][%d] Invalid argument error!!! \n", __FUNCTION__,__LINE__);
        return -1;
    }

    OnboardLog("[%s][%d] Received [%s] event from udhcpc \n", __FUNCTION__,__LINE__,pinfo->input_option);
    int ret = 0;
    ipc_dhcpv4_data_t data;
    memset (&data, 0, sizeof(data));

    ret = get_and_fill_env_data (&data, pinfo);
    if (ret != 0)
    {
         OnboardLog("[%s][%d] Failed to get dhcpv4 data from enviornment \n", __FUNCTION__,__LINE__);
         return -1;
    }

    /**
     * Send data to the DhcpManager.
     */
    ret = send_dhcp_data_to_dhcpmanager(&data);
    if (ret != 0)
    {
         OnboardLog("[%s][%d] Failed to send dhcpv4 data to wanmanager \n", __FUNCTION__,__LINE__);
         return -1;
    }

    return ret;
}
#endif //FEATURE_RDKB_WAN_MANAGER

static int handle_wan (udhcpc_script_t *pinfo)
{
#ifdef FEATURE_RDKB_WAN_MANAGER
    /**
     * This argument is used when state moves to bound/renew.
     */
    if (pinfo == NULL)
    {
        OnboardLog("[%s][%d] Invalid argument error!!! \n", __FUNCTION__,__LINE__);
        return -1;
    }
 
    OnboardLog("[%s][%d] Received [%s] event from udhcpc \n", __FUNCTION__,__LINE__,pinfo->input_option);
    int ret = 0;
    ipc_dhcpv4_data_t data;
    memset (&data, 0, sizeof(data));

    ret = get_and_fill_env_data (&data, pinfo);
    if (ret != 0)
    {
         OnboardLog("[%s][%d] Failed to get dhcpv4 data from envoironment \n", __FUNCTION__,__LINE__);
         return -1;
    }

    /**
     * Print data.
     */
    OnboardLog("[%s][%d] ===============DHCPv4 Configuration Received==============================\n",__FUNCTION__, __LINE__);
    OnboardLog("[%s][%d] Address assigned = %d \n", __FUNCTION__, __LINE__, data.addressAssigned);
    OnboardLog("[%s][%d] is expired      = %d \n", __FUNCTION__, __LINE__, data.isExpired);
    OnboardLog("[%s][%d] ip              = %s\n",__FUNCTION__, __LINE__, data.ip);
    OnboardLog("[%s][%d] mask            = %s \n", __FUNCTION__, __LINE__,data.mask);
    OnboardLog("[%s][%d] gateway         = %s \n",__FUNCTION__, __LINE__,data.gateway);
    OnboardLog("[%s][%d] dnsserver1      = %s \n",__FUNCTION__, __LINE__, data.dnsServer);
    OnboardLog("[%s][%d] dnsserver2      = %s \n", __FUNCTION__, __LINE__,data.dnsServer1);
    OnboardLog("[%s][%d] Interface       = %s \n",  __FUNCTION__, __LINE__,data.dhcpcInterface);
    OnboardLog("[%s][%d] Lease time      = %d \n",__FUNCTION__, __LINE__, data.leaseTime);
    OnboardLog("[%s][%d] Renewal Time    = %d \n", __FUNCTION__, __LINE__, data.renewalTime);
    OnboardLog("[%s][%d] Rebinding Time  = %d \n", __FUNCTION__, __LINE__, data.rebindingTime);
    OnboardLog("[%s][%d] Time offset     = %d \n", __FUNCTION__, __LINE__, data.timeOffset);
    OnboardLog("[%s][%d] TimeZone        = %s \n", __FUNCTION__, __LINE__, data.timeZone);
    OnboardLog("[%s][%d] DHCP Server ID  = %s \n", __FUNCTION__, __LINE__, data.dhcpServerId);
    OnboardLog("[%s][%d] DHCP State      = %s \n", __FUNCTION__, __LINE__, data.dhcpState);

    ret = send_dhcp_data_to_dhcpmanager(&data);
    if (ret != 0)
    {
         OnboardLog("[%s][%d] Failed to send dhcpv4 data to wanmanager \n", __FUNCTION__,__LINE__);
         return -1;
    }
    return ret;
#else
    char router[256];
    char *mask;
    char *ip;
    char *broadcast_ip;
    char *subnet;
    char *interface;
	int ret = 0;

    if (!pinfo)
        return -1;

    snprintf(router, sizeof(router), "%s", (pinfo->router) ? pinfo->router : "");

    save_dhcp_offer(pinfo);

    mask = getenv("mask");
    ip = getenv("ip");
    broadcast_ip = getenv("broadcast");
    subnet = getenv("subnet");
    interface = getenv("interface");

    if (pinfo->ip_util_exist)
    {
	if(broadcast_ip){
                addr_add_va_arg("dev %s %s/%s broadcast %s",interface,ip,mask,broadcast_ip);
	}else{
                addr_add_va_arg("dev %s %s/%s",interface,ip,mask);
        }
        if (mask && ip)
        {
            DHCPMGR_LOG_INFO ("IP is %s and mask is %s",ip, mask);
            sysevent_set(sysevent_fd, sysevent_token, "ipv4_wan_subnet", mask, 0);
            sysevent_set(sysevent_fd, sysevent_token, "ipv4_wan_ipaddr", ip, 0);
        }
        sysevent_set(sysevent_fd, sysevent_token, "current_ipv4_link_state", "up", 0);
        // sysevent_set(sysevent_fd, sysevent_token, "wan_service-status", "started", 0);
        //sysevent_set(sysevent_fd, sysevent_token, "wan-status", "started", 0);
	if (pinfo->wan_type && !strcmp(pinfo->wan_type,"EPON"))
	{
	     print_uptime("Waninit_complete", NULL, NULL);
             creat("/tmp/wan_ready",S_IRUSR |S_IWUSR |S_IRGRP |S_IROTH);
             print_uptime("boot_to_wan_uptime",NULL, NULL);
    	}

    }else{
        if (ip)
        {
            if(broadcast_ip){
		    addr_add_va_arg("dev %s broadcast %s %s/%s",interface,broadcast_ip,ip,subnet);
            DHCPMGR_LOG_INFO("router:%s buf: /sbin/ifconfig %s %s broadcast %s netmask %s",router,interface,ip,broadcast_ip,subnet);
	    }else{
		    addr_add_va_arg("dev %s %s/%s",interface,ip,subnet);
            DHCPMGR_LOG_INFO("router:%s buf:/sbin/ifconfig %s %s netmask %s",router,interface,ip,subnet);
            }
        }
    }

    if (pinfo->box_type && strcmp("XB3",pinfo->box_type))
    {
        if (strlen(router) > 0)
        {
            if (!pinfo->broot_is_nfs)
            {
                if (pinfo->ip_util_exist)
                {
                    v_secure_system("/etc/utopia_ip_route.sh");
                    DHCPMGR_LOG_INFO("Exit ip while");
                }
                else
                {
                    v_secure_system("/etc/utopia_ip_interface.sh %s",interface);
                }
            }        
        }
        add_route(pinfo);
    }

    //Deleting previous ip based rule and adding new rule
    if (pinfo->box_type && (!strcmp("XB3",pinfo->box_type) || (!strcmp("XB6",pinfo->box_type) && !strcmp("TG3482G",pinfo->model_num) )))
    {
        char prev_ip[100];
        sysevent_get(sysevent_fd, sysevent_token, "previous_wan_ipaddr",prev_ip, sizeof(prev_ip));
        DHCPMGR_LOG_INFO("removing ip rule based on prev_ip:%s and adding ip: %s",prev_ip,ip);
        if(strcmp(prev_ip,"") && strcmp(prev_ip,"0.0.0.0"))
        {
                rule_delete_va_arg("-4 from %s lookup erouter",prev_ip);
                rule_delete_va_arg("-4 from %s lookup all_lans",prev_ip);
        }

        rule_add_va_arg("-4 from %s lookup erouter",ip);
        rule_add_va_arg("-4 from %s lookup all_lans",ip);
    }

    // Set default route
    if (pinfo->ip_util_exist)
    {
	route_add_va_arg("default via %s dev %s table erouter",router, interface);
	DHCPMGR_LOG_INFO("Set default route command: ip route add default via %s dev %s table erouter",router, interface);
    }
    else
    {
	route_add_va_arg("default via %s dev %s table erouter",router, interface);
	DHCPMGR_LOG_INFO("Set default route command: route add default via %s dev %s table erouter",router, interface);
    }

    set_wan_sysevents();
    //update .ipv4dnsserver file
    update_dns_tofile(pinfo);

    ipc_dhcpv4_data_t data;
    memset (&data, 0, sizeof(data));

    get_and_fill_env_data (&data, pinfo);
    ret = send_dhcp_data_to_dhcpmanager(&data);
    if (ret != 0)
    {
         OnboardLog("[%s][%d] Failed to send dhcpv4 data to dhcpmanager \n", __FUNCTION__,__LINE__);
    }

    if (pinfo->resconf_exist)
    {
        v_secure_system("/sbin/resolvconf -a %s.udhcpc",interface);
    }
    else   
    {
        //update resolve.conf
        if(dns_changed)
        {
                update_resolveconf(pinfo);

                FILE *fIn=NULL;
                if((fIn = fopen("/tmp/ipv4_renew_dnsserver_restart","r")))
                {
                        fclose(fIn);
                        /*As there is a change in resolv.conf restarting dhcp-server (dnsmasq)*/
                        DHCPMGR_LOG_INFO("As there is a change in resolv.conf restarting dhcp-server (dnsmasq)");
                        sysevent_set(sysevent_fd, sysevent_token, "dhcp_server-stop","", 0);
                        sysevent_set(sysevent_fd, sysevent_token, "dhcp_server-start","", 0);
                }



                creat("/tmp/ipv4_renew_dnsserver_restart",S_IRUSR |S_IWUSR |S_IRGRP |S_IWGRP |S_IROTH |S_IWOTH);
        }
        else
        {
                DHCPMGR_LOG_INFO("Not Adding new IPV4 DNS Config to resolv.conf");
        }
        dns_changed=false; 
        sysevent_set(sysevent_fd, sysevent_token, "dhcp_domain",getenv("domain"), 0);
    }
#endif
    return 0;
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
    char out[128];
    memset(out,0,sizeof(out));
    result = read_cmd_output("sed -n 's/^[^ ]* \([^ ]*) \([^ ]*) .*$/\1 \2/p' /proc/mounts | grep \"^/ \\(nfs\\|smbfs\\|ncp\\|coda\\)$\"",out,128);
    if ((0 == result) && (strlen(out) > 0))
        return true;
    return false;
}

static int init_udhcpc_script_info (udhcpc_script_t *pinfo, char *option)
{
    char *dns = NULL;
    char *router = NULL;
    if (!pinfo)
        return -1;
    memset(pinfo,0,sizeof(struct udhcpc_script_t));
    if ((access(RESOLVE_CONF_BIN_FULL_PATH, F_OK) == 0))
    {
        pinfo->resconf_exist = true;
        DHCPMGR_LOG_INFO("RES conf bin exist");
    }    
    if ((access(IP_UTIL_BIN_FULL_PATH, F_OK) == 0))
    {
        pinfo->ip_util_exist = true;
        DHCPMGR_LOG_INFO("ip bin exist");
    }
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
    OnboardLog("hex[%s] decimal[%u]\n", hex, decimal);
    return decimal;
}

static int get_and_fill_env_data (ipc_dhcpv4_data_t *dhcpv4_data, udhcpc_script_t* pinfo)
{
    char *env;

    if (dhcpv4_data == NULL || pinfo == NULL)
    {
        DHCPMGR_LOG_INFO(" %d Invalid argument",__LINE__);
        return -1;
    }

    if ((env = getenv(DHCP_INTERFACE_NAME)) != NULL)
    {
        strncpy(dhcpv4_data->dhcpcInterface, env, sizeof(dhcpv4_data->dhcpcInterface));
    }
	
    if ((env = getenv(DHCP_SIPSRV)) != NULL)
    {
        strncpy(dhcpv4_data->sipsrv, env, sizeof(dhcpv4_data->sipsrv));
    }

    if ((env = getenv(DHCP_STATIC_ROUTES)) != NULL)
    {
        strncpy(dhcpv4_data->staticroutes, env, sizeof(dhcpv4_data->staticroutes));
    }

    /** DHCP server id */
    if ((env = getenv(DHCP_SERVER_ID)) != NULL)
    {
        strncpy(dhcpv4_data->dhcpServerId, env, sizeof(dhcpv4_data->dhcpServerId));
    }
    else
    {
        OnboardLog("[%s-%d] Server id is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
    }

    /** DHCP State */
    if (pinfo->input_option != NULL)
    {
        strncpy(dhcpv4_data->dhcpState, pinfo->input_option, sizeof(dhcpv4_data->dhcpState));
    }
    else
    {
        OnboardLog("[%s-%d] dhcp state is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
    }

    if ( (strcmp(pinfo->input_option, "bound") == 0) || (strcmp(pinfo->input_option, "renew") == 0))
    {
        dhcpv4_data->addressAssigned = 1;
        dhcpv4_data->isExpired = 0;
        /** IP */
        if ((env = getenv(DHCP_IP_ADDRESS)) != NULL)
        {
            strncpy(dhcpv4_data->ip, env, sizeof(dhcpv4_data->ip));
        }
        else
        {
            OnboardLog("[%s-%d] IP address is not available \n", __FUNCTION__,__LINE__);
        }

        /** Subnet mask. */
        if ((env = getenv(DHCP_SUBNET)) != NULL)
        {
            strncpy(dhcpv4_data->mask, env, sizeof(dhcpv4_data->mask));
        }
        else
        {
            OnboardLog("[%s-%d] Subnet is not available \n", __FUNCTION__,__LINE__);
        }

        /** Gateway. */
        if (pinfo->router != NULL)
        {
            strncpy(dhcpv4_data->gateway, pinfo->router, sizeof(dhcpv4_data->gateway));
        }
        else
        {
            OnboardLog("[%s-%d] GW address is not available in dhcp ack \n", __FUNCTION__,__LINE__);
        }


        /** DNS server. */
        if (pinfo->dns != NULL)
        {
            char dns[256];
            char *tok = NULL;
            snprintf(dns, sizeof(dns), "%s", pinfo->dns);
            strncpy(dhcpv4_data->dnsServer, dns, sizeof(dhcpv4_data->dnsServer));
            fprintf(stderr, "[%s][%s] \n", dns, getenv(DHCP_DNS_SERVER)); 
            if (tok == NULL)
            {
                OnboardLog("%s %d: tok is NULL..\n", __FUNCTION__, __LINE__);
            }

#if 0
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
#endif
        }
        else
        {
            OnboardLog("[%s-%d] DNS server is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** Lease time. */
        if ((env = getenv(DHCP_LEASETIME)) != NULL)
        {
            dhcpv4_data->leaseTime = (uint32_t) atoi(env);
        }
        else
        {
            OnboardLog("[%s-%d] Lease time is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
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
            OnboardLog("[%s-%d] Renewl time is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
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
            OnboardLog("[%s-%d] Rebinding time is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** TimeZone. */
        if ((env = getenv(DHCP_TIMEZONE)) != NULL)
        {
            strncpy(dhcpv4_data->timeZone, env, sizeof(dhcpv4_data->timeZone));
        }
        else
        {
            OnboardLog("[%s-%d] Timezone is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** Timeoffset. */
        if ((env = getenv(DHCP_TIMEOFFSET)) != NULL)
        {
            dhcpv4_data->timeOffset = (int32_t) atoi(env);
            dhcpv4_data->isTimeOffsetAssigned = 1;
        }
        else
        {
            OnboardLog("[%s-%d] Timeoffset is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** UpstreamCurrRate. **/
        if ((env = getenv(DHCP_UPSTREAMRATE)) != NULL)
        {
            dhcpv4_data->upstreamCurrRate = (uint32_t) atoi(env);
        }
        else
        {
            OnboardLog("[%s-%d] Upstreamrate is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
        }

        /** DownsteamCurRrate */
        if ((env = getenv(DHCP_DOWNSTREAMRATE)) != NULL)
        {
            dhcpv4_data->downstreamCurrRate  = (uint32_t) atoi(env);
        }
        else
        {
            OnboardLog("[%s-%d] Upstreamrate is not available in dhcp ack \n",  __FUNCTION__,__LINE__);
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

static int send_dhcp_data_to_dhcpmanager (ipc_dhcpv4_data_t *dhcpv4_data)
{
    if ( NULL == dhcpv4_data)
    {
        DHCPMGR_LOG_INFO ("%d Invalid argument",__LINE__);
        return -1;
    }

    /**
     * Send data to dhcpmanager.
     */
    ipc_msg_payload_t msg;
    memset(&msg, 0, sizeof(ipc_msg_payload_t));

    msg.msg_type = DHCPC_STATE_CHANGED;
    memcpy(&msg.data.dhcpv4, dhcpv4_data, sizeof(ipc_dhcpv4_data_t));

    int sock   = -1;
    int conn   = -1;
    int bytes  = -1;
    int sz_msg = sizeof(ipc_msg_payload_t);

    sock = nn_socket(AF_SP, NN_PUSH);
    if (sock < 0)
    {
        OnboardLog("[%s-%d] Failed to create the socket , error = [%d][%s]\n", __FUNCTION__, __LINE__, errno, strerror(errno));
        return -1;
    }

    OnboardLog("[%s-%d] Created socket endpoint \n", __FUNCTION__, __LINE__);

    conn = nn_connect(sock, DHCP_MANAGER_ADDR);
    if (conn < 0)
    {
        OnboardLog("[%s-%d] Failed to connect to the dhcpmanager [%s], error= [%d][%s] \n", __FUNCTION__, __LINE__, DHCP_MANAGER_ADDR,errno, strerror(errno));
        nn_close(sock);
        return -1;
    }

    OnboardLog("[%s-%d] Connected to server socket [%s] \n", __FUNCTION__, __LINE__,DHCP_MANAGER_ADDR);

    for (int i = 0; i < MAX_SEND_THRESHOLD; i++)
    {
        bytes = nn_send(sock, (char *) &msg, sz_msg, 0);
        if (bytes < 0)
        {
            sleep(1);
            OnboardLog("[%s-%d] Failed to send data to the dhcpmanager error=[%d][%s] \n", __FUNCTION__, __LINE__,errno, strerror(errno));
        }
        else
            break;
    }

    OnboardLog("Successfully send %d bytes to dhcpmanager \n", bytes);
    nn_close(sock);
    return 0;
}

int main(int argc, char *argv[])
{
    udhcpc_script_t info;

    if ((argc < 2) || !argv) {
        return -1;
    }
    if (!argv[1])
    {
        return -1;
    }

    DHCPMGR_LOG_INFO ("service_udhcpc arg %s",argv[1]);
    if (sysevent_init() < 0)
    {
        return -1;
    }    
    init_udhcpc_script_info(&info,argv[1]);
    if (!strcmp (argv[1],"deconfig"))
    {
        handle_defconfig(&info);
    }
    else if ((!strcmp (argv[1],"bound")) || (!strcmp (argv[1],"renew")))
    {    
        handle_wan(&info);
    }
#ifdef FEATURE_RDKB_WAN_MANAGER
    else if( !strcmp (argv[1], "leasefail"))
    {
        /**
         * leasefail.
         */
        handle_leasefail(&info);
    }
#endif

    udhcpc_sysevent_close(); 
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
