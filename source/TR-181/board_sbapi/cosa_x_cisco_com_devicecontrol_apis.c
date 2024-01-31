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

/**************************************************************************

    module: cosa_x_cisco_com_devicecontrol_apis.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        07/15/2011    initial revision.

**************************************************************************/

#include "cosa_x_cisco_com_devicecontrol_apis.h"
#include "cosa_x_cisco_com_devicecontrol_dml.h"
#include "dml_tr181_custom_cfg.h"
#include "ccsp_dm_api.h"
#include <arpa/inet.h>
#include "platform_hal.h"
#ifdef _MACSEC_SUPPORT_
#include "ccsp_hal_ethsw.h"
#endif
#include "secure_wrapper.h"
#include "cosa_drg_common.h"
#include "ccsp_psm_helper.h"
#include "safec_lib_common.h"

#include "cosa_deviceinfo_apis.h"
#include "ansc_string_util.h"
#include "util.h"
#include "ccsp_trace.h"

#include <string.h>
#include <ctype.h>

#if defined (_XB6_PRODUCT_REQ_) || defined (_XB7_PRODUCT_REQ_)
#define LED_SOLID 0
#define LED_BLINK 1
#define FR_BLINK_INTRVL 3
#endif

extern void* g_pDslhDmlAgent;

PCHAR g_avahi_daemon_conf[] =
{
    "",
    "[server]",
    "#host-name=foo",
    "#domain-name=local",
    "#browse-domains=0pointer.de, zeroconf.org",
    "use-ipv4=yes",
    "use-ipv6=no",
    "allow-interfaces=brlan0",
    "#deny-interfaces=eth1",
    "#check-response-ttl=no",
    "#use-iff-running=no",
    "enable-dbus=no",
    "#disallow-other-stacks=no",
    "#allow-point-to-point=no",
    "#cache-entries-max=4096",
    "#clients-max=4096",
    "#objects-per-client-max=1024",
    "#entries-per-entry-group-max=32",
    "ratelimit-interval-usec=1000000",
    "ratelimit-burst=1000",
    "",
    "[wide-area]",
    "enable-wide-area=yes",
    "",
    "[publish]",
    "#disable-publishing=no",
    "#disable-user-service-publishing=no",
    "#add-service-cookie=no",
    "#publish-addresses=yes",
    "#publish-hinfo=yes",
    "#publish-workstation=yes",
    "#publish-domain=yes",
    "#publish-dns-servers=192.168.50.1, 192.168.50.2",
    "#publish-resolv-conf-dns-servers=yes",
    "#publish-aaaa-on-ipv4=yes",
    "#publish-a-on-ipv6=no",
    "",
    "[reflector]",
    "#enable-reflector=no",
    "#reflect-ipv=no",
    "",
    "[rlimits]",
    "#rlimit-as=",
    "rlimit-core=0",
    "rlimit-data=4194304",
    "rlimit-fsize=0",
    "rlimit-nofile=768",
    "rlimit-stack=4194304",
    "rlimit-nproc=3",
    NULL
};


#define FR_NONE 1
#define FR_WIFI (1<<1)
#define FR_ROUTER (1<<2)
#define FR_FW (1<<3)
#define FR_OTHER (1<<4)

extern ANSC_HANDLE bus_handle;
char   dst_pathname_cr[64]  =  {0};
static componentStruct_t **        ppComponents = NULL;
extern char        g_Subsystem[32];

int fwSync = 0;

#include "arpa/inet.h"

#include <utctx.h>
#include <utctx_api.h>
#include <utapi.h>
#include <utapi_util.h>
#include <ccsp_syslog.h>
#include "syscfg/syscfg.h"

#include "platform_hal.h"
#include "cm_hal.h"

#define HTTPD_CONF      "/var/lighttpd.conf"
#define HTTPD_DEF_CONF  "/etc/lighttpd.conf"
#define HTTPD_PID       "/var/run/lighttpd.pid"
#define RM_L2_PATH "rm -rf /nvram/dl"
#define Device_Config_Ignore_size 1024


static int curticket   = 1; /*The thread should be run with the ticket*/

extern int commonSyseventFd ;
extern token_t commonSyseventToken;

void* set_mesh_disabled();
BOOL is_mesh_enabled();

#if defined (CONFIG_TI_BBU) || defined (CONFIG_TI_BBU_TI)
INT mta_hal_BatteryGetPowerSavingModeStatus(ULONG *pValue);
#endif

#if defined (INTEL_PUMA7)
BOOL moca_factoryReset(void);
#endif

typedef struct WebServConf {
    ULONG       httpport;
    ULONG       httpsport;
} WebServConf_t;

void* WebGuiRestart( void *arg )
{
    UNREFERENCED_PARAMETER(arg);
    pthread_detach(pthread_self());
    sleep(30);
#if defined (_XB6_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
    vsystem("/bin/systemctl restart CcspWebUI.service");
#else
    vsystem("/bin/sh /etc/webgui.sh &");
#endif
    return NULL;
}


#if defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_TURRIS_)
static int
DmSetBool(const char *param, BOOL value)
{
    parameterValStruct_t val[1];
    char crname[256], *fault = NULL;
    int err;

    val[0].parameterName  = (char*)param;
    val[0].parameterValue = (value ? "true" : "false");
    val[0].type           = ccsp_boolean;

    snprintf(crname, sizeof(crname), "%s%s", g_GetSubsystemPrefix(g_pDslhDmlAgent), CCSP_DBUS_INTERFACE_CR);

    if ((err = CcspBaseIf_SetRemoteParameterValue(g_MessageBusHandle,
                                                  crname, param, g_GetSubsystemPrefix(g_pDslhDmlAgent), 0, 0xFFFF, val, 1, 1, &fault)) != CCSP_SUCCESS)

        if (fault)
            AnscFreeMemory(fault);

    return (err == CCSP_SUCCESS) ? 0 : -1;
}
#endif

void* WebServRestart( void *arg )
{
    UNREFERENCED_PARAMETER(arg);
#if 0
    if (access(HTTPD_CONF, F_OK) != 0) {
        if (vsystem("cp %s %s", HTTPD_DEF_CONF, HTTPD_CONF) != 0) {
            DHCPMGR_LOG_INFO("%s: no config file");
            return -1;
        }
    }

    if (vsystem("sed -i ':a;N;$!ba;s#[ \\t]*server.port[ \\t]*=[ 0-9]*#server.port = %d#' %s",
                conf->httpport, HTTPD_CONF) != 0
        || vsystem("sed -i ':a;N;$!ba;s#\\$SERVER\\[[^]]*\\] == \"[^\"]*#$SERVER[\"socket\"] == \":%d\"#' %s",
                   conf->httpsport, HTTPD_CONF) != 0) {
        DHCPMGR_LOG_INFO("%s: fail to set config file");
        return -1;
    }

    if (vsystem("lighttpd -t -f %s", HTTPD_CONF) != 0) {
        DHCPMGR_LOG_INFO("%s: bad config file format");
        return -1;
    }

    if (access(HTTPD_PID, F_OK) == 0) {
        if (vsystem("kill `cat %s`", HTTPD_PID) != 0) {
            DHCPMGR_LOG_INFO("%s: fail to stop lighttpd");
            return -1;
        }
    }

    if (vsystem("lighttpd -f %s", HTTPD_CONF) != 0) {
        DHCPMGR_LOG_INFO("%s: fail to start lighttpd");
        return -1;
    }
#endif
    pthread_detach(pthread_self());
    CcspTraceInfo(("%s vsystem %d \n", __FUNCTION__,__LINE__));
    if (vsystem("/bin/sh /etc/webgui.sh") != 0) {
        DHCPMGR_LOG_INFO("fail to restart lighttpd");
        return NULL;
    }

    v_secure_system("sysevent set firewall-restart");

    return NULL;
}

#ifdef _XF3_PRODUCT_REQ_
static int openCommonSyseventConnection()
{
    if (commonSyseventFd == -1) {
        commonSyseventFd = s_sysevent_connect(&commonSyseventToken);
    }
    return 0;
}
#endif

void _CosaDmlDcStartZeroConfig()
{
    FILE    *fileHandle  = NULL;
    int      i           = 0;

    AnscTraceWarning(("_CosaDmlDcStartZeroConfig -- start avahi.\n"));

    /* If configuration file doesn't exist, create it firstly. */
    fileHandle = fopen(CONFIG_AVAHI_DAEMON_FILENAME, "r" );
    /*fileHandle = fopen("/home/yali3/avahi-daemon.conf", "r" );*/

    if ( !fileHandle )
    {
        fileHandle = fopen(CONFIG_AVAHI_DAEMON_FILENAME, "w+" );
        /*fileHandle = fopen("/home/yali3/avahi-daemon.conf", "w+" );*/

        if (!fileHandle)
        {
            AnscTraceWarning(("_CosaDmlDcStartZeroConfig -- create file:%s, error.\n", CONFIG_AVAHI_DAEMON_FILENAME));
            return;
        }

        do
        {
            fputs(g_avahi_daemon_conf[i], fileHandle);
            fputs("\n", fileHandle);
        }while(g_avahi_daemon_conf[++i]);
    }

    fclose(fileHandle);

    /* Start two daemon */
    v_secure_system(CMD_START_AVAHI_DAEMON);
    v_secure_system(CMD_START_AVAHI_AUTOIPD);

    return;
}

#define _CALC_NETWORK(ip, mask) ((ULONG)(ip) & (ULONG)(mask))

static void getLanMgmtUpnp(UtopiaContext *utctx, BOOLEAN *enable)
{
    int bEnabled;

    if (utctx == NULL || enable == NULL)
        return;

    Utopia_GetBool(utctx, UtopiaValue_Mgmt_IGDEnabled, &bEnabled);

    if (bEnabled){
        *enable = TRUE;
    }else{
        *enable = FALSE;
    }

}

static void setLanMgmtUpnp(UtopiaContext *utctx, BOOLEAN enable)
{
    int bEnabled = (enable == TRUE) ? 1 : 0;

    if (utctx == NULL)
        return;

    Utopia_SetBool(utctx, UtopiaValue_Mgmt_IGDEnabled, bEnabled);
}

static
void _Get_LanMngm_Setting(UtopiaContext *utctx, ULONG index, PCOSA_DML_LAN_MANAGEMENT pLanMngm)
{
    UNREFERENCED_PARAMETER(index);
    lanSetting_t lan;
    ANSC_IPV4_ADDRESS network, netmask, ipaddr;
    bridgeInfo_t bridge_info = {0}; /* initialize before use*/
    int int_tmp;
    napt_mode_t napt_mode;
    /* Till now,just support only one lan interface */
    /* ignor the index */
    Utopia_GetLanMngmInsNum(utctx, &(pLanMngm->InstanceNumber));
    Utopia_GetLanMngmAlias(utctx, pLanMngm->Alias, sizeof(pLanMngm->Alias));
    Utopia_GetBridgeSettings(utctx, &bridge_info);

    /*
     * Configure Bridge Static Mode Configuration
     * if COSA_DML_LanMode_BridgeStatic then BridgeStaticMode then "Advanced Bridge" 2
     * if COSA_DML_LanMode_FullBridgeStatic then BridgeStaticMode then "Primary Bridge" 4
     */

    switch( bridge_info.mode )
    {
    case BRIDGE_MODE_STATIC:
    {
        pLanMngm->LanMode = COSA_DML_LanMode_BridgeStatic;
    }
    break; /* BRIDGE_MODE_STATIC */

    case BRIDGE_MODE_FULL_STATIC:
    {
        pLanMngm->LanMode = COSA_DML_LanMode_FullBridgeStatic;
    }
    break; /* BRIDGE_MODE_FULL_STATIC */

    case BRIDGE_MODE_OFF:
    {
        pLanMngm->LanMode = COSA_DML_LanMode_Router;
    }
    break; /* BRIDGE_MODE_OFF */

    default:
    {
        pLanMngm->LanMode = COSA_DML_LanMode_Router;
    }
    break;
    }

    Utopia_GetLanSettings(utctx, &lan);
    inet_pton(AF_INET, lan.ipaddr, &ipaddr);
    memcpy(&(pLanMngm->LanIPAddress), &(ipaddr), sizeof(ANSC_IPV4_ADDRESS));
    inet_pton(AF_INET, lan.netmask, &netmask);
    memcpy(&(pLanMngm->LanSubnetMask), &(netmask), sizeof(ANSC_IPV4_ADDRESS));
    network.Value = _CALC_NETWORK(ipaddr.Value, netmask.Value);
    memcpy(&(pLanMngm->LanNetwork), &(network), sizeof(ANSC_IPV4_ADDRESS));

    Utopia_GetLanMngmLanNetworksAllow(utctx, &int_tmp);
    pLanMngm->LanNetworksAllow = (COSA_DML_LanNetworksAllow)int_tmp;

    /* TO-DO */
    /* LanDhcpServer; */
    Utopia_GetLanMngmLanNapt(utctx, &napt_mode);
    switch (napt_mode){
    default:
        pLanMngm->LanNaptEnable = TRUE;
        pLanMngm->LanNaptType = 1;//COSA_DML_LanNapt_DHCP;
        break;
    case NAPT_MODE_DISABLE_STATIC:
        pLanMngm->LanNaptEnable = FALSE;
        pLanMngm->LanNaptType = 0;//COSA_DML_LanNapt_StaticIP;
        break;
    case NAPT_MODE_DISABLE_DHCP:
        pLanMngm->LanNaptEnable = FALSE;
        pLanMngm->LanNaptType = 1;//COSA_DML_LanNapt_DHCP;
        break;
    case NAPT_MODE_DHCP:
        pLanMngm->LanNaptEnable = TRUE;
        pLanMngm->LanNaptType = 1;//COSA_DML_LanNapt_DHCP;
        break;
    case NAPT_MODE_STATICIP:
        pLanMngm->LanNaptEnable = TRUE;
        pLanMngm->LanNaptType = 0;//COSA_DML_LanNapt_StaticIP;
        break;
    }

    /* TO-DO */
    /* LanTos;
     */

    getLanMgmtUpnp(utctx, &pLanMngm->LanUpnp);
}

ULONG
CosaDmlLanMngm_GetNumberOfEntries(void)
{
    UtopiaContext utctx = {0};
    int num = 0;
    if (Utopia_Init(&utctx))
    {
        Utopia_GetLanMngmCount(&utctx, &num);
        Utopia_Free(&utctx, 0);
    }
    return (ULONG)num;
}

ANSC_STATUS
CosaDmlLanMngm_GetEntryByIndex(ULONG index, PCOSA_DML_LAN_MANAGEMENT pLanMngm)
{
    UtopiaContext utctx = {0};
    int num = -1;
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;

    if (Utopia_Init(&utctx))
    {
        Utopia_GetLanMngmCount(&utctx, &num);
        if(index < (ULONG)num ){
            _Get_LanMngm_Setting(&utctx, index, pLanMngm);
            ret = ANSC_STATUS_SUCCESS;
        }
        Utopia_Free(&utctx, 0);
    }
    return ret;
}

ANSC_STATUS
CosaDmlLanMngm_SetValues(ULONG index, ULONG ins, const char *alias)
{
    UNREFERENCED_PARAMETER(index);
    UtopiaContext utctx = {0};
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;
    if (Utopia_Init(&utctx))
    {
        Utopia_SetLanMngmInsNum(&utctx, ins);
        Utopia_SetLanMngmAlias(&utctx, alias);
        Utopia_Free(&utctx, 1);
        ret = ANSC_STATUS_SUCCESS;
    }
    return ret;
}

ANSC_STATUS
CosaDmlLanMngm_GetConf(ULONG ins, PCOSA_DML_LAN_MANAGEMENT pLanMngm)
{
    UtopiaContext utctx = {0};
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;

    if (Utopia_Init(&utctx))
    {
        _Get_LanMngm_Setting(&utctx, ins, pLanMngm);
        Utopia_Free(&utctx, 0);
        ret = ANSC_STATUS_SUCCESS;
    }
    return ret;
}

/*To make multi thread to exec sequentially*/
static void  checkTicket(int ticket)
{
    while(1)
    {
        if(ticket != curticket)
            sleep(5);
        else
            break;
    }
}

void* bridge_mode_wifi_notifier_thread(void* arg) 
{
    PCOSA_NOTIFY_WIFI pNotify = (PCOSA_NOTIFY_WIFI)arg;
    char*   faultParam = NULL;
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;
    char acBridgeMode[ 4 ],
        acSetRadioString[ 8 ],
        acSetSSIDString[ 8 ];
    errno_t safec_rc = -1;
    int  sizevalCommit1 = 0;
    int  sizeval = 0;
    int  sizeval2 = 0;
    int ulNumOfEntries=0;
    parameterValStruct_t **valWifistatus;
    char pWifiComponentName[64]="eRT.com.cisco.spvtg.ccsp.wifi";
    char pComponentPath[64]="/com/cisco/spvtg/ccsp/wifi";
    char *paramNames[]={"Device.WiFi.RadioNumberOfEntries"};
    int nval;

    checkTicket(pNotify->ticket);

    /*
     * Configure Bridge Static Mode Configuration
     * if BridgeStaticMode then "Advanced Bridge" 2 then COSA_DML_LanMode_BridgeStatic
     * if BridgeStaticMode then "Primary Bridge" 4 then COSA_DML_LanMode_FullBridgeStatic
     *
     * if "Advanced Bridge" then disable Private SSIDs only
     * if "Primary Bridge" then disable both Radios and Private SSIDs too
     */

    memset( acBridgeMode, 0 ,sizeof( acBridgeMode ) );
    syscfg_get( NULL, "bridge_mode", acBridgeMode, sizeof(acBridgeMode));

    switch( atoi( acBridgeMode ) )
    {
    case BRIDGE_MODE_STATIC:
    {
        safec_rc = strcpy_s( acSetRadioString, sizeof(acSetRadioString), "true" );
        if(safec_rc != EOK)
        {
            ERR_CHK(safec_rc);
        }
        safec_rc = strcpy_s( acSetSSIDString,sizeof(acSetSSIDString), "false" );
        if(safec_rc != EOK)
        {
            ERR_CHK(safec_rc);
        }
    }
    break; /* BRIDGE_MODE_STATIC */

    case BRIDGE_MODE_FULL_STATIC:
    {
        safec_rc = strcpy_s( acSetRadioString, sizeof( acSetRadioString ), "false" );
        if(safec_rc != EOK)
        {
            ERR_CHK(safec_rc);
        }
        safec_rc = strcpy_s( acSetSSIDString,sizeof( acSetSSIDString ), "false" );
        if(safec_rc != EOK)
        {
            ERR_CHK(safec_rc);
        }
    }
    break; /* BRIDGE_MODE_FULL_STATIC */

    default: /* BRIDGE_MODE_OFF */
    {
        safec_rc = strcpy_s( acSetRadioString,sizeof( acSetRadioString ), "true" );
        if(safec_rc != EOK)
        {
            ERR_CHK(safec_rc);
        }
        safec_rc = strcpy_s( acSetSSIDString,sizeof( acSetSSIDString ), "true" );
        if(safec_rc != EOK)
        {
            ERR_CHK(safec_rc);
        }
    }
    break;
    }

    AnscTraceInfo(("%s - Mode:%d Radio:%s SSID:%s\n", __FUNCTION__, atoi( acBridgeMode ), acSetRadioString, acSetSSIDString ));

#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
    char param[50];
    char* enVal = NULL;
    char* guestnetDM = NULL;
    char* guestEnableStr = NULL;
    char* enableStr = (char*)(pNotify->flag?"false" : "true");
    snprintf(param, sizeof(param), "dmsb.CiscoConnect.guestEnabled");
    if (PSM_Get_Record_Value2(bus_info, g_GetSubsystemPrefix(g_pDslhDmlAgent), (char *)param, NULL, &enVal) == CCSP_SUCCESS) {
        if ( enVal[0] == '1' && enableStr[0] == 't') {
            guestEnableStr = "true";
        } else {
            guestEnableStr = "false";
        }
        //businfo = g_MessageBusHandle;
        bus_info->freefunc(enVal);
    } else {
        guestEnableStr = "false";
    }
    guestnetDM = "Device.WiFi.SSID.5.Enable";

#endif
    ret = CcspBaseIf_getParameterValues(
        bus_handle,
        pWifiComponentName,
        pComponentPath,
        paramNames,
        1,
        &nval,
        &valWifistatus);

    if (CCSP_SUCCESS == ret) {
        ulNumOfEntries = atoi(valWifistatus[0]->parameterValue);
    }

    if (valWifistatus) {
        free_parameterValStruct_t (bus_handle, nval, valWifistatus);
    }

    //Full bridge
    parameterValStruct_t           val[] = {
#ifdef CONFIG_CISCO_FEATURE_CISCOCONNECT
        {guestnetDM, guestEnableStr, ccsp_boolean},
#endif
        {"Device.WiFi.Radio.1.Enable", acSetRadioString, ccsp_boolean},
        {"Device.WiFi.Radio.2.Enable", acSetRadioString, ccsp_boolean},
#if !defined (_CBR_PRODUCT_REQ_) && !defined (_BWG_PRODUCT_REQ_) // CBR and BWG don't have XHS don't force here
        {"Device.WiFi.SSID.3.Enable", acSetRadioString, ccsp_boolean},
#endif
        {"Device.WiFi.Radio.3.Enable", acSetRadioString, ccsp_boolean}
    };

// Pseudo bridge
    parameterValStruct_t val2[] = {
        {"Device.WiFi.SSID.1.Enable", acSetSSIDString, ccsp_boolean},
        {"Device.WiFi.SSID.2.Enable", acSetSSIDString, ccsp_boolean},
        {"Device.WiFi.SSID.17.Enable", acSetSSIDString, ccsp_boolean}};

    parameterValStruct_t valCommit1[] = {
        {"Device.WiFi.Radio.1.X_CISCO_COM_ApplySetting", "true", ccsp_boolean},
        {"Device.WiFi.Radio.2.X_CISCO_COM_ApplySetting", "true", ccsp_boolean},
        {"Device.WiFi.Radio.3.X_CISCO_COM_ApplySetting", "true", ccsp_boolean} };

    if (ulNumOfEntries < 3) {
        sizeval         = (sizeof(val)/sizeof(*val)) - 1;
        sizeval2        = (sizeof(val2)/sizeof(*val2)) - 1;
        sizevalCommit1  = (sizeof(valCommit1)/sizeof(*valCommit1)) - 1;
    } else {
        sizeval         = sizeof(val)/sizeof(*val);
        sizeval2        = sizeof(val2)/sizeof(*val2);
        sizevalCommit1  = sizeof(valCommit1)/sizeof(*valCommit1);
    }

#ifdef _XF3_PRODUCT_REQ_
    parameterValStruct_t valCommit2[] = { {"Device.WiFi.X_CISCO_COM_ResetRadios", "true", ccsp_boolean} };
#endif

    // All the cases Radio should get update since transition will happen during full - psedo - router
    ret = CcspBaseIf_setParameterValues
        (
            bus_handle,
            ppComponents[0]->componentName,
            ppComponents[0]->dbusPath,
            0, 0x0,   /* session id and write id */
            val,
            sizeval,
            TRUE,   /* no commit */
            &faultParam
            );

    // All the cases Radio should get update since transition will happen during full - psedo - router
    ret = CcspBaseIf_setParameterValues
        (
            bus_handle,
            ppComponents[0]->componentName,
            ppComponents[0]->dbusPath,
            0, 0x0,   /* session id and write id */
            val2,
            sizeval2,
            TRUE,   /* no commit */
            &faultParam
            );

    if (ret != CCSP_SUCCESS && faultParam)
    {
        AnscTraceError(("Error:Failed to SetValue for param '%s'\n", faultParam));
        bus_info->freefunc(faultParam);
        faultParam = NULL;
    }


    ret = CcspBaseIf_setParameterValues
        (
            bus_handle,
            ppComponents[0]->componentName,
            ppComponents[0]->dbusPath,
            0, 0x0,   /* session id and write id */
            valCommit1,
            sizevalCommit1,
            TRUE,   /* no commit */
            &faultParam
            );
    if (ret != CCSP_SUCCESS && faultParam)
    {
        AnscTraceError(("Error:Failed to SetValue for param '%s'\n", faultParam));
        bus_info->freefunc(faultParam);
        faultParam = NULL;
    }
#ifdef _XF3_PRODUCT_REQ_
    ret = CcspBaseIf_setParameterValues
        (
            bus_handle,
            ppComponents[0]->componentName,
            ppComponents[0]->dbusPath,
            0, 0x0,   /* session id and write id */
            valCommit2,
            1,
            TRUE,   /* no commit */
            &faultParam
            );
#endif
    if (ret != CCSP_SUCCESS && faultParam)
    {
        AnscTraceError(("Error:Failed to SetValue for param '%s'\n", faultParam));
        bus_info->freefunc(faultParam);
        faultParam = NULL;
    }

    // All the cases Radio should get update since transition will happen during full - psedo - router
    {
        parameterValStruct_t resetRadio[] = {{"Device.WiFi.X_CISCO_COM_ResetRadios", "true", ccsp_boolean}};

        ret = CcspBaseIf_setParameterValues
            (
                bus_handle,
                ppComponents[0]->componentName,
                ppComponents[0]->dbusPath,
                0, 0x0,   /* session id and write id */
                resetRadio,
                1,
                TRUE,   /* no commit */
                &faultParam
                );

        if (ret != CCSP_SUCCESS && faultParam)
        {
            AnscTraceError(("Error:Failed to SetValue for param '%s'\n", faultParam));
            bus_info->freefunc(faultParam);
            faultParam = NULL;
        }
    }

    curticket++;
    AnscFreeMemory(arg);
    return NULL;
}

ANSC_STATUS
CosaDmlLanMngm_SetConf(ULONG ins, PCOSA_DML_LAN_MANAGEMENT pLanMngm)
{
    UtopiaContext utctx = {0};
    lanSetting_t  lan;
    ANSC_STATUS ret = ANSC_STATUS_FAILURE;
    bridgeInfo_t bridge_info;
    char str[IFNAME_SZ];
    napt_mode_t napt;
#if !defined(_CBR_PRODUCT_REQ_) && !defined(_PLATFORM_RASPBERRYPI_) && !defined(_HUB4_PRODUCT_REQ_) && !defined(_PLATFORM_TURRIS_)// MOCA is not present for TCCBR environment, HUB4 and RaspberryPi environment
    parameterValStruct_t **valMoCAstatus = NULL;
    char pMoCAComponentName[64]="eRT.com.cisco.spvtg.ccsp.moca";
    char pComponentPath[64]="/com/cisco/spvtg/ccsp/moca";
    char *paramNames[]={"Device.MoCA.Interface.1.Enable"};
    int nval;
    char buf[16];
    int MoCAstate;
#endif

    COSA_DML_LAN_MANAGEMENT orgLanMngm;

    if (Utopia_Init(&utctx))
    {
        _Get_LanMngm_Setting(&utctx, ins, &orgLanMngm);
        Utopia_SetLanMngmAlias(&utctx, pLanMngm->Alias);
        Utopia_SetLanMngmInsNum(&utctx, pLanMngm->InstanceNumber);

        /*
         * Configure Bridge Static Mode Configuration
         * if COSA_DML_LanMode_BridgeStatic then BridgeStaticMode then "Advanced Bridge" 2
         * if COSA_DML_LanMode_FullBridgeStatic then BridgeStaticMode then "Primary Bridge" 4
         */

        switch( pLanMngm->LanMode )
        {
        case COSA_DML_LanMode_BridgeStatic:
        {
            bridge_info.mode = BRIDGE_MODE_STATIC;
            CcspTraceInfo(("LanMode:Adv_Bridge_Mode_selected\n"));
        }
        break; /* COSA_DML_LanMode_BridgeStatic */

        case COSA_DML_LanMode_FullBridgeStatic:
        {
            bridge_info.mode = BRIDGE_MODE_FULL_STATIC;
            CcspTraceInfo(("LanMode:Basic_Bridge_Mode_selected\n"));
        }
        break; /* COSA_DML_LanMode_BridgeStatic */

        case COSA_DML_LanMode_Router:
        {
            bridge_info.mode = BRIDGE_MODE_OFF;
            CcspTraceInfo(("LanMode:Router_Mode_selected\n"));
        }
        break; /* COSA_DML_LanMode_Router */

        default:
        {
            bridge_info.mode = BRIDGE_MODE_OFF;
        }
        break;
        }

        Utopia_SetBridgeSettings(&utctx,&bridge_info);
#if !defined(_CBR_PRODUCT_REQ_) && !defined(_PLATFORM_RASPBERRYPI_) && !defined(_HUB4_PRODUCT_REQ_) && !defined(_PLATFORM_TURRIS_)// MOCA is not present for TCCBR environment, HUB4 and RaspberryPi environment
        ret = CcspBaseIf_getParameterValues(
            bus_handle,
            pMoCAComponentName,
            pComponentPath,
            paramNames,
            1,
            &nval,
            &valMoCAstatus);
        if( CCSP_SUCCESS == ret ){
            CcspTraceWarning(("valMoCAstatus[0]->parameterValue = %s\n",valMoCAstatus[0]->parameterValue));
            if(strcmp("true", valMoCAstatus[0]->parameterValue)==0)
                MoCAstate=1;
            else
                MoCAstate=0;
            snprintf(buf,sizeof(buf),"%d",MoCAstate);
            if ((syscfg_set_commit(NULL, "MoCA_current_status", buf) != 0))
            {
                Utopia_Free(&utctx, 0);
                CcspTraceWarning(("syscfg_set failed\n"));
                return -1;
            }
        }
        else
        {
            CcspTraceError(("CcspBaseIf_getParameterValues failed to get MoCA status return vaule = %lu\n",ret));
        }
        if(valMoCAstatus){
            free_parameterValStruct_t (bus_handle, nval, valMoCAstatus);
        }
#endif


        memset(&lan, 0 ,sizeof(lan));
        inet_ntop(AF_INET, &(pLanMngm->LanIPAddress), str, sizeof(str));
        memcpy(&(lan.ipaddr), str, sizeof(str));
        inet_ntop(AF_INET, &(pLanMngm->LanSubnetMask), str, sizeof(str));
        memcpy(&(lan.netmask), str, sizeof(str));
        Utopia_SetLanSettings(&utctx, &lan);

#if defined(_COSA_INTEL_USG_ARM_) && !defined(INTEL_PUMA7) && defined(ENABLE_FEATURE_MESHWIFI)
        // Send subnet change message to ATOM so that MESH is notified.
        {
#define DATA_SIZE 1024
            FILE *fp1;
            char buf[DATA_SIZE] = {0};
            char *urlPtr = NULL;
            errno_t safec_rc = -1;

            // Grab the ATOM RPC IP address
            // sprintf(cmd1, "cat /etc/device.properties | grep ATOM_ARPING_IP | cut -f 2 -d\"=\"");

            fp1 = fopen("/etc/device.properties", "r");
            if (fp1 == NULL) {
                CcspTraceError(("Error opening properties file! \n"));
                Utopia_Free(&utctx, 0);
                return FALSE;
            }

            while (fgets(buf, DATA_SIZE, fp1) != NULL) {
                // Look for ATOM_ARPING_IP
                if (strstr(buf, "ATOM_ARPING_IP") != NULL) {
                    buf[strcspn(buf, "\r\n")] = 0; // Strip off any carriage returns

                    // grab URL from string
                    urlPtr = strstr(buf, "=");
                    urlPtr++;
                    break;
                }
            }

            if (fclose(fp1) != 0) {
                /* Error reported by pclose() */
                CcspTraceError(("Error closing properties file! \n"));
            }

            if (urlPtr != NULL && urlPtr[0] != 0 && strlen(urlPtr) > 0) {
                CcspTraceInfo(("Reported an ATOM IP of %s \n", urlPtr));
                pid_t pid = fork();

                if (pid == -1)
                {
                    // error, failed to fork()
                }
                else if (pid > 0)
                {
                    int status;
                    waitpid(pid, &status, 0); // wait here until the child completes
                }
                else
                {
                    // we are the child
                    char cmd[DATA_SIZE] = {0};
                    CcspTraceInfo(("Sending subnet_change notification to ATOM IP %s \n", urlPtr));
                    safec_rc = sprintf_s(cmd, sizeof(cmd), "/usr/bin/sysevent set subnet_change \"RDK|%s|%s\"",
                                         lan.ipaddr,lan.netmask);
                    if(safec_rc < EOK)
                    {
                        ERR_CHK(safec_rc);
                    }
                    char *args[] = {"rpcclient", urlPtr, cmd, (char *) 0 };
                    execv(args[0], args);
                    _exit(EXIT_FAILURE);   // exec never returns
                }
            }
        }
#elif defined(ENABLE_FEATURE_MESHWIFI)
        // In all the other platforms XB6, XF3, etc. PandM is running on the same processor as on Mesh, so we just need to
        // send the sysevent call directly.
        {
#define DATA_SIZE 1024

            pid_t pid = fork();
            errno_t safec_rc = -1;

            if (pid == -1)
            {
                // error, failed to fork()
            }
            else if (pid > 0)
            {
                int status;
                waitpid(pid, &status, 0); // wait here until the child completes
            }
            else
            {
                // we are the child
                char cmd[DATA_SIZE] = {0};
                CcspTraceInfo(("Sending subnet_change notification \n"));
                safec_rc = sprintf_s(cmd, sizeof(cmd), "RDK|%s|%s", lan.ipaddr, lan.netmask);
                if(safec_rc < EOK)
                {
                    ERR_CHK(safec_rc);
                }
                char *args[] = {"/usr/bin/sysevent", "set", "subnet_change", cmd, (char *) 0 };
                execv(args[0], args);
                _exit(EXIT_FAILURE);   // exec never returns
            }
        }
#endif
        /* TODO: Useless call Utopia_SetLanMngmLanNetworksAllow , no definition*/
#if 0
        if(pLanMngm->LanNaptType == COSA_DML_LanNapt_DHCP && pLanMngm->LanNaptEnable == TRUE)
            napt = NAPT_MODE_DHCP;
        else if(pLanMngm->LanNaptType == COSA_DML_LanNapt_DHCP && pLanMngm->LanNaptEnable == FALSE)
            napt = NAPT_MODE_DISABLE_DHCP;
        else if(pLanMngm->LanNaptType == COSA_DML_LanNapt_StaticIP && pLanMngm->LanNaptEnable == TRUE)
            napt = NAPT_MODE_STATICIP;
        else if(pLanMngm->LanNaptType == COSA_DML_LanNapt_StaticIP && pLanMngm->LanNaptEnable == FALSE)
            napt = NAPT_MODE_DISABLE_STATIC;
        else
            napt = NAPT_MODE_DHCP;
#endif
        if(pLanMngm->LanNaptType == 1 && pLanMngm->LanNaptEnable == TRUE)
            napt = NAPT_MODE_DHCP;
        else if(pLanMngm->LanNaptType == 1 && pLanMngm->LanNaptEnable == FALSE)
            napt = NAPT_MODE_DISABLE_DHCP;
        else if(pLanMngm->LanNaptType == 0 && pLanMngm->LanNaptEnable == TRUE)
            napt = NAPT_MODE_STATICIP;
        else if(pLanMngm->LanNaptType == 0 && pLanMngm->LanNaptEnable == FALSE)
            napt = NAPT_MODE_DISABLE_STATIC;
        else
            napt = NAPT_MODE_DHCP;

        Utopia_SetLanMngmLanNapt(&utctx, napt);
        setLanMgmtUpnp(&utctx, pLanMngm->LanUpnp);
        Utopia_Free(&utctx, 1);
        pLanMngm->LanNetwork.Value = _CALC_NETWORK(pLanMngm->LanIPAddress.Value, pLanMngm->LanSubnetMask.Value);
        char l_cSecWebUI_Enabled[8] = {0};
        syscfg_get(NULL, "SecureWebUI_Enable", l_cSecWebUI_Enabled, sizeof(l_cSecWebUI_Enabled));
        if (!strncmp(l_cSecWebUI_Enabled, "true", 4)) {
            /* If lan settings are changed, restart the webgui.sh */
            if(orgLanMngm.LanIPAddress.Value != pLanMngm->LanIPAddress.Value)
            {
                pthread_t tid;
                pthread_create( &tid, NULL, &WebGuiRestart, NULL);
            }
        }


#ifdef _HUB4_PRODUCT_REQ_
        /* If lan settings(gw-ip or subnet-mask) not change, skip refreshing lan_prefix */
        if( (orgLanMngm.LanIPAddress.Value != pLanMngm->LanIPAddress.Value) ||
            (orgLanMngm.LanSubnetMask.Value != pLanMngm->LanSubnetMask.Value) )
        {
            /* SKYH4-1780 : This will help to set Down state to
             * sysevent 'ipv6_connection_state' */
            CcspTraceInfo(("lan_prefix_clear is setting\n"));
            commonSyseventSet("lan_prefix_clear", "");
        }
#endif
        if (pLanMngm->LanMode == orgLanMngm.LanMode) {
            return ANSC_STATUS_SUCCESS;
        }



        //Bridge mode has changed, so we need to report the change and toggle wifi accordingly
        //TODO: move this to a thread
#ifdef _XF3_PRODUCT_REQ_
        int bEnable;
#endif

        if(bridge_info.mode == BRIDGE_MODE_OFF)
        {
            syslog_systemlog("Local Network", LOG_NOTICE, "Status change: IP %s mask %s", lan.ipaddr, lan.netmask);
#ifdef _XF3_PRODUCT_REQ_
            bEnable = 0;
#endif
        }
        else
        {
            syslog_systemlog("Local Network", LOG_NOTICE, "Status change: Bridge mode");
#ifndef _XF3_PRODUCT_REQ_
            // stop lan when it is bridge mode
            commonSyseventSet("lan-stop", "");
#endif
#ifdef _XF3_PRODUCT_REQ_
            bEnable = 3;
        }

        char buf[7] = {0};
        snprintf(buf,sizeof(buf),"%d",bEnable);
        openCommonSyseventConnection();
        sysevent_set(commonSyseventFd, commonSyseventToken, "bridge_mode",buf,0);
        configBridgeMode(bEnable);
#else
        //bEnable = 1;
    }
#endif

#if defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_TURRIS_)
    char buf[7] = {0};
    BOOL value;
    snprintf(buf,sizeof(buf),"%d",bridge_info.mode);
    if ((syscfg_set(NULL, "bridge_mode", buf) != 0))
    {
        Utopia_Free(&utctx, 0);
        CcspTraceWarning(("syscfg_set failed\n"));
        return -1;
    }
    if(bridge_info.mode == 0)
    {
        value = 1;
        commonSyseventSet("bridge-stop", "");
        commonSyseventSet("lan-start", "");
        if (DmSetBool("Device.WiFi.SSID.1.Enable", value) != ANSC_STATUS_SUCCESS) {
            DHCPMGR_LOG_ERROR("Set WiFi.SSID.1 Enable error");
        } else {
            DHCPMGR_LOG_INFO("Set WiFi.SSID.1 Enable OK");
        }
        if (DmSetBool("Device.WiFi.SSID.2.Enable", value) != ANSC_STATUS_SUCCESS) {
            DHCPMGR_LOG_ERROR("Set WiFi.SSID.2 Enable error");
        } else {
            DHCPMGR_LOG_INFO("Set WiFi.SSID.2 Enable OK");
        }
    }
    else if(bridge_info.mode == 2)
    {
        value = 0;
        commonSyseventSet("bridge-start", "");
        commonSyseventSet("lan-stop", "");
        if (DmSetBool("Device.WiFi.SSID.1.Enable", value) != ANSC_STATUS_SUCCESS) {
            DHCPMGR_LOG_ERROR("Set WiFi.SSID.1 Disable error");
        } else {
            DHCPMGR_LOG_INFO("Set WiFi.SSID.1 Disable OK");
        }
        if (DmSetBool("Device.WiFi.SSID.2.Enable", value) != ANSC_STATUS_SUCCESS) {
            DHCPMGR_LOG_ERROR("Set WiFi.SSID.2 Disable error");
        } else {
            DHCPMGR_LOG_INFO("Set WiFi.SSID.2 Disable OK");
        }
    }
    else
    {
        DHCPMGR_LOG_INFO("Running in different Modes ");
    }
    if (DmSetBool("Device.WiFi.Radio.1.X_CISCO_COM_ApplySetting", 1) != ANSC_STATUS_SUCCESS) {
        DHCPMGR_LOG_ERROR("Set WiFi.Radio.1.X_CISCO_COM_ApplySetting Enable error");
    } else {
        DHCPMGR_LOG_INFO("Set WiFi.Radio.1.X_CISCO_COM_ApplySetting Enable OK");
    }
    if (DmSetBool("Device.WiFi.Radio.2.X_CISCO_COM_ApplySetting", 1) != ANSC_STATUS_SUCCESS) {
        DHCPMGR_LOG_ERROR("Set WiFi.Radio.2.X_CISCO_COM_ApplySetting Enable error");
    } else {
        DHCPMGR_LOG_INFO("Set WiFi.Radio.2.X_CISCO_COM_ApplySetting Enable OK");
    }
    sleep(1);
    vsystem("/bin/sh /etc/webgui.sh &");
#endif
    //configBridgeMode(bEnable);

    if( ( ( bridge_info.mode == BRIDGE_MODE_STATIC ) || \
          ( bridge_info.mode == BRIDGE_MODE_FULL_STATIC ) ) && \
        ( is_mesh_enabled( ) )
        )
    {
        CcspTraceWarning(("Setting MESH to disabled as LanMode is changed to Bridge mode\n"));
        pthread_t tid;
        pthread_create(&tid, NULL, &set_mesh_disabled, NULL);
    }

    ret = ANSC_STATUS_SUCCESS;
}
return ret;
}

BOOL is_mesh_enabled()
{
    char buf[10] = {0};

    if(!syscfg_get(NULL, "mesh_enable", buf, sizeof(buf)))
    {
        if ((strcmp(buf,"true") == 0))
        {
            return TRUE;
        }
    }
    return FALSE;
}

void* set_mesh_disabled(void* arg)
{
    UNREFERENCED_PARAMETER(arg);
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t   param_val[1];
    char  component[256]  = "eRT.com.cisco.spvtg.ccsp.meshagent";
    char  bus[256]        = "/com/cisco/spvtg/ccsp/meshagent";
    char* faultParam      = NULL;
    int   ret             = 0;

    param_val[0].parameterName="Device.DeviceInfo.X_RDKCENTRAL-COM_xOpsDeviceMgmt.Mesh.Enable";
    param_val[0].parameterValue="false";
    param_val[0].type = ccsp_boolean;

    ret = CcspBaseIf_setParameterValues(
        bus_handle,
        component,
        bus,
        0,
        0,
        (void*)&param_val,
        1,
        TRUE,
        &faultParam
        );

    if( ( ret != CCSP_SUCCESS ) && ( faultParam!=NULL )) {
        CcspTraceError(("%s-%d Failed to set Mesh Enable to false\n",__FUNCTION__,__LINE__));
        bus_info->freefunc( faultParam );
        return NULL;
    }
    return NULL;

}

/* CheckAndGetDevicePropertiesEntry() */
int CheckAndGetDevicePropertiesEntry( char *pOutput, int size, char *sDevicePropContent )
{
    FILE *fp1 = NULL;
    char buf[1024] = {0},
    *urlPtr = NULL;
    int ret = -1;

    // Read the device.properties file
    fp1 = fopen( "/etc/device.properties", "r" );

    if ( NULL == fp1 )
    {
        CcspTraceError(("Error opening properties file! \n"));
        return -1;
    }

    while ( fgets( buf, sizeof( buf ), fp1 ) != NULL )
    {
        // Look for Device Properties Passed Content
        if ( strstr( buf, sDevicePropContent ) != NULL )
        {
            buf[strcspn( buf, "\r\n" )] = 0; // Strip off any carriage returns

            // grab content from string(entry)
            urlPtr = strstr( buf, "=" );
            if ( urlPtr != NULL )
            {
                urlPtr++;
            }
           
            if (urlPtr !=NULL)
            {
            strncpy( pOutput, urlPtr, size );

            ret=0;

            break;
            }
        }
    }

    fclose( fp1 );
    return ret;
}
