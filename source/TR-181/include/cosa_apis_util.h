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

#define LM_GEN_STR_SIZE    64
#define LM_MAX_IP_AMOUNT 24
#define LM_MAX_COMMENT_SIZE 64
#define MAX_STR_SIZE 256

#ifdef FEATURE_RDKB_WAN_MANAGER
extern ANSC_HANDLE bus_handle;
#define ETHERNET_INTERFACE_OBJECT "Device.Ethernet.Interface"
#define ETH_COMPONENT_NAME "eRT.com.cisco.spvtg.ccsp.ethagent"
#define ETH_DBUS_PATH "/com/cisco/spvtg/ccsp/ethagent"
#endif

#define PARTNERS_INFO_FILE              "/nvram/partners_defaults.json"
#define BOOTSTRAP_INFO_FILE             "/opt/secure/bootstrap.json"
/*
enum LM_ADDR_SOURCE{
        LM_ADDRESS_SOURCE_STATIC =0,
        LM_ADDRESS_SOURCE_DHCP,
        LM_ADDRESS_SOURCE_RESERVED,
        LM_ADDRESS_SOURCE_NONE
};

enum LM_MEDIA_TYPE{
        LM_MEDIA_TYPE_UNKNOWN=0,
        LM_MEDIA_TYPE_ETHERNET,
        LM_MEDIA_TYPE_WIFI,
        LM_MEDIA_TYPE_MOCA
};

typedef struct{
        unsigned char   addr[16];
    int active;
    int LeaseTime;
        enum LM_ADDR_SOURCE     addrSource;
    unsigned int priFlg;
}LM_ip_addr_t;

typedef struct{
        unsigned char   phyAddr[6];
        unsigned char   online;
        unsigned char   ipv4AddrAmount;
        unsigned char   ipv6AddrAmount;
//      LM_ip_addr_t    priAddr;
        enum LM_MEDIA_TYPE mediaType;
        char    hostName[LM_GEN_STR_SIZE];
        char    l1IfName[LM_GEN_STR_SIZE];
        char    l3IfName[LM_GEN_STR_SIZE];
    char    AssociatedDevice[LM_GEN_STR_SIZE];//Only works if this is a wifi host. 
    time_t  activityChangeTime;
        LM_ip_addr_t    ipv4AddrList[LM_MAX_IP_AMOUNT];
        LM_ip_addr_t    ipv6AddrList[LM_MAX_IP_AMOUNT];
    unsigned char   comments[LM_MAX_COMMENT_SIZE];
    int             RSSI;
}LM_host_t, *LM_host_ptr_t;


typedef struct{
    int result;
    union{
        LM_host_t host;
        int online_num;
    }data;
}LM_cmd_common_result_t;
*/

ULONG
CosaGetParamValueUlong
    (
        char*                       pParamName
    );

ULONG
CosaGetInstanceNumberByIndex
    (
        char*                      pObjName,
        ULONG                      ulIndex
    );


PUCHAR
CosaUtilGetFullPathNameByKeyword
    (
        PUCHAR                      pTableName,
        PUCHAR                      pParameterName,
        PUCHAR                      pKeyword);

ANSC_STATUS is_usg_in_bridge_mode(BOOL *pBridgeMode);

ANSC_STATUS
CosaSListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCOSA_CONTEXT_LINK_OBJECT   pCosaContext
    );


ANSC_STATUS UpdateJsonParam
        (
                char*                       pKey,
                char*                   PartnerId,
                char*                   pValue,
                char*                   pSource,
                char*                   pCurrentTime
    );

int writeToJson(char *data, char *file);
ANSC_STATUS UpdateJsonParamLegacy
        (
                char*                       pKey,
                char*                   PartnerId,
                char*                   pValue
    );

PCOSA_CONTEXT_LINK_OBJECT
CosaSListGetEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        ULONG                       InstanceNumber
    );




//static int openCommonSyseventConnection();
int commonSyseventSet(char* key, char* value);
int commonSyseventGet(char* key, char* value, int valLen);
int commonSyseventClose();
void _get_shell_output(FILE *fp, char *buf, int len);
int _get_shell_output2(FILE *fp, char * dststr);
char *safe_strcpy (char *dst, char *src, size_t dst_size);

int GetInstanceNumberByIndex(char* pObjName,unsigned int* Inscont,unsigned int** InsArray);

ANSC_STATUS fillCurrentPartnerId
        (
                char*                       pValue,
        PULONG                      pulSize
    );


int
CosaGetParamValueString
    (
        char*                       pParamName,
        char*                       pBuffer,
        PULONG                      pulSize
    );

int g_GetParamValueString(ANSC_HANDLE g_pDslhDmlAgent, char* prefixFullName, char* prefixValue,PULONG uSize);

//int lm_get_host_by_mac(char *mac, LM_cmd_common_result_t *pHost);

INT PsmWriteParameter( char *pParamName, char *pParamVal );

INT PsmReadParameter( char *pParamName, char *pReturnVal, int returnValLength );
