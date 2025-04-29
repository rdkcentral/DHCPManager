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

#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <syscfg/syscfg.h>
#include "sysevent/sysevent.h"
#include "utapi/utapi.h"
#include "utapi/utapi_util.h"
#include "ansc_platform.h"
#include "cosa_apis.h"
#include "cosa_apis_util.h"
#include "plugin_main.h"
#include "plugin_main_apis.h"
#include "secure_wrapper.h"
#include "safec_lib_common.h"
#include "cJSON.h"
#include "ifl.h"
#include <sys/ioctl.h>
#include "util.h"

#ifdef DHCPV6C_PSM_ENABLE
#include "ccsp_psm_helper.h"
#endif //DHCPV6C_PSM_ENABLE

#define BOOTSTRAP_INFO_FILE_BACKUP  "/nvram/bootstrap.json"
#define CLEAR_TRACK_FILE            "/nvram/ClearUnencryptedData_flags"
#define NVRAM_BOOTSTRAP_CLEARED     (1 << 0)

#define UNUSED(x) (void)(x)
#define PARTNER_ID_LEN 64
typedef int (*CALLBACK_FUNC_NAME)(void *);
extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];

#ifdef FEATURE_RDKB_WAN_MANAGER
static ANSC_STATUS RdkBus_GetParamValues( char *pComponent, char *pBus, char *pParamName, char *pReturnVal )
{
    parameterValStruct_t   **retVal;
    char                   *ParamName[1];
    int                    ret               = 0,
                           nval;

    //Assign address for get parameter name
    ParamName[0] = pParamName;

    ret = CcspBaseIf_getParameterValues(
                                    bus_handle,
                                    pComponent,
                                    pBus,
                                    ParamName,
                                    1,
                                    &nval,
                                    &retVal);

    //Copy the value
    if( CCSP_SUCCESS == ret )
    {
        if( NULL != retVal[0]->parameterValue )
        {
            memcpy( pReturnVal, retVal[0]->parameterValue, strlen( retVal[0]->parameterValue ) + 1 );
        }

        if( retVal )
        {
            free_parameterValStruct_t (bus_handle, nval, retVal);
        }

        return ANSC_STATUS_SUCCESS;
    }

    if( retVal )
    {
       free_parameterValStruct_t (bus_handle, nval, retVal);
    }

    return ANSC_STATUS_FAILURE;
}
#endif

static int Get_comp_namespace(char* compName,char* dbusPath,char *obj_name){


        if(!obj_name || AnscSizeOfString(obj_name) == 0) return -1;

        char                        dst_pathname_cr[256] = {0};
        componentStruct_t **        ppComponents = NULL;
        errno_t                     safec_rc = -1;
        int                         size = 0;
        int                         ret = -1;

        safec_rc = sprintf_s(dst_pathname_cr, sizeof(dst_pathname_cr), "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
        if(safec_rc < EOK)
        {
                ERR_CHK(safec_rc);
        }

        ret = CcspBaseIf_discComponentSupportingNamespace(bus_handle, dst_pathname_cr, obj_name, g_Subsystem, &ppComponents, &size);

        if ( ret == CCSP_SUCCESS && size == 1)
        {
                strncpy(compName, ppComponents[0]->componentName, MAX_STR_SIZE);
                strncpy(dbusPath, ppComponents[0]->dbusPath, MAX_STR_SIZE);
                free_componentStruct_t(bus_handle, size, ppComponents);
                return 1;
        }
        free_componentStruct_t(bus_handle, size, ppComponents);

        return 0;

}

static int Get_comp_paramvalue(char* compName,char* dbusPath,char *param_name,char *param_value){


        if(!param_name || AnscSizeOfString(param_name) == 0) return -1;
        char*                       getList[1] = {0};
        int                         val_size=0;
        int                         ret = -1;
        parameterValStruct_t **parameterval = NULL;

        getList[0]=param_name;
        ret = CcspBaseIf_getParameterValues(bus_handle,compName,dbusPath,getList,1, &val_size, &parameterval);



        if(ret == CCSP_SUCCESS){
                strncpy(param_value, parameterval[0]->parameterValue, MAX_STR_SIZE);
                free_parameterValStruct_t (bus_handle, val_size, parameterval);
                return 1;
        }

        free_parameterValStruct_t (bus_handle, val_size, parameterval);
        return 0;
}

ULONG
CosaGetInstanceNumberByIndex
    (
        char*                      pObjName,
        ULONG                      ulIndex
    )
{
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable
            Currently, we suppose all the parameter is from P&M. */


    return g_GetInstanceNumberByIndex(g_pDslhDmlAgent, pObjName, ulIndex);
}

int GetInstanceNumberByIndex(char* pObjName,unsigned int* Inscont,unsigned int** InsArray){
    int ret = -1;
    char comp_name[MAX_STR_SIZE];
    char dbus_path[MAX_STR_SIZE];


    ret = Get_comp_namespace(comp_name,dbus_path,pObjName);

    if(ret){
        if(CcspBaseIf_GetNextLevelInstances(bus_handle,comp_name,dbus_path,pObjName,Inscont,InsArray) == CCSP_SUCCESS){
           return 0;
        }
    }

    return 1;

}

int g_GetParamValueString(ANSC_HANDLE g_pDslhDmlAgent, char* prefixFullName, char* prefixValue,PULONG uSize){

        UNUSED(g_pDslhDmlAgent);
        return CosaGetParamValueString(prefixFullName, prefixValue, &uSize);
}

int
CosaGetParamValueString
    (
        char*                       pParamName,
        char*                       pBuffer,
        PULONG                      pulSize
    )
{
    char        acTmpReturnValue[256] = {0};
    int         ret = -1;
    char        comp_name[MAX_STR_SIZE];
    char        dbus_path[MAX_STR_SIZE];

#ifdef FEATURE_RDKB_WAN_MANAGER
    if (strstr(pParamName, ETHERNET_INTERFACE_OBJECT))
    {
        if (ANSC_STATUS_FAILURE == RdkBus_GetParamValues(ETH_COMPONENT_NAME, ETH_DBUS_PATH, pParamName, acTmpReturnValue))
        {
            DHCPMGR_LOG_ERROR("[%s][%d]Failed to get param value\n", __FUNCTION__, __LINE__);
            return -1;
        }
        strncpy(pBuffer, acTmpReturnValue, strlen(acTmpReturnValue));
        *pulSize = strlen(acTmpReturnValue) + 1;
        return 0;
    }
#endif
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable
            Currently, we suppose all the parameter is from P&M. */



    ret = Get_comp_namespace(comp_name,dbus_path,pParamName);

    if(ret){

        ret=Get_comp_paramvalue(comp_name,dbus_path,pParamName,acTmpReturnValue);
        if(ret){

                strncpy(pBuffer, acTmpReturnValue, strlen(acTmpReturnValue));
                *pulSize = strlen(acTmpReturnValue) + 1;
                return 0;
        }

    }

        return 1;
}


PUCHAR
CosaUtilGetFullPathNameByKeyword
    (
        PUCHAR                      pTableName,
        PUCHAR                      pParameterName,
        PUCHAR                      pKeyword
    )
{

    unsigned int                    ulNumOfEntries              = 0;
    ULONG                           i                           = 0;
    ULONG                           ulEntryNameLen;
    CHAR                            ucEntryParamName[256]       = {0};
    CHAR                            ucEntryNameValue[256]       = {0};
    CHAR                            ucTmp[128]                  = {0};
    CHAR                            ucTmp2[128]                 = {0};
    CHAR                            ucEntryFullPath[256]        = {0};
    PUCHAR                          pMatchedLowerLayer          = NULL;
    unsigned int*                   ulEntryInstanceNum          = NULL;
    PANSC_TOKEN_CHAIN               pTableListTokenChain        = (PANSC_TOKEN_CHAIN)NULL;
    PANSC_STRING_TOKEN              pTableStringToken           = (PANSC_STRING_TOKEN)NULL;
    PCHAR                           pString                     = NULL;
    PCHAR                           pString2                    = NULL;
    errno_t                         rc                          = -1;

    if ( !pTableName || AnscSizeOfString((const char*)pTableName) == 0 ||
         !pKeyword   || AnscSizeOfString((const char*)pKeyword) == 0   ||
         !pParameterName   || AnscSizeOfString((const char*)pParameterName) == 0
       )
    {
        return NULL;
    }

    pTableListTokenChain = AnscTcAllocate((char*)pTableName, ",");

    if ( !pTableListTokenChain )
    {
        return NULL;
    }

    while ((pTableStringToken = AnscTcUnlinkToken(pTableListTokenChain)))
    {
         /* Array compared against 0*/
            /* Get the string XXXNumberOfEntries */
            pString2 = &pTableStringToken->Name[0];
            pString  = pString2;
            for (i = 0;pTableStringToken->Name[i]; i++)
            {
                if ( pTableStringToken->Name[i] == '.' )
                {
                    pString2 = pString;
                    pString  = &pTableStringToken->Name[i+1];
                }
            }

            pString--;
            pString[0] = '\0';
            //rc = sprintf_s(ucTmp2, sizeof(ucTmp2), "%sNumberOfEntries", pString2);
            rc = sprintf_s(ucTmp2, sizeof(ucTmp2), "%s.", pString2);
            if(rc < EOK)
            {
              ERR_CHK(rc);
              continue;
            }
            pString[0] = '.';

            /* Enumerate the entry in this table */
            if ( TRUE )
            {
                pString2--;
                pString2[0]='\0';
                rc = sprintf_s(ucTmp, sizeof(ucTmp), "%s.%s", pTableStringToken->Name, ucTmp2);
                if(rc < EOK)
                {
                  ERR_CHK(rc);
                  continue;
                }

                pString2[0]='.';

                GetInstanceNumberByIndex (ucTmp,&ulNumOfEntries,&ulEntryInstanceNum);

                for ( i = 0 ; i < ulNumOfEntries; i++ )
                {

                    if ( ulEntryInstanceNum[i] )
                    {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath), "%s%d.", pTableStringToken->Name, ulEntryInstanceNum[i]);
                        if(rc < EOK)
                        {
                          ERR_CHK(rc);
                          continue;
                        }


                        rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName), "%s%s", ucEntryFullPath, pParameterName);
                        if(rc < EOK)
                        {
                          ERR_CHK(rc);
                          continue;
                        }


                        ulEntryNameLen = sizeof(ucEntryNameValue);
                        memset(ucEntryNameValue,0,sizeof(ucEntryNameValue));

                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             (strcmp(ucEntryNameValue, (char*)pKeyword) == 0))
                        {
                            pMatchedLowerLayer =  (PUCHAR)AnscCloneString(ucEntryFullPath);
                            break;
                        }

                    }
                }
            }

            if ( pMatchedLowerLayer )
            {
                break;
            }

        AnscFreeMemory(pTableStringToken);

        if ( ulEntryInstanceNum ){
             AnscFreeMemory(ulEntryInstanceNum);
        }
    }

    if ( pTableListTokenChain )
    {
        AnscTcFree((ANSC_HANDLE)pTableListTokenChain);
    }


    return pMatchedLowerLayer;
}

ANSC_STATUS is_usg_in_bridge_mode(BOOL *pBridgeMode)
{
    char retVal[128] = {'\0'};
    ULONG retLen;
        retLen = sizeof( retVal );
    if (pBridgeMode == NULL)
        return ANSC_STATUS_FAILURE;

    if (0 == CosaGetParamValueString(
                "Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode",
                retVal,
                &retLen)){
        if (strcmp(retVal, "router") == 0)
            *pBridgeMode = FALSE;
        else
            *pBridgeMode = TRUE;
        return ANSC_STATUS_SUCCESS;
    }else
        return ANSC_STATUS_FAILURE;

}


ANSC_STATUS
CosaSListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCOSA_CONTEXT_LINK_OBJECT   pCosaContext
    )
{
    PCOSA_CONTEXT_LINK_OBJECT       pCosaContextEntry = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContext->InstanceNumber < pCosaContextEntry->InstanceNumber )
            {
                AnscSListPushEntryByIndex(pListHead, &pCosaContext->Linkage, ulIndex);

                return ANSC_STATUS_SUCCESS;
            }
        }

        AnscSListPushEntryAtBack(pListHead, &pCosaContext->Linkage);
    }

    return ANSC_STATUS_SUCCESS;
}


PCOSA_CONTEXT_LINK_OBJECT
CosaSListGetEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        ULONG                       InstanceNumber
    )
{
    PCOSA_CONTEXT_LINK_OBJECT       pCosaContextEntry = (PCOSA_CONTEXT_LINK_OBJECT)NULL;
    PSINGLE_LINK_ENTRY              pSLinkEntry       = (PSINGLE_LINK_ENTRY       )NULL;
    ULONG                           ulIndex           = 0;

    if ( pListHead->Depth == 0 )
    {
        return NULL;
    }
    else
    {
        pSLinkEntry = AnscSListGetFirstEntry(pListHead);

        for ( ulIndex = 0; ulIndex < pListHead->Depth; ulIndex++ )
        {
            pCosaContextEntry = ACCESS_COSA_CONTEXT_LINK_OBJECT(pSLinkEntry);
            pSLinkEntry       = AnscSListGetNextEntry(pSLinkEntry);

            if ( pCosaContextEntry->InstanceNumber == InstanceNumber )
            {
                return pCosaContextEntry;
            }
        }
    }

    return NULL;
}


int commonSyseventFd = -1;
token_t commonSyseventToken;

static int openCommonSyseventConnection() {
    if (commonSyseventFd == -1) {
        //commonSyseventFd = s_sysevent_connect(&commonSyseventToken);
        if (IFL_SUCCESS != ifl_init_ctx("cosa_apis_util", IFL_CTX_STATIC))
        {
            DHCPMGR_LOG_ERROR("Failed to init ifl ctx for cosa_apis_util");
        }
        else
        {
            commonSyseventFd = 0;
        }
    }
    return 0;
}

int commonSyseventSet(char* key, char* value){
    if(commonSyseventFd == -1) {
        openCommonSyseventConnection();
    }
    //return sysevent_set(commonSyseventFd, commonSyseventToken, key, value, 0);
    return ifl_set_event(key, value);
}

int commonSyseventGet(char* key, char* value, int valLen){
    if(commonSyseventFd == -1) {
        openCommonSyseventConnection();
    }
    //return sysevent_get(commonSyseventFd, commonSyseventToken, key, value, valLen);
    return ifl_get_event(key, value, valLen);
}

int commonSyseventClose() {
    int retval;

    if(commonSyseventFd == -1) {
        return 0;
    }

    //retval = sysevent_close(commonSyseventFd, commonSyseventToken);
    retval = ifl_deinit_ctx("cosa_apis_util");
    commonSyseventFd = -1;
    return retval;
}

void _get_shell_output(FILE *fp, char *buf, int len)
{
    char * p;

    if (fp)
    {
        if(fgets (buf, len-1, fp) != NULL)
        {
            buf[len-1] = '\0';
            if ((p = strchr(buf, '\n'))) {
                *p = '\0';
            }
        }
    v_secure_pclose(fp);
    }
}

int _get_shell_output2(FILE *fp, char * dststr)
{
    char   buf[256];
//    char * p;
    int   bFound = 0;

    if (fp)
    {
        while( fgets(buf, sizeof(buf), fp) )
        {
            if (strstr(buf, dststr))
            {
                bFound = 1;;
                break;
            }
        }

        v_secure_pclose(fp);
    }

    return bFound;
}


char *safe_strcpy (char *dst, char *src, size_t dst_size)
{
    size_t len;

    if (dst_size == 0)
        return dst;

    len = strlen (src);

    if (len >= dst_size)
    {
        dst[dst_size - 1] = 0;
        return memcpy (dst, src, dst_size - 1);
    }

    return memcpy (dst, src, len + 1);
}

ANSC_STATUS fillCurrentPartnerId
        (
                char*                       pValue,
        PULONG                      pulSize
    )
{
        char buf[PARTNER_ID_LEN];
        memset(buf, 0, sizeof(buf));
    if(ANSC_STATUS_SUCCESS == syscfg_get( NULL, "PartnerID", buf, sizeof(buf)))
    {
         strncpy(pValue ,buf,strlen(buf));
         *pulSize = AnscSizeOfString(pValue);
         return ANSC_STATUS_SUCCESS;
    }
        else
                return ANSC_STATUS_FAILURE;

}


int writeToJson(char *data, char *file)
{
    if (file == NULL || data == NULL)
    {
        DHCPMGR_LOG_WARNING("%s : %d Invalid input parameter", __FUNCTION__,__LINE__);
        return -1;
    }
    FILE *fp;
    fp = fopen(file, "w");
    if (fp == NULL )
    {
        DHCPMGR_LOG_WARNING("%s : %d Failed to open file %s\n", __FUNCTION__,__LINE__,file);
        return -1;
    }

    fwrite(data, strlen(data), 1, fp);
    fclose(fp);
    return 0;
}


ANSC_STATUS UpdateJsonParamLegacy
        (
                char*                       pKey,
                char*                   PartnerId,
                char*                   pValue
    )
{
        cJSON *partnerObj = NULL;
        cJSON *json = NULL;
        FILE *fileRead = NULL;
        char * cJsonOut = NULL;
        char* data = NULL;
         int len ;
         int configUpdateStatus = -1;
         fileRead = fopen( PARTNERS_INFO_FILE, "r" );
         if( fileRead == NULL )
         {
                 DHCPMGR_LOG_WARNING("%s-%d : Error in opening JSON file\n" , __FUNCTION__, __LINE__ );
                 return ANSC_STATUS_FAILURE;
         }

         fseek( fileRead, 0, SEEK_END );
         len = ftell( fileRead );
         /* Argument cannot be negative*/
         if(len < 0) {
               DHCPMGR_LOG_WARNING("%s-%d : Error in file handle\n" , __FUNCTION__, __LINE__ );
               fclose( fileRead );
               return ANSC_STATUS_FAILURE;
         }
         fseek( fileRead, 0, SEEK_SET );
         data = ( char* )malloc( sizeof(char) * (len + 1) );
         if (data != NULL)
         {
                memset( data, 0, ( sizeof(char) * (len + 1) ));
                int chk_ret = fread( data, 1, len, fileRead );
                if(chk_ret <=0){
                 DHCPMGR_LOG_WARNING("%s-%d : Failed to read the data from file \n", __FUNCTION__, __LINE__);
                 fclose( fileRead );
                 free(data);
                 return ANSC_STATUS_FAILURE;
                }
         }
         else
         {
                 DHCPMGR_LOG_WARNING("%s-%d : Memory allocation failed \n", __FUNCTION__, __LINE__);
                 fclose( fileRead );
                 return ANSC_STATUS_FAILURE;
         }

         fclose( fileRead );
         /* String not null terminated*/
         data[len]='\0';
         if ( data == NULL )
         {
                DHCPMGR_LOG_WARNING("%s-%d : fileRead failed \n", __FUNCTION__, __LINE__);
                return ANSC_STATUS_FAILURE;
         }
         else if ( strlen(data) != 0)
         {
                 json = cJSON_Parse( data );
                 if( !json )
                 {
                         DHCPMGR_LOG_WARNING(  "%s : json file parser error : [%d]\n", __FUNCTION__,__LINE__);
                         free(data);
                         return ANSC_STATUS_FAILURE;
                 }
                 else
                 {
                         partnerObj = cJSON_GetObjectItem( json, PartnerId );
                         if ( NULL != partnerObj)
                         {
                                 if (NULL != cJSON_GetObjectItem( partnerObj, pKey) )
                                 {
                                         cJSON_ReplaceItemInObject(partnerObj, pKey, cJSON_CreateString(pValue));
                                         cJsonOut = cJSON_Print(json);
                                         DHCPMGR_LOG_WARNING( "Updated json content is %s\n", cJsonOut);
                                         configUpdateStatus = writeToJson(cJsonOut, PARTNERS_INFO_FILE);
                                         free(cJsonOut);
                                         if ( !configUpdateStatus)
                                         {
                                                 DHCPMGR_LOG_WARNING( "Updated Value for %s partner\n",PartnerId);
                                                 DHCPMGR_LOG_WARNING( "Param:%s - Value:%s\n",pKey,pValue);
                                         }
                                         else
                                        {
                                                 DHCPMGR_LOG_WARNING( "Failed to update value for %s partner\n",PartnerId);
                                                 DHCPMGR_LOG_WARNING( "Param:%s\n",pKey);
                                                 cJSON_Delete(json);
                                                 return ANSC_STATUS_FAILURE;
                                        }
                                 }
                                else
                                {
                                        DHCPMGR_LOG_WARNING("%s - OBJECT  Value is NULL %s\n", pKey,__FUNCTION__ );
                                        cJSON_Delete(json);
                                        return ANSC_STATUS_FAILURE;
                                }

                         }
                         else
                         {
                                DHCPMGR_LOG_WARNING("%s - PARTNER ID OBJECT Value is NULL\n", __FUNCTION__ );
                                cJSON_Delete(json);
                                return ANSC_STATUS_FAILURE;
                         }
                        cJSON_Delete(json);
                 }
          }
          else
          {
                DHCPMGR_LOG_WARNING("PARTNERS_INFO_FILE %s is empty\n", PARTNERS_INFO_FILE);
                /* Resource leak*/
                if (data)
                   free(data);
                return ANSC_STATUS_FAILURE;
          }
         return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS UpdateJsonParam
        (
                char*                       pKey,
                char*                   PartnerId,
                char*                   pValue,
                char*                   pSource,
                char*                   pCurrentTime
    )
{
        cJSON *partnerObj = NULL;
        cJSON *json = NULL;
        FILE *fileRead = NULL;
        char * cJsonOut = NULL;
        char* data = NULL;
         int len ;
         int configUpdateStatus = -1;
         fileRead = fopen( BOOTSTRAP_INFO_FILE, "r" );
         if( fileRead == NULL )
         {
                 DHCPMGR_LOG_WARNING("%s-%d : Error in opening JSON file\n" , __FUNCTION__, __LINE__ );
                 return ANSC_STATUS_FAILURE;
         }

         fseek( fileRead, 0, SEEK_END );
         len = ftell( fileRead );
         /* Argument cannot be negative*/
         if (len < 0) {
             DHCPMGR_LOG_WARNING("%s-%d : Error in File handle\n" , __FUNCTION__, __LINE__ );
             fclose( fileRead );
             return ANSC_STATUS_FAILURE;
         }
         fseek( fileRead, 0, SEEK_SET );
         data = ( char* )malloc( sizeof(char) * (len + 1) );
         if (data != NULL)
         {
                memset( data, 0, ( sizeof(char) * (len + 1) ));
                int chk_ret = fread( data, 1, len, fileRead );
                if(chk_ret <= 0){
                 DHCPMGR_LOG_WARNING("%s-%d : Failed to read the data from file \n", __FUNCTION__, __LINE__);
                 fclose( fileRead );
                 free(data);
                 return ANSC_STATUS_FAILURE;
                }
         }
         else
         {
                 DHCPMGR_LOG_WARNING("%s-%d : Memory allocation failed \n", __FUNCTION__, __LINE__);
                 fclose( fileRead );
                 return ANSC_STATUS_FAILURE;
         }

         fclose( fileRead );
         /* String not null terminated*/
         data[len] = '\0';
         if ( data == NULL )
         {
                DHCPMGR_LOG_WARNING("%s-%d : fileRead failed \n", __FUNCTION__, __LINE__);
                return ANSC_STATUS_FAILURE;
         }
         else if ( strlen(data) != 0)
         {
                 json = cJSON_Parse( data );
                 if( !json )
                 {
                         DHCPMGR_LOG_WARNING(  "%s : json file parser error : [%d]\n", __FUNCTION__,__LINE__);
                         free(data);
                         return ANSC_STATUS_FAILURE;
                 }
                 else
                 {
                         partnerObj = cJSON_GetObjectItem( json, PartnerId );
                         if ( NULL != partnerObj)
                         {
                                 cJSON *paramObj = cJSON_GetObjectItem( partnerObj, pKey);
                                 if (NULL != paramObj )
                                 {
                                         cJSON_ReplaceItemInObject(paramObj, "ActiveValue", cJSON_CreateString(pValue));
                                         cJSON_ReplaceItemInObject(paramObj, "UpdateTime", cJSON_CreateString(pCurrentTime));
                                         cJSON_ReplaceItemInObject(paramObj, "UpdateSource", cJSON_CreateString(pSource));

                                         cJsonOut = cJSON_Print(json);
                                         DHCPMGR_LOG_WARNING( "Updated json content is %s\n", cJsonOut);
                                         configUpdateStatus = writeToJson(cJsonOut, BOOTSTRAP_INFO_FILE);
                                         unsigned int flags = 0;
                                         FILE *fp = fopen(CLEAR_TRACK_FILE, "r");
                                         if (fp)
                                         {
                                             fscanf(fp, "%u", &flags);
                                             fclose(fp);
                                         }
                                         if ((flags & NVRAM_BOOTSTRAP_CLEARED) == 0)
                                         {
                                             DHCPMGR_LOG_WARNING("%s: Updating %s\n", __FUNCTION__, BOOTSTRAP_INFO_FILE_BACKUP);
                                             writeToJson(cJsonOut, BOOTSTRAP_INFO_FILE_BACKUP);
                                         }
                                         free(cJsonOut);
                                         if ( !configUpdateStatus)
                                         {
                                                 DHCPMGR_LOG_WARNING( "Bootstrap config update: %s, %s, %s, %s \n", pKey, pValue, PartnerId, pSource);
                                         }
                                         else
                                        {
                                                 DHCPMGR_LOG_WARNING( "Failed to update value for %s partner\n",PartnerId);
                                                 DHCPMGR_LOG_WARNING( "Param:%s\n",pKey);
                                                 cJSON_Delete(json);
                                                 return ANSC_STATUS_FAILURE;
                                        }
                                 }
                                else
                                {
                                        DHCPMGR_LOG_WARNING("%s - OBJECT  Value is NULL %s\n", pKey,__FUNCTION__ );
                                        cJSON_Delete(json);
                                        return ANSC_STATUS_FAILURE;
                                }

                         }
                         else
                         {
                                DHCPMGR_LOG_WARNING("%s - PARTNER ID OBJECT Value is NULL\n", __FUNCTION__ );
                                cJSON_Delete(json);
                                return ANSC_STATUS_FAILURE;
                         }
                        cJSON_Delete(json);
                 }
          }
          else
          {
                DHCPMGR_LOG_WARNING("BOOTSTRAP_INFO_FILE %s is empty\n", BOOTSTRAP_INFO_FILE);
                free(data);
                return ANSC_STATUS_FAILURE;
          }

         //Also update in the legacy file /nvram/partners_defaults.json for firmware roll over purposes.
         UpdateJsonParamLegacy(pKey, PartnerId, pValue);

         return ANSC_STATUS_SUCCESS;
}

/*
int lm_get_host_by_mac(char *mac, LM_cmd_common_result_t *pHost){


        if(!mac || AnscSizeOfString((const char*)mac) == 0) return -1;
        ULONG                       NumberofEntries = 0;
        char                        ucEntryFullPath[MAX_STR_SIZE]={0};
        char                        ucEntryParamName[MAX_STR_SIZE]={0};
        char                        lm_param_name[MAX_STR_SIZE]={0};
        char                        ucEntryNameValue[MAX_STR_SIZE]={0};
        ULONG                       i;
        ULONG                       ulEntryInstanceNum;
        ULONG                       ulEntryNameLen;
        errno_t                     rc= -1;




        memset(lm_param_name,0,MAX_STR_SIZE);
        strncpy(lm_param_name,"Device.Hosts.HostNumberOfEntries", MAX_STR_SIZE);

        NumberofEntries = CosaGetParamValueUlong(lm_param_name);

        memset(lm_param_name,0,MAX_STR_SIZE);
        strncpy(lm_param_name,"Device.Hosts.Host.", MAX_STR_SIZE);

        for ( i = 0 ; i < NumberofEntries; i++ )
        {
                ulEntryInstanceNum = CosaGetInstanceNumberByIndex(lm_param_name, i);

                if ( ulEntryInstanceNum )
                {
                        rc = sprintf_s(ucEntryFullPath, sizeof(ucEntryFullPath), "%s%lu.", lm_param_name, ulEntryInstanceNum);
                        if(rc < EOK)
                        {
                          ERR_CHK(rc);
                          continue;
                        }

                        rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName), "%s%s", ucEntryFullPath, "PhysAddress");
                        if(rc < EOK)
                        {
                          ERR_CHK(rc);
                          continue;
                        }

                        ulEntryNameLen = sizeof(ucEntryNameValue);
                        if ( ( 0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)) &&
                             (strcmp(ucEntryNameValue, (char*)mac) == 0))
                        {
                                memset(ucEntryParamName,0,sizeof(ucEntryParamName));

                                rc = sprintf_s(ucEntryParamName, sizeof(ucEntryParamName), "%s%s", ucEntryFullPath,"Layer1Interface");
                                if(rc < EOK)
                                {
                                  ERR_CHK(rc);
                                  continue;
                                }
                                ulEntryNameLen = sizeof(ucEntryNameValue);
                                if(0 == CosaGetParamValueString(ucEntryParamName, ucEntryNameValue, &ulEntryNameLen)){

                                        strncpy(pHost->data.host.l1IfName, ucEntryNameValue, sizeof(pHost->data.host.l1IfName));
                                        pHost->result=0;
                                }else{
                                        DHCPMGR_LOG_ERROR("%s failed to get ucEntryParamName = %s\n",__FUNCTION__,ucEntryParamName);
                               }

                            break;
                            return 0;
                        }
                    }
                }

       return -1;
}
*/

#ifdef DHCPV6C_PSM_ENABLE
INT PsmWriteParameter( char *pParamName, char *pParamVal )
{
    INT     retPsmSet  = CCSP_SUCCESS;

    if( ( NULL == pParamName) || ( NULL == pParamVal ) )
    {
        DHCPMGR_LOG_ERROR("%s Invalid Input Parameters\n", __FUNCTION__);
        return CCSP_FAILURE;
    }

    retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, pParamName, ccsp_string, pParamVal);
    if (retPsmSet != CCSP_SUCCESS)
    {
        DHCPMGR_LOG_INFO("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, pParamName, pParamVal);
    }

    return retPsmSet;
}

INT PsmReadParameter( char *pParamName, char *pReturnVal, int returnValLength )
{
    INT     retPsmGet     = CCSP_SUCCESS;
    CHAR   *param_value   = NULL;

    if( ( NULL == pParamName) || ( NULL == pReturnVal ) || ( 0 >= returnValLength ) )
    {
        DHCPMGR_LOG_ERROR("%s Invalid Input Parameters\n", __FUNCTION__);
        return CCSP_FAILURE;
    }

    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, pParamName, NULL, &param_value);
    if (retPsmGet != CCSP_SUCCESS) {
        DHCPMGR_LOG_ERROR("%s Error %d reading %s\n", __FUNCTION__, retPsmGet, pParamName);
    }
    else {
        snprintf(pReturnVal, returnValLength, "%s", param_value);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(param_value);
    }

    return retPsmGet;
}
#endif //DHCPV6C_PSM_ENABLE
