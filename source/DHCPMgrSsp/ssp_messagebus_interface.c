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

/*********************************************************************************

    description:

        This is the template file of ssp_messagebus_interface.c for XxxxSsp.
        You may fill in the functions below if needed.

        * ssp_Mbi_Initialize
        * ssp_finalize
        * ssp_Mbi_BusCheck    
        * ssp_Mbi_FreeResources

  ------------------------------------------------------------------------------

    revision:

        09/08/2011    initial revision.

**********************************************************************************/

#include "ssp_global.h"
#include "safec_lib_common.h"
#include "util.h"

ANSC_HANDLE                 bus_handle               = NULL;
extern char                 g_Subsystem[32];
extern ANSC_HANDLE          g_MessageBusHandle_Irep; 
extern char                 g_SubSysPrefix_Irep[32];

ANSC_STATUS
ssp_Mbi_MessageBusEngage
    (
        char * component_id,
        char * config_file,
        char * path
    )
{
    ANSC_STATUS                 returnStatus       = ANSC_STATUS_SUCCESS;
    CCSP_Base_Func_CB           cb                 = {0};
    errno_t        rc = -1;

    if ( ! component_id || ! path )
    {
        DHCPMGR_LOG_ERROR(" !!! ssp_Mbi_MessageBusEngage: component_id or path is NULL !!!\n");
        return ANSC_STATUS_FAILURE;
    }

    /* Connect to message bus */
    returnStatus = 
        CCSP_Message_Bus_Init
            (
                component_id,
                config_file,
                &bus_handle,
                (CCSP_MESSAGE_BUS_MALLOC)Ansc_AllocateMemory_Callback,           /* mallocfc, use default */
                Ansc_FreeMemory_Callback                /* freefc,   use default */
            );

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        DHCPMGR_LOG_ERROR(" !!! SSD Message Bus Init ERROR !!!\n");

        return returnStatus;
    }

    DHCPMGR_LOG_INFO("INFO: bus_handle: 0x%p \n", bus_handle);
    g_MessageBusHandle_Irep = bus_handle;
    char *pSubsystem = g_Subsystem;
    rc =  strcpy_s(g_SubSysPrefix_Irep,sizeof(g_SubSysPrefix_Irep), pSubsystem);
     if(rc != EOK)
    {
         ERR_CHK(rc);
         return ANSC_STATUS_FAILURE;
     }

    CCSP_Msg_SleepInMilliSeconds(1000);

    /* Base interface implementation that will be used cross components */
    cb.getParameterValues     = CcspCcMbi_GetParameterValues;
    cb.setParameterValues     = CcspCcMbi_SetParameterValues;
    cb.setCommit              = CcspCcMbi_SetCommit;
    cb.setParameterAttributes = CcspCcMbi_SetParameterAttributes;
    cb.getParameterAttributes = CcspCcMbi_GetParameterAttributes;
    cb.AddTblRow              = CcspCcMbi_AddTblRow;
    cb.DeleteTblRow           = CcspCcMbi_DeleteTblRow;
    cb.getParameterNames      = CcspCcMbi_GetParameterNames;
    cb.currentSessionIDSignal = CcspCcMbi_CurrentSessionIdSignal;

    /* Base interface implementation that will only be used by ssd */
    cb.initialize             = ssp_Mbi_Initialize;
    cb.finalize               = ssp_Mbi_Finalize;
    cb.freeResources          = ssp_Mbi_FreeResources;
    cb.busCheck               = ssp_Mbi_Buscheck;

    CcspBaseIf_SetCallback(bus_handle, &cb);

    /* Register event/signal */
    returnStatus = 
        CcspBaseIf_Register_Event
            (
                bus_handle,
                0,
                "currentSessionIDSignal"
            );

    if ( returnStatus != CCSP_Message_Bus_OK )
    {
         DHCPMGR_LOG_ERROR(" !!! CCSP_Message_Bus_Register_Event: CurrentSessionIDSignal ERROR returnStatus: %lu!!!\n", returnStatus);

        return returnStatus;
    }

    return ANSC_STATUS_SUCCESS;

}


int
ssp_Mbi_Initialize
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    
    return 0;
}


int
ssp_Mbi_Finalize
    (
        void*               user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    returnStatus = ssp_cancel();

    return ( returnStatus == ANSC_STATUS_SUCCESS ) ? 0 : 1;
}


int
ssp_Mbi_Buscheck
    (
        void*               user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    return 0;
}


int
ssp_Mbi_FreeResources
    (
        int                 priority,
        void                * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    if ( priority == CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_Low )
    {
        /* Currently do nothing */
    }
    else if ( priority == CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_High )
    {
        returnStatus = ssp_cancel();
    }
    
    return ( returnStatus == ANSC_STATUS_SUCCESS ) ? 0 : 1;
}


