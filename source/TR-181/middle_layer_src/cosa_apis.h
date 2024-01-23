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


/**********************************************************************

    module:   cosa_apis.h

        This is base file for all parameters H files.

    ---------------------------------------------------------------

    description:

        All cosa_xxx_apis.h will include this file and realize 
        necessary functions in the struct of this file.

    ---------------------------------------------------------------

    environment:

        COSA independent

    ---------------------------------------------------------------

    author:

        Yan Li

    ---------------------------------------------------------------

    revision:

        01/12/2011    initial revision.

**********************************************************************/


#ifndef  _COSA_APIS_H
#define  _COSA_APIS_H

#include "ansc_platform.h"
#include "ansc_string_util.h"

#include "cosa_dml_api_common.h"
//#include "cosa_apis_util.h"
//#include "cosa_apis_busutil.h"

// for PSM access
extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
// PSM access MACRO
#define _PSM_WRITE_PARAM(_PARAM_NAME) { \
        errno_t rc = -1; \
        rc = sprintf_s(param_name, sizeof(param_name), _PARAM_NAME, instancenum); \
        if(rc < EOK) { \
            ERR_CHK(rc); \
        } \
        retPsmSet = PSM_Set_Record_Value2(bus_handle,g_Subsystem, param_name, ccsp_string, param_value); \
        if (retPsmSet != CCSP_SUCCESS) { \
            AnscTraceFlow(("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, param_name, param_value));\
        } \
        else \
        { \
            /*AnscTraceFlow(("%s: retPsmSet == CCSP_SUCCESS writing %s = %s \n", __FUNCTION__,param_name,param_value)); */\
        } \
        _ansc_memset(param_name, 0, sizeof(param_name)); \
        _ansc_memset(param_value, 0, sizeof(param_value)); \
    }

#define _PSM_READ_PARAM(_PARAM_NAME) { \
        errno_t rc = -1; \
        _ansc_memset(param_name, 0, sizeof(param_name)); \
        rc = sprintf_s(param_name, sizeof(param_name), _PARAM_NAME, instancenum); \
        if(rc < EOK) { \
            ERR_CHK(rc); \
        } \
        retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, param_name, NULL, &param_value); \
        if (retPsmGet != CCSP_SUCCESS) { \
            AnscTraceFlow(("%s Error %d reading %s %s\n", __FUNCTION__, retPsmGet, param_name, param_value));\
        } \
        else { \
            /*AnscTraceFlow(("%s: retPsmGet == CCSP_SUCCESS reading %s = \n%s\n", __FUNCTION__,param_name, param_value)); */\
        } \
    }

#define _PSM_WRITE_TBL_PARAM(_PARAM_NAME) { \
        errno_t rc = -1; \
        rc = sprintf_s(param_name, sizeof(param_name), _PARAM_NAME, tblInstancenum, instancenum); \
        if(rc < EOK) { \
            ERR_CHK(rc); \
        } \
        retPsmSet = PSM_Set_Record_Value2(bus_handle,g_Subsystem, param_name, ccsp_string, param_value); \
        if (retPsmSet != CCSP_SUCCESS) { \
            AnscTraceFlow(("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, param_name, param_value));\
            /*printf("%s Error %d writing %s %s\n", __FUNCTION__, retPsmSet, param_name, param_value);*/\
        } \
        else \
        { \
            /*AnscTraceFlow(("%s: retPsmGet == CCSP_SUCCESS writing %s = %s \n", __FUNCTION__,param_name,param_value));*/ \
            /*printf("%s: retPsmSet == CCSP_SUCCESS writing %s = %s \n", __FUNCTION__,param_name,param_value);*/ \
        } \
        _ansc_memset(param_name, 0, sizeof(param_name)); \
        _ansc_memset(param_value, 0, sizeof(param_value)); \
    }

#define _PSM_READ_TBL_PARAM(_PARAM_NAME) { \
        errno_t rc = -1; \
        _ansc_memset(param_name, 0, sizeof(param_name)); \
        rc = sprintf_s(param_name, sizeof(param_name), _PARAM_NAME, tblInstancenum, instancenum); \
        if(rc < EOK) { \
            ERR_CHK(rc); \
        } \
        retPsmGet = PSM_Get_Record_Value2(bus_handle,g_Subsystem, param_name, NULL, &param_value); \
        if (retPsmGet != CCSP_SUCCESS) { \
            AnscTraceFlow(("%s Error %d reading %s %s\n", __FUNCTION__, retPsmGet, param_name, param_value));\
            /*printf("%s Error %d reading %s %s\n", __FUNCTION__, retPsmGet, param_name, param_value);*/\
        } \
        else { \
            /*AnscTraceFlow(("%s: retPsmGet == CCSP_SUCCESS reading %s = \n%s\n", __FUNCTION__,param_name, param_value)); */\
            /*printf("%s: retPsmGet == CCSP_SUCCESS reading %s = \n%s\n", __FUNCTION__,param_name, param_value);*/ \
        } \
    }

typedef  ANSC_HANDLE
(*PFN_COSADM_CREATE)
    (
        VOID
    );

typedef  ANSC_STATUS
(*PFN_COSADM_REMOVE)
    (
        ANSC_HANDLE                 hThisObject
    );

typedef  ANSC_STATUS
(*PFN_COSADM_INITIALIZE)
    (
        ANSC_HANDLE                 hThisObject
    );

/*
 * the main struct in cosa_xxx_apis.h need includes this struct and realize all functions. 
 */
#define  COSA_BASE_CONTENT                                                                  \
    /* start of object class content */                                                     \
    ULONG                           Oid;                                                    \
    ANSC_HANDLE                     hSbContext;                                             \
                                                                                            \
    PFN_COSADM_CREATE               Create;                                                 \
    PFN_COSADM_REMOVE               Remove;                                                 \
    PFN_COSADM_INITIALIZE           Initialize;                                             \

typedef  struct
_COSA_BASE_OBJECT
{
    COSA_BASE_CONTENT
}
COSA_BASE_OBJECT,  *PCOSA_BASE_OBJECT;

/*
*  This struct is for creating entry context link in writable table when call GetEntry()
*/
#define  COSA_CONTEXT_LINK_CLASS_CONTENT                                                    \
         SINGLE_LINK_ENTRY                Linkage;                                          \
         ANSC_HANDLE                      hContext;                                         \
         ANSC_HANDLE                      hParentTable;  /* Back pointer */                 \
         ULONG                            InstanceNumber;                                   \
         BOOL                             bNew;                                             \
         ANSC_HANDLE                      hPoamIrepUpperFo;                                 \
         ANSC_HANDLE                      hPoamIrepFo;                                      \

typedef  struct
_COSA_CONTEXT_LINK_OBJECT
{
    COSA_CONTEXT_LINK_CLASS_CONTENT
}
COSA_CONTEXT_LINK_OBJECT,  *PCOSA_CONTEXT_LINK_OBJECT;

#define  ACCESS_COSA_CONTEXT_LINK_OBJECT(p)              \
         ACCESS_CONTAINER(p, COSA_CONTEXT_LINK_OBJECT, Linkage)

#define COSA_CONTEXT_LINK_INITIATION_CONTENT(cxt)                                      \
    (cxt)->hContext            = (ANSC_HANDLE)NULL;                                    \
    (cxt)->hParentTable        = (ANSC_HANDLE)NULL;                                    \
    (cxt)->InstanceNumber      = 0;                                                    \
    (cxt)->bNew                = FALSE;                                                \
    (cxt)->hPoamIrepUpperFo    = (ANSC_HANDLE)NULL;                                    \
    (cxt)->hPoamIrepFo         = (ANSC_HANDLE)NULL;                                    \

#define  COSA_DML_ALIAS_NAME_LENGTH                 64


ANSC_STATUS
CosaSListPushEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        PCOSA_CONTEXT_LINK_OBJECT   pCosaContext
    );

PCOSA_CONTEXT_LINK_OBJECT
CosaSListGetEntryByInsNum
    (
        PSLIST_HEADER               pListHead,
        ULONG                       InstanceNumber
    );

#endif
