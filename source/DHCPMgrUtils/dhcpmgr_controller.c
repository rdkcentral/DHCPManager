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

/* ---- Include Files ---------------------------------------- */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include "ansc_platform.h"
#include "cosa_apis.h"
#include "cosa_dml_api_common.h"
#include "cosa_dhcpv4_apis.h"
#include "cosa_dhcpv4_internal.h"
#include "cosa_dhcpv4_dml.h"



/* ---- Global Constants -------------------------- */

static void* DhcpMgr_MainController( void *arg );


int DhcpMgr_StartMainController()
{
    pthread_t threadId;
    int ret = -1;

    ret = pthread_create( &threadId, NULL, &DhcpMgr_MainController, NULL );

    if( 0 != ret )
    {
        DHCPMGR_LOG_ERROR("%s %d - Failed to start Main Controller Thread Error:%d\n", __FUNCTION__, __LINE__, ret);
    }
    else
    {
        DHCPMGR_LOG_INFO("%s %d - Main Controller Thread Started Successfully\n", __FUNCTION__, __LINE__);
        ret = 0;
    }

    return ret;
}


static void* DhcpMgr_MainController( void *args )
{
    (void) args;
    //detach thread from caller stack
    pthread_detach(pthread_self());

    BOOL bRunning = TRUE;
    struct timeval tv;
    int n = 0;

    while (bRunning)
    {
        /* Wait up to 250 milliseconds */
        tv.tv_sec = 0;
        tv.tv_usec = 250000;

        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }

        //DHCPv4 client entries
        //TODO : implement a internal DHCP structures and APIs, replace COSA APIs
        PCOSA_DML_DHCPC_FULL            pDhcpc        = NULL;
        PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink  = NULL;
        PSINGLE_LINK_ENTRY              pSListEntry   = NULL;
        ULONG ulIndex;
        ULONG instanceNum;
        ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);

        for ( ulIndex = 0; ulIndex < clientCount; ulIndex++ )
        {
            pSListEntry = (PSINGLE_LINK_ENTRY)Client_GetEntry(NULL,ulIndex,&instanceNum);
            if ( pSListEntry )
            {
                pDhcpCxtLink          = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
                pDhcpc            = (PCOSA_DML_DHCPC_FULL)pDhcpCxtLink->hContext;
            }

            if (!pDhcpc)
            {
                DHCPMGR_LOG_ERROR("%s : pDhcpc is NULL\n",__FUNCTION__);
                continue;
            }

        }
    }
    return NULL;

}