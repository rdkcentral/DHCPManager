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
#include "dhcpv4_interface.h"
#include "dhcpmgr_controller.h"
#include "dhcp_lease_monitor_thrd.h"
#include "dhcp_client_common_utils.h"



/* ---- Global Constants -------------------------- */

static void* DhcpMgr_MainController( void *arg );

/**
 * @brief Starts the main controller thread.
 *
 * This function initializes and starts the main controller thread for the DHCP Manager.
 *
 * @return int Returns 0 on success, or a negative error code on failure.
 */
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

/**
 * @brief Builds the DHCPv4 option lists.
 *
 * This function constructs the `req_opt_list` and `send_opt_list` from the DML entries.
 *
 * @param[in] hInsContext A handle to the DHCP client context.
 * @param[out] req_opt_list A pointer to the list of requested DHCP options.
 * @param[out] send_opt_list A pointer to the list of DHCP options to be sent.
 *
 * @return int Returns 0 on success, or a negative error code on failure.
 */
static int DhcpMgr_build_dhcpv4_opt_list (PCOSA_CONTEXT_DHCPC_LINK_OBJECT hInsContext, dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
    PCOSA_DML_DHCPC_REQ_OPT         pDhcpReqOpt   = NULL;
    PCOSA_DML_DHCP_OPT              pDhcpSentOpt  = NULL;
    ULONG                           noOfReqOpt    = -1;
    ULONG                           noOfSentOpt   = -1;
    PCOSA_DML_DHCPC_FULL pDhcpc                   = (PCOSA_DML_DHCPC_FULL)hInsContext->hContext;

    DHCPMGR_LOG_INFO("%s %d: Entered \n",__FUNCTION__, __LINE__);
    noOfReqOpt = CosaDmlDhcpcGetNumberOfReqOption(hInsContext, pDhcpc->Cfg.InstanceNumber);

    for (ULONG reqIdx = 0; reqIdx < noOfReqOpt; reqIdx++)
    {
        pDhcpReqOpt = CosaDmlDhcpcGetReqOption_Entry(hInsContext, reqIdx);
        if (!pDhcpReqOpt)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcpReqOpt is NULL",__FUNCTION__);
        }
        else if (pDhcpReqOpt->bEnabled)
        {
            add_dhcp_opt_to_list(req_opt_list, (int)pDhcpReqOpt->Tag, NULL);
        }
    }
    noOfSentOpt = CosaDmlDhcpcGetNumberOfSentOption(hInsContext, pDhcpc->Cfg.InstanceNumber);

    for (ULONG sentIdx = 0; sentIdx < noOfSentOpt; sentIdx++)
    {
        pDhcpSentOpt = CosaDmlDhcpcGetSentOption_Entry(hInsContext, sentIdx);

        if (!pDhcpSentOpt)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcpSentOpt is NULL",__FUNCTION__);
        }
        else if (pDhcpSentOpt->bEnabled)
        {
            //TODO: add verdor specific options API call
            add_dhcp_opt_to_list(send_opt_list, (int)pDhcpSentOpt->Tag, (char *)pDhcpSentOpt->Value);
        }
    }

    return 0;
}



static void* DhcpMgr_MainController( void *args )
{
    (void) args;
    //detach thread from caller stack
    pthread_detach(pthread_self());

    DHCPMGR_LOG_INFO("%s %d DhcpMgr_MainController started \n", __FUNCTION__, __LINE__);
    BOOL bRunning = TRUE;
    struct timeval tv;
    int n = 0;

    int retStatus = DhcpMgr_LeaseMonitor_Start();
    if(retStatus < 0)
    {
        DHCPMGR_LOG_INFO("%s %d - Lease Monitor Thread failed to start!\n", __FUNCTION__, __LINE__ );
    }

    while (bRunning)
    {
        /* Wait up to 250 milliseconds */
        tv.tv_sec = 0;
        tv.tv_usec = 250000;
        //TODO : add a Signaling mechanism instead of sleep.
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
            
            pthread_mutex_lock(&pDhcpc->mutex); //MUTEX lock
            if(pDhcpc->Cfg.bEnabled == TRUE )
            {
                if(pDhcpc->Info.Status == COSA_DML_DHCP_STATUS_Disabled)
                {
                    ////DHCP client Enabled, start the client if not started.
                    DHCPMGR_LOG_INFO("%s %d: Starting dhcpv4 client on %s\n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
                    
                    dhcp_opt_list *req_opt_list = NULL;
                    dhcp_opt_list *send_opt_list = NULL;
                    DhcpMgr_build_dhcpv4_opt_list (pDhcpCxtLink, &req_opt_list, &send_opt_list);

                    pDhcpc->Info.ClientProcessId  = start_dhcpv4_client(pDhcpc->Cfg.Interface, req_opt_list, send_opt_list);

                    //Free optios list
                    if(req_opt_list)
                        free_opt_list_data (req_opt_list);
                    if(send_opt_list)
                        free_opt_list_data (send_opt_list);

                    if(pDhcpc->Info.ClientProcessId > 0 ) 
                    {
                        pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Enabled;
                        DHCPMGR_LOG_INFO("%s %d: dhcpv4 client for %s started PID : %d \n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pDhcpc->Info.ClientProcessId);
                        //TODO: add success rbus event 
                    }
                    else
                    {
                        DHCPMGR_LOG_INFO("%s %d: dhcpv4 client for %s failed to start \n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
                        //TODO: add success rbus event 
                    }

                } 
                else if (pDhcpc->Cfg.Renew == TRUE)
                {
                    DHCPMGR_LOG_INFO("%s %d: Triggering renew for  dhcpv4 client : %s PID : %d\n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pDhcpc->Info.ClientProcessId);
                    send_dhcpv4_renew(pDhcpc->Info.ClientProcessId);
                    pDhcpc->Cfg.Renew = FALSE;
                }

                //Process new lease
                DhcpMgr_ProcessV4Lease(pDhcpc);
            }
            else
            {
                //DHCP client disabled, stop the client if it is running.
                if(pDhcpc->Info.Status == COSA_DML_DHCP_STATUS_Enabled)
                {
                    DHCPMGR_LOG_INFO("%s %d: Stopping the dhcpv4 client : %s PID : %d \n",__FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pDhcpc->Info.ClientProcessId);
                    stop_dhcpv4_client(pDhcpc->Info.ClientProcessId);
                    pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
                    pDhcpc->Cfg.Renew = FALSE;
                    DhcpMgr_clearDHCPv4Lease(pDhcpc);
                }
            }

            pthread_mutex_unlock(&pDhcpc->mutex); //MUTEX unlock

        }
    }
    return NULL;

}

/**
 * @brief Adds a new DHCPv4 lease.
 *
 * This function locates the DHCPv4 client interface using the provided interface name (`ifName`) and updates the `pDhcpc->NewLeases` linked list with the new lease information.
 *  If the operation fails, it frees the memory allocated for the new lease.
 *
 * @param[in] ifName The name of the interface.
 * @param[in] newLease A pointer to the new DHCPv4 lease information.
 */
void DHCPMgr_AddDhcpv4Lease(char * ifName, DHCPv4_PLUGIN_MSG *newLease)
{
    PCOSA_DML_DHCPC_FULL            pDhcpc        = NULL;
    PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink  = NULL;
    PSINGLE_LINK_ENTRY              pSListEntry   = NULL;
    ULONG ulIndex;
    ULONG instanceNum;
    BOOL interfaceFound                           = FALSE;
    ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);
    //iterate all entries and find the ineterface with the ifname
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

        pthread_mutex_lock(&pDhcpc->mutex); //MUTEX lock

        // Verify if the DHCP clients are running. There may be multiple DHCP client interfaces with the same name that are not active.
        if(strcmp(ifName, pDhcpc->Cfg.Interface) == 0)
        {
            DHCPv4_PLUGIN_MSG *temp = pDhcpc->NewLeases;
            //Find the tail of the list
            if (temp == NULL) 
            {
                // If the list is empty, add the new lease as the first element
                pDhcpc->NewLeases = newLease;
            } else 
            {
                while (temp->next != NULL) 
                {
                    temp = temp->next;
                }
                // Add the new lease details to the tail of the list
                temp->next = newLease;
            }

            //Just the add the new lease details in the list. the controlled thread will hanlde it. 
            newLease->next = NULL;
            interfaceFound = TRUE;
            DHCPMGR_LOG_INFO("%s %d: New dhcpv4 lease msg added for %s \n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
            pthread_mutex_unlock(&pDhcpc->mutex); //MUTEX release before break
            break;
        }

        pthread_mutex_unlock(&pDhcpc->mutex); //MUTEX unlock

    }

    if( interfaceFound == FALSE)
    {
        //if we are here, we didn't find the correct interface the received lease. free the memory
        free(newLease);
        DHCPMGR_LOG_ERROR("%s %d: Failed to add dhcpv4 lease msg for ineterface %s \n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface);
    }

    return;
}

/**
 * @brief Updates the status of the DHCP client interface to 'stopped' based on the given process ID.
 *
 * This function iterates through the DHCPv4 and DHCPv6 client lists to find the interface
 * associated with the specified process ID (`pid`). Once found, it updates the status of
 * that interface to 'stopped'.
 *
 * This function is called from a SIGCHLD handler, so it is designed to be simple and quick.
 *
 * @param pid The process ID of the DHCP client to be marked as stopped.
 */
void processKilled(pid_t pid)
{
    PCOSA_DML_DHCPC_FULL            pDhcpc        = NULL;
    PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink  = NULL;
    PSINGLE_LINK_ENTRY              pSListEntry   = NULL;
    ULONG ulIndex;
    ULONG instanceNum;
    ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);
    //iterate all entries and find the ineterface with the ifname
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

        //No mutex lock, since this funtions is called from teh sigchild handler. Keep this function simple and quick
        if(pDhcpc->Info.ClientProcessId == pid)
        {
            DHCPMGR_LOG_INFO("%s %d: DHCpv4 client for %s pid %d is terminated.\n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pid);
            if(pDhcpc->Info.Status == COSA_DML_DHCP_STATUS_Enabled)
            {
                pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
            }
            break;
        }
    }

    //TODO: add v6 handle
    return;
}
