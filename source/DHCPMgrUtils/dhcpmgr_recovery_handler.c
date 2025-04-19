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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include "util.h"
#include "cosa_dhcpv4_dml.h"
#include "cosa_dhcpv4_internal.h"
#include "cosa_dhcpv6_internal.h"
#include "dhcpmgr_controller.h"
#include "dhcpmgr_recovery_handler.h"
#include "dhcpv4_interface.h"
#include "cosa_dhcpv4_apis.h"

#define EXIT_FAIL -1
#define EXIT_SUCCESS 0
#define MAX_PIDS 20
#define TMP_DIR_PATH "/tmp/Dhcp_manager"

extern ANSC_STATUS DhcpMgr_updateDHCPv4DML(PCOSA_DML_DHCPC_FULL pDhcpc);

int pid_count = 0;
int pids[MAX_PIDS];

static int DHCPMgr_loadDhcpLeases();
static void *dhcp_pid_mon( void *args );

int DhcpMgr_Dhcp_Recovery_Start()
{
    pthread_t dhcp_pid_mon_thread;
    int ret_val = DHCPMgr_loadDhcpLeases();

    if (ret_val != EXIT_SUCCESS) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to load DHCP leases\n", __FUNCTION__, __LINE__);
        return EXIT_FAIL;
    }
    else
    {
        if (pid_count == 0)
        {
            DHCPMGR_LOG_ERROR("%s:%d No PIDs to monitor\n", __FUNCTION__, __LINE__);
            return EXIT_FAIL;
        }

        ret_val = pthread_create(&dhcp_pid_mon_thread, NULL, &dhcp_pid_mon, NULL);
        if (0 != ret_val) 
        {
            DHCPMGR_LOG_ERROR("%s %d - Failed to start dhcp_pid_mon Thread Error:%d\n", __FUNCTION__, __LINE__, ret_val);
            return EXIT_FAIL;
        } 
        else 
        {
            DHCPMGR_LOG_INFO("%s %d - dhcp_pid_mon Thread Started Successfully\n", __FUNCTION__, __LINE__);
            return EXIT_SUCCESS;
        }
    }

    return EXIT_SUCCESS;
}

/**
 * @brief Monitors the udhcpc pid files.
 *
 * This function reads the PID from the udhcpc pid files and logs the PID for each interface.
 */

static void *dhcp_pid_mon(void *args)
{
    (void) args;
    pthread_detach(pthread_self());

    int active_pids = pid_count;

    for (int i = 0; i < pid_count; i++) 
    {
        // Attach each process
        if (ptrace(PTRACE_SEIZE, pids[i], NULL, NULL) == -1) 
        {
            DHCPMGR_LOG_ERROR("%s:%d PTRACE_SEIZE failed for process %d\n", __FUNCTION__, __LINE__, pids[i]);
            continue;
        }
        DHCPMGR_LOG_INFO("%s:%d Monitoring process %d via ptrace...\n", __FUNCTION__, __LINE__, pids[i]);
    }

    while (active_pids > 0) 
    {
        int status;
        pid_t pid = waitpid(-1, &status, __WALL); // Wait for any traced process

        if (pid == -1) 
        {
            DHCPMGR_LOG_ERROR("%s:%d waitpid failed\n", __FUNCTION__, __LINE__);
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) 
        {
            // Check if the exited pid is in the list of pids
            for (int i = 0; i < pid_count; i++)
            {
                if (pids[i] == pid) {
                    DHCPMGR_LOG_INFO("%s:%d Process %d exited!\n", __FUNCTION__, __LINE__, pid);
                    processKilled(pid);
                    active_pids--;
                    continue;
                }
            }
        } 
        else if (WIFSTOPPED(status)) 
        {
            int sig = WSTOPSIG(status);
            DHCPMGR_LOG_INFO("%s:%d Process %d got a signal %d to send\n", __FUNCTION__, __LINE__, pid, sig);
            
            if (ptrace(PTRACE_CONT, pid, NULL, sig) == -1) 
            {
                DHCPMGR_LOG_ERROR("%s:%d PTRACE_CONT failed for process %d\n", __FUNCTION__, __LINE__, pid);
            } 
            else 
            {
                DHCPMGR_LOG_INFO("%s:%d Sent signal %d to process %d\n", __FUNCTION__, __LINE__, sig, pid);
            }
            continue;
        }
    }

    DHCPMGR_LOG_INFO("%s:%d Thread Exited \n", __FUNCTION__, __LINE__);
    pthread_exit(NULL);
}


static int Create_Dir_ifnEx(const char *path)
{
    if (access(path, F_OK) == -1) 
    {
        if (mkdir(path, 0755) == -1) 
        {
            return EXIT_FAIL;
        }
    }
    return EXIT_SUCCESS;
}

int DHCPMgr_storeDhcpv4Lease(PCOSA_DML_DHCPC_FULL data)
{
    char filePath[256] = {0};

    if (!data) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Invalid arguments\n", __FUNCTION__, __LINE__);
        return EXIT_FAIL;
    }

    // Create the directory if it doesn't exist
    if (Create_Dir_ifnEx(TMP_DIR_PATH) != EXIT_SUCCESS) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to create directory\n", __FUNCTION__, __LINE__);
        return EXIT_FAIL;
    }

    snprintf(filePath, sizeof(filePath), "/tmp/Dhcp_manager/dhcpLease_%lu_v4", data->Cfg.InstanceNumber);
    FILE *file = fopen(filePath, "wb");

    if (!file) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to open file %s for writing\n", __FUNCTION__, __LINE__, filePath);
        return EXIT_FAIL;
    }

    // Storing the current lease as a separate segment to fetch it easily
    if (fwrite(data, sizeof(COSA_DML_DHCPC_FULL), 1, file) != 1) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to write data to file %s\n", __FUNCTION__, __LINE__, filePath);
        fclose(file);
        return EXIT_FAIL;
    }

    DHCPMGR_LOG_INFO("%s:%d Writing DHCP.Client.%lu to file %s\n", __FUNCTION__, __LINE__, data->Cfg.InstanceNumber, filePath);

    if (data->currentLease != NULL) 
    {
        fwrite(data->currentLease, sizeof(DHCPv4_PLUGIN_MSG), 1, file);
    }

    fclose(file);
    return EXIT_SUCCESS;
}


/* * @brief Stores the DHCPv6 lease information in a file.
 *
 * This function stores the DHCPv6 lease information in a file for later retrieval.
 *
 * @param ifname The name of the interface.
 * @param data A pointer to the new DHCP lease information.
 * @return int Returns 0 on success, or a negative error code on failure.
 */

int DHCPMgr_storeDhcpv6Lease(PCOSA_DML_DHCPCV6_FULL data)
{
    char filePath[256] = {0};

    if (!data) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Invalid arguments\n", __FUNCTION__, __LINE__);
        return EXIT_FAIL;
    }

    // Create the directory if it doesn't exist
    if (Create_Dir_ifnEx(TMP_DIR_PATH) != EXIT_SUCCESS) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to create directory\n", __FUNCTION__, __LINE__);
        return EXIT_FAIL;
    }

    snprintf(filePath, sizeof(filePath), "/tmp/Dhcp_manager/dhcpLease_%lu_v6", data->Cfg.InstanceNumber);
    FILE *file = fopen(filePath, "wb");

    if (!file) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to open file %s for writing\n", __FUNCTION__, __LINE__, filePath);
        return EXIT_FAIL;
    }

    DHCPMGR_LOG_INFO("%s:%d Writing DHCP.Client.%lu to file %s\n",  __FUNCTION__, __LINE__, data->Cfg.InstanceNumber, filePath);
    
    if (fwrite(data, sizeof(COSA_DML_DHCPCV6_FULL), 1, file) != 1) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to write data to file %s\n", __FUNCTION__, __LINE__, filePath);
        fclose(file);
        return EXIT_FAIL;
    }

    //<<DEBUG>> //cleanup at last
    if (data->currentLease != NULL) 
    {
        DHCPMGR_LOG_INFO("%s:%d <<DEBUG>> currentLease->ia_na.address=%s\n", __FUNCTION__, __LINE__, data->currentLease->ia_na.address);
    }
    //<<DEBUG>>

        // Storing the current lease as a separate segment to fetch it easily
    if (data->currentLease != NULL) 
    {
        if(fwrite(data->currentLease, sizeof(DHCPv6_PLUGIN_MSG), 1, file) != 1) 
        {
            DHCPMGR_LOG_ERROR("%s:%d Failed to write current lease to file %s\n", __FUNCTION__, __LINE__, filePath);
            fclose(file);
            return EXIT_FAIL;
        }
    }

    fclose(file);
    return EXIT_SUCCESS;
}

static int load_v6dhcp_leases() 
{
    DHCPMGR_LOG_INFO("%s:%d ------ IN\n", __FUNCTION__, __LINE__);
    ULONG ulIndex;
    ULONG instanceNum;
    PSINGLE_LINK_ENTRY pSListEntry = NULL;
    PCOSA_CONTEXT_DHCPCV6_LINK_OBJECT pDhcp6cxtLink  = NULL;
    PCOSA_DML_DHCPCV6_FULL pDhcp6c = NULL;
    char FilePattern[256] = {0};
    
    ULONG clientCount = CosaDmlDhcpv6cGetNumberOfEntries(NULL);

    if (clientCount == 0) 
    {
        DHCPMGR_LOG_ERROR("%s:%d No DHCPv6 client entries found\n", __FUNCTION__, __LINE__);
        return EXIT_FAIL;
    }

    for (ulIndex = 0; ulIndex < clientCount; ulIndex++) 
    {
        COSA_DML_DHCPCV6_FULL storedLease;

        pSListEntry = (PSINGLE_LINK_ENTRY)Client3_GetEntry(NULL, ulIndex, &instanceNum);
        if (pSListEntry) 
        {
            pDhcp6cxtLink          = ACCESS_COSA_CONTEXT_DHCPCV6_LINK_OBJECT(pSListEntry);
            pDhcp6c            = (PCOSA_DML_DHCPC_FULL)pDhcp6cxtLink->hContext;
        }
        DHCPMGR_LOG_INFO("%s:%d Loading data for DHCPv6.Client.%lu\n", __FUNCTION__, __LINE__, instanceNum);

        if (!pDhcp6c) 
        {
            DHCPMGR_LOG_ERROR("%s : pDhcp6c is NULL\n", __FUNCTION__);
            continue;
        }

        snprintf(FilePattern, sizeof(FilePattern), "/tmp/Dhcp_manager/dhcpLease_%lu_v6", instanceNum);

        if (access(FilePattern, F_OK) == 0) 
        {
            FILE *file = fopen(FilePattern, "rb");
            if (!file) 
            {
                DHCPMGR_LOG_ERROR("%s:%d Failed to open file %s , No file was store for DHCPv6.%lu.Client \n", __FUNCTION__, __LINE__, FilePattern, instanceNum);
                continue;
            }

            memset(&storedLease, 0, sizeof(COSA_DML_DHCPCV6_FULL));

            if (fread(&storedLease, sizeof(COSA_DML_DHCPCV6_FULL), 1, file) != 1) 
            {
                DHCPMGR_LOG_ERROR("%s:%d Failed to read data from file %s\n", __FUNCTION__, __LINE__, FilePattern);
                fclose(file);
                continue;
            }

            pthread_mutex_lock(&pDhcp6c->mutex);
            pDhcp6c->currentLease = (DHCPv6_PLUGIN_MSG *)malloc(sizeof(DHCPv6_PLUGIN_MSG));
            memset(pDhcp6c->currentLease, 0, sizeof(DHCPv6_PLUGIN_MSG));

            if (!pDhcp6c->currentLease) 
            {
                DHCPMGR_LOG_ERROR("%s:%d Failed to allocate memory for currentLease\n",__FUNCTION__, __LINE__);
                fclose(file);
                pthread_mutex_unlock(&pDhcp6c->mutex);
                continue;
            }

            if (fread(pDhcp6c->currentLease, sizeof(DHCPv6_PLUGIN_MSG), 1, file) != 1) 
            {
                DHCPMGR_LOG_ERROR("%s:%d Failed to read current lease from file %s\n", __FUNCTION__, __LINE__, FilePattern);
                free(pDhcp6c->currentLease);
                pDhcp6c->currentLease = NULL;
                fclose(file);
                pthread_mutex_unlock(&pDhcp6c->mutex);
                continue;
            }
            pDhcp6c->currentLease->next = NULL;
            char procPath[64] = {0};

            snprintf(procPath, sizeof(procPath), "/proc/%d", storedLease.Info.ClientProcessId);
            /*If the ClientPid is running before and after DHCPMgr restart, populate data for the Client*/
            
            if (access(procPath, F_OK) == -1) 
            {
               /*If stored pid is not running ,Need restart the dhcp client*/
                DHCPMGR_LOG_INFO("%s:%d PID %d is not running, calling processKilled\n", __FUNCTION__, __LINE__, storedLease.Info.ClientProcessId);
                pDhcp6c->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
            } 
            else
            {
                DHCPMGR_LOG_INFO("%s:%d PID %d is still running\n", __FUNCTION__, __LINE__, storedLease.Info.ClientProcessId);
                pDhcp6c->Info.Status = COSA_DML_DHCP_STATUS_Enabled;
                pids[pid_count++] = storedLease.Info.ClientProcessId;
                pDhcp6c->Info.ClientProcessId = storedLease.Info.ClientProcessId;
            }
            // Copy the stored Cfg data to the pDHCPC
            memcpy(&pDhcp6c->Cfg, &storedLease.Cfg, sizeof(COSA_DML_DHCPCV6_CFG));
            pthread_mutex_unlock(&pDhcp6c->mutex);
            fclose(file);

            //<<DEBUG>> Need to cleanup at last
            DHCPMGR_LOG_INFO("%s:%d pDhcp6c->Info.ClientProcessId=%d Status=%d bEnabled=%d Interface=%s \n", __FUNCTION__, __LINE__, pDhcp6c->Info.ClientProcessId, pDhcp6c->Info.Status, pDhcp6c->Cfg.bEnabled, pDhcp6c->Cfg.Interface);
            DHCPMGR_LOG_INFO("%s:%d pDhcp6c->currentLease->ipAddr=%s \n",__FUNCTION__, __LINE__, pDhcp6c->currentLease->ia_na.address);
            //<<DEBUG>>
        }
        else
        {
            DHCPMGR_LOG_ERROR("%s:%d File %s does not exist, No file was stored for DHCPv6.Client.%lu\n", __FUNCTION__, __LINE__, FilePattern, instanceNum);
            continue;
        }
    }
    DHCPMGR_LOG_INFO("%s:%d ------OUT\n", __FUNCTION__, __LINE__);
    return EXIT_SUCCESS;
}


static int load_v4dhcp_leases() 
{
        DHCPMGR_LOG_INFO("%s:%d ------ IN\n", __FUNCTION__, __LINE__);
        ULONG ulIndex;
        ULONG instanceNum;
        PSINGLE_LINK_ENTRY pSListEntry = NULL;
        PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink = NULL;
        PCOSA_DML_DHCPC_FULL pDhcpc = NULL;
        char FilePattern[256] = {0};
        
        ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);

        if (clientCount == 0) 
        {
            DHCPMGR_LOG_ERROR("%s:%d No DHCP client entries found\n", __FUNCTION__, __LINE__);
            return EXIT_FAIL;
        }

        for (ulIndex = 0; ulIndex < clientCount; ulIndex++) 
        {
            COSA_DML_DHCPC_FULL storedLease;

            pSListEntry = (PSINGLE_LINK_ENTRY)Client_GetEntry(NULL, ulIndex, &instanceNum);
            if (pSListEntry) 
            {
                pDhcpCxtLink = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
                pDhcpc = (PCOSA_DML_DHCPC_FULL)pDhcpCxtLink->hContext;
            }
            DHCPMGR_LOG_INFO("%s:%d Loading data for DHCPv4.Client.%lu\n", __FUNCTION__, __LINE__, instanceNum);

            if (!pDhcpc) 
            {
                DHCPMGR_LOG_ERROR("%s : pDhcpc is NULL\n", __FUNCTION__);
                continue;
            }

            snprintf(FilePattern, sizeof(FilePattern), "/tmp/Dhcp_manager/dhcpLease_%lu_v4", instanceNum);

            if (access(FilePattern, F_OK) == 0) 
            {
                FILE *file = fopen(FilePattern, "rb");
                if (!file) 
                {
                    DHCPMGR_LOG_ERROR("%s:%d Failed to open file %s , No file was store for DHCPv4.%lu.Client \n", __FUNCTION__, __LINE__, FilePattern, instanceNum);
                    continue;
                }

                memset(&storedLease, 0, sizeof(COSA_DML_DHCPC_FULL));

                if (fread(&storedLease, sizeof(COSA_DML_DHCPC_FULL), 1, file) != 1) 
                {
                    DHCPMGR_LOG_ERROR("%s:%d Failed to read data from file %s\n", __FUNCTION__, __LINE__, FilePattern);
                    fclose(file);
                    continue;
                }

                pthread_mutex_lock(&pDhcpc->mutex);
                pDhcpc->currentLease = (DHCPv4_PLUGIN_MSG *)malloc(sizeof(DHCPv4_PLUGIN_MSG));
                memset(pDhcpc->currentLease, 0, sizeof(DHCPv4_PLUGIN_MSG));
                if (!pDhcpc->currentLease) 
                {
                    DHCPMGR_LOG_ERROR("%s:%d Failed to allocate memory for currentLease\n",__FUNCTION__, __LINE__);
                    fclose(file);
                    pthread_mutex_unlock(&pDhcpc->mutex);
                    continue;
                }

                if (fread(pDhcpc->currentLease, sizeof(DHCPv4_PLUGIN_MSG), 1, file) != 1) 
                {
                    DHCPMGR_LOG_ERROR("%s:%d Failed to read current lease from file %s\n", 
                                      __FUNCTION__, __LINE__, FilePattern);
                    free(pDhcpc->currentLease);
                    pDhcpc->currentLease = NULL;
                    fclose(file);
                    pthread_mutex_unlock(&pDhcpc->mutex);
                    continue;
                }
                pDhcpc->currentLease->next = NULL;

                char procPath[64] = {0};
                snprintf(procPath, sizeof(procPath), "/proc/%d", storedLease.Info.ClientProcessId);

                /*If the ClientPid is running before and after DHCPMgr restart, we have to populate data for the Client*/
                /*If not we need to tell the Controller that the stored pid is not running we have to restart the dhcp client*/
                if (access(procPath, F_OK) == -1) 
                {
                    DHCPMGR_LOG_INFO("%s:%d PID %d is not running, calling processKilled\n", __FUNCTION__, __LINE__, storedLease.Info.ClientProcessId);
                    pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Disabled;
                } 
                else 
                {
                    DHCPMGR_LOG_INFO("%s:%d PID %d is still running\n", __FUNCTION__, __LINE__, storedLease.Info.ClientProcessId);
                    pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Enabled;
                    pids[pid_count++] = storedLease.Info.ClientProcessId;
                    pDhcpc->Info.ClientProcessId = storedLease.Info.ClientProcessId;
                }

                // Copy the stored Cfg data to the pDHCPC
                memcpy(&pDhcpc->Cfg, &storedLease.Cfg, sizeof(COSA_DML_DHCPC_CFG));

                // copy the Info structure to pdhcpc ,ensure DhcpMgr_updateDHCPv4DML is not having any mutex lock
                DhcpMgr_updateDHCPv4DML(pDhcpc);

                pthread_mutex_unlock(&pDhcpc->mutex);

                //<<DEBUG>> Need to cleanup at last
                DHCPMGR_LOG_INFO("%s:%d <<DEBUG>> pDhcpc->Info.ClientProcessId=%d Status=%d bEnabled=%d Interface=%s \n", __FUNCTION__, __LINE__, pDhcpc->Info.ClientProcessId, pDhcpc->Info.Status, pDhcpc->Cfg.bEnabled, pDhcpc->Cfg.Interface);
                DHCPMGR_LOG_INFO("%s:%d <<DEBUG>> pDhcpc->currentLease->ipAddr=%s \n",__FUNCTION__, __LINE__, pDhcpc->currentLease->address);
                DHCPMGR_LOG_INFO("%s:%d <<DEBUG>> pDhcpc->currentLease->netmask=%s \n",__FUNCTION__, __LINE__, pDhcpc->currentLease->netmask);
                //<<DEBUG>>

                fclose(file);
            }
            else 
            {
                DHCPMGR_LOG_ERROR("%s:%d File %s does not exist, No file was stored for DHCPv4.Client.%lu\n", __FUNCTION__, __LINE__, FilePattern, instanceNum);
                continue;
            }
        }
        DHCPMGR_LOG_INFO("%s:%d ------OUT\n", __FUNCTION__, __LINE__);
        return EXIT_SUCCESS;
}

/**
 * @brief Loads DHCP leases for both v4 and v6.
 *
 * This function loads the DHCP leases for both v4 and v6 by calling the respective load functions.
 *
 * @return int Returns 0 on success, or a negative error code on failure.
 */

static int DHCPMgr_loadDhcpLeases() 
{
    int ret=0;
    int retv4=EXIT_SUCCESS;
    int retv6=EXIT_SUCCESS;
    ret=load_v4dhcp_leases();
    if (ret != EXIT_SUCCESS) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to load DHCP leases for v4\n", __FUNCTION__, __LINE__);
        retv4=EXIT_FAIL;
    }
    else
    {
        DHCPMGR_LOG_INFO("%s:%d Loaded DHCP leases for v4 successfully\n", __FUNCTION__, __LINE__);
    }

    ret=load_v6dhcp_leases();
    if (ret != EXIT_SUCCESS) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to load DHCP leases for v6\n", __FUNCTION__, __LINE__);
        retv6=EXIT_FAIL;
    }
    else
    {
        DHCPMGR_LOG_INFO("%s:%d Loaded DHCP leases for v6 successfully\n", __FUNCTION__, __LINE__);
    }

    if (retv4 == EXIT_FAIL && retv6 == EXIT_FAIL) 
    {
        DHCPMGR_LOG_ERROR("%s:%d Failed to load DHCP leases for both v4 and v6\n", __FUNCTION__, __LINE__);
        return EXIT_FAIL;
    }
   
    return EXIT_SUCCESS;
}

/**
 * @brief Removes the DHCP lease file for a given instanceNumber.
 *
 * This function removes the DHCP lease file corresponding to the given instanceNumber.
 *
 * @param instanceNumber The instance number of the DHCP client.
 * @return void
 */
void remove_dhcp_lease_file(int instanceNumber, int dhcpVersion)
{
    char filePath[256] = {0};

    if (dhcpVersion == DHCP_v4) 
    {
        snprintf(filePath, sizeof(filePath), "/tmp/Dhcp_manager/dhcpLease_%d_v4", instanceNumber);
        if (remove(filePath) == 0) 
        {
            DHCPMGR_LOG_INFO("%s:%d Successfully removed DHCPv4 lease file %s\n", __FUNCTION__, __LINE__, filePath);
        } 
        else 
        {
            DHCPMGR_LOG_ERROR("%s:%d Failed to remove DHCPv4 lease file %s\n", __FUNCTION__, __LINE__, filePath);
        }
    }
    else if (dhcpVersion == DHCP_v6) 
    {
        snprintf(filePath, sizeof(filePath), "/tmp/Dhcp_manager/dhcpLease_%d_v6", instanceNumber);
        if (remove(filePath) == 0) 
        {
            DHCPMGR_LOG_INFO("%s:%d Successfully removed DHCPv6 lease file %s\n", __FUNCTION__, __LINE__, filePath);
        } 
        else 
        {
            DHCPMGR_LOG_ERROR("%s:%d Failed to remove DHCPv6 lease file %s\n", __FUNCTION__, __LINE__, filePath);
        }
    }
}
