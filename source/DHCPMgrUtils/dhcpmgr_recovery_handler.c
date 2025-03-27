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
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/poll.h>
#include <glob.h>
#include "util.h"
#include "cosa_dhcpv4_dml.h"
#include "cosa_dhcpv4_internal.h"
#include "dhcpmgr_controller.h"
#include "dhcpmgr_recovery_handler.h"
#include "dhcpv4_interface.h"
#include "cosa_dhcpv4_apis.h"

#define EXIT_FAIL -1
#define EXIT_SUCCESS 0
#define PID_PATTERN "/tmp/udhcpc.*.pid"
#define CMDLINE_PATH "/proc/%d/cmdline"
#define MAX_PIDS 5
#define MAX_PROC_LEN 24
#define MAX_CMDLINE_LEN 512


typedef enum {
    DHCP_VERSION_4,
    DHCP_VERSION_6,
} DHCP_SOURCE;

//void processKilled(pid_t pid);
static int read_pid_from_file(const char *filepath, int *pid_count, int *pids);
//static int get_interface_from_pid(int pid, char *Interface);
static void DHCPMgr_loadDhcpLeases(int dhcpVersion);

static int read_pid_from_file(const char *filepath, int *pid_count, int *pids) 
{
    FILE *file = fopen(filepath, "r");
    if (!file) {
        return EXIT_FAIL;
    }
    int pid;
    if (fscanf(file, "%d", &pid) == 1) {
        if (*pid_count < MAX_PIDS) {
            pids[(*pid_count)++] = pid;
        }
    }
    fclose(file);
    return EXIT_SUCCESS;
}

/**
 * @brief Gets the interface name from the command line of a process.
 *
 * This function reads the command line of a process to find the interface name.
 *
 * @param[in] pid The process ID.
 */
/*static int get_interface_from_pid(int pid, char *Interface) 
{
    DHCPMGR_LOG_INFO("%s %d  Interface=%s pid=%d \n", __FUNCTION__, __LINE__,Interface,pid);
    char path[MAX_PROC_LEN]={0};
    char cmdline[MAX_CMDLINE_LEN]={0};
    size_t len=0;
    snprintf(path, sizeof(path), CMDLINE_PATH, pid);
    DHCPMGR_LOG_INFO("%s %d  path=%s CMDLINE_PATH=%s\n", __FUNCTION__, __LINE__,path,CMDLINE_PATH);
    FILE *file = fopen(path, "r");
    if (!file) {
        DHCPMGR_LOG_ERROR("%s %d Failed to open cmdline file for PID %d\n", __FUNCTION__, __LINE__, pid);
        return EXIT_FAIL;
    }

    len = fread(cmdline, 1, MAX_CMDLINE_LEN - 1, file);
    fclose(file);
    if (len == 0) {
        DHCPMGR_LOG_ERROR("%s %d Empty cmdline for PID %d\n", __FUNCTION__, __LINE__, pid);
        return EXIT_FAIL;
    }
    DHCPMGR_LOG_INFO("%s %d cmdline=%s \n",__FUNCTION__, __LINE__,cmdline);
    char *match = strstr(cmdline, Interface);
    DHCPMGR_LOG_INFO("%s %d  match=%s \n", __FUNCTION__, __LINE__,match);
    if (match) {
      return EXIT_SUCCESS;
    } else {
      return EXIT_FAIL;
    }
} */

/**
 * @brief Monitors the udhcpc pid files.
 *
 * This function reads the PID from the udhcpc pid files and logs the PID for each interface.
 */


void udhcpc_pid_mon() 
{
    //<<DEBUG>> Need to remove this code while commiting the code
    pthread_mutex_lock(&mutex);
    thread_info[thread_count].tid = pthread_self();
    strncpy(thread_info[thread_count].name, "udhcpc_pid_mon", sizeof(thread_info[thread_count].name));
    thread_count++;
    pthread_mutex_unlock(&mutex);
    /*DEBUG*/

    pthread_detach(pthread_self());
 
    DHCPMGR_LOG_INFO("%s:%d Inside-----",__FUNCTION__,__LINE__);
    PCOSA_DML_DHCPC_FULL            pDhcpc        = NULL;
    PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink  = NULL;
    PSINGLE_LINK_ENTRY              pSListEntry   = NULL;
    ULONG                           ulIndex;
    ULONG                           instanceNum;
    ULONG                           clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);
    int pidfds[MAX_PIDS];

    int pid_count = 0;
    int pids[MAX_PIDS];
    glob_t results;
    struct pollfd poll_fds[MAX_PIDS]; // Poll file descriptors

    // Set up a signal handler for segmentation faults or crashes 
    //<<DEBUG>> Need to remove this code while commiting the code
    void signal_handler(int signum) {
        pthread_t self_tid = pthread_self();
        char thread_name[16] = "Unknown";
    
        pthread_mutex_lock(&mutex);
        for (int i = 0; i < thread_count; i++) {
            if (pthread_equal(thread_info[i].tid, self_tid)) {
                strncpy(thread_name, thread_info[i].name, sizeof(thread_name));
                break;
            }
        }
        pthread_mutex_unlock(&mutex);
    
        DHCPMGR_LOG_ERROR("%s : %d Thread '%s' crashed with signal %d\n",__FUNCTION__,__LINE__, thread_name, signum);
        pthread_exit(NULL); // Exit the thread gracefully
    }

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        DHCPMGR_LOG_ERROR("%s:%d Failed to set signal handler for SIGSEGV\n", __FUNCTION__, __LINE__);
    }
    if (sigaction(SIGABRT, &sa, NULL) == -1) {
        DHCPMGR_LOG_ERROR("%s:%d Failed to set signal handler for SIGABRT\n", __FUNCTION__, __LINE__);
    }

    /*signal handler close*/
    
    // Load the DHCP leases from already stored /tmp/Dhcp_manager data
    DHCPMgr_loadDhcpLeases(DHCP_VERSION_4);

     /* Need to write logic to read the pids from stored DS */
    // Read the PID from the udhcpc pid files 
    DHCPMGR_LOG_INFO("%s:%d DEBUG------PID_PATTERN=%s\n",__FUNCTION__,__LINE__,PID_PATTERN);
    if (glob(PID_PATTERN, 0, NULL, &results) == 0) {
        for (size_t i = 0; i < results.gl_pathc ; i++) {
            DHCPMGR_LOG_INFO("%s:%d DEBUG------filepath=%s\n",__FUNCTION__,__LINE__,results.gl_pathv[i]);
            if (read_pid_from_file(results.gl_pathv[i], &pid_count, pids) != EXIT_SUCCESS) {
                DHCPMGR_LOG_ERROR("%s %d Error reading pid from file %s\n", __FUNCTION__, __LINE__, results.gl_pathv[i]);
                continue;
            }
            DHCPMGR_LOG_INFO("%s %d PID found for interface %s : %d\n", __FUNCTION__, __LINE__, results.gl_pathv[i], pids[pid_count - 1]);
        }
    }

    //Fill the pid and status in the global structure if the udhcpc is already running for the interface
/* No need for following code as we are storing the lease data in the tmp file and loading it in the DHCP Manager , this code is for only debug and need to remove while commiting the code */
    for (ulIndex = 0; ulIndex < clientCount; ulIndex++) 
    {
        DHCPMGR_LOG_INFO("%s:%d DEBUG------INSIDE for  pid_count=%d\n",__FUNCTION__,__LINE__,pid_count);
        pSListEntry = (PSINGLE_LINK_ENTRY)Client_GetEntry(NULL, ulIndex, &instanceNum);
        if (pSListEntry) 
        {
            pDhcpCxtLink = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
            pDhcpc = (PCOSA_DML_DHCPC_FULL)pDhcpCxtLink->hContext;
        }

        if (!pDhcpc)
        {
            DHCPMGR_LOG_ERROR("%s : pDhcpc is NULL\n", __FUNCTION__);
            continue;
        }

        DHCPMGR_LOG_INFO("%s %d: Info.ClientProcessId=%d Info.Status=%d Cfg.bEnabled=%d Cfg.Interface=%s \n", __FUNCTION__, __LINE__,pDhcpc->Info.ClientProcessId,pDhcpc->Info.Status,pDhcpc->Cfg.bEnabled, pDhcpc->Cfg.Interface);
        /* No need for following code as we are storing the lease data in the tmp file and loading it in the DHCP Manager */
 /*       for (int i = 0; i < pid_count; i++) 
        {
            if(get_interface_from_pid(pids[i], pDhcpc->Cfg.Interface) == EXIT_SUCCESS) 
            {
                DHCPMGR_LOG_INFO("%s %d: Found interface %s for pid %d\n", __FUNCTION__, __LINE__, pDhcpc->Cfg.Interface, pids[i]);
                pthread_mutex_lock(&pDhcpc->mutex);
                pDhcpc->Info.ClientProcessId = pids[i];
                pDhcpc->Info.Status = COSA_DML_DHCP_STATUS_Enabled;
                pDhcpc->Cfg.bEnabled = TRUE;
                pthread_mutex_unlock(&pDhcpc->mutex);
            }
        } */
    }
 //Monitoring the pid for the udhcpc process
    for (int i = 0; i < pid_count; i++) {
        DHCPMGR_LOG_INFO("%s:%d DEBUG------INSIDE Monitoring the pid for the udhcpc process pid_count=%d\n",__FUNCTION__,__LINE__,pid_count);
        pidfds[i] = syscall(SYS_pidfd_open, pids[i], 0);
        if (pidfds[i] == -1) {
            DHCPMGR_LOG_ERROR("%s : %d pidfd_open syscall failed\n", __FUNCTION__, __LINE__);
            continue;
        }

        poll_fds[i].fd = pidfds[i];
        poll_fds[i].events = POLLIN; // Watch for process exit event

        DHCPMGR_LOG_INFO("%s:%d Monitoring process %d...\n",__FUNCTION__,__LINE__,pids[i]);
    }

    // Wait for any process to exit
    DHCPMGR_LOG_INFO("%s:%d DEBUG------pid_count=%d\n",__FUNCTION__,__LINE__,pid_count);
    int rem_pid=pid_count;
    while (rem_pid > 0) {
        DHCPMGR_LOG_INFO("%s:%d DEBUG------INSIDE while poll\n",__FUNCTION__,__LINE__);
        int ret = poll(poll_fds, pid_count, -1); // Block until an event occurs
        if (ret == -1) {
            DHCPMGR_LOG_ERROR("%s : %d Poll failed \n", __FUNCTION__, __LINE__);
            return;
        }

        // Check which process exited
        for (int i = 0; i < pid_count; i++) {
            DHCPMGR_LOG_INFO("%s:%d DEBUG------INSIDE after  while poll to check process exited\n",__FUNCTION__,__LINE__);
            if ( poll_fds[i].fd != -1 && poll_fds[i].revents & POLLIN) {
                DHCPMGR_LOG_INFO("%s:%d Process %s : %d exited!\n",__FUNCTION__, __LINE__,results.gl_pathv[i],pids[i]);
                processKilled(pids[i]);      // notify the processKilled that udhcpc pid exited
                poll_fds[i].fd = -1;             // Mark this as handled
                rem_pid--;                         //Reduce count of active processes
                if (close(pidfds[i]) == -1) {
                    DHCPMGR_LOG_ERROR("%s : %d Error closing pidfd\n", __FUNCTION__, __LINE__);
                }
            }
        }
    }
    globfree(&results);
    DHCPMGR_LOG_INFO("%s:%d DEBUG------END\n",__FUNCTION__,__LINE__);
    pthread_exit(NULL);
}


int DHCPMgr_storeDhcpLease(char* ifname, PCOSA_DML_DHCPC_FULL newLease, int dhcpVersion,ULONG instanceNum)
{
    DHCPMGR_LOG_INFO("%s : %d <<DEBUG>> Entered\n",__FUNCTION__,__LINE__);
    if (!ifname || !newLease) {
        DHCPMGR_LOG_ERROR("%s:%d Invalid arguments\n", __FUNCTION__, __LINE__);
        return EXIT_FAIL;
    }

    // Determine the DHCP version suffix
    const char *versionSuffix = (dhcpVersion == DHCP_VERSION_4) ? "v4" : "v6";

    // Construct the file path
    char filePath[256] = {0};
    snprintf(filePath, sizeof(filePath), "/tmp/Dhcp_manager/%s_%lu.LeaseInfo.%s", ifname, instanceNum,versionSuffix);

    DHCPMGR_LOG_INFO("%s:%d <<DEBUG>> filePath=%s\n", __FUNCTION__, __LINE__, filePath);
    // Create the directory if it doesn't exist
    if (access("/tmp/Dhcp_manager", F_OK) == -1) {
        if (mkdir("/tmp/Dhcp_manager", 0755) == -1) {
            DHCPMGR_LOG_ERROR("%s:%d Failed to create directory /tmp/Dhcp_manager\n", __FUNCTION__, __LINE__);
            return EXIT_FAIL;
        }
    }

    // Open the file for writing
    FILE *file = fopen(filePath, "wb");
    if (!file) {
        DHCPMGR_LOG_ERROR("%s:%d Failed to open file %s for writing\n", __FUNCTION__, __LINE__, filePath);
        return EXIT_FAIL;
    }

    // Write the newLease structure to the file
    if (fwrite(newLease, sizeof(COSA_DML_DHCPC_FULL), 1, file) != 1) {
        DHCPMGR_LOG_ERROR("%s:%d Failed to write lease data to file %s\n", __FUNCTION__, __LINE__, filePath);
        fclose(file);
        return EXIT_FAIL;
    }

    fclose(file);
    DHCPMGR_LOG_INFO("%s:%d Lease data successfully stored in %s\n", __FUNCTION__, __LINE__, filePath);
    return EXIT_SUCCESS;
}


static void DHCPMgr_loadDhcpLeases(int dhcpVersion) 
{
    pid_t clientpid = 0;
    ULONG instanceNum,instanceNum_from_file;
    PSINGLE_LINK_ENTRY pSListEntry = NULL;
    PCOSA_CONTEXT_DHCPC_LINK_OBJECT pDhcpCxtLink = NULL;
    PCOSA_DML_DHCPC_FULL pDhcpc = NULL;
    
    DHCPMGR_LOG_INFO("%s:%d DEBUG Loading stored lease data for DHCP version %s\n", __FUNCTION__, __LINE__, (dhcpVersion == DHCP_VERSION_4) ? "v4" : "v6");
    // Determine the DHCP version suffix
    const char *versionSuffix = (dhcpVersion == DHCP_VERSION_4) ? "v4" : "v6";
    glob_t results;

    // Construct the file search pattern
    if (strcmp(versionSuffix, "v4") == 0) {
        char searchPattern[256] = {0};
        snprintf(searchPattern, sizeof(searchPattern), "/tmp/Dhcp_manager/*.LeaseInfo.%s", versionSuffix);

        if (glob(searchPattern, 0, NULL, &results) != 0) {
            DHCPMGR_LOG_ERROR("%s:%d No lease files found for DHCP version %s\n", __FUNCTION__, __LINE__, versionSuffix);
            return;
        }

        DHCPMGR_LOG_INFO("%s:%d DEBUG Found %d lease files for DHCP version %s\n", __FUNCTION__, __LINE__, results.gl_pathc, versionSuffix);

        for (size_t i = 0; i < results.gl_pathc; i++) {
            const char *filePath = results.gl_pathv[i];
            DHCPMGR_LOG_INFO("%s:%d DEBUG Processing lease file: %s\n", __FUNCTION__, __LINE__, filePath);

            // Extract the instance number from the file path using sscanf
            if (sscanf(filePath, "/tmp/Dhcp_manager/%*[^_]_%lu.LeaseInfo.%*s", &instanceNum_from_file) != 1) {
                DHCPMGR_LOG_ERROR("%s:%d Failed to extract instance number from file path %s\n", __FUNCTION__, __LINE__, filePath);
                continue;
            }

            DHCPMGR_LOG_INFO("%s:%d DEBUG instanceNum_from_file=%lu\n", __FUNCTION__, __LINE__, instanceNum_from_file);

            // Open the file for reading
            FILE *file = fopen(filePath, "rb");
            if (!file) {
                DHCPMGR_LOG_ERROR("%s:%d Failed to open file %s for reading\n", __FUNCTION__, __LINE__, filePath);
                continue;
            }

            // Read the stored lease data
            PCOSA_DML_DHCPC_FULL storedLease = (PCOSA_DML_DHCPC_FULL)malloc(sizeof(COSA_DML_DHCPC_FULL));
            if (!storedLease) {
                DHCPMGR_LOG_ERROR("%s:%d Failed to allocate memory for storedLease\n", __FUNCTION__, __LINE__);
                fclose(file);
                continue;
            }

            memset(storedLease, 0, sizeof(COSA_DML_DHCPC_FULL));

            if (fread(storedLease, sizeof(COSA_DML_DHCPC_FULL), 1, file) != 1) {
                DHCPMGR_LOG_ERROR("%s:%d Failed to read lease data from file %s\n", __FUNCTION__, __LINE__, filePath);
                free(storedLease);
                fclose(file);
                continue;
            }
            fclose(file);

            // Iterate through the DHCP Manager entries to find a matching interface
            ULONG clientCount = CosaDmlDhcpcGetNumberOfEntries(NULL);
            for (ULONG ulIndex = 0; ulIndex < clientCount; ulIndex++) {
                pSListEntry = (PSINGLE_LINK_ENTRY)Client_GetEntry(NULL, ulIndex, &instanceNum);
                DHCPMGR_LOG_INFO("%s:%d DEBUG  instanceNum=%lu\n", __FUNCTION__, __LINE__, instanceNum);
                if (pSListEntry) {
                    DHCPMGR_LOG_INFO("%s:%d DEBUG  pSListEntry INSIDE \n", __FUNCTION__, __LINE__);
                    pDhcpCxtLink = ACCESS_COSA_CONTEXT_DHCPC_LINK_OBJECT(pSListEntry);
                    pDhcpc = (PCOSA_DML_DHCPC_FULL)pDhcpCxtLink->hContext;
                    DHCPMGR_LOG_INFO("%s:%d DEBUG storedLease.Cfg.Interface=%s\n", __FUNCTION__, __LINE__, storedLease->Cfg.Interface);
                    // Extract clientpid from the stored lease
                    clientpid = storedLease->Info.ClientProcessId;
                    DHCPv4_PLUGIN_MSG *current = (DHCPv4_PLUGIN_MSG *)malloc(sizeof(DHCPv4_PLUGIN_MSG));
                    if (!current) {
                        DHCPMGR_LOG_ERROR("%s:%d Failed to allocate memory for current lease\n", __FUNCTION__, __LINE__);
                        free(storedLease);
                        continue;
                    }
                    else
                    {
                        memset(current, 0, sizeof(DHCPv4_PLUGIN_MSG));
                    }
                    if (pDhcpc && instanceNum == instanceNum_from_file) {
                        if(storedLease->currentLease)
                        {
                            DHCPMGR_LOG_INFO("%s:%d <<DEBUG>> storedLease->currentLease is VALID\n", __FUNCTION__, __LINE__);
                            memcpy(current, storedLease->currentLease, sizeof(DHCPv4_PLUGIN_MSG));
                        }
                        else
                        {
                            DHCPMGR_LOG_ERROR("%s:%d <<DEBUG>>  storedLease->currentLease is NULL\n", __FUNCTION__, __LINE__);
                        }
                        pthread_mutex_lock(&pDhcpc->mutex);
                        system("echo `dmcli eRT getv Device.DHCPv4.Client.1.` >> /rdklogs/logs/DHCPMGRLog.txt.0"); // DELETE
                        snprintf(pDhcpc->Cfg.Interface, sizeof(pDhcpc->Cfg.Interface), "%s", storedLease->Cfg.Interface);
                        system("echo After........ >> /rdklogs/logs/DHCPMGRLog.txt.0"); // DELETE
                        memcpy(&pDhcpc->Info.IPAddress, &storedLease->Info.IPAddress, sizeof(pDhcpc->Info.IPAddress));
                        system("echo `dmcli eRT getv Device.DHCPv4.Client.1.` >> /rdklogs/logs/DHCPMGRLog.txt.0"); // DELETE
                        memcpy(&pDhcpc->Info.SubnetMask, &storedLease->Info.SubnetMask, sizeof(pDhcpc->Info.SubnetMask));
                        pDhcpc->Info.ClientProcessId = clientpid;
                        pDhcpc->Info.Status = storedLease->Info.Status;
                        pDhcpc->Cfg.bEnabled = storedLease->Cfg.bEnabled;
                        pDhcpc->currentLease = current;
                        if (pDhcpc->currentLease) {
                            DHCPMGR_LOG_INFO("%s:%d <<DEBUG>> currentLease is VALID\n", __FUNCTION__, __LINE__);
                        } else {
                            DHCPMGR_LOG_ERROR("%s:%d <<DEBUG>> currentLease is INVALID\n", __FUNCTION__, __LINE__);
                        }
                        pDhcpc->currentLease->next = NULL;
                        pthread_mutex_unlock(&pDhcpc->mutex);
                        DHCPMGR_LOG_INFO("%s:%d  <<DEBUG>> Lease data loaded into DHCP Manager for interface storedLease->Cfg.Interface=%s \n pDhcpc->Cfg.Interface=%s \n", __FUNCTION__, __LINE__, storedLease->Cfg.Interface, pDhcpc->Cfg.Interface);
                    }
                    // Check if the PID in the stored data is still running
                    char procPath[64] = {0};
                    snprintf(procPath, sizeof(procPath), "/proc/%d", clientpid);
                    if (access(procPath, F_OK) == -1) {
                        DHCPMGR_LOG_INFO("%s:%d PID %d is not running, calling processKilled\n", __FUNCTION__, __LINE__, clientpid);
                        processKilled(clientpid);
                    } else {
                        DHCPMGR_LOG_INFO("%s:%d PID %d is still running\n", __FUNCTION__, __LINE__, clientpid);
                    }
                    free(storedLease);
                    break; // Exit loop once a match is found
                }
            }
        }
    }

    globfree(&results);
    DHCPMGR_LOG_INFO("%s:%d Completed loading all lease files\n", __FUNCTION__, __LINE__);
}