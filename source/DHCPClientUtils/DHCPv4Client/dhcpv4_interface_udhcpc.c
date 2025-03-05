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

#include "dhcpv4_interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#define UDHCPC_CLIENT                    "udhcpc"
#define UDHCPC_CLIENT_PATH               "/sbin/"UDHCPC_CLIENT
#define UDHCP_PIDFILE                    "/tmp/udhcpc.%s.pid"
#define UDHCPC_PLUGIN_EXE               "/usr/bin/dhcpmgr_udhcpc_plugin"
#define UDHCP_PIDFILE_PATTERN            "-p "UDHCP_PIDFILE" "
#define UDHCPC_TERMINATE_TIMEOUT         (10 * MSECS_IN_SEC)


/*
 * udhcpc_get_req_options ()
 * @description: This function will construct a buffer with all the udhcpc REQUEST options
 * @params     : buff - output buffer to pass all REQUEST options
 *               req_opt_list - input list of DHCP REQUEST options
 * @return     : return a buffer that has -O <REQ-DHCP-OPT>
 *
 */
static int udhcpc_get_req_options (char * buff, dhcp_opt_list * req_opt_list)
{

    if (buff == NULL)
    {
        DHCPMGR_LOG_ERROR(" %s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (req_opt_list == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: No req option sent to udhcpc.\n", __FUNCTION__, __LINE__);
        return SUCCESS;
    }

    char args [BUFLEN_16] = {0};

    while (req_opt_list)
    {
        memset (&args, 0, BUFLEN_16);
        if (req_opt_list->dhcp_opt == DHCPV4_OPT_2)
        {
            /* CID 189999 Calling risky function */
            snprintf(args, (BUFLEN_16-1),"-O timezone ");
        }
        else if (req_opt_list->dhcp_opt == DHCPV4_OPT_42)
        {
            strcpy (args, "-O ntpsrv ");
        }
        else
        {
            snprintf (args, BUFLEN_16, "-O %d ", req_opt_list->dhcp_opt);
        }
        req_opt_list = req_opt_list->next;
        strcat(buff, args);
    }

    DHCPMGR_LOG_INFO("%s %d: udhcpc args with request options args :  %s\n", __FUNCTION__, __LINE__, buff);
    return SUCCESS;

}

/*
 * udhcpc_get_send_options ()
 * @description: This function will construct a buffer with all the udhcpc SEND options
 * @params     : buff - output buffer to pass all SEND options
 *               req_opt_list - input list of DHCP SEND options
 * @return     : return a buffer that has -x <SEND-DHCP-OPT:SEND-DHCP-OPT-VALUE> (or -V <SEND-DHCP-OPT-VALUE> for option60)
 *
 */
static int udhcpc_get_send_options (char * buff, dhcp_opt_list * send_opt_list)
{

    if (buff == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (send_opt_list == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: No send option sent to udhcpc.\n", __FUNCTION__, __LINE__);
        return SUCCESS;
    }

    char args [BUFLEN_128] = {0};
    while ((send_opt_list != NULL) && (send_opt_list->dhcp_opt_val != NULL))
    {
        memset (&args, 0, BUFLEN_128);
        if (send_opt_list->dhcp_opt == DHCPV4_OPT_60)
        {
            // Option 60 - Vendor Class Identifier has udhcp cmd line arg "-V <option-str>"
            snprintf (args, BUFLEN_128, "-V %s ", send_opt_list->dhcp_opt_val);
        }
        else
        {
            /* char * buffer = ascii_to_hex (send_opt_list->dhcp_opt_val, strlen(send_opt_list->dhcp_opt_val)); */
            /* if (buffer != NULL) */
            /* { */
            /*     snprintf (args, BUFLEN_128, "-x 0x%02X:%s ", send_opt_list->dhcp_opt, buffer); */
            /*     free(buffer); */
            /* } */
            snprintf (args, BUFLEN_128, "-x 0x%02X:%s ", send_opt_list->dhcp_opt, send_opt_list->dhcp_opt_val);
        }
        send_opt_list = send_opt_list->next;
        strcat (buff,args);
    }

    DHCPMGR_LOG_INFO("%s %d: udhcpc args with send options  :  %s\n", __FUNCTION__, __LINE__, buff);

    return SUCCESS;
}

/*
 * udhcpc_get_other_args ()
 * @description: This function will construct a buffer with all other udhcpc options
 * @params     : buff - output buffer to pass all SEND options
 * @param      : interfaceName - The name of the network interface.

 * @return     : return a buffer that has -i, -p, -s, -b/f/n options
 *
 */
static int udhcpc_get_other_args (char * buff, char *interfaceName)
{
     if ((buff == NULL) || (interfaceName == NULL))
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    // Add -i <ifname>
    if (interfaceName != NULL)
    {
        char ifname_opt[BUFLEN_16] = {0};
        snprintf (ifname_opt, sizeof(ifname_opt), "-i %s ", interfaceName);
        strcat (buff, ifname_opt);

        // Add -p <pidfile>
        char pidfile[BUFLEN_32] = {0};
        snprintf (pidfile, sizeof(pidfile), UDHCP_PIDFILE_PATTERN , interfaceName);
        strcat (buff, pidfile);
    }

   // Add -s <servicefile>
    char servicefile[BUFLEN_64] = {0};

    snprintf (servicefile, sizeof(servicefile), "-s %s ", UDHCPC_PLUGIN_EXE);
    strcat (buff, servicefile);

    //TODO : define a generic behaviour
    // Add udhcpc process behavior
#ifdef UDHCPC_RUN_IN_FOREGROUND
    // udhcpc will run in foreground
    strcat (buff, "-f ");
#elif UDHCPC_RUN_IN_BACKGROUND
    // udhcpc will run in background if lease not obtained
    strcat (buff, "-b ");
#elif UDHCPC_EXIT_AFTER_LEAVE_FAILURE
    // exit if lease is not obtained
    strcat (buff, "-n ");
#endif

   // send release before exit
    strcat (buff, "-R ");

    DHCPMGR_LOG_INFO("%s %d: udhcpc args with other options args :  %s\n", __FUNCTION__, __LINE__, buff);

    return SUCCESS;
}

/**
 * @brief Creates the argument string for the udhcpc client.
 *
 * This function generates the argument string for the udhcpc client using the provided interface name,
 * request option list, and send option list.
 *
 * @param[out] args_buffer Buffer to store the generated argument string.
 * @param[in] interfaceName The name of the network interface.
 * @param[in] req_opt_list Pointer to the list of requested DHCP options.
 * @param[in] send_opt_list Pointer to the list of options to be sent.
 * @return 0 on success, -1 on failure.
 */
int udhcpc_args_generator(char *args_buffer, char *interfaceName, dhcp_opt_list *req_opt_list, dhcp_opt_list *send_opt_list)
{
    DHCPMGR_LOG_INFO("%s %d: Constructing REQUEST option args to udhcpc.\n", __FUNCTION__, __LINE__);
    if ((req_opt_list != NULL) && (udhcpc_get_req_options(args_buffer, req_opt_list)) != SUCCESS)
    {
        DHCPMGR_LOG_ERROR("%s %d: Unable to get DHCPv4 REQ OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    DHCPMGR_LOG_INFO("%s %d: Constructing SEND option args to udhcpc.\n", __FUNCTION__, __LINE__);
    if ((send_opt_list != NULL) && (udhcpc_get_send_options(args_buffer, send_opt_list) != SUCCESS))
    {
        DHCPMGR_LOG_ERROR("%s %d: Unable to get DHCPv4 SEND OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    DHCPMGR_LOG_INFO("%s %d: Constructing other option args to udhcpc.\n", __FUNCTION__, __LINE__);
    if (udhcpc_get_other_args(args_buffer, interfaceName) != SUCCESS)
    {
        DHCPMGR_LOG_ERROR("%s %d: Unable to get DHCPv4 SEND OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    return SUCCESS;

}

pid_t start_dhcpv4_client(char *interfaceName, dhcp_opt_list *req_opt_list, dhcp_opt_list *send_opt_list) 
{
    DHCPMGR_LOG_INFO("%s %d udhcpc api called \n", __FUNCTION__, __LINE__);
    pid_t udhcpc_pid = 0;
    if ((interfaceName == NULL))
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }


    char buff [BUFLEN_512] = {0};
    udhcpc_args_generator(buff,interfaceName, req_opt_list, send_opt_list);


    udhcpc_pid = get_process_pid(UDHCPC_CLIENT, buff, false);

    if (udhcpc_pid > 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: another instance of %s runing on %s\n", __FUNCTION__, __LINE__, UDHCPC_CLIENT, interfaceName);
        //TODO: Existing client will not be handled by the sigchild handler. Selfheal will not work for this PID, should we kill and restart?
        return udhcpc_pid;
    }

    udhcpc_pid = start_exe2(UDHCPC_CLIENT_PATH, buff);

#ifdef UDHCPC_RUN_IN_BACKGROUND
    // udhcpc-client will demonize a child thread during start, so we need to collect the exited main thread
    if (collect_waiting_process(udhcpc_pid, UDHCPC_TERMINATE_TIMEOUT) != SUCCESS)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to collect pid for %d.\n", __FUNCTION__, __LINE__, udhcpc_pid);
    }

    DHCPMGR_LOG_INFO("%s %d: Started udhcpc. returning pid..\n", __FUNCTION__, __LINE__);
    udhcpc_pid = get_process_pid (UDHCPC_CLIENT, NULL, true);
#endif
    return udhcpc_pid;
}


int send_dhcpv4_renew(pid_t processID) 
{
    DHCPMGR_LOG_INFO("%s %d udhcpc api called \n", __FUNCTION__, __LINE__);
    if (signal_process(processID, SIGUSR1) != RETURN_OK)
    {
         DBG_PRINT("<<DEBUG>>%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, processID);
         return FAILURE;
    }
    return SUCCESS;
}

int send_dhcpv4_release(pid_t processID) 
{
    (void)processID;
    DHCPMGR_LOG_INFO("%s %d udhcpc api called \n", __FUNCTION__, __LINE__);
    //Trigger a release 
    if (signal_process(processID, SIGUSR2) != RETURN_OK)
    {
        DHCPMGR_LOG_ERROR("<<DEBUG>>%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, processID);
        return FAILURE;    
    }
    return SUCCESS;
}

int stop_dhcpv4_client(pid_t processID) 
{
    DHCPMGR_LOG_INFO("%s %d udhcpc api called \n", __FUNCTION__, __LINE__);

    if (processID <= 0)
    {
        DHCPMGR_LOG_ERROR("<<DEBUG>>%s %d: unable to get pid of %s\n", __FUNCTION__, __LINE__, UDHCPC_CLIENT);
        return FAILURE;
    }

    //Trigger a release. Always release when client stopped ?
    if (signal_process(processID, SIGUSR2) != RETURN_OK)
    {
        DHCPMGR_LOG_ERROR("<<DEBUG>>%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, processID);
        return FAILURE;    
    }
    if (signal_process(processID, SIGTERM) != RETURN_OK)
    {
        DHCPMGR_LOG_ERROR("<<DEBUG>>%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, processID);
         return FAILURE;
    }

    //TODO: start_exe2 will add a sigchild handler, Do we still require this call ?
    int ret = collect_waiting_process(processID, UDHCPC_TERMINATE_TIMEOUT);
    return ret;
}
