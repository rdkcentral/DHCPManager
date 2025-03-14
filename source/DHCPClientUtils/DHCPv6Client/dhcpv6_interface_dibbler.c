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

#include "dhcpv6_interface.h"
#include <stdio.h>

#define DIBBLER_CLIENT                    "dibbler-client"
#define DIBBLER_CLIENT_PATH               "/usr/sbin/"DIBBLER_CLIENT
#define DIBBLER_CLIENT_RUN_CMD            "start"
#define DIBBLER_CLIENT_CMD                DIBBLER_CLIENT" "DIBBLER_CLIENT_RUN_CMD
#define DIBBLER_DFT_PATH                  "/etc/dibbler/"
#define DIBBLER_CLIENT_CONFIG_FILE        "client.conf"
#define DIBBLER_TMP_CONFIG_FILE           "/tmp/dibbler/client-tmp.conf"
#define DIBBLER_TEMPLATE_CONFIG_FILE      "/tmp/dibbler/client-template.conf"
#define DIBBLER_CLIENT_PIDFILE            "/tmp/dibbler/client.pid"
#define DIBBLER_DEFAULT_CONFIG_FILE       "/tmp/dibbler/client.conf"
#define DIBBLER_CLIENT_TERMINATE_TIMEOUT  (10 * MSECS_IN_SEC)
#define DIBBLER_PLUGIN_EXE                "/usr/bin/dhcpmgr_dibbler_plugin"
#define DIBBLER_LOG_CONFIG                "log-level 7\nlog-mode full\n"
#define DIBBLER_DUID_LL_CONFIG            "duid-type duid-ll\n"  
#define DIBBLER_CLIENT_TERMINATE_INTERVAL (0.5 * MSECS_IN_SEC)
#define DIBBLER_TMP_DIR_PATH              "/var/lib/dibbler"
#define DIBBLER_RADVD_FILE                "/etc/dibbler/radvd.conf"
#define DIBBLER_RADVD_FILE_OLD            "/etc/dibbler/radvd.conf.old"

static int copy_file (char * src, char * dst)
{
    if ((src == NULL) || (dst == NULL))
    {
        DHCPMGR_LOG_ERROR("<<DEBUG>>%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    FILE * fin = NULL;
    FILE * fout = NULL;

    fout = fopen(dst, "wb");
    if (fout == NULL)
    {
        DHCPMGR_LOG_ERROR("<<DEBUG>>%s %d: failed to open file %s\n", __FUNCTION__, __LINE__, dst);
        return FAILURE;
    }
    
    fin = fopen(src, "r");

    if (fin == NULL)
    {
        DHCPMGR_LOG_ERROR("<<DEBUG>>%s %d: failed to open file %s\n", __FUNCTION__, __LINE__, src);
        fclose (fout);
        return FAILURE;
    }

    ssize_t nread;
    size_t len = 0;
    char *line = NULL;

    while ((nread = getline(&line, &len, fin)) != -1) 
    {
        fwrite(line, nread, 1, fout);
    }

    if (line)
    {
        free(line);
    }
    fclose(fin);
    fclose(fout);

    DHCPMGR_LOG_INFO("<<DEBUG>>%s %d: successfully copied content from %s to %s\n", __FUNCTION__, __LINE__, src, dst);
    return SUCCESS;

}

static int dibbler_get_req_options(FILE * fout,  dhcp_opt_list * req_opt_list)
{
    if(fout == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid file pointer.\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if(req_opt_list == NULL)
    {
        DHCPMGR_LOG_WARNING("%s %d: Invalid file pointer.\n", __FUNCTION__, __LINE__);
        return 0;
    }

    char args [BUFLEN_512] = {0};
    // request option
    dhcp_opt_list * opt_list = req_opt_list;
    while (opt_list)
    {
        memset (&args, 0, sizeof(args));

        if (opt_list->dhcp_opt == DHCPV6_OPT_5)
        {
            snprintf (args, sizeof(args), "\n\t%s \n", (opt_list->dhcp_opt_val == NULL)?"ia":opt_list->dhcp_opt_val);
            fputs(args, fout);
        }
        else if (opt_list->dhcp_opt == DHCPV6_OPT_23)
        {
            snprintf (args, sizeof(args), "\n\t%s \n", "option dns-server");
            fputs(args, fout);
        }
        else if (opt_list->dhcp_opt == DHCPV6_OPT_25)
        {
            snprintf (args, sizeof(args), "\n\t%s \n", (opt_list->dhcp_opt_val == NULL)?"pd":opt_list->dhcp_opt_val);
            fputs(args, fout);
        }
        else if (opt_list->dhcp_opt == DHCPV6_OPT_24)
        {
            snprintf (args, sizeof(args), "\n\t%s \n", "option domain");
            fputs(args, fout);
        }
        else if (opt_list->dhcp_opt == DHCPV6_OPT_95)
        {
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
            if (syscfg_get(NULL, SYSCFG_MAPT_FEATURE_ENABLE, mapt_feature_enable, sizeof(mapt_feature_enable)) == 0)
            {
                if (strncmp(mapt_feature_enable, "true", 4) == 0)
                {
#endif
                    snprintf (args, sizeof(args), "\n\toption 00%d hex \n", opt_list->dhcp_opt);
                    fputs(args, fout);
#if defined(FEATURE_MAPT) || defined(FEATURE_SUPPORT_MAPT_NAT46)
                }
            }
#endif
        }
        else if (opt_list->dhcp_opt == DHCPV6_OPT_64)
        {
            fputs("\n\toption aftr\n", fout);
        }
        else
        {
            snprintf (args, sizeof(args), "\n\toption 00%d hex \n", opt_list->dhcp_opt);
            fputs(args, fout);
        }
        opt_list = opt_list->next;
    }

    return 0;

}

static int dibbler_get_send_options(FILE * fout,  dhcp_opt_list * send_opt_list)
{
    if(fout == NULL)
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid file pointer.\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if(send_opt_list == NULL)
    {
        DHCPMGR_LOG_WARNING("%s %d: Invalid file pointer.\n", __FUNCTION__, __LINE__);
        return 0;
    }

    char args [BUFLEN_512] = {0};
    //send option list
    dhcp_opt_list * opt_list = send_opt_list;
    while (opt_list)
    {
        memset (&args, 0, sizeof(args));
        if (opt_list->dhcp_opt == DHCPV6_OPT_15)
        {
            char str[32]={0};
            char option15[100]={0};
            char temp[16]={0};

            strncpy(str,opt_list->dhcp_opt_val,strlen(opt_list->dhcp_opt_val)+1);

            snprintf(temp, 8, "0x%04X",(int)strlen(str)+1);
            strncat(option15,temp,8);

            for(int i=0; i<(int)strlen(str)+1; i++)
            {
                snprintf(temp, 3, "%02X",str[i]);
                strncat(option15,temp,3);
            }

            snprintf (args, sizeof(args), "\n\toption 00%d hex %s\n", opt_list->dhcp_opt,option15 );
            fputs(args, fout);
        }
        else if (opt_list->dhcp_opt_val != NULL) /* Generic Dibbler option format */
        {
            snprintf (args, sizeof(args), "\n\toption 00%d hex %s\n", opt_list->dhcp_opt, opt_list->dhcp_opt_val);
            fputs(args, fout);
        }

        opt_list = opt_list->next;
    }

    return 0;

}

static int dibbler_get_reconfigureAccept(dhcp_opt_list * send_opt_list)
{
    dhcp_opt_list * opt_list = send_opt_list;
    while (opt_list)
    {
        if (opt_list->dhcp_opt == DHCPV6_OPT_20)
        {
            return 1;
        }
        opt_list = opt_list->next;
    }

    return 0;
}

/**
 * @brief Creates the Dibbler client configuration file.
 *
 * This function generates the Dibbler client configuration file in the specified config_path
 * using the provided interface name, request option list, and send option list.
 *
 * @param[in] config_path The path where the configuration file will be created. Example : /etc/dibbler/vdsl0
 * @param[in] interfaceName The name of the network interface.
 * @param[in] req_opt_list Pointer to the list of requested DHCP options.
 * @param[in] send_opt_list Pointer to the list of options to be sent.
 * @return 0 on success, -1 on failure.
 */
static int dibbler_client_config_generator(char *config_path, char *interfaceName, dhcp_opt_list *req_opt_list, dhcp_opt_list *send_opt_list)
{
     //Create /etc/dibbler/radvd.conf file if doesn't exist. Dibbler client requires this file.
     FILE *radvdFile;
     radvdFile = fopen(DIBBLER_RADVD_FILE_OLD, "a");
     if(radvdFile != NULL)
     {
         fclose(radvdFile);
     }
 
     radvdFile = fopen(DIBBLER_RADVD_FILE, "a");
     if(radvdFile != NULL)
     {
         fclose(radvdFile);
     }
 
     /************ DIBBLER CLIENT CONF FILE GENERATION *************/
     
    FILE * fout;
    fout = fopen(DIBBLER_TMP_CONFIG_FILE, "w+");

    if (fout == NULL)
    {
        DBG_PRINT("%s %d: unable to open tmp file: %s\n", __FUNCTION__, __LINE__, DIBBLER_TMP_CONFIG_FILE);
        return FAILURE;
    }

    char buff[BUFLEN_128];
    // write common config
    snprintf(buff, sizeof(buff), "script \"%s\"\n", DIBBLER_PLUGIN_EXE);
    fputs(buff, fout);
    fputs(DIBBLER_LOG_CONFIG, fout);
    fputs(DIBBLER_DUID_LL_CONFIG, fout);

    // interface specific config start
    snprintf(buff, sizeof(buff), "iface %s {\n", interfaceName);
    fputs(buff, fout);

    if ((dibbler_get_req_options(fout, req_opt_list)) != SUCCESS)
    {
        DHCPMGR_LOG_ERROR("%s %d: Unable to get DHCPv6 REQ OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    DHCPMGR_LOG_INFO("%s %d: Constructing SEND option args to udhcpc.\n", __FUNCTION__, __LINE__);
    if ((dibbler_get_send_options(fout, send_opt_list) != SUCCESS))
    {
        DHCPMGR_LOG_ERROR("%s %d: Unable to get DHCPv6 SEND OPT.\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    // interface specific config end
    fputs("\n}", fout);
    
    // write common config
    fputs("skip-confirm\n", fout);
    fputs("downlink-prefix-ifaces \"brlan0\"\n", fout);

    if(dibbler_get_reconfigureAccept(send_opt_list))
    {
        snprintf (buff, sizeof(buff), "\n%s\n", "reconfigure-accept 1");
        fputs(buff, fout);
    }
    fclose(fout);

    // copy the file to new location
    char file_path[BUFLEN_128];
    int ret = snprintf(file_path, sizeof(file_path), "%s/%s", config_path, DIBBLER_CLIENT_CONFIG_FILE);
    if (ret <= 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to contruct filepath\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (copy_file (DIBBLER_TMP_CONFIG_FILE, file_path) != SUCCESS)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to copy %s to %s due to %s\n", __FUNCTION__, __LINE__, DIBBLER_TEMPLATE_CONFIG_FILE, file_path, strerror(errno));
        return FAILURE;
    }
    
    // dibber-client uses default config to generate DUID, so linking default file to tmp file

    if (access(DIBBLER_DEFAULT_CONFIG_FILE, F_OK) == 0) {
        DHCPMGR_LOG_WARNING("%s %d: link already exists, continuing\n", __FUNCTION__, __LINE__);
        return SUCCESS;
    } 
    else 
    {
        // Creating the link only if it doesn't already exist
        if (link(DIBBLER_TMP_CONFIG_FILE, DIBBLER_DEFAULT_CONFIG_FILE) == 0) {
            DHCPMGR_LOG_INFO("%s %d: link created successfully\n", __FUNCTION__, __LINE__);
            return SUCCESS;
        } else {
            DHCPMGR_LOG_ERROR("%s %d: unable to create link: %s\n", __FUNCTION__, __LINE__, strerror(errno));
            return FAILURE;
        }
    }

    return SUCCESS;

}

pid_t start_dhcpv6_client(char *interfaceName, dhcp_opt_list *req_opt_list, dhcp_opt_list *send_opt_list) 
{
    DHCPMGR_LOG_INFO("%s %d start_dhcpv6_client dibbler API called \n", __FUNCTION__, __LINE__);
    pid_t dibbler_pid = 0;
    if ((interfaceName == NULL))
    {
        DHCPMGR_LOG_ERROR("%s %d: Invalid args..\n", __FUNCTION__, __LINE__);
        return -1;
    }

    //Check if default dibbler tmp path available or not. If not then create it
    create_dir_path(DIBBLER_TMP_DIR_PATH);

    dibbler_pid = get_process_pid(DIBBLER_CLIENT, interfaceName, false);
    if (dibbler_pid > 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: another instance of %s running on %s \n", __FUNCTION__, __LINE__, DIBBLER_CLIENT, interfaceName);
        return dibbler_pid;
    }

    // check if interface is ipv6 ready with a link-local address
    unsigned int waitTime = INTF_V6LL_TIMEOUT_IN_MSEC;
    char cmd[BUFLEN_128] = {0};
    snprintf(cmd, sizeof(cmd), "ip address show dev %s tentative", interfaceName);
    while (waitTime > 0)
    {
        FILE *fp_dad   = NULL;
        char buffer[BUFLEN_256] = {0};

        fp_dad = popen(cmd, "r");
        if(fp_dad != NULL)
        {
            if ((fgets(buffer, BUFLEN_256, fp_dad) == NULL) || (strlen(buffer) == 0))
            {
                pclose(fp_dad);
                break;
            }
            DHCPMGR_LOG_WARNING("%s %d: interface still tentative: %s\n", __FUNCTION__, __LINE__, buffer);
            pclose(fp_dad);
        }
        usleep(INTF_V6LL_INTERVAL_IN_MSEC * USECS_IN_MSEC);
        waitTime -= INTF_V6LL_INTERVAL_IN_MSEC;
    }

    if (waitTime <= 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: interface %s doesnt have link local address\n", __FUNCTION__, __LINE__, interfaceName);
        //TODO: linklocal isn't present, should we toggle IPv6 on the interface here?
        return dibbler_pid;
    }

    //create a directry for dibbler client to run. 
    char config_path[BUFLEN_256] = {0};
    snprintf(config_path, sizeof(config_path), "%s%s", DIBBLER_DFT_PATH, interfaceName);
    if (mkdir(config_path, 0644) == 0)
    {
        DHCPMGR_LOG_ERROR ("%s %d: created directory %s\n", __FUNCTION__, __LINE__, config_path);
    }
    else
    {
        DHCPMGR_LOG_INFO ("%s %d: Directory already exists / not created  %s\n", __FUNCTION__, __LINE__, config_path);
    }
    
    if (dibbler_client_config_generator(config_path,interfaceName, req_opt_list, send_opt_list) != SUCCESS)
    {
        DHCPMGR_LOG_ERROR("%s %d: Unable to create dibbler conf.\n", __FUNCTION__, __LINE__);
        return FAILURE;

    }

    DHCPMGR_LOG_INFO("%s %d: Starting dibbler with config %s\n", __FUNCTION__, __LINE__, config_path);

    char cmd_args[BUFLEN_256] = {0};
    snprintf(cmd_args, sizeof(cmd_args), "%s -w %s", DIBBLER_CLIENT_RUN_CMD, config_path);

    pid_t ret = start_exe(DIBBLER_CLIENT_PATH, cmd_args);
    if (ret <= 0)
    {
        DHCPMGR_LOG_ERROR("%s %d: unable to start dibbler-client %d.\n", __FUNCTION__, __LINE__, ret);
        return FAILURE;
    }

    //dibbler-client will demonize a child thread during start, so we need to collect the exited main thread
    if (collect_waiting_process(ret, DIBBLER_CLIENT_TERMINATE_TIMEOUT) != SUCCESS)
    {
        DHCPMGR_LOG_WARNING("%s %d: unable to collect pid for %d.\n", __FUNCTION__, __LINE__, ret);
    }

    DHCPMGR_LOG_INFO("%s %d: Started dibbler-client. returning pid..\n", __FUNCTION__, __LINE__);
    return get_process_pid (DIBBLER_CLIENT, cmd_args, true);

}

int send_dhcpv6_renew(pid_t processID) {
    (void)processID;
    DHCPMGR_LOG_INFO("%s %d  send_dhcpv6_renew\n", __FUNCTION__, __LINE__);
    return 0;
}

int send_dhcpv6_release(pid_t processID) {
    (void)processID;
    DHCPMGR_LOG_INFO("%s %d  send_dhcpv6_release\n", __FUNCTION__, __LINE__);
    return 0;
}

 int stop_dhcpv6_client(pid_t processID) 
 {
    DHCPMGR_LOG_INFO("%s %d dibbler-client api called \n", __FUNCTION__, __LINE__);

    if (processID <= 0)
    {
        DHCPMGR_LOG_ERROR("<<DEBUG>>%s %d: unable to get pid of dibbler\n", __FUNCTION__, __LINE__);
        return FAILURE;
    }

    if (signal_process(processID, SIGTERM) != RETURN_OK)
    {
        DHCPMGR_LOG_ERROR("<<DEBUG>>%s %d: unable to send signal to pid %d\n", __FUNCTION__, __LINE__, processID);
         return FAILURE;
    }

    //TODO: start_exe2 will add a sigchild handler, Do we still require this call ?
    int ret = collect_waiting_process(processID, DIBBLER_CLIENT_TERMINATE_TIMEOUT);
    return ret;
}