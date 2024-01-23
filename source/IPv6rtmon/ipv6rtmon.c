/*********************************************************************************
 If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 Deutsche Telekom AG.
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
********************************************************************************/
#include "ipv6rtmon.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <memory.h>
#include <net/if.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include "secure_wrapper.h"
#include "ansc_wrapper_base.h"

desiredOpts Opts = {-1, true, true, false}; /* default values */

static bool fifo_created = false;

/*
 * @brief Signal handler for taking action based on notify from CcspPandM
 */

void sig_handler(int signum)
{
    if (signum == SIGUSR1) { /* received SIGUSR1 */
        syslog(LOG_NOTICE, "Notify script invoked due to notification received after FIFO file creation.");
        fifo_created = true;
        setenv("FIFO_CREATED", "1", 1);
        notifyScript();
    }

    if (signum == SIGUSR2) { /* received SIGUSR2 */
        Opts.aFlag = false;
        setenv("AFlag", "0", 1);
    }
}

/*
 * @brief Function to create netlink socket
 */
int open_netlink_socket()
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);   // create netlink socket
    struct sockaddr_nl nl;
    int rcvBufSize = NLMSG_SPACE(NETLINK_BUFFER_SIZE)*3;

    if (fd < 0) {
        syslog(LOG_ERR, "Failed to create netlink socket: %s.", (char*)strerror(errno));
        return fd;
    }
    memset(&nl, 0, sizeof(nl));

    nl.nl_family = AF_NETLINK;       // set protocol family
    nl.nl_groups =   RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFINFO | RTMGRP_IPV6_IFADDR;   /* set interested groups */
    nl.nl_pid    = getpid();

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvBufSize, sizeof(rcvBufSize)) < 0) { // set socket options
        syslog(LOG_ERR, "Configuring SO_RCVBUF failed.");
        return FAILURE;
    }

    if (bind(fd, (struct sockaddr*)&nl, sizeof(nl)) < 0) {     // bind socket
        syslog(LOG_ERR, "Failed to bind netlink socket: %s.", (char*)strerror(errno));
        close(fd);
        return FAILURE;
    }

    return fd;
}

/*
 * @brief Function to read events from netlink socket
 */
void read_event(int fd, int (*msg_handler)(struct sockaddr_nl *, struct nlmsghdr *))
{
    int    ret            = FAILURE;
    struct sockaddr_nl nl = {0};

    char *buf = (char*)calloc(NLMSG_SPACE(NETLINK_BUFFER_SIZE), sizeof(char));    // message buffer
    if (buf == NULL) {
        syslog(LOG_ERR, "Out of memory error.");
    }

    struct iovec iov = {0};           // message structure
    iov.iov_base = buf;               // set message buffer as io
    iov.iov_len = sizeof(buf);        // set size

    /* initialize protocol message header */
    struct msghdr msg;
    {
        msg.msg_name = &nl;                  // nl address
        msg.msg_namelen = sizeof(nl);        // address size
        msg.msg_iov = &iov;                  // io vector
        msg.msg_iovlen = 1;                  // io size
    }

    while (1) {
        iov.iov_base = buf;                               // set message buffer as io
        iov.iov_len = NLMSG_SPACE(NETLINK_BUFFER_SIZE);   // set size
        ssize_t status = recvmsg(fd, &msg, 0);

        /*  check status */
        if (status < 0) {
            syslog(LOG_ERR, "Failed to read netlink: %s.", (char*)strerror(errno));
            continue;
        }
        if (msg.msg_namelen != sizeof(nl)) { // check message length, just in case
            syslog(LOG_ERR, "Invalid length of the sender address struct.");
            continue;
        }

        struct nlmsghdr *h;

        for (h = (struct nlmsghdr*)buf; status >= (ssize_t)sizeof(*h); ) {   // read all messagess headers
            int len = h->nlmsg_len;
            int l = len - sizeof(*h);

            if ((l < 0) || (len > status)) {
                syslog(LOG_ERR, "Invalid message length: %i.", len);
                continue;
            }
            /* Call message handler */
            if (msg_handler) {
                ret = (*msg_handler)(&nl, h);
                if (ret < 0)
                {
                    syslog(LOG_ERR, "read_netlink - Message hander error %d.", ret);
                    continue;
                }
            }
            else
            {
                syslog(LOG_ERR, "read_netlink - Error NULL message handler.");
                continue;
            }
            status -= NLMSG_ALIGN(len); // align offsets by the message length, this is important

            h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));    // get next message
       }
    }
}

/*
 * @brief Function to parse route attributes from the received message
 */

void parseRtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {  // while not end of the message
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta; // read attr
        }
        rta = RTA_NEXT(rta,len);    // get next attr
    }
}

/*
 * @brief Function to get total ipv6 default routes
 */

int getV6DefaultRoutesTotal()
{
    char count[16] ={0};

    FILE *defaultRoutes = v_secure_popen("r", "ip -6 route show | grep -i 'dev %s' | grep -i default | wc -l", WAN_INTERFACE);
    if (!defaultRoutes)
        return FAILURE;

    fgets(count, sizeof(count), defaultRoutes);
    count[strlen(count) -1 ] ='\0';
    v_secure_pclose(defaultRoutes);

    return atoi(count);
}

/*
 * @brief Function to handle received messages from netlink
 */

static int msg_handler(struct sockaddr_nl *nl, struct nlmsghdr *msg)
{
    bool isNotifyNeeded = false;
    bool isEnabled      = false;
    char temp[5];
    char raIfname[64]   = {0};

    UNREFERENCED_PARAMETER(nl);

    if (msg->nlmsg_type == RTM_NEWLINK || msg->nlmsg_type == RTM_NEWADDR) { /* changes in link or ipv6 address*/
        struct ifinfomsg *ifmsg = (struct ifinfomsg*) NLMSG_DATA(msg);
        struct rtattr *tbl[IFLA_MAX+1];
        parseRtattr(tbl, IFLA_MAX, IFLA_RTA(ifmsg), msg->nlmsg_len);  /* get attributes */
        if (tbl[IFLA_IFNAME]) { /* get associated interface */
             strcpy(raIfname,(char*)RTA_DATA(tbl[IFLA_IFNAME]));
             setenv("RAIFNAME", raIfname, 1);
        }

        if (tbl[IFLA_PROTINFO]) { /* protocol specific info of a link */
            struct rtattr *protoinfo[IFLA_MAX+1];
            parseRtattr(protoinfo, IFLA_MAX, (struct rtattr *)RTA_DATA(tbl[IFLA_PROTINFO]), msg->nlmsg_len);
            if (protoinfo[IFLA_INET6_FLAGS]) { /* get IPv6 link flags */
                if (((*(__u32 *)RTA_DATA(protoinfo[IFLA_INET6_FLAGS])) & IF_RA_RCVD) == false) { /* RA_RCVD flag in interface */
                    syslog(LOG_NOTICE, "Router advertisement not received in %s interface - RA_RCVD flag is not set.", raIfname);
                    Opts.aFlag = false;
                    setenv("AFlag", "0", 1);
                }
                if ((*(__u32 *)RTA_DATA(protoinfo[IFLA_INET6_FLAGS])) & IF_RA_MANAGED) { /* M flag is set in RA */
                    syslog(LOG_NOTICE, "M flag is set in Router Advertisement received in %s.", raIfname);
                    isEnabled = true;
                }
                else {
                    syslog(LOG_NOTICE, "M flag is unset in Router Advertisement received in %s.", raIfname);
                    isEnabled = false;
                }
                if (isEnabled != Opts.mFlag) {
                    isNotifyNeeded = true; /* notifyScript invocation needed as M flag changed */
                    setenv("MFlag", (isEnabled == true) ? "1" : "0", 1);
                    Opts.mFlag = isEnabled;
                }

                isEnabled = false;

                if ((*(__u32 *)RTA_DATA(protoinfo[IFLA_INET6_FLAGS])) & IF_RA_OTHERCONF) { /* O flag is set in RA */
                    syslog(LOG_NOTICE, "O flag is set in Router Advertisement received in %s.", raIfname);
                    isEnabled = true;
                }
                else {
                    syslog(LOG_NOTICE, "O flag is unset in Router Advertisement received in %s.", raIfname);
                    isEnabled = false;
                }
                if (isEnabled != Opts.oFlag) {
                    isNotifyNeeded = true; /* notifyScript invocation needed as O flag changed */
                    setenv("OFlag", (isEnabled == true) ? "1" : "0", 1);
                    Opts.oFlag = isEnabled;
                }

                isEnabled = false;
             }
        }

        if (msg->nlmsg_type == RTM_NEWADDR) {
            struct ifaddrmsg *ifa = (struct ifaddrmsg*) NLMSG_DATA(msg);
            struct rtattr *tba[IFLA_MAX + 1];
            parseRtattr(tba, IFA_MAX, IFA_RTA(ifa), msg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa))); /* get attributes */
            char ifname[128] = {0};

            if_indextoname(ifa->ifa_index, ifname); /* get associated interface */
            if (!tba[IFA_LOCAL])
                tba[IFA_LOCAL] = tba[IFA_ADDRESS];
            if (!tba[IFA_ADDRESS])
                tba[IFA_ADDRESS] = tba[IFA_LOCAL];

            isEnabled = false;
            if (tba[IFA_LOCAL] && (!IN6_IS_ADDR_LINKLOCAL(RTA_DATA(tba[IFA_LOCAL])))) /* got global IPv6 address from RA */
                isEnabled = true;
            else {
	        /* A flag off or Invalid prefix*/
	        Opts.aFlag = false;
	        setenv("AFlag", "0", 1);
            }						                   
            if (isEnabled && (isEnabled != Opts.aFlag)) { /* notifyScript invocation needed */
                isNotifyNeeded = true;
                syslog(LOG_NOTICE, "A flag is set as global IPv6 address got accepted for %s interface from Router Advertisement.", raIfname);
                Opts.aFlag = true;
                setenv("AFlag", "1", 1);
            }
            isEnabled = false;
         }

         if (isNotifyNeeded) {
             setenv("RA_Flags_Change", "1", 1);
             setenv("v6Routes_Change", "0", 1);
         }
    }
    else if ((msg->nlmsg_type == RTM_NEWROUTE) || (msg->nlmsg_type == RTM_DELROUTE)) { // changes in routing table
        struct rtmsg *rmsg    = (struct rtmsg *) NLMSG_DATA(msg);
        rmsg->rtm_flags       = RTM_F_NOTIFY;
        struct rtattr *tbr[RTA_MAX+1];
        char outInterface[64] = {0};

        parseRtattr(tbr, RTA_MAX, RTM_RTA(rmsg), msg->nlmsg_len);  // get attributes
        if (tbr[RTA_OIF]) { // output interface of route
            if_indextoname(*(__u32 *)RTA_DATA(tbr[RTA_OIF]), outInterface);
        }

        if (strcmp(outInterface, WAN_INTERFACE) == 0) {
            int count = getV6DefaultRoutesTotal();
            if (count != Opts.defaultRoutesCount) {
                if (count == 0) {
                    syslog(LOG_NOTICE, "No IPv6 default routes for %s interface present in the gateway.", WAN_INTERFACE);
                }
                else {
                    syslog(LOG_NOTICE, "IPv6 Default route(s) for %s interface present in the gateway.", WAN_INTERFACE);
                }
                if (count >= 0 && count < 10000) {
                    memset(temp, 0, sizeof(temp));
                    int ret = snprintf(temp, sizeof(temp), "%d", count);
                    if((ret > 0) && (ret < (int)sizeof(temp)))
                        setenv("DEFAULT_IPV6_ROUTES_COUNT", temp, 1);
                    isNotifyNeeded = true;
                    setenv("v6Routes_Change", "1", 1);
                    setenv("RA_Flags_Change", "0", 1);
                    Opts.defaultRoutesCount = count;
                }
            }
        }
    }

    if (isNotifyNeeded && fifo_created) { /* notify script invoked */
        notifyScript();
    }

    return SUCCESS;
}

/*
 * @brief Function to invoke notify script upon change in ipv6 deafult route entries or M/O flags in Router Advertisement.
 */

int notifyScript()
{
    FILE *script = v_secure_popen("r", "%s", NOTIFY_SCRIPT);
    if (!script) {
        syslog(LOG_ERR, "Notify script invocation failed.");
        return FAILURE;
    }
    v_secure_pclose(script);
    return SUCCESS;
}

int main() {
    pid_t pid, sid;
    int nl_socket = 0;

    /* Open the log file */
    openlog("ipv6rtmon-daemon", LOG_PID, LOG_DAEMON);
    syslog(LOG_NOTICE, "ipv6rtmon daemon started.");

    /* Fork off parent process */
    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "Forking the parent process failed. Exiting...");
        exit(EXIT_FAILURE);
    }

    /* exit the parent process if its good pid. */
    if (pid > 0) { /* Child can continue to run even after the parent has finished executing. */
        syslog(LOG_NOTICE, "Terminating the parent process.");
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Create a new Session ID for the child process */
    sid = setsid();
    if (sid < 0) {
        syslog(LOG_ERR, "Session ID creation for child process failed. Exiting...");
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        syslog(LOG_ERR, "Not able to change the current working directory. Exiting...");
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Daemon-specific initialization */
    nl_socket = open_netlink_socket();
    if (nl_socket < 0) {
        syslog(LOG_ERR, "Netlink socket open Error...");
        exit(EXIT_FAILURE);
    }

    signal(SIGUSR1, sig_handler); /* Register signal handler */
    signal(SIGUSR2, sig_handler);
    read_event(nl_socket, msg_handler);

    return 0;
}
