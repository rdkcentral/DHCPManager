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
#ifndef IPV6ROUTEMON_H
#define IPV6ROUTEMON_H

#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <stdbool.h>

#define WAN_INTERFACE        "erouter0"
#define NETLINK_BUFFER_SIZE  16*1024
#define NOTIFY_SCRIPT        "/etc/ipv6rtmon/notify.sh"

/* Router Advertisement flags */
#define IF_RA_MANAGED        0x40
#define IF_RA_OTHERCONF      0x80
#define IF_RA_RCVD           0x20

enum{
        FAILURE = -1,
        SUCCESS
    } RET;

typedef struct {
    int defaultRoutesCount;
    bool mFlag;
    bool oFlag;
    bool aFlag;
} desiredOpts;

int open_netlink_socket();
void read_event(int , int (*)(struct sockaddr_nl *,struct nlmsghdr *));
void parseRtattr(struct rtattr *tb[], int , struct rtattr *, int);
int getV6DefaultRoutesTotal();
int notifyScript();

#endif // IPV6ROUTEMON_H
