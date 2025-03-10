#ifndef _UDHCPC_MSG_H_
#define _UDHCPC_MSG_H_

#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>
#include "dhcpv4_interface.h"
#include "dhcp_lease_monitor_thrd.h"

#define IP_ADDR_LENGTH                   46          //!< IP address length
#define IFNAME_LENGTH                    BUFLEN_32
#define MAX_FULLPATH_LENGTH              1024
#define AFTR_NAME_LENGTH                 256
#define MAX_SEND_THRESHOLD 5

#define DHCP_INTERFACE_NAME "interface"
#define DHCP_IP_ADDRESS "ip"
#define DHCP_SUBNET "subnet"
#define DHCP_SUBNET_MASK "mask"
#define DHCP_ROUTER_GW "router"
#define DHCP_DNS_SERVER "dns"
#define DHCP_UPSTREAMRATE "upstreamrate"
#define DHCP_DOWNSTREAMRATE "downstreamrate"
#define DHCP_TIMEZONE "timezone"
#define DHCP_TIMEOFFSET "timeoffset"
#define DHCP_LEASETIME "lease"
#define DHCP_RENEWL_TIME "renewaltime"
#define DHCP_ACK_OPT58 "opt58"
#define DHCP_ACK_OPT59 "opt59"
#define DHCP_REBINDING_TIME "rebindingtime"
#define DHCP_SERVER_ID "serverid"
#define DHCP_SIPSRV "sipsrv"
#define DHCP_STATIC_ROUTES "staticroutes"

#endif
