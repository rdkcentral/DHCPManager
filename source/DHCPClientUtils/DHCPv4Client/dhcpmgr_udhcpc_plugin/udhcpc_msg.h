#ifndef _UDHCPC_MSG_H_
#define _UDHCPC_MSG_H_

#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>

#define LEASE_MONITOR_SOCKET "tcp://127.0.0.1:50324"

#define BUFLEN_4                         4           //!< buffer length 4
#define BUFLEN_8                         8           //!< buffer length 8
#define BUFLEN_16                        16          //!< buffer length 16
#define BUFLEN_18                        18          //!< buffer length 18
#define BUFLEN_24                        24          //!< buffer length 24
#define BUFLEN_32                        32          //!< buffer length 32
#define BUFLEN_40                        40          //!< buffer length 40
#define BUFLEN_48                        48          //!< buffer length 48
#define BUFLEN_64                        64          //!< buffer length 64
#define BUFLEN_80                        80          //!< buffer length 80
#define BUFLEN_128                       128         //!< buffer length 128
#define BUFLEN_256                       256         //!< buffer length 256
#define BUFLEN_264                       264         //!< buffer length 264
#define BUFLEN_512                       512         //!< buffer length 512
#define BUFLEN_1024                      1024        //!< buffer length 1024
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

typedef struct _DHCPv4_PLUGIN_MSG
{
    bool addressAssigned;              /** Have we been assigned an IP address ? */
    bool isExpired;                    /** Is the lease time expired ? */
    char ip[BUFLEN_32];                /** New IP address, if addressAssigned==TRUE */
    char mask[BUFLEN_32];              /** New netmask, if addressAssigned==TRUE */
    char gateway[BUFLEN_32];           /** New gateway, if addressAssigned==TRUE */
    char dnsServer[BUFLEN_64];         /** New dns Server, if addressAssigned==TRUE */
    char dnsServer1[BUFLEN_64];        /** New dns Server, if addressAssigned==TRUE */
    char InterfaceName[BUFLEN_32];    /** Dhcp interface name */
    uint32_t leaseTime;                /** Lease time, , if addressAssigned==TRUE */
    uint32_t rebindingTime;            /** Rebinding time, if addressAssigned==TRUE */
    uint32_t renewalTime;              /** Renewal Time, if addressAssigned==TRUE */
    int32_t timeOffset;                /** New time offset, if addressAssigned==TRUE */
    bool isTimeOffsetAssigned;         /** Is the time offset assigned ? */
    char timeZone[BUFLEN_64];          /** New time zone, if addressAssigned==TRUE */
    uint32_t upstreamCurrRate;         /** Upstream rate */
    uint32_t downstreamCurrRate;       /** Downstream rate */
    char dhcpServerId[BUFLEN_64];      /** Dhcp server id */
    char dhcpState[BUFLEN_64];         /** Dhcp state. */
    bool mtuAssigned;                  /** Have we been assigned MTU size ? */
    uint32_t mtuSize;                  /** MTU Size, if mtuAssigned==TRUE */
    char sipsrv[BUFLEN_64];            /** Dhcp sipsrv. */
    char staticroutes[BUFLEN_64];      /** Dhcp classless static route */
} DHCPv4_PLUGIN_MSG;


typedef enum {
    DHCP_VERSION_4, 
    DHCP_VERSION_6,
} DHCP_SOURCE;

typedef struct {
    char ifname[BUFLEN_32];
    DHCP_SOURCE version;
    void *payload; // Dynamically allocated message (either DHCPv6_PLUGIN_MSG or DHCPv4_PLUGIN_MSG)
} PLUGIN_MSG;

typedef enum
{
    DHCPC_STATE_CHANGED = 1,
    DHCP6C_STATE_CHANGED,
    IPC_MSG_PPP_STATE_CHANGE,
    IHC_STATE_CHANGE,
    MAPT_STATE_CHANGED
}ipc_msg_type_t;

#endif
