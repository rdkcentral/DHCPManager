#include <stdbool.h>
#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>

#define DHCP_MANAGER_ADDR              "tcp://127.0.0.1:50324"

#define BUFLEN_32                        32          //buffer length 32
#define BUFLEN_64                        64          //buffer length 64
#define BUFLEN_48                        48          //buffer length 48
#define BUFLEN_128                       128         //buffer length 128
#define BUFLEN_256                       256         //buffer length 256
#define AFTR_NAME_LENGTH                 256

typedef struct _DHCPv6_PLUGIN_MSG
{
    bool isExpired;        /** Is the lease time expired ? */
    char ifname[BUFLEN_32];    /** Dhcp interface name */

    //address details
    struct {
        char     address[BUFLEN_48];      /**< New IPv6 address */
        uint32_t IA_ID;
        uint32_t PreferedLifeTime;
        uint32_t ValidLifeTime;
        uint32_t T1;
        uint32_t T2;
    }ia_na;

    //IAPD details
    struct {
        char     Prefix[BUFLEN_48];   /**< New site prefix, if prefixAssigned==TRUE */
        uint32_t PrefixLength;
        uint32_t IA_ID;
        uint32_t PreferedLifeTime;
        uint32_t ValidLifeTime;
        uint32_t T1;
        uint32_t T2;
    }ia_pd;

    //DNS details
    struct {
        bool assigned;
        char nameserver[BUFLEN_128];  /**< New nameserver,   */
        char nameserver1[BUFLEN_128];  /**< New nameserver,   */
    } dns;

    //MAPT
    struct {
        bool Assigned;     /**< Have we been assigned mapt config ? */
        unsigned char  Container[BUFLEN_256]; /* MAP-T option 95 in hex format*/
    }mapt;
 
    #if 0
    //TODO: MAPE support not added yet
    struct {
        bool Assigned;     /**< Have we been assigned mape config ? */
        unsigned char  Container[BUFLEN_256]; /* MAP-E option 94 in hex format*/
    }mape;
    #endif

    char domainName[BUFLEN_64];  /**< New domain Name,   */
    char ntpserver[BUFLEN_128];  /**< New ntp server(s), dhcp server may provide this */
    char aftr[AFTR_NAME_LENGTH];      /**< dhcp server may provide this */

}DHCPv6_PLUGIN_MSG;

typedef enum {
    DHCP_VERSION_4,
    DHCP_VERSION_6,
} DHCP_SOURCE;

typedef struct {
    char ifname[BUFLEN_32];
    DHCP_SOURCE version;
    union {
        DHCPv4_PLUGIN_MSG dhcpv4;
        DHCPv6_PLUGIN_MSG dhcpv6;
    } data;
} PLUGIN_MSG;

/**
 * @brief Starts the DHCP Lease Monitor service.
 *
 * This function initializes and starts the DHCP Lease Monitor,
 * which listens for DHCP lease events and processes lease updates.
 *
 * @return ANSC_STATUS_SUCCESS on successful start, ANSC_STATUS_FAILURE otherwise.
 */
ANSC_STATUS DhcpMgr_LeaseMonitor_Start();

