#ifndef DHCPV4_INTERFACE_H
#define DHCPV4_INTERFACE_H

#include <sys/types.h>
#include "dhcp_option_list.h"
#include "util.h"


/**
 * @brief Interface API for starting the DHCPv4 client.
 *
 * This function creates the configuration file using the provided request and send option lists,
 * starts the DHCPv4 client, and collects the process ID (PID).
 *
 * @param[in] interfaceName The name of the network interface.
 * @param[in] req_opt_list Pointer to the list of requested DHCP options.
 * @param[in] send_opt_list Pointer to the list of options to be sent.
 * @return The process ID (PID) of the started DHCPv4 client.
 */
pid_t start_dhcpv4_client(char *interfaceName, dhcp_option_list *req_opt_list, dhcp_option_list *send_opt_list);

/**
 * @brief Interface API for triggering a renew from the DHCPv4 client.
 *
 * This function sends the respective signal to the DHCPv4 client application to trigger a renew.
 *
 * @param[in] processID The process ID (PID) of the DHCPv4 client.
 * @return 0 on success, -1 on failure.
 */
int send_dhcpv4_renew(pid_t processID);

/**
 * @brief Interface API for triggering a release from the DHCPv4 client.
 *
 * This function sends the respective signal to the DHCPv4 client application to trigger a release and terminate.
 *
 * @param[in] processID The process ID (PID) of the DHCPv4 client.
 * @return 0 on success, -1 on failure.
 */
int send_dhcpv4_release(pid_t processID);

/**
 * @brief Interface API for stopping the DHCPv4 client.
 *
 * This function sends the respective signal to the DHCPv4 client application to stop the client.
 *
 * @param[in] processID The process ID (PID) of the DHCPv4 client.
 * @return 0 on success, -1 on failure.
 */
int stop_dhcpv4_client(pid_t processID);

#endif // DHCPV4_INTERFACE_H
