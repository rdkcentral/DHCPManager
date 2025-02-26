#include "dhcpv4_interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

// Weak function implementations
__attribute__((weak)) pid_t start_dhcpv4_client(char *interfaceName, dhcp_option_list *req_opt_list, dhcp_option_list *send_opt_list) 
{
    (void)interfaceName;
    (void)req_opt_list;
    (void)send_opt_list;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of start_dhcpv4_client \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int send_dhcpv4_renew(pid_t processID) 
{
    (void)processID;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of send_dhcpv4_renew \n", __FUNCTION__, __LINE__);
    return -1;
}

__attribute__((weak)) int send_dhcpv4_release(pid_t processID) 
{
    (void)processID;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of send_dhcpv4_release \n", __FUNCTION__, __LINE__);
    return -1;

}

__attribute__((weak)) int stop_dhcpv4_client(pid_t processID) 
{
    (void)processID;
    DHCPMGR_LOG_INFO("%s %d Weak implementation of stop_dhcpv4_client \n", __FUNCTION__, __LINE__);
    return -1;
}
