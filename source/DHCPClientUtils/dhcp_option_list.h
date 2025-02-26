#ifndef DHCP_OPTION_LIST_H
#define DHCP_OPTION_LIST_H

/* DHCP options linked list */
typedef struct dhcp_option_list {
    int dhcp_opt;
    char *dhcp_opt_val;
    struct dhcp_option_list *next;
} dhcp_option_list;

#endif // DHCP_OPTION_LIST_H
