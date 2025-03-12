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
#ifndef DHCP_MSH_H
#define DHCP_MSH_H

#define BUFLEN_32                        32          //buffer length 32
#define BUFLEN_64                        64          //buffer length 64
#define BUFLEN_48                        48          //buffer length 48
#define BUFLEN_128                       128         //buffer length 128

typedef struct _DHCP_MGR_IPV4_MSG
{
    char ifname[BUFLEN_64]; 
    char address[BUFLEN_32];     
    char netmask[BUFLEN_32];   
    char gateway[BUFLEN_32];
    char dnsServer[BUFLEN_64];
    char dnsServer1[BUFLEN_64];
    char timeZone[BUFLEN_64];
    uint32_t mtuSize;          
    int32_t timeOffset;        
    bool isTimeOffsetAssigned; 
    uint32_t upstreamCurrRate; 
    uint32_t downstreamCurrRate;
} DHCP_MGR_IPV4_MSG;



typedef struct _DHCP_MGR_MAPT_DATA
{
   char brIPv6Prefix[BUFLEN_128];   /* MAP Border Relay  prefix*/
   char ruleIPv4Prefix[BUFLEN_32];  /*Rule IPv6 prefix:       An IPv6 prefix assigned by a service provider for a MAP Rule */
   char ruleIPv6Prefix[BUFLEN_128]; /* Rule IPv4 prefix:       An IPv4 prefix assigned by a service provider for a MAP Rule.*/
   char pdIPv6Prefix[BUFLEN_128];   /* Prefix Delegation */
   uint32_t iapdPrefixLen;          /* Prefix Delegation length */
   uint32_t eaLen;                  /* Embedded Address (EA) length */
   uint32_t psidOffset;             /* PSID offset */
   uint32_t psidLen;                /*Port Set ID (PSID) len */
   uint32_t psid;                   /*Port Set ID (PSID):     Algorithmically identifies a set of ports exclusively assigned to a CE.*/
   uint32_t ipv4Len;                /* IPv4 prefix length */
   uint32_t ipv6Len;                /* IPv6 prefix length */
   uint32_t ratio;                  /* sharing ratio */
   bool isFMR;                      /* is Forwarding Mapping Rule */
} DHCP_MGR_MAPT_DATA;



typedef struct _DHCP_MGR_IPV6_MSG
{
   char ifname[BUFLEN_32];			
   char address[BUFLEN_48];      
   char nameserver[BUFLEN_128];  
   char nameserver1[BUFLEN_128]; 
   char domainName[BUFLEN_64];  
   char sitePrefix[BUFLEN_48];  
   uint32_t prefixPltime; 		
   uint32_t prefixVltime;		
   bool addrAssigned;	
   bool prefixAssigned; 
   bool domainNameAssigned;   
   DHCP_MGR_MAPT_DATA mapInfo;
} DHCP_MGR_IPV6_MSG;

typedef enum {
    DHCP_CLIENT_STARTED,
    DHCP_CLIENT_STOPPED,
    DHCP_CLIENT_FAILED,
    DHCP_LEASE_UPDATE, // New lease or change in the Lease value
    DHCP_LEASE_DEL,    // Lease Expired, Released
    DHCP_LEASE_RENEW,  // Lease Renewed
} DHCP_MESSAGE_TYPE;

#endif //DHCP_MSH_H