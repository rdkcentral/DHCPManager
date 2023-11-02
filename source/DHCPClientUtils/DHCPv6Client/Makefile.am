#
# Copyright 2020 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#
noinst_LTLIBRARIES = libCcspDhcpMgr_Dhcpv6Client.la

AM_CFLAGS = -fno-exceptions -Os -Wall -Wextra

AM_CFLAGS += -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -D_CCSP_CWMP_TCP_CONNREQ_HANDLER
AM_CFLAGS += -D_ANSC_IPV6_COMPATIBLE_
AM_CFLAGS += -DBUILD_WEB
AM_LDFLAGS =
AM_LDFLAGS += -lhal_platform
AM_LDFLAGS += -lz

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

AM_LDFLAGS +=  -lpthread -lz -lccsp_common $(DBUS_LIBS)

libCcspDhcpMgr_Dhcpv6Client_la_CPPFLAGS = -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/dbus-1.0 \
                                          -I${PKG_CONFIG_SYSROOT_DIR}$(libdir)/dbus-1.0/include \
                                          -I$(top_srcdir)/source/DHCPClientUtils/DHCPv4Client/include \
                                          -I$(top_srcdir)/source/DHCPClientUtils/DHCPv6Client/include \
                                          -I$(top_srcdir)/source/DHCPServerUtils/utils \
                                          -I$(top_srcdir)/source/DHCPServerUtils/utils/include \
                                          -I$(top_srcdir)/source/DHCPMgrInterface \
                                          -I$(top_srcdir)/source/DHCPMgrInterface/include

libCcspDhcpMgr_Dhcpv6Client_la_SOURCES = service_dhcpv6_client.c dibbler_client_utils.c dhcpv6_client_utils.c

libCcspDhcpMgr_Dhcpv6Client_la_LIBADD = -lccsp_common -ltelemetry_msgsender -lulog -lsyscfg -lsysevent -ltime_conversion -lprint_uptime -lhal_platform -lnet
