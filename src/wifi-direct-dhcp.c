/*
 * Network Configuration Module
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 */

#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <glib.h>
#include <glib-object.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vconf.h>
#include <vconf-keys.h>

#include "wifi-direct.h"
#include "wifi-direct-client-handler.h"
#include "wifi-direct-internal.h"
#include "wifi-direct-service.h"
#include "wifi-direct-stub.h"
#include "wifi-direct-oem.h"

#if 0

#define IF_BUF_LEN		30
#define NET_BUF_LEN		10


#define DRIVER_DELAY	250000	/* micro seconds */

#define SOFTAP_SSID_LEN		32
#define SOFTAP_PASSWD_LEN	64
#define SOFTAP_IP_ADDR_LEN	20
#define SOFTAP_STR_BSSID_LEN	18
#define INTERFACE_NAME_LEN	10

/* Network Interface */
#define WIFID_IF  "wl0.1"

#define IP_ADDRESS_SOFTAP	"192.168.61.1"

#define RET_FAILURE     (-1)
#define RET_SUCCESS     (0)
#define MAX_BUF_SIZE    (256u)
#define WFD_BSSID_LEN   32
#define MOBILE_AP_WIFI_MAX_DEVICE 8
#define DNSMASQ_CONF_LEN	1024

#define DNSMASQ_CONF	"dhcp-range=set:red,192.168.61.21,192.168.61.150\n" \
			"dhcp-range=set:green,192.168.130.2,192.168.130.150\n" \
			"dhcp-range=set:blue,192.168.129.4,192.168.129.150\n"\
			"dhcp-option=option:dns-server,%s\n" \
			"dhcp-option=tag:red,option:router,192.168.61.1\n" \
			"dhcp-option=tag:green,option:router,192.168.130.1\n" \
			"dhcp-option=tag:blue,option:router,192.168.129.3\n"


#define DNSMASQ_CONF_FILE	"/tmp/dnsmasq.conf"
#define RESOLV_CONF_FILE	"/etc/resolv.conf"

#define DNSMASQ_LEASES_FILE	"/var/lib/misc/dnsmasq.leasess"


typedef struct
{
	unsigned int number;		/* Number of connected device */
	/* BSSID list of connected device */
	char bssid[MOBILE_AP_WIFI_MAX_DEVICE][WFD_BSSID_LEN];
} softap_device_info_t;


static int __issue_ioctl(int sock_fd, char *if_name, char *cmd, char *buf)
{
	int ret_val = RET_SUCCESS;
	struct iwreq iwr;

	memset(buf, 0, MAX_BUF_SIZE);
	memset(&iwr, 0, sizeof(iwr));

	/* Configure ioctl parameters */
	g_strlcpy(iwr.ifr_name, if_name, IFNAMSIZ);
	g_strlcpy(buf, cmd, MAX_BUF_SIZE);
	iwr.u.data.pointer = buf;
	iwr.u.data.length = MAX_BUF_SIZE;

	/* Print the command buffer. */
	//MH_AGENT_LOG (MH_LOW, "iwr.u.data.length = %d\n", iwr.u.data.length);
	//__print_buf (iwr.u.data.pointer, iwr.u.data.length, 16);

	usleep(DRIVER_DELAY);
	/* Issue ioctl */
	if ((ioctl(sock_fd, SIOCSIWPRIV, &iwr)) < 0)
	{
		WDS_LOGF( "ioctl failed...!!!\n");
		ret_val = RET_FAILURE;
	}

	/* Print the return buffer. */
	//MH_AGENT_LOG (MH_LOW, "iwr.u.data.length = %d\n", iwr.u.data.length);
	//__print_buf (iwr.u.data.pointer, iwr.u.data.length, 16);

	return ret_val;
}


int _wfd_core_set_ip_address(const char *if_name, const char *ip_address)
{
	struct ifreq ifr;
	struct sockaddr_in addr;
	int sock_fd;

	WDS_LOGD( "if_name : %s ip address :%s\n", if_name, ip_address);

	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		WDS_LOGF( "socket open failed!!!\n");
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}

	g_strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);

	memset(&addr, 0, sizeof(struct sockaddr));
	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = inet_addr(ip_address);

	memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));
	if (ioctl(sock_fd, SIOCSIFADDR, &ifr) < 0)
	{
		WDS_LOGF( "ioctl failed...!!!\n");
		close(sock_fd);
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0)
	{
		WDS_LOGF( "ioctl failed...!!!\n");
		close(sock_fd);
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0)
	{
		WDS_LOGF( "ioctl failed...!!!\n");
		close(sock_fd);
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	close(sock_fd);

	return WIFI_DIRECT_ERROR_NONE;
}


int _mh_core_get_device_info(softap_device_info_t * di)
{
	int sock_fd;
	char *if_name = WIFID_IF;
	char cmd[MAX_BUF_SIZE];
	char buf[MAX_BUF_SIZE] = { 0 };
	int ret_status = WIFI_DIRECT_ERROR_NONE;

	char *buf_ptr = NULL;
	unsigned int sta_count = 0;
	int i;

	WDS_LOGF( "+\n");

	if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		WDS_LOGF( "Failed to open socket...!!!\n");
		di->number = 0;
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}

	snprintf(cmd, MAX_BUF_SIZE, "AP_GET_STA_LIST");
	ret_status = __issue_ioctl(sock_fd, if_name, cmd, buf);
	if (ret_status < 0)
	{
		WDS_LOGF( "__issue_ioctl failed...!!!\n");
		di->number = 0;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	buf_ptr = buf;

	sscanf(buf_ptr, "%02x", &sta_count);
	buf_ptr += 2;
	WDS_LOGF( "connected station : %d\n", sta_count);

	di->number = sta_count;

	for (i = 0; i < di->number; i++)
	{
		unsigned int l_bssid[WFD_BSSID_LEN];
		sscanf(buf_ptr, "%02X%02X%02X%02X%02X%02X", &l_bssid[0],
			   &l_bssid[1], &l_bssid[2], &l_bssid[3], &l_bssid[4], &l_bssid[5]);
		snprintf(di->bssid[i], WFD_BSSID_LEN,
				 "%02X:%02X:%02X:%02X:%02X:%02X",
				 l_bssid[0], l_bssid[1], l_bssid[2],
				 l_bssid[3], l_bssid[4], l_bssid[5]);

		WDS_LOGF( "STA[%d] address[%s]\n", i,
					   di->bssid[i]);

		buf_ptr += 12;
	}

	close(sock_fd);

	return ret_status;
}

int _mh_core_execute_dhcp_server()
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	char buf[DNSMASQ_CONF_LEN] = "";
	char dns_server[SOFTAP_IP_ADDR_LEN] = { 0, };
	FILE *fp = NULL;
	pid_t pid;

	snprintf(buf, DNSMASQ_CONF_LEN, DNSMASQ_CONF, dns_server);

	fp = fopen(DNSMASQ_CONF_FILE, "w");
	if (NULL == fp)
	{
		WDS_LOGF( "Could not create the file.\n");
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}

	fputs(buf, fp);
	fclose(fp);

	if ((pid = fork()) < 0)
	{
		WDS_LOGF( "fork failed\n");
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}

	if (!pid)
	{
		if (execl("/usr/bin/dnsmasq", "/usr/bin/dnsmasq", "-d", "-p",
				  "0", "-C", DNSMASQ_CONF_FILE, (char *) NULL))
		{
			WDS_LOGF( "execl failed\n");
		}

		WDS_LOGF( "Should not get here!");
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}
	else
	{
		WDS_LOGF( "child pid : %d\n", pid);
		wfd_server->dhcp_pid = pid;
	}

	return WIFI_DIRECT_ERROR_NONE;
}

int _mh_core_terminate_dhcp_server()
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	kill(wfd_server->dhcp_pid, SIGTERM);
	waitpid(wfd_server->dhcp_pid, NULL, 0);

	return WIFI_DIRECT_ERROR_NONE;
}
#endif

#define VCONFKEY_DHCP_IP_LEASE "memory/private/wifi_direct_manager/dhcp_ip_lease"
#define DHCP_DUMP_FILE "/tmp/dhcp-client-table"
#define MAX_DHCP_DUMP_SIZE 64    // Single lease format: [99:66:dd:00:11:aa 192.168.16.20 00:00:60]

void __wfd_DHCP_lease_add_cb(keynode_t *key, void* data)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	wifi_direct_client_noti_s noti;
	FILE *fp = NULL;
	char buf[MAX_DHCP_DUMP_SIZE];
	char ip_str[20];
	char mac_str[20];
	unsigned char mac_hex[6];
	int n = 0;
	int i = 0;

	WDS_LOGD( "DHCP: IP is leased..\n");
	memset(&noti, 0, sizeof(wifi_direct_client_noti_s));

	if (wfd_oem_is_groupowner() == FALSE)
	{
		WDS_LOGD( "DHCP: Ignore event. and Kill DHPC server\n");
		system("wifi-direct-dhcp.sh stop");
		return;
	}

	fp = fopen(DHCP_DUMP_FILE, "r");
	if (NULL == fp)
	{
		WDS_LOGF( "Could not read the file [%s].\n",DHCP_DUMP_FILE);
		return;
	}

    while(fgets(buf, MAX_DHCP_DUMP_SIZE, fp) != NULL)
    {
        n = sscanf(buf,"%s %s", mac_str, ip_str);
    	WDS_LOGE( "ip=[%s], mac=[%s].\n",ip_str, mac_str);
        if (n != 2)
        {
        	continue;
        }
        wfd_macaddr_atoe(mac_str, mac_hex);
        for(i=0; i<WFD_MAX_ASSOC_STA; i++)
        {

        	if (wfd_server->connected_peers[i].isUsed == 1 &&
        			memcmp(mac_hex, wfd_server->connected_peers[i].int_address, 6) == 0)
        	{
			WDS_LOGD( "Found peer: interface mac=[%s].\n",mac_str);
			WDS_LOGD( "device mac=["MACSTR"]\n",MAC2STR(wfd_server->connected_peers[i].peer.mac_address));

			inet_aton(ip_str, (struct in_addr*)&wfd_server->connected_peers[i].ip_address);
			WDS_LOGD( "Fill IP: ip=[%s].\n",ip_str);

			//Send event to client with [dev_mac, ip]
			noti.event = WIFI_DIRECT_CLI_EVENT_IP_LEASED_IND;
			snprintf(noti.param1, 64, MACSTR, MAC2STR(wfd_server->connected_peers[i].peer.mac_address));
			snprintf(noti.param2, 64, "%s", ip_str);
			__wfd_server_send_client_event(&noti);
        		break;
        	}
        }
        if (i==WFD_MAX_ASSOC_STA)
        	WDS_LOGE( "Can't find peer from table\n");

        __wfd_server_print_connected_peer();
    }
	fclose(fp);

	__WDS_LOG_FUNC_EXIT__;
}


#define VCONFKEY_DHCPC_SERVER_IP "memory/private/wifi_direct_manager/dhcpc_server_ip"
int wfd_get_dhcpc_server_ip(char* str, int len)
{
	__WDS_LOG_FUNC_ENTER__;

	char* get_str = NULL;
	if (str==NULL || len <=0)
		return -1;

	get_str = vconf_get_str(VCONFKEY_DHCPC_SERVER_IP);

	if (get_str == NULL)
	{
		WDS_LOGE( "Error reading vconf (%s)\n", VCONFKEY_DHCPC_SERVER_IP);
		return -1;
	}
	else
	{
		WDS_LOGD("VCONFKEY_WIFI_STATE(%s) : %d\n", VCONFKEY_DHCPC_SERVER_IP, get_str);
		snprintf(str, len, get_str);
		return 0;
	}

	__WDS_LOG_FUNC_EXIT__;

	return 0;

}


int wfd_set_DHCP_event_handler()
{
	__WDS_LOG_FUNC_ENTER__;


	vconf_set_int(VCONFKEY_DHCP_IP_LEASE, 0);
	vconf_notify_key_changed(VCONFKEY_DHCP_IP_LEASE, __wfd_DHCP_lease_add_cb, NULL);

	__WDS_LOG_FUNC_EXIT__;
	
	return 0;
}


