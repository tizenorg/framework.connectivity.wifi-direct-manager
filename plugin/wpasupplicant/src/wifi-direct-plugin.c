/**
 * Copyright (c) 2000~2008 Samsung Electronics, Inc.
 * All rights reserved.
 *
 * This software is a confidential and proprietary information
 * of Samsung Electronics, Inc. ("Confidential Information").  You
 * shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement
 * you entered into with Samsung Electronics.
 */
/**
 * This file implements wifi direct oem functions.
 *
 * @file    wifi-direct-oem.c
 * @author  Sungsik Jang <sungsik.jang@samsung.com>
 * @author  Dongwook Lee <dwmax.lee@samsung.com>
 * @version 0.1
 */

#include <stdlib.h>
#include <stdbool.h>
#include <glib.h>
#include <glib-object.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "wifi-direct-utils.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-service.h"
#include "wifi-direct-wpasupplicant.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

int g_global_sockfd;
int g_control_sockfd;
int g_monitor_sockfd;
int g_source_id;

static char g_local_interface_ip_address[20];
static wfd_noti_cb g_noti_cb;
wfd_oem_event_cb g_oem_event_callback;
int g_oem_pipe[2];
GList *g_conn_peer_addr;
static unsigned char g_assoc_sta_mac[6];
static unsigned char g_disassoc_sta_mac[6];

static struct wfd_oem_operations supplicant_ops =
{
	.wfd_oem_init = wfd_ws_init,
	.wfd_oem_destroy = wfd_ws_destroy,
	.wfd_oem_activate = wfd_ws_activate,
	.wfd_oem_deactivate = wfd_ws_deactivate,
	.wfd_oem_connect = wfd_ws_connect,
	.wfd_oem_wps_pbc_start = wfd_ws_wps_pbc_start,
	.wfd_oem_disconnect = wfd_ws_disconnect,
	.wfd_oem_disconnect_sta = wfd_ws_disconnect_sta,
	.wfd_oem_is_discovery_enabled = wfd_ws_is_discovery_enabled,
	.wfd_oem_start_discovery = wfd_ws_start_discovery,
	.wfd_oem_cancel_discovery = wfd_ws_cancel_discovery,
	.wfd_oem_get_discovery_result = wfd_ws_get_discovery_result,
	.wfd_oem_get_peer_info = wfd_ws_get_peer_info,
	.wfd_oem_send_provision_discovery_request = wfd_ws_send_provision_discovery_request,
	.wfd_oem_send_invite_request = wfd_ws_send_invite_request,
	.wfd_oem_create_group = wfd_ws_create_group,
	.wfd_oem_cancel_group = wfd_ws_cancel_group,
	.wfd_oem_activate_pushbutton = wfd_ws_activate_pushbutton,
	.wfd_oem_get_default_interface_name = wfd_ws_get_default_interface_name,
	.wfd_oem_dhcpc_get_ip_address = wfd_ws_dhcpc_get_ip_address,
	.wfd_oem_get_ip = wfd_ws_get_ip,
	.wfd_oem_set_ssid = wfd_ws_set_ssid,
	.wfd_oem_is_groupowner = wfd_ws_is_groupowner,
	.wfd_oem_get_ssid = wfd_ws_get_ssid,
	.wfd_oem_set_wps_pin = wfd_ws_set_wps_pin,
	.wfd_oem_get_wps_pin = wfd_ws_get_wps_pin,
	.wfd_oem_generate_wps_pin = wfd_ws_generate_wps_pin,
	.wfd_oem_set_wpa_passphrase = wfd_ws_set_wpa_passphrase,
	.wfd_oem_get_supported_wps_mode = wfd_ws_get_supported_wps_mode,
	.wfd_oem_get_connected_peers_info = wfd_ws_get_connected_peers_info,
	.wfd_oem_get_connected_peers_count = wfd_ws_get_connected_peers_count,
	.wfd_oem_set_oem_loglevel = wfd_ws_set_oem_loglevel,
	.wfd_oem_get_go_intent = wfd_ws_get_go_intent,
	.wfd_oem_set_go_intent = wfd_ws_set_go_intent,
	.wfd_oem_set_device_type = wfd_ws_set_device_type,
	.wfd_oem_get_device_mac_address = wfd_ws_get_device_mac_address,
	.wfd_oem_get_disassoc_sta_mac = wfd_ws_get_disassoc_sta_mac,
	.wfd_oem_get_assoc_sta_mac = wfd_ws_get_assoc_sta_mac,
	.wfd_oem_get_requestor_mac = wfd_ws_get_requestor_mac,
	.wfd_oem_get_operating_channel = wfd_ws_get_operating_channel,
	.wfd_oem_get_persistent_group_info = wfd_ws_get_persistent_group_info,
	.wfd_oem_remove_persistent_group = wfd_ws_remove_persistent_group,
};

int wfd_plugin_load( struct wfd_oem_operations **ops)
{
	*ops = &supplicant_ops;

	return true;
}

static gboolean __wfd_oem_thread_safe_event_handler_cb(GIOChannel* source, GIOCondition condition, gpointer data)
{
	wfd_event_t event;
	int n = 0;

	// Read header part
	n = read(g_oem_pipe[0], &event, sizeof(event));
	if (n < 0)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "pipe read error, Error=[%s]\n",strerror(errno));
		return 0;  // false
	}

	if (g_oem_event_callback != NULL)
		g_oem_event_callback(event);

	return true;
}

int __send_wpa_request(int sockfd, char *cmd, char *reply, size_t reply_buf_len)
{
	__WFD_SERVER_FUNC_ENTER__;
 
	int result = 0;
	size_t cmd_len;

	int pollret = 0;
	struct pollfd pollfd;
	int timeout = 6000; /** for 6.0 sec */

	if (sockfd <=0 )
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR,"Invalid argument sfd=[%d]\n", sockfd);
		return false;
	}

	if(cmd == NULL)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR,"Invalid argument. Command is NULL\n");
		return false;
	}
	cmd_len = strlen(cmd);
	WFD_SERVER_LOG(WFD_LOG_HIGH,"cmd [%s] cmd_len[%d]\n", cmd, cmd_len);

	result = write(sockfd, cmd, cmd_len);
	if ( result < 0)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Send cmd failed: [%d]\n", result);
		__WFD_SERVER_FUNC_EXIT__;
		return false;
	}

	for (;;)
	{
		pollfd.fd = sockfd;
		pollfd.events = POLLIN | POLLERR | POLLHUP;
		pollret = poll(&pollfd, 1, timeout);

		if (pollret == 0)
		{
			WFD_SERVER_LOG(WFD_LOG_HIGH, "POLLing timeout. Nothing to read.\n");
			__WFD_SERVER_FUNC_EXIT__;
			return 0;
		}
		else if (pollret < 0)
		{
			WFD_SERVER_LOG( WFD_LOG_ERROR,"Polling error [%d]\n", pollret);
			__WFD_SERVER_FUNC_EXIT__;
			return false;
		}
		else
		{
			if (pollfd.revents == POLLIN)
			{
				WFD_SERVER_LOG(WFD_LOG_LOW,"POLLIN \n");
				result = read(sockfd, (char *) reply, reply_buf_len);
				
				WFD_SERVER_LOG(WFD_LOG_LOW,"sockfd %d retval %d\n", sockfd, result);
				WFD_SERVER_LOG(WFD_LOG_LOW,"reply[%s]\n", reply);
				
				if (result < 0)
				{
					WFD_SERVER_LOG(WFD_LOG_ERROR, "Error!!! reading data, error [%s]\n", strerror(errno));
					__WFD_SERVER_FUNC_EXIT__;
					return false;
				}
				break;
			}
			else
			{
				WFD_SERVER_LOG(WFD_LOG_LOW,"POLL EVENT=%d ignored\n", pollfd.revents);
				__WFD_SERVER_FUNC_EXIT__;
				return false;
			}
		}
	}

	__WFD_SERVER_FUNC_EXIT__;
	return result;
}


int __create_ctrl_intf(char *ctrl_intf_name, char *path)
{
	__WFD_SERVER_FUNC_ENTER__;

	struct sockaddr_un servAddr;
	struct sockaddr_un localAddr;
	char local_path[32] = {0, };
	int sockfd = 0;
	int len = 0;
	int ret = 0;

	snprintf(local_path, sizeof(local_path), "/tmp/%s", ctrl_intf_name);
	unlink(local_path);

	errno = 0;
	if ((sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Error!!! creating sync socket. Error = [%s].\n", strerror(errno));
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	WFD_SERVER_LOG(WFD_LOG_HIGH, "Created socket [%d]\n", sockfd);

	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sun_family = AF_UNIX;
	strcpy(servAddr.sun_path, path);
	len = sizeof(servAddr.sun_family) + strlen(path);

	WFD_SERVER_LOG(WFD_LOG_LOW, "Connecting to server socket to register socket [%d]\n", sockfd);

	memset(&localAddr, 0, sizeof(localAddr));
	localAddr.sun_family = AF_UNIX;
	strcpy(localAddr.sun_path, local_path);

	if (bind(sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!!! bind(). Error = [%s]. Try again..\n", strerror(errno));
		
		unlink(localAddr.sun_path);
		if (bind(sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0)
		{
			WFD_SERVER_LOG( WFD_LOG_ERROR, "Error!!! bind(). Error = [%s]. Give up..\n", strerror(errno));
			__WFD_SERVER_FUNC_EXIT__;
			return -1;
		}
	}

	errno = 0;
	if ((ret = connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr))) < 0)
	{

		if (unlink(path) < 0)
		{
			WFD_SERVER_LOG(WFD_LOG_ERROR, "unlink[ctrl_iface], Error=[%s]\n", strerror(errno));
			__WFD_SERVER_FUNC_EXIT__;
			return -1;
		}

		if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0)
		{
			WFD_SERVER_LOG(WFD_LOG_ERROR, "bind[PF_UNIX], Error=[%s]\n", strerror(errno));
			__WFD_SERVER_FUNC_EXIT__;
			return -1;
		}
		WFD_SERVER_LOG(WFD_LOG_HIGH, "Successfully replaced leftover ctrl_iface socket [%s]\n", path);
	}

	__WFD_SERVER_FUNC_EXIT__;

	return sockfd;
}


static int __read_socket_cb(int sockfd, char *dataptr, int datalen)
{
	__WFD_SERVER_FUNC_ENTER__;

	int pollret = 0;
	struct pollfd pollfd;
	int timeout = 2000; /** for 2 sec */
	int retval = 0;

	WFD_SERVER_LOG(WFD_LOG_LOW, "Reading msg from socketfd=[%d]\n", sockfd);

	if (sockfd <= 0)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Error!!! Invalid socket FD [%d]\n", sockfd);
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	if ((dataptr == NULL) || (datalen <= 0))
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Error!!! Invalid parameter\n");
		__WFD_SERVER_FUNC_EXIT__;

		return -1;
	}

	//printf("@@@@@@@ len = %d  @@@@@@@@@@@\n", datalen);

	pollfd.fd = sockfd;
	pollfd.events = POLLIN | POLLERR | POLLHUP;
	pollret = poll(&pollfd, 1, timeout);

	//printf("POLL ret = %d,  \n", pollret);

	if (pollret > 0)
	{
		if (pollfd.revents == POLLIN)
		{
			WFD_SERVER_LOG(WFD_LOG_LOW, "POLLIN\n");

			errno = 0;
			retval = read(sockfd, (char *) dataptr, datalen);
			WFD_SERVER_LOG(WFD_LOG_LOW, "sockfd %d retval %d\n", sockfd, retval);
			if (retval <= 0)
			{
				WFD_SERVER_LOG(WFD_LOG_LOW, "Error!!! reading data, Error=[%s]\n", strerror(errno));
			}
			__WFD_SERVER_FUNC_EXIT__;
			return retval;
		}
		else if (pollfd.revents & POLLHUP)
		{
			WFD_SERVER_LOG(WFD_LOG_LOW, "POLLHUP\n");
			__WFD_SERVER_FUNC_EXIT__;

			return 0;
		}
		else if (pollfd.revents & POLLERR)
		{
			WFD_SERVER_LOG(WFD_LOG_LOW, "POLLERR\n");
			__WFD_SERVER_FUNC_EXIT__;
			return 0;
		}
	}
	else if (pollret == 0)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "POLLing timeout  \n");
		__WFD_SERVER_FUNC_EXIT__;
		return 0;
	}
	else
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "Polling unknown error \n");
		__WFD_SERVER_FUNC_EXIT__;
		return -1;
	}

	__WFD_SERVER_FUNC_EXIT__;
	return 1;
}


void __polling_ip(char *ipaddr_buf, int len, int is_IPv6)
{
	int i = 0;

	while(i < 24) {
		if (wfd_ws_dhcpc_get_ip_address(ipaddr_buf, len, is_IPv6) == true)
		{
			return;
		}
		usleep(250);
		i++;
	}
	WFD_SERVER_LOG(WFD_LOG_ERROR, "** Failed to get IP address!!\n");
}

char* __get_event_str(char*ptr, char* event_str)
{
	char* p = ptr;
	int c = 0;

	event_str[0] = '\0';

	if (p==NULL)
		return NULL;

	while(*p != '\n')
	{
		if (*p == '\0')
		{
			event_str[c] = '\0';
			return NULL;
		}

		if (*p == ' ')
			break;

		event_str[c++] = *p++;
	}
	event_str[c]='\0';
	p++;

	return p;
}

int __extract_value_str(char *str, char *key, char *value)
{
	__WFD_SERVER_FUNC_ENTER__;
	char *tmp_str = NULL;
	int i = 0;

	if(value == NULL)
		return -1;
	
	tmp_str = strstr(str, key);
	if(tmp_str == NULL)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Key[%s] is not found\n", key);
		return -1;
	}
	tmp_str = tmp_str + strlen(key) + 1;
	//WFD_SERVER_LOG(WFD_LOG_LOW, "tmp_str [%s]\n", tmp_str);

	for(i = 0; tmp_str[i]; i++)
	{
		if(tmp_str[i] == '\n' || tmp_str[i] == '\r' || tmp_str[i] == ' ')
		{
			break;
		}
	}

	memcpy(value, tmp_str, i);
	value[i] = '\0';

	WFD_SERVER_LOG(WFD_LOG_LOW, "extracted value [%s]\n", value);

	__WFD_SERVER_FUNC_EXIT__;
	return i;
}


int __is_white_space(char c)
{
	if (c < 32)
		return 1;

	return 0;
}

int __is_item_char(char c)
{
	if (c >= 'a' && c <= 'z')
		return 1;

	if (c >= 'A' && c <= 'Z')
		return 1;

	if (c >= '0' && c <= '9')
		return 1;

	if (c=='_')
		return 1;

	if (c=='-')
		return 1;

	if (c==':')
		return 1;

	if (c=='[')
		return 1;

	if (c==']')
		return 1;

	return 0;
}


char* __get_item_value(char*ptr, char* item, char* value)
{
	char* p = ptr;
	int c = 0;

	item[0] = '\0';
	value[0]='\0';

	if (p==NULL)
		return NULL;

	while(*p != '=')
	{
		if (*p == '\n')
		{
			item[c] = '\0';
			return ++p;
		}
		if (*p == '\0')
		{
			item[c] = '\0';
			return NULL;
		}
		if (__is_white_space(*p) || !__is_item_char(*p))
			p++;
		else
			item[c++] = *p++;
	}
	item[c]='\0';
	p++;

	c=0;
	while(*p != '\n')
	{
		if (*p == '\0')
		{
			value[c] = '\0';
			return NULL;
		}
		if (__is_white_space(*p))
			p++;
		else
			value[c++] = *p++;
	}
	value[c]='\0';
	p++;

	return p;
}


char* __get_persistent_group_value(char*ptr, ws_network_info_s* group)
{
	char* p = ptr;
	int c;
	char value[128];

	if (p==NULL)
		return NULL;

	/* network_id */
	c = 0;
	memset(value, 0, sizeof(value));
	while(__is_item_char(*p))
	{
		value[c++] = *p++;
	}
	group->network_id = atoi(value);

	while(!__is_item_char(*p))
	{
		p++;
	}

	/* ssid */
	c = 0;
	memset(value, 0, sizeof(value));
	while(__is_item_char(*p))
	{
		value[c++] = *p++;
	}
	strncpy(group->ssid, value, sizeof(group->ssid));

	while(!__is_item_char(*p))
	{
		p++;
	}

	/* bssid */
	c = 0;
	memset(value, 0, sizeof(value));
	while(__is_item_char(*p))
	{
		value[c++] = *p++;
	}
	strncpy(group->bssid, value, sizeof(group->bssid));
	
	while(!__is_item_char(*p))
	{
		p++;
	}

	/* flags */
	c = 0;
	memset(value, 0, sizeof(value));
	while(*p != '\n')
	{
		value[c++] = *p++;
	}
	strncpy(group->flags, value, sizeof(group->flags));

	p++;
	return p;
}


int __parsing_peer(char* buf, ws_discovered_peer_info_s* peer)
{
	__WFD_SERVER_FUNC_ENTER__;

	char* ptr = buf;
	char item[64];
	char value[128];
	int i;
	int item_id;

	memset(peer, 0, sizeof(ws_discovered_peer_info_s));

	// Get mac address
	strncpy(peer->mac, ptr, 17);
	peer->mac[18]='\0';
	ptr += 17+1;

	WFD_SERVER_LOG(WFD_LOG_LOW, "mac=%s\n", peer->mac);

	for(;;)
	{
		ptr = __get_item_value(ptr, item, value);
		if (ptr==NULL)
			break;

		//printf("item=%s, value=%s\n", item,value);

		i=0;
		item_id = WS_PEER_INFO_NONE;
		while(g_ws_field_info[i].item_id != WS_PEER_INFO_NONE)
		{
			if (strcmp(g_ws_field_info[i].item_str, item)==0)
			{
				item_id = g_ws_field_info[i].item_id;
				break;
			}
			i++;
		}

		switch(item_id)
		{
		case WS_PEER_INFO_AGE:
			peer->age = atoi(value);
			break;
		case WS_PEER_INFO_LISTEN_FREQ:
			peer->listen_freq = atoi(value);
			break;
		case WS_PEER_INFO_LEVEL:
			peer->level = atoi(value);
			break;
		case WS_PEER_INFO_WPS_METHOD:
			strncpy(peer->wps_method, value, sizeof(peer->wps_method));
			break;
		case WS_PEER_INFO_INTERFACE_ADDR:
			strncpy(peer->interface_addr, value, sizeof(peer->interface_addr));
			break;
		case WS_PEER_INFO_MEMBER_IN_GO_DEV:
			strncpy(peer->member_in_go_dev, value, sizeof(peer->member_in_go_dev));
			break;
		case WS_PEER_INFO_MEMBER_IN_GO_IFACE:
			strncpy(peer->member_in_go_iface, value, sizeof(peer->member_in_go_iface));
			break;
		case WS_PEER_INFO_PRI_DEV_TYPE:
			strncpy(peer->pri_dev_type, value, sizeof(peer->pri_dev_type));
			break;
		case WS_PEER_INFO_DEVICE_NAME:
			strncpy(peer->device_name, value, sizeof(peer->device_name));
			break;
		case WS_PEER_INFO_MANUFACTURER:
			strncpy(peer->manufacturer, value, sizeof(peer->manufacturer));
			break;
		case WS_PEER_INFO_MODEL_NAME:
			strncpy(peer->model_name, value, sizeof(peer->model_name));
			break;
		case WS_PEER_INFO_MODEL_NUMBER:
			strncpy(peer->model_number, value, sizeof(peer->model_number));
			break;
		case WS_PEER_INFO_SERIAL_NUMBER:
			strncpy(peer->serial_number, value, sizeof(peer->serial_number));
			break;
		case WS_PEER_INFO_CONFIG_METHODS:
			{
				char* p = value;
				unsigned long int ret = 0;
				ret = strtoul(p, &p, 16);
				if (ret == ULONG_MAX)
				{
					peer->config_methods = 0;
					WFD_SERVER_LOG(WFD_LOG_ERROR, "config_methods has wrong value=[%s], Error=[%s]\n", value, strerror(errno));
				}
				else
				{
					peer->config_methods = (unsigned int)ret;
					WFD_SERVER_LOG(WFD_LOG_LOW, "config_methods value=[%x <- %s]\n", peer->config_methods, value);
				}
			}
			break;
		case WS_PEER_INFO_DEV_CAPAB:
			{
				char* p = value;
				unsigned long int ret = 0;
				ret = strtoul(p, &p, 16);
				if (ret == ULONG_MAX)
				{
					peer->dev_capab = 0;
					WFD_SERVER_LOG(WFD_LOG_ERROR, "device_capab has wrong value=[%s], Error=[%s]\n", value, strerror(errno));
				}
				else
				{
					peer->dev_capab = (unsigned int)ret;
					WFD_SERVER_LOG(WFD_LOG_LOW, "device_capab value=[%x <- %s]\n", peer->dev_capab, value);
				}
			}
			break;
		case WS_PEER_INFO_GROUP_CAPAB:
			{
				char* p = value;
				unsigned long int ret = 0;
				ret = strtoul(p, &p, 16);
				if (ret == ULONG_MAX)
				{
					peer->group_capab = 0;
					WFD_SERVER_LOG(WFD_LOG_ERROR, "group_capab has wrong value=[%s], Error=[%s]\n", value, strerror(errno));
				}
				else
				{
					peer->group_capab = (unsigned int)ret;
					WFD_SERVER_LOG(WFD_LOG_LOW, "group_capab value=[%x <- %s]\n", peer->group_capab, value);
				}
			}
			break;
		case WS_PEER_INFO_GO_NEG_REQ_SENT:
			peer->go_neg_req_sent = atoi(value);
			break;
		case WS_PEER_INFO_GO_STATE:
			strncpy(peer->go_state, value, sizeof(peer->go_state));
			break;
		case WS_PEER_INFO_DIALOG_TOKEN:
			peer->dialog_token = atoi(value);
			break;
		case WS_PEER_INFO_INTENDED_ADDR:
			strncpy(peer->intended_addr, value, sizeof(peer->intended_addr));
			break;
		case WS_PEER_INFO_COUNTRY:
			strncpy(peer->country, value, sizeof(peer->country));
			break;
		case WS_PEER_INFO_OPER_FREQ:
			peer->oper_freq = atoi(value);
			break;
		case WS_PEER_INFO_REQ_CONFIG_METHODS:
			peer->req_config_methods = atoi(value);
			break;
		case WS_PEER_INFO_FLAGS:
			strncpy(peer->flags, value, sizeof(peer->flags));
			break;
		case WS_PEER_INFO_STATUS:
			strncpy(peer->status, value, sizeof(peer->status));
			break;
		case WS_PEER_INFO_WAIT_COUNT:
			peer->wait_count = atoi(value);
			break;
		case WS_PEER_INFO_INVITATION_REQS:
			peer->invitation_reqs = atoi(value);
			break;
		case WS_PEER_INFO_OPER_SSID:
			strncpy(peer->oper_ssid, value, sizeof(peer->oper_ssid));
			break;

/*----- Miracast -----*/
		case WS_PEER_INFO_IS_WFD_DEVICE:
			peer->is_wfd_device = atoi(value);
			break;

 		default:
			WFD_SERVER_LOG(WFD_LOG_LOW, "unknown field\n");
			break;
		}
	}

 	__WFD_SERVER_FUNC_EXIT__;

	return 0;
	
}


int __parsing_persistent_group(char* buf, ws_network_info_s ws_persistent_group_list[], int* persistent_group_num)
{
	__WFD_SERVER_FUNC_ENTER__;

	char* ptr = buf;
	ws_network_info_s group;
	int count;
	int i;

	memset(&group, 0, sizeof(ws_network_info_s));


	// Passing first line : "network id / ssid / bssid / flags"
	while (*ptr != '\n')
	{
		ptr++;
	}
	ptr++;

	count = 0;
	while(*ptr != '\0')
	{
		ptr = __get_persistent_group_value(ptr, &group);

		ws_persistent_group_list[count].network_id = group.network_id;
		strncpy(ws_persistent_group_list[count].ssid, group.ssid, sizeof(ws_persistent_group_list[count].ssid));
		strncpy(ws_persistent_group_list[count].bssid, group.bssid, sizeof(ws_persistent_group_list[count].bssid));
		strncpy(ws_persistent_group_list[count].flags, group.flags, sizeof(ws_persistent_group_list[count].flags));
		count++;
	}

	*persistent_group_num = count;

 	__WFD_SERVER_FUNC_EXIT__;
	return 0;
	
}

void __parsing_ws_event(char* buf, ws_event_s *event)
{
	__WFD_SERVER_FUNC_ENTER__;

	char* ptr = buf;
	char event_str[64];
	int i;
	ws_field_id_e event_id;
	int res = 0;

	if (NULL == buf)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "ERROR : buf is NULL!!\n");
		return;
	}

	ptr = ptr +3;
	ptr = __get_event_str(ptr, event_str);

	if (NULL != event_str)
		WFD_SERVER_LOG(WFD_LOG_LOW, "event str [%s]\n", event_str);

	i=0;
	event_id = WS_EVENT_NONE;
	while(g_ws_event_info[i].id != WS_EVENT_NONE)
	{
		if (strcmp(g_ws_event_info[i].str, event_str)==0)
		{
			event_id = g_ws_event_info[i].id;
			break;
		}
		i++;
	}

	switch(event_id)
	{
		memset(event, 0, sizeof(ws_event_s));
		
		case WS_EVENT_DISCOVER_FOUND_PEER:
			event->id = WS_EVENT_DISCOVER_FOUND_PEER;
			WFD_SERVER_LOG(WFD_LOG_LOW, "WS EVENT : [WS_EVENT_DISCOVER_FOUND_PEER]\n");
		break;

		case WS_EVENT_PROVISION_DISCOVERY_RESPONSE:
			event->id = WS_EVENT_PROVISION_DISCOVERY_RESPONSE;
			ptr = __get_event_str(ptr, event_str);
			strncpy(event->peer_mac_address, event_str, sizeof(event->peer_mac_address)); 
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_RESPONSE]\n");
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [MAC : %s]\n", event_str);
		break;

		case WS_EVENT_PROVISION_DISCOVERY_PBC_REQ:
			event->id = WS_EVENT_PROVISION_DISCOVERY_PBC_REQ;
			res = __extract_value_str(ptr, "p2p_dev_addr", event->peer_mac_address);
			if(res <= 0)
			{
				WFD_SERVER_LOG(WFD_LOG_ERROR, "Failed to extract p2p_dev_addr");
				// TO-DO: stop parsing and make event callback function stop
				__WFD_SERVER_FUNC_EXIT__;
				return;
			}
			res = __extract_value_str(ptr, "name" , event->peer_ssid);
			if(res <= 0)
			{
				WFD_SERVER_LOG(WFD_LOG_ERROR, "Failed to extract name(ssid)");
				// TO-DO: stop parsing and make event callback function stop
				__WFD_SERVER_FUNC_EXIT__;
				return;
			}
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_PBC_REQ]\n");
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [MAC : %s]\n", event_str);
		break;

		case WS_EVENT_PROVISION_DISCOVERY_DISPLAY:
			event->id = WS_EVENT_PROVISION_DISCOVERY_DISPLAY;
			res = __extract_value_str(ptr, "p2p_dev_addr", event->peer_mac_address);
			if(res <= 0)
			{
				WFD_SERVER_LOG(WFD_LOG_LOW, "Failed to extract p2p_dev_addr");
				WFD_SERVER_LOG(WFD_LOG_LOW, "Prov disc Response : DISPLAY");
				event->id = WS_EVENT_PROVISION_DISCOVERY_RESPONSE_DISPLAY;
				ptr = __get_event_str(ptr, event_str);
				strncpy(event->peer_mac_address, event_str, sizeof(event->peer_mac_address)); 
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_RESPONSE_DISPLAY]\n");
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [MAC : %s]\n", event_str);
				__WFD_SERVER_FUNC_EXIT__;
				return;
			}
			res = __extract_value_str(ptr, "name" , event->peer_ssid);
			if(res <= 0)
			{
				WFD_SERVER_LOG(WFD_LOG_ERROR, "Failed to extract name(ssid)");
				__WFD_SERVER_FUNC_EXIT__;
				return;
			}
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_DISPLAY]\n");
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [MAC : %s]\n", event_str);
		break;

		case WS_EVENT_PROVISION_DISCOVERY_KEYPAD:
			event->id = WS_EVENT_PROVISION_DISCOVERY_KEYPAD;
			res = __extract_value_str(ptr, "p2p_dev_addr", event->peer_mac_address);
			if(res <= 0)
			{
				WFD_SERVER_LOG(WFD_LOG_LOW, "Failed to extract p2p_dev_addr");
				WFD_SERVER_LOG(WFD_LOG_LOW, "Prov disc Response : KEYPAD");
				event->id = WS_EVENT_PROVISION_DISCOVERY_RESPONSE_KEYPAD;
				ptr = __get_event_str(ptr, event_str);
				strncpy(event->peer_mac_address, event_str, sizeof(event->peer_mac_address)); 
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_RESPONSE_KEYPAD]\n");
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [MAC : %s]\n", event_str);
				__WFD_SERVER_FUNC_EXIT__;
				return;
			}
			res = __extract_value_str(ptr, "name" , event->peer_ssid);
			if(res <= 0)
			{
				WFD_SERVER_LOG(WFD_LOG_ERROR, "Failed to extract name(ssid)");
				__WFD_SERVER_FUNC_EXIT__;
				return;
			}
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_KEYPAD]\n");
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [MAC : %s]\n", event_str);
		break;


		case WS_EVENT_GROUP_STARTED:
			event->id = WS_EVENT_GROUP_STARTED;
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_GROUP_STARTED]\n");
			{
				int res = 0;
				char *dev_addr;
				dev_addr = (char*) calloc(1, 18);
				res = __extract_value_str(ptr, "dev_addr", dev_addr);
				if(res > 0)
					strcpy(event->peer_mac_address, dev_addr);
				free(dev_addr);
				WFD_SERVER_LOG(WFD_LOG_LOW, "connected peer mac address [%s]", event->peer_mac_address);
			}
		break;

		case WS_EVENT_GROUP_REMOVED:
			event->id = WS_EVENT_GROUP_REMOVED;
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_GROUP_REMOVED]\n");
		break;

		case WS_EVENT_TERMINATING:
			event->id = WS_EVENT_TERMINATING;
			WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_TERMINATING]\n");
		break;
#if 1
		case WS_EVENT_CONNECTED:
			{
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_CONNECTED]\n");
				int res = 0;
				char *intf_addr;
				intf_addr = (char*) calloc(1, 18);
				event->id = WS_EVENT_CONNECTED;
				res = __extract_value_str(ptr, "to", intf_addr);
				if(res > 0)
					wfd_macaddr_atoe(intf_addr, g_assoc_sta_mac);
				WFD_SERVER_LOG(WFD_LOG_LOW, "connected peer interface mac address [%s]", intf_addr);
				free(intf_addr);
			}
		break;
#endif
		case WS_EVENT_STA_CONNECTED:
			{
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_STA_CONNECTED]\n");
				int res = 0;
				event->id = WS_EVENT_STA_CONNECTED;

				ptr = __get_event_str(ptr, event_str);
				strncpy(event->peer_intf_mac_address, event_str, sizeof(event->peer_intf_mac_address));

				res = __extract_value_str(ptr, "dev_addr", event->peer_mac_address);
				WFD_SERVER_LOG(WFD_LOG_LOW, "connected peer mac address [%s]", event->peer_intf_mac_address);
			}
		break;

		case WS_EVENT_DISCONNECTED:
			{
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_DISCONNECTED]\n");
				int res = 0;
				char *intf_addr;
				intf_addr = (char*) calloc(1, 18);
				event->id = WS_EVENT_DISCONNECTED;
				res = __extract_value_str(ptr, "to", intf_addr);
				if(res > 0)
					strncpy(event->peer_mac_address, intf_addr, 18);
				free(intf_addr);
				WFD_SERVER_LOG(WFD_LOG_LOW, "disconnected peer mac address [%s]", event->peer_mac_address);
			}
		break;

		case WS_EVENT_STA_DISCONNECTED:
			{
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_STA_DISCONNECTED]\n");
				int res = 0;
				event->id = WS_EVENT_STA_DISCONNECTED;

				ptr = __get_event_str(ptr, event_str);
				strncpy(event->peer_intf_mac_address, event_str, sizeof(event->peer_intf_mac_address));

				res = __extract_value_str(ptr, "dev_addr", event->peer_mac_address);
				WFD_SERVER_LOG(WFD_LOG_LOW, "disconnected peer mac address [%s]", event->peer_intf_mac_address);
			}
		break;

		case WS_EVENT_INVITATION_REQ:
			{
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_INVITATION_REQ]\n");
				int res = 0;
				event->id = WS_EVENT_INVITATION_REQ;

#if 1		
				res = __extract_value_str(ptr, "go_dev_addr", event->peer_mac_address);
#else
				res = __extract_value_str(ptr, "bssid", event->peer_mac_address);
#endif
				if(res <= 0)
				{
					WFD_SERVER_LOG(WFD_LOG_ERROR, "Failed to extract p2p_dev_addr");
					__WFD_SERVER_FUNC_EXIT__;
					return;
				}
 				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [GO MAC : %s]\n", event->peer_mac_address);
			}
		break;

		case WS_EVENT_INVITATION_RSP:
			{
				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [WS_EVENT_INVITATION_RSP]\n");
				//int res = 0;
				event->id = WS_EVENT_INVITATION_RSP;

#if 0		
				res = __extract_value_str(ptr, "status", );
				if(res <= 0)
				{
				    WFD_SERVER_LOG(WFD_LOG_ERROR, "Failed to extract p2p_dev_addr");
				    return;
				}
 				WFD_SERVER_LOG( WFD_LOG_LOW, "WS EVENT : [GO MAC : %s]\n", event->peer_mac_address);
#endif

			}
		break;
		

 		default:
			WFD_SERVER_LOG( WFD_LOG_ASSERT, "ERROR : unknown event !!\n");
		break;
	}

 	__WFD_SERVER_FUNC_EXIT__;

	return;
	
}

int glist_compare_peer_mac_cb(const void* data1, const void* data2)
{
	char *mac_str1 = (char*) data1;
	char *mac_str2 = (char*) data2;
	int r = 0;

	if (data1==NULL || data2==NULL)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Error!! data is NULL\n");
		return -1;
	}

	r = strcmp(mac_str1, mac_str2);
	if (r==0)
		return 0;
	else
		return 1;
}

void glist_print_connected_peer_cb(gpointer data, gpointer user_data)
{
	char *mac_str = (char*) data;
	int count = *(int*)user_data;
	WFD_SERVER_LOG( WFD_LOG_LOW, "Connected peer[%d] mac=[%s]\n", count, mac_str);
	*(int*)user_data = count+1;
}

void wfd_ws_print_connected_peer()
{
	WFD_SERVER_LOG( WFD_LOG_LOW, "Connected Peer Table\n");
	int count = 0;
	g_list_foreach(g_conn_peer_addr, glist_print_connected_peer_cb, &count);	
	WFD_SERVER_LOG( WFD_LOG_LOW, "Count=%d\n", count);
}

void wfd_ws_glist_reset_connected_peer()
{
	if(g_conn_peer_addr)
	{
		GList *element = NULL;

		element = g_list_first(g_conn_peer_addr);
		while(element)
		{
			if(element->data)
				free((char*) element->data);
			element = g_list_next(element);
		}
		g_list_free(g_conn_peer_addr);
		g_conn_peer_addr = NULL;
	}
}


static gboolean __ws_event_callback(GIOChannel * source,
										   GIOCondition condition,
										   gpointer data)
{
	__WFD_SERVER_FUNC_ENTER__;

	int sockfd = g_monitor_sockfd;
	char buffer[4096] = {0, };
	int n = 0;
	ws_event_s event = {0,};

	// Read socket
	if ( (n = __read_socket_cb(sockfd, buffer, sizeof(buffer))) < 0)	
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Error!!! Reading Async Event[%d]\n", sockfd);
		__WFD_SERVER_FUNC_EXIT__;
		return false;
	}

	WFD_SERVER_LOG( WFD_LOG_ASSERT, "Received Event:[%d, %s]\n", n, buffer);

	__parsing_ws_event(buffer, &event);

	switch (event.id)
	{
	
		case WS_EVENT_DISCOVER_FOUND_PEER:
			g_noti_cb(WFD_EVENT_DISCOVER_FOUND_PEERS);
		break;

		case WS_EVENT_PROVISION_DISCOVERY_RESPONSE:
		{
			unsigned char la_mac_addr[6];
			wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);

			wfd_server_control_t * wfd_server = wfd_server_get_control();

			WFD_SERVER_LOG(WFD_LOG_LOW, "wfd_server->current_peer.is_group_owner=[%d]\n", wfd_server->current_peer.is_group_owner);
			if (wfd_server->current_peer.is_group_owner == FALSE)
				wfd_ws_connect(la_mac_addr, WIFI_DIRECT_WPS_TYPE_PBC);
		}
		break;

		case WS_EVENT_PROVISION_DISCOVERY_RESPONSE_DISPLAY:
		case WS_EVENT_PROVISION_DISCOVERY_RESPONSE_KEYPAD:
		{
			unsigned char la_mac_addr[6];
			wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);
			memset(g_incomming_peer_mac_address, 0, sizeof(g_incomming_peer_mac_address));
			memcpy(&g_incomming_peer_mac_address, la_mac_addr, 6);

			g_noti_cb(WFD_EVENT_CONNECT_PBC_START);
		}
		break;


		case WS_EVENT_PROVISION_DISCOVERY_PBC_REQ:
		case WS_EVENT_PROVISION_DISCOVERY_DISPLAY:
		case WS_EVENT_PROVISION_DISCOVERY_KEYPAD:
		{
			unsigned char la_mac_addr[6];
			wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);
			memset(g_incomming_peer_mac_address, 0, sizeof(g_incomming_peer_mac_address));
			memcpy(&g_incomming_peer_mac_address, la_mac_addr, 6);
			memset(g_incomming_peer_ssid, 0, sizeof(g_incomming_peer_ssid));
			strncpy(g_incomming_peer_ssid, event.peer_ssid, sizeof(g_incomming_peer_ssid));
			WFD_SERVER_LOG(WFD_LOG_LOW, "Prov Req:  mac[" MACSTR"] ssid=[%s]\n",
					MAC2STR(g_incomming_peer_mac_address), g_incomming_peer_ssid);

			if (WS_EVENT_PROVISION_DISCOVERY_PBC_REQ == event.id)
				g_noti_cb(WFD_EVENT_PROV_DISCOVERY_REQUEST);
			else if (WS_EVENT_PROVISION_DISCOVERY_DISPLAY == event.id)
				g_noti_cb(WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_DISPLAY);
			else
				g_noti_cb(WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_KEYPAD);
		}
		break;

		case WS_EVENT_GROUP_STARTED:
		{
			if(wfd_ws_is_groupowner())
			{
				WFD_SERVER_LOG( WFD_LOG_LOW," CHECK : It's AP... \n");
				system("/usr/bin/wifi-direct-dhcp.sh server");
				__polling_ip(g_local_interface_ip_address, 20, FALSE);
				WFD_SERVER_LOG( WFD_LOG_ERROR, "*** IP : %s\n", g_local_interface_ip_address);

				g_noti_cb(WFD_EVENT_SOFTAP_READY);
			}
			else
			{
				wfd_ws_glist_reset_connected_peer();

				g_conn_peer_addr = g_list_append(g_conn_peer_addr, strdup(event.peer_mac_address));
				WFD_SERVER_LOG(WFD_LOG_LOW, "connected peer[%s] is added\n", event.peer_mac_address);

				g_noti_cb(WFD_EVENT_CREATE_LINK_COMPLETE);
			}
		}
		break;

		case WS_EVENT_GROUP_REMOVED:
		{
			system("/usr/bin/wifi-direct-dhcp.sh stop");
			g_noti_cb(WFD_EVENT_CREATE_LINK_CANCEL);
			g_noti_cb(WFD_EVENT_CREATE_LINK_DOWN);
			g_noti_cb(WFD_EVENT_SOFTAP_STOP);

			wfd_ws_glist_reset_connected_peer();
#if 0			
			wfd_ws_flush();
#endif			
		}
		break;

		case WS_EVENT_TERMINATING:
			system("/usr/bin/wlan.sh stop");
			system("/usr/sbin/wpa_supp_p2p.sh stop");
			WFD_SERVER_LOG( WFD_LOG_ASSERT, "Device is Deactivated\n");
		break;

		case WS_EVENT_CONNECTED:
			{
				// Nothing
			}
		break;

		case WS_EVENT_DISCONNECTED:
			{
				GList *element = NULL;
				element = g_list_find(g_conn_peer_addr, event.peer_mac_address);
				if(element != NULL)
				{
					g_conn_peer_addr = g_list_remove(g_conn_peer_addr, event.peer_mac_address);
					WFD_SERVER_LOG(WFD_LOG_LOW, "disconnected peer[%s] is removed\n", event.peer_mac_address);
					free((char*) element->data);
				}
			}
		break;

		case WS_EVENT_STA_CONNECTED:
			{
				GList *element = NULL;
				element = g_list_find_custom(g_conn_peer_addr, event.peer_mac_address, glist_compare_peer_mac_cb);
				if(element  == NULL)
				{
					g_conn_peer_addr = g_list_append(g_conn_peer_addr, strdup(event.peer_mac_address));
					WFD_SERVER_LOG(WFD_LOG_LOW, "connected peer[%s] is added\n", event.peer_mac_address);
				}

				wfd_ws_print_connected_peer();

				wfd_macaddr_atoe(event.peer_intf_mac_address, g_assoc_sta_mac);
				g_noti_cb(WFD_EVENT_CREATE_LINK_COMPLETE);
			}
			break;
		case WS_EVENT_STA_DISCONNECTED:
			{
				GList *element = NULL;

				wfd_ws_print_connected_peer();

				element = g_list_find_custom(g_conn_peer_addr, event.peer_mac_address, glist_compare_peer_mac_cb);
				if(element != NULL)
				{
					g_conn_peer_addr = g_list_remove(g_conn_peer_addr, element->data);
					WFD_SERVER_LOG(WFD_LOG_LOW, "disconnected peer[%s] is removed\n", event.peer_mac_address);
					wfd_ws_print_connected_peer();
				}
				else
				{
					WFD_SERVER_LOG(WFD_LOG_LOW, "Something wrong.. disconnected peer[%s] is not in Table\n", event.peer_mac_address);
				}
				wfd_macaddr_atoe(event.peer_intf_mac_address, g_disassoc_sta_mac);
				g_noti_cb(WFD_EVENT_SOFTAP_STA_DISASSOC);
			}
			break;

		case WS_EVENT_INVITATION_REQ:
		{
			unsigned char la_mac_addr[6];
			wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);
			memcpy(&g_incomming_peer_mac_address, la_mac_addr, 6);
			WFD_SERVER_LOG(WFD_LOG_LOW, "INVITATION REQ. RECEIVED:  mac[" MACSTR"]\n", MAC2STR(g_incomming_peer_mac_address));

			wfd_server_control_t * wfd_server = wfd_server_get_control();
			wfd_server->current_peer.is_group_owner = true;

			g_noti_cb(WFD_EVENT_INVITE_REQUEST);
		}
		break;

		case WS_EVENT_INVITATION_RSP:
			{
			}
		break;
 
		default:
		break;

	}

	__WFD_SERVER_FUNC_EXIT__;

	return true;
}

int __convert_category_from_type(char *pri_dev_type)
{
	__WFD_SERVER_FUNC_ENTER__;
	char *saveptr = NULL;
	char *token = NULL;

	if(pri_dev_type == NULL)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Incorrect parameter\n");
		return -1;
	}

	token = strtok_r(pri_dev_type, "-", &saveptr);
	if(token == NULL)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "Extracting failed\n");
		return -1;
	}

	if(!strcmp(token, "255"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_OTHER;
	else if(!strcmp(token, "11"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_AUDIO;
	else if(!strcmp(token, "10"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_TELEPHONE;
	else if(!strcmp(token, "9"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_GAME_DEVICE;
	else if(!strcmp(token, "8"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_MULTIMEDIA_DEVICE;
	else if(!strcmp(token, "7"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_DISPLAY;
	else if(!strcmp(token, "6"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_NETWORK_INFRA;
	else if(!strcmp(token, "5"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_STORAGE;
	else if(!strcmp(token, "4"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_CAMERA;
	else if(!strcmp(token, "3"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_PRINTER;
	else if(!strcmp(token, "2"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_INPUT_DEVICE;
	else if(!strcmp(token, "1"))
		return WIFI_DIRECT_PRIMARY_DEVICE_TYPE_COMPUTER;
	else
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "Unknown device type [%s]\n", token);
		return -1;
	}
	__WFD_SERVER_FUNC_EXIT__;
	return -1;
}


int __wpa_ctrl_attach(int sockfd)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[8] = {0};
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result= 0;

	strncpy(cmd, CMD_ATTACH, sizeof(cmd));
	result = __send_wpa_request(sockfd, cmd, (char*)res_buffer,  res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request(ATTACH) result=[%d]\n", result);
	
	if (result < 0)
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");

 	__WFD_SERVER_FUNC_EXIT__;

	return result;
}




static char*
__convert_wps_config_methods_value(wifi_direct_wps_type_e wps_config_methods)
{
	__WFD_SERVER_FUNC_ENTER__;

	WFD_SERVER_LOG( WFD_LOG_LOW,"wps_config_methods [%d]\n", wps_config_methods);

	switch(wps_config_methods)
	{
		case WIFI_DIRECT_WPS_TYPE_PBC:
		{
		 	__WFD_SERVER_FUNC_EXIT__;
			return "pbc";
		}
		break;

		case WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY:
		{
		 	__WFD_SERVER_FUNC_EXIT__;
			return "display";
		}
		break;

		case WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD:
		{
		 	__WFD_SERVER_FUNC_EXIT__;
			return "keypad";
		}
		break;

		default :
		{
			WFD_SERVER_LOG( WFD_LOG_LOW,"Invalid input parameter!\n");
		 	__WFD_SERVER_FUNC_EXIT__;
			return "";
		}
		break;

	}
}

static unsigned int
__convert_device_type(char *ptr)
{
	__WFD_SERVER_FUNC_ENTER__;

	char* p = ptr;
	int c = 0;
	char category_type[3] = {0,};

	if (p==NULL)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "ERROR : ptr is NULL!!\n");
		return 0;
	}

	c = 0;
	while(*p != '-')   // take the first number before the first '-' (e.g. 1-0050F204-5)
	{
		category_type[c++] = *p++;
	}
	category_type[c]='\0';

	WFD_SERVER_LOG( WFD_LOG_LOW,"category=[%d]\n", atoi(category_type));
 
 	__WFD_SERVER_FUNC_EXIT__;

	return atoi(category_type);
}

static unsigned int
__convert_secondary_device_type(char *ptr)
{
	__WFD_SERVER_FUNC_ENTER__;

	char* p = NULL;
	int c = 0;
	char category_type[3] = {0,};

	if (ptr==NULL)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "ERROR : ptr is NULL!!\n");
		return 0;
	}

	p = strstr(ptr, WIFI_ALLIANCE_OUI);
	if (p==NULL)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "ERROR : Unknown OUI, It's vendor specific device type..\n");
		return 0;
	}
	p += strlen(WIFI_ALLIANCE_OUI); // // skip OUI (e.g. 1-0050F204-5)
	p ++;   // skip the second '-' (e.g. 1-0050F204-5)

	c = 0;
	while(*p != '\0')
	{
		category_type[c++] = *p++;
	}
	category_type[c]='\0';

	WFD_SERVER_LOG( WFD_LOG_LOW,"sub-category [%d]\n", atoi(category_type));

 	__WFD_SERVER_FUNC_EXIT__;

	return atoi(category_type);
}


int __convert_freq_to_channel(char *freq_kHz)
{
	__WFD_SERVER_FUNC_ENTER__;
	int i = 0;
	int channel = 0;

	while(g_ws_op_channel_info[i].channel != 0)
	{
		if (strcmp(g_ws_op_channel_info[i].freq, freq_kHz)==0)
		{
			channel = g_ws_op_channel_info[i].channel;
			break;
		}
		i++;
	}

	__WFD_SERVER_FUNC_EXIT__;
	return channel;
}


#if 1  // Threadsafe event handling.

void __wfd_oem_callback(wfd_event_t event)
{
	// write header parts
	write(g_oem_pipe[1], &event, sizeof(event));
}

#else

void __wfd_oem_callback(wfd_event_t event_type)
{
	if (g_oem_event_callback != NULL)
		g_oem_event_callback(event_type);
}

#endif

int wfd_ws_init(wfd_oem_event_cb event_callback)
{
	__WFD_SERVER_FUNC_ENTER__;

#if 1  // Threadsafe event handling
	if (pipe(g_oem_pipe) < 0) {
		WFD_SERVER_LOG(WFD_LOG_LOW, "pipe error : Error=[%s]\n", strerror(errno));
		return false;
	}

	GIOChannel* gio2 = g_io_channel_unix_new(g_oem_pipe[0]);
	g_io_add_watch(gio2, G_IO_IN, (GIOFunc)__wfd_oem_thread_safe_event_handler_cb, NULL);
	g_io_channel_unref(gio2);
#endif

	g_oem_event_callback = event_callback;

	g_noti_cb = __wfd_oem_callback;

	memset(g_incomming_peer_mac_address, 0, sizeof(g_incomming_peer_mac_address));
	memset(g_incomming_peer_ssid, 0, sizeof(g_incomming_peer_ssid));

	__WFD_SERVER_FUNC_EXIT__;
	return true;
}

int wfd_ws_destroy()
{
	__WFD_SERVER_FUNC_ENTER__;

	// Do nothing upto now...

	__WFD_SERVER_FUNC_EXIT__;
	return true;
}

int wfd_ws_activate()
{
	__WFD_SERVER_FUNC_ENTER__;
	int result = 0;
	char cmd[128] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	
	// Loading Driver,  Excuting p2p_supplicant
	system("/usr/bin/wlan.sh p2p");
	system("/usr/sbin/p2p_supp.sh start");

	sleep(1);
	g_global_sockfd = __create_ctrl_intf("p2p_ctrl_global", "/var/run/p2p_global");
	if(g_global_sockfd < 0)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Failed to create Global Control interface\n");
		return false;
	}

	strncpy(cmd, CMD_INTERFACE, sizeof(cmd));
	result = __send_wpa_request(g_global_sockfd, cmd, res_buffer,  res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request(LOG_LEVEL) result=[%d]\n", result);
	if(!strstr(res_buffer, "wlan0"))
	{
		memset(cmd, 0x0, 128);
		memset(res_buffer, 0x0, 1024);

		snprintf(cmd, sizeof(cmd), "%s %s", CMD_INTERFACE_ADD, "wlan0\t/usr/etc/wifi-direct/p2p_suppl.conf\tnl80211\t/var/run/p2p_supplicant");
		result = __send_wpa_request(g_global_sockfd, cmd, res_buffer,  res_buffer_len);
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request(LOG_LEVEL) result=[%d]\n", result);
	}
	memset(res_buffer, 0x0, 1024);

	// Creating Socket
	int count = 10;
	do
	{
		sleep(1);

		// Sync Socket
		g_control_sockfd = __create_ctrl_intf("p2p_ctrl_control", "/var/run/p2p_supplicant/wlan0");
		if (g_control_sockfd > 0)
		{
			// Async Socket			
			g_monitor_sockfd = __create_ctrl_intf("p2p_ctrl_monitor", "/var/run/p2p_supplicant/wlan0");
			if (g_monitor_sockfd > 0)
			{
				if (__wpa_ctrl_attach(g_monitor_sockfd) < 0)
				{
					WFD_SERVER_LOG( WFD_LOG_ERROR, "Failed to attach p2p_supplicant!!! monitor_sockfd=[%d]\n", g_monitor_sockfd);
					return false;
				}
				break;
			}
		}
		count--;

		if (count == 0)
			WFD_SERVER_LOG( WFD_LOG_ASSERT, "Failed to create socket !!\n");		
		
	} while (count > 0);

	WFD_SERVER_LOG( WFD_LOG_LOW, "Successfully socket connected to server !!\n");

	GIOChannel *gio3;

	gio3 = g_io_channel_unix_new(g_monitor_sockfd);
	g_source_id = g_io_add_watch(gio3, G_IO_IN | G_IO_ERR | G_IO_HUP, (GIOFunc) __ws_event_callback, NULL);
	g_io_channel_unref(gio3);
	WFD_SERVER_LOG( WFD_LOG_LOW, "Scoket is successfully registered to g_main_loop.\n");

	//wfd_ws_set_oem_loglevel(3);

	/* init miracast */
	if(wfd_ws_dsp_init() == true)
		WFD_SERVER_LOG( WFD_LOG_LOW, "Success : wfd_ws_dsp_init() \n");
	else
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Failed : wfd_ws_dsp_init()\n");

	__WFD_SERVER_FUNC_EXIT__;
	return true;
}

int wfd_ws_deactivate()
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result = 0;

	// stop p2p_find
	wfd_ws_cancel_discovery();

	// detach monitor interface
	strncpy(cmd, CMD_DETACH, sizeof(cmd));
	result = __send_wpa_request(g_monitor_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_DETACH) result=[%d]\n", result);
	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "DETACH command Fail. result [%d], res_buffer [%s]\n", result, res_buffer);
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);


	// close control interface
	g_source_remove(g_source_id);
	unlink("/tmp/wpa_ctrl_monitor");
	if (g_monitor_sockfd >= 0)
		close(g_monitor_sockfd);
	unlink("/tmp/wpa_ctrl_control");
	if (g_control_sockfd >= 0)
		close(g_control_sockfd);

	// interface_remove
	snprintf(cmd, sizeof(cmd), "%s %s", CMD_INTERFACE_REMOVE, "p2p-wlan0-0");
	result = __send_wpa_request(g_global_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(INTERFACE_REMOVE p2p-wlan0-0) result=[%d]\n", result);
	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	// interface_remove
	snprintf(cmd, sizeof(cmd), "%s %s", CMD_INTERFACE_REMOVE, "wlan0");
	result = __send_wpa_request(g_global_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(INTERFACE_REMOVE wlan0) result=[%d]\n", result);
	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	// close global interface
	unlink("/tmp/wpa_ctrl_global");
	if(g_global_sockfd >= 0)
	    close(g_global_sockfd);

	wfd_ws_glist_reset_connected_peer();

	// wlan.sh stop
	system("/usr/bin/wlan.sh stop");
	system("/usr/sbin/wpa_supp_p2p.sh stop");

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_wps_pbc_start(void)
{
	__WFD_SERVER_FUNC_ENTER__;

 	char cmd[8] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (wfd_ws_is_groupowner()!=true)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "wps_pbc_start() can be called, only when device is go!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	strncpy(cmd, CMD_WPS_PUSHBUTTON_START, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(WPS_PBC) result=[%d]\n", result);
	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	WFD_SERVER_LOG( WFD_LOG_LOW, "start WPS PBC...\n");

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_connect(unsigned char mac_addr[6], wifi_direct_wps_type_e wps_config)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[50] = {0, };
	char mac_str[18] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	wfd_server_control_t * wfd_server = wfd_server_get_control();
	WFD_SERVER_LOG(WFD_LOG_LOW, "wfd_server->current_peer.is_group_owner=[%d]\n", wfd_server->current_peer.is_group_owner);

	if (wfd_ws_is_groupowner()==true)
	{
		strncpy(cmd, CMD_WPS_PUSHBUTTON_START, sizeof(cmd));
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(WPS_PBC) result=[%d]\n", result);
	}

	if (wfd_server->current_peer.is_group_owner)
	{
		snprintf(mac_str, 18, MACSTR, MAC2STR(mac_addr));
		snprintf(cmd, sizeof(cmd),"%s %s %s join", CMD_CONNECT, mac_str, __convert_wps_config_methods_value(wps_config));
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_CONNECT join) result=[%d]\n", result);
	}
	else
	{
		if (wfd_server->config_data.want_persistent_group == true)	/* persistent mode */
		{
			WFD_SERVER_LOG( WFD_LOG_LOW, "[persistent mode!!!]\n");
			snprintf(mac_str, 18, MACSTR, MAC2STR(mac_addr));
			snprintf(cmd, sizeof(cmd), "%s %s %s persistent", CMD_CONNECT, mac_str, __convert_wps_config_methods_value(wps_config));
			result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
			WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_CONNECT ... persistent) result=[%d]\n", result);
		}
		else
		{
			snprintf(mac_str, 18, MACSTR, MAC2STR(mac_addr));
			snprintf(cmd, sizeof(cmd), "%s %s %s", CMD_CONNECT, mac_str, __convert_wps_config_methods_value(wps_config));
			result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
			WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_CONNECT) result=[%d]\n", result);
		}
	}

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	WFD_SERVER_LOG( WFD_LOG_LOW, "Connecting... peer-MAC [%s]\n", mac_str);
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_disconnect()
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), "%s %s", CMD_GROUP_REMOVE, DEFAULT_IF_NAME);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_GROUP_REMOVE) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	WFD_SERVER_LOG( WFD_LOG_LOW, "disconnect... remove group [%s]\n", DEFAULT_IF_NAME);
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}


// TODO: should find how to disconnect with peer by peer_mac
int wfd_ws_disconnect_sta(unsigned char mac_addr[6])
{
	__WFD_SERVER_FUNC_ENTER__;

	int result;

 	result = wfd_ws_disconnect();

	__WFD_SERVER_FUNC_EXIT__;
 	return result;
}

bool wfd_ws_is_discovery_enabled()
{
	__WFD_SERVER_FUNC_ENTER__;

	__WFD_SERVER_FUNC_EXIT__;
	return false;
}

bool wfd_ws_flush()
{
        __WFD_SERVER_FUNC_ENTER__;

        char cmd[16] = {0, };
        char res_buffer[1024]={0,};
        int res_buffer_len=sizeof(res_buffer);
        int result = 0;

        // Skip checking result..
        strncpy(cmd, CMD_FLUSH, sizeof(cmd));
        result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
        WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_FLUSH) result=[%d]\n", result);

        if (result < 0)
        {
                WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
                __WFD_SERVER_FUNC_EXIT__;
                return false;
        }

        if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
        {
                __WFD_SERVER_FUNC_EXIT__;
                return false;
        }

        __WFD_SERVER_FUNC_EXIT__;
        return true;
}



int wfd_ws_start_discovery(bool listen_only, int timeout)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result = 0;

#if 0
	if (wfd_ws_is_groupowner()==false && wfd_ws_is_groupclient()==false)
		wfd_ws_flush();
#endif

	if (listen_only == true)
	{
		if (timeout > 0)
			snprintf(cmd, sizeof(cmd), "%s %d", CMD_START_LISTEN, timeout);
		else
			strncpy(cmd, CMD_START_LISTEN, sizeof(cmd));

			result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
			WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_LISTEN) result=[%d]\n", result);
	}
	else
	{
		strncpy(cmd, CMD_START_DISCOVER, sizeof(cmd));
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_FIND) result=[%d]\n", result);
	}

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	// to notify to the application.
	if (listen_only == true)
		g_noti_cb(WFD_EVENT_DISCOVER_START_LISTEN_ONLY);
	else
		g_noti_cb(WFD_EVENT_DISCOVER_START_80211_SCAN);

 	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_cancel_discovery()
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result = 0;

	strncpy(cmd, CMD_CANCEL_DISCOVER, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_STOP_FIND) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	// to notify to the application.
	g_noti_cb(WFD_EVENT_DISCOVER_CANCEL);

 	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_discovery_result(wfd_discovery_entry_s ** peer_list, int* peer_num)
{
	__WFD_SERVER_FUNC_ENTER__;
	
	char cmd[40] = {0, };
	char mac_str[18] = {0, };
	char res_buffer[1024] = {0,};
	int res_buffer_len = sizeof(res_buffer);
	int result = 0;
	int peer_count = 0;
	int i;
	ws_discovered_peer_info_s ws_peer_list[MAX_PEER_NUM];
	static wfd_discovery_entry_s wfd_peer_list[16];

	memset(&ws_peer_list, 0, (sizeof(ws_discovered_peer_info_s)*MAX_PEER_NUM));
	memset(&wfd_peer_list, 0, (sizeof(wfd_discovery_entry_s)*16));
	
	/* Reading first discovered peer */
	strncpy(cmd, CMD_GET_FIRST_DISCOVERED_PEER, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_PEER FIRST) result=[%d]\n", result);
	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
		*peer_num = 0;
		*peer_list = NULL;
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))	/* p2p_supplicant returns the 'FAIL' if there is no discovered peer. */
	{
		*peer_num = 0;
		*peer_list = NULL;
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	__parsing_peer(res_buffer, &ws_peer_list[peer_count]);
	peer_count++;

	/* Reading Next discovered peers */
	do
	{
	 	memset(cmd, 0x0, 40);
	 	memset(mac_str, 0x0, 18);
		memset(res_buffer, 0, sizeof(res_buffer));

		strncpy(mac_str, ws_peer_list[peer_count-1].mac, sizeof(mac_str));
		snprintf(cmd, sizeof(cmd), "%s%s", CMD_GET_NEXT_DISCOVERED_PEER, mac_str);
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_PEER NEXT-) result=[%d]\n", result);

		if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))	/* p2p_asupplicant returns the 'FAIL' if there is no discovered peer. */
			break;

		__parsing_peer(res_buffer, &ws_peer_list[peer_count]);
		peer_count++;

	} while(1);

	WFD_SERVER_LOG(WFD_LOG_LOW, "number of discovered peers: %d\n", peer_count);

	for(i=0; i<peer_count; i++)
	{
		memset(&wfd_peer_list[i], 0, sizeof(wfd_discovery_entry_s));
		WFD_SERVER_LOG( WFD_LOG_LOW, "index [%d] MAC [%s] GOstate=[%s] groupCapab=[%x] devCapab=[%x] is_wfd_device[%d] Name[%s] type=[%s] ssid[%s]\n",
				i,
				ws_peer_list[i].mac,
				ws_peer_list[i].go_state,
				ws_peer_list[i].group_capab,
				ws_peer_list[i].dev_capab,
				ws_peer_list[i].is_wfd_device,
				ws_peer_list[i].device_name,
				ws_peer_list[i].pri_dev_type,
				ws_peer_list[i].oper_ssid);
/*
		typedef struct
		{
			bool is_group_owner;
			char ssid[WIFI_DIRECT_MAX_SSID_LEN + 1];
			unsigned char mac_address[6];
			int channel;
			bool is_connected;
			unsigned int services;
			bool is_persistent_go;
			unsigned char intf_mac_address[6];
			unsigned int wps_device_pwd_id;
			unsigned int wps_cfg_methods;
			unsigned int category;
			unsigned int subcategory;
		} wfd_discovery_entry_s;
*/
		// Device MAC address
		if (NULL != ws_peer_list[i].mac)
		{
			unsigned char la_mac_addr[6];

			wfd_macaddr_atoe(ws_peer_list[i].mac, la_mac_addr);
			memcpy(wfd_peer_list[i].mac_address, (char*)(la_mac_addr), sizeof(la_mac_addr));
		}

		// Interface MAC address
		if (NULL != ws_peer_list[i].interface_addr)
		{
			unsigned char la_mac_addr[6];

			wfd_macaddr_atoe(ws_peer_list[i].interface_addr, la_mac_addr);
			memcpy(wfd_peer_list[i].intf_mac_address, (char*)(la_mac_addr), sizeof(la_mac_addr));
		}

		// WPS Config method
		wfd_peer_list[i].wps_cfg_methods = 0;
		if ((ws_peer_list[i].config_methods & WPS_CONFIG_DISPLAY) > 0)
			wfd_peer_list[i].wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY;
		if ((ws_peer_list[i].config_methods & WPS_CONFIG_PUSHBUTTON) > 0)
			wfd_peer_list[i].wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PBC;
		if ((ws_peer_list[i].config_methods & WPS_CONFIG_KEYPAD) > 0)
			wfd_peer_list[i].wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD;

		// Device name --> SSID
		strncpy(wfd_peer_list[i].ssid, ws_peer_list[i].device_name, sizeof(wfd_peer_list[i].ssid));

		// is_group_owner
		if ((ws_peer_list[i].group_capab & GROUP_CAPAB_GROUP_OWNER) > 0)  /* checking GO state */
			wfd_peer_list[i].is_group_owner = true;
		else
			wfd_peer_list[i].is_group_owner = false;

		WFD_SERVER_LOG( WFD_LOG_LOW, "GroupOwnerCapab: %x & %x = %d\n", ws_peer_list[i].group_capab, GROUP_CAPAB_GROUP_OWNER, (ws_peer_list[i].group_capab & GROUP_CAPAB_GROUP_OWNER));

		// is_persistent_go
		if ((ws_peer_list[i].group_capab & GROUP_CAPAB_PERSISTENT_GROUP) > 0)  /* checking persistent GO state */
			wfd_peer_list[i].is_persistent_go = true;
		else
			wfd_peer_list[i].is_persistent_go = false;

		// is_connected
#if 1
		if (wfd_peer_list[i].is_group_owner)
			wfd_peer_list[i].is_connected = true;
		else if (strncmp(ws_peer_list[i].member_in_go_dev, "00:00:00:00:00:00", strlen("00:00:00:00:00:00"))!=0)
			wfd_peer_list[i].is_connected = true;
		else
			wfd_peer_list[i].is_connected = false;
#else
		wfd_peer_list[i].is_connected  = wfd_server_is_connected_peer_by_device_mac(wfd_peer_list[i].mac_address);
#endif


		// Listen channel
		// ToDo: convert freq to channel...
		wfd_peer_list[i].channel = ws_peer_list[i].listen_freq;

		// wps_device_pwd_id
		// ToDo: where to get it?
		wfd_peer_list[i].wps_device_pwd_id = 0;

		wfd_peer_list[i].category = __convert_device_type(ws_peer_list[i].pri_dev_type);
		wfd_peer_list[i].subcategory = __convert_secondary_device_type(ws_peer_list[i].pri_dev_type);
	}

	*peer_num = peer_count;
	*peer_list = &wfd_peer_list[0];

	WFD_SERVER_LOG( WFD_LOG_ASSERT, "Getting discovery result is Completed.\n");

	__WFD_SERVER_FUNC_EXIT__;
 	return true;

}

int wfd_ws_get_peer_info(unsigned char *mac_addr, wfd_discovery_entry_s **peer)
{
	__WFD_SERVER_FUNC_ENTER__;

 	char cmd[32] = {0, };
	char mac_str[18] = {0, };
	char res_buffer[1024] = {0,};
	int res_buffer_len = sizeof(res_buffer);
	int result = 0;
	ws_discovered_peer_info_s ws_peer_info;
	wfd_discovery_entry_s* wfd_peer_info;

	memset(&ws_peer_info, 0x0, sizeof(ws_discovered_peer_info_s));
	wfd_peer_info = (wfd_discovery_entry_s *) calloc(1, sizeof(wfd_discovery_entry_s));
	
	/* Reading first discovered peer */
	snprintf(mac_str, 18, MACSTR, MAC2STR(mac_addr));
	snprintf(cmd, sizeof(cmd),"%s %s", CMD_GET_PEER_INFO, mac_str);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_PEER) result=[%d]\n", result);
	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
		*peer = NULL;
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))	/* p2p_supplicant returns the 'FAIL' if there is no discovered peer. */
	{
		*peer = NULL;
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	// TODO: parsing peer info
	__parsing_peer(res_buffer, &ws_peer_info);

	WFD_SERVER_LOG( WFD_LOG_LOW, "MAC [%s] GOstate=[%s] groupCapab=[%x] devCapab=[%x] Name[%s] type=[%s] ssid[%s]\n",
			ws_peer_info.mac,
			ws_peer_info.go_state,
			ws_peer_info.group_capab,
			ws_peer_info.dev_capab,
			ws_peer_info.device_name,
			ws_peer_info.pri_dev_type,
			ws_peer_info.oper_ssid);

	if (NULL != ws_peer_info.mac)
	{
		unsigned char la_mac_addr[6];

		wfd_macaddr_atoe(ws_peer_info.mac, la_mac_addr);
		memcpy(wfd_peer_info->mac_address, (char*)(la_mac_addr), sizeof(la_mac_addr));
	}

	// Interface MAC address
	if (NULL != ws_peer_info.interface_addr)
	{
		unsigned char la_mac_addr[6];

		wfd_macaddr_atoe(ws_peer_info.interface_addr, la_mac_addr);
		memcpy(wfd_peer_info->intf_mac_address, (char*)(la_mac_addr), sizeof(la_mac_addr));
	}

	// WPS Config method
	wfd_peer_info->wps_cfg_methods = 0;
	if ((ws_peer_info.config_methods & WPS_CONFIG_DISPLAY) > 0)
		wfd_peer_info->wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY;
	if ((ws_peer_info.config_methods & WPS_CONFIG_PUSHBUTTON) > 0)
		wfd_peer_info->wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PBC;
	if ((ws_peer_info.config_methods & WPS_CONFIG_KEYPAD) > 0)
		wfd_peer_info->wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD;

	// Device name --> SSID
	strncpy(wfd_peer_info->ssid, ws_peer_info.device_name, sizeof(wfd_peer_info->ssid));

	// is_group_owner
	if ((ws_peer_info.group_capab & GROUP_CAPAB_GROUP_OWNER) > 0)  /* checking GO state */
		wfd_peer_info->is_group_owner = true;
	else
		wfd_peer_info->is_group_owner = false;

	WFD_SERVER_LOG( WFD_LOG_LOW, "GroupOwnerCapab: %x & %x = %d\n", ws_peer_info.group_capab, GROUP_CAPAB_GROUP_OWNER, (ws_peer_info.group_capab & GROUP_CAPAB_GROUP_OWNER));

	// is_persistent_go
	if ((ws_peer_info.group_capab & GROUP_CAPAB_PERSISTENT_GROUP) > 0)  /* checking persistent GO state */
		wfd_peer_info->is_persistent_go = true;
	else
		wfd_peer_info->is_persistent_go = false;

	// is_connected
#if 1
	if (wfd_peer_info->is_group_owner)
		wfd_peer_info->is_connected = true;
	else if (strncmp(ws_peer_info.member_in_go_dev, "00:00:00:00:00:00", strlen("00:00:00:00:00:00"))!=0)
		wfd_peer_info->is_connected = true;
	else
		wfd_peer_info->is_connected = false;
#else
	wfd_peer_info->is_connected  = wfd_server_is_connected_peer_by_device_mac(wfd_peer_info->mac_address);
#endif


	// Listen channel
	// ToDo: convert freq to channel...
	wfd_peer_info->channel = ws_peer_info.listen_freq;

	// wps_device_pwd_id
	// ToDo: where to get it?
	wfd_peer_info->wps_device_pwd_id = 0;

	wfd_peer_info->category = __convert_device_type(ws_peer_info.pri_dev_type);
	wfd_peer_info->subcategory = __convert_secondary_device_type(ws_peer_info.pri_dev_type);

	*peer = wfd_peer_info;

	__WFD_SERVER_FUNC_EXIT__;
	return true;
}

int wfd_ws_send_provision_discovery_request(unsigned char mac_addr[6], wifi_direct_wps_type_e config_method, int is_peer_go)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[40] = {0, };
	char mac_str[18] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	// temporary code : stop p2p_find (multi-supplicant ignore provision discovery response)
	wfd_ws_cancel_discovery();

	if (is_peer_go)
	{
		snprintf(mac_str, 18, MACSTR, MAC2STR(mac_addr));
		snprintf(cmd, sizeof(cmd),"%s %s %s join", CMD_CONNECT, mac_str, __convert_wps_config_methods_value(config_method));
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_PROV_DISC) result=[%d]\n", result);
	}
	else
	{
		snprintf(mac_str, 18, MACSTR, MAC2STR(mac_addr));
		snprintf(cmd, sizeof(cmd),"%s %s %s", CMD_SEND_PROVISION_DISCOVERY_REQ, mac_str, __convert_wps_config_methods_value(config_method));
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_PROV_DISC) result=[%d]\n", result);
	}

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	WFD_SERVER_LOG( WFD_LOG_LOW, "Provisioning... peer-MAC [%s]\n", mac_str);

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}


bool wfd_ws_get_go_dev_addr(char* p2p_device_address)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (p2p_device_address == NULL)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "Wrong param\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	strncpy(cmd, CMD_STATUS_P2P, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(STATUS P2P) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	char* ptr = strstr(res_buffer, "p2p_device_address=");
	if (ptr==NULL)
	{
	    WFD_SERVER_LOG( WFD_LOG_LOW, "Can't find p2p_device_address...\n");
	    __WFD_SERVER_FUNC_EXIT__;
	    return false;
	}

	char item[32];
	char value[32];

	if (__get_item_value(ptr, item, value) == NULL)
	{
	    WFD_SERVER_LOG( WFD_LOG_LOW, "Can't wrong format to get p2p_device_address...\n");
	    __WFD_SERVER_FUNC_EXIT__;
	    return false;
	}

	if (strcmp(item, "p2p_device_address")!=0)
	{
	    WFD_SERVER_LOG( WFD_LOG_LOW, "Can't get p2p_device_address.... item=[%s]\n", item);
	    __WFD_SERVER_FUNC_EXIT__;
	    return false;
	}

	strncpy(p2p_device_address, value, sizeof(value));

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_send_invite_request(unsigned char dev_mac_addr[6])
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[128] = {0, };
	char mac_str[18] = {0, };
	char res_buffer[1024]={0,};
	char p2p_device_address[32];
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if(wfd_ws_get_go_dev_addr(p2p_device_address) == false)
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	snprintf(mac_str, 18, MACSTR, MAC2STR(dev_mac_addr));
	snprintf(cmd, sizeof(cmd), "%s group=p2p-wlan0-0 peer=%s go_dev_addr=%s", CMD_SEND_INVITE_REQ, mac_str, p2p_device_address);

	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_SEND_INVITE_REQ) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	WFD_SERVER_LOG(WFD_LOG_LOW, "Invite... peer-MAC [%s]\n", mac_str);

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}


int wfd_ws_create_group(char* ssid)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[64] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;
	wfd_server_control_t * wfd_server = wfd_server_get_control();

	if (wfd_server->config_data.want_persistent_group)
	{
		/* Persistent group mode */
		snprintf(cmd, sizeof(cmd), "%s %s %s", CMD_CREATE_GROUP, "persistent", FREQUENCY_2G);
	}
	else
	{
                snprintf(cmd, sizeof(cmd), "%s %s", CMD_CREATE_GROUP, FREQUENCY_2G);
	}

	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_GROUP_ADD) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	WFD_SERVER_LOG( WFD_LOG_LOW, "Create p2p group... \n");
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_cancel_group()
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[30] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), "%s %s", CMD_GROUP_REMOVE, DEFAULT_IF_NAME);
	
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(P2P_GROUP_REMOVE) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	WFD_SERVER_LOG( WFD_LOG_LOW, "Remove p2p group... \n");
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_activate_pushbutton()
{
 	__WFD_SERVER_FUNC_ENTER__;

 	char cmd[8] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	strncpy(cmd, CMD_WPS_PUSHBUTTON_START, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(WPS_PBC) result=[%d]\n", result);
	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	WFD_SERVER_LOG( WFD_LOG_LOW, "start WPS PBC...\n");

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
 }

bool wfd_ws_is_groupowner()
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	strncpy(cmd, CMD_STATUS_P2P, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(STATUS P2P) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if(strstr(res_buffer, "mode=P2P GO") == NULL)
	{
	    WFD_SERVER_LOG( WFD_LOG_LOW, "This device is not Groupowner\n");
	    __WFD_SERVER_FUNC_EXIT__;
	    return false;
	}
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

bool wfd_ws_is_groupclient()
{
	__WFD_SERVER_FUNC_ENTER__;
	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	strncpy(cmd, CMD_STATUS_P2P, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(STATUS P2P) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if(strstr(res_buffer, "mode=station") == NULL)
	{
	    WFD_SERVER_LOG( WFD_LOG_LOW, "This device is not client\n");
	    __WFD_SERVER_FUNC_EXIT__;
	    return false;
	}

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_ssid(char* ssid, int len)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[12] = {0, };
 	char tmp_ssid[64] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if(ssid == NULL)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Incorrect parameter");
		return -1;
	}

	strncpy(cmd, CMD_STATUS_P2P, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(STATUS) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return -1;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return -1;
	}

	result = __extract_value_str(res_buffer, "\nssid", (char*) tmp_ssid);
	if(result <= 0)
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Extracting value failed\n");
		return -1;
	}
	WFD_SERVER_LOG( WFD_LOG_LOW, "######    ssid [%s]         ###########\n", tmp_ssid);
	memcpy(ssid, tmp_ssid, len);
	ssid[len] = '\0';

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

char* wfd_ws_get_default_interface_name()
{
	__WFD_SERVER_FUNC_ENTER__;
 
	__WFD_SERVER_FUNC_EXIT__;
	
 	return DEFAULT_IF_NAME;
}

bool wfd_ws_dhcpc_get_ip_address(char *ipaddr_buf, int len, int is_IPv6)
{
	__WFD_SERVER_FUNC_ENTER__;

	struct ifreq IfRequest;
	struct sockaddr_in* sin = NULL;
	int fd;

	if (ipaddr_buf == NULL)
		return false;
#if 0
	FILE *fp = NULL;
	if((fp = fopen(DEFAULT_IP_LOG_PATH, "r+")) != NULL)
	{
		fclose(fp);
		fp = NULL;
#endif

		if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
			WFD_SERVER_LOG( WFD_LOG_ERROR, "Failed to open socket\n");
			return false;
		}

		memset(IfRequest.ifr_name, 0, DEFAULT_IF_NAME_LEN);
		strncpy(IfRequest.ifr_name, DEFAULT_IF_NAME, DEFAULT_IF_NAME_LEN - 1);
		if(ioctl(fd, SIOCGIFADDR, &IfRequest) < 0) {
			WFD_SERVER_LOG( WFD_LOG_ERROR, "Failed to get IP\n");
			close(fd);
			return false;
		}

		sin = (struct sockaddr_in*)&IfRequest.ifr_broadaddr;
		if (ipaddr_buf != NULL)
			strncpy(ipaddr_buf, (char*)inet_ntoa(sin->sin_addr), len);
		return true;
#if 0
	}
#endif

	__WFD_SERVER_FUNC_EXIT__;
	
	return false;
}


char* wfd_ws_get_ip()
{
	__WFD_SERVER_FUNC_ENTER__;

	char ip_string[20] = {0,};

	snprintf(ip_string, 20, "%s", g_local_interface_ip_address);
	WFD_SERVER_LOG( WFD_LOG_LOW, "################################################\n");
	WFD_SERVER_LOG( WFD_LOG_LOW, "######    IP = %s         ###########\n", ip_string);
	WFD_SERVER_LOG( WFD_LOG_LOW, "################################################\n");

	__WFD_SERVER_FUNC_EXIT__;
 	return ip_string;
}

int wfd_ws_set_wps_pin(char* pin)
{
	__WFD_SERVER_FUNC_ENTER__;
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
 }

int wfd_ws_get_wps_pin(char* wps_pin, int len)
{
	__WFD_SERVER_FUNC_ENTER__;
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_generate_wps_pin()
{
	__WFD_SERVER_FUNC_ENTER__;
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;

}


int wfd_ws_set_ssid(char* ssid)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[128] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (ssid == NULL || strlen(ssid) == 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "Wrong SSID\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	snprintf(cmd, sizeof(cmd), "%s device_name %s", CMD_SET_PARAM, ssid);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	memset(cmd, 0x0, 128);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s p2p_ssid_postfix %s", CMD_SET_PARAM, ssid);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_set_wpa_passphrase(char* wpa_key)
{
	__WFD_SERVER_FUNC_ENTER__;
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_supported_wps_mode()
{
	__WFD_SERVER_FUNC_ENTER__;

	int wps_config;

	//TO-DO : supplicant CLI command should be supported.

	wps_config = WIFI_DIRECT_WPS_TYPE_PBC |WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY |WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD;

	return wps_config;

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_connected_peers_count(int* peer_num)
{
	__WFD_SERVER_FUNC_ENTER__;
	GList *element = NULL;

	*peer_num = 0;
	element = g_list_first(g_conn_peer_addr);
	while(element)
	{
		(*peer_num)++;
		element = g_list_next(element);
	}
	WFD_SERVER_LOG( WFD_LOG_LOW, "Connected peer number [%d]\n", *peer_num);
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}


int wfd_ws_get_connected_peers_info(wfd_connected_peer_info_s ** peer_list, int* peer_num)
{
	__WFD_SERVER_FUNC_ENTER__;
	int i = 0;
	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	char pri_dev_type[16] ={0, };
	GList *element = NULL;
	int result;

	if(peer_list == NULL || peer_num == NULL)
	{
		WFD_SERVER_LOG( WFD_LOG_LOW, "Incorrect parameter\n");
		return false;
	}

	wfd_ws_get_connected_peers_count(peer_num);

	wfd_connected_peer_info_s *tmp_peer_list = NULL;

	tmp_peer_list = (wfd_connected_peer_info_s*) calloc(*peer_num, sizeof(wfd_connected_peer_info_s));
	if(tmp_peer_list == NULL)
	{
		WFD_SERVER_LOG( WFD_LOG_LOW, "Memory allocatin failed\n");
		*peer_list = NULL;
		*peer_num = 0;

		return false;
	}

	element = g_list_first(g_conn_peer_addr);
	while(element)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "element data is [%s]\n", (char*) element->data);
		memset(cmd, 0x0, 32);
		memset(res_buffer, 0x0, 1024);

		snprintf(cmd, sizeof(cmd), "%s %s", CMD_GET_PEER_INFO, (char*) element->data);
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(%s) result=[%d]\n", cmd, result);

		if (result < 0)
		{
			WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

		 	__WFD_SERVER_FUNC_EXIT__;
		 	return false;
		}

		if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
		{
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

		 	__WFD_SERVER_FUNC_EXIT__;
	 		return false;
		}

		/*
			typedef struct
			{
				char ssid[WIFI_DIRECT_MAX_SSID_LEN + 1];
				unsigned char mac_address[6];
				unsigned char intf_mac_address[6];
				unsigned int services;
				bool is_p2p;
				unsigned short category;
				int channel;
			} wfd_connected_peer_info_s;
		 */
		result = __extract_value_str(res_buffer, "device_name", (char*) tmp_peer_list[i].ssid);
		if(result <= 0)
		{
			WFD_SERVER_LOG(WFD_LOG_ERROR, "Extracting value failed\n");
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

			return false;
		}

		wfd_macaddr_atoe((char*) element->data, tmp_peer_list[i].mac_address);

		char intf_mac_address[18] = {0, };
		result = __extract_value_str(res_buffer, "interface_addr", (char*) intf_mac_address);
		if(result <= 0)
		{
			WFD_SERVER_LOG(WFD_LOG_ERROR, "Extracting value failed\n");
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

			return false;
		}
		wfd_macaddr_atoe((char*) intf_mac_address, tmp_peer_list[i].intf_mac_address);

		tmp_peer_list[i].services = 0;
		tmp_peer_list[i].is_p2p = true;

		result = __extract_value_str(res_buffer, "pri_dev_type", (char*) pri_dev_type);
		if(result <= 0)
		{
			WFD_SERVER_LOG(WFD_LOG_ERROR, "Extracting value failed\n");
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

			return false;
		}

		tmp_peer_list[i].category = __convert_category_from_type(pri_dev_type);
		if(tmp_peer_list[i].category < 0)
		{
			WFD_SERVER_LOG(WFD_LOG_ERROR, "Category converting error\n");
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

			return false;
		}

		element = g_list_next(element);
		i++;
	}

	*peer_list = tmp_peer_list;
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}


int wfd_ws_get_go_intent(int *p2p_go_intent)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (p2p_go_intent == NULL)
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "p2p_go_intent is NULL\n", p2p_go_intent);
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	snprintf(cmd, sizeof(cmd), "%s p2p_go_intent", CMD_GET_PARAM);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(GET P2P_GO_INTENT) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	*p2p_go_intent = atoi(res_buffer);
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_set_go_intent(int go_intent)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (go_intent < 0 || go_intent > 15)
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "Wrong p2p_go_intent [%d]\n", go_intent);
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	snprintf(cmd, sizeof(cmd), "%s p2p_go_intent %d", CMD_SET_PARAM, go_intent);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
 
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}


int wfd_ws_set_device_type(wifi_direct_primary_device_type_e primary_cat, wifi_direct_secondary_device_type_e sub_cat)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), "%s device_type %d", CMD_SET_PARAM, primary_cat);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s device_type %d", CMD_SET_PARAM, sub_cat);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

 	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}


int wfd_ws_get_device_mac_address(unsigned char* device_mac)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[8] = {0, };
 	char device_address[18] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	strncpy(cmd, CMD_STATUS, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(STATUS) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ERROR, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return -1;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return -1;
	}

	__extract_value_str(res_buffer, "p2p_device_address", (char*) device_address);
	if(strlen(device_address) ==18)
	{
		wfd_macaddr_atoe((char*) device_address, device_mac);
	}
	else
	{
		WFD_SERVER_LOG(WFD_LOG_ERROR, "Extracting value failed\n");
		return -1;
	}

	__WFD_SERVER_FUNC_EXIT__;
 	return 0;
}

int wfd_ws_set_oem_loglevel(int is_increase)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;
 
	snprintf(cmd, sizeof(cmd), "%s %d", CMD_LOG_LEVEL, is_increase);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer,  res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request(LOG_LEVEL) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_assoc_sta_mac(unsigned char *mac_addr)
{
	__WFD_SERVER_FUNC_ENTER__;

	memcpy(mac_addr, g_assoc_sta_mac, 6);

	__WFD_SERVER_FUNC_EXIT__;
	return true;
}

int wfd_ws_get_disassoc_sta_mac(unsigned char *mac_addr)
{
	__WFD_SERVER_FUNC_ENTER__;
	memcpy(mac_addr, g_disassoc_sta_mac, 6);
	__WFD_SERVER_FUNC_EXIT__;
	return true;
}

int wfd_ws_get_requestor_mac(unsigned char* mac_addr)
{
	__WFD_SERVER_FUNC_ENTER__;

	memcpy(mac_addr, g_incomming_peer_mac_address, 6);

	__WFD_SERVER_FUNC_EXIT__;
	return true;
}

int wfd_ws_get_operating_channel(void)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;
	char item[32] = {0, };
	char freq_value[32] = {0,};
	int channel;


	strncpy(cmd, CMD_STATUS_P2P, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(STATUS P2P) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	char* ptr = strstr(res_buffer, "frequency=");
	if (ptr==NULL)
	{
		WFD_SERVER_LOG( WFD_LOG_LOW, "Can't find frequency field...\n");
		__WFD_SERVER_FUNC_EXIT__;
		return false;
	}

	if (__get_item_value(ptr, item, freq_value) == NULL)
	{
		WFD_SERVER_LOG( WFD_LOG_LOW, "Can't get value of frequency...\n");
		__WFD_SERVER_FUNC_EXIT__;
		return false;
	}

	if (strcmp(item, "frequency")!=0)
	{
		WFD_SERVER_LOG( WFD_LOG_LOW, "Can't get frequency.... item=[%s]\n", item);
		__WFD_SERVER_FUNC_EXIT__;
		return false;
	}

	WFD_SERVER_LOG( WFD_LOG_LOW, "freq_value=[%s]\n", freq_value);

	channel = __convert_freq_to_channel(freq_value);

	WFD_SERVER_LOG( WFD_LOG_LOW, "channel=[%d]\n", channel);

	__WFD_SERVER_FUNC_EXIT__;
	return channel;

}


/* -------------------- Miracast ---------------------------*/


int wfd_ws_dsp_init(void)
{
	__WFD_SERVER_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	int enable = 1;
	char* dev_info = "0400";
	int ctrl_port = 2022;
	int max_tput = 40;
	char* cpled_sink_status = "00";

	/* param : enable*/
	snprintf(cmd, sizeof(cmd), "%s enable %d", CMD_WFD_SET, enable);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED[param : enable]!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	/* param : dev_info */
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s dev_info %s", CMD_WFD_SET, dev_info);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED[param : dev_info]!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	/* param : ctrl_port */
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s ctrl_port %d", CMD_WFD_SET, ctrl_port);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED[param : ctrl_port]!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	/* param : max_tput */
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s max_tput %d", CMD_WFD_SET, max_tput);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED[param : max_tput]!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	/* param : cpled_sink_status */
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s cpled_sink_status %s", CMD_WFD_SET, cpled_sink_status);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED[param : cpled_sink_status]!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	__WFD_SERVER_FUNC_EXIT__;
	return true;
}


int wfd_ws_get_persistent_group_info(wfd_persistent_group_info_s ** persistent_group_list, int* persistent_group_num)
{
	__WFD_SERVER_FUNC_ENTER__;
	
	char cmd[16] = {0, };
	char mac_str[18] = {0, };
	char res_buffer[1024] = {0,};
	int res_buffer_len = sizeof(res_buffer);
	int result = 0;
	int i;
	ws_network_info_s ws_persistent_group_list[MAX_PERSISTENT_GROUP_NUM];
	wfd_persistent_group_info_s	wfd_persistent_group_list[MAX_PERSISTENT_GROUP_NUM];

	memset(ws_persistent_group_list, 0, (sizeof(ws_network_info_s)*MAX_PERSISTENT_GROUP_NUM));
	memset(wfd_persistent_group_list, 0, (sizeof(wfd_persistent_group_info_s)*MAX_PERSISTENT_GROUP_NUM));

	/* Reading lists the configured networks, including stored information for persistent groups. 
	The identifier in this is used with p2p_group_add and p2p_invite to indicate witch persistent
	group is to be reinvoked. */
	strncpy(cmd, CMD_GET_LIST_NETWORKS, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(LIST_NETWORKS) result=[%d]\n", result);
	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
		*persistent_group_num = 0;
		*persistent_group_list = NULL;
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
		*persistent_group_num = 0;
		*persistent_group_list = NULL;
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	__parsing_persistent_group(res_buffer, ws_persistent_group_list, persistent_group_num);

	WFD_SERVER_LOG(WFD_LOG_LOW, "Persistent Group Count=%d\n", *persistent_group_num);
	for(i=0;i<(*persistent_group_num);i++)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "----persistent group [%d]----\n", i);		
		WFD_SERVER_LOG(WFD_LOG_LOW, "network_id=%d\n", ws_persistent_group_list[i].network_id);
		WFD_SERVER_LOG(WFD_LOG_LOW, "ssid=%s\n", ws_persistent_group_list[i].ssid);
		WFD_SERVER_LOG(WFD_LOG_LOW, "bssid=%s\n", ws_persistent_group_list[i].bssid);
		WFD_SERVER_LOG(WFD_LOG_LOW, "flags=%s\n", ws_persistent_group_list[i].flags);


// TODO: should filer by [PERSISTENT] value of flags.


		strncpy(wfd_persistent_group_list[i].ssid, ws_persistent_group_list[i].ssid, sizeof(wfd_persistent_group_list[i].ssid));
		
		unsigned char la_mac_addr[6];
		wfd_macaddr_atoe(ws_persistent_group_list[i].bssid, la_mac_addr);
		memcpy(wfd_persistent_group_list[i].go_mac_address, la_mac_addr, 6);
	}

	*persistent_group_list = &wfd_persistent_group_list[0];

	__WFD_SERVER_FUNC_EXIT__;
 	return true;

}

int wfd_ws_remove_persistent_group(wfd_persistent_group_info_s *persistent_group)
{
	__WFD_SERVER_FUNC_ENTER__;
	char cmd[32] = {0, };
	char res_buffer[1024] = {0,};
	int res_buffer_len = sizeof(res_buffer);
	int result = 0;
	int i;
	ws_network_info_s ws_persistent_group_list[MAX_PERSISTENT_GROUP_NUM];
	int persistent_group_num;
	char go_mac_str[18];
	
	memset(ws_persistent_group_list, 0, (sizeof(ws_network_info_s)*MAX_PERSISTENT_GROUP_NUM));
	memset(go_mac_str, 0, sizeof(go_mac_str));	
	snprintf(go_mac_str, 18, MACSTR, MAC2STR(persistent_group->go_mac_address));	

	strncpy(cmd, CMD_GET_LIST_NETWORKS, sizeof(cmd));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(LIST_NETWORKS) result=[%d]\n", result);
	if (result < 0)
	{
		WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED!!\n");
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WFD_SERVER_FUNC_EXIT__;
	 	return false;
	}

	__parsing_persistent_group(res_buffer, ws_persistent_group_list, &persistent_group_num);

	WFD_SERVER_LOG(WFD_LOG_LOW, "Persistent Group Count=%d\n", persistent_group_num);
	for(i=0;i<persistent_group_num;i++)
	{
		WFD_SERVER_LOG(WFD_LOG_LOW, "----persistent group [%d]----\n", i);		
		WFD_SERVER_LOG(WFD_LOG_LOW, "network_id=%d\n", ws_persistent_group_list[i].network_id);
		WFD_SERVER_LOG(WFD_LOG_LOW, "ssid=%s\n", ws_persistent_group_list[i].ssid);
		WFD_SERVER_LOG(WFD_LOG_LOW, "bssid=%s\n", ws_persistent_group_list[i].bssid);
		WFD_SERVER_LOG(WFD_LOG_LOW, "flags=%s\n", ws_persistent_group_list[i].flags);

// TODO: should filer by [PERSISTENT] value of flags.


			WFD_SERVER_LOG(WFD_LOG_LOW, "persistent_group->ssid [%s]----\n", persistent_group->ssid);
			WFD_SERVER_LOG(WFD_LOG_LOW, "ws_persistent_group_list[i].ssid [%s]----\n", ws_persistent_group_list[i].ssid);
			WFD_SERVER_LOG(WFD_LOG_LOW, "go_mac_str [%s]----\n", go_mac_str);
			WFD_SERVER_LOG(WFD_LOG_LOW, "ws_persistent_group_list[i].bssid [%s]----\n", ws_persistent_group_list[i].bssid);

		if (strcmp(persistent_group->ssid, ws_persistent_group_list[i].ssid) == 0
			&& strcmp(go_mac_str, ws_persistent_group_list[i].bssid) == 0)
		{
		
			WFD_SERVER_LOG(WFD_LOG_LOW, "----Found persistent group [%d]----\n", i);
			
			memset(cmd, 0x0, sizeof(cmd));
			memset(res_buffer, 0x0, sizeof(res_buffer));

			snprintf(cmd, sizeof(cmd), "%s %d", CMD_REMOVE_NETWORK, ws_persistent_group_list[i].network_id);
			result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
			WFD_SERVER_LOG( WFD_LOG_LOW, "__send_wpa_request(CMD_REMOVE_NETWORK) result=[%d]\n", result);

			if (result < 0)
			{
				WFD_SERVER_LOG( WFD_LOG_ASSERT, "__send_wpa_request FAILED[CMD_REMOVE_NETWORK]!!\n");
			 	__WFD_SERVER_FUNC_EXIT__;
			 	return false;
			}
			if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
			{
			 	__WFD_SERVER_FUNC_EXIT__;
			 	return false;
			}


			break;
		}

	}


	
	__WFD_SERVER_FUNC_EXIT__;
 	return true;
}



