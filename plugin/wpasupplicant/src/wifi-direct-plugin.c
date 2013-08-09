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

//#include "wifi-direct-utils.h"
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
char g_wps_pin[WPS_PIN_LEN];
static int g_wps_event_block;
static unsigned char g_inviting_peer_mac_address[6];

enum current_conn_direction
{
	CONN_DIRECTION_NONE,
	CONN_DIRECTION_INCOMING,
	CONN_DIRECTION_OUTGOING,
};

static struct wfd_oem_operations supplicant_ops =
{
	.wfd_oem_init = wfd_ws_init,
	.wfd_oem_destroy = wfd_ws_destroy,
	.wfd_oem_activate = wfd_ws_activate,
	.wfd_oem_deactivate = wfd_ws_deactivate,
	.wfd_oem_connect = wfd_ws_connect,
	.wfd_oem_wps_pbc_start = wfd_ws_wps_pbc_start,
	.wfd_oem_wps_pin_start = wfd_ws_wps_pin_start,
	.wfd_oem_disconnect = wfd_ws_disconnect,
	.wfd_oem_disconnect_sta = wfd_ws_disconnect_sta,
	.wfd_oem_reject_connection = wfd_ws_reject_connection,
	.wfd_oem_is_discovery_enabled = wfd_ws_is_discovery_enabled,
	.wfd_oem_start_discovery = wfd_ws_start_discovery,
	.wfd_oem_restart_discovery = wfd_ws_restart_discovery,
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
	.wfd_oem_set_persistent_group_enabled = wfd_ws_set_persistent_reconnect,
	.wfd_oem_connect_for_persistent_group = wfd_ws_connect_for_persistent_group,
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
		WDP_LOGE( "pipe read error, Error=[%s]\n",strerror(errno));
		return 0;  // false
	}

	if (g_oem_event_callback != NULL)
		g_oem_event_callback(event);

	return true;
}

int __send_wpa_request(int sockfd, char *cmd, char *reply, size_t reply_buf_len)
{
	__WDP_LOG_FUNC_ENTER__;
 
	int result = 0;
	size_t cmd_len;

	int pollret = 0;
	struct pollfd pollfd;
	int timeout = 6000; /** for 6.0 sec */

	if (sockfd < 3 )
	{
		WDP_LOGE("Invalid argument sfd=[%d]\n", sockfd);
		return false;
	}

	if(cmd == NULL)
	{
		WDP_LOGE("Invalid argument. Command is NULL\n");
		return false;
	}
	cmd_len = strlen(cmd);
	WDP_LOGI("cmd [%s] cmd_len[%d]\n", cmd, cmd_len);

	result = write(sockfd, cmd, cmd_len);
	if ( result < 0)
	{
		WDP_LOGE( "Send cmd failed: [%d]\n", result);
		__WDP_LOG_FUNC_EXIT__;
		return false;
	}

	for (;;)
	{
		pollfd.fd = sockfd;
		pollfd.events = POLLIN | POLLERR | POLLHUP;
		pollret = poll(&pollfd, 1, timeout);

		if (pollret == 0)
		{
			WDP_LOGI( "POLLing timeout. Nothing to read.\n");
			__WDP_LOG_FUNC_EXIT__;
			return 0;
		}
		else if (pollret < 0)
		{
			WDP_LOGE("Polling error [%d]\n", pollret);
			__WDP_LOG_FUNC_EXIT__;
			return false;
		}
		else
		{
			if (pollfd.revents == POLLIN)
			{
				WDP_LOGD("POLLIN \n");
				result = read(sockfd, (char *) reply, reply_buf_len);

				WDP_LOGD("sockfd %d retval %d\n", sockfd, result);
				WDP_LOGD("reply[%s]\n", reply);

				if (result < 0)
				{
					WDP_LOGE( "Error!!! reading data, error [%s]\n", strerror(errno));
					__WDP_LOG_FUNC_EXIT__;
					return false;
				}
				break;
			}
			else
			{
				WDP_LOGD("POLL EVENT=%d ignored\n", pollfd.revents);
				__WDP_LOG_FUNC_EXIT__;
				return false;
			}
		}
	}

	__WDP_LOG_FUNC_EXIT__;
	return result;
}


int __create_ctrl_intf(char *ctrl_intf_name, char *path)
{
	__WDP_LOG_FUNC_ENTER__;

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
		WDP_LOGE( "Error!!! creating sync socket. Error = [%s].\n", strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	WDP_LOGI( "Created socket [%d]\n", sockfd);

	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sun_family = AF_UNIX;
	strcpy(servAddr.sun_path, path);
	len = sizeof(servAddr.sun_family) + strlen(path);

	WDP_LOGD( "Connecting to server socket to register socket [%d]\n", sockfd);

	memset(&localAddr, 0, sizeof(localAddr));
	localAddr.sun_family = AF_UNIX;
	strcpy(localAddr.sun_path, local_path);

	if (bind(sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0)
	{
		WDP_LOGE( "Error!!! bind(). Error = [%s]. Try again..\n", strerror(errno));
		
		unlink(localAddr.sun_path);
		if (bind(sockfd, (struct sockaddr*)&localAddr, sizeof(localAddr)) < 0)
		{
			WDP_LOGE( "Error!!! bind(). Error = [%s]. Give up..\n", strerror(errno));
			close(sockfd);
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
	}

	errno = 0;
	if ((ret = connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr))) < 0)
	{

		if (unlink(path) < 0)
		{
			WDP_LOGE("unlink[ctrl_iface], Error=[%s]", strerror(errno));
			close(sockfd);
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}

		if (connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0)
		{
			WDP_LOGE("bind[PF_UNIX], Error=[%s]", strerror(errno));
			close(sockfd);
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
		WDP_LOGI( "Successfully replaced leftover ctrl_iface socket [%s]\n", path);
	}

	__WDP_LOG_FUNC_EXIT__;

	return sockfd;
}


static int __read_socket_cb(int sockfd, char *dataptr, int datalen)
{
	__WDP_LOG_FUNC_ENTER__;

	int pollret = 0;
	struct pollfd pollfd;
	int timeout = 2000; /** for 2 sec */
	int retval = 0;

	WDP_LOGD( "Reading msg from socketfd=[%d]\n", sockfd);

	if (sockfd <= 0)
	{
		WDP_LOGE( "Error!!! Invalid socket FD [%d]\n", sockfd);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if ((dataptr == NULL) || (datalen <= 0))
	{
		WDP_LOGE( "Error!!! Invalid parameter\n");
		__WDP_LOG_FUNC_EXIT__;

		return -1;
	}

	pollfd.fd = sockfd;
	pollfd.events = POLLIN | POLLERR | POLLHUP;
	pollret = poll(&pollfd, 1, timeout);

	if (pollret > 0)
	{
		if (pollfd.revents == POLLIN)
		{
			WDP_LOGD( "POLLIN\n");

			errno = 0;
			retval = read(sockfd, (char *) dataptr, datalen);
			WDP_LOGD( "sockfd %d retval %d\n", sockfd, retval);
			if (retval <= 0)
			{
				WDP_LOGD( "Error!!! reading data, Error=[%s]\n", strerror(errno));
			}
			__WDP_LOG_FUNC_EXIT__;
			return retval;
		}
		else if (pollfd.revents & POLLHUP)
		{
			WDP_LOGD( "POLLHUP\n");
			__WDP_LOG_FUNC_EXIT__;

			return 0;
		}
		else if (pollfd.revents & POLLERR)
		{
			WDP_LOGD( "POLLERR\n");
			__WDP_LOG_FUNC_EXIT__;
			return 0;
		}
	}
	else if (pollret == 0)
	{
		WDP_LOGD( "POLLing timeout  \n");
		__WDP_LOG_FUNC_EXIT__;
		return 0;
	}
	else
	{
		WDP_LOGD( "Polling unknown error \n");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDP_LOG_FUNC_EXIT__;
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
	WDP_LOGE( "** Failed to get IP address!!\n");
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
	__WDP_LOG_FUNC_ENTER__;
	char *tmp_str = NULL;
	int i = 0;

	if(value == NULL)
		return -1;
	
	tmp_str = strstr(str, key);
	if(tmp_str == NULL)
	{
		WDP_LOGE( "Key[%s] is not found\n", key);
		return -1;
	}
	tmp_str = tmp_str + strlen(key) + 1;
	//WDP_LOGD( "tmp_str [%s]\n", tmp_str);

	for(i = 0; tmp_str[i]; i++)
	{
		if(tmp_str[i] == '\n' || tmp_str[i] == '\r' || tmp_str[i] == ' ')
		{
			break;
		}
	}

	memcpy(value, tmp_str, i);
	value[i] = '\0';

	WDP_LOGD( "extracted value [%s]\n", value);

	__WDP_LOG_FUNC_EXIT__;
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
	strncpy(group->ssid, value, NETWORK_SSID_LEN);
	group->ssid[NETWORK_SSID_LEN-1] = '\0';

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
	strncpy(group->bssid, value, NETWORK_BSSID_LEN);
	group->bssid[NETWORK_BSSID_LEN-1] = '\0';

	while(!__is_item_char(*p))
	{
		p++;
	}

	/* flags */
	c = 0;
	memset(value, 0x00, sizeof(value));
	while(*p != '\n')
	{
		value[c++] = *p++;
	}
	strncpy(group->flags, value, NETWORK_FLAGS_LEN);
	group->flags[NETWORK_FLAGS_LEN-1] = '\0';

	p++;
	return p;
}


int __parsing_peer(char* buf, ws_discovered_peer_info_s* peer)
{
	__WDP_LOG_FUNC_ENTER__;

	char* ptr = buf;
	char item[64];
	char value[128];
	int i;
	int item_id;

	memset(peer, 0, sizeof(ws_discovered_peer_info_s));

	// Get mac address
	strncpy(peer->mac, ptr, MACSTR_LEN);
	peer->mac[MACSTR_LEN-1]='\0';
	ptr += 17+1;

	WDP_LOGD( "mac=%s\n", peer->mac);

	for(;;)
	{
		ptr = __get_item_value(ptr, item, value);
		if (ptr==NULL)
			break;

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
			strncpy(peer->wps_method, value, WPS_METHOD_LEN);
			peer->wps_method[WPS_METHOD_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_INTERFACE_ADDR:
			strncpy(peer->interface_addr, value, MACSTR_LEN);
			peer->interface_addr[MACSTR_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_MEMBER_IN_GO_DEV:
			strncpy(peer->member_in_go_dev, value, MACSTR_LEN);
			peer->member_in_go_dev[MACSTR_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_MEMBER_IN_GO_IFACE:
			strncpy(peer->member_in_go_iface, value, MACSTR_LEN);
			peer->member_in_go_iface[MACSTR_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_PRI_DEV_TYPE:
			strncpy(peer->pri_dev_type, value, DEVICE_TYPE_LEN);
			peer->pri_dev_type[DEVICE_TYPE_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_DEVICE_NAME:
			strncpy(peer->device_name, value, DEVICE_NAME_LEN);
			peer->device_name[DEVICE_NAME_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_MANUFACTURER:
			strncpy(peer->manufacturer, value, MANUFACTURER_LEN);
			peer->manufacturer[MANUFACTURER_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_MODEL_NAME:
			strncpy(peer->model_name, value, MODEL_NAME_LEN);
			peer->model_name[MODEL_NAME_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_MODEL_NUMBER:
			strncpy(peer->model_number, value, MODEL_NUMBER_LEN);
			peer->model_number[MODEL_NUMBER_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_SERIAL_NUMBER:
			strncpy(peer->serial_number, value, SERIAL_NUMBER_LEN);
			peer->serial_number[SERIAL_NUMBER_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_CONFIG_METHODS:
			{
				char* p = value;
				unsigned long int ret = 0;
				ret = strtoul(p, &p, 16);
				if (ret == ULONG_MAX)
				{
					peer->config_methods = 0;
					WDP_LOGE( "config_methods has wrong value=[%s], Error=[%s]\n", value, strerror(errno));
				}
				else
				{
					peer->config_methods = (unsigned int)ret;
					WDP_LOGD( "config_methods value=[%x <- %s]\n", peer->config_methods, value);
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
					WDP_LOGE( "device_capab has wrong value=[%s], Error=[%s]\n", value, strerror(errno));
				}
				else
				{
					peer->dev_capab = (unsigned int)ret;
					WDP_LOGD( "device_capab value=[%x <- %s]\n", peer->dev_capab, value);
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
					WDP_LOGE( "group_capab has wrong value=[%s], Error=[%s]\n", value, strerror(errno));
				}
				else
				{
					peer->group_capab = (unsigned int)ret;
					WDP_LOGD( "group_capab value=[%x <- %s]\n", peer->group_capab, value);
				}
			}
			break;
		case WS_PEER_INFO_GO_NEG_REQ_SENT:
			peer->go_neg_req_sent = atoi(value);
			break;
		case WS_PEER_INFO_GO_STATE:
			strncpy(peer->go_state, value, GO_STATE_LEN);
			peer->go_state[GO_STATE_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_DIALOG_TOKEN:
			peer->dialog_token = atoi(value);
			break;
		case WS_PEER_INFO_INTENDED_ADDR:
			strncpy(peer->intended_addr, value, MACSTR_LEN);
			peer->intended_addr[MACSTR_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_COUNTRY:
			strncpy(peer->country, value, COUNTRY_CODE_LEN);
			peer->country[COUNTRY_CODE_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_OPER_FREQ:
			peer->oper_freq = atoi(value);
			break;
		case WS_PEER_INFO_REQ_CONFIG_METHODS:
			peer->req_config_methods = atoi(value);
			break;
		case WS_PEER_INFO_FLAGS:
			strncpy(peer->flags, value, PEER_FLAGS_LEN);
			peer->flags[PEER_FLAGS_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_STATUS:
			strncpy(peer->status, value, PEER_STATUS_LEN);
			peer->status[PEER_STATUS_LEN-1] = '\0';
			break;
		case WS_PEER_INFO_WAIT_COUNT:
			peer->wait_count = atoi(value);
			break;
		case WS_PEER_INFO_INVITATION_REQS:
			peer->invitation_reqs = atoi(value);
			break;
		case WS_PEER_INFO_OPER_SSID:
			strncpy(peer->oper_ssid, value, DEVICE_NAME_LEN);
			peer->oper_ssid[DEVICE_NAME_LEN-1] = '\0';
			break;

/*----- Miracast -----*/
		case WS_PEER_INFO_IS_WFD_DEVICE:
			peer->is_wfd_device = atoi(value);
			break;

 		default:
			WDP_LOGD( "unknown field\n");
			break;
		}
	}

 	__WDP_LOG_FUNC_EXIT__;
	return 0;
}


int __parsing_persistent_group(char* buf, ws_network_info_s ws_persistent_group_list[], int* persistent_group_num)
{
	__WDP_LOG_FUNC_ENTER__;

	char* ptr = buf;
	ws_network_info_s group;
	int count;

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
		snprintf(ws_persistent_group_list[count].ssid, NETWORK_SSID_LEN, "%s", group.ssid);
		snprintf(ws_persistent_group_list[count].bssid, NETWORK_BSSID_LEN, "%s", group.bssid);
		snprintf(ws_persistent_group_list[count].flags, NETWORK_FLAGS_LEN, "%s", group.flags);
		count++;
	}

	*persistent_group_num = count;

 	__WDP_LOG_FUNC_EXIT__;
	return 0;
	
}

void __parsing_ws_event(char* buf, ws_event_s *event)
{
	__WDP_LOG_FUNC_ENTER__;

	char* ptr = buf;
	char event_str[64];
	int i;
	ws_field_id_e event_id;
	int res = 0;

	if (NULL == buf)
	{
		WDP_LOGE( "ERROR : buf is NULL!!\n");
		return;
	}

	ptr = ptr +3;
	ptr = __get_event_str(ptr, event_str);

	WDP_LOGD( "event str [%s]\n", event_str);

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
			WDP_LOGD( "WS EVENT : [WS_EVENT_DISCOVER_FOUND_PEER]\n");
		break;

		case WS_EVENT_PROVISION_DISCOVERY_RESPONSE:
			event->id = WS_EVENT_PROVISION_DISCOVERY_RESPONSE;
			ptr = __get_event_str(ptr, event_str);
			strncpy(event->peer_mac_address, event_str, MACSTR_LEN);
			event->peer_mac_address[MACSTR_LEN-1] = '\0';
			WDP_LOGD( "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_RESPONSE]\n");
			WDP_LOGD( "WS EVENT : [MAC : %s]\n", event_str);
		break;

		case WS_EVENT_PROVISION_DISCOVERY_PBC_REQ:
			event->id = WS_EVENT_PROVISION_DISCOVERY_PBC_REQ;
			res = __extract_value_str(ptr, "p2p_dev_addr", event->peer_mac_address);
			if(res <= 0)
			{
				WDP_LOGE( "Failed to extract p2p_dev_addr");
				// TO-DO: stop parsing and make event callback function stop
				__WDP_LOG_FUNC_EXIT__;
				return;
			}
			res = __extract_value_str(ptr, "name" , event->peer_ssid);
			if(res <= 0)
			{
				WDP_LOGE( "Failed to extract name(ssid)");
				// TO-DO: stop parsing and make event callback function stop
				__WDP_LOG_FUNC_EXIT__;
				return;
			}
			WDP_LOGD( "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_PBC_REQ]\n");
			WDP_LOGD( "WS EVENT : [MAC : %s]\n", event_str);
		break;

		case WS_EVENT_PROVISION_DISCOVERY_DISPLAY:
			event->id = WS_EVENT_PROVISION_DISCOVERY_DISPLAY;
			res = __extract_value_str(ptr, "p2p_dev_addr", event->peer_mac_address);
			if(res <= 0)
			{
				WDP_LOGD( "Failed to extract p2p_dev_addr");
				WDP_LOGD( "Prov disc Response : DISPLAY");
				event->id = WS_EVENT_PROVISION_DISCOVERY_RESPONSE_DISPLAY;
				ptr = __get_event_str(ptr, event_str);
				strncpy(event->peer_mac_address, event_str, MACSTR_LEN);
				event->peer_mac_address[MACSTR_LEN-1] = '\0';
				WDP_LOGD( "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_RESPONSE_DISPLAY]\n");
				WDP_LOGD( "WS EVENT : [MAC : %s]\n", event_str);
				ptr = __get_event_str(ptr, event_str);
				strncpy(event->wps_pin, event_str, WPS_PIN_LEN);
				event->wps_pin[WPS_PIN_LEN-1] = '\0';
				WDP_LOGD( "WS EVENT : [PIN : %s]\n", event_str);
				__WDP_LOG_FUNC_EXIT__;
				return;
			}
			ptr = __get_event_str(ptr, event_str); /* Stepping Mac Addr */
			ptr = __get_event_str(ptr, event_str); /* Stepping PIN */
			memset(event->wps_pin, 0x00, sizeof(event->wps_pin));
			strncpy(event->wps_pin, event_str, WPS_PIN_LEN);
			event->wps_pin[WPS_PIN_LEN-1] = '\0';
			WDP_LOGD( "WS EVENT : [PIN : %s]\n", event_str);

			res = __extract_value_str(ptr, "name" , event->peer_ssid);
			if(res <= 0)
			{
				WDP_LOGE( "Failed to extract name(ssid)");
				__WDP_LOG_FUNC_EXIT__;
				return;
			}
			WDP_LOGD( "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_DISPLAY]\n");
			WDP_LOGD( "WS EVENT : [MAC : %s]\n", event_str);
		break;

		case WS_EVENT_PROVISION_DISCOVERY_KEYPAD:
			event->id = WS_EVENT_PROVISION_DISCOVERY_KEYPAD;
			res = __extract_value_str(ptr, "p2p_dev_addr", event->peer_mac_address);
			if(res <= 0)
			{
				WDP_LOGD( "Failed to extract p2p_dev_addr");
				WDP_LOGD( "Prov disc Response : KEYPAD");
				event->id = WS_EVENT_PROVISION_DISCOVERY_RESPONSE_KEYPAD;
				ptr = __get_event_str(ptr, event_str);
				strncpy(event->peer_mac_address, event_str, MACSTR_LEN);
				event->peer_mac_address[MACSTR_LEN-1] = '\0';
				WDP_LOGD( "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_RESPONSE_KEYPAD]\n");
				WDP_LOGD( "WS EVENT : [MAC : %s]\n", event_str);
				__WDP_LOG_FUNC_EXIT__;
				return;
			}
			res = __extract_value_str(ptr, "name" , event->peer_ssid);
			if(res <= 0)
			{
				WDP_LOGE( "Failed to extract name(ssid)");
				__WDP_LOG_FUNC_EXIT__;
				return;
			}
			WDP_LOGD( "WS EVENT : [WS_EVENT_PROVISION_DISCOVERY_KEYPAD]\n");
			WDP_LOGD( "WS EVENT : [MAC : %s]\n", event_str);
		break;

		case WS_EVENT_GROUP_FORMATION_SUCCESS:
		case WS_EVENT_GROUP_FORMATION_FAILURE:
			event->id = event_id;
		break;

		case WS_EVENT_GROUP_STARTED:
			{
				event->id = WS_EVENT_GROUP_STARTED;
				WDP_LOGD( "WS EVENT : [WS_EVENT_GROUP_STARTED]\n");
				if (strstr(ptr, "client")) {
					WDP_LOGD("[Group Client]");
					int res = 0;
					char *go_dev_addr = NULL;
					go_dev_addr = (char*) calloc(1, MACSTR_LEN);
					res = __extract_value_str(ptr, "go_dev_addr", go_dev_addr);
					if(res > 0) {
						strncpy(event->peer_mac_address, go_dev_addr, MACSTR_LEN);
						event->peer_mac_address[MACSTR_LEN-1] = '\0';
					}
					free(go_dev_addr);
					WDP_LOGD( "connected peer mac address [%s]", event->peer_mac_address);
				} else {
					WDP_LOGD("[Group Owner]");
				}

				/* for checking persistent group */
				if (strstr(ptr, "PERSISTENT")) {
					WDP_LOGD( "[PERSISTENT GROUP]");
					event->id = WS_EVENT_PERSISTENT_GROUP_STARTED;
				}
			}
		break;

		case WS_EVENT_GROUP_REMOVED:
			event->id = WS_EVENT_GROUP_REMOVED;
			WDP_LOGD( "WS EVENT : [WS_EVENT_GROUP_REMOVED]\n");
		break;

		case WS_EVENT_TERMINATING:
			event->id = WS_EVENT_TERMINATING;
			WDP_LOGD( "WS EVENT : [WS_EVENT_TERMINATING]\n");
		break;
#if 1
		case WS_EVENT_CONNECTED:
			{
				WDP_LOGD( "WS EVENT : [WS_EVENT_CONNECTED]\n");
				int res = 0;
				char *intf_addr;
				intf_addr = (char*) calloc(1, MACSTR_LEN);
				event->id = WS_EVENT_CONNECTED;
				res = __extract_value_str(ptr, "to", intf_addr);
				if(res > 0)
					wfd_macaddr_atoe(intf_addr, g_assoc_sta_mac);
				WDP_LOGD( "connected peer interface mac address [%s]", intf_addr);
				free(intf_addr);
			}
		break;
#endif
		case WS_EVENT_STA_CONNECTED:
			{
				WDP_LOGD( "WS EVENT : [WS_EVENT_STA_CONNECTED]\n");
				int res = 0;
				event->id = WS_EVENT_STA_CONNECTED;

				ptr = __get_event_str(ptr, event_str);
				strncpy(event->peer_intf_mac_address, event_str, MACSTR_LEN);
				event->peer_intf_mac_address[MACSTR_LEN-1] = '\0';

				res = __extract_value_str(ptr, "dev_addr", event->peer_mac_address);
				if (res < 0)
					WDP_LOGD("Key %s is not found", "dev_addr");
				else if (res == 0)
					WDP_LOGD("Empty value");
				else
					WDP_LOGD( "connected peer mac address [%s]", event->peer_intf_mac_address);
			}
		break;

		case WS_EVENT_DISCONNECTED:
			{
				WDP_LOGD( "WS EVENT : [WS_EVENT_DISCONNECTED]\n");
				int res = 0;
				char *intf_addr;
				intf_addr = (char*) calloc(1, MACSTR_LEN);
				event->id = WS_EVENT_DISCONNECTED;
				res = __extract_value_str(ptr, "to", intf_addr);
				if(res > 0) {
					strncpy(event->peer_mac_address, intf_addr, MACSTR_LEN);
					event->peer_mac_address[MACSTR_LEN-1] = '\0';
				}
				free(intf_addr);
				WDP_LOGD( "disconnected peer mac address [%s]", event->peer_mac_address);
			}
		break;

		case WS_EVENT_STA_DISCONNECTED:
			{
				WDP_LOGD( "WS EVENT : [WS_EVENT_STA_DISCONNECTED]\n");
				int res = 0;
				event->id = WS_EVENT_STA_DISCONNECTED;

				ptr = __get_event_str(ptr, event_str);
				strncpy(event->peer_intf_mac_address, event_str, MACSTR_LEN);
				event->peer_intf_mac_address[MACSTR_LEN-1] = '\0';

				res = __extract_value_str(ptr, "dev_addr", event->peer_mac_address);
				if (res < 0)
					WDP_LOGD("Key %s is not found", "dev_addr");
				else if (res == 0)
					WDP_LOGD("Empty value");
				else
					WDP_LOGD( "disconnected peer mac address [%s]", event->peer_intf_mac_address);
			}
		break;

		case WS_EVENT_INVITATION_REQ:
			{
				WDP_LOGD( "WS EVENT : [WS_EVENT_INVITATION_REQ]\n");
				int res = 0;
				event->id = WS_EVENT_INVITATION_REQ;

#if 1		
				res = __extract_value_str(ptr, "go_dev_addr", event->peer_mac_address);
#else
				res = __extract_value_str(ptr, "bssid", event->peer_mac_address);
#endif
				if(res <= 0)
				{
					WDP_LOGE( "Failed to extract p2p_dev_addr");
					__WDP_LOG_FUNC_EXIT__;
					return;
				}
 				WDP_LOGD( "WS EVENT : [GO MAC : %s]\n", event->peer_mac_address);
			}
		break;

		case WS_EVENT_INVITATION_RSP:
			{
				WDP_LOGD( "WS EVENT : [WS_EVENT_INVITATION_RSP]\n");
				//int res = 0;
				event->id = WS_EVENT_INVITATION_RSP;

#if 0		
				res = __extract_value_str(ptr, "status", );
				if(res <= 0)
				{
				    WDP_LOGE( "Failed to extract p2p_dev_addr");
				    return;
				}
 				WDP_LOGD( "WS EVENT : [GO MAC : %s]\n", event->peer_mac_address);
#endif

			}
		break;
		case WS_EVENT_GO_NEG_REQUEST:
			{
				WDP_LOGD( "WS EVENT : [WS_EVENT_GO_NEG_REQUEST]");

				event->id = WS_EVENT_GO_NEG_REQUEST;
				ptr = __get_event_str(ptr + 19, event_str);
				strncpy(event->peer_intf_mac_address, event_str, MACSTR_LEN);
				event->peer_intf_mac_address[MACSTR_LEN-1] = '\0';
			}
		break;

		case WS_EVENT_GO_NEG_FAILURE:
			{
				WDP_LOGD("WS EVENT : [WS_EVENT_GO_NEG_FAILURE]");
				char status[16] = {0, };
				event->id = WS_EVENT_GO_NEG_FAILURE;
				ptr = __extract_value_str(ptr, "status", status);
				event->msg = atoi(status);
				WDP_LOGD("Status [%d]", event->msg);
			}
		break;

		case WS_EVENT_WPS_FAIL:
			{
				WDP_LOGD("WS EVENT : [WS_EVENT_WPS_FAIL]");
				char config_error[4] = {0, };
				event->id = WS_EVENT_WPS_FAIL;
				ptr = __extract_value_str(ptr, "config_error", config_error);
				event->msg = atoi(config_error);
			}
		break;

 		default:
			WDP_LOGE( "ERROR : unknown event !!\n");
		break;
	}

 	__WDP_LOG_FUNC_EXIT__;

	return;
	
}

int __store_persistent_peer(int network_id, char* persistent_group_ssid, char* peer_mac_address)
{
	__WDP_LOG_FUNC_ENTER__;

	char buf[100] = "";
	FILE *fp = NULL;

	snprintf(buf, sizeof(buf), "%d %s %s\n",network_id, persistent_group_ssid, peer_mac_address);

	fp = fopen(PERSISTENT_PEER_PATH, "a");
	if (NULL == fp)
	{
		WDP_LOGE( "ERROR : file open failed!! [persistent-peer]\n");
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}

	//fseek(fp, 0, SEEK_END);
	fputs(buf, fp);
	fclose(fp);

	__WDP_LOG_FUNC_EXIT__;
	return true;

}

int __get_network_id_from_network_list_with_ssid(char* persistent_group_ssid)
{
	__WDP_LOG_FUNC_ENTER__;

	int persistent_group_count = 0;
	int i;
	int result;
	wfd_persistent_group_info_s* plist;
	int network_id = -1;

	WDP_LOGD( "search with persistent_group_ssid = [%s]\n",persistent_group_ssid);

	result = wfd_ws_get_persistent_group_info(&plist, &persistent_group_count);
	if (result == true)
	{
		if (persistent_group_count > 0)
		{
			for(i=0; i<persistent_group_count; i++)
			{
				WDP_LOGD( "plist[%d].ssid=[%s]\n", i,plist[i].ssid);
				if (strcmp(plist[i].ssid, persistent_group_ssid) == 0)
				{
					WDP_LOGD( "Found peer in persistent group list [network id : %d]\n", plist[i].network_id);
					network_id = plist[i].network_id;
					free(plist);
					return network_id;
				}
			}
			WDP_LOGE( "There is no Persistent Group has ssid[%s]\n", persistent_group_ssid);
			free(plist);
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
		else
		{
			WDP_LOGE( "have no Persistent Group!!\n");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
	}
	else
	{
		WDP_LOGE( "Error!! wfd_ws_get_persistent_group_info() failed..\n");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
}

int __get_network_id_from_network_list_with_go_mac(char* go_mac_address)
{
	__WDP_LOG_FUNC_ENTER__;

	int persistent_group_count = 0;
	int i;
	int result;
	wfd_persistent_group_info_s* plist;
	char mac_str[18] = {0, };
	int network_id = -1;

	WDP_LOGD( "search with persistent_group go_mac_address = [%s]\n",go_mac_address);

	result = wfd_ws_get_persistent_group_info(&plist, &persistent_group_count);
	if (result == true)
	{
		if (persistent_group_count > 0)
		{
			for(i=0; i<persistent_group_count; i++)
			{
				snprintf(mac_str, MACSTR_LEN, MACSTR, MAC2STR(plist[i].go_mac_address));
				WDP_LOGD( "plist[%d].go_mac_address=[%s]\n", i,mac_str);
				if (strcmp(mac_str, go_mac_address) == 0)
				{
					WDP_LOGD( "Found peer in persistent group list [network id : %d]\n", plist[i].network_id);
					network_id = plist[i].network_id;
					free(plist);
				 	__WDP_LOG_FUNC_EXIT__;
					return network_id;
				}
			}
			WDP_LOGE( "There is no Persistent Group has go mac[%s]\n", go_mac_address);
			free(plist);
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
		else
		{
			WDP_LOGE( "have no Persistent Group!!\n");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
	}
	else
	{
		WDP_LOGE( "Error!! wfd_ws_get_persistent_group_info() failed..\n");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
}


int __get_network_id_from_persistent_client_list_with_mac(char* peer_mac_address)
{
	__WDP_LOG_FUNC_ENTER__;

	FILE *fp = NULL;
	char buf[100] = "";
	int n = 0;
	int network_id;
	char stored_ssid[NETWORK_SSID_LEN] = {0, };
	char stored_peer_mac[MACSTR_LEN] = {0, };

	fp = fopen(PERSISTENT_PEER_PATH, "r");
	if (NULL == fp)
	{
		WDP_LOGE( "ERROR : file open failed!! [persistent-peer]\n");
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}

	while(fgets(buf, 100, fp) != NULL)
	{
		n = sscanf(buf,"%d %s %s", &network_id, stored_ssid, stored_peer_mac);
		WDP_LOGD( "network_id=[%d], ssid=[%s], peer_mac=[%s]\n",network_id, stored_ssid, stored_peer_mac);

		if (strcmp(stored_peer_mac, peer_mac_address) == 0)
		{
			fclose(fp);
			return network_id;
		}
	}
	fclose(fp);

	WDP_LOGD( "Can not find peer mac in persistent peer list\n");

	__WDP_LOG_FUNC_EXIT__;
	return -1;

}

bool __is_already_stored_persistent_client(int network_id, char* peer_mac_address)
{
	__WDP_LOG_FUNC_ENTER__;

	FILE *fp = NULL;
	char buf[100] = "";
	int n = 0;
	int stored_network_id;
	char stored_ssid[NETWORK_SSID_LEN] = {0, };
	char stored_peer_mac[MACSTR_LEN] = {0, };

	fp = fopen(PERSISTENT_PEER_PATH, "r");
	if (NULL == fp)
	{
		WDP_LOGE( "ERROR : file open failed!! [persistent-peer]\n");
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}

	while(fgets(buf, 100, fp) != NULL)
	{
		n = sscanf(buf,"%d %s %s", &stored_network_id, stored_ssid, stored_peer_mac);
		WDP_LOGD( "stored_network_id=[%d], stored_ssid=[%s], stored_peer_mac=[%s]\n",stored_network_id, stored_ssid, stored_peer_mac);

		if ((strcmp(stored_peer_mac, peer_mac_address) == 0)
			&& (stored_network_id == network_id))
		{
			WDP_LOGD( "found peer in persistent peer list\n");
			fclose(fp);
			__WDP_LOG_FUNC_EXIT__;
			return true;
		}
	}
	fclose(fp);

	WDP_LOGD( "Can not find peer in persistent peer list\n");
	__WDP_LOG_FUNC_EXIT__;
	return false;

}

int __get_persistent_group_clients(void)
{
	__WDP_LOG_FUNC_ENTER__;

	FILE *fp = NULL;
	char buf[100] = "";
	int n = 0;
	int network_id;
	char ssid[NETWORK_SSID_LEN] = {0, };
	char peer_mac[MACSTR_LEN] = {0, };

	fp = fopen(PERSISTENT_PEER_PATH, "r");
	if (NULL == fp)
	{
		WDP_LOGE( "ERROR : file open failed!! [persistent-peer]\n");
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}

	while(fgets(buf, 100, fp) != NULL)
	{
		n = sscanf(buf,"%d %s %s", &network_id, ssid, peer_mac);
		WDP_LOGD( "network_id=[%d], ssid=[%s], peer_mac=[%s]\n",network_id, ssid, peer_mac);
	}
	fclose(fp);

	__WDP_LOG_FUNC_EXIT__;
	return true;

}

int __send_invite_request_with_network_id(int network_id, unsigned char dev_mac_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[128] = {0, };
	char mac_str[MACSTR_LEN] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(mac_str, 18, MACSTR, MAC2STR(dev_mac_addr));
	snprintf(cmd, sizeof(cmd), "%s persistent=%d peer=%s", CMD_SEND_INVITE_REQ, network_id, mac_str);

	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(p2p_invite persistent=%d peer=%s) result=[%d]\n", network_id, mac_str, result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "Invite... peer-MAC [%s]\n", mac_str);

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int glist_compare_peer_mac_cb(const void* data1, const void* data2)
{
	char *mac_str1 = (char*) data1;
	char *mac_str2 = (char*) data2;
	int r = 0;

	if (data1==NULL || data2==NULL)
	{
		WDP_LOGE( "Error!! data is NULL\n");
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
	WDP_LOGD( "Connected peer[%d] mac=[%s]\n", count, mac_str);
	*(int*)user_data = count+1;
}

void wfd_ws_print_connected_peer()
{
	WDP_LOGD( "Connected Peer Table\n");
	int count = 0;
	g_list_foreach(g_conn_peer_addr, glist_print_connected_peer_cb, &count);	
	WDP_LOGD( "Count=%d\n", count);
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
	__WDP_LOG_FUNC_ENTER__;

	int sockfd = g_monitor_sockfd;
	char buffer[4096] = {0, };
	int n = 0;
	ws_event_s event = {0,};

	// Read socket
	if ( (n = __read_socket_cb(sockfd, buffer, sizeof(buffer))) < 0)	
	{
		WDP_LOGE( "Error!!! Reading Async Event[%d]\n", sockfd);
		__WDP_LOG_FUNC_EXIT__;
		return false;
	}

	WDP_LOGD( "Received Event:[%d, %s]\n", n, buffer);

	__parsing_ws_event(buffer, &event);

	WDP_LOGD( "EVENT ID = %d\n", event.id);

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

			WDP_LOGD( "wfd_server->current_peer.is_group_owner=[%d]\n", wfd_server->current_peer.is_group_owner);
			wfd_ws_connect(la_mac_addr, WIFI_DIRECT_WPS_TYPE_PBC);
		}
		break;

		case WS_EVENT_PROVISION_DISCOVERY_RESPONSE_DISPLAY:
		{
			if (g_wps_event_block)
				break;

			g_wps_event_block = 1;
			unsigned char la_mac_addr[6];
			wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);
			memset(g_incomming_peer_mac_address, 0, sizeof(g_incomming_peer_mac_address));
			memcpy(g_incomming_peer_mac_address, la_mac_addr, 6);
			memset(g_wps_pin, 0x00, sizeof(g_wps_pin));
			memcpy(&g_wps_pin, event.wps_pin, 8);
			WDP_LOGD( "MAC ADDR = " MACSTR "(a)\tPIN = %s\n", MAC2STR(g_incomming_peer_mac_address), g_wps_pin);
			g_noti_cb(WFD_EVENT_PROV_DISCOVERY_RESPONSE_WPS_DISPLAY);
		}
		break;

		case WS_EVENT_PROVISION_DISCOVERY_RESPONSE_KEYPAD:
		{
			if (g_wps_event_block)
				break;

			g_wps_event_block = 1;
			unsigned char la_mac_addr[6];
			wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);
			memset(g_incomming_peer_mac_address, 0, sizeof(g_incomming_peer_mac_address));
			memcpy(&g_incomming_peer_mac_address, la_mac_addr, 6);
			g_noti_cb(WFD_EVENT_PROV_DISCOVERY_RESPONSE_WPS_KEYPAD);
		}
		break;


		case WS_EVENT_PROVISION_DISCOVERY_PBC_REQ:
		case WS_EVENT_PROVISION_DISCOVERY_DISPLAY:
		case WS_EVENT_PROVISION_DISCOVERY_KEYPAD:
		{
			if (g_wps_event_block)
				break;

			g_wps_event_block = 1;
			WDP_LOGD("Incomming PROV_DISC [%d]", event.id);
			unsigned char la_mac_addr[6];
			wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);
			memset(g_incomming_peer_mac_address, 0, sizeof(g_incomming_peer_mac_address));
			memcpy(&g_incomming_peer_mac_address, la_mac_addr, 6);
			memset(g_incomming_peer_ssid, 0, sizeof(g_incomming_peer_ssid));
			strncpy(g_incomming_peer_ssid, event.peer_ssid, sizeof(g_incomming_peer_ssid));
			g_incomming_peer_ssid[32] = '\0';

			WDP_LOGD( "NEW PIN RECEIVED = %s\n", event.wps_pin);
			memset(g_wps_pin, 0x00, sizeof(g_wps_pin));
			strncpy(g_wps_pin, event.wps_pin, WPS_PIN_LEN);
			g_wps_pin[WPS_PIN_LEN-1] = '\0';

			WDP_LOGD( "Prov Req:  mac[" MACSTR"] ssid=[%s]\n",
				MAC2STR(g_incomming_peer_mac_address), g_incomming_peer_ssid);

			if (WS_EVENT_PROVISION_DISCOVERY_DISPLAY == event.id)
				g_noti_cb(WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_DISPLAY);
			else if (WS_EVENT_PROVISION_DISCOVERY_KEYPAD == event.id)
				g_noti_cb(WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_KEYPAD);
			else
				g_noti_cb(WFD_EVENT_PROV_DISCOVERY_REQUEST);
		}
		break;

		case WS_EVENT_GROUP_FORMATION_SUCCESS:
		case WS_EVENT_GROUP_FORMATION_FAILURE:
			g_wps_event_block = 0;
		break;

		case WS_EVENT_GROUP_STARTED:
		{
			g_wps_event_block = 0;

			if(wfd_ws_is_groupowner())
			{
				WDP_LOGD(" CHECK : It's AP... \n");
				system("/usr/bin/wifi-direct-dhcp.sh server");
				__polling_ip(g_local_interface_ip_address, 20, FALSE);
				WDP_LOGE( "*** IP : %s\n", g_local_interface_ip_address);

				g_noti_cb(WFD_EVENT_SOFTAP_READY);
			}
			else
			{
				wfd_ws_glist_reset_connected_peer();

				g_conn_peer_addr = g_list_append(g_conn_peer_addr, strdup(event.peer_mac_address));
				WDP_LOGD( "connected peer[%s] is added\n", event.peer_mac_address);

				g_noti_cb(WFD_EVENT_CREATE_LINK_COMPLETE);
			}
		}
		break;

		case WS_EVENT_PERSISTENT_GROUP_STARTED:
		{
			if(wfd_ws_is_groupowner())
			{
				WDP_LOGD(" CHECK : It's AP... \n");
				system("/usr/bin/wifi-direct-dhcp.sh server");
				__polling_ip(g_local_interface_ip_address, 20, FALSE);
				WDP_LOGE( "*** IP : %s\n", g_local_interface_ip_address);

				g_noti_cb(WFD_EVENT_SOFTAP_READY);
			}
			else
			{
				wfd_ws_glist_reset_connected_peer();

				g_conn_peer_addr = g_list_append(g_conn_peer_addr, strdup(event.peer_mac_address));
				WDP_LOGD( "connected peer[%s] is added\n", event.peer_mac_address);

				/* We need to store current peer
				because, persistent joining is excuted silencely without client event.*/
				unsigned char la_mac_addr[6];
				wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);
				wfd_server_remember_connecting_peer(la_mac_addr);
				wfd_server_set_state(WIFI_DIRECT_STATE_CONNECTING);

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
			system("/usr/sbin/p2p_supp.sh stop");
			system("/usr/bin/wlan.sh stop");
			WDP_LOGE( "Device is Deactivated\n");
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
					WDP_LOGD( "disconnected peer[%s] is removed\n", event.peer_mac_address);
					free((char*) element->data);
				}
			}
		break;

		case WS_EVENT_STA_CONNECTED:
			{
				g_wps_event_block = 0;
				GList *element = NULL;
				element = g_list_find_custom(g_conn_peer_addr, event.peer_mac_address, glist_compare_peer_mac_cb);
				if(element  == NULL)
				{
					g_conn_peer_addr = g_list_append(g_conn_peer_addr, strdup(event.peer_mac_address));
					WDP_LOGD( "connected peer[%s] is added\n", event.peer_mac_address);
				}

				wfd_ws_print_connected_peer();

				wfd_macaddr_atoe(event.peer_intf_mac_address, g_assoc_sta_mac);

				wfd_server_control_t * wfd_server = wfd_server_get_control();
				if (wfd_server->config_data.want_persistent_group == true)
				{
					char g_persistent_group_ssid[64];
					int network_id;
					int result;

					memset(g_persistent_group_ssid, 0, sizeof(g_persistent_group_ssid));
					wfd_ws_get_ssid(g_persistent_group_ssid, 64);

					/* find network id with ssid */
					network_id = __get_network_id_from_network_list_with_ssid(g_persistent_group_ssid);
					if (network_id < 0)	/* NOT Persistent group */
					{
						WDP_LOGD( "__get_network_id_from_network_list_with_ssid FAIL!![%d]\n", network_id);
						WDP_LOGD( "[NOT Persistent Group]\n");
					}
					else	/* Persistent group */
					{
						/* checking peer list whether the peer is already stored or not */
						if (__is_already_stored_persistent_client(network_id, event.peer_mac_address) == false)
						{
							/* storing new persistent group client*/
							result = __store_persistent_peer(network_id, g_persistent_group_ssid, event.peer_mac_address);
							if (result != true)
								WDP_LOGD( "__store_persistent_peer FAIL!![%d]\n", result);
						}

						/* We need to store current peer
						because, persistent joining is excuted silencely without client event.*/
						unsigned char la_mac_addr[6];
						wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);
						wfd_server_remember_connecting_peer(la_mac_addr);
						wfd_server_set_state(WIFI_DIRECT_STATE_CONNECTING);
					}
				}

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
					WDP_LOGD( "disconnected peer[%s] is removed\n", event.peer_mac_address);
					wfd_ws_print_connected_peer();
				}
				else
				{
					WDP_LOGD( "Something wrong.. disconnected peer[%s] is not in Table\n", event.peer_mac_address);
				}
				wfd_macaddr_atoe(event.peer_intf_mac_address, g_disassoc_sta_mac);
				g_noti_cb(WFD_EVENT_SOFTAP_STA_DISASSOC);
			}
			break;

		case WS_EVENT_INVITATION_REQ:
		{
			wfd_ws_restart_discovery();
			unsigned char la_mac_addr[6];
			wfd_macaddr_atoe(event.peer_mac_address, la_mac_addr);
			memcpy(&g_incomming_peer_mac_address, la_mac_addr, 6);
			WDP_LOGD( "INVITATION REQ. RECEIVED:  mac[" MACSTR"]\n", MAC2STR(g_incomming_peer_mac_address));
			memcpy(&g_inviting_peer_mac_address, la_mac_addr, 6);
			g_noti_cb(WFD_EVENT_INVITE_REQUEST);
		}
		break;

		case WS_EVENT_INVITATION_RSP:
			{
			}
		break;

		case WS_EVENT_GO_NEG_FAILURE:
			{
				if (event.msg == -1) {
					g_noti_cb(WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL_TIMEOUT);
					break;
				}
				wfd_ws_cancel();
				wfd_ws_flush();
				g_noti_cb(WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL);
			}
		break;

		case WS_EVENT_WPS_FAIL:
			{
				if (event.msg == WPS_ERROR_PASSWORD_MISMATCH) {
					WDP_LOGD("WPS_ERROR_PASSWORD_MISMATCH");
					g_noti_cb(WFD_EVENT_CREATE_LINK_AUTH_FAIL);
				}
			}
		break;
 
		default:
		break;

	}

	__WDP_LOG_FUNC_EXIT__;

	return true;
}

unsigned short __convert_category_from_type(char *pri_dev_type)
{
	__WDP_LOG_FUNC_ENTER__;
	char *saveptr = NULL;
	char *token = NULL;

	if(pri_dev_type == NULL)
	{
		WDP_LOGE( "Incorrect parameter\n");
		return 0;
	}

	token = strtok_r(pri_dev_type, "-", &saveptr);
	if(token == NULL)
	{
		WDP_LOGD( "Extracting failed\n");
		return 0;
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
		WDP_LOGD( "Unknown device type [%s]\n", token);
		return 0;
	}
}


int __wpa_ctrl_attach(int sockfd)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[8] = {0};
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result= 0;

	snprintf(cmd, sizeof(cmd), CMD_ATTACH);
	result = __send_wpa_request(sockfd, cmd, (char*)res_buffer,  res_buffer_len);
	WDP_LOGE( "__send_wpa_request(ATTACH) result=[%d]\n", result);
	
	if (result < 0)
		WDP_LOGE( "__send_wpa_request FAILED!!\n");

 	__WDP_LOG_FUNC_EXIT__;

	return result;
}




static char*
__convert_wps_config_methods_value(wifi_direct_wps_type_e wps_config_methods)
{
	__WDP_LOG_FUNC_ENTER__;

	WDP_LOGD("wps_config_methods [%d]\n", wps_config_methods);

	switch(wps_config_methods)
	{
		case WIFI_DIRECT_WPS_TYPE_PBC:
		{
		 	__WDP_LOG_FUNC_EXIT__;
			return "pbc";
		}
		break;

		case WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY:
		{
		 	__WDP_LOG_FUNC_EXIT__;
			return "display";
		}
		break;

		case WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD:
		{
		 	__WDP_LOG_FUNC_EXIT__;
			return "keypad";
		}
		break;

		default :
		{
			WDP_LOGD("Invalid input parameter!\n");
		 	__WDP_LOG_FUNC_EXIT__;
			return "";
		}
		break;

	}
}

static unsigned int
__convert_device_type(char *ptr)
{
	__WDP_LOG_FUNC_ENTER__;

	char* p = ptr;
	int c = 0;
	char category_type[3] = {0,};

	if (p==NULL)
	{
		WDP_LOGE( "ERROR : ptr is NULL!!\n");
		return 0;
	}

	c = 0;
	while(*p != '-')   // take the first number before the first '-' (e.g. 1-0050F204-5)
	{
		category_type[c++] = *p++;
	}
	category_type[c]='\0';

	WDP_LOGD("category=[%d]\n", atoi(category_type));
 
 	__WDP_LOG_FUNC_EXIT__;

	return atoi(category_type);
}

static unsigned int
__convert_secondary_device_type(char *ptr)
{
	__WDP_LOG_FUNC_ENTER__;

	char* p = NULL;
	int c = 0;
	char category_type[3] = {0,};

	if (ptr==NULL)
	{
		WDP_LOGE( "ERROR : ptr is NULL!!\n");
		return 0;
	}

	p = strstr(ptr, WIFI_ALLIANCE_OUI);
	if (p==NULL)
	{
		WDP_LOGE( "ERROR : Unknown OUI, It's vendor specific device type..\n");
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

	WDP_LOGD("sub-category [%d]\n", atoi(category_type));

 	__WDP_LOG_FUNC_EXIT__;

	return atoi(category_type);
}


int __convert_freq_to_channel(char *freq_kHz)
{
	__WDP_LOG_FUNC_ENTER__;
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

	__WDP_LOG_FUNC_EXIT__;
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

int __wfd_ws_reinvoke_persistent_group(int network_id)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[64] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	/* Persistent group mode */
	snprintf(cmd, sizeof(cmd), "%s %s%d", CMD_CREATE_GROUP, "persistent=", network_id);

	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(P2P_GROUP_ADD persistent=%d) result=[%d]\n", network_id, result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "Create p2p persistent group... \n");

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

static int __is_zero_addr(unsigned char *addr)
{
	if (!addr[0] && !addr[1] && !addr[2] &&
		!addr[3] && !addr[4] && !addr[5]) {
		WDP_LOGD("NULL address");
		return true;
	}
	return false;
}

int wfd_ws_init(wfd_oem_event_cb event_callback)
{
	__WDP_LOG_FUNC_ENTER__;

#if 1  // Threadsafe event handling
	if (pipe(g_oem_pipe) < 0) {
		WDP_LOGD( "pipe error : Error=[%s]\n", strerror(errno));
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
	memset(g_inviting_peer_mac_address, 0, sizeof(g_inviting_peer_mac_address));

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_destroy()
{
	__WDP_LOG_FUNC_ENTER__;

	// Do nothing upto now...

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_activate()
{
	__WDP_LOG_FUNC_ENTER__;
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
		WDP_LOGE( "Failed to create Global Control interface\n");
		return false;
	}

	snprintf(cmd, sizeof(cmd), CMD_INTERFACE);
	result = __send_wpa_request(g_global_sockfd, cmd, res_buffer,  res_buffer_len);
	WDP_LOGE( "__send_wpa_request(LOG_LEVEL) result=[%d]\n", result);
	if(!strstr(res_buffer, "wlan0"))
	{
		memset(cmd, 0x0, 128);
		memset(res_buffer, 0x0, 1024);

		snprintf(cmd, sizeof(cmd), "%s %s", CMD_INTERFACE_ADD, "wlan0\t/usr/etc/wifi-direct/p2p_suppl.conf\tnl80211\t/var/run/p2p_supplicant");
		result = __send_wpa_request(g_global_sockfd, cmd, res_buffer,  res_buffer_len);
		WDP_LOGE( "__send_wpa_request(LOG_LEVEL) result=[%d]\n", result);
	}
	memset(res_buffer, 0x0, 1024);

	// Creating Socket
	int count = 10;
	do
	{
		sleep(1);

		// Sync Socket
		g_control_sockfd = __create_ctrl_intf("p2p_ctrl_control", "/var/run/p2p_supplicant/wlan0");
		if (g_control_sockfd > 0) {
			// Async Socket
			g_monitor_sockfd = __create_ctrl_intf("p2p_ctrl_monitor", "/var/run/p2p_supplicant/wlan0");
			if (g_monitor_sockfd > 0)
			{
				if (__wpa_ctrl_attach(g_monitor_sockfd) < 0)
				{
					WDP_LOGE( "Failed to attach monitor socket! sockfd=[%d]", g_monitor_sockfd);
					system("/usr/sbin/p2p_supp.sh stop");
					system("/usr/bin/wlan.sh stop");
					close(g_global_sockfd);
					g_global_sockfd = -1;
					close(g_control_sockfd);
					g_control_sockfd = -1;
					close(g_monitor_sockfd);
					g_monitor_sockfd = -1;
					return false;
				}
				break;
			} else {
				close(g_control_sockfd);
				g_control_sockfd = -1;
			}
		} else {
			WDP_LOGE( "Failed to attach control socket! sockfd=[%d]", g_control_sockfd);
		}
		count--;

		if (count == 0) {
			WDP_LOGE( "Failed to create socket !!\n");
			system("/usr/sbin/p2p_supp.sh stop");
			system("/usr/bin/wlan.sh stop");
			close(g_global_sockfd);
			g_global_sockfd = -1;
			return false;
		}

	} while (count > 0);
	WDP_LOGD( "Successfully socket connected to server !!\n");

	GIOChannel *gio3;
	gio3 = g_io_channel_unix_new(g_monitor_sockfd);
	g_source_id = g_io_add_watch(gio3, G_IO_IN | G_IO_ERR | G_IO_HUP, (GIOFunc) __ws_event_callback, NULL);
	g_io_channel_unref(gio3);
	WDP_LOGD( "Scoket is successfully registered to g_main_loop.\n");

	//wfd_ws_set_oem_loglevel(3);

	/* init miracast */
	if(wfd_ws_dsp_init() == true)
		WDP_LOGD( "Success : wfd_ws_dsp_init() \n");
	else
		WDP_LOGE( "Failed : wfd_ws_dsp_init()\n");

	__get_persistent_group_clients();

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_deactivate()
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result = 0;

	g_wps_event_block = 0;
	memset(g_inviting_peer_mac_address, 0, sizeof(g_inviting_peer_mac_address));

	// stop p2p_find
	wfd_ws_cancel_discovery();

	// detach monitor interface
	snprintf(cmd, sizeof(cmd), CMD_DETACH);
	result = __send_wpa_request(g_monitor_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_DETACH) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
		WDP_LOGE( "DETACH command Fail. result [%d], res_buffer [%s]\n", result, res_buffer);
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	// close control interface
	g_source_remove(g_source_id);
	unlink("/tmp/wpa_ctrl_monitor");
	if (g_monitor_sockfd > 2)
		close(g_monitor_sockfd);

	// terminate wpasupplicant
	snprintf(cmd, sizeof(cmd), CMD_TERMINATE);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_TERMINATE) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
		WDP_LOGE( "DETACH command Fail. result [%d], res_buffer [%s]\n", result, res_buffer);
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	unlink("/tmp/wpa_ctrl_control");
	if (g_control_sockfd > 2)
		close(g_control_sockfd);

	wfd_ws_glist_reset_connected_peer();

	// wlan.sh stop
	system("/usr/bin/wlan.sh stop");

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_wps_pbc_start(unsigned char peer_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;

 	char cmd[40] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (wfd_ws_is_groupowner()!=true)
	{
		WDP_LOGE( "wps_pbc_start() can be called, only when device is go!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	char tmp_mac[6] = {0,};

	if (peer_addr == NULL) {
		WDP_LOGD("Peer address is NULL");
		if (memcmp(g_incomming_peer_mac_address, tmp_mac, 6) == 0) {
			WDP_LOGD("Incomming peer [" MACSTR "]", MAC2STR(g_incomming_peer_mac_address));
			snprintf(cmd, sizeof(cmd), "%s", CMD_WPS_PUSHBUTTON_START);
		} else {
			WDP_LOGD("Incomming peer [" MACSTR "]", MAC2STR(g_incomming_peer_mac_address));
			snprintf(cmd, sizeof(cmd), "%s p2p_dev_addr=" MACSTR "", CMD_WPS_PUSHBUTTON_START, MAC2STR(g_incomming_peer_mac_address));
		}
	} else if (memcmp(peer_addr, tmp_mac, 6) != 0){
		WDP_LOGD("Peer address [" MACSTR "]", MAC2STR(peer_addr));
		snprintf(cmd, sizeof(cmd), "%s p2p_dev_addr=" MACSTR "", CMD_WPS_PUSHBUTTON_START, MAC2STR(peer_addr));
	} else {
		WDP_LOGE("Peer address is incorrent");
		return false;
	}

	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(WPS_PBC) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "start WPS PBC...\n");

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_wps_pin_start(unsigned char peer_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[50] = {0, };
	char mac_str[18] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(mac_str, 18, MACSTR, MAC2STR(peer_addr));
	snprintf(cmd, sizeof(cmd),"%s %s %s", CMD_WPS_WPS_PIN_START, mac_str, g_wps_pin);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(WPS_PIN) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "start WPS PBC...\n");


	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_connect(unsigned char mac_addr[6], wifi_direct_wps_type_e wps_config)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[64] = {0, };
	char mac_str[MACSTR_LEN] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	wfd_server_control_t * wfd_server = wfd_server_get_control();
	WDP_LOGD( "wfd_server->current_peer.is_group_owner=[%d]\n", wfd_server->current_peer.is_group_owner);

	if (wfd_ws_is_groupowner()==true)
	{
		snprintf(cmd, sizeof(cmd), CMD_WPS_PUSHBUTTON_START);
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WDP_LOGD( "__send_wpa_request(WPS_PBC) result=[%d]\n", result);
	}

	snprintf(mac_str, MACSTR_LEN, MACSTR, MAC2STR(mac_addr));
	if (wfd_server->current_peer.is_group_owner || !__is_zero_addr(g_inviting_peer_mac_address))
	{
		if (wps_config == WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD || 
			wps_config == WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY) {
			snprintf(cmd, sizeof(cmd),"WPS_ENROLLEE %s %s %s", mac_str, g_wps_pin, __convert_wps_config_methods_value(wps_config));
		}else {
			snprintf(cmd, sizeof(cmd),"WPS_ENROLLEE %s pbc", mac_str);
		}
		WDP_LOGD("WPS Enrollee start, because GO is already known");
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		memset(g_inviting_peer_mac_address, 0, sizeof(g_inviting_peer_mac_address));
		WDP_LOGD( "__send_wpa_request(WPS_ENROLLEE) result=[%d]\n", result);
	}
	else
	{
		WDP_LOGD( "MAC ADDR = [%s]\t PIN = [%s]\n",
				mac_str, g_wps_pin);

		if (wps_config == WIFI_DIRECT_WPS_TYPE_PBC) {
			WDP_LOGD("WIFI_DIRECT_WPS_TYPE_PBC");
			snprintf(cmd, sizeof(cmd), "%s %s %s", CMD_CONNECT, mac_str, CMD_PBC_STRING);
		} else if (wps_config == WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY) {
			WDP_LOGD("WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY");
			snprintf(cmd, sizeof(cmd), "%s %s %s %s", CMD_CONNECT, mac_str, g_wps_pin, CMD_DISPLAY_STRING);
		} else if (wps_config == WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD) {
			WDP_LOGD("WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD");
			snprintf(cmd, sizeof(cmd), "%s %s %s %s", CMD_CONNECT, mac_str, g_wps_pin, CMD_KEYPAD_STRING);
		} else {
			WDP_LOGD( "UNKNOWN CONFIG METHOD\n");
			return false;
		}

		WDP_LOGD( "COMMAND = [%s]\n", cmd);

		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WDP_LOGD( "__send_wpa_request(P2P_CONNECT) result=[%d]\n", result);
	}

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "Connecting... peer-MAC [%s]\n", mac_str);
 
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}
int wfd_ws_connect_for_go_neg(unsigned char mac_addr[6],
		wifi_direct_wps_type_e wps_config)
{
	__WDP_LOG_FUNC_ENTER__;
	char cmd[64] = {0, };
	char mac_str[MACSTR_LEN] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	WDP_LOGD( "CONNECT REQUEST FOR GO NEGOTIATION");
	snprintf(mac_str, MACSTR_LEN, MACSTR, MAC2STR(mac_addr));
	snprintf(cmd, sizeof(cmd), "%s %s %s %s", CMD_CONNECT, mac_str, g_wps_pin, __convert_wps_config_methods_value(wps_config));

	if (wps_config == WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD ||
			wps_config == WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY) {
		WDP_LOGD( "CONFIG = [%d] \n", wps_config);
	} else {
		WDP_LOGE( "Not expected CONFIG METHOD\n");
		return false;
	}

	WDP_LOGD( "COMMAND = [%s]****\n", cmd);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer,
			res_buffer_len);
	if (result < 0)	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0)) {
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	WDP_LOGD( "Connecting... peer-MAC [%s]\n", mac_str);
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

/* for sending connection request in case Persistent mode enabled */
int wfd_ws_connect_for_persistent_group(unsigned char mac_addr[6], wifi_direct_wps_type_e wps_config)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[64] = {0, };
	char mac_str[MACSTR_LEN] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	wfd_server_control_t * wfd_server = wfd_server_get_control();
	WDP_LOGD( "wfd_server->current_peer.is_group_owner=[%d]\n", wfd_server->current_peer.is_group_owner);
	WDP_LOGD( "wfd_server->current_peer.is_persistent_go=[%d]\n", wfd_server->current_peer.is_persistent_go);

	int network_id;

	WDP_LOGD( "[persistent mode!!!]\n");
	snprintf(mac_str, MACSTR_LEN, MACSTR, MAC2STR(mac_addr));

	if (wfd_server->current_peer.is_group_owner)	/* join group */
	{
		snprintf(mac_str, MACSTR_LEN, MACSTR, MAC2STR(mac_addr));
		snprintf(cmd, sizeof(cmd),"%s %s %s join", CMD_CONNECT, mac_str, __convert_wps_config_methods_value(wps_config));
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WDP_LOGD( "__send_wpa_request(CMD_CONNECT join) result=[%d]\n", result);
	}
	else /* Creating or reinvoking my persistent group and send invite req. */
	{
#if 1
		/*  First, searching for peer in persistent client list : in case, My device is GO */
		network_id = __get_network_id_from_persistent_client_list_with_mac(mac_str);

		if (network_id < 0)	/* If peer is not exist in client list, searching for peer in persistnet group GO list : in case, peer is GO */
			network_id = __get_network_id_from_network_list_with_go_mac(mac_str);

		if (network_id < 0)	/* If can not find peer anywhere, Create new persistent group */
		{
			if (wfd_ws_create_group(NULL) != true)
			{
				WDP_LOGE( "wfd_ws_create_group FAILED!!\n");
			 	__WDP_LOG_FUNC_EXIT__;
			 	return false;
			}

			if (wfd_ws_send_invite_request(mac_addr) != true)
			{
				WDP_LOGE( "wfd_ws_send_invite_request FAILED!!\n");
			 	__WDP_LOG_FUNC_EXIT__;
			 	return false;
			}
		}
		else	/* Reinvoke persistent group and invite peer */
		{
			if (__send_invite_request_with_network_id(network_id, mac_addr) != true)
			{
				WDP_LOGE( "__send_invite_request_with_network_id FAILED!!\n");
			 	__WDP_LOG_FUNC_EXIT__;
			 	return false;
			}

			if (__wfd_ws_reinvoke_persistent_group(network_id) != true)
			{
				WDP_LOGE( "__wfd_ws_reinvoke_persistent_group FAILED!!\n");
			 	__WDP_LOG_FUNC_EXIT__;
			 	return false;
			}
		}
#else
		int persistent_group_count = 0;
		wfd_persistent_group_info_s* plist;
		int i;

		result = wfd_ws_get_persistent_group_info(&plist, &persistent_group_count);
		if (result == true)
		{
			/* checking already created persistent group list */
			for(i=0; i<persistent_group_count; i++)
			{
				WDP_LOGD( "plist[%d].go_mac_address=[%s]\n", i,plist[i].go_mac_address);
				if (strcmp(plist[i].go_mac_address, mac_str) == 0)
				{
					WDP_LOGD( "Found peer in persistent group list [network id : %d]\n", plist[i].network_id);
					snprintf(cmd, sizeof(cmd), "%s persistent=%d", CMD_CREATE_GROUP, plist[i].network_id);
					result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
					WDP_LOGD( "__send_wpa_request(P2P_GROUP_ADD persistent=%d) result=[%d]\n", plist[i].network_id, result);
					break;
				}
			}

			if (i == persistent_group_count)	/* Can't find peer in persistent group list. Creation of new persistent group */
			{
				/* Persistent group mode */
				snprintf(cmd, sizeof(cmd), "%s %s %s", CMD_CREATE_GROUP, "persistent", FREQUENCY_2G);
				result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
				WDP_LOGD( "__send_wpa_request(P2P_GROUP_ADD) result=[%d]\n", result);

				if (result < 0)
				{
					WDP_LOGE( "__send_wpa_request FAILED!!\n");
				 	__WDP_LOG_FUNC_EXIT__;
				 	return false;
				}

				if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
				{
				 	__WDP_LOG_FUNC_EXIT__;
				 	return false;
				}

				wfd_ws_send_invite_request(mac_addr);

			}
		}
		else
		{
			WDP_LOGE( "Error!! wfd_ws_get_persistent_group_info() failed..\n");
			__WDP_LOG_FUNC_EXIT__;
			return false;
		}
#endif

	}

	WDP_LOGD( "Connecting... peer-MAC [%s]\n", mac_str);

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_disconnect()
{
	__WDP_LOG_FUNC_ENTER__;
	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	g_wps_event_block = 0;

	snprintf(cmd, sizeof(cmd), "%s %s", CMD_GROUP_REMOVE, DEFAULT_IF_NAME);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(P2P_GROUP_REMOVE) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "disconnect... remove group [%s]\n", DEFAULT_IF_NAME);
 
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}


// TODO: should find how to disconnect with peer by peer_mac
int wfd_ws_disconnect_sta(unsigned char mac_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;
	int result;

 	result = wfd_ws_disconnect();

	__WDP_LOG_FUNC_EXIT__;
 	return result;
}

int wfd_ws_reject_connection(unsigned char mac_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;
	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	g_wps_event_block = 0;

	snprintf(cmd, sizeof(cmd), "%s " MACSTR, CMD_REJECT, MAC2STR(mac_addr));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD("__send_wpa_request(P2P_REJECT) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE("__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD("reject connection attempt by peer [" MACSTR "]", MAC2STR(mac_addr));

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

bool wfd_ws_cancel()
{
        __WDP_LOG_FUNC_ENTER__;
        char cmd[16] = {0, };
        char res_buffer[1024]={0,};
        int res_buffer_len=sizeof(res_buffer);
        int result = 0;

        snprintf(cmd, sizeof(cmd), CMD_CANCEL);
        result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
        WDP_LOGD("__send_wpa_request(CMD_CANCEL) result=[%d]\n", result);

        if (result < 0)
        {
                WDP_LOGE("__send_wpa_request FAILED!!\n");
                __WDP_LOG_FUNC_EXIT__;
                return false;
        }

        if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
        {
                __WDP_LOG_FUNC_EXIT__;
                return false;
        }

        __WDP_LOG_FUNC_EXIT__;
        return true;
}

bool wfd_ws_is_discovery_enabled()
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return false;
}

bool wfd_ws_flush()
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result = 0;

	g_wps_event_block = 0;

	// Skip checking result..
	snprintf(cmd, sizeof(cmd), CMD_FLUSH);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(P2P_FLUSH) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
		__WDP_LOG_FUNC_EXIT__;
		return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
		__WDP_LOG_FUNC_EXIT__;
		return false;
	}

	__WDP_LOG_FUNC_EXIT__;
	return true;
}



int wfd_ws_start_discovery(bool listen_only, int timeout)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result = 0;

	if (listen_only == true)
	{
		if (timeout > 0)
			snprintf(cmd, sizeof(cmd), CMD_START_LISTEN " %d", timeout);
		else
			snprintf(cmd, sizeof(cmd), CMD_START_LISTEN);

			result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
			WDP_LOGD( "__send_wpa_request(P2P_LISTEN) result=[%d]\n", result);
	}
	else
	{
		wfd_ws_flush();

		snprintf(cmd, sizeof(cmd), CMD_START_DISCOVER " %d", timeout);
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WDP_LOGD( "__send_wpa_request(P2P_FIND) result=[%d]\n", result);
	}

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	// to notify to the application.
	if (listen_only == true)
		g_noti_cb(WFD_EVENT_DISCOVER_START_LISTEN_ONLY);
	else
		g_noti_cb(WFD_EVENT_DISCOVER_START_80211_SCAN);

 	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_restart_discovery()
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result = 0;

	snprintf(cmd, sizeof(cmd), CMD_START_DISCOVER " 4 type=social");
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(P2P_FIND) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_cancel_discovery()
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len=sizeof(res_buffer);
	int result = 0;

	snprintf(cmd, sizeof(cmd), CMD_CANCEL_DISCOVER);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(P2P_STOP_FIND) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	// to notify to the application.
	g_noti_cb(WFD_EVENT_DISCOVER_CANCEL);

 	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_discovery_result(wfd_discovery_entry_s ** peer_list, int* peer_num)
{
	__WDP_LOG_FUNC_ENTER__;
	
	char cmd[40] = {0, };
	char mac_str[MACSTR_LEN] = {0, };
	char res_buffer[1024] = {0,};
	int res_buffer_len = sizeof(res_buffer);
	int result = 0;
	int peer_count = 0;
	int i;
	int j = 0;
	ws_discovered_peer_info_s ws_peer_list[MAX_PEER_NUM];
	static wfd_discovery_entry_s wfd_peer_list[16];

	memset(&ws_peer_list, 0, (sizeof(ws_discovered_peer_info_s)*MAX_PEER_NUM));
	memset(&wfd_peer_list, 0, (sizeof(wfd_discovery_entry_s)*16));
	
	/* Reading first discovered peer */
	snprintf(cmd, sizeof(cmd), CMD_GET_FIRST_DISCOVERED_PEER);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(P2P_PEER FIRST) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
		*peer_num = 0;
		*peer_list = NULL;
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))	/* p2p_supplicant returns the 'FAIL' if there is no discovered peer. */
	{
		*peer_num = 0;
		*peer_list = NULL;
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	__parsing_peer(res_buffer, &ws_peer_list[peer_count]);
	peer_count++;

	/* Reading Next discovered peers */
	do
	{
	 	memset(cmd, 0x0, 40);
	 	memset(mac_str, 0x0, MACSTR_LEN);
		memset(res_buffer, 0, sizeof(res_buffer));

		strncpy(mac_str, ws_peer_list[peer_count-1].mac, MACSTR_LEN);
		mac_str[MACSTR_LEN-1] = '\0';
		snprintf(cmd, sizeof(cmd), "%s%s", CMD_GET_NEXT_DISCOVERED_PEER, mac_str);
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WDP_LOGD( "__send_wpa_request(P2P_PEER NEXT-) result=[%d]\n", result);

		if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))	/* p2p_supplicant returns the 'FAIL' if there is no discovered peer. */
			break;

		__parsing_peer(res_buffer, &ws_peer_list[peer_count]);
		peer_count++;

	} while(peer_count < MAX_PEER_NUM);

	WDP_LOGD( "number of discovered peers: %d\n", peer_count);

	GList *element = NULL;
	int connected_peer;

	for(i=0; i<peer_count; i++)
	{
		connected_peer = 0;
		element = g_list_first(g_conn_peer_addr);
		while(element) {
			if (!strncmp(element->data, ws_peer_list[i].mac, MACSTR_LEN)) {
				connected_peer = 1;
				break;
			}
			element = g_list_next(element);
		}

		if (connected_peer)
			continue;

		memset(&wfd_peer_list[j], 0, sizeof(wfd_discovery_entry_s));
		WDP_LOGD( "index [%d] MAC [%s] GOstate=[%s] groupCapab=[%x] devCapab=[%x] is_wfd_device[%d] Name[%s] type=[%s] ssid[%s]\n",
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
		unsigned char la_mac_addr[6];
		memset(la_mac_addr, 0x0, sizeof(la_mac_addr));
		wfd_macaddr_atoe(ws_peer_list[i].mac, la_mac_addr);
		memcpy(wfd_peer_list[j].mac_address, (char*)(la_mac_addr), sizeof(la_mac_addr));

		// Interface MAC address
		memset(la_mac_addr, 0x0, sizeof(la_mac_addr));
		wfd_macaddr_atoe(ws_peer_list[i].interface_addr, la_mac_addr);
		memcpy(wfd_peer_list[j].intf_mac_address, (char*)(la_mac_addr), sizeof(la_mac_addr));

		// WPS Config method
		wfd_peer_list[j].wps_cfg_methods = 0;
		if ((ws_peer_list[i].config_methods & WPS_CONFIG_DISPLAY) > 0)
			wfd_peer_list[j].wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY;
		if ((ws_peer_list[i].config_methods & WPS_CONFIG_PUSHBUTTON) > 0)
			wfd_peer_list[j].wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PBC;
		if ((ws_peer_list[i].config_methods & WPS_CONFIG_KEYPAD) > 0)
			wfd_peer_list[j].wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD;

		// Device name --> SSID
		strncpy(wfd_peer_list[j].device_name, ws_peer_list[i].device_name, WIFI_DIRECT_MAX_DEVICE_NAME_LEN);
		wfd_peer_list[j].device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN] = '\0';

		// is_group_owner
		if ((ws_peer_list[i].group_capab & GROUP_CAPAB_GROUP_OWNER) > 0)  /* checking GO state */
			wfd_peer_list[j].is_group_owner = true;
		else
			wfd_peer_list[j].is_group_owner = false;

		WDP_LOGD( "GroupOwnerCapab: %x & %x = %d\n", ws_peer_list[i].group_capab, GROUP_CAPAB_GROUP_OWNER, (ws_peer_list[i].group_capab & GROUP_CAPAB_GROUP_OWNER));

		// is_persistent_go
		if ((ws_peer_list[i].group_capab & GROUP_CAPAB_PERSISTENT_GROUP) > 0)  /* checking persistent GO state */
			wfd_peer_list[j].is_persistent_go = true;
		else
			wfd_peer_list[j].is_persistent_go = false;

		// is_connected
		if (strncmp(ws_peer_list[i].member_in_go_dev, "00:00:00:00:00:00", strlen("00:00:00:00:00:00"))!=0)
			continue;
		else
			wfd_peer_list[j].is_connected = false;

		// Listen channel
		// ToDo: convert freq to channel...
		wfd_peer_list[j].channel = ws_peer_list[i].listen_freq;

		// wps_device_pwd_id
		// ToDo: where to get it?
		wfd_peer_list[j].wps_device_pwd_id = 0;

		wfd_peer_list[j].category = __convert_device_type(ws_peer_list[i].pri_dev_type);
		wfd_peer_list[j].subcategory = __convert_secondary_device_type(ws_peer_list[i].pri_dev_type);
		j++;
	}

	*peer_num = j;
	*peer_list = &wfd_peer_list[0];

	WDP_LOGE( "Getting discovery result is Completed.\n");

	__WDP_LOG_FUNC_EXIT__;
 	return true;

}

int wfd_ws_get_peer_info(unsigned char *mac_addr, wfd_discovery_entry_s **peer)
{
	__WDP_LOG_FUNC_ENTER__;

 	char cmd[32] = {0, };
	char mac_str[MACSTR_LEN] = {0, };
	char res_buffer[1024] = {0,};
	int res_buffer_len = sizeof(res_buffer);
	int result = 0;
	ws_discovered_peer_info_s ws_peer_info;
	wfd_discovery_entry_s* wfd_peer_info;

	/* Reading first discovered peer */
	snprintf(mac_str, 18, MACSTR, MAC2STR(mac_addr));
	snprintf(cmd, sizeof(cmd),"%s %s", CMD_GET_PEER_INFO, mac_str);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(P2P_PEER) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
		*peer = NULL;
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))	/* p2p_supplicant returns the 'FAIL' if there is no discovered peer. */
	{
		*peer = NULL;
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	memset(&ws_peer_info, 0x0, sizeof(ws_discovered_peer_info_s));
	wfd_peer_info = (wfd_discovery_entry_s *) calloc(1, sizeof(wfd_discovery_entry_s));

	// TODO: parsing peer info
	__parsing_peer(res_buffer, &ws_peer_info);

	WDP_LOGD( "MAC [%s] GOstate=[%s] groupCapab=[%x] devCapab=[%x] Name[%s] type=[%s] ssid[%s]\n",
			ws_peer_info.mac,
			ws_peer_info.go_state,
			ws_peer_info.group_capab,
			ws_peer_info.dev_capab,
			ws_peer_info.device_name,
			ws_peer_info.pri_dev_type,
			ws_peer_info.oper_ssid);

	// Device MAC address
	unsigned char la_mac_addr[6];
	memset(la_mac_addr, 0x0, sizeof(la_mac_addr));
	wfd_macaddr_atoe(ws_peer_info.mac, la_mac_addr);
	memcpy(wfd_peer_info->mac_address, (char*)(la_mac_addr), sizeof(la_mac_addr));

	// Interface MAC address
	memset(la_mac_addr, 0x0, sizeof(la_mac_addr));
	wfd_macaddr_atoe(ws_peer_info.interface_addr, la_mac_addr);
	memcpy(wfd_peer_info->intf_mac_address, (char*)(la_mac_addr), sizeof(la_mac_addr));

	// WPS Config method
	wfd_peer_info->wps_cfg_methods = 0;
	if ((ws_peer_info.config_methods & WPS_CONFIG_DISPLAY) > 0)
		wfd_peer_info->wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY;
	if ((ws_peer_info.config_methods & WPS_CONFIG_PUSHBUTTON) > 0)
		wfd_peer_info->wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PBC;
	if ((ws_peer_info.config_methods & WPS_CONFIG_KEYPAD) > 0)
		wfd_peer_info->wps_cfg_methods += WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD;

	// Device name --> SSID
	strncpy(wfd_peer_info->device_name, ws_peer_info.device_name, WIFI_DIRECT_MAX_DEVICE_NAME_LEN);
	wfd_peer_info->device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN] = '\0';

	// is_group_owner
	if ((ws_peer_info.group_capab & GROUP_CAPAB_GROUP_OWNER) > 0)  /* checking GO state */
		wfd_peer_info->is_group_owner = true;
	else
		wfd_peer_info->is_group_owner = false;

	WDP_LOGD( "GroupOwnerCapab: %x & %x = %d\n", ws_peer_info.group_capab, GROUP_CAPAB_GROUP_OWNER, (ws_peer_info.group_capab & GROUP_CAPAB_GROUP_OWNER));

	// is_persistent_go
	if ((ws_peer_info.group_capab & GROUP_CAPAB_PERSISTENT_GROUP) > 0)  /* checking persistent GO state */
		wfd_peer_info->is_persistent_go = true;
	else
		wfd_peer_info->is_persistent_go = false;

	// is_connected
	if (strncmp(ws_peer_info.member_in_go_dev, "00:00:00:00:00:00", strlen("00:00:00:00:00:00"))!=0)
		wfd_peer_info->is_connected = true;
	else
		wfd_peer_info->is_connected = false;

	// Listen channel
	// ToDo: convert freq to channel...
	wfd_peer_info->channel = ws_peer_info.listen_freq;

	// wps_device_pwd_id
	// ToDo: where to get it?
	wfd_peer_info->wps_device_pwd_id = 0;

	wfd_peer_info->category = __convert_device_type(ws_peer_info.pri_dev_type);
	wfd_peer_info->subcategory = __convert_secondary_device_type(ws_peer_info.pri_dev_type);

	*peer = wfd_peer_info;

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_send_provision_discovery_request(unsigned char mac_addr[6], wifi_direct_wps_type_e config_method, int is_peer_go)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[64] = {0, };
	char mac_str[MACSTR_LEN] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	WDP_LOGD("Outgoing PROV_DISC");

	snprintf(mac_str, MACSTR_LEN, MACSTR, MAC2STR(mac_addr));
	snprintf(cmd, sizeof(cmd),"%s %s %s", CMD_SEND_PROVISION_DISCOVERY_REQ, mac_str, __convert_wps_config_methods_value(config_method));
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(P2P_PROV_DISC) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "Provisioning... peer-MAC [%s]\n", mac_str);

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}


bool wfd_ws_get_go_dev_addr(char* p2p_device_address)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (p2p_device_address == NULL)
	{
		WDP_LOGE( "Wrong param\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	snprintf(cmd, sizeof(cmd), CMD_STATUS_P2P);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(STATUS P2P) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	char* ptr = strstr(res_buffer, "p2p_device_address=");
	if (ptr==NULL)
	{
	    WDP_LOGD( "Can't find p2p_device_address...\n");
	    __WDP_LOG_FUNC_EXIT__;
	    return false;
	}

	char item[32];
	char value[MACSTR_LEN];

	if (__get_item_value(ptr, item, value) == NULL)
	{
	    WDP_LOGD( "Can't wrong format to get p2p_device_address...\n");
	    __WDP_LOG_FUNC_EXIT__;
	    return false;
	}

	if (strcmp(item, "p2p_device_address")!=0)
	{
	    WDP_LOGD( "Can't get p2p_device_address.... item=[%s]\n", item);
	    __WDP_LOG_FUNC_EXIT__;
	    return false;
	}

	snprintf(p2p_device_address, MACSTR_LEN, "%s", value);

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_send_invite_request(unsigned char dev_mac_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[128] = {0, };
	char mac_str[MACSTR_LEN] = {0, };
	char res_buffer[1024]={0,};
	char p2p_device_address[MACSTR_LEN];
	int res_buffer_len = sizeof(res_buffer);
	int result;

	/* invite request sometimes failed in listen only mode */
	wfd_server_control_t * wfd_server = wfd_server_get_control();

	if(wfd_ws_get_go_dev_addr(p2p_device_address) == false)
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	snprintf(mac_str, MACSTR_LEN, MACSTR, MAC2STR(dev_mac_addr));
	snprintf(cmd, sizeof(cmd), "%s group=p2p-wlan0-0 peer=%s go_dev_addr=%s", CMD_SEND_INVITE_REQ, mac_str, p2p_device_address);

	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGI( "__send_wpa_request(CMD_SEND_INVITE_REQ) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "Invite... peer-MAC [%s]\n", mac_str);

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}


int wfd_ws_create_group(char* ssid)
{
	__WDP_LOG_FUNC_ENTER__;

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
	WDP_LOGD( "__send_wpa_request(P2P_GROUP_ADD) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "Create p2p group... \n");
 
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_cancel_group()
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[30] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), "%s %s", CMD_GROUP_REMOVE, DEFAULT_IF_NAME);
	
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(P2P_GROUP_REMOVE) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "Remove p2p group... \n");
 
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_activate_pushbutton()
{
 	__WDP_LOG_FUNC_ENTER__;

 	char cmd[8] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), CMD_WPS_PUSHBUTTON_START);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(WPS_PBC) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	WDP_LOGD( "start WPS PBC...\n");

	__WDP_LOG_FUNC_EXIT__;
 	return true;
 }

bool wfd_ws_is_groupowner()
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), CMD_STATUS_P2P);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(STATUS P2P) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if(strstr(res_buffer, "mode=P2P GO") == NULL)
	{
	    WDP_LOGD( "This device is not Groupowner\n");
	    __WDP_LOG_FUNC_EXIT__;
	    return false;
	}
 
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

bool wfd_ws_is_groupclient()
{
	__WDP_LOG_FUNC_ENTER__;
	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), CMD_STATUS_P2P);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(STATUS P2P) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if(strstr(res_buffer, "mode=station") == NULL)
	{
	    WDP_LOGD( "This device is not client\n");
	    __WDP_LOG_FUNC_EXIT__;
	    return false;
	}

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_ssid(char* ssid, int len)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[12] = {0, };
 	char tmp_ssid[64] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if(ssid == NULL)
	{
		WDP_LOGE( "Incorrect parameter");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), CMD_STATUS_P2P);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(STATUS) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return -1;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return -1;
	}

	result = __extract_value_str(res_buffer, "\nssid", (char*) tmp_ssid);
	if(result <= 0)
	{
		WDP_LOGE( "Extracting value failed\n");
		return -1;
	}
	WDP_LOGD( "######    ssid [%s]         ###########\n", tmp_ssid);
	memcpy(ssid, tmp_ssid, len);
	ssid[len] = '\0';

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

char* wfd_ws_get_default_interface_name()
{
	__WDP_LOG_FUNC_ENTER__;
 
	__WDP_LOG_FUNC_EXIT__;
	
 	return DEFAULT_IF_NAME;
}

bool wfd_ws_dhcpc_get_ip_address(char *ipaddr_buf, int len, int is_IPv6)
{
	__WDP_LOG_FUNC_ENTER__;

	struct ifreq IfRequest;
	struct sockaddr_in* sin = NULL;
	int fd;

	if (ipaddr_buf == NULL)
		return false;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(fd < 3) {
		WDP_LOGE( "Failed to open socket\n");
		return false;
	}

	memset(IfRequest.ifr_name, 0x00, DEFAULT_IF_NAME_LEN);
	strncpy(IfRequest.ifr_name, DEFAULT_IF_NAME, DEFAULT_IF_NAME_LEN-1);
	IfRequest.ifr_name[DEFAULT_IF_NAME_LEN-1] = '\0';

	if(ioctl(fd, SIOCGIFADDR, &IfRequest) < 0) {
		WDP_LOGE( "Failed to get IP\n");
		if (fd > 2)
			close(fd);
		return false;
	}

	sin = (struct sockaddr_in*) &IfRequest.ifr_broadaddr;
	if (ipaddr_buf != NULL) {
		strncpy(ipaddr_buf, (char*) inet_ntoa(sin->sin_addr), len);
		ipaddr_buf[len-1] = '\0';
	}

	if (fd > 2)
		close(fd);
	__WDP_LOG_FUNC_EXIT__;
	return true;
}


char* wfd_ws_get_ip()
{
	__WDP_LOG_FUNC_ENTER__;

	char *ip_string = NULL;

	ip_string = (char*) calloc(1, 20);
	if (!ip_string) {
		WDP_LOGE("Failed to allocate memory for IP string");
		return NULL;
	}

	snprintf(ip_string, 20, "%s", g_local_interface_ip_address);
	WDP_LOGD( "################################################\n");
	WDP_LOGD( "######    IP = %s         ###########\n", ip_string);
	WDP_LOGD( "################################################\n");

	__WDP_LOG_FUNC_EXIT__;
 	return ip_string;
}

int wfd_ws_set_wps_pin(char* pin)
{
	__WDP_LOG_FUNC_ENTER__;
	if (pin != NULL) {
		strncpy(g_wps_pin, pin, WPS_PIN_LEN);
		g_wps_pin[WPS_PIN_LEN-1] = '\0';
		WDP_LOGD( "SETTING WPS PIN = %s\n", \
				g_wps_pin);
	} else {
		return false;
	}
	__WDP_LOG_FUNC_EXIT__;
 	return true;
 }

int wfd_ws_get_wps_pin(char* wps_pin, int len)
{
	__WDP_LOG_FUNC_ENTER__;

	if (wps_pin == NULL) {
		return false;
	}
 	strncpy(wps_pin, g_wps_pin, WPS_PIN_LEN);
	wps_pin[WPS_PIN_LEN-1] = '\0';
	WDP_LOGD( "FILLED WPS PIN = %s\n", wps_pin);
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_generate_wps_pin()
{
	__WDP_LOG_FUNC_ENTER__;
 
	__WDP_LOG_FUNC_EXIT__;
 	return true;

}


int wfd_ws_set_ssid(char* ssid)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[128] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (ssid == NULL || strlen(ssid) == 0)
	{
		WDP_LOGE( "Wrong SSID\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	snprintf(cmd, sizeof(cmd), "%s device_name %s", CMD_SET_PARAM, ssid);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	memset(cmd, 0x0, 128);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s p2p_ssid_postfix %s", CMD_SET_PARAM, ssid);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_set_wpa_passphrase(char* wpa_key)
{
	__WDP_LOG_FUNC_ENTER__;
 
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_supported_wps_mode()
{
	__WDP_LOG_FUNC_ENTER__;

	int wps_config;

	//TO-DO : supplicant CLI command should be supported.

	wps_config = WIFI_DIRECT_WPS_TYPE_PBC |WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY |WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD;

	return wps_config;

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_connected_peers_count(int* peer_num)
{
	__WDP_LOG_FUNC_ENTER__;
	GList *element = NULL;

	*peer_num = 0;
	element = g_list_first(g_conn_peer_addr);
	while(element)
	{
		(*peer_num)++;
		element = g_list_next(element);
	}
	WDP_LOGD( "Connected peer number [%d]\n", *peer_num);
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}


int wfd_ws_get_connected_peers_info(wfd_connected_peer_info_s ** peer_list, int* peer_num)
{
	__WDP_LOG_FUNC_ENTER__;
	int i = 0;
	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	char pri_dev_type[16] ={0, };
	GList *element = NULL;
	int result;

	if(peer_list == NULL || peer_num == NULL)
	{
		WDP_LOGD( "Incorrect parameter\n");
		return false;
	}

	wfd_ws_get_connected_peers_count(peer_num);

	wfd_connected_peer_info_s *tmp_peer_list = NULL;

	tmp_peer_list = (wfd_connected_peer_info_s*) calloc(*peer_num, sizeof(wfd_connected_peer_info_s));
	if(tmp_peer_list == NULL)
	{
		WDP_LOGD( "Memory allocatin failed\n");
		*peer_list = NULL;
		*peer_num = 0;

		return false;
	}

	element = g_list_first(g_conn_peer_addr);
	while(element)
	{
		WDP_LOGD( "element data is [%s]\n", (char*) element->data);
		memset(cmd, 0x0, 32);
		memset(res_buffer, 0x0, 1024);

		snprintf(cmd, sizeof(cmd), "%s %s", CMD_GET_PEER_INFO, (char*) element->data);
		result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
		WDP_LOGD( "__send_wpa_request(%s) result=[%d]\n", cmd, result);

		if (result < 0)
		{
			WDP_LOGE( "__send_wpa_request FAILED!!\n");
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

		 	__WDP_LOG_FUNC_EXIT__;
		 	return false;
		}

		if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
		{
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

		 	__WDP_LOG_FUNC_EXIT__;
	 		return false;
		}

		/*
			typedef struct
			{
				char device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN + 1];
				unsigned char ip_address[4];
				unsigned char mac_address[6];
				unsigned char intf_mac_address[6];
				unsigned int services;
				bool is_p2p;
				unsigned short category;
				int channel;
			} wfd_connected_peer_info_s;
		 */

		result = __extract_value_str(res_buffer, "device_name", (char*) tmp_peer_list[i].device_name);
		if(result <= 0) {
			WDP_LOGE( "Extracting value failed\n");
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

			return false;
		}

		wfd_macaddr_atoe((char*) element->data, tmp_peer_list[i].mac_address);

		char intf_mac_address[MACSTR_LEN] = {0, };
		result = __extract_value_str(res_buffer, "interface_addr", (char*) intf_mac_address);
		if(result <= 0)
		{
			WDP_LOGE( "Extracting value failed\n");
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
			WDP_LOGE( "Extracting value failed\n");
			*peer_list = NULL;
			*peer_num = 0;
			if (tmp_peer_list != NULL)
				free(tmp_peer_list);

			return false;
		}

		tmp_peer_list[i].category = __convert_category_from_type(pri_dev_type);
		if(tmp_peer_list[i].category == 0)
		{
			WDP_LOGE( "Category converting error\n");
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
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}


int wfd_ws_get_go_intent(int *p2p_go_intent)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (p2p_go_intent == NULL)
	{
		WDP_LOGE( "p2p_go_intent is NULL\n", p2p_go_intent);
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	snprintf(cmd, sizeof(cmd), "%s p2p_go_intent", CMD_GET_PARAM);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(GET P2P_GO_INTENT) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	*p2p_go_intent = atoi(res_buffer);
 
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_set_go_intent(int go_intent)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	if (go_intent < 0 || go_intent > 15)
	{
		WDP_LOGE( "Wrong p2p_go_intent [%d]\n", go_intent);
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	snprintf(cmd, sizeof(cmd), "%s p2p_go_intent %d", CMD_SET_PARAM, go_intent);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
 
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}


int wfd_ws_set_device_type(wifi_direct_primary_device_type_e primary_cat, wifi_direct_secondary_device_type_e sub_cat)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[32] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), "%s device_type %d", CMD_SET_PARAM, primary_cat);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s device_type %d", CMD_SET_PARAM, sub_cat);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_SET_PARAM) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

 	__WDP_LOG_FUNC_EXIT__;
 	return true;
}


int wfd_ws_get_device_mac_address(unsigned char* device_mac)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[8] = {0, };
 	char device_address[MACSTR_LEN] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), CMD_STATUS);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(STATUS) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return -1;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return -1;
	}

	__extract_value_str(res_buffer, "p2p_device_address", (char*) device_address);
	if(strlen(device_address) ==18)
	{
		wfd_macaddr_atoe((char*) device_address, device_mac);
	}
	else
	{
		WDP_LOGE( "Extracting value failed\n");
		return -1;
	}

	__WDP_LOG_FUNC_EXIT__;
 	return 0;
}

int wfd_ws_set_oem_loglevel(int is_increase)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;
 
	snprintf(cmd, sizeof(cmd), "%s %d", CMD_LOG_LEVEL, is_increase);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer,  res_buffer_len);
	WDP_LOGE( "__send_wpa_request(LOG_LEVEL) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_get_assoc_sta_mac(unsigned char *mac_addr)
{
	__WDP_LOG_FUNC_ENTER__;

	memcpy(mac_addr, g_assoc_sta_mac, 6);

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_get_disassoc_sta_mac(unsigned char *mac_addr)
{
	__WDP_LOG_FUNC_ENTER__;
	memcpy(mac_addr, g_disassoc_sta_mac, 6);
	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_get_requestor_mac(unsigned char* mac_addr)
{
	__WDP_LOG_FUNC_ENTER__;

	memcpy(mac_addr, g_incomming_peer_mac_address, 6);

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_get_operating_channel(void)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[16] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;
	char item[32] = {0, };
	char freq_value[32] = {0,};
	int channel;


	snprintf(cmd, sizeof(cmd), CMD_STATUS_P2P);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(STATUS P2P) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	char* ptr = strstr(res_buffer, "frequency=");
	if (ptr==NULL)
	{
		WDP_LOGD( "Can't find frequency field...\n");
		__WDP_LOG_FUNC_EXIT__;
		return false;
	}

	if (__get_item_value(ptr, item, freq_value) == NULL)
	{
		WDP_LOGD( "Can't get value of frequency...\n");
		__WDP_LOG_FUNC_EXIT__;
		return false;
	}

	if (strcmp(item, "frequency")!=0)
	{
		WDP_LOGD( "Can't get frequency.... item=[%s]\n", item);
		__WDP_LOG_FUNC_EXIT__;
		return false;
	}

	WDP_LOGD( "freq_value=[%s]\n", freq_value);

	channel = __convert_freq_to_channel(freq_value);

	WDP_LOGD( "channel=[%d]\n", channel);

	__WDP_LOG_FUNC_EXIT__;
	return channel;

}


/* -------------------- Miracast ---------------------------*/


int wfd_ws_dsp_init(void)
{
	__WDP_LOG_FUNC_ENTER__;

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
	WDP_LOGD( "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED[param : enable]!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	/* param : dev_info */
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s dev_info %s", CMD_WFD_SET, dev_info);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED[param : dev_info]!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	/* param : ctrl_port */
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s ctrl_port %d", CMD_WFD_SET, ctrl_port);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED[param : ctrl_port]!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	/* param : max_tput */
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s max_tput %d", CMD_WFD_SET, max_tput);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED[param : max_tput]!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	/* param : cpled_sink_status */
	memset(cmd, 0x0, 32);
	memset(res_buffer, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), "%s cpled_sink_status %s", CMD_WFD_SET, cpled_sink_status);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(CMD_WFD_SET) result=[%d]\n", result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED[param : cpled_sink_status]!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	__WDP_LOG_FUNC_EXIT__;
	return true;
}


int wfd_ws_get_persistent_group_info(wfd_persistent_group_info_s **persistent_group_list, int *persistent_group_num)
{
	__WDP_LOG_FUNC_ENTER__;
	
	char cmd[16] = {0, };
	char res_buffer[1024] = {0,};
	int res_buffer_len = sizeof(res_buffer);
	int result = 0;
	int i;
	ws_network_info_s ws_persistent_group_list[MAX_PERSISTENT_GROUP_NUM];
	wfd_persistent_group_info_s *wfd_persistent_group_list = NULL;

	memset(ws_persistent_group_list, 0, (sizeof(ws_network_info_s)*MAX_PERSISTENT_GROUP_NUM));

	/* Reading lists the configured networks, including stored information for persistent groups. 
	The identifier in this is used with p2p_group_add and p2p_invite to indicate witch persistent
	group is to be reinvoked. */
	snprintf(cmd, sizeof(cmd), CMD_GET_LIST_NETWORKS);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(LIST_NETWORKS) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
		*persistent_group_num = 0;
		*persistent_group_list = NULL;
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
		*persistent_group_num = 0;
		*persistent_group_list = NULL;
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	__parsing_persistent_group(res_buffer, ws_persistent_group_list, persistent_group_num);
	WDP_LOGD( "Persistent Group Count=%d\n", *persistent_group_num);

	if (*persistent_group_num == 0) {
		WDP_LOGD("There is no persistent group");
		*persistent_group_list = NULL;
	 	__WDP_LOG_FUNC_EXIT__;
		return false;
	}

	wfd_persistent_group_list = (wfd_persistent_group_info_s*) calloc(*persistent_group_num,
																sizeof(wfd_persistent_group_info_s));
	if (!wfd_persistent_group_list) {
		WDP_LOGF("Failed to allocate memory for wfd_persistent_group_list");
		*persistent_group_num = 0;
		*persistent_group_list = NULL;
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	for(i=0;i<(*persistent_group_num);i++)
	{
		WDP_LOGD( "----persistent group [%d]----\n", i);		
		WDP_LOGD( "network_id=%d\n", ws_persistent_group_list[i].network_id);
		WDP_LOGD( "ssid=%s\n", ws_persistent_group_list[i].ssid);
		WDP_LOGD( "bssid=%s\n", ws_persistent_group_list[i].bssid);
		WDP_LOGD( "flags=%s\n", ws_persistent_group_list[i].flags);

// TODO: should filer by [PERSISTENT] value of flags.

		wfd_persistent_group_list[i].network_id = ws_persistent_group_list[i].network_id;
		strncpy(wfd_persistent_group_list[i].ssid, ws_persistent_group_list[i].ssid, WIFI_DIRECT_MAX_SSID_LEN);
		wfd_persistent_group_list[i].ssid[WIFI_DIRECT_MAX_SSID_LEN] = '\0';
		
		unsigned char la_mac_addr[6];
		wfd_macaddr_atoe(ws_persistent_group_list[i].bssid, la_mac_addr);
		memcpy(wfd_persistent_group_list[i].go_mac_address, la_mac_addr, 6);
	}

	*persistent_group_list = wfd_persistent_group_list;

	__WDP_LOG_FUNC_EXIT__;
 	return true;

}

int wfd_ws_remove_persistent_group(wfd_persistent_group_info_s *persistent_group)
{
	__WDP_LOG_FUNC_ENTER__;
	char cmd[32] = {0, };
	char res_buffer[1024] = {0,};
	int res_buffer_len = sizeof(res_buffer);
	int result = 0;
	int i;
	ws_network_info_s ws_persistent_group_list[MAX_PERSISTENT_GROUP_NUM];
	int persistent_group_num;
	char go_mac_str[18];
	
	memset(ws_persistent_group_list, 0x0, (sizeof(ws_network_info_s)*MAX_PERSISTENT_GROUP_NUM));
	memset(go_mac_str, 0x0, sizeof(go_mac_str));
	snprintf(go_mac_str, MACSTR_LEN, MACSTR, MAC2STR(persistent_group->go_mac_address));

	snprintf(cmd, sizeof(cmd), CMD_GET_LIST_NETWORKS);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(LIST_NETWORKS) result=[%d]\n", result);
	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	__parsing_persistent_group(res_buffer, ws_persistent_group_list, &persistent_group_num);

	WDP_LOGD( "Persistent Group Count=%d\n", persistent_group_num);
	for(i=0;i<persistent_group_num;i++)
	{
		WDP_LOGD( "----persistent group [%d]----\n", i);		
		WDP_LOGD( "network_id=%d\n", ws_persistent_group_list[i].network_id);
		WDP_LOGD( "ssid=%s\n", ws_persistent_group_list[i].ssid);
		WDP_LOGD( "bssid=%s\n", ws_persistent_group_list[i].bssid);
		WDP_LOGD( "flags=%s\n", ws_persistent_group_list[i].flags);

// TODO: should filer by [PERSISTENT] value of flags.


			WDP_LOGD( "persistent_group->ssid [%s]----\n", persistent_group->ssid);
			WDP_LOGD( "ws_persistent_group_list[i].ssid [%s]----\n", ws_persistent_group_list[i].ssid);
			WDP_LOGD( "go_mac_str [%s]----\n", go_mac_str);
			WDP_LOGD( "ws_persistent_group_list[i].bssid [%s]----\n", ws_persistent_group_list[i].bssid);

		if (strcmp(persistent_group->ssid, ws_persistent_group_list[i].ssid) == 0
			&& strcmp(go_mac_str, ws_persistent_group_list[i].bssid) == 0)
		{
		
			WDP_LOGD( "----Found persistent group [%d]----\n", i);
			
			memset(cmd, 0x0, sizeof(cmd));
			memset(res_buffer, 0x0, sizeof(res_buffer));

			snprintf(cmd, sizeof(cmd), "%s %d", CMD_REMOVE_NETWORK, ws_persistent_group_list[i].network_id);
			result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
			WDP_LOGD( "__send_wpa_request(CMD_REMOVE_NETWORK) result=[%d]\n", result);

			if (result < 0)
			{
				WDP_LOGE( "__send_wpa_request FAILED[CMD_REMOVE_NETWORK]!!\n");
			 	__WDP_LOG_FUNC_EXIT__;
			 	return false;
			}
			if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
			{
			 	__WDP_LOG_FUNC_EXIT__;
			 	return false;
			}


			break;
		}

	}


	
	__WDP_LOG_FUNC_EXIT__;
 	return true;
}

int wfd_ws_set_persistent_reconnect(bool enabled)
{
	__WDP_LOG_FUNC_ENTER__;

	char cmd[128] = {0, };
	char res_buffer[1024]={0,};
	int res_buffer_len = sizeof(res_buffer);
	int result;

	snprintf(cmd, sizeof(cmd), "%s persistent_reconnect %d", CMD_SET_PARAM, enabled);
	result = __send_wpa_request(g_control_sockfd, cmd, (char*)res_buffer, res_buffer_len);
	WDP_LOGD( "__send_wpa_request(SET persistent_reconnect %d) result=[%d]\n", enabled, result);

	if (result < 0)
	{
		WDP_LOGE( "__send_wpa_request FAILED!!\n");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}
	if ( (result == 0) || (strncmp(res_buffer, "FAIL", 4) == 0))
	{
	 	__WDP_LOG_FUNC_EXIT__;
	 	return false;
	}

	__WDP_LOG_FUNC_EXIT__;
 	return true;
}
