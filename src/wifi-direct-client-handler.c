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
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <vconf.h>
#include <vconf-keys.h>

#include "wifi-direct-client-handler.h"
#include "wifi-direct-internal.h"
#include "wifi-direct-service.h"
#include "wifi-direct-stub.h"
#include "wifi-direct-oem.h"



int wfd_check_wifi_status()
{
	int wifi_state = 0;

	/* vconf key and value (vconf-keys.h)
#define VCONFKEY_WIFI_STATE "memory/wifi/state"
enum {
        VCONFKEY_WIFI_OFF = 0x00,
        VCONFKEY_WIFI_UNCONNECTED,
        VCONFKEY_WIFI_CONNECTED,
        VCONFKEY_WIFI_TRANSFER,
        VCONFKEY_WIFI_STATE_MAX
};
	 */

	/* Check wifi state again */
	if (vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state) < 0)
	{
		WDS_LOGF( "Error reading vconf (%s)\n", VCONFKEY_WIFI_STATE);
		return -1;
	}
	else
	{
		WDS_LOGF( "VCONFKEY_WIFI_STATE(%s) : %d\n", VCONFKEY_WIFI_STATE, wifi_state);
		if (wifi_state > VCONFKEY_WIFI_OFF)
		{
			WDS_LOGE( "Sorry. Wi-Fi is on\n");
			return 0;
		}
		WDS_LOGD( "OK. Wi-Fi is off\n");
	}
	return 1;
}

int wfd_check_mobile_ap_status()
{
	int mobile_ap_state = 0;

	/* Check wifi state again */
	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &mobile_ap_state) < 0)
	{
		WDS_LOGF( "Error reading vconf (%s)\n", VCONFKEY_MOBILE_HOTSPOT_MODE);
		return -1;
	}
	else
	{
		WDS_LOGF( "VCONFKEY_WIFI_STATE(%s) : %d\n", VCONFKEY_MOBILE_HOTSPOT_MODE, mobile_ap_state);
		if (mobile_ap_state != VCONFKEY_MOBILE_HOTSPOT_MODE_NONE)
		{
			WDS_LOGF( "Sorry. Mobile AP is on\n");
			return 0;
		}
		else
		{
			WDS_LOGF( "OK. Mobile AP is off\n");
		}
	}
	return 1;
}


int wfd_set_wifi_direct_state(int state)
{
	WDS_LOGF( "VCONFKEY_WIFI_DIRECT_STATE(%s) : %d\n", VCONFKEY_WIFI_DIRECT_STATE, state);

	if (vconf_set_int(VCONFKEY_WIFI_DIRECT_STATE, state) < 0)
	{
		WDS_LOGE( "Error setting vconf (%s)\n", VCONFKEY_WIFI_DIRECT_STATE);
		return -1;
	}

	return 1;
}

int wfd_check_wifi_direct_state()
{
	int wifi_direct_state = 0;

	if (vconf_get_int(VCONFKEY_WIFI_DIRECT_STATE, &wifi_direct_state) < 0)
	{
		WDS_LOGF( "Error reading vconf (%s)\n", VCONFKEY_WIFI_DIRECT_STATE);
		return -1;
	}
	else
	{
		WDS_LOGF( "VCONFKEY_WIFI_DIRECT_STATE(%s) : %d\n", VCONFKEY_WIFI_DIRECT_STATE, wifi_direct_state);

		switch(wifi_direct_state)
		{
		case VCONFKEY_WIFI_DIRECT_DEACTIVATED:
		{
			WDS_LOGD( "Wi-Fi direct is off\n");
		}
		break;

		case VCONFKEY_WIFI_DIRECT_ACTIVATED:
		{
			WDS_LOGD( "Wi-Fi direct is on\n");
		}
		break;

		case VCONFKEY_WIFI_DIRECT_DISCOVERING:
		{
			WDS_LOGD( "Wi-Fi direct is discovering\n");
		}
		break;

		case VCONFKEY_WIFI_DIRECT_CONNECTED:
		{
			WDS_LOGD( "Wi-Fi direct is connected\n");
		}
		break;

		case VCONFKEY_WIFI_DIRECT_GROUP_OWNER:
		{
			WDS_LOGD( "Wi-Fi direct is group owner\n");
		}
		break;

		default:
		{
			WDS_LOGF( "ERROR:Wi-Fi direct is unkown state\n");
			return -1;
		}
		break;
		}
	}
	return wifi_direct_state;
}


int wfd_get_phone_device_name(char* str, int len)
{
	char* get_str = NULL;
	if (str==NULL || len <=0)
		return -1;

	get_str = vconf_get_str(VCONFKEY_SETAPPL_DEVICE_NAME_STR);

	if (get_str == NULL)
	{
		WDS_LOGF( "Error reading vconf (%s)\n", VCONFKEY_SETAPPL_DEVICE_NAME_STR);
		return -1;
	}
	else
	{
		WDS_LOGF( "VCONFKEY_WIFI_STATE(%s) : %d\n", VCONFKEY_SETAPPL_DEVICE_NAME_STR, get_str);
		strncpy(str, get_str, len);
		str[len-1] = '\0';
		return 0;
	}
}


void wfd_set_device_name()
{
	wfd_server_control_t * wfd_server = wfd_server_get_control();
	char device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN + 1];
	wifi_direct_state_e state = wfd_server_get_state();

	if (wfd_get_phone_device_name(device_name, WIFI_DIRECT_MAX_DEVICE_NAME_LEN) != -1)
	{
		strncpy(wfd_server->config_data.device_name, device_name, WIFI_DIRECT_MAX_DEVICE_NAME_LEN);
		wfd_server->config_data.device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN] ='\0';
		wfd_oem_set_ssid(device_name);

		// In WIFI_DIRECT_STATE_ACTIVATED  state, devie name will be applied immediately.
		// In other sate, it will be set in next discovery start.
		if (state == WIFI_DIRECT_STATE_ACTIVATED)
		{
			wfd_oem_cancel_discovery();
			wfd_oem_start_discovery(false,0);
		}
		return;
	}
}

void __wfd_device_name_change_cb(keynode_t *key, void* data)
{
	WDS_LOGD( "device name has been changed. change ssid (friendly name)..\n");
	wfd_set_device_name();
}

int wfd_set_device_name_from_phone_name()
{
	wfd_set_device_name();
	vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR, __wfd_device_name_change_cb, NULL);

	return 0;
}

void __wfd_server_print_entry_list(wfd_discovery_entry_s * list, int num)
{
	int i = 0;

	WDS_LOGD( "------------------------------------------\n");
	for(i = 0; i < num; i++)
	{
		WDS_LOGD( "== Peer index : %d ==\n", i);
		WDS_LOGD( "is Group Owner ? %s\n", list[i].is_group_owner ? "YES" : "NO");
		WDS_LOGD( "is Connected ? %s\n", list[i].is_connected ? "YES" : "NO");
		WDS_LOGD( "device_name : %s\n", list[i].device_name);
		WDS_LOGD( "MAC address : " MACSTR "\n", MAC2STR(list[i].mac_address));
		WDS_LOGD( "Iface address : " MACSTR "\n", MAC2STR(list[i].intf_mac_address));
		WDS_LOGD( "Device type [%d/%d] ==\n", list[i].category, list[i].subcategory);
		WDS_LOGD( "wps cfg method [%d] ==\n", list[i].wps_cfg_methods);
	}
	WDS_LOGD( "------------------------------------------\n");
}

void __wfd_server_print_connected_peer_info(wfd_connected_peer_info_s* list, int num)
{
	int i = 0;

	WDS_LOGD( "------------------------------------------\n");
	for(i = 0; i < num; i++)
	{
		WDS_LOGD( "CONN[%d] device_name=[%s]\n", 
				i,
				list[i].device_name);
		WDS_LOGD( "         cat=[%d] svc=[%d] isp2p=[%d] channel=[%d]\n",
				list[i].category,
				list[i].services,
				list[i].is_p2p,
				list[i].channel);				
		WDS_LOGD( "         mac dev/Intf=[" MACSTR "/" MACSTR "]\n", 
				MAC2STR(list[i].mac_address),
				MAC2STR(list[i].intf_mac_address));
		WDS_LOGD( "         IP =["IPSTR"]\n", 
				IP2STR(list[i].ip_address));
	}
	WDS_LOGD( "------------------------------------------\n");
}

wfd_server_client_t * wfd_server_find_client(int client_id)
{
	int i = 0;
	wfd_server_control_t * wfd_server = wfd_server_get_control();

	__WDS_LOG_FUNC_ENTER__;

	for(i = 0; i < WFD_MAX_CLIENTS; i++)
	{
		if(wfd_server->client[i].client_id == client_id)
		{
			WDS_LOGD( "index [%d] client id [%d]\n", i, wfd_server->client[i].client_id);
			return &(wfd_server->client[i]);
		}
	}

	WDS_LOGE( "No Matching client!! client id [%d]\n", client_id);
	return NULL;
}

int wfd_server_find_peer_by_macaddr(wfd_discovery_entry_s *plist, int entry_size, unsigned char macaddr[6])
{
	int i = 0;
	__WDS_LOG_FUNC_ENTER__;

	if (plist == NULL)
		return -1;

	if (entry_size < 0 || entry_size > WFD_MAX_CLIENTS)
		return -2;

	for(i = 0; i < entry_size; i++)
	{
		if(memcmp((void*)&plist[i].mac_address[0], (void*)&macaddr[0], sizeof(plist[i].mac_address))==0)
		{
			return i;
		}
	}

	WDS_LOGF( "No Matching client!! client mac addr\n");

	return -3;
}


int wfd_server_send_response(int sockfd, void *data, int len)
{
	int ret_val = 0;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	wifi_direct_client_response_s *resp = (wifi_direct_client_response_s*) data;

	__WDS_LOG_FUNC_ENTER__;

	WDS_LOGD( "Send sync resp cmd=[%d], result=[%d], len=[%d]\n", resp->cmd, resp->result, len);

	wfd_server->sync_sockfd = sockfd;

	if (wfd_server_is_fd_writable(sockfd) <= 0)
	{
		WDS_LOGF( "socketfd[%d] write is not possible!! \n", sockfd);
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	ret_val = write(sockfd, (char*)data, len);
	if(ret_val <= 0)
	{
		WDS_LOGF( "socket write FAILED!!! [%s]\n", strerror(errno));
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;	
}

void wfd_server_process_client_request(wifi_direct_client_request_s * client_req)
{
	__WDS_LOG_FUNC_ENTER__;

	int ret = WIFI_DIRECT_ERROR_NONE;
	wifi_direct_client_response_s	resp;
	wfd_server_control_t * wfd_server = wfd_server_get_control();
	wfd_server_client_t * client = wfd_server_find_client(client_req->client_id);
	wifi_direct_client_noti_s	noti;

	if(client == NULL)
	{
		WDS_LOGF( "Invalid client id [%d]\n", client_req->client_id);
		return ;
	}

	WDS_LOGD( "Requested Cmd [%d, %s]\n", client_req->cmd, wfd_server_print_cmd(client_req->cmd));

	memset(&resp, 0, sizeof(wifi_direct_client_response_s));
	resp.client_id = client_req->client_id;
	resp.data_length = 0;
	resp.cmd = client_req->cmd;

	if (wfd_server_check_valid(client_req->cmd) == false) {
		resp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
		WDS_LOGI( "Invalid command [%d] at state=[%d]\n", client_req->cmd, wfd_server->state);
		wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	switch(client_req->cmd)
	{
	case WIFI_DIRECT_CMD_DEREGISTER:
	{
		resp.result = WIFI_DIRECT_ERROR_NONE;
		wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
		wfd_server_reset_client(client_req->client_id);
	}
	break;
	case WIFI_DIRECT_CMD_ACTIVATE:
	{
		if (wfd_check_wifi_status() == 0)
		{
			resp.result = WIFI_DIRECT_ERROR_WIFI_USED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			return;
		}
		else if (wfd_check_mobile_ap_status() == 0)
		{
			resp.result =WIFI_DIRECT_ERROR_MOBILE_AP_USED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			return;
		}
		else
		{
			resp.result = WIFI_DIRECT_ERROR_NONE;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));

			int res = 0;
			wifi_direct_client_noti_s noti;
			memset(&noti, 0, sizeof(wifi_direct_client_noti_s));

			noti.event = WIFI_DIRECT_CLI_EVENT_ACTIVATION;
			noti.error = WIFI_DIRECT_ERROR_NONE;

			// Initialize server db.
			{
				int i = -1;
				for(i=0;i<WFD_MAX_ASSOC_STA;i++)
				{
					memset(&wfd_server->connected_peers[i], 0, sizeof(wfd_local_connected_peer_info_t));
					wfd_server->connected_peers[i].isUsed = 0;
				}
				wfd_server->connected_peer_count = 0;
				memset(&wfd_server->current_peer, 0x00, sizeof(wfd_discovery_entry_s));
			}

			wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATING);

			res = wfd_oem_activate();

			WDS_LOGF( "Device handle from oem res=[%d]\n", res);

			if (res == false)
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_DEACTIVATED);
				noti.error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}
			else
			{
				wfd_set_device_name();
				wfd_oem_set_device_type(wfd_server->config_data.primary_dev_type,
						wfd_server->config_data.secondary_dev_type);
				wfd_oem_set_go_intent(7);

				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);

				noti.error = WIFI_DIRECT_ERROR_NONE;
			}

			__wfd_server_send_client_event(&noti);

			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_DEACTIVATE:
	{
		resp.result = WIFI_DIRECT_ERROR_NONE;
		wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
		wfd_server_set_state(WIFI_DIRECT_STATE_DEACTIVATING);
		wfd_oem_deactivate();
		wfd_server_set_state(WIFI_DIRECT_STATE_DEACTIVATED);

		wifi_direct_client_noti_s noti;
		memset(&noti, 0, sizeof(wifi_direct_client_noti_s));

		noti.event = WIFI_DIRECT_CLI_EVENT_DEACTIVATION;
		noti.error = WIFI_DIRECT_ERROR_NONE;
		__wfd_server_send_client_event(&noti);

		__WDS_LOG_FUNC_EXIT__;
		return;
	}
	break;

	case WIFI_DIRECT_CMD_START_DISCOVERY:
	{
		int res = 0;
		bool listen_only = client_req->data.listen_only;
		int timeout = client_req->data.timeout;
		wifi_direct_state_e state = wfd_server_get_state();

		WDS_LOGF( "Flag of Listen only : %s timeout[%d]\n", listen_only ? "ON" : "OFF", timeout);

		if (state == WIFI_DIRECT_STATE_GROUP_OWNER)
			res = wfd_oem_restart_discovery();
		else
			res = wfd_oem_start_discovery(listen_only, timeout);
		if (res==true)
		{
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
					state == WIFI_DIRECT_STATE_DISCOVERING)
				wfd_server_set_state(WIFI_DIRECT_STATE_DISCOVERING);

			if ( timeout>0 )
				wfd_timer_discovery_start(timeout);

			resp.result = WIFI_DIRECT_ERROR_NONE;

		}
		else
		{
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}

		wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));

		__WDS_LOG_FUNC_EXIT__;
		return;
	}
	break;

	case WIFI_DIRECT_CMD_CANCEL_DISCOVERY:
	{
		ret = wfd_oem_cancel_discovery();
		if (ret == false)
		{
			WDS_LOGE( "Error!! wfd_oem_cancel_discovery() failed..\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		resp.result = WIFI_DIRECT_ERROR_NONE;
		wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
		__WDS_LOG_FUNC_EXIT__;
		return;
	}
	break;

	case WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT:
	{
		int peer_count = 0;
		int total_msg_len = 0;
		wfd_discovery_entry_s* plist = NULL;

		wifi_direct_state_e state = wfd_server_get_state();
		if (state > WIFI_DIRECT_STATE_ACTIVATING)
		{
			ret = wfd_oem_get_discovery_result(&plist, &peer_count);
			if (ret == false)
			{
				WDS_LOGE( "Error!! wfd_oem_get_discovery_result() failed..\n");
				resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
				__WDS_LOG_FUNC_EXIT__;
				return;
			}
		}

		total_msg_len = sizeof(wifi_direct_client_response_s) + (sizeof(wfd_discovery_entry_s) * peer_count);

		WDS_LOGD( "Peer count : %d, total message size : %d\n", peer_count, total_msg_len);

		char * msg = (char*)malloc(total_msg_len);
		if(msg == NULL)
		{
			WDS_LOGF( "Memory Allocation is FAILED!!!!!![%d]\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		resp.param1 = peer_count;
		resp.result = WIFI_DIRECT_ERROR_NONE;

		memset(msg, 0, total_msg_len);
		memcpy(msg, &resp, sizeof(wifi_direct_client_response_s));
		if (peer_count && plist != NULL) {
			memcpy(msg + sizeof(wifi_direct_client_response_s), plist, sizeof(wfd_discovery_entry_s) * peer_count);
			__wfd_server_print_entry_list((wfd_discovery_entry_s*)plist, peer_count);
		}

		wfd_server_send_response(client->sync_sockfd, msg, total_msg_len);

		g_free(msg);
		__WDS_LOG_FUNC_EXIT__;
		return;
	}
	break;

	case WIFI_DIRECT_CMD_SEND_PROVISION_DISCOVERY_REQ:
	{
		resp.result = WIFI_DIRECT_ERROR_NONE;
		wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
		__WDS_LOG_FUNC_EXIT__;
		return;
	}
	break;

	case WIFI_DIRECT_CMD_CONNECT:
	{
		wifi_direct_wps_type_e	wps_config;
		int max_client;

		max_client = wfd_server->config_data.max_clients;
		WDS_LOGF( "max_client [%d] connected_peer_count[%d]\n", max_client, wfd_server->connected_peer_count);
		if (wfd_server->connected_peer_count >= max_client)
		{
			WDS_LOGF( "Error... available number of clients is full!!\n");
			resp.result = WIFI_DIRECT_ERROR_TOO_MANY_CLIENT;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			break;
		}

		wfd_discovery_entry_s *peer = NULL;

		ret = wfd_oem_get_peer_info(client_req->data.mac_addr, &peer);
		if (!ret || !peer) {
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			break;
		}

		if (wfd_oem_is_groupowner() && peer->is_group_owner) {
			resp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			break;
		} else {
			resp.result = WIFI_DIRECT_ERROR_NONE;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
		}

		wfd_server_set_state(WIFI_DIRECT_STATE_CONNECTING);

		memcpy(&wfd_server->current_peer, peer, sizeof(wfd_discovery_entry_s));

		wps_config = wfd_server->config_data.req_wps_config;
		WDS_LOGI( "wps_config : %d\n", wps_config);

		if (wfd_server->config_data.want_persistent_group == true)
		{
			/* skip prov_disco_req() in persistent mode. reinvoke stored persistent group or create new persistent group */
			ret = wfd_oem_connect_for_persistent_group(client_req->data.mac_addr, wps_config);
			WDS_LOGI( "wfd_oem_connect_for_persistent_group: ret = %d\n", ret);
		}
		else
		{
			if (wfd_oem_is_groupowner() == true)
			{
				wfd_oem_cancel_discovery();
				ret = wfd_oem_send_invite_request(client_req->data.mac_addr);
				WDS_LOGI( "Invite request: ret = %d\n", ret);
			}
			else
			{
				ret = wfd_oem_send_provision_discovery_request(client_req->data.mac_addr, wps_config, wfd_server->current_peer.is_group_owner);
				WDS_LOGI( "ProvisionDiscovery request: ret = %d\n", ret);
			}
		}

		if (ret == true)
		{
			snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(client_req->data.mac_addr));

			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_START;
			noti.error = WIFI_DIRECT_ERROR_NONE;
		}
		else
		{
			if (wfd_oem_is_groupowner() == true)
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
			}
			else
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			}

			WDS_LOGF( "Error... fail to connect\n");

			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}

		__wfd_server_send_client_event(&noti);

		__WDS_LOG_FUNC_EXIT__;
		return;
	}
	break;

	case WIFI_DIRECT_CMD_DISCONNECT_ALL:
	{
		wfd_server_set_state(WIFI_DIRECT_STATE_DISCONNECTING);

		// Response app first.
		resp.result = WIFI_DIRECT_ERROR_NONE;
		wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
		
		if (wfd_oem_disconnect())
		{
			wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PBC;	// set wps_config to default value
		}
		else
		{
			wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			
			WDS_LOGF( "Error... wfd_oem_disconnect() failed\n");
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			__wfd_server_send_client_event(&noti);
		}
	}
	break;

	case WIFI_DIRECT_CMD_DISCONNECT:
	{
		// Response app first.
		resp.result = WIFI_DIRECT_ERROR_NONE;
		wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));

		wfd_local_connected_peer_info_t* peer = NULL;
		peer = wfd_server_get_connected_peer_by_device_mac(client_req->data.mac_addr);
#if 0		
		if (peer == NULL)
		{
			WDS_LOGF( "Connected Peer not found!\n");
			resp.result = WIFI_DIRECT_ERROR_INVALID_PARAMETER;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			break;
		}
#endif

		if (wfd_oem_is_groupowner() == TRUE)
		{
			if (NULL == peer)
			{
				if (wfd_oem_disconnect_sta(wfd_server->current_peer.intf_mac_address))
				{
					wfd_server_remember_connecting_peer(client_req->data.mac_addr);
				}
				else
				{
					WDS_LOGF( "Error... wfd_oem_disconnect() failed\n");
					noti.event =WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
					noti.error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
					__wfd_server_send_client_event(&noti);
				}
			}
			else
			{
				if (wfd_oem_disconnect_sta(peer->int_address))
				{
					wfd_server_remember_connecting_peer(client_req->data.mac_addr);
				}
				else
				{
					WDS_LOGF( "Error... wfd_oem_disconnect() failed\n");
					noti.event =WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
					noti.error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
					__wfd_server_send_client_event(&noti);
				}
			}

		}
		else if (wfd_server->current_peer.is_group_owner)
		{
			wfd_server_set_state(WIFI_DIRECT_STATE_DISCONNECTING);
			ret = wfd_oem_disconnect();
			if (ret)
			{
				wfd_server_remember_connecting_peer(client_req->data.mac_addr);
				wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PBC;
			}
			else
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
				WDS_LOGE("Error... wfd_oem_disconnect() failed");
				noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
				noti.error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				__wfd_server_send_client_event(&noti);
			}
		}
		else
		{
			if (wfd_server->state < WIFI_DIRECT_STATE_CONNECTED) {
				ret = wfd_oem_reject_connection(client_req->data.mac_addr);
				ret = wfd_oem_connect(client_req->data.mac_addr, wfd_server->config_data.req_wps_config);
			} else {
				ret = wfd_oem_disconnect();
			}
			wfd_server_set_state(WIFI_DIRECT_STATE_DISCONNECTING);
		
			if (ret)
			{
				wfd_server_remember_connecting_peer(client_req->data.mac_addr);
				wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PBC;        // set wps_config to default
			}
			else
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);

				WDS_LOGF( "Error... wfd_oem_disconnect() failed\n");
				noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
				noti.error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
				__wfd_server_send_client_event(&noti);
			}

		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_LINK_STATUS:
	{
		int status = wfd_server_get_state();
		WDS_LOGD( "Link Status [%s]\n", wfd_print_state(status));
		resp.param1 = status;
		resp.result = WIFI_DIRECT_ERROR_NONE;
		wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
	}
	break;

	case WIFI_DIRECT_CMD_SEND_CONNECT_REQ:
	{
		wifi_direct_wps_type_e	wps_config;
		int max_client;

		max_client = wfd_server->config_data.max_clients;
		WDS_LOGF( "max_client [%d] connected_peer_count[%d]\n", max_client, wfd_server->connected_peer_count);
		if (wfd_server->connected_peer_count >= max_client)
		{
			WDS_LOGF( "Error... available number of clients is full!!\n");
			resp.result = WIFI_DIRECT_ERROR_TOO_MANY_CLIENT;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
		}
		else
		{
			wps_config = wfd_server->config_data.wps_config;

			WDS_LOGD( "Connect to peer %02x:%02x:%02x:%02x:%02x:%02x\n",
					client_req->data.mac_addr[0],
					client_req->data.mac_addr[1],
					client_req->data.mac_addr[2],
					client_req->data.mac_addr[3],
					client_req->data.mac_addr[4],
					client_req->data.mac_addr[5]);

			wfd_server_remember_connecting_peer(client_req->data.mac_addr);

			wfd_server_set_state(WIFI_DIRECT_STATE_CONNECTING);

			// Response app first.
			resp.result = WIFI_DIRECT_ERROR_NONE;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));

			if (wfd_oem_is_groupowner()) {
				if (wps_config == WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY ||
					  wps_config == WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD)
					wfd_oem_wps_pin_start(client_req->data.mac_addr);
				else
					wfd_oem_wps_pbc_start(client_req->data.mac_addr);
				break;
			}

			if (wfd_oem_connect(client_req->data.mac_addr, wps_config))
			{
				snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(client_req->data.mac_addr));

				noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_START;
				noti.error = WIFI_DIRECT_ERROR_NONE;
				
			}
			else
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
				WDS_LOGF( "Error: wfd_oem_connect() failed..\n");
				snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(client_req->data.mac_addr));
				
				noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
				noti.error = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}

			__wfd_server_send_client_event(&noti);
		

		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_CONFIG:
	{
		int status = wfd_server_get_state();

		resp.param1 = status;
		resp.result = ret;

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(resp)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
		if (wfd_server_send_response(client->sync_sockfd,  &wfd_server->config_data, sizeof(wfd_config_data_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
		return;
	}
	break;

	case WIFI_DIRECT_CMD_SET_CONFIG:
	{
		wfd_config_data_s config;
		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)&config, sizeof(wfd_config_data_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		resp.param1 = wfd_server_get_state();
		resp.result = ret;

		memcpy((void*)&wfd_server->config_data, (void*)&config, sizeof(wfd_config_data_s));

		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_CREATE_GROUP:
	{
		wfd_server_set_state(WIFI_DIRECT_STATE_CONNECTING);
		ret = wfd_oem_create_group(wfd_server->config_data.device_name);
		if (ret==false)
		{
			wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		else
		{
			wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_server->autonomous_group_owner = true;
			resp.result = WIFI_DIRECT_ERROR_NONE;
		}
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON:
	{
		wfd_oem_activate_pushbutton();
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_IS_GROUPOWNER:
	{
		int owner = wfd_oem_is_groupowner();
		resp.param1 = owner;
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_SSID:
	{
		char ssid[32+1];

		if (wfd_oem_get_ssid(ssid, 32)==false)
		{
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		else
		{
			snprintf(resp.param2, sizeof(resp.param2), "%s", ssid);
			resp.result = WIFI_DIRECT_ERROR_NONE;
		}

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_DEVICE_NAME:
	{
		snprintf(resp.param2, sizeof(resp.param2), "%s", wfd_server->config_data.device_name);
		resp.result = WIFI_DIRECT_ERROR_NONE;

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_SET_DEVICE_NAME:
	{
		char	device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN+1] = {0,};

		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)device_name, WIFI_DIRECT_MAX_DEVICE_NAME_LEN) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		WDS_LOGI( "device_name = [%s]\n", device_name);

		memset(wfd_server->config_data.device_name, 0, WIFI_DIRECT_MAX_DEVICE_NAME_LEN+1);
		strncpy(wfd_server->config_data.device_name, device_name, WIFI_DIRECT_MAX_DEVICE_NAME_LEN);
		wfd_server->config_data.device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN] = '\0';
		ret = wfd_oem_set_ssid(device_name);

		if (ret == TRUE)
			resp.result = WIFI_DIRECT_ERROR_NONE;
		else
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_IP_ADDR:
	{
		char* ip_addr = wfd_oem_get_ip();
		if (!ip_addr)
			snprintf(resp.param2, sizeof(resp.param2), "0.0.0.0");
		else
			snprintf(resp.param2, sizeof(resp.param2), "%s", ip_addr);

		if (ip_addr)
			free(ip_addr);

		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_SET_WPS_PIN:
	{
		char	pin[WIFI_DIRECT_WPS_PIN_LEN+1];

		memset(pin, 0, WIFI_DIRECT_WPS_PIN_LEN+1);

		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)pin, WIFI_DIRECT_WPS_PIN_LEN) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		WDS_LOGF( "PIN = [%s]\n", pin);

		ret = wfd_oem_set_wps_pin(pin);

		if (ret == TRUE)
			resp.result = WIFI_DIRECT_ERROR_NONE;
		else
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_WPS_PIN:
	{
		char	pin[WIFI_DIRECT_WPS_PIN_LEN+1];
		memset(pin, 0, WIFI_DIRECT_WPS_PIN_LEN+1);

		if (wfd_oem_get_wps_pin(pin, sizeof(pin)) == false)
		{
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			WDS_LOGE( "wfd_oem_get_wps_pin() failed!\n");
		}
		else
		{
			WDS_LOGD( "pin [%s]\n", pin);
			snprintf(resp.param2, sizeof(resp.param2), "%s", pin);
			resp.result = WIFI_DIRECT_ERROR_NONE;
		}
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GENERATE_WPS_PIN:
	{

		if (wfd_oem_generate_wps_pin() == false)
		{
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			WDS_LOGE( "wfd_oem_generate_wps_pin() failed!\n");
		}
		else
		{
			resp.result = WIFI_DIRECT_ERROR_NONE;
		}
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_SET_SSID:
	{
		char	ssid[WIFI_DIRECT_MAX_SSID_LEN+1] = {0,};

		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)ssid, WIFI_DIRECT_MAX_SSID_LEN) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		WDS_LOGD( "ssid = [%s]\n", ssid);

		ret = wfd_oem_set_ssid(ssid);

		if (ret == TRUE)
			resp.result = WIFI_DIRECT_ERROR_NONE;
		else
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_SET_WPA:
	{
		char	new_wpa[64+1] = {0,};

		resp.result = WIFI_DIRECT_ERROR_NONE;

		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)new_wpa, 64) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		WDS_LOGD( "new_wpa = [%s]\n", new_wpa);

		if (wfd_oem_set_wpa_passphrase(new_wpa) == false)
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE:
	{
		int wps_mode = wfd_oem_get_supported_wps_mode();
		WDS_LOGF( "supported wps mode (%d)\n", wps_mode);
		resp.param1 = wps_mode;
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_SET_CURRENT_WPS_MODE:
	{
		wifi_direct_wps_type_e wps_mode;
		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)&wps_mode, sizeof(wifi_direct_wps_type_e)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		WDS_LOGD( "wps_mode (%d)\n", wps_mode);
		wfd_server->config_data.wps_config = wps_mode;

		resp.param1 = wfd_server_get_state();
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_SET_REQUESTED_WPS_MODE:
	{
		wifi_direct_wps_type_e wps_mode;
		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)&wps_mode, sizeof(wifi_direct_wps_type_e)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		WDS_LOGF( "wps_mode (%d)\n", wps_mode);
		wfd_server->config_data.req_wps_config = wps_mode;
				
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_REQUESTED_WPS_MODE:
	{
		WDS_LOGD("wps_mode (%d)\n", wfd_server->config_data.req_wps_config);

		resp.param1 = wfd_server->config_data.req_wps_config;
		resp.result = WIFI_DIRECT_ERROR_NONE;

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO:
	{
		int total_msg_len = 0;
		wfd_connected_peer_info_s* plist = NULL;
		int peer_count = 0;
		int i = 0, j = 0;

		wifi_direct_state_e state = wfd_server_get_state();
		ret = WIFI_DIRECT_ERROR_NONE;
		if (state < WIFI_DIRECT_STATE_CONNECTED) {
			WDS_LOGE( "state != WIFI_DIRECT_STATE_CONNECTED\n");
			resp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
			if (wfd_server_send_response(client->sync_sockfd, &resp,
											sizeof(wifi_direct_client_response_s)) < 0) {
				wfd_server_reset_client(client->sync_sockfd);
				__WDS_LOG_FUNC_EXIT__;
				return;
			}
			break;

		}
		WDS_LOGD("WFD status [%d]", state);

		peer_count = wfd_server->connected_peer_count;
		if (peer_count <= 0) {
			if (state == WIFI_DIRECT_STATE_GROUP_OWNER) {
				resp.result = WIFI_DIRECT_ERROR_NONE;
				resp.param1 = 0;
			} else {
				resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			}

			if (wfd_server_send_response(client->sync_sockfd, &resp,
											sizeof(wifi_direct_client_response_s)) < 0) {
				wfd_server_reset_client(client->sync_sockfd);
				__WDS_LOG_FUNC_EXIT__;
				return;
			}
			break;
		}
		WDS_LOGD("Connected peer count [%d]", peer_count);

		plist = (wfd_connected_peer_info_s*) calloc(peer_count, sizeof(wfd_connected_peer_info_s));
		if(plist == NULL)
		{
			WDS_LOGF( "Memory Allocation is FAILED!!!!!![%d]\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			if (wfd_server_send_response(client->sync_sockfd, &resp,
											sizeof(wifi_direct_client_response_s)) < 0) {
				wfd_server_reset_client(client->sync_sockfd);
				__WDS_LOG_FUNC_EXIT__;
				return;
			}
			break;
		}

		for (i = 0, j = 0; j < peer_count && i < WFD_MAX_ASSOC_STA; i++) {
			if (wfd_server->connected_peers[i].isUsed == 0) {
				WDS_LOGD("Not used peer info [%s]", wfd_server->connected_peers[i].peer.device_name);
				continue;
			}
			WDS_LOGD("Connected peer info found [%s]", wfd_server->connected_peers[i].peer.device_name);

			strncpy(plist[j].device_name, wfd_server->connected_peers[i].peer.device_name, WIFI_DIRECT_MAX_DEVICE_NAME_LEN);
			plist[j].device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN] = '\0';
			memcpy(&plist[j].intf_mac_address[0], wfd_server->connected_peers[i].int_address, 6);
			memcpy(&plist[j].mac_address[0], wfd_server->connected_peers[i].peer.mac_address, 6);
			plist[j].services = wfd_server->connected_peers[i].peer.services;
			plist[j].is_p2p = 1;
			plist[j].category = wfd_server->connected_peers[i].peer.category;
			plist[j].channel = wfd_server->connected_peers[i].peer.channel;
			memcpy(&plist[j].ip_address[0], wfd_server->connected_peers[i].ip_address, 4);

			j++;
		}
		total_msg_len = sizeof(wifi_direct_client_response_s) + (sizeof(wfd_connected_peer_info_s) * peer_count);

		WDS_LOGD( "Peer count : %d, total message size : %d\n", peer_count, total_msg_len);

		char * msg = (char*)malloc(total_msg_len);
		if(msg == NULL)
		{
			WDS_LOGF( "Memory Allocation is FAILED!!!!!![%d]\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
			{
				wfd_server_reset_client(client->sync_sockfd);
				g_free(plist);
				__WDS_LOG_FUNC_EXIT__;
				return;
			}
			g_free(plist);
			break;
		}

		resp.param1 = peer_count;
		resp.result = ret;

		memset(msg, 0, total_msg_len);
		memcpy(msg, &resp, sizeof(wifi_direct_client_response_s));
		if (peer_count > 0)
			memcpy(msg + sizeof(wifi_direct_client_response_s), plist, sizeof(wfd_connected_peer_info_s) * peer_count);

		__wfd_server_print_connected_peer_info((wfd_connected_peer_info_s*)plist, peer_count);

		if (wfd_server_send_response(client->sync_sockfd, msg, total_msg_len) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			g_free(plist);
			g_free(msg);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
		g_free(plist);
		g_free(msg);
	}
	break;

	case WIFI_DIRECT_CMD_CANCEL_GROUP:
	{
		ret = wfd_oem_cancel_group();
		if (ret==false)
		{
			//wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		else
		{
			wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			resp.result = WIFI_DIRECT_ERROR_NONE;
		}
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_GO_INTENT:
	{
		int intent;

		ret = wfd_oem_get_go_intent(&intent);
		if (ret == false)
		{
			WDS_LOGE( "Error!! wfd_oem_get_go_intent() failed..\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		resp.param1 = intent;
		resp.result = WIFI_DIRECT_ERROR_NONE;

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_SET_GO_INTENT:
	{
		int intent;
		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)&intent, sizeof(int)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		WDS_LOGF( "intent (%d)\n", intent);

		ret = wfd_oem_set_go_intent(intent);

		if (ret == false)
		{
			WDS_LOGE( "Error!! wfd_oem_set_go_intent() failed..\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		resp.param1 = wfd_server_get_state();
		resp.result = ret;

		wfd_server->config_data.group_owner_intent = intent;

		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
		
	}
	break;

	case WIFI_DIRECT_CMD_SET_MAX_CLIENT:
	{
		int max_client;
		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)&max_client, sizeof(int)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		WDS_LOGF( "max_client (%d)\n", max_client);

		resp.param1 = wfd_server_get_state();

		if (max_client > WFD_MAX_ASSOC_STA)
		{
			WDS_LOGF( "ERROR : Max client number shold be under [%d]\n", WFD_MAX_ASSOC_STA);
			resp.result = WIFI_DIRECT_ERROR_INVALID_PARAMETER;
		}
		else
		{
			wfd_server->config_data.max_clients = max_client;
			resp.result = WIFI_DIRECT_ERROR_NONE;
		}

		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_MAX_CLIENT:
	{
		int max_client;

		max_client = wfd_server->config_data.max_clients;
		
		WDS_LOGF( "max_client (%d)\n", max_client);
		resp.param1 = max_client;
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;


	case WIFI_DIRECT_CMD_GET_DEVICE_MAC:
	{

		unsigned char device_mac[6] = {0,};

		ret = wfd_oem_get_device_mac_address((unsigned char*)&device_mac);

		if (ret == false)
		{
			WDS_LOGE( "Error!! wfd_oem_get_device_mac_address() failed..\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		memcpy(resp.param2, device_mac, sizeof(device_mac));
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP:
	{
		int autonomous_group = wfd_server->autonomous_group_owner;
		resp.param1 = autonomous_group;
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE:
	{
		bool autoconnection_mode;
		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)&autoconnection_mode, sizeof(bool)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		WDS_LOGF( "autoconnection_mode (%d)\n", autoconnection_mode);

		resp.param1 = wfd_server_get_state();
		resp.result = ret;

		wfd_server->config_data.auto_connection = autoconnection_mode;
				
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_IS_AUTOCONNECTION_MODE:
	{
		int auto_connection = (int)wfd_server->config_data.auto_connection;
		resp.param1 = auto_connection;
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_IS_DISCOVERABLE:
	{
#if 0
		int discoverable = (int)wfd_oem_is_discovery_enabled();
		resp.param1 = discoverable;
#else
		if ((wfd_server->state == WIFI_DIRECT_STATE_DISCOVERING)
			|| (wfd_server->autonomous_group_owner == TRUE))
			resp.param1 = 1;
		else
			resp.param1 = 0;
#endif
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_IS_LISTENING_ONLY:
	{
		int listen_only = (int)wfd_server->config_data.listen_only;
		resp.param1 = listen_only;
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL:
	{
		if (client_req->data.listen_only)
			wfd_oem_set_oem_loglevel(true);
		else
			wfd_oem_set_oem_loglevel(false);

		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL:
	{
		int operating_channel = wfd_oem_get_operating_channel();
		WDS_LOGF( "operating_channel (%d)\n", operating_channel);
		resp.param1 = operating_channel;
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_ACTIVATE_PERSISTENT_GROUP:
	{
		wfd_server->config_data.want_persistent_group = true;
		ret = wfd_oem_set_persistent_group_enabled(true);
		if (ret == false)
		{
			WDS_LOGE( "Error!! wfd_oem_set_persistent_group_enabled() failed..\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_DEACTIVATE_PERSISTENT_GROUP:
	{
		wfd_server->config_data.want_persistent_group = false;
		ret = wfd_oem_set_persistent_group_enabled(false);
		if (ret == false)
		{
			WDS_LOGE( "Error!! wfd_oem_set_persistent_group_enabled() failed..\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	case WIFI_DIRECT_CMD_IS_PERSISTENT_GROUP:
	{
		int persistent_group_enabled = (int)wfd_server->config_data.want_persistent_group;
		resp.param1 = persistent_group_enabled;
		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;


	case WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO:
	{
		int persistent_group_count = 0;
		int total_msg_len = 0;
		wfd_persistent_group_info_s *plist;
		
		ret = wfd_oem_get_persistent_group_info(&plist, &persistent_group_count);
		if (ret == false)
		{
			WDS_LOGE( "Error!! wfd_oem_get_persistent_group_info() failed..\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		total_msg_len = sizeof(wifi_direct_client_response_s) + (sizeof(wfd_persistent_group_info_s) * persistent_group_count);

		WDS_LOGD( "persistent_group_count : %d, total message size : %d\n", persistent_group_count, total_msg_len);

		char * msg = (char*) calloc(1, total_msg_len);
		if(msg == NULL)
		{
			WDS_LOGF( "Memory Allocation is FAILED!!!!!![%d]\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			if (plist)
				free(plist);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		resp.param1 = persistent_group_count;
		resp.result = WIFI_DIRECT_ERROR_NONE;

		memcpy(msg, &resp, sizeof(wifi_direct_client_response_s));
		if (persistent_group_count > 0)
			memcpy(msg + sizeof(wifi_direct_client_response_s), plist, sizeof(wfd_persistent_group_info_s) * persistent_group_count);

		wfd_server_send_response(client->sync_sockfd, msg, total_msg_len);
		if (plist)
			free(plist);
		free(msg);

		__WDS_LOG_FUNC_EXIT__;
		return;
	}
	break;

	case WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP:
	{
		wfd_persistent_group_info_s persistent_group;
		
		if(wfd_server_read_socket_event(client->sync_sockfd, (char*)&persistent_group, sizeof(wfd_persistent_group_info_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		ret = wfd_oem_remove_persistent_group(&persistent_group);
		if (ret == false)
		{
			WDS_LOGE( "Error!! wfd_oem_remove_persistent_group() failed..\n");
			resp.result = WIFI_DIRECT_ERROR_OPERATION_FAILED;
			wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s));
			__WDS_LOG_FUNC_EXIT__;
			return;
		}

		resp.result = WIFI_DIRECT_ERROR_NONE;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
	}
	break;

	default:
		WDS_LOGF( "Error!!! Invalid cmd = [%d] \n", client_req->cmd);
		resp.result = WIFI_DIRECT_ERROR_NOT_PERMITTED;
		if (wfd_server_send_response(client->sync_sockfd, &resp, sizeof(wifi_direct_client_response_s)) < 0)
		{
			wfd_server_reset_client(client->sync_sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return;
		}
		break;
	}

	__WDS_LOG_FUNC_EXIT__;
}



