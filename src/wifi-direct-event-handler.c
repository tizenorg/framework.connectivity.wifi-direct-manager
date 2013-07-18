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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <glib.h>

#include "wifi-direct-service.h"
#include "wifi-direct-event-handler.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-internal.h"
#include "wifi-direct-utils.h"

char wfd_event_str[WFD_EVENT_MAX];

char *__wfd_print_client_event(wfd_client_event_e event)
{
	switch (event)
	{
	case WIFI_DIRECT_CLI_EVENT_ACTIVATION:
		return "ACTIVATION";
	case WIFI_DIRECT_CLI_EVENT_DEACTIVATION:
		return "DEACTIVATION";
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START:
		return "DISCOVER_START_80211_SCAN";
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START_LISTEN_ONLY:
		return "DISCOVER_START_LISTEN_ONLY";
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START_SEARCH_LISTEN:
		return "DISCOVER_START_SEARCH_LISTEN";
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_END:
		return "DISCOVER_END";
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS:
		return "DISCOVER_FOUND_PEERS";
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_START:
		return "CONNECTION_START";
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ:
		return "CONNECTION_REQ";
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP:
		return "CONNECTION_RSP";
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ:
		return "CONNECTION_WPS_REQ";
	case WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP:
		return "DISCONNECTION_RSP";
	case WIFI_DIRECT_CLI_EVENT_DISCONNECTION_IND:
		return "DISCONNECTION_IND";
	case WIFI_DIRECT_CLI_EVENT_GROUP_CREATE_RSP:
		return "GROUP_CREATE_RSP";
	case WIFI_DIRECT_CLI_EVENT_GROUP_DESTROY_RSP:
		return "GROUP_DESTROY_RSP";
	case WIFI_DIRECT_CLI_EVENT_IP_LEASED_IND:
		return "IP_LEASED_IND";
	default:
		WDS_LOGF( "Error!!! Invalid Event (%d) \n", event);
		return "INVALID EVENT";
	}
}


char *__wfd_server_print_event(wfd_event_t event)
{
	switch (event)
	{
	case WFD_EVENT_DISCOVER_START_80211_SCAN:
		return "DISCOVER_START_80211_SCAN";
	case WFD_EVENT_DISCOVER_START_SEARCH_LISTEN:
		return "DISCOVER_START_SEARCH_LISTEN";
	case WFD_EVENT_DISCOVER_FOUND_PEERS:
		return "DISCOVER_FOUND_PEERS";
	case WFD_EVENT_DISCOVER_FOUND_P2P_GROUPS:
		return "DISCOVER_FOUND_P2P_GROUPS";
	case WFD_EVENT_DISCOVER_CANCEL:
		return "DISCOVER_CANCEL";
	case WFD_EVENT_DISCOVER_COMPLETE:
		return "DISCOVER_COMPLETE";
	case WFD_EVENT_DISCOVER_FAIL:
		return "DISCOVER_FAIL";
	case WFD_EVENT_DISCOVER_RESUMED:
		return "DISCOVER_RESUMED";
	case WFD_EVENT_DISCOVER_SUSPENDED:
		return "DISCOVER_SUSPENDED";
	case WFD_EVENT_DISCOVER_START_LISTEN_ONLY:
		return "DISCOVER_START_LISTEN_ONLY";
	case WFD_EVENT_PROV_DISCOVERY_REQUEST:
		return "PROV_DISCOVERY_REQUEST";
	case WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_DISPLAY:
		return "PROV_DISCOVERY_REQUEST_WPS_DISPLAY";
	case WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_KEYPAD:
		return "PROV_DISCOVERY_REQUEST_WPS_KEYPAD";
	case WFD_EVENT_PROV_DISCOVERY_RESPONSE:
		return "PROV_DISCOVERY_RESPONSE";
	case WFD_EVENT_PROV_DISCOVERY_TIMEOUT:
		return "PROV_DISCOVERY_TIMEOUT";
	case WFD_EVENT_GROUP_OWNER_NEGOTIATION_START:
		return "GROUP_OWNER_NEGOTIATION_START";
	case WFD_EVENT_GROUP_OWNER_NEGOTIATION_AP_ACK:
		return "GROUP_OWNER_NEGOTIATION_AP_ACK";
	case WFD_EVENT_GROUP_OWNER_NEGOTIATION_STA_ACK:
		return "GROUP_OWNER_NEGOTIATION_STA_ACK";
	case WFD_EVENT_GROUP_OWNER_NEGOTIATION_REQUEST_RECEIVED:
		return "GROUP_OWNER_NEGOTIATION_REQUEST_RECEIVED";
	case WFD_EVENT_GROUP_OWNER_NEGOTIATION_COMPLETE:
		return "GROUP_OWNER_NEGOTIATION_COMPLETE";
	case WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL:
		return "GROUP_OWNER_NEGOTIATION_FAIL";
	case WFD_EVENT_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO:
		return "GROUP_OWNER_NEGOTIATION_NO_PROV_INFO";
	case WFD_EVENT_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL:
		return "GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL";
	case WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL_INTENT:
		return "GROUP_OWNER_NEGOTIATION_FAIL_INTENT";
	case WFD_EVENT_CREATE_LINK_START:
		return "CREATE_LINK_START";
	case WFD_EVENT_CREATE_LINK_CANCEL:
		return "CREATE_LINK_CANCEL";
	case WFD_EVENT_CREATE_LINK_TIMEOUT:
		return "CREATE_LINK_TIMEOUT";
	case WFD_EVENT_CREATE_LINK_AUTH_FAIL:
		return "CREATE_LINK_AUTH_FAIL";
	case WFD_EVENT_CREATE_LINK_FAIL:
		return "CREATE_LINK_FAIL";
	case WFD_EVENT_CREATE_LINK_COMPLETE:
		return "CREATE_LINK_COMPLETE";
	case WFD_EVENT_CONNECT_PBC_START:
		return "CONNECT_PBC_START";
	case WFD_EVENT_PRIMARY_IF_DISCONNECTION:
		return "PRIMARY_IF_DISCONNECTION";
	case WFD_EVENT_SVC_REQ_RECEIVED:
		return "SVC_REQ_RECEIVED";
	case WFD_EVENT_SVC_RESP_RECEIVED:
		return "SVC_RESP_RECEIVED";
	case WFD_EVENT_SVC_COMEBACK_REQ_RECEIVED:
		return "SVC_COMEBACK_REQ_RECEIVED";
	case WFD_EVENT_SVC_COMEBACK_RESP_RECEIVED:
		return "SVC_COMEBACK_RESP_RECEIVED";
	case WFD_EVENT_DEV_DISCOVERABILITY_REQ:
		return "DEV_DISCOVERABILITY_REQ";
	case WFD_EVENT_DEV_DISCOVERABILITY_RSP:
		return "DEV_DISCOVERABILITY_RSP";
	case WFD_EVENT_GO_DISCOVERABILITY_REQ:
		return "GO_DISCOVERABILITY_REQ";
	case WFD_EVENT_SOFTAP_READY:
		return "SOFTAP_READY";
	case WFD_EVENT_SOFTAP_STOP:
		return "SOFTAP_STOP";
	case WFD_EVENT_IP_ASSIGNED:
		return "IP_ASSIGNED";
	case WFD_EVENT_IP_LEASED:
		return "IP_LEASED";
	case WFD_EVENT_INVITE_REQUEST:
		return "INVITE_REQUEST";
	case WFD_EVENT_INVITE_RESPONSE:
		return "INVITE_RESPONSE";
  	default:
		WDS_LOGF( "Error!!! Invalid Event (%d) \n", event);
		return "INVALID EVENT";
	}

}

void __wfd_server_print_connected_peer()
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i;

	for (i = 0; i < WFD_MAX_ASSOC_STA; i++)
	{
		if (wfd_server->connected_peers[i].isUsed == 0)
		{
			WDS_LOGD( "Connected Peer[%d] isUsed=[%d]\n", i,
						   wfd_server->connected_peers[i].isUsed);
		}
		else
		{
			WDS_LOGD( "Connected Peer[%d] isUsed=[%d] dev mac=" MACSTR " intf mac=" MACSTR " ip="IPSTR" device_name=%s\n" ,
					i,
					wfd_server->connected_peers[i].isUsed,
					MAC2STR(wfd_server->connected_peers[i].peer.mac_address),
					MAC2STR(wfd_server->connected_peers[i].int_address),
					IP2STR(wfd_server->connected_peers[i].ip_address),
					wfd_server->connected_peers[i].peer.device_name
			);
		}
	}
}


bool __wfd_get_ip_address(void *user_data)
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	char ip_addr[64];
	if (wfd_oem_dhcpc_get_ip_address(ip_addr, 64, 0) == true)
	{
		wfd_event_t event;
		WDS_LOGE( "** Get IP address!!ip = %s\n", ip_addr);
		wfd_server->dhcp_ip_address_timer = 0;

		event = WFD_EVENT_IP_ASSIGNED;
		wfd_server_process_event(event);
		return false;
	}
	else
	{
		WDS_LOGE( "** Failed to get IP address!!Wait more...\n");
		return true;
	}
}

void wfd_server_start_dhcp_wait_timer()
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_server_control_t *wfd_server = wfd_server_get_control();

#if 0
	//system("killall udhcpc;/usr/bin/udhcpc -i wl0.1 -s /usr/etc/wifi-direct/udhcp_script.non-autoip &");

	char cmdStr[256] = {0,};
	char *interface_name = NULL;

	interface_name = wfd_oem_get_default_interface_name();
	if (NULL == interface_name)
		WDS_LOGE( "ERROR : \default interface name is NULL !!!\n");
	else
		WDS_LOGE( "Interface name is [%s]\n", interface_name);

	sprintf(cmdStr, "killall udhcpc;/usr/bin/udhcpc -i %s -s /usr/etc/wifi-direct/udhcp_script.non-autoip &", interface_name);
	system(cmdStr);

#else

	system("/usr/bin/wifi-direct-dhcp.sh client");

#endif

	wfd_server->dhcp_ip_address_timer = g_timeout_add(1000, (GSourceFunc) __wfd_get_ip_address, NULL);
}

void wfd_server_cancel_dhcp_wait_timer()
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	if (wfd_server->dhcp_ip_address_timer > 0)
	{
		g_source_remove(wfd_server->dhcp_ip_address_timer);
		wfd_server->dhcp_ip_address_timer = 0;
	}
	else
	{
		WDS_LOGE( "** dhcp_wait_timer is already stopped...\n");
	}
}

void __wfd_server_send_client_event(wifi_direct_client_noti_s * noti)
{
	int i = 0;
	int ret = 0;
	int len = sizeof(wifi_direct_client_noti_s);

	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	WDS_LOGI( "__wfd_server_send_client_event(%d, %s)\n",
				   noti->event, __wfd_print_client_event(noti->event));

	for (i = 0; i < WFD_MAX_CLIENTS; i++)
	{
		errno = 0;
		if ((wfd_server->client[i].isUsed == true)
			&& (wfd_server->client[i].client_id > WFD_INVALID_ID)
			&& (wfd_server->client[i].async_sockfd > 0))
		{
			WDS_LOGD( "Sending event to client[%d]: cid=[%d] sock=[%d] a-sock=[%d], dev_handle=[%d], sourceid=[%d]\n",
					i,
					wfd_server->client[i].client_id,
					wfd_server->client[i].sync_sockfd,
					wfd_server->client[i].async_sockfd,
					wfd_server->client[i].dev_handle,
					wfd_server->client[i].g_source_id);

			if (wfd_server_is_fd_writable(wfd_server->client[i].async_sockfd) <= 0)
			{
				continue;
			}

			ret = write(wfd_server->client[i].async_sockfd, (char *) noti, len);
			if (ret <= 0)
			{
				WDS_LOGF( "Error!!! writing to the socket. Error [%s] \n", strerror(errno));
			}
			else
				WDS_LOGD( "Event(%s) is Sent to client(id:%d) successfully!!!\n",
						__wfd_print_client_event(noti->event), wfd_server->client[i].client_id);
		}
	}
}


bool wfd_server_remember_connecting_peer(unsigned char device_mac[6])
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	wfd_discovery_entry_s *peer;
	int status;

	status = wfd_oem_get_peer_info(device_mac, &peer);
	if (status == true)
	{
		if (peer != NULL)
		{
			WDS_LOGD( "wfd_oem_get_peer_info() Success\n");
			memcpy(&wfd_server->current_peer, peer, sizeof(wfd_discovery_entry_s));

			__wfd_server_print_connected_peer();
			free(peer);
			WDS_LOGD( "peer " MACSTR" go=[%d] connected=[%d] ch=[%d] device_name=[%s]\n",
					MAC2STR(wfd_server->current_peer.mac_address),
					wfd_server->current_peer.is_group_owner,
					wfd_server->current_peer.is_connected,
					wfd_server->current_peer.channel,
					wfd_server->current_peer.device_name);

			
			return true;
		}
	}

	WDS_LOGE( "Remember Peer: Error!! can't find peer from the discovery result..\n");
	return false;
}

bool wfd_server_clear_connected_peer()
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i;
	unsigned char NULL_IP[4] = { 0, 0, 0, 0};

	for (i = 0; i < WFD_MAX_ASSOC_STA; i++)
	{
		wfd_server->connected_peers[i].isUsed = 0;
		memcpy(wfd_server->connected_peers[i].ip_address, NULL_IP, 4);
	}

	wfd_server->connected_peer_count = 0;
		
	__wfd_server_print_connected_peer();
	return true;
}


void wfd_server_reset_connecting_peer()
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	unsigned char NULL_MAC[6] = { 0, 0, 0, 0, 0, 0 };
	memcpy(wfd_server->current_peer.mac_address, NULL_MAC, 6);
	__wfd_server_print_connected_peer();
}

void wfd_server_add_connected_peer(wfd_discovery_entry_s* peer, unsigned char interface_mac[6], char* ip_address)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i;

	for (i = 0; i < WFD_MAX_ASSOC_STA; i++)
	{
		if (wfd_server->connected_peers[i].isUsed == 0)
		{
			wfd_server->connected_peers[i].isUsed = 1;
			memcpy(&wfd_server->connected_peers[i].peer, peer, sizeof(wfd_discovery_entry_s));
			memcpy(wfd_server->connected_peers[i].int_address, interface_mac, 6);
			wfd_server->connected_peer_count++;
			break;
		}
	}
	__wfd_server_print_connected_peer();

}

void wfd_server_remove_connected_peer(wfd_discovery_entry_s * peer)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i;

	for (i = 0; i < WFD_MAX_ASSOC_STA; i++)
	{
		if (wfd_server->connected_peers[i].isUsed==1 &&
				memcmp(wfd_server->connected_peers[i].peer.mac_address, peer->mac_address, 6) == 0 )
		{
			wfd_server->connected_peers[i].isUsed = 0;
			wfd_server->connected_peer_count--;
			memset(&wfd_server->connected_peers[i], 0x00, sizeof(wfd_local_connected_peer_info_t));
			break;
		}
	}
	__wfd_server_print_connected_peer();
}

void wfd_server_remove_connected_peer_by_interface_mac(unsigned char interface_mac[6])
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i;

	for (i = 0; i < WFD_MAX_ASSOC_STA; i++)
	{
		if (wfd_server->connected_peers[i].isUsed==1 &&
				memcmp(wfd_server->connected_peers[i].int_address, interface_mac, 6) == 0 )
		{
			wfd_server->connected_peers[i].isUsed = 0;
			wfd_server->connected_peer_count--;
			memset(&wfd_server->connected_peers[i], 0x00, sizeof(wfd_local_connected_peer_info_t));
			break;
		}
	}
	__wfd_server_print_connected_peer();
}


int wfd_server_is_connected_peer_by_device_mac(unsigned char device_mac[6])
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i;

	for (i = 0; i < WFD_MAX_ASSOC_STA; i++)
	{
		if (wfd_server->connected_peers[i].isUsed==1 &&
				memcmp(wfd_server->connected_peers[i].peer.mac_address, device_mac, 6) == 0 )
		{
			return true;
		}
	}
	return false;
}

wfd_local_connected_peer_info_t* 
wfd_server_get_connected_peer_by_device_mac(unsigned char device_mac[6])
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i;

	for (i = 0; i < WFD_MAX_ASSOC_STA; i++)
	{
		if (wfd_server->connected_peers[i].isUsed==1 &&
				memcmp(wfd_server->connected_peers[i].peer.mac_address, device_mac, 6) == 0 )
		{
			return &wfd_server->connected_peers[i];
		}
	}
	return NULL;
}


wfd_local_connected_peer_info_t* 
wfd_server_get_connected_peer_by_interface_mac(unsigned char int_mac[6])
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i;

	__wfd_server_print_connected_peer();

	for (i = 0; i < WFD_MAX_ASSOC_STA; i++)
	{
		if (wfd_server->connected_peers[i].isUsed == 1 &&
			memcmp(wfd_server->connected_peers[i].int_address, int_mac, 6) == 0)
		{
			WDS_LOGD( "Found: peer[%d] device_name=[%s] int_mac=["MACSTR"] dev_mac=["MACSTR"] cat=[%d] ip=["IPSTR"]\n",
					i,
					wfd_server->connected_peers[i].peer.device_name,
					MAC2STR(wfd_server->connected_peers[i].int_address),
					MAC2STR(wfd_server->connected_peers[i].peer.mac_address),
					wfd_server->connected_peers[i].peer.category,
					IP2STR(wfd_server->connected_peers[i].ip_address));

			return &wfd_server->connected_peers[i];
		}
	}
	return NULL;
}


int wfd_server_is_connected_peer_by_interface_mac(unsigned char interface_mac[6])
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i;

	for (i = 0; i < WFD_MAX_ASSOC_STA; i++)
	{
		if (wfd_server->connected_peers[i].isUsed==1 &&
				memcmp(wfd_server->connected_peers[i].int_address, interface_mac, 6) == 0 )
		{
			return true;
		}
	}
	return false;
}


void wfd_server_process_event(wfd_event_t event)
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	wifi_direct_client_noti_s noti;

	__WDS_LOG_FUNC_ENTER__;

	memset(&noti, 0, sizeof(wifi_direct_client_noti_s));

	noti.event = event;
	noti.error = WIFI_DIRECT_ERROR_NONE;

	wifi_direct_state_e state = wfd_server_get_state();

	WDS_LOGI( "state=[%s] process event= [%s] \n", wfd_print_state(state), __wfd_server_print_event(noti.event));

	if (state == WIFI_DIRECT_STATE_CONNECTING)
	{
		switch (event)
		{
#if 1
		//case WFD_EVENT_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO:
		case WFD_EVENT_GROUP_OWNER_NEGOTIATION_ALREADY_CONNECTED:
		{
			unsigned char mac[6];
			wifi_direct_wps_type_e	wps_config;
		
			wps_config = wfd_server->config_data.wps_config;
			
			wfd_oem_get_requestor_mac(mac);
			if (wfd_oem_connect(mac, wps_config) == true)
			{
				return;
			}
			else
			{
				if (wfd_oem_is_groupowner())
				{
					wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
				}
				else
				{
					wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
				}
				
				snprintf(noti.param1, sizeof(noti.param1),MACSTR, MAC2STR(mac));
				wfd_server_reset_connecting_peer();
				noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
				noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
				__wfd_server_send_client_event(&noti);
			}
		}
		break;
#else
			//case WFD_EVENT_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO:
		case WFD_EVENT_GROUP_OWNER_NEGOTIATION_ALREADY_CONNECTED:
			// fall down
#endif

			// TODO: Do we need to make it, asynchronously?
			// Ignore provision discovery timeout, since provision request used syn API.
			// case WFD_EVENT_PROV_DISCOVERY_TIMEOUT:

			// Fail cases
			//case WFD_EVENT_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL:
		case WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL:
		case WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL_INTENT:
		case WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL_TIMEOUT:
		case WFD_EVENT_WPS_WRONG_PIN:
		case WFD_EVENT_WPS_TIMEOUT:
		case WFD_EVENT_WPS_SESSION_OVERLAP:
		case WFD_EVENT_CREATE_LINK_CANCEL:
			if (event == WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL_TIMEOUT) {
				if (wfd_server->connecting_120) {
					int wps_config = wfd_server->config_data.wps_config;

					if (wfd_server->config_data.want_persistent_group == true)
						wfd_oem_connect_for_persistent_group(wfd_server->current_peer.mac_address, wps_config);
					else
						wfd_oem_connect(wfd_server->current_peer.mac_address, wps_config);
					WDS_LOGD("Retry connection with " MACSTR, MAC2STR(wfd_server->current_peer.mac_address));
					break;
				}
			}

			if (wfd_oem_is_groupowner())
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
			}
			else
			{
				wfd_server_cancel_dhcp_wait_timer();
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			}
			snprintf(noti.param1, sizeof(noti.param1),MACSTR, MAC2STR(wfd_server->current_peer.mac_address));
			wfd_server_reset_connecting_peer();
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
			__wfd_server_send_client_event(&noti);
			//wfd_oem_start_discovery(true, 0);
			break;

		case WFD_EVENT_SOFTAP_FAIL:
			wfd_server_cancel_dhcp_wait_timer();
			wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			wfd_server_reset_connecting_peer();
			noti.event = WIFI_DIRECT_CLI_EVENT_GROUP_CREATE_RSP;
			noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
			__wfd_server_send_client_event(&noti);
			break;

		case WFD_EVENT_CREATE_LINK_TIMEOUT:
		case WFD_EVENT_CREATE_LINK_AUTH_FAIL:
		case WFD_EVENT_CREATE_LINK_FAIL:
			if (wfd_oem_is_groupowner())
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
			}
			else
			{
				wfd_server_cancel_dhcp_wait_timer();
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			}
			snprintf(noti.param1, sizeof(noti.param1),MACSTR, MAC2STR(wfd_server->current_peer.mac_address));
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
			if (event == WFD_EVENT_CREATE_LINK_TIMEOUT)
				noti.error = WIFI_DIRECT_ERROR_CONNECTION_TIME_OUT;
			else if (event == WFD_EVENT_CREATE_LINK_AUTH_FAIL)
				noti.error = WIFI_DIRECT_ERROR_AUTH_FAILED;
			else if (event == WFD_EVENT_CREATE_LINK_FAIL)
				noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
			wfd_server_reset_connecting_peer();

			if (wfd_oem_is_groupowner() == false)
				wfd_server_clear_connected_peer();

			__wfd_server_send_client_event(&noti);
			//wfd_oem_start_discovery(true, 0);
			break;

		case WFD_EVENT_DISCOVER_COMPLETE:
			wfd_server->config_data.listen_only = false;

			noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_END;
			__wfd_server_send_client_event(&noti);

			// TODO:  M-Project "find/scan" concept. First time, we start discovery during 30 seconds  and then try again discovery with Listen only mode continuosly.
			//wfd_oem_start_discovery(true, 0);
			break;

		case WFD_EVENT_CREATE_LINK_COMPLETE:
			{
				if (wfd_oem_is_groupowner())
				{
					unsigned char intf_mac[6] = {0, };

					wfd_oem_get_assoc_sta_mac(intf_mac);
					
					wfd_server_add_connected_peer(&wfd_server->current_peer,
												  intf_mac, NULL);
					wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);

					wfd_local_connected_peer_info_t *peer = NULL;
					peer =
						wfd_server_get_connected_peer_by_interface_mac(intf_mac);
					WDS_LOGI(
								   "Peer's Intf MAC is " MACSTR "\n",
								   MAC2STR(intf_mac));

					if (peer == NULL)
					{
						WDS_LOGI(
									   "Something wrong... Peer's Dev MAC is " MACSTR "\n",
									   MAC2STR(peer->peer.mac_address));
						snprintf(noti.param1, sizeof(noti.param1), MACSTR,
								 MAC2STR(wfd_server->current_peer.mac_address));
					}
					else
					{
						snprintf(noti.param1, sizeof(noti.param1), MACSTR,
								 MAC2STR(peer->peer.mac_address));
					}

					wfd_server_reset_connecting_peer();

					noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;


					__wfd_server_send_client_event(&noti);
				}
				else
				{
					wfd_connected_peer_info_s *peer_list = NULL;

					int peer_num = 0;

					wfd_server_clear_connected_peer();

					wfd_oem_get_connected_peers_info(&peer_list, &peer_num);

					if (peer_num == 1)
					{
						wfd_server_add_connected_peer(&wfd_server->current_peer,
									  peer_list[0].intf_mac_address,
									  NULL);
					}
					else
					{
						unsigned char intf_mac[6] = {0, };
						WDS_LOGI(
									   "Something wrong. peer_num is [%d]\n",
									   peer_num);
						wfd_server_add_connected_peer(&wfd_server->current_peer,
										intf_mac,
										NULL);
					}

					wfd_server_start_dhcp_wait_timer();
				}
			}
			break;

		case WFD_EVENT_IP_ASSIGNED:
		{
				// Update peer IP address which is DHCP server IP.
				char peer_ip_str[20];
				wfd_get_dhcpc_server_ip(peer_ip_str, 20);
				inet_aton(peer_ip_str, (struct in_addr*)&wfd_server->connected_peers[0].ip_address);

				snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(wfd_server->current_peer.mac_address));
				wfd_server_reset_connecting_peer();
				wfd_server_set_state(WIFI_DIRECT_STATE_CONNECTED);
				noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
				__wfd_server_send_client_event(&noti);

			}
			break;

		case WFD_EVENT_CONNECT_PBC_START:
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ;

			WDS_LOGI(
						   "g_incomming_peer_mac_address is " MACSTR "\n",
						   MAC2STR(g_incomming_peer_mac_address));
			//WDS_LOGI( "g_incomming_peer_ssid is [%s]\n", g_incomming_peer_ssid);
			snprintf(noti.param1, sizeof(noti.param1), MACSTR,
					 MAC2STR(g_incomming_peer_mac_address));
			//strncpy(noti.param2, g_incomming_peer_ssid, strlen(g_incomming_peer_ssid));

			__wfd_server_send_client_event(&noti);
			break;

		case WFD_EVENT_PROV_DISCOVERY_REQUEST:
			if (wfd_oem_is_groupowner())
			{
				// provision request comes, when we sent 'invite'...
				wfd_oem_wps_pbc_start(NULL);
			}
			else
			{
				//Ignore provision request during connecting...
			}
			break;

		case WFD_EVENT_PROV_DISCOVERY_RESPONSE_WPS_DISPLAY:
		case WFD_EVENT_PROV_DISCOVERY_RESPONSE_WPS_KEYPAD:
			if (event == WFD_EVENT_PROV_DISCOVERY_RESPONSE_WPS_DISPLAY) {
				wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY;
				wfd_oem_connect(g_incomming_peer_mac_address, wfd_server->config_data.wps_config);
			}
			else if (event == WFD_EVENT_PROV_DISCOVERY_RESPONSE_WPS_KEYPAD)
				wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD;
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ;
			WDS_LOGI("g_incomming_peer_mac_address is [" MACSTR "]\n", MAC2STR(g_incomming_peer_mac_address));
			snprintf(noti.param1, sizeof(noti.param1), MACSTR,	 MAC2STR(g_incomming_peer_mac_address));
			__wfd_server_send_client_event(&noti);
			break;

		case WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_DISPLAY:
		case WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_KEYPAD:
			if (event == WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_DISPLAY) {
				wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY;
				wfd_oem_wps_pin_start(g_incomming_peer_mac_address);
			} else if (event == WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_KEYPAD) {
				wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD;
			}
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ;
			WDS_LOGI("g_incomming_peer_mac_address is [" MACSTR "]\n", MAC2STR(g_incomming_peer_mac_address));
			snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(g_incomming_peer_mac_address));
			__wfd_server_send_client_event(&noti);
		break;
		default:
			WDS_LOGI(
						   "Unprocessed event: state=[%s] event= [%s] \n",
						   wfd_print_state(state),
						   __wfd_server_print_event(noti.event));
			break;
		}
	}
	else if (state == WIFI_DIRECT_STATE_DISCONNECTING)
	{
		switch (event)
		{
		case WFD_EVENT_CREATE_LINK_CANCEL:

			if (wfd_oem_is_groupowner())
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
			}
			else
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			}

			WDS_LOGI( "Peer's Dev MAC is " MACSTR "\n",
						   MAC2STR(wfd_server->current_peer.mac_address));
			snprintf(noti.param1, sizeof(noti.param1), MACSTR,
					 MAC2STR(wfd_server->current_peer.mac_address));

			noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			wfd_server_reset_connecting_peer();
			wfd_server_clear_connected_peer();
			__wfd_server_send_client_event(&noti);
			//wfd_oem_start_discovery(true, 0);
			break;
		case WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL:
			if (wfd_oem_is_groupowner())
			{
				wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
			}
			else
			{
				wfd_server_cancel_dhcp_wait_timer();
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			}
			snprintf(noti.param1, sizeof(noti.param1),MACSTR, MAC2STR(wfd_server->current_peer.mac_address));
			wfd_server_reset_connecting_peer();
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			__wfd_server_send_client_event(&noti);
			break;
		default:
			WDS_LOGI(
						   "Unprocessed event: state=[%s] event= [%s] \n",
						   wfd_print_state(state),
						   __wfd_server_print_event(noti.event));
			break;
		}
	}
	else if (state == WIFI_DIRECT_STATE_CONNECTED ||
			 state == WIFI_DIRECT_STATE_ACTIVATED ||
			 state == WIFI_DIRECT_STATE_DISCOVERING ||
			 state == WIFI_DIRECT_STATE_GROUP_OWNER)
	{
		switch (event)
		{
		case WFD_EVENT_PROV_DISCOVERY_REQUEST:
		case WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_DISPLAY:
		case WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_KEYPAD:
			{
				if (event == WFD_EVENT_PROV_DISCOVERY_REQUEST)
					wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PBC;
				else if (event == WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_DISPLAY)
					wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY;
				else if (event == WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_KEYPAD)
					wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD;

				noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ;
				WDS_LOGI("g_incomming_peer_mac_address is " MACSTR "\n",
							   MAC2STR(g_incomming_peer_mac_address));
				snprintf(noti.param1, sizeof(noti.param1), MACSTR,
						 MAC2STR(g_incomming_peer_mac_address));

				__wfd_server_send_client_event(&noti);
				wfd_server_set_state(WIFI_DIRECT_STATE_CONNECTING);
			}
			break;

		case WFD_EVENT_INVITE_REQUEST:
			{
				noti.event = WIFI_DIRECT_CLI_EVENT_INVITATION_REQ;
				WDS_LOGD("WIFI_DIRECT_CLI_EVENT_INVITATION_REQ");
				snprintf(noti.param1, sizeof(noti.param1), MACSTR,
						 MAC2STR(g_incomming_peer_mac_address));
				__wfd_server_send_client_event(&noti);
			}
			break;

		case WFD_EVENT_SOFTAP_STA_DISASSOC:
			{
				if (wfd_oem_is_groupowner() == true)
				{
					int count = 0;
					unsigned char interface_mac[6];
					wfd_oem_get_disassoc_sta_mac(interface_mac);

					wfd_local_connected_peer_info_t *peer = NULL;
					peer =
						wfd_server_get_connected_peer_by_interface_mac(interface_mac);
					if (peer != NULL)
					{
						WDS_LOGI("Peer's Intf MAC: " MACSTR ", Device MAC:" MACSTR " \n",
									MAC2STR(interface_mac),
									MAC2STR(peer->peer.mac_address));
						snprintf(noti.param1, sizeof(noti.param1), MACSTR,
								 MAC2STR(peer->peer.mac_address));
					}
					else
					{
						WDS_LOGI("Peer's Intf MAC: " MACSTR ", Device MAC:null \n",
									MAC2STR(interface_mac));
						memset(noti.param1, 0, 6);
					}

					wfd_server_remove_connected_peer_by_interface_mac(interface_mac);
					wfd_server_reset_connecting_peer();

					wfd_oem_get_connected_peers_count(&count);
					if (count == 0)
					{
						wfd_server->config_data.wps_config =
							WIFI_DIRECT_WPS_TYPE_PBC;
						if (wfd_oem_disconnect() == false)
							WDS_LOGF("Error!!! wfd_oem_disconnect() failed!!..\n");
						else
							wfd_server_set_state(WIFI_DIRECT_STATE_DISCONNECTING);
					}
					noti.event = WIFI_DIRECT_CLI_EVENT_DISASSOCIATION_IND;
					__wfd_server_send_client_event(&noti);
				}
				else
				{
					WDS_LOGF("Error!!! DISASSOC event come..\n");
				}
			}
			break;

		case WFD_EVENT_PRIMARY_IF_DISCONNECTION:
			WDS_LOGD("Primary interface (wlan0) is down. Just let it up!\n");
			system("ifconfig wlan0 up");
			break;

		case WFD_EVENT_CREATE_LINK_CANCEL:
			{
				if (state == WIFI_DIRECT_STATE_GROUP_OWNER)
				{
					WDS_LOGI("Peer's Dev MAC is " MACSTR "\n",
								   MAC2STR(wfd_server->current_peer.mac_address));
					snprintf(noti.param1, sizeof(noti.param1), MACSTR,
							 MAC2STR(wfd_server->current_peer.mac_address));

					wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PBC;
					noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_IND;
					__wfd_server_send_client_event(&noti);
					wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
				}
				else
				{
					WDS_LOGD("message is ignored [%d] at state=[%d]\n",
								event, state);
				}
				wfd_server_clear_connected_peer();

			}
			break;
		case WFD_EVENT_CREATE_LINK_DOWN:
			{
				if (state >= WIFI_DIRECT_STATE_CONNECTED)
				{
					WDS_LOGI(
								   "Peer's Intf MAC: " MACSTR ", Device MAC:" MACSTR " \n",
								   MAC2STR(wfd_server->connected_peers[0].int_address),
								   MAC2STR(wfd_server->connected_peers[0].peer.mac_address));

					snprintf(noti.param1, sizeof(noti.param1), MACSTR,
							 MAC2STR(wfd_server->connected_peers[0].peer.mac_address));

					wfd_server_clear_connected_peer();
					wfd_server->config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PBC;
					noti.event = WIFI_DIRECT_CLI_EVENT_DISCONNECTION_IND;
					__wfd_server_send_client_event(&noti);
					wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
				}
				else
				{
					WDS_LOGD(
								   "message is ignored [%d] at state=[%d]\n",
								   event, state);
				}
			}
			break;
		case WFD_EVENT_DISCOVER_START_80211_SCAN:
			wfd_server->config_data.listen_only = false;
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_START;
			__wfd_server_send_client_event(&noti);
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING)
				wfd_server_set_state(WIFI_DIRECT_STATE_DISCOVERING);
			break;
#if 0
		case WFD_EVENT_DISCOVER_START_SEARCH_LISTEN:
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_START_SEARCH_LISTEN;
			__wfd_server_send_client_event(&noti);
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING)
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			break;
#endif

		case WFD_EVENT_DISCOVER_START_LISTEN_ONLY:
			wfd_server->config_data.listen_only = true;
		
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_START_LISTEN_ONLY;
			__wfd_server_send_client_event(&noti);
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING)
				wfd_server_set_state(WIFI_DIRECT_STATE_DISCOVERING);
			break;

		case WFD_EVENT_DISCOVER_CANCEL:
		case WFD_EVENT_DISCOVER_COMPLETE:
		case WFD_EVENT_DISCOVER_FAIL:
			wfd_server->config_data.listen_only = false;
		
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_END;
			__wfd_server_send_client_event(&noti);
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING)
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			break;

			// TODO:  M-Project "find/scan" concept. First time, we start discovery during 30 seconds  and then try again discovery with Listen only mode continuosly.
#if 0
		case WFD_EVENT_DISCOVER_COMPLETE:
			noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_END;
			__wfd_server_send_client_event(&noti);
			wfd_oem_start_discovery(true, 0);
			break;
#endif

		case WFD_EVENT_DISCOVER_FOUND_PEERS:
		case WFD_EVENT_DISCOVER_FOUND_P2P_GROUPS:
			{
				if (state == WIFI_DIRECT_STATE_CONNECTED)
				{
					// Note:
					// In case of GC, when connected, interface_mac_address is not updated, since scan is stopped.
					// If scan is started (by user request), then we have changce to get the interface_mac_address.
					//
					unsigned char null_mac[6]={0,};
					if (memcmp(&wfd_server->connected_peers[0].int_address, &null_mac, 6)==0)
					{
						wfd_connected_peer_info_s *peer_list = NULL;
						int peer_num = 0;

						wfd_oem_get_connected_peers_info(&peer_list, &peer_num);

						if (peer_num == 1)
						{
							memcpy(&wfd_server->connected_peers[0].int_address,
									&peer_list[0].intf_mac_address,
									6);
						}
						else
						{
							// Something wrong, and ignore it...
						}
					}
				}
				noti.event = WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS;
				__wfd_server_send_client_event(&noti);
			}
			break;

		case WFD_EVENT_SOFTAP_READY:
			{
				noti.event = WIFI_DIRECT_CLI_EVENT_GROUP_CREATE_RSP;
				__wfd_server_send_client_event(&noti);
			}
			break;

		case WFD_EVENT_SOFTAP_STOP:
			{
				noti.event = WIFI_DIRECT_CLI_EVENT_GROUP_DESTROY_RSP;
				__wfd_server_send_client_event(&noti);
				wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
			}
			break;

		default:
			WDS_LOGI( "Unprocessed event: state=[%s] event= [%s] \n", wfd_print_state(state), __wfd_server_print_event(noti.event));
			break;
		}
	}

	__WDS_LOG_FUNC_EXIT__;
}
