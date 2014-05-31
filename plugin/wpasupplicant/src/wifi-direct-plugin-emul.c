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

#include <glib.h>
#include <glib-object.h>

//#include "wifi-direct-utils.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-service.h"
#include "wifi-direct-wpasupplicant.h"


unsigned char g_incomming_peer_mac_address[6] = {0,};
char g_incomming_peer_ssid[32 + 1] = {0,};


static struct wfd_oem_operations supplicant_ops =
{
	.wfd_oem_init = wfd_ws_init,
	.wfd_oem_destroy = wfd_ws_destroy,
	.wfd_oem_activate = wfd_ws_activate,
	.wfd_oem_deactivate = wfd_ws_deactivate,
	.wfd_oem_connect = wfd_ws_connect,
	.wfd_oem_disconnect = wfd_ws_disconnect,
	.wfd_oem_disconnect_sta = wfd_ws_disconnect_sta,
	.wfd_oem_start_discovery = wfd_ws_start_discovery,
	.wfd_oem_cancel_discovery = wfd_ws_cancel_discovery,
	.wfd_oem_get_discovery_result = wfd_ws_get_discovery_result,
	.wfd_oem_get_peer_info = wfd_ws_get_peer_info,
	.wfd_oem_send_provision_discovery_request = wfd_ws_send_provision_discovery_request,
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


#if 1  // Threadsafe event handling.

void __wfd_ws_callback(wfd_event_t event)
{

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
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return true;
}

int wfd_ws_destroy()
{
	__WDP_LOG_FUNC_ENTER__;

	// Do nothing upto now...

	__WDP_LOG_FUNC_EXIT__;
	return false;
}

int wfd_ws_activate()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_deactivate()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


int wfd_ws_connect(unsigned char mac_addr[6], wifi_direct_wps_type_e wps_config)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_disconnect()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


int wfd_ws_disconnect_sta(unsigned char mac_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

bool wfd_ws_is_discovery_enabled()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_start_discovery(bool listen_only, int timeout)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_cancel_discovery()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_get_discovery_result(wfd_discovery_entry_s ** peer_list, int* peer_num)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;

}

int wfd_ws_get_peer_info(unsigned char *mac_addr, wfd_discovery_entry_s **peer)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_send_provision_discovery_request(unsigned char mac_addr[6], wifi_direct_wps_type_e config_method, int is_peer_go)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


int wfd_ws_create_group(char* ssid)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_cancel_group()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_activate_pushbutton()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

bool wfd_ws_is_groupowner()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

bool wfd_ws_is_groupclient()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_get_ssid(char* ssid, int len)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;

}

bool wfd_ws_dhcpc_get_ip_address(char *ipaddr_buf, int len, int is_IPv6)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


char* wfd_ws_get_ip()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;

}

int wfd_ws_set_wps_pin(char* pin)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_get_wps_pin(char* wps_pin, int len)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_generate_wps_pin()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


int wfd_ws_set_ssid(char* ssid)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_set_wpa_passphrase(char* wpa_key)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_get_supported_wps_mode()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_get_connected_peers_count(int* peer_num)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


int wfd_ws_get_connected_peers_info(wfd_connected_peer_info_s ** peer_list, int* peer_num)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


int wfd_ws_get_go_intent(int* intent)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_set_go_intent(int go_intent)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


int wfd_ws_set_device_type(wifi_direct_primary_device_type_e primary_cat, wifi_direct_secondary_device_type_e sub_cat)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


int wfd_ws_get_device_mac_address(unsigned char* device_mac)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_set_oem_loglevel(int is_increase)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}


int wfd_ws_get_assoc_sta_mac(unsigned char mac_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}
int wfd_ws_get_disassoc_sta_mac(unsigned char mac_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_get_requestor_mac(unsigned char mac_addr[6])
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_get_operating_channel()
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_get_persistent_group_info(wfd_persistent_group_info_s ** persistent_group_list, int* persistent_group_num)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_remove_persistent_group(wfd_persistent_group_info_s *persistent_group)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_set_persistent_reconnect(bool enabled)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

int wfd_ws_connect_for_persistent_group(unsigned char mac_addr[6], wifi_direct_wps_type_e wps_config)
{
	__WDP_LOG_FUNC_ENTER__;
	return false;
}

