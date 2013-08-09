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

#include "wifi-direct-oem.h"
#include "wifi-direct-utils.h"
#include "wifi-direct-service.h"

unsigned char g_incomming_peer_mac_address[6];
char g_incomming_peer_ssid[32 + 1];
struct wfd_oem_operations *g_ops;

int wfd_oem_init(wfd_oem_event_cb event_callback)
{
	if (NULL == g_ops->wfd_oem_init)
	{
		WDS_LOGE( "g_ops->wfd_oem_init is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_init(event_callback));
}

int wfd_oem_destroy()
{
	if (NULL == g_ops->wfd_oem_destroy)
	{
		WDS_LOGE( "g_ops->wfd_oem_destroy is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_destroy());
}

int wfd_oem_activate()
{
	if (NULL == g_ops->wfd_oem_activate)
	{
		WDS_LOGE( "g_ops->wfd_oem_activate is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_activate());
}

int wfd_oem_deactivate()
{
	if (NULL == g_ops->wfd_oem_deactivate)
	{
		WDS_LOGE( "g_ops->wfd_oem_deactivate is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_deactivate());
}


int wfd_oem_connect(unsigned char mac_addr[6], wifi_direct_wps_type_e	wps_config)
{
	if (NULL == g_ops->wfd_oem_connect)
	{
		WDS_LOGE( "g_ops->wfd_oem_connect is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_connect(mac_addr, wps_config));
}

int wfd_oem_wps_pbc_start(unsigned char mac_addr[6])
{
	if (NULL == g_ops->wfd_oem_wps_pbc_start)
	{
		WDS_LOGE( "g_ops->wfd_oem_wps_pbc_start is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_wps_pbc_start(mac_addr));
}

int wfd_oem_wps_pin_start(unsigned char mac_addr[6])
{
	if (NULL == g_ops->wfd_oem_wps_pin_start)
	{
		WDS_LOGE( "g_ops->wfd_oem_wps_pin_start is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_wps_pin_start(mac_addr));
}

int wfd_oem_disconnect()
{
	if (NULL == g_ops->wfd_oem_disconnect)
	{
		WDS_LOGE( "g_ops->wfd_oem_disconnect is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_disconnect());
}


int wfd_oem_disconnect_sta(unsigned char mac_addr[6])
{
	if (NULL == g_ops->wfd_oem_disconnect_sta)
	{
		WDS_LOGE( "g_ops->wfd_oem_disconnect_sta is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_disconnect_sta(mac_addr));
}

int wfd_oem_reject_connection(unsigned char mac_addr[6])
{
	if (NULL == g_ops->wfd_oem_reject_connection)
	{
		WDS_LOGE( "g_ops->wfd_oem_reject_connection is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_reject_connection(mac_addr));
}

bool wfd_oem_is_discovery_enabled()
{
	if (NULL == g_ops->wfd_oem_is_discovery_enabled)
	{
		WDS_LOGE( "g_ops->wfd_oem_is_discovery_enabled is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_is_discovery_enabled());
}

int wfd_oem_start_discovery(bool listen_only, int timeout)
{
	if (NULL == g_ops->wfd_oem_start_discovery)
	{
		WDS_LOGE( "g_ops->wfd_oem_start_discovery is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_start_discovery(listen_only, timeout));
}

int wfd_oem_restart_discovery()
{
	if (NULL == g_ops->wfd_oem_restart_discovery)
	{
		WDS_LOGE( "g_ops->wfd_oem_restart_discovery is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_restart_discovery());
}

int wfd_oem_cancel_discovery()
{
	if (NULL == g_ops->wfd_oem_cancel_discovery)
	{
		WDS_LOGE( "g_ops->wfd_oem_cancel_discovery is NULL!!\n");
		return false;
	}

	wfd_timer_discovery_cancel();

	return (g_ops->wfd_oem_cancel_discovery());
}

int wfd_oem_get_discovery_result(wfd_discovery_entry_s ** peer_list, int* peer_num)
{
	if (NULL == g_ops->wfd_oem_get_discovery_result)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_discovery_result is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_discovery_result(peer_list, peer_num));
}

int wfd_oem_get_peer_info(unsigned char *mac_addr, wfd_discovery_entry_s **peer)
{
	if (NULL == g_ops->wfd_oem_get_peer_info)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_peer_info is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_peer_info(mac_addr, peer));
}

int wfd_oem_send_provision_discovery_request(unsigned char mac_addr[6], wifi_direct_wps_type_e config_method, int is_peer_go)
{
	if (NULL == g_ops->wfd_oem_send_provision_discovery_request)
	{
		WDS_LOGE( "g_ops->wfd_oem_send_provision_discovery_request is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_send_provision_discovery_request(mac_addr, config_method, is_peer_go));
}

int wfd_oem_send_invite_request(unsigned char dev_mac_addr[6])
{
	if (NULL == g_ops->wfd_oem_send_invite_request)
	{
		WDS_LOGE( "g_ops->wfd_oem_send_invite_request is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_send_invite_request(dev_mac_addr));
}


int wfd_oem_create_group(char* ssid)
{
	if (NULL == g_ops->wfd_oem_create_group)
	{
		WDS_LOGE( "g_ops->wfd_oem_create_group is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_create_group(ssid));
}

int wfd_oem_cancel_group()
{
	if (NULL == g_ops->wfd_oem_cancel_group)
	{
		WDS_LOGE( "g_ops->wfd_oem_cancel_group is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_cancel_group());
}

int wfd_oem_activate_pushbutton()
{
	if (NULL == g_ops->wfd_oem_activate_pushbutton)
	{
		WDS_LOGE( "g_ops->wfd_oem_activate_pushbutton is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_activate_pushbutton());
}

bool wfd_oem_is_groupowner()
{
	if (NULL == g_ops->wfd_oem_is_groupowner)
	{
		WDS_LOGE( "g_ops->wfd_oem_is_groupowner is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_is_groupowner());
}

bool wfd_oem_is_groupclient()
{
	if (NULL == g_ops->wfd_oem_is_groupclient)
	{
		WDS_LOGE( "g_ops->wfd_oem_is_groupclient is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_is_groupclient());
}

#if 0
int wfd_oem_get_link_status()
{
	if (NULL == g_ops->wfd_oem_get_link_status)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_link_status is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_link_status());
}
#endif

int wfd_oem_get_ssid(char* ssid, int len)
{
	if (NULL == g_ops->wfd_oem_get_ssid)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_ssid is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_ssid(ssid, len));
}

bool wfd_oem_dhcpc_get_ip_address(char *ipaddr_buf, int len, int is_IPv6)
{
	if (NULL == g_ops->wfd_oem_dhcpc_get_ip_address)
	{
		WDS_LOGE( "g_ops->wfd_oem_dhcpc_get_ip_address is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_dhcpc_get_ip_address(ipaddr_buf, len, is_IPv6));
}


char* wfd_oem_get_default_interface_name()
{
	if (NULL == g_ops->wfd_oem_get_default_interface_name)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_default_interface_name is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_default_interface_name());
}

char* wfd_oem_get_ip()
{
	if (NULL == g_ops->wfd_oem_get_ip)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_ip is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_ip());
}

int wfd_oem_set_wps_pin(char* pin)
{
	if (NULL == g_ops->wfd_oem_set_wps_pin)
	{
		WDS_LOGE( "g_ops->wfd_oem_set_wps_pin is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_set_wps_pin(pin));
}

int wfd_oem_get_wps_pin(char* wps_pin, int len)
{
	if (NULL == g_ops->wfd_oem_get_wps_pin)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_wps_pin is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_wps_pin(wps_pin, len));
}

int wfd_oem_generate_wps_pin()
{
	if (NULL == g_ops->wfd_oem_generate_wps_pin)
	{
		WDS_LOGE( "g_ops->wfd_oem_generate_wps_pin is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_generate_wps_pin());
}


int wfd_oem_set_ssid(char* ssid)
{
	if (NULL == g_ops->wfd_oem_set_ssid)
	{
		WDS_LOGE( "g_ops->wfd_oem_set_ssid is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_set_ssid(ssid));
}

int wfd_oem_set_wpa_passphrase(char* wpa_key)
{
	if (NULL == g_ops->wfd_oem_set_wpa_passphrase)
	{
		WDS_LOGE( "g_ops->wfd_oem_set_wpa_passphrase is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_set_wpa_passphrase(wpa_key));
}

int wfd_oem_get_supported_wps_mode()
{
	if (NULL == g_ops->wfd_oem_get_supported_wps_mode)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_supported_wps_mode is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_supported_wps_mode());
}

int wfd_oem_get_connected_peers_count(int* peer_num)
{
	if (NULL == g_ops->wfd_oem_get_connected_peers_count)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_connected_peers_count is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_connected_peers_count(peer_num));
}


int wfd_oem_get_connected_peers_info(wfd_connected_peer_info_s ** peer_list, int* peer_num)
{
	if (NULL == g_ops->wfd_oem_get_connected_peers_info)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_connected_peers_info is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_connected_peers_info(peer_list, peer_num));
}


int wfd_oem_get_go_intent(int* intent)
{
	if (NULL == g_ops->wfd_oem_get_go_intent)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_go_intent is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_go_intent(intent));
}


int wfd_oem_set_go_intent(int intent)
{
	if (NULL == g_ops->wfd_oem_set_go_intent)
	{
		WDS_LOGE( "g_ops->wfd_oem_set_go_intent is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_set_go_intent(intent));
}


int wfd_oem_set_device_type(wifi_direct_primary_device_type_e primary_cat, wifi_direct_secondary_device_type_e sub_cat)
{
	if (NULL == g_ops->wfd_oem_set_device_type)
	{
		WDS_LOGE( "g_ops->wfd_oem_set_device_type is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_set_device_type(primary_cat, sub_cat));
}


int wfd_oem_get_device_mac_address(unsigned char* device_mac)
{
	if (NULL == g_ops->wfd_oem_get_device_mac_address)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_device_mac_address is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_device_mac_address(device_mac));
}

int wfd_oem_set_oem_loglevel(int is_increase)
{
	if (NULL == g_ops->wfd_oem_set_oem_loglevel)
	{
		WDS_LOGE( "g_ops->wfd_oem_set_oem_loglevel is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_set_oem_loglevel(is_increase));
}

int wfd_oem_get_disassoc_sta_mac(unsigned char *mac_addr)
{
	if (NULL == g_ops->wfd_oem_get_disassoc_sta_mac)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_disassoc_sta_mac is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_disassoc_sta_mac(mac_addr));
}

int wfd_oem_get_assoc_sta_mac(unsigned char *mac_addr)
{
	if (NULL == g_ops->wfd_oem_get_assoc_sta_mac)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_assoc_sta_mac is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_assoc_sta_mac(mac_addr));
}

int wfd_oem_get_requestor_mac(unsigned char *mac_addr)
{
	if (NULL == g_ops->wfd_oem_get_requestor_mac)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_requestor_mac is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_requestor_mac(mac_addr));
}

int wfd_oem_get_operating_channel()
{
	if (NULL == g_ops->wfd_oem_get_operating_channel)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_operating_channel is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_operating_channel());
}

int wfd_oem_get_persistent_group_info(wfd_persistent_group_info_s ** persistent_group_list, int* persistent_group_num)
{
	if (NULL == g_ops->wfd_oem_get_persistent_group_info)
	{
		WDS_LOGE( "g_ops->wfd_oem_get_persistent_group_info is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_get_persistent_group_info(persistent_group_list, persistent_group_num));
}

int wfd_oem_remove_persistent_group(wfd_persistent_group_info_s *persistent_group)
{
	if (NULL == g_ops->wfd_oem_remove_persistent_group)
	{
		WDS_LOGE( "g_ops->wfd_oem_remove_persistent_group is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_remove_persistent_group(persistent_group));

}

int wfd_oem_set_persistent_group_enabled(bool enabled)
{
	if (NULL == g_ops->wfd_oem_set_persistent_group_enabled)
	{
		WDS_LOGE( "g_ops->wfd_oem_set_persistent_group_enabled is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_set_persistent_group_enabled(enabled));
}

int wfd_oem_connect_for_persistent_group(unsigned char mac_addr[6], wifi_direct_wps_type_e	wps_config)
{
	if (NULL == g_ops->wfd_oem_connect_for_persistent_group)
	{
		WDS_LOGE( "g_ops->wfd_oem_connect_for_persistent_group is NULL!!\n");
		return false;
	}

	return (g_ops->wfd_oem_connect_for_persistent_group(mac_addr, wps_config));
}

