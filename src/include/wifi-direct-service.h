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

#ifndef __WIFI_DIRECT_SERVICE_H_
#define __WIFI_DIRECT_SERVICE_H_

#include "wifi-direct.h"
#include "wifi-direct-internal.h"
#include "wifi-direct-event-handler.h"
//#include "wifi-direct-utils.h"

/*****************************************************************************
 * 	Macros
 *****************************************************************************/
#define WFD_MAX_CLIENTS  		16
#define WFD_MAX_ASSOC_STA        8

#define WFD_SERVER_SOCKET_PATH "/tmp/wfd_client_socket"

/*****************************************************************************
 * 	Definitions
 *****************************************************************************/

typedef struct
{
	bool	 	isUsed;
	int 		client_id;
	int 		sync_sockfd;
	int 		async_sockfd;
	int 		dev_handle;
	int			g_source_id;
} wfd_server_client_t;



/**
 * @enum wfd_connected_dev_info_t
 * Wi-Fi Direct buffer structure to store device information of connected peer  */
typedef struct
{
	/** Null-terminated device friendly name. */
	char ssid[WIFI_DIRECT_MAX_SSID_LEN + 1];

	/** Peer's P2P Device Address */
	unsigned char mac_address[6];

	/** Peer's P2P Interface Address.  Valid only if our device is a P2P GO. */
	unsigned char	int_address[6];

	/** Peer's P2P IP Address.  Valid only if our device is a P2P GO. */
	unsigned char	ip_address[4];

} wfd_connected_dev_info_t;


/**
 * @enum wfd_connected_dev_info_t
 * Wi-Fi Direct buffer structure to store device information of connected peer  */
typedef struct
{
    bool isUsed;

    wfd_discovery_entry_s peer;

    /** Peer's P2P Interface Address.  Valid only if our device is a P2P GO. */
    unsigned char	int_address[6];

    /** Peer's P2P IP Address.  Valid only if our device is a P2P GO. */
    unsigned char	ip_address[4];
} wfd_local_connected_peer_info_t;


typedef struct
{
	wfd_server_client_t	client[WFD_MAX_CLIENTS];
	int 		active_clients;

	int 		sync_sockfd;
	int 		async_sockfd;

	wfd_config_data_s 	config_data;

	wifi_direct_state_e	state;
	int connecting_120;

	wfd_discovery_entry_s current_peer;   // it is used during connecting/disconnecting

	wfd_local_connected_peer_info_t connected_peers[WFD_MAX_ASSOC_STA];
	int connected_peer_count;

	int dhcp_pid;

	void* mainloop;

	/** Daemon timer */
	int connection_timer;
	int termination_timer;
	int discovery_timer;

	int dhcp_ip_address_timer;

	/** Autonomous Group mode */
	bool autonomous_group_owner;

	void *plugin_handle;
}wfd_server_control_t;


/*****************************************************************************
 * 	Functions
 *****************************************************************************/
wfd_server_control_t * wfd_server_get_control();
char * wfd_server_print_cmd(wifi_direct_cmd_e cmd);

void wfd_refresh_wifi_direct_state(void *data);

int wfd_server_check_valid(wifi_direct_cmd_e command);
void wfd_server_set_state(int state);
int wfd_server_get_state();
void wfd_timer_connection_start();	
void wfd_timer_connection_cancel();
void wfd_termination_timer_start();
void wfd_termination_timer_cancel();
void wfd_timer_discovery_start(int seconds);
void wfd_timer_discovery_cancel();

int wfd_server_is_connected_peer_by_device_mac(unsigned char device_mac[6]);
wfd_local_connected_peer_info_t*
wfd_server_get_connected_peer_by_device_mac(unsigned char device_mac[6]);
wfd_local_connected_peer_info_t*
wfd_server_get_connected_peer_by_interface_mac(unsigned char int_mac[6]);
int wfd_server_is_connected_peer_by_interface_mac(unsigned char interface_mac[6]);
void wfd_server_remove_connected_peer_by_interface_mac(unsigned char interface_mac[6]);
void wfd_server_remove_connected_peer(wfd_discovery_entry_s * peer);
void wfd_server_add_connected_peer(wfd_discovery_entry_s* peer, unsigned char interface_mac[6], char* ip_address);
void wfd_server_reset_connecting_peer();
bool wfd_server_clear_connected_peer();
bool wfd_server_remember_connecting_peer(unsigned char device_mac[6]);
void wfd_server_process_event(wfd_event_t event);

char *__wfd_server_print_event(wfd_event_t event);
char *__wfd_print_client_event(wfd_client_event_e event);
char *wfd_print_state(wifi_direct_state_e s);


#endif 		//__WIFI_DIRECT_SERVICE_H_
