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

/**
 * This file declares wifi direct manager functions and structures.
 *
 * @file		wifi-direct-manager.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_MANAGER_H__
#define __WIFI_DIRECT_MANAGER_H__

#define DEFAULT_DEVICE_NAME "Tizen_Device"
#define DEFAULT_IFNAME "p2p0"
#if defined TIZEN_TV
#	define GROUP_IFNAME "p2p0"
#else
#if defined TIZEN_WLAN_BOARD_SPRD
#	define GROUP_IFNAME "p2p0"
#else /* TIZEN_WLAN_BOARD_SPRD */
#	define GROUP_IFNAME "p2p-wlan0-0"
#endif /* TIZEN_WLAN_BOARD_SPRD */
#endif
#define WFD_MAX_CLIENT 16
#define WFD_MAX_STATION 8

#define DEV_NAME_LEN 32
#define MACADDR_LEN 6
#define MACSTR_LEN 18
#define IPADDR_LEN 4
#define IPSTR_LEN 16
#define PINSTR_LEN 8
#define PASSPHRASE_LEN_MAX 63
#define PASSPHRASE_LEN_MIN 8

#if 0
typedef enum {
	WFD_STATE_DEACTIVATED,
	WFD_STATE_ACTIVATED,
	WFD_STATE_IDLE,			// passive scaning
	WFD_STATE_SCANNING,		// active scanning
	WFD_STATE_CONNECTING,
	WFD_STATE_CONNECTED,
} wfd_state_e;
#endif

typedef enum {
	WFD_WPS_MODE_NONE,
	WFD_WPS_MODE_PBC = 0x1,
	WFD_WPS_MODE_DISPLAY = 0x2,
	WFD_WPS_MODE_KEYPAD = 0x4,
} wfd_wps_mode_e;

typedef enum {
	WFD_DEV_ROLE_NONE,
	WFD_DEV_ROLE_GC,
	WFD_DEV_ROLE_GO,
} wfd_dev_role_e;

typedef enum {
	WFD_SCAN_MODE_NONE,
	WFD_SCAN_MODE_ACTIVE,
	WFD_SCAN_MODE_PASSIVE,
} wfd_scan_mode_e;

typedef enum {
	WFD_PEER_STATE_DISCOVERED,
	WFD_PEER_STATE_CONNECTING,
	WFD_PEER_STATE_CONNECTED,
} wfd_peer_state_e;

typedef enum {
	WFD_IP_TYPE_DYNAMIC = 0x0,
	WFD_IP_TYPE_OVER_EAPOL = 0x1,
} wfd_ip_type_e;

#ifdef TIZEN_FEATURE_WIFI_DISPLAY

typedef enum {
	WFD_DISPLAY_TYPE_SOURCE,
	WFD_DISPLAY_TYPE_PRISINK,
	WFD_DISPLAY_TYPE_SECSINK,
	WFD_DISPLAY_TYPE_DUAL,
} wfd_display_type_e;

typedef struct {
	int type;
	int availablity;
	int wsd_support;
	int tdls_support;
	int hdcp_support;
	int sync_support;
	int port;
	int max_tput;
} wfd_display_s;

#define WIFI_DISPLAY_DEFAULT_TYPE WFD_DISPLAY_TYPE_SOURCE
#define WIFI_DISPLAY_DEFAULT_AVAIL 1
#define WIFI_DISPLAY_DEFAULT_HDCP 1
#define WIFI_DISPLAY_DEFAULT_PORT 7236
#define WIFI_DISPLAY_DEFAULT_TPUT 54
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

typedef struct {
	int state;
	unsigned long time;

	char dev_name[DEV_NAME_LEN+1];
	unsigned char dev_addr[MACADDR_LEN];
	unsigned char intf_addr[MACADDR_LEN];
	unsigned char go_dev_addr[MACADDR_LEN];
	int channel;
	int dev_role;
	int config_methods;
	int pri_dev_type;
	int sec_dev_type;
	int dev_flags;
	int group_flags;
	int wps_mode;

	char passphrase[PASSPHRASE_LEN_MAX + 1];

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	wfd_display_s display;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	GList *services;
	unsigned int service_count;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

	unsigned char ip_addr[IPADDR_LEN];

	int ip_type;
	unsigned char client_ip_addr[IPADDR_LEN];
	unsigned char go_ip_addr[IPADDR_LEN];
} wfd_device_s;

typedef struct {
	GMainLoop *main_loop;

	int serv_sock;
	unsigned int client_handle;	// for accept clients
	GList *clients;
	unsigned int client_count;

	wifi_direct_state_e state;
	unsigned int exit_timer;

	wfd_device_s *local;
	int go_intent;
	int req_wps_mode;
	int max_station;
	int autoconnection;
	unsigned char autoconnection_peer[MACADDR_LEN];
	char auto_pin[PINSTR_LEN+1];	// for NFC Printer
	int scan_mode;

	GList *peers;
	unsigned int peer_count;

	void *session;

	void *group;

	void *oem_ops;
	void *plugin_handle;
} wfd_manager_s;

wfd_manager_s *wfd_get_manager();
int wfd_local_reset_data(wfd_manager_s *manager);
int wfd_local_get_dev_name(char *dev_name);
int wfd_local_set_dev_name(char *dev_name);
int wfd_local_get_dev_mac(char *dev_mac);
#if 0
int wfd_local_get_intf_mac(unsigned char *intf_mac);
int wfd_local_set_wps_mode(int wps_mode);
wfd_device_s *wfd_manager_find_connected_peer(wfd_manager_s *manager, unsigned char *peer_addr);
#endif
int wfd_local_get_ip_addr(char *ip_str);
int wfd_local_get_supported_wps_mode(int *wps_mode);
int wfd_local_get_wps_mode(int *wps_mode);
int wfd_manager_get_go_intent(int *go_intent);
int wfd_manager_set_go_intent(int go_intent);
int wfd_manager_get_max_station(int *max_station);
int wfd_manager_set_max_station(int max_station);
int wfd_manager_get_autoconnection(int *autoconnection);
int wfd_manager_set_autoconnection(int autoconnection);
int wfd_manager_get_req_wps_mode(int *req_wps_mode);
int wfd_manager_set_req_wps_mode(int req_wps_mode);

int wfd_manager_local_config_set(wfd_manager_s *manager);
int wfd_manager_activate(wfd_manager_s *manager);
int wfd_manager_deactivate(wfd_manager_s *manager);
int wfd_manager_connect(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_accept_connection(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_cancel_connection(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_reject_connection(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_disconnect(wfd_manager_s *manager, unsigned char *peer_addr);
int wfd_manager_disconnect_all(wfd_manager_s *manager);
int wfd_manager_get_peer_info(wfd_manager_s *manager, unsigned char* addr, wfd_discovery_entry_s **peer);
int wfd_manager_get_peers(wfd_manager_s *manager, wfd_discovery_entry_s **peers);
int wfd_manager_get_connected_peers(wfd_manager_s *manager, wfd_connected_peer_info_s **peers_data);
int wfd_manager_get_goup_ifname(char **ifname);
wfd_device_s *wfd_manager_get_peer_by_addr(wfd_manager_s *manager, unsigned char *peer_addr);
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
int wfd_manager_set_display_device(int type, int port, int hdcp);
int wfd_manager_set_session_availability(int availability);
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

#endif /* __WIFI_DIRECT_MANAGER_H__ */
