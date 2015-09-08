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
 * This file declares wifi direct oem functions and structures.
 *
 * @file		wifi-direct-ome.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_OEM_H__
#define __WIFI_DIRECT_OEM_H__

#define SUPPL_PLUGIN_PATH "/usr/lib/wifi-direct-plugin-wpasupplicant.so"

#define OEM_MACSTR_LEN 18
#define OEM_MACADDR_LEN 6
#define OEM_IPADDR_LEN 4
#define OEM_PINSTR_LEN 8
#define OEM_PASS_PHRASE_LEN 8
#define OEM_DEV_NAME_LEN 32
#define OEM_IFACE_NAME_LEN 16
#define OEM_SERVICE_TYPE_LEN 8
#define OEM_QUERY_ID_LEN 15
#define OEM_SERVICE_MAX_LEN 1024

typedef enum {
	WFD_OEM_SC_SUCCESS = 0,
	WFD_OEM_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE = 1,
	WFD_OEM_SC_FAIL_INCOMPATIBLE_PARAMS = 2,
	WFD_OEM_SC_FAIL_LIMIT_REACHED = 3,
	WFD_OEM_SC_FAIL_INVALID_PARAMS = 4,
	WFD_OEM_SC_FAIL_UNABLE_TO_ACCOMMODATE = 5,
	WFD_OEM_SC_FAIL_PREV_PROTOCOL_ERROR = 6,
	WFD_OEM_SC_FAIL_NO_COMMON_CHANNELS = 7,
	WFD_OEM_SC_FAIL_UNKNOWN_GROUP = 8,
	WFD_OEM_SC_FAIL_BOTH_GO_INTENT_15 = 9,
	WFD_OEM_SC_FAIL_INCOMPATIBLE_PROV_METHOD = 10,
	WFD_OEM_SC_FAIL_REJECTED_BY_USER = 11,
} wfd_oem_status_code_e;

typedef enum {
	WFD_OEM_EVENT_NONE,
	WFD_OEM_EVENT_DEACTIVATED,
	WFD_OEM_EVENT_PEER_FOUND,
	WFD_OEM_EVENT_PEER_DISAPPEARED,
	WFD_OEM_EVENT_DISCOVERY_FINISHED,

	WFD_OEM_EVENT_PROV_DISC_REQ,	// 5
	WFD_OEM_EVENT_PROV_DISC_DISPLAY,
	WFD_OEM_EVENT_PROV_DISC_KEYPAD,
	WFD_OEM_EVENT_PROV_DISC_RESP,
	WFD_OEM_EVENT_PROV_DISC_FAIL,

	WFD_OEM_EVENT_GO_NEG_REQ,	// 10
	WFD_OEM_EVENT_GO_NEG_FAIL,
	WFD_OEM_EVENT_GO_NEG_DONE,
	WFD_OEM_EVENT_WPS_FAIL,
	WFD_OEM_EVENT_WPS_DONE,
	WFD_OEM_EVENT_KEY_NEG_FAIL,	// 15
	WFD_OEM_EVENT_KEY_NEG_DONE,

	WFD_OEM_EVENT_CONN_FAIL,
	WFD_OEM_EVENT_CONN_DONE,

	WFD_OEM_EVENT_GROUP_CREATED,
	WFD_OEM_EVENT_GROUP_DESTROYED,	// 20

	WFD_OEM_EVENT_INVITATION_REQ,
	WFD_OEM_EVENT_INVITATION_RES,
	WFD_OEM_EVENT_STA_CONNECTED,
	WFD_OEM_EVENT_STA_DISCONNECTED,

	WFD_OEM_EVENT_CONNECTED,	// 25
	WFD_OEM_EVENT_DISCONNECTED,

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	WFD_OEM_EVENT_SERV_DISC_RESP,
	WFD_OEM_EVENT_SERV_DISC_STARTED,
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

	WFD_OEM_EVENT_TERMINATING,
	WFD_OEM_EVENT_MAX,
} wfd_oem_event_e;

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
typedef enum {
	WFD_OEM_DISPLAY_TYPE_SOURCE,
	WFD_OEM_DISPLAY_TYPE_PRISINK,
	WFD_OEM_DISPLAY_TYPE_SECSINK,
	WFD_OEM_DISPLAY_TYPE_DUAL,
} wfd_oem_display_type_e;

typedef struct {
	int type;
	int availablity;
	int wsd_support;
	int tdls_support;
	int hdcp_support;
	int sync_support;
	int port;
	int max_tput;
} wfd_oem_display_s;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

typedef struct {
	int age;
	char dev_name[OEM_DEV_NAME_LEN+1];
	unsigned char dev_addr[OEM_MACADDR_LEN];
	unsigned char intf_addr[OEM_MACADDR_LEN];
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
	int channel;
	int dev_role;
	int config_methods;
	int pri_dev_type;
	int sec_dev_type;
	int dev_flags;
	int group_flags;
	int wps_mode;
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	wfd_oem_display_s *display;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
} wfd_oem_device_s;

typedef struct {
	unsigned char p2p_dev_addr[OEM_MACADDR_LEN];
	unsigned char p2p_intf_addr[OEM_MACADDR_LEN];
	char name[OEM_DEV_NAME_LEN + 1];
	int pri_dev_type;
	int sec_dev_type;
	int config_methods;
	int dev_flags;
	int group_flags;
	int dev_role;
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	wfd_oem_display_s *display;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
	unsigned char p2p_go_addr[OEM_MACADDR_LEN];
} wfd_oem_dev_data_s;

typedef struct {
	unsigned char peer_intf_addr[OEM_MACADDR_LEN];
	int wps_mode;
	int status;
	int error;
} wfd_oem_conn_data_s;

typedef struct {
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
	unsigned char bssid[OEM_MACADDR_LEN];
	int listen;
	int status;
} wfd_oem_invite_data_s;

typedef struct {
	char ssid[OEM_DEV_NAME_LEN+1];
	int freq;
	char pass[OEM_PASS_PHRASE_LEN+1];
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
} wfd_oem_group_data_s;

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
typedef enum {
	WFD_OEM_SERV_STATUS_SUCCESS,
	WFD_OEM_SERV_STATUS_FAIL,
} wfd_oem_serv_status_e;

typedef enum {
	WFD_OEM_SERV_TYPE_ALL,
	WFD_OEM_SERV_TYPE_BTADDR,
} wfd_oem_serv_type_e;

typedef struct {
	int status;
	int type;
	unsigned char data[OEM_MACADDR_LEN];
	unsigned char value[20];
} wfd_oem_service_data_s;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

typedef struct {
	int event_id;
	unsigned char dev_addr[OEM_MACADDR_LEN];	// device address
	unsigned char intf_addr[OEM_MACADDR_LEN];
	int wps_mode;
	char wps_pin[OEM_PINSTR_LEN+1];	// just for DISPLAY
	char ifname[OEM_IFACE_NAME_LEN+1];
	int dev_role;
	int edata_type;
	void *edata;
} wfd_oem_event_s;

typedef enum {
	WFD_OEM_EDATA_TYPE_NONE,
	WFD_OEM_EDATA_TYPE_DEVICE,
	WFD_OEM_EDATA_TYPE_CONN,
	WFD_OEM_EDATA_TYPE_INVITE,
	WFD_OEM_EDATA_TYPE_GROUP,
	WFD_OEM_EDATA_TYPE_SERVICE,
	WFD_OEM_EDATA_TYPE_NEW_SERVICE,
} ws_event_type_e;

typedef enum {
	WFD_OEM_SCAN_MODE_ACTIVE,
	WFD_OEM_SCAN_MODE_PASSIVE,
} wfd_oem_scan_mode_e;

typedef enum {
	WFD_OEM_SCAN_TYPE_FULL,
	WFD_OEM_SCAN_TYPE_SOCIAL,
	WFD_OEM_SCAN_TYPE_SPECIFIC,
	WFD_OEM_SCAN_TYPE_CHANNEL1,
	WFD_OEM_SCAN_TYPE_CHANNEL6,
	WFD_OEM_SCAN_TYPE_CHANNEL11,
	WFD_OEM_SCAN_TYPE_GO_FREQ,
} wfd_oem_scan_type_e;

typedef enum {
	WFD_OEM_WPS_MODE_NONE,
	WFD_OEM_WPS_MODE_PBC = 0x1,
	WFD_OEM_WPS_MODE_DISPLAY = 0x2,
	WFD_OEM_WPS_MODE_KEYPAD = 0x4,
} wfd_oem_wps_mode_e;

#define WFD_OEM_GROUP_FLAG_GROUP_OWNER 0x1
#define WFD_OEM_GROUP_FLAG_PERSISTENT_GROUP 0x2

typedef enum {
	WFD_OEM_CONN_TYPE_NONE,
	WFD_OEM_CONN_TYPE_JOIN,
	WFD_OEM_CONN_TYPE_AUTH,
	WFD_OEM_CONN_TYPE_PERSISTENT = 0x4,
} wfd_oem_conn_flag_e;

typedef enum {
	WFD_OEM_DEV_ROLE_NONE,
	WFD_OEM_DEV_ROLE_GC,
	WFD_OEM_DEV_ROLE_GO,
} wfd_oem_dev_role_e;

typedef struct {
	int scan_mode;
	int scan_time;
	int scan_type;
	int freq;
	int refresh;
} wfd_oem_scan_param_s;

typedef struct {
	int wps_mode;
	int conn_flags;	// join, auth, persistent
	int go_intent;
	int freq;
	char wps_pin[OEM_PINSTR_LEN+1];
} wfd_oem_conn_param_s;

typedef struct {
	int net_id;
	char *ifname;
	unsigned char go_dev_addr[OEM_MACADDR_LEN];
} wfd_oem_invite_param_s;

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
typedef enum {
	WFD_OEM_SERVICE_TYPE_ALL,
	WFD_OEM_SERVICE_TYPE_BONJOUR,
	WFD_OEM_SERVICE_TYPE_UPNP,
	WFD_OEM_SERVICE_TYPE_WS_DISCOVERY,
	WFD_OEM_SERVICE_TYPE_WIFI_DISPLAY,
	WFD_OEM_SERVICE_TYPE_BT_ADDR,
	WFD_OEM_SERVICE_TYPE_CONTACT_INFO,
	WFD_OEM_SERVICE_TYPE_VENDOR = 0xff,
} wfd_oem_service_type_e;

typedef enum {
	WFD_OEM_BONJOUR_RDATA_PTR = 0x0c,
	WFD_OEM_BONJOUR_RDATA_TXT = 0x10,
}wfd_oem_bonjour_rdata_type_e;

typedef struct {
	/** Device address for which service discovery is requested */
	char dev_addr[OEM_MACSTR_LEN+1];

	/** service type requested */
	char service_type[OEM_SERVICE_TYPE_LEN+1];

	/** query identifier returned by wpa_supplicant for each service discovery request */
	char query_id[OEM_QUERY_ID_LEN+1];
} wfd_oem_service_s;

typedef struct {
	int protocol;
	int trans_id;
	int status;
	char *str_ptr;
	union {
		struct {
			char *version;
			char *service;
		} upnp;
		struct {
			char *query;
			char *rdata;
			wfd_oem_bonjour_rdata_type_e rdata_type;
		} bonjour;
		struct {
			char *data1;
			char *data2;
		} vendor;
	} data;
} wfd_oem_new_service_s;	
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

typedef struct
{
	int network_id;
	char ssid[OEM_DEV_NAME_LEN + 1];
	unsigned char go_mac_address[OEM_MACADDR_LEN];
} wfd_oem_persistent_group_s;

typedef int (*wfd_oem_event_cb) (void *user_data, void *event);

typedef struct _wfd_oem_ops_s {
	int (*init) (wfd_oem_event_cb event_callback, void *user_data);
	int (*deinit) (void);
	int (*activate) (int concurrent);
	int (*deactivate) (int concurrent);
	int (*start_scan) (wfd_oem_scan_param_s *param);
	int (*stop_scan) (void);
	int (*get_visibility) (int *visibility);
	int (*set_visibility) (int visibility);
	int (*get_scan_result) (GList **peers, int *peer_count);
	int (*get_peer_info) (unsigned char *peer_addr, wfd_oem_device_s **peer);
	int (*prov_disc_req) (unsigned char *peer_addr, wfd_oem_wps_mode_e wps_mode, int join);
	int (*connect) (unsigned char *peer_addr, wfd_oem_conn_param_s *param);
	int (*disconnect) (unsigned char *peer_addr);
	int (*reject_connection) (unsigned char *peer_addr);
	int (*cancel_connection) (unsigned char *peer_addr);
	int (*get_connected_peers) (GList **peers, int *peer_count);
	int (*wps_start) (unsigned char *peer_addr, int wps_mode, const char *pin);
	int (*enrollee_start) (unsigned char *peer_addr, int wps_mode, const char *pin);
	int (*wps_cancel) (void);
	int (*get_pin) (char *pin);
	int (*set_pin) (char *pin);
//	int (*generate_pin) (char *pin);
	int (*get_supported_wps_mode) (int *wps_mode);
	int (*create_group) (int persistent, int freq);
	int (*destroy_group) (const char *ifname);
	int (*invite) (unsigned char *peer_addr, wfd_oem_invite_param_s *param);

	int (*get_dev_name) (char *dev_name);
	int (*set_dev_name) (char *dev_name);
	int (*get_dev_mac) (char *dev_mac);
	int (*get_dev_type) (int *pri_dev_type, int *sec_dev_type);
	int (*set_dev_type) (int pri_dev_type, int sec_dev_type);
	int (*get_go_intent) (int *go_intent);
	int (*set_go_intent) (int go_intent);
	int (*set_country) (char *ccode);
//	int (*get_country) (char **ccode);

	int (*get_persistent_groups) (wfd_oem_persistent_group_s **groups, int *group_count);
	int (*remove_persistent_group) (char *ssid, unsigned char *bssid);
	int (*set_persistent_reconnect) (unsigned char *bssid, int reconnect);

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	int (*register_local_service) (int service_type, char *value);
	int (*deregister_local_service) (int service_type);
	int (*start_service_discovery) (unsigned char mac_addr[6], int service_type);
	int (*cancel_service_discovery) (unsigned char mac_addr[6], int service_type);

	int (*serv_add) (wfd_oem_new_service_s *service);
	int (*serv_del) (wfd_oem_new_service_s *service);
	int (*serv_disc_start) (wfd_oem_new_service_s *service);
	int (*serv_disc_stop) (int handle);
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	int (*miracast_init) (int enable);
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

	int (*refresh) (void);

} wfd_oem_ops_s;

int wfd_oem_init(wfd_oem_ops_s *ops, wfd_oem_event_cb event_callback, void *user_data);
int wfd_oem_destroy(wfd_oem_ops_s *ops);
int wfd_oem_activate(wfd_oem_ops_s *ops, int concurrent);
int wfd_oem_deactivate(wfd_oem_ops_s *ops, int concurrent);
int wfd_oem_start_scan(wfd_oem_ops_s *ops, wfd_oem_scan_param_s *param);
int wfd_oem_stop_scan(wfd_oem_ops_s *ops);
int wfd_oem_get_visibility(wfd_oem_ops_s *ops, int *visibility);
int wfd_oem_set_visibility(wfd_oem_ops_s *ops, int visibility);
int wfd_oem_get_scan_result(wfd_oem_ops_s *ops, GList **peers, int *peer_count);
int wfd_oem_get_peer_info(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_device_s **peer);
int wfd_oem_prov_disc_req(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_wps_mode_e wps_mode, int join);
int wfd_oem_connect(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_conn_param_s *param);
int wfd_oem_disconnect(wfd_oem_ops_s *ops, unsigned char *peer_addr);
int wfd_oem_reject_connection(wfd_oem_ops_s *ops, unsigned char *peer_addr);
int wfd_oem_cancel_connection(wfd_oem_ops_s *ops, unsigned char *peer_addr);
int wfd_oem_get_connected_peers(wfd_oem_ops_s *ops, GList **peers, int *peer_count);
int wfd_oem_wps_start(wfd_oem_ops_s *ops, unsigned char *peer_addr, int wps_mode, const char *pin);
int wfd_oem_enrollee_start(wfd_oem_ops_s *ops, unsigned char *peer_addr, int wps_mode, const char *pin);
int wfd_oem_wps_cancel(wfd_oem_ops_s *ops);
int wfd_oem_get_pin(wfd_oem_ops_s *ops, char *pin);
int wfd_oem_set_pin(wfd_oem_ops_s *ops, char *pin);
//int wfd_oem_generate_pin(wfd_oem_ops_s *ops, char *pin);
int wfd_oem_get_supported_wps_mode(wfd_oem_ops_s *ops, int *wps_mode);
int wfd_oem_create_group(wfd_oem_ops_s *ops, int persistent, int freq);
int wfd_oem_destroy_group(wfd_oem_ops_s *ops, const char *ifname);
int wfd_oem_invite(wfd_oem_ops_s *ops, unsigned char *peer_addr, wfd_oem_invite_param_s *param);

int wfd_oem_get_dev_name(wfd_oem_ops_s *ops, char *dev_name);
int wfd_oem_set_dev_name(wfd_oem_ops_s *ops, char *dev_name);
int wfd_oem_get_dev_mac(wfd_oem_ops_s *ops, char *dev_mac);
int wfd_oem_get_dev_type(wfd_oem_ops_s *ops, int *pri_dev_type, int *sec_dev_type);
int wfd_oem_set_dev_type(wfd_oem_ops_s *ops, int priv_dev_type, int sec_dev_type);
int wfd_oem_get_go_intent(wfd_oem_ops_s *ops, int *go_intent);
int wfd_oem_set_go_intent(wfd_oem_ops_s *ops, int go_intent);
int wfd_oem_set_country(wfd_oem_ops_s *ops, char *ccode);

int wfd_oem_get_persistent_groups(wfd_oem_ops_s *ops, wfd_oem_persistent_group_s **groups, int *group_count);
int wfd_oem_remove_persistent_group(wfd_oem_ops_s *ops, char *ssid, unsigned char *bssid);
int wfd_oem_set_persistent_reconnect(wfd_oem_ops_s *ops, unsigned char *bssid, int reconnect);

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
int wfd_oem_register_local_service(wfd_oem_ops_s *ops, int service_type, char *value);
int wfd_oem_deregister_local_service(wfd_oem_ops_s *ops, int service_type);
int wfd_oem_start_service_discovery(wfd_oem_ops_s *ops, unsigned char *peer_addr, int service_type);
int wfd_oem_cancel_service_discovery(wfd_oem_ops_s *ops, unsigned char *peer_addr, int service_type);

int wfd_oem_serv_add(wfd_oem_ops_s *ops, wfd_oem_new_service_s *service);
int wfd_oem_serv_del(wfd_oem_ops_s *ops, wfd_oem_new_service_s *service);
int wfd_oem_serv_disc_start(wfd_oem_ops_s *ops, wfd_oem_new_service_s *service);
int wfd_oem_serv_disc_stop(wfd_oem_ops_s *ops, int handle);
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
int wfd_oem_miracast_init(wfd_oem_ops_s *ops, int enable);
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

int wfd_oem_refresh(wfd_oem_ops_s *ops);

#endif /* __WIFI_DIRECT_OEM_H__ */
