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

#ifndef __WFD_WPA_SUPPLICANT_H_
#define __WFD_WPA_SUPPLICANT_H_

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <net/ethernet.h>

#ifdef USE_DLOG
#include <dlog.h>

#undef LOG_TAG
#define LOG_TAG "WIFI_DIRECT_PLUGIN"

#define WDP_LOGV(format, args...) LOGV(format, ##args)
#define WDP_LOGD(format, args...) LOGD(format, ##args)
#define WDP_LOGI(format, args...) LOGI(format, ##args)
#define WDP_LOGW(format, args...) LOGW(format, ##args)
#define WDP_LOGE(format, args...) LOGE(format, ##args)
#define WDP_LOGF(format, args...) LOGF(format, ##args)

#define __WDP_LOG_FUNC_ENTER__ LOGV("Enter")
#define __WDP_LOG_FUNC_EXIT__ LOGV("Quit")

#else /** _DLOG_UTIL */

#define WDP_LOGV(format, args...)
#define WDP_LOGD(format, args...)
#define WDP_LOGI(format, args...)
#define WDP_LOGW(format, args...)
#define WDP_LOGE(format, args...)
#define WDP_LOGF(format, args...)

#define __WDP_LOG_FUNC_ENTER__
#define __WDP_LOG_FUNC_EXIT__

#endif /** _DLOG_UTIL */

#define DEFAULT_IF_NAME "p2p-wlan0-0"
#define DEFAULT_IF_NAME_LEN 12
#define DEFAULT_IP_LOG_PATH "/tmp/udhcpc_log"
#define PERSISTENT_PEER_PATH "/opt/etc/persistent-peer"
#define DEFAULT_SERVER_IP "192.168.16.1"
#define FREQUENCY_2G "freq=2"
#define MAX_PEER_NUM 10
#define MAX_PERSISTENT_GROUP_NUM 20
#define MACSTR_LEN 18
#define WPS_METHOD_LEN 16
#define DEVICE_NAME_LEN 64
#define DEVICE_TYPE_LEN 18
#define MANUFACTURER_LEN 64
#define MODEL_NAME_LEN 64
#define MODEL_NUMBER_LEN 64
#define SERIAL_NUMBER_LEN 64
#define GO_STATE_LEN 16
#define PEER_FLAGS_LEN 128
#define PEER_STATUS_LEN 16
#define COUNTRY_CODE_LEN 8

#define NETWORK_SSID_LEN 64
#define NETWORK_BSSID_LEN 18
#define NETWORK_FLAGS_LEN 32

#define WPS_PIN_LEN 9

#define BIT(n) 1<<(n-1)

/* Device Capability bitmap */
#define DEVICE_CAPAB_SERVICE_DISCOVERY         BIT(1)
#define DEVICE_CAPAB_CLIENT_DISCOVERABILITY    BIT(2)
#define DEVICE_CAPAB_CONCURRENT_OPER           BIT(3)
#define DEVICE_CAPAB_INFRA_MANAGED             BIT(4)
#define DEVICE_CAPAB_DEVICE_LIMIT              BIT(5)
#define DEVICE_CAPAB_INVITATION_PROCEDURE      BIT(6)

/* Group Capability bitmap */
#define GROUP_CAPAB_GROUP_OWNER                BIT(1)
#define GROUP_CAPAB_PERSISTENT_GROUP           BIT(2)
#define GROUP_CAPAB_GROUP_LIMIT                BIT(3)
#define GROUP_CAPAB_INTRA_BSS_DIST             BIT(4)
#define GROUP_CAPAB_CROSS_CONN                 BIT(5)
#define GROUP_CAPAB_PERSISTENT_RECONN          BIT(6)
#define GROUP_CAPAB_GROUP_FORMATION            BIT(7)

/* WPS config methods supported */
#define WPS_CONFIG_DISPLAY         BIT(4)   //0x0008;
#define WPS_CONFIG_PUSHBUTTON      BIT(8)   //0x0080;
#define WPS_CONFIG_KEYPAD          BIT(9)   //0x0100;

#define WIFI_ALLIANCE_OUI "0050F204"  // wifi direct spec Annex B.2

typedef void (*wfd_noti_cb) (int event_type);

#define CMD_INTERFACE "INTERFACES"
#define CMD_INTERFACE_ADD "INTERFACE_ADD"
#define CMD_INTERFACE_REMOVE "INTERFACE_REMOVE"
#define CMD_ATTACH "ATTACH"
#define CMD_DETACH "DETACH"
#define CMD_START_DISCOVER "P2P_FIND"
#define CMD_START_LISTEN "P2P_LISTEN"
#define CMD_CANCEL_DISCOVER "P2P_STOP_FIND"
#define CMD_FLUSH "P2P_FLUSH"
#define CMD_GET_FIRST_DISCOVERED_PEER "P2P_PEER FIRST"
#define CMD_GET_NEXT_DISCOVERED_PEER "P2P_PEER NEXT-"
#define CMD_SEND_PROVISION_DISCOVERY_REQ "P2P_PROV_DISC"
#define CMD_SEND_INVITE_REQ "P2P_INVITE"
#define CMD_CREATE_GROUP "P2P_GROUP_ADD"
#define CMD_CONNECT "P2P_CONNECT"
#define CMD_REJECT "P2P_REJECT"
#define CMD_PBC_STRING "pbc"
#define CMD_DISPLAY_STRING "display"
#define CMD_KEYPAD_STRING "keypad"
#define CMD_WPS_PUSHBUTTON_START "WPS_PBC"
#define CMD_WPS_WPS_PIN_START "WPS_PIN"
#define CMD_GET_PEER_INFO "P2P_PEER"
#define CMD_SET_PARAM "SET"
#define CMD_GET_PARAM "GET"
#define CMD_STATUS "STATUS"
#define CMD_STATUS_P2P "STATUS P2P"
#define CMD_LOG_LEVEL "LOG_LEVEL"
#define CMD_GROUP_REMOVE "P2P_GROUP_REMOVE"
#define CMD_QUIT "QUIT"
#define CMD_TERMINATE "TERMINATE"
#define CMD_GET_LIST_NETWORKS "LIST_NETWORKS"
#define CMD_REMOVE_NETWORK "REMOVE_NETWORK"
#define CMD_CANCEL "P2P_CANCEL"


/*----- Miracast -----*/
#define CMD_WFD_SET "WFD_SET"


typedef enum
{
	WS_PEER_INFO_AGE,
	WS_PEER_INFO_LISTEN_FREQ,
	WS_PEER_INFO_LEVEL,
	WS_PEER_INFO_WPS_METHOD,
	WS_PEER_INFO_INTERFACE_ADDR,
	WS_PEER_INFO_MEMBER_IN_GO_DEV,
	WS_PEER_INFO_MEMBER_IN_GO_IFACE,
	WS_PEER_INFO_PRI_DEV_TYPE,
	WS_PEER_INFO_DEVICE_NAME,
	WS_PEER_INFO_MANUFACTURER,
	WS_PEER_INFO_MODEL_NAME,
	WS_PEER_INFO_MODEL_NUMBER,
	WS_PEER_INFO_SERIAL_NUMBER,
	WS_PEER_INFO_CONFIG_METHODS,
	WS_PEER_INFO_DEV_CAPAB,
	WS_PEER_INFO_GROUP_CAPAB,
	WS_PEER_INFO_GO_NEG_REQ_SENT,
	WS_PEER_INFO_GO_STATE,
	WS_PEER_INFO_DIALOG_TOKEN,
	WS_PEER_INFO_INTENDED_ADDR,
	WS_PEER_INFO_COUNTRY,
	WS_PEER_INFO_OPER_FREQ,
	WS_PEER_INFO_REQ_CONFIG_METHODS,
	WS_PEER_INFO_FLAGS,
	WS_PEER_INFO_STATUS,
	WS_PEER_INFO_WAIT_COUNT,
	WS_PEER_INFO_INVITATION_REQS,
	WS_PEER_INFO_OPER_SSID,

/*----- Miracast -----*/
	WS_PEER_INFO_IS_WFD_DEVICE,
	
	WS_PEER_INFO_NONE
} ws_field_id_e;

typedef struct
{
	char* item_str;
	ws_field_id_e item_id;
} ws_field_id_s;

ws_field_id_s g_ws_field_info[] =
{
	{"age", WS_PEER_INFO_AGE},
	{"listen_freq", WS_PEER_INFO_LISTEN_FREQ},
	{"level", WS_PEER_INFO_LEVEL},
	{"wps_method", WS_PEER_INFO_WPS_METHOD},
	{"interface_addr", WS_PEER_INFO_INTERFACE_ADDR},
	{"member_in_go_dev", WS_PEER_INFO_MEMBER_IN_GO_DEV},
	{"member_in_go_iface", WS_PEER_INFO_MEMBER_IN_GO_IFACE},
	{"pri_dev_type", WS_PEER_INFO_PRI_DEV_TYPE},
	{"device_name", WS_PEER_INFO_DEVICE_NAME},
	{"manufacturer", WS_PEER_INFO_MANUFACTURER},
	{"model_name", WS_PEER_INFO_MODEL_NAME},
	{"model_number", WS_PEER_INFO_MODEL_NUMBER},
	{"serial_number", WS_PEER_INFO_SERIAL_NUMBER},
	{"config_methods", WS_PEER_INFO_CONFIG_METHODS},
	{"dev_capab", WS_PEER_INFO_DEV_CAPAB},
	{"group_capab", WS_PEER_INFO_GROUP_CAPAB},
	{"go_neg_req_sent", WS_PEER_INFO_GO_NEG_REQ_SENT},
	{"go_state", WS_PEER_INFO_GO_STATE},
	{"dialog_token", WS_PEER_INFO_DIALOG_TOKEN},
	{"intended_addr", WS_PEER_INFO_INTENDED_ADDR},
	{"country", WS_PEER_INFO_COUNTRY},
	{"oper_freq", WS_PEER_INFO_OPER_FREQ},
	{"req_config_methods", WS_PEER_INFO_REQ_CONFIG_METHODS},
	{"flags", WS_PEER_INFO_FLAGS},
	{"status", WS_PEER_INFO_STATUS},
	{"wait_count", WS_PEER_INFO_WAIT_COUNT},
	{"invitation_reqs", WS_PEER_INFO_INVITATION_REQS},
	{"oper_ssid", WS_PEER_INFO_OPER_SSID},
	
/*----- Miracast -----*/
	{"is_wfd_device", WS_PEER_INFO_IS_WFD_DEVICE},
	
	{"", WS_PEER_INFO_NONE}
};

typedef struct
{
	char mac[MACSTR_LEN];
	int age;
	int listen_freq;
	int level;
	char wps_method[WPS_METHOD_LEN];
	char interface_addr[MACSTR_LEN];
	char member_in_go_dev[MACSTR_LEN];
	char member_in_go_iface[MACSTR_LEN];
	char pri_dev_type[DEVICE_TYPE_LEN];
	char device_name[DEVICE_NAME_LEN];
	char manufacturer[MANUFACTURER_LEN];
	char model_name[MODEL_NAME_LEN];
	char model_number[MODEL_NUMBER_LEN];
	char serial_number[SERIAL_NUMBER_LEN];
	unsigned int config_methods;
	unsigned int dev_capab;
	unsigned int group_capab;
	unsigned int go_neg_req_sent;
	char go_state[GO_STATE_LEN];
	int dialog_token;
	char intended_addr[MACSTR_LEN];
	char country[COUNTRY_CODE_LEN];
	unsigned int oper_freq;
	unsigned int req_config_methods;
	char flags[PEER_FLAGS_LEN];
	char status[PEER_STATUS_LEN];
	int wait_count;
	int invitation_reqs;
	char oper_ssid[DEVICE_NAME_LEN];

/*----- Miracast -----*/
	int is_wfd_device;
 } ws_discovered_peer_info_s;

typedef struct
{
	int network_id;
	char ssid[NETWORK_SSID_LEN];
	char bssid[NETWORK_BSSID_LEN];
	char flags[NETWORK_FLAGS_LEN];
 } ws_network_info_s;


/** Event notification code */
typedef enum {
	WS_EVENT_NONE = 0,

	WS_EVENT_DISCOVER_FOUND_PEER,

	WS_EVENT_PROVISION_DISCOVERY_RESPONSE,
	WS_EVENT_PROVISION_DISCOVERY_RESPONSE_DISPLAY,
	WS_EVENT_PROVISION_DISCOVERY_RESPONSE_KEYPAD,
	WS_EVENT_PROVISION_DISCOVERY_PBC_REQ,
	WS_EVENT_PROVISION_DISCOVERY_DISPLAY,
	WS_EVENT_PROVISION_DISCOVERY_KEYPAD,

	WS_EVENT_GROUP_FORMATION_SUCCESS,
	WS_EVENT_GROUP_FORMATION_FAILURE,

	WS_EVENT_GROUP_STARTED,
	WS_EVENT_PERSISTENT_GROUP_STARTED,
	WS_EVENT_GROUP_REMOVED,

	WS_EVENT_CONNECTED,
	WS_EVENT_STA_CONNECTED,

	WS_EVENT_DISCONNECTED,
	WS_EVENT_STA_DISCONNECTED,

	WS_EVENT_INVITATION_REQ,
	WS_EVENT_INVITATION_RSP,

	WS_EVENT_TERMINATING,
	WS_EVENT_GO_NEG_REQUEST,
	WS_EVENT_GO_NEG_FAILURE,

	WS_EVENT_WPS_FAIL,

} ws_event_id_e;

typedef enum {
	WPS_ERROR_NONE,

	WPS_ERROR_OOBINFO_READ_FAIL,
	WPS_ERROR_DECRYPTION_FAIL,
	WPS_ERROR_2G_NOT_SUPPORTED,
	WPS_ERROR_5G_NOT_SUPPORTED,
	WPS_ERROR_WEAK_SIGNAL,
	WPS_ERROR_NET_AUTH_FAIL,
	WPS_ERROR_NET_ASSOC_FAIL,
	WPS_ERROR_NO_DHCP_RESPONSE,
	WPS_ERROR_DHCP_CONFIG_FAIL,
	WPS_ERROR_IP_CONFLICT,

	WPS_ERROR_REGISTRAT_CONN_FAIL,
	WPS_ERROR_PBC_SESSION_OVERLAP,
	WPS_ERROR_ROGUE_ACTIVITY,
	WPS_ERROR_DEVICE_BUSY,
	WPS_ERROR_SETUP_LOCKED,
	WPS_ERROR_MESSAGE_TIMEOUT,
	WPS_ERROR_SESSION_TIMEOUT,
	WPS_ERROR_PASSWORD_MISMATCH,
} ws_wps_msg_e;

typedef struct
{
	char* str;
	ws_event_id_e id;
} ws_event_id_s;

ws_event_id_s g_ws_event_info[] =
{
	// discovery
	{"P2P-DEVICE-FOUND", WS_EVENT_DISCOVER_FOUND_PEER},

	// provision discovery
	{"P2P-PROV-DISC-PBC-RESP", WS_EVENT_PROVISION_DISCOVERY_RESPONSE},
	{"P2P-PROV-DISC-PBC-REQ", WS_EVENT_PROVISION_DISCOVERY_PBC_REQ},
	{"P2P-PROV-DISC-SHOW-PIN", WS_EVENT_PROVISION_DISCOVERY_DISPLAY},
	{"P2P-PROV-DISC-ENTER-PIN", WS_EVENT_PROVISION_DISCOVERY_KEYPAD},

	{"P2P-GROUP-FORMATION-SUCCESS", WS_EVENT_GROUP_FORMATION_SUCCESS},
	{"P2P-GROUP-FORMATION-FAILURE", WS_EVENT_GROUP_FORMATION_FAILURE},

	// connection
	{"P2P-GROUP-STARTED", WS_EVENT_GROUP_STARTED},
	{"P2P-GROUP-REMOVED", WS_EVENT_GROUP_REMOVED},

	{"CTRL-EVENT-CONNECTED", WS_EVENT_CONNECTED},
	{"AP-STA-CONNECTED", WS_EVENT_STA_CONNECTED},
	{"CTRL-EVENT-DISCONNECTED", WS_EVENT_DISCONNECTED},
	{"AP-STA-DISCONNECTED", WS_EVENT_STA_DISCONNECTED},

	// invite
	{"P2P-INVITATION-RECEIVED", WS_EVENT_INVITATION_REQ},
	{"P2P-INVITATION-RESULT", WS_EVENT_INVITATION_RSP},
	

	{"CTRL-EVENT-TERMINATING", WS_EVENT_TERMINATING},
	{"P2P-GO-NEG-REQUEST", WS_EVENT_GO_NEG_REQUEST},

	{"P2P-GO-NEG-FAILURE", WS_EVENT_GO_NEG_FAILURE},
	{"WPS-FAIL", WS_EVENT_WPS_FAIL},

	{"", WS_EVENT_NONE}
};

typedef struct
{
	ws_event_id_e id;
	char peer_mac_address[MACSTR_LEN];
	char peer_intf_mac_address[MACSTR_LEN];
	char peer_ssid[DEVICE_NAME_LEN];
	char wps_pin[WPS_PIN_LEN];
	int msg;
} ws_event_s;

typedef struct
{
	char* freq;
	int channel;
} ws_op_channel_s;

ws_op_channel_s g_ws_op_channel_info[] =
{
	/* 2 GHz */
	{"2412", 1},	{"2417", 2},	{"2422", 3},	{"2427", 4},	{"2432", 5},
	{"2437", 6},	{"2442", 7},	{"2447", 8},	{"2452", 9},	{"2457", 10},
	{"2462", 11},	{"2467", 12},	{"2472", 13},	{"2484", 14},

	/* 5 GHz */
	{"5180", 36},	{"5190", 38},	{"5200", 40},	{"5210", 42},	{"5220", 44},
	{"5230", 46},	{"5240", 48},	{"5260", 52},	{"5280", 56},	{"5300", 60},
	{"5320", 64},	{"5500", 100},	{"5520", 104},	{"5540", 108},	{"5560", 112},
	{"5580", 116},	{"5600", 120},	{"5620", 124},	{"5640", 128},	{"5660", 132},
	{"5680", 136},	{"5700", 140},	{"5745", 149},	{"5765", 153},	{"5785", 157},
	{"5805", 161},	{"5825", 165},

	{"", 0}
};


int wfd_ws_init(wfd_oem_event_cb event_callback);
int wfd_ws_destroy();
int wfd_ws_activate();
int wfd_ws_deactivate();
int wfd_ws_connect(unsigned char mac_addr[6], wifi_direct_wps_type_e wps_config);
int wfd_ws_disconnect();
int wfd_ws_disconnect_sta(unsigned char mac_addr[6]);
int wfd_ws_reject_connection(unsigned char mac_addr[6]);
int wfd_ws_wps_pbc_start(unsigned char mac_addr[6]);
int wfd_ws_wps_pin_start(unsigned char mac_addr[6]);
bool wfd_ws_is_discovery_enabled();
int wfd_ws_start_discovery(bool listen_only, int timeout);
int wfd_ws_restart_discovery();
int wfd_ws_cancel_discovery();
int wfd_ws_get_discovery_result(wfd_discovery_entry_s ** peer_list, int* peer_num);
int wfd_ws_get_peer_info(unsigned char *mac_addr, wfd_discovery_entry_s **peer);
int wfd_ws_send_provision_discovery_request(unsigned char mac_addr[6], wifi_direct_wps_type_e config_method, int is_peer_go);
int wfd_ws_send_invite_request(unsigned char dev_mac_addr[6]);
int wfd_ws_create_group(char* ssid);
int wfd_ws_cancel_group();
int wfd_ws_activate_pushbutton();
bool wfd_ws_is_groupowner();
bool wfd_ws_is_groupclient();
int wfd_ws_get_ssid(char* ssid, int len);
char* wfd_ws_get_default_interface_name();
bool wfd_ws_dhcpc_get_ip_address(char *ipaddr_buf, int len, int is_IPv6);
char* wfd_ws_get_ip();
int wfd_ws_set_wps_pin(char* pin);
int wfd_ws_get_wps_pin(char* wps_pin, int len);
int wfd_ws_generate_wps_pin();
int wfd_ws_set_ssid(char* ssid);
int wfd_ws_set_wpa_passphrase(char* wpa_key);
int wfd_ws_get_supported_wps_mode();
int wfd_ws_get_connected_peers_count(int* peer_num);
int wfd_ws_get_connected_peers_info(wfd_connected_peer_info_s ** peer_list, int* peer_num);
int wfd_ws_get_go_intent();
int wfd_ws_set_go_intent(int go_intent);
int wfd_ws_set_device_type(wifi_direct_primary_device_type_e primary_cat, wifi_direct_secondary_device_type_e sub_cat);
int wfd_ws_get_device_mac_address(unsigned char* device_mac);
int wfd_ws_set_oem_loglevel(int is_increase);
int wfd_ws_get_assoc_sta_mac(unsigned char *mac_addr);
int wfd_ws_get_disassoc_sta_mac(unsigned char *mac_addr);
int wfd_ws_get_requestor_mac(unsigned char *mac_addr);
int wfd_ws_get_operating_channel(void);
bool wfd_ws_flush();
bool wfd_ws_cancel();
int wfd_ws_dsp_init(void);
int wfd_ws_get_persistent_group_info(wfd_persistent_group_info_s ** persistent_group_list, int* persistent_group_num);
int wfd_ws_remove_persistent_group(wfd_persistent_group_info_s *persistent_group);
int wfd_ws_set_persistent_reconnect(bool enabled);
int wfd_ws_connect_for_persistent_group(unsigned char mac_addr[6], wifi_direct_wps_type_e wps_config);

#endif /** __WFD_WPA_SUPPLICANT_H_ */

