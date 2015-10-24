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
 * This file declares wifi direct wpasupplicant plugin functions and structures.
 *
 * @file		wfd-plugin-wpasupplicant.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WFD_PLUGIN_WPASUPPLICANT_H__
#define __WFD_PLUGIN_WPASUPPLICANT_H__


#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define IP2STR(a) (a)[0], (a)[1], (a)[2], (a)[3]
#define IPSTR "%d.%d.%d.%d"
#define MAC2SECSTR(a) (a)[0], (a)[4], (a)[5]
#define MACSECSTR "%02x:%02x:%02x"
#define ISZEROMACADDR(a) !(a[0] | a[1] | a[2] | a[3] | a[4] | a[5])
#define IP2SECSTR(a) (a)[0], (a)[3]
#define IPSECSTR "%d..%d"
#define OBJECT_PATH_MAX 150

#if !defined TIZEN_TV
#define DEFAULT_MAC_FILE_PATH "/opt/etc/.mac.info"
#define CONF_FILE_PATH "/usr/etc/wifi-direct/p2p_supp.conf"
#else
#define DEFAULT_MAC_FILE_PATH "/sys/class/net/p2p0/address"
#define CONF_FILE_PATH "/opt/etc/p2p_supp.conf"
#endif

#if defined TIZEN_TV /*For TIZEN TV Platform*/
#define COMMON_IFACE_NAME "p2p0"
#define GROUP_IFACE_NAME "p2p0"
#define GROUP_IFACE_PREFIX "p2p"
#define PRIMARY_DEVICE_TYPE "\x00\x07\x00\x50\xf2\x04\x00\x01"
#define DEFAULT_DEVICE_NAME "[TV]Tizen"
#define DEFAULT_GO_INTENT 7
#define DEFAULT_PERSISTENT_RECONNECT 1
#define DEFAULT_LISTEN_REG_CLASS 81
#define DEFAULT_LISTEN_CHANNEL 1
#define DEFAULT_OPER_REG_CLASS 115
#define DEFAULT_OPER_CHANNEL 48
#define DEFAULT_CONFIG_METHOD "keypad virtual_push_button physical_display"
#define DEFAULT_NO_GROUP_IFACE 1
#else /*TIZEN_TV*/
#define COMMON_IFACE_NAME "wlan0"
#if defined TIZEN_WLAN_BOARD_SPRD
#define P2P_IFACE_NAME "p2p0"
#define GROUP_IFACE_NAME "p2p0"
#define GROUP_IFACE_PREFIX "p2p"
#else /* TIZEN_WLAN_BOARD_SPRD */
#define GROUP_IFACE_NAME "p2p-wlan0-0"
#define GROUP_IFACE_PREFIX "p2p-wlan0-"
#endif /* TIZEN_WLAN_BOARD_SPRD */
#define PRIMARY_DEVICE_TYPE "\x00\x0a\x00\x50\xf2\x04\x00\x05"
#define DEFAULT_DEVICE_NAME "Tizen"
#define DEFAULT_GO_INTENT 7
#define DEFAULT_PERSISTENT_RECONNECT 1
#define DEFAULT_LISTEN_REG_CLASS 81
#define DEFAULT_LISTEN_CHANNEL 1
#define DEFAULT_OPER_REG_CLASS 81
#define DEFAULT_OPER_CHANNEL 1
#define DEFAULT_CONFIG_METHOD "display push_button keypad"
#define DEFAULT_NO_GROUP_IFACE 0
#endif /*TIZEN_TV*/

#define DEFAULT_IP_GO "\xc0\xa8\x31\x01"
#define DEFAULT_IP_MASK "\xff\xff\xff\x00"
#define DEFAULT_IP_START "\xc0\xa8\x31\x33"
#define DEFAULT_IP_END "\xc0\xa8\x31\x64"

#define WS_POLL_TIMEOUT 5000
#define WS_CONN_RETRY_COUNT 10
#define WS_PINSTR_LEN 8
#define WS_SSID_LEN 32
#define WS_MACSTR_LEN 18
#define WS_MACADDR_LEN 6
#define WS_MAX_PERSISTENT_COUNT 20

#define WS_DEVTYPE_LEN 8

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
#define SERV_DISC_REQ_ALL "02000001"
#define SERV_DISC_REQ_BONJOUR "02000101"
#define SERV_DISC_REQ_UPNP "02000201"

#define SERVICE_TYPE_LEN 8
#define WS_MAX_SERVICE_LEN 1024
#define SERVICE_QUERY_LEN 4

#define SERVICE_TYPE_ALL "0000f00c"
#define SERV_BROADCAST_ADDRESS "00:00:00:00:00:00"

#define WS_QTYPE_PTR 0x0c
#define WS_QTYPE_TXT 0x10
#define WS_TCP_PTR_HEX "\xc0\x0c"
#define WS_UDP_PTR_HEX "\xc0\x1e"
#define WS_PTR_TYPE_HEX "\x00\x0c\x01"
#define WS_TXT_TYPE_HEX "\x00\x10\x01"
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

/* Config Method bitmap */
#define WS_CONFIG_METHOD_DISPLAY 0x0008
#define WS_CONFIG_METHOD_PUSHBUTTON 0x0080
#define WS_CONFIG_METHOD_KEYPAD 0x0100

#define WS_DBUS_STR_PBC "pbc"
#define WS_DBUS_STR_DISPLAY "display"
#define WS_DBUS_STR_KEYPAD "keypad"
#define WS_DBUS_STR_JOIN "join"
#define WS_DBUS_STR_AUTH "auth"
#define WS_DBUS_STR_PERSISTENT "persistent"

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
#define WS_WFD_INFO_PRIMARY_SINK 0x01
#define WS_WFD_INFO_SECONDARY_SINK 0x02
#define WS_WFD_INFO_AVAILABLITY 0x10
#define WS_WFD_INFO_WSD_SUPPORT 0x40
#define WS_WFD_INFO_TDLS_SUPPORT 0x80
#define WS_WFD_INFO_HDCP_SUPPORT 0x100
#define WS_WFD_INFO_SYNC_SUPPORT 0x200
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

typedef enum {
	WS_IFTYPE_NONE,
	WS_IFTYPE_STATION,
	WS_IFTYPE_GROUP,
} ws_iftype_e;

typedef enum {
	WS_PRI_DEV_TYPE_NONE,
	WS_PRI_DEV_TYPE_COMPUTER = 1,
	WS_PRI_DEV_TYPE_INPUT_DEVICE = 2,
	WS_PRI_DEV_TYPE_PRINTER = 3,
	WS_PRI_DEV_TYPE_CAMERA = 4,
	WS_PRI_DEV_TYPE_STORAGE = 5,
	WS_PRI_DEV_TYPE_NETWORK_INFRA = 6,
	WS_PRI_DEV_TYPE_DISPLAY = 7,
	WS_PRI_DEV_TYPE_MULTIMEDIA_DEVICE = 8,
	WS_PRI_DEV_TYPE_GAME_DEVICE = 9,
	WS_PRI_DEV_TYPE_TELEPHONE = 10,
	WS_PRI_DEV_TYPE_AUDIO = 11,
	WS_PRI_DEV_TYPE_OTHER = 255,
} ws_device_type_e;

typedef enum {
	/* The Service Discovery field shall be set to 1
	 * if the P2P Device supports Service Discovery,
	 * and is set to 0 otherwise. */
	WS_DEVICE_CAP_SERVICE_DISCOVERY = 0x01,

	/* Within a P2P Group Info attribute and a (Re)association
	 * request frame the P2P Client Discoverability field shall be set to 1
	 * when the P2P Device supports P2P Client Discoverability,
	 * and is set to 0 otherwise.
	 * This field shall be reserved and set to 0 in all other frames or uses. */
	WS_DEVICE_CAP_CLIENT_DISCOVERABILITY = 0x02,

	/* The Concurrent Operation field shall be set to 1
	 * when the P2P Device supports Concurrent Operation with WLAN,
	 * and is set to 0 otherwise. */
	WS_DEVICE_CAP_CONCURRENT_OPERATION = 0x04,

	/* The P2P Infrastructure Managed field shall be set to 1
	 * when the P2P interface of the P2P Device is capable of being
	 * managed by the WLAN (infrastructure network) based on
	 * P2P Coexistence Parameters, and set to 0 otherwise. */
	WS_DEVICE_CAP_INFRASTRUCTURE_MANAGED = 0x08,

	/* The P2P Device Limit field shall be set to 1
	 * when the P2P Device is unable to participate in additional P2P Groups,
	 * and set to 0 otherwise. */
	WS_DEVICE_CAP_DEVICE_LIMIT = 0x10,

	/* The P2P Invitation Procedure field shall be set to 1
	 * if the P2P Device is capable of processing P2P Invitation Procedure
	 * signaling, and set to 0 otherwise. */
	WS_DEVICE_CAP_INVITATION_PROCEDURE = 0x20,
} ws_device_cap_flag_e;

typedef enum {
	/* The P2P Group Owner field shall be set to 1
	 * when the P2P Device is operating as a Group Owner,
	 * and set to 0 otherwise. */
	WS_GROUP_CAP_GROUP_OWNER = 0x01,

	/* The Persistent P2P Group field shall be set to 1
	 * when the P2P Device is hosting, or intends to host,
	 * a persistent P2P Group, and set to 0 otherwise. */
	WS_GROUP_CAP_PERSISTENT_GROUP = 0x02,

	/* The P2P Group Limit field shall be set to 1
	 * when the P2P Group Owner is unable to add additional Clients
	 * to its P2P Group, and set to 0 otherwise. */
	WS_GROUP_CAP_GROUP_LIMIT = 0x04,

	/* The Intra-BSS Distribution field shall be set to 1
	 * if the P2P Device is hosting, or intends to host,
	 * a P2P Group that provides a data distribution service
	 * between Clients in the P2P Group.
	 * The Intra-BSS Distribution field shall be set to 0,
	 * if the P2P Device is not a P2P Group Owner,
	 * or is not providing such a data distribution service. */
	WS_GROUP_CAP_INTRA_BSS_DISTRIB = 0x08,

	/* The Cross Connection field shall be set to 1
	 * if the P2P Device is hosting, or intends to host,
	 * a P2P Group that provides cross connection
	 * between the P2P Group and a WLAN.
	 * The Cross Connection field shall be set to 0
	 * if the P2P Device is not a P2P Group Owner,
	 * or is not providing a cross connection service. */
	WS_GROUP_CAP_CROSS_CONNECTION = 0x10,

	/* The Persistent Reconnect field shall be set to 1
	 * when the P2P Device is hosting, or intends to host,
	 * a persistent P2P Group that allows reconnection
	 * without user intervention, and set to 0 otherwise. */
	WS_GROUP_CAP_PERSISTENT_RECONN = 0x20,

	/* The Group Formation field shall be set to 1
	 * when the P2P Device is operating as a Group Owner
	 * in the Provisioning phase of Group Formation,
	 * and set to 0 otherwise. */
	WS_GROUP_CAP_GROUP_FORMATION = 0x40,
} ws_group_cap_flag_e;

typedef enum {
	/* If the Device Password ID is Default, the Enrollee should use
	 * its PIN password (from the label or display). This password may
	 * correspond to the label, display, or a user-defined password
	 * that has been configured to replace the original device password. */
	WS_DEV_PASSWD_ID_DEFAULT = 0x0000,

	/* User-specified indicates that the user has overridden the password
	 * with a manually selected value. */
	WS_DEV_PASSWD_ID_USER_SPECIFIED = 0x0001,

	/* Machine-specified indicates that the original PIN password has been
	 * overridden by a strong, machine-generated device password value. */
	WS_DEV_PASSWD_ID_MACHINE_SPECIFIED = 0x0002,

	/* The Rekey value indicates that the device's 256-bit rekeying
	 * password will be used. */
	WS_DEV_PASSWD_ID_REKEY = 0x0003,

	/* The PushButton value indicates that the PIN is the all-zero value
	 * reserved for the Push Button Configuration method. */
	WS_DEV_PASSWD_ID_PUSH_BUTTON = 0x0004,

	/* The Registrar-specified value indicates a PIN that has been
	 * obtained from the Registrar (via a display or other out-of-band
	 * method). This value may be further augmented with the optional
	 * "Identity" attribute in M1. */
	WS_DEV_PASSWD_ID_REGISTRAR_SPECIFIED = 0x0005,	// ENTER-PIN
} ws_dev_passwd_id_e;

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
} ws_wps_error_e;

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
typedef enum {
	WFD_SUBELM_ID_DEV_INFO,
	WFD_SUBELM_ID_ASSOC_BSSID,
	WFD_SUBELM_ID_AUDIO_FORMAT,
	WFD_SUBELM_ID_VIDEO_FORMAT,
	WFD_SUBELM_ID_3D_FORMAT,
	WFD_SUBELM_ID_CONTENT_PROTECTION,

	WFD_SUBELM_ID_CUPLED_SYNC_INFO,
	WFD_SUBELM_ID_EXT_CAPAB,
	WFD_SUBELM_ID_LOCAL_IP,
	WFD_SUBELM_ID_SESSION_INFO,
	WFD_SUBELM_ID_ALT_MAC,
} ws_wfd_subelm_id_e;
#define WFD_SUBELEM_LEN_DEV_INFO 6
#define WFD_SUBELM_LEN_ASSOC_BSSID 6
#define WFD_SUBELM_LEN_CUPLED_SYNC_INFO 7
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

typedef enum {
	WFD_OEM_NETFLAG_CURRENT,
	WFD_OEM_NETFLAG_DISABLED,
	WFD_OEM_NETFLAG_TEMP_DISABLED,
	WFD_OEM_NETFLAG_P2P_PERSISTENT,
} ws_netowrk_flag_e;

typedef struct {
	int network_id;
	char ssid[OEM_DEV_NAME_LEN+1];
	unsigned char bssid[OEM_MACADDR_LEN];
	char persistent_path[OBJECT_PATH_MAX];
	int total;
} ws_network_info_s;

typedef struct {
	int initialized;	// check whether plugin is initialized or not. block init function if initialized
	int activated;
	int concurrent;

	GDBusConnection *g_dbus;
	guint supp_sub_id;
	char iface_path[150];
	char group_iface_path[150];
	guint p2pdevice_sub_id;
	guint group_sub_id;
	guint group_iface_sub_id;
	unsigned char local_dev_addr[WS_MACADDR_LEN];
	wfd_oem_event_cb callback;
	void *user_data;
} ws_dbus_plugin_data_s;

int ws_init(wfd_oem_event_cb callback, void *user_data);
int ws_deinit();
int ws_activate(int concurrent);
int ws_deactivate(int concurrent);
int ws_start_scan(wfd_oem_scan_param_s *param);
int ws_restart_scan(int freq);
int ws_stop_scan();
int ws_get_visibility(int *visibility);
int ws_set_visibility(int visibility);
int ws_get_scan_result(GList **peers, int *peer_count);
int ws_get_peer_info(unsigned char *peer_addr, wfd_oem_device_s **peer);
int ws_prov_disc_req(unsigned char *peer_addr, wfd_oem_wps_mode_e wps_mode, int join);
int ws_connect(unsigned char *peer_addr, wfd_oem_conn_param_s *param);
int ws_disconnect(unsigned char *peer_addr);
int ws_reject_connection(unsigned char *peer_addr);
int ws_cancel_connection(unsigned char *peer_addr);
int ws_get_connected_peers(GList **peers, int *peer_count);
int ws_get_pin(char *pin);
int ws_set_pin(char *pin);
int ws_generate_pin(char **pin);
int ws_get_supported_wps_mode();
int ws_create_group(int persistent, int freq, const char *passphrase);
int ws_destroy_group(const char *ifname);
int ws_invite(unsigned char *peer_addr, wfd_oem_invite_param_s *param);
int ws_wps_start(unsigned char *peer_addr, int wps_mode, const char *pin);
int ws_enrollee_start(unsigned char *peer_addr, int wps_mode, const char *pin);
int ws_wps_cancel();
int ws_get_dev_name(char *dev_name);
int ws_set_dev_name(char *dev_name);
int ws_get_dev_mac(char *dev_mac);
int ws_get_dev_type(int *pri_dev_type, int *sec_dev_type);
int ws_set_dev_type(int pri_dev_type, int sec_dev_type);
int ws_get_go_intent(int *go_intent);
int ws_set_go_intent(int go_intent);
int ws_set_country(char *ccode);

int ws_get_persistent_groups(wfd_oem_persistent_group_s **groups, int *group_count);
int ws_remove_persistent_group(char *ssid, unsigned char *bssid);
int ws_set_persistent_reconnect(unsigned char *bssid, int reconnect);

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
int ws_start_service_discovery(unsigned char *mac_addr, int service_type);
int ws_cancel_service_discovery(unsigned char *mac_addr, int service_type);

int ws_serv_add(wfd_oem_new_service_s *service);
int ws_serv_del(wfd_oem_new_service_s *service);
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
int ws_miracast_init(int enable);
int ws_set_display(wfd_oem_display_s *wifi_display);
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

int ws_refresh();

#endif /* __WFD_PLUGIN_WPASUPPLICANT_H__ */
