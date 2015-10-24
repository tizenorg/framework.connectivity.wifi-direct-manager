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
 * This file implements wifi direct wpasupplicant dbus plugin functions.
 *
 * @file		wfd-plugin-dbus-wpasupplicant.c
 * @author	Jiung Yu (jiung.yu@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <poll.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <glib.h>
#include <gio/gio.h>

#include "wifi-direct-oem.h"
#include "wfd-plugin-log.h"
#include "wfd-plugin-wpasupplicant.h"
#include "dbus/wfd-plugin-supplicant-dbus.h"

#define NETCONFIG_SERVICE "net.netconfig"
#define NETCONFIG_WIFI_INTERFACE "net.netconfig.wifi"
#define NETCONFIG_WIFI_PATH "/net/netconfig/wifi"

#define NETCONFIG_DBUS_REPLY_TIMEOUT (10 * 1000)

static wfd_oem_ops_s supplicant_ops = {
	.init = ws_init,
	.deinit = ws_deinit,
	.activate = ws_activate,
	.deactivate = ws_deactivate,

	.start_scan = ws_start_scan,
	.stop_scan = ws_stop_scan,
	.get_visibility = ws_get_visibility,
	.set_visibility = ws_set_visibility,
	.get_scan_result = ws_get_scan_result,
	.get_peer_info = ws_get_peer_info,

	.prov_disc_req = ws_prov_disc_req,

	.connect = ws_connect,
	.disconnect = ws_disconnect,
	.reject_connection = ws_reject_connection,
	.cancel_connection = ws_cancel_connection,

	.get_connected_peers = ws_get_connected_peers,
	.get_pin = ws_get_pin,
	.set_pin = ws_set_pin,
	.generate_pin = ws_generate_pin,
	.get_supported_wps_mode = ws_get_supported_wps_mode,

	.create_group = ws_create_group,
	.destroy_group = ws_destroy_group,
	.invite = ws_invite,
	.wps_start = ws_wps_start,
	.enrollee_start = ws_enrollee_start,
	.wps_cancel = ws_wps_cancel,

	.get_dev_name = ws_get_dev_name,
	.set_dev_name = ws_set_dev_name,
	.get_dev_mac = ws_get_dev_mac,
	.get_dev_type = ws_get_dev_type,
	.set_dev_type = ws_set_dev_type,
	.get_go_intent = ws_get_go_intent,
	.set_go_intent = ws_set_go_intent,
	.set_country = ws_set_country,
	.get_persistent_groups = ws_get_persistent_groups,
	.remove_persistent_group = ws_remove_persistent_group,
	.set_persistent_reconnect = ws_set_persistent_reconnect,

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	.start_service_discovery = ws_start_service_discovery,
	.cancel_service_discovery = ws_cancel_service_discovery,

	.serv_add = ws_serv_add,
	.serv_del = ws_serv_del,
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	.miracast_init = ws_miracast_init,
	.set_display = ws_set_display,
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

	.refresh = ws_refresh,

	};

static ws_dbus_plugin_data_s *g_pd;

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
static GList *service_list;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

static void _supplicant_signal_cb(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path, const gchar *interface,
		const gchar *signal, GVariant *parameters, gpointer user_data);

static void _p2pdevice_signal_cb(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path, const gchar *interface,
		const gchar *signal, GVariant *parameters, gpointer user_data);

static void _group_signal_cb(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path, const gchar *interface,
		const gchar *signal, GVariant *parameters, gpointer user_data);

static int __ws_txt_to_mac(unsigned char *txt, unsigned char *mac)
{
	int i = 0;

	if (!txt || !mac) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	for (;;) {
		mac[i++] = (char) strtoul((char *)txt, (char **)&txt, 16);
		if (!*txt++ || i == 6)
			break;
	}

	if (i != WS_MACADDR_LEN)
		return -1;

	return 0;
}

static int __ws_mac_compact_to_normal(char *compact, unsigned char *mac)
{
	g_snprintf((char *)mac, OEM_MACSTR_LEN, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
			compact[0], compact[1], compact[2], compact[3],
			compact[4], compact[5], compact[6], compact[7],
			compact[8], compact[9], compact[10], compact[11]);
	return 0;
}

static char *__ws_wps_to_txt(int wps_mode)
{
	switch (wps_mode) {
	case WFD_OEM_WPS_MODE_PBC:
		return WS_DBUS_STR_PBC;
		break;
	case WFD_OEM_WPS_MODE_DISPLAY:
		return WS_DBUS_STR_DISPLAY;
		break;
	case WFD_OEM_WPS_MODE_KEYPAD:
		return WS_DBUS_STR_KEYPAD;
		break;
	default:
		return "";
		break;
	}
}
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
static int __ws_byte_to_hex(char *buf, int buf_size, unsigned char *data, int data_len)
{
	int i;
	char *pos = buf;
	char *end = buf + buf_size;
	int ret;
	if (buf_size == 0)
		return 0;
	for (i = 0; i < data_len; i++) {
		ret = snprintf(pos, end - pos, "%02x", data[i]);
		if (ret < 0 || ret >= end - pos) {
			end[-1] = '\0';
			return pos - buf;
		}
		pos += ret;
	}
	end[-1] = '\0';
	return pos - buf;
}

static int __ws_hex_to_num(char *src, int len)
{
	char *temp = NULL;
	int num = 0;

	if (!src || len < 0) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	temp = (char*) g_try_malloc0(len+1);
	if (!temp) {
		WDP_LOGE("Failed to allocate memory");
		return -1;
	}

	memcpy(temp, src, len);
	num = strtoul(temp, NULL, 16);
	g_free(temp);

	return num;
}

static int __ws_segment_to_service(char *segment, wfd_oem_new_service_s **service)
{
	wfd_oem_new_service_s *serv_tmp = NULL;
	char *ptr = NULL;
	char *temp = NULL;
	int len = 0;
	int i = 0;

	if (!segment || !service) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	ptr = segment;
	WDP_LOGD("Segment: %s", segment);

	serv_tmp = (wfd_oem_new_service_s*) g_try_malloc0(sizeof(wfd_oem_new_service_s));
	if (!serv_tmp) {
		WDP_LOGE("Failed to allocate memory for service");
		return -1;
	}

	serv_tmp->protocol = __ws_hex_to_num(ptr, 2);
	serv_tmp->trans_id = __ws_hex_to_num(ptr+2, 2);
	serv_tmp->status = __ws_hex_to_num(ptr+4, 2);
	ptr += 6;
	WDP_LOGD("Protocol[%d], Transaction ID[%d], Status[%d]", serv_tmp->protocol, serv_tmp->trans_id, serv_tmp->status);

	if (serv_tmp->status != 0) {
		WDP_LOGE("Service status is not success");
		free(serv_tmp);
		return -1;
	}

	if (serv_tmp->protocol == WFD_OEM_SERVICE_TYPE_BONJOUR) {
		WDP_LOGD("===== Bonjour service =====");
		char compr[5] = {0, };
		char query[256] = {0, };
		char rdata[256] = {0, };
		int dns_type = 0;

		while (*ptr != 0 && strncmp(ptr, "c0", 2)) {
			len = __ws_hex_to_num(ptr, 2);
			ptr +=2;
			if (len) {
				temp = (char*) calloc(1, len+2);
				if (temp) {
					temp[0] = '.';
					for (i=0; i<len; i++) {
						temp[i+1] = (char) __ws_hex_to_num(ptr, 2);
						ptr += 2;
					}
					strncat(query, temp, len+1);
					g_free(temp);
					temp = NULL;
				}
			}
		}

		if (!strncmp(ptr, "c0", 2)) {
			memcpy(compr, ptr, 4);
			ptr += 2;

			if (!strncmp(ptr, "27", 2)) {
				WDP_LOGD("Segment ended");
				ptr += 2;
			} else {
				ptr += 2;
				dns_type = __ws_hex_to_num(ptr, 4);
				ptr += 6;
				if (dns_type == 12) {
					if (!strncmp(compr, "c011", 4))
						strncat(query, ".local.", 7);
					else if (!strncmp(compr, "c00c", 4))
						strncat(query, "._tcp.local.", 12);
					else if (!strncmp(compr, "c01c", 4))
						strncat(query, "._udp.local.", 12);
				}
			}
		}
		serv_tmp->data.bonjour.query = strdup(query + 1);
		while (*ptr != 0 && strncmp(ptr, "c0", 2)) {
			len = __ws_hex_to_num(ptr, 2);
			ptr += 2;
			if (len) {
				temp = (char*) g_try_malloc0(len+2);
				if (temp) {
					temp[0] = '.';
					for (i=0; i<len; i++) {
						temp[i+1] = (char) __ws_hex_to_num(ptr, 2);
						ptr += 2;
					}
					strncat(rdata, temp, len+1);
					g_free(temp);
					temp = NULL;
				}
			}
		}
		serv_tmp->data.bonjour.rdata = strdup(rdata + 1);

		WDP_LOGD("Query: %s", serv_tmp->data.bonjour.query);
		WDP_LOGD("RData: %s", serv_tmp->data.bonjour.rdata);
	} else {
		WDP_LOGE("Not supported yet. Only bonjour service supproted [%d]",
					serv_tmp->protocol);
		g_free(serv_tmp);
		return -1;
	}

	*service = serv_tmp;

	return 0;
}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

static void __ws_path_to_addr(char *peer_path,
		unsigned char *dev_addr, GVariant *parameter)
{
	static unsigned char peer_dev[WS_MACSTR_LEN] = {'\0',};
	const char *path = NULL;
	char *loc = NULL;

	g_variant_get(parameter, "(o)", &path);
	g_strlcpy(peer_path, path, DBUS_OBJECT_PATH_MAX);
	WDP_LOGD("Retrive Added path [%s]", peer_path);

	loc = strrchr(peer_path,'/');
	if(loc != NULL)
		__ws_mac_compact_to_normal(loc + 1, peer_dev);

	__ws_txt_to_mac(peer_dev, dev_addr);
	WDP_LOGD("peer mac [" MACSTR "]", MAC2STR(dev_addr));

	return;
}

static int __ws_unpack_ay(unsigned char *dst, GVariant *src, int size)
{
	GVariantIter *iter = NULL;
	int length = 0;
	int res = 1;

	if (!dst || !src || size == 0) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_variant_get(src, "ay", &iter);
	if (iter == NULL) {
		WDP_LOGE("failed to get iterator");
		return -1;
	}

	while (g_variant_iter_loop (iter, "y", &dst[length])) {
		length++;
		if(length >= size)
			break;
	}
	g_variant_iter_free(iter);

	if (length < size) {
		WDP_LOGE("array is shorter than size");
		res = -1;
	}

	return res;
}

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
static int __parsing_wfd_info(unsigned char *wfd_dev_info,
		wfd_oem_display_s *display )
{
	__WDP_LOG_FUNC_ENTER__;

	int wfd_info = 0;
	if (!wfd_dev_info || !display) {
		WDP_LOGE("Invalid parameter");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	wfd_info = (wfd_dev_info[3]<<8 | wfd_dev_info[4]);

	if (wfd_info & WS_WFD_INFO_PRIMARY_SINK)
		display->type |= WS_WFD_INFO_PRIMARY_SINK;
	if (wfd_info & WS_WFD_INFO_SECONDARY_SINK)
		display->type |= WS_WFD_INFO_SECONDARY_SINK;

	display->availablity = (wfd_info & WS_WFD_INFO_AVAILABLITY) >> 4;
	display->hdcp_support = (wfd_info & WS_WFD_INFO_HDCP_SUPPORT) >> 8;

	display->port = (wfd_dev_info[5]<<8 | wfd_dev_info[6]);
	display->max_tput = (wfd_dev_info[7]<<8 | wfd_dev_info[8]);

	WDP_LOGD("type [%d],availablity [%d],hdcp_support [%d],ctrl_port [%d] "
			"max_tput[%d]", display->type, display->availablity,
			display->hdcp_support, display->port,display->max_tput);

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

static void _supplicant_signal_cb(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path, const gchar *interface,
		const gchar *signal, GVariant *parameters, gpointer user_data)
{
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	DEBUG_SIGNAL(sender, object_path, interface, signal, parameters);
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	if (!g_strcmp0(signal,"InterfaceAdded")) {
		WDP_LOGD("InterfaceAdded");

	} else if (!g_strcmp0(signal,"InterfaceRemoved")) {
		WDP_LOGD("InterfaceRemoved");
		static char interface_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
		const char *path = NULL;

		g_variant_get(parameters, "(o)", &path);
		g_strlcpy(interface_path, path, DBUS_OBJECT_PATH_MAX);

		WDP_LOGD("Retrive removed path [%s]", interface_path);

		if (!g_strcmp0(g_pd->group_iface_path, interface_path)) {

			WDP_LOGD("p2p group interface removed");
			memset(g_pd->group_iface_path, 0x0, DBUS_OBJECT_PATH_MAX);
		}
#if defined(TIZEN_WLAN_CONCURRENT_ENABLE) && defined(TIZEN_MOBILE)
		else if (!g_strcmp0(g_pd->iface_path, interface_path)) {

			WDP_LOGD("p2p interface removed");
			wfd_oem_event_s event;

			ws_deactivate(1);

			memset(&event, 0x0, sizeof(wfd_oem_event_s));
			event.event_id = WFD_OEM_EVENT_DEACTIVATED;
			g_pd->callback(g_pd->user_data, &event);

			memset(g_pd->iface_path, 0x0, DBUS_OBJECT_PATH_MAX);
		}
#endif /* TIZEN_WLAN_CONCURRENT_ENABLE && TIZEN_MOBILE */
	} else if(!g_strcmp0(signal,"PropertiesChanged")){
		WDP_LOGD("PropertiesChanged");
	}
}

static void __ws_get_peer_property(const char *key, GVariant *value, void *user_data)
{
	wfd_oem_device_s *peer = (wfd_oem_device_s *)user_data;
	if(!peer) {
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	if (g_strcmp0(key, "DeviceName") == 0) {
		const char *name = NULL;

		g_variant_get(value, "s", &name);
		g_strlcpy(peer->dev_name, name, WS_SSID_LEN);
		WDP_LOGD("Device name [%s]", peer->dev_name);

	} else if (g_strcmp0(key, "config_method") == 0) {
		int config_methods = 0;
		g_variant_get(value, "q", &config_methods);

		if (config_methods & WS_CONFIG_METHOD_DISPLAY)
			peer->config_methods |= WFD_OEM_WPS_MODE_DISPLAY;
		if (config_methods & WS_CONFIG_METHOD_PUSHBUTTON)
			peer->config_methods |= WFD_OEM_WPS_MODE_PBC;
		if (config_methods & WS_CONFIG_METHOD_KEYPAD)
			peer->config_methods |= WFD_OEM_WPS_MODE_KEYPAD;
		WDP_LOGD("Config method [0x%x]", peer->config_methods);

	} else if (g_strcmp0(key, "level") == 0) {

	} else if (g_strcmp0(key, "devicecapability") == 0) {
		unsigned char devicecapability = 0;

		g_variant_get(value, "y", &devicecapability);
		peer->dev_flags = (int)devicecapability;
		WDP_LOGD("Device Capa [0x%02x]", peer->dev_flags);

	} else if (g_strcmp0(key, "groupcapability") == 0) {
		unsigned char groupcapability = 0;

		g_variant_get(value, "y", &groupcapability);
		WDP_LOGD("Group Capa [0x%02x]", groupcapability);
		if (groupcapability & WS_GROUP_CAP_GROUP_OWNER) {
			peer->group_flags = WFD_OEM_GROUP_FLAG_GROUP_OWNER;
			peer->dev_role = WFD_OEM_DEV_ROLE_GO;
		}
		if (groupcapability & WS_GROUP_CAP_PERSISTENT_GROUP)
			peer->group_flags = WFD_OEM_GROUP_FLAG_PERSISTENT_GROUP;

	} else if (g_strcmp0(key, "PrimaryDeviceType") == 0) {
		unsigned char primarydevicetype[WS_DEVTYPE_LEN] = {0,};

		if(__ws_unpack_ay(primarydevicetype, value, WS_DEVTYPE_LEN)) {
			peer->pri_dev_type = primarydevicetype[1];
			peer->sec_dev_type = primarydevicetype[WS_DEVTYPE_LEN -1];
		}
	} else if (g_strcmp0(key, "SecondaryDeviceTypes") == 0) {
	} else if (g_strcmp0(key, "VendorExtension") == 0) {
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	} else if (g_strcmp0(key, "IEs") == 0) {
		unsigned char ies[WFD_SUBELEM_LEN_DEV_INFO + 3] = {0,};

		if(__ws_unpack_ay(ies, value, WFD_SUBELEM_LEN_DEV_INFO + 3))
			__parsing_wfd_info(ies, &(peer->display));
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
	} else if (g_strcmp0(key, "DeviceAddress") == 0) {

		if (__ws_unpack_ay(peer->dev_addr, value, WS_MACADDR_LEN))
			WDP_LOGD("Device address [" MACSTR "]", MAC2STR(peer->dev_addr));

	} else if (g_strcmp0(key, "InterfaceAddress") == 0) {

		if (__ws_unpack_ay(peer->intf_addr, value, WS_MACADDR_LEN))
			WDP_LOGD("Interface address [" MACSTR "]", MAC2STR(peer->intf_addr));

	} else if (g_strcmp0(key, "GODeviceAddress") == 0) {

		if (__ws_unpack_ay(peer->go_dev_addr, value, WS_MACADDR_LEN))
			WDP_LOGD("GODevice address [" MACSTR "]", MAC2STR(peer->go_dev_addr));

		if(!ISZEROMACADDR(peer->go_dev_addr))
			peer->dev_role = WFD_OEM_DEV_ROLE_GC;

	} else {
		WDP_LOGE("Unknown value");
	}
	return;
}

static void __ws_peer_property(const char *key, GVariant *value, void *user_data)
{
	if(!user_data) {
		return;
	}

	wfd_oem_dev_data_s *peer = (wfd_oem_dev_data_s *)user_data;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "DeviceName") == 0) {
		const char *name = NULL;

		g_variant_get(value, "s", &name);
		g_strlcpy(peer->name, name, WS_SSID_LEN);
		WDP_LOGD("Device Name [%s]", peer->name);

	} else if (g_strcmp0(key, "config_method") == 0) {
		int config_methods = 0;

		g_variant_get(value, "q", &config_methods);

		if (config_methods & WS_CONFIG_METHOD_DISPLAY)
			peer->config_methods |= WFD_OEM_WPS_MODE_DISPLAY;
		if (config_methods & WS_CONFIG_METHOD_PUSHBUTTON)
			peer->config_methods |= WFD_OEM_WPS_MODE_PBC;
		if (config_methods & WS_CONFIG_METHOD_KEYPAD)
			peer->config_methods |= WFD_OEM_WPS_MODE_KEYPAD;
		WDP_LOGD("Config method [0x%x]", peer->config_methods);

	} else if (g_strcmp0(key, "level") == 0) {

	} else if (g_strcmp0(key, "devicecapability") == 0) {
		unsigned char devicecapability = 0;

		g_variant_get(value, "y", &devicecapability);
		peer->dev_flags = (int)devicecapability;
		WDP_LOGD("Device Capa [0x%02x]", peer->dev_flags);

	} else if (g_strcmp0(key, "groupcapability") == 0) {
		unsigned char groupcapability = 0;

		g_variant_get(value, "y", &groupcapability);
		WDP_LOGD("Group Capa [0x%02x]", groupcapability);
		if (groupcapability & WS_GROUP_CAP_GROUP_OWNER) {
			peer->group_flags = WFD_OEM_GROUP_FLAG_GROUP_OWNER;
			peer->dev_role = WFD_OEM_DEV_ROLE_GO;
		}
		if (groupcapability & WS_GROUP_CAP_PERSISTENT_GROUP)
			peer->group_flags = WFD_OEM_GROUP_FLAG_PERSISTENT_GROUP;

	} else if (g_strcmp0(key, "PrimaryDeviceType") == 0) {
		unsigned char primarydevicetype[WS_DEVTYPE_LEN] = {0,};

		if (__ws_unpack_ay(primarydevicetype, value, WS_DEVTYPE_LEN)) {
			peer->pri_dev_type = primarydevicetype[1];
			peer->sec_dev_type = primarydevicetype[WS_DEVTYPE_LEN -1];
		}
	} else if (g_strcmp0(key, "SecondaryDeviceTypes") == 0) {
	} else if (g_strcmp0(key, "VendorExtension") == 0) {
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	} else if (g_strcmp0(key, "IEs") == 0) {
		unsigned char ies[WFD_SUBELEM_LEN_DEV_INFO + 3] = {0,};

		if(__ws_unpack_ay(ies, value, WFD_SUBELEM_LEN_DEV_INFO + 3))
			__parsing_wfd_info(ies, &(peer->display));
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
	} else if (g_strcmp0(key, "DeviceAddress") == 0) {

		if (__ws_unpack_ay(peer->p2p_dev_addr, value, WS_MACADDR_LEN))
			WDP_LOGD("Device address [" MACSTR "]", MAC2STR(peer->p2p_dev_addr));

	} else if (g_strcmp0(key, "InterfaceAddress") == 0) {

		if (__ws_unpack_ay(peer->p2p_intf_addr, value, WS_MACADDR_LEN))
			WDP_LOGD("Interface Address [" MACSTR "]", MAC2STR(peer->p2p_intf_addr));

	} else if (g_strcmp0(key, "GODeviceAddress") == 0) {

		unsigned char go_dev_addr[OEM_MACADDR_LEN];
		if (__ws_unpack_ay(go_dev_addr, value, WS_MACADDR_LEN))
			WDP_LOGD("[" MACSTR "]", MAC2STR(go_dev_addr));

		if(!ISZEROMACADDR(go_dev_addr))
			peer->dev_role = WFD_OEM_DEV_ROLE_GC;

	} else {
		WDP_LOGE("Unknown value");
	}
	return;
}

void __ws_interface_property(const char *key, GVariant *value, void *user_data)
{
	wfd_oem_event_s *event = (wfd_oem_event_s *)user_data;
	if(!event)
		return;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "Ifname") == 0) {
		const char *ifname = NULL;

		g_variant_get(value, "s", &ifname);
		g_strlcpy(event->ifname, ifname, OEM_IFACE_NAME_LEN+1);
		WDP_LOGD("Ifname [%s]", event->ifname);

	}
	return;
}

void __ws_group_property(const char *key, GVariant *value, void *user_data)
{
	wfd_oem_event_s *event = (wfd_oem_event_s *)user_data;
	if(!event || !event->edata)
		return;

	wfd_oem_group_data_s *group = (wfd_oem_group_data_s *)event->edata;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "Role") == 0) {
		const char *role = NULL;

		g_variant_get(value, "s", &role);
		WDP_LOGD("Role [%s]", role);

		if (!strncmp(role, "GO", 2))
			event->dev_role = WFD_OEM_DEV_ROLE_GO;
		else if (!strncmp(role, "client", 6))
			event->dev_role = WFD_OEM_DEV_ROLE_GC;

	} else if (g_strcmp0(key, "Frequency") == 0) {
		int frequency = 0;

		g_variant_get(value, "q", &frequency);
		group->freq = (int)frequency;

	} else if (g_strcmp0(key, "Passphrase") == 0) {
		const char *passphrase = NULL;

		g_variant_get(value, "s", &passphrase);
		g_strlcpy(group->pass, passphrase, OEM_PASS_PHRASE_LEN+1);
		WDP_LOGD("passphrase [%s]", group->pass);

	} else if (g_strcmp0(key, "Group") == 0) {

	} else if (g_strcmp0(key, "SSID") == 0) {
		unsigned char ssid[WS_SSID_LEN +1] = {0,};

		__ws_unpack_ay(ssid, value, WS_SSID_LEN);
		memcpy(group->ssid, ssid, WS_SSID_LEN+1);
		WDP_LOGD("ssid [%s]", group->ssid);

	} else if (g_strcmp0(key, "BSSID") == 0) {

		if (__ws_unpack_ay(group->go_dev_addr, value, WS_MACADDR_LEN))
			WDP_LOGD("[" MACSTR "]", MAC2STR(group->go_dev_addr));

	} else {
		WDP_LOGE("Unknown value");
	}
	return;
}

void __ws_extract_invitation_details(const char *key, GVariant *value, void *user_data)
{
	wfd_oem_event_s *event = (wfd_oem_event_s *)user_data;
	if(!event || !event->edata)
		return;

	wfd_oem_invite_data_s *invitation = (wfd_oem_invite_data_s *)event->edata;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "sa") == 0) {
		if (__ws_unpack_ay(invitation->sa, value, WS_MACADDR_LEN))
			WDP_LOGD("SA [" MACSTR "]", MAC2STR(invitation->sa));

	} else if (g_strcmp0(key, "go_dev_add") == 0) {
		if (__ws_unpack_ay(invitation->go_dev_addr, value, WS_MACADDR_LEN))
					WDP_LOGD("GO device address [" MACSTR "]", MAC2STR(invitation->go_dev_addr));

	} else if (g_strcmp0(key, "bssid") == 0) {
		if (__ws_unpack_ay(invitation->bssid, value, WS_MACADDR_LEN))
					WDP_LOGD("BSSID [" MACSTR "]", MAC2STR(invitation->bssid));

	} else if (g_strcmp0(key, "persistent_id") == 0) {
		g_variant_get(value, "i", &(invitation->persistent_id));
		WDP_LOGD("persistent id [%d]", invitation->persistent_id);

	} else if (g_strcmp0(key, "oper_freq") == 0) {
		g_variant_get(value, "i", &(invitation->oper_freq));
		WDP_LOGD("oper freq [%d]", invitation->oper_freq);
	} else {
		WDP_LOGE("Unknown value");
	}
	return;
}

void __ws_extract_group_details(const char *key, GVariant *value, void *user_data)
{
	wfd_oem_event_s *event = (wfd_oem_event_s *)user_data;
	if(!event || !event->edata)
		return;

	wfd_oem_group_data_s *group = (wfd_oem_group_data_s *)event->edata;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "interface_object") == 0) {
		static char interface_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
		const char *i_path = NULL;

		g_variant_get(value, "o", &i_path);
		g_strlcpy(interface_path, i_path, DBUS_OBJECT_PATH_MAX);
		WDP_LOGD("Retrive Added path [%s]", interface_path);
		g_strlcpy(g_pd->group_iface_path, interface_path, DBUS_OBJECT_PATH_MAX);
		dbus_property_get_all(interface_path, g_pd->g_dbus,
				SUPPLICANT_IFACE, __ws_interface_property, event);

	} else if (g_strcmp0(key, "role") == 0) {
		const char *role = NULL;

		g_variant_get(value, "s", &role);
		WDP_LOGD("Role [%s]", role);

		if (!strncmp(role, "GO", 2))
			event->dev_role = WFD_OEM_DEV_ROLE_GO;
		else if (!strncmp(role, "client", 6))
			event->dev_role = WFD_OEM_DEV_ROLE_GC;

	} else if (g_strcmp0(key, "IpAddr") == 0) {

		if (__ws_unpack_ay(group->ip_addr, value, OEM_IPADDR_LEN))
			WDP_LOGD("IP address [" IPSTR "]", IP2STR(group->ip_addr));

	} else if (g_strcmp0(key, "IpAddrMask") == 0) {

		if (__ws_unpack_ay(group->ip_addr_mask, value, OEM_IPADDR_LEN))
			WDP_LOGD("IP mask [" IPSTR "]", IP2STR(group->ip_addr_mask));

	} else if (g_strcmp0(key, "IpAddrGo") == 0) {

		if (__ws_unpack_ay(group->ip_addr_go, value, OEM_IPADDR_LEN))
			WDP_LOGD("GO IP address [" IPSTR "]", IP2STR(group->ip_addr_go));

	} else if (g_strcmp0(key, "group_object") == 0) {
		static char group_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
		const char *g_path;

		g_variant_get(value, "o", &g_path);
		g_strlcpy(group_path, g_path, DBUS_OBJECT_PATH_MAX);
		WDP_LOGD("Retrive group path [%s]", group_path);
		dbus_property_get_all(group_path, g_pd->g_dbus, SUPPLICANT_P2P_GROUP,
				__ws_group_property, event);

		g_pd->group_sub_id =
			g_dbus_connection_signal_subscribe(
				g_pd->g_dbus,
				SUPPLICANT_SERVICE, /* bus name */
				SUPPLICANT_P2P_GROUP, /* interface */
				NULL, /* member */
				group_path, /* object path */
				NULL, /* arg0 */
				G_DBUS_SIGNAL_FLAGS_NONE,
				_group_signal_cb,
				NULL, NULL);
	}
	return;
}

void __ws_extract_gonegfailaure_details(const char *key, GVariant *value, void *user_data)
{
	wfd_oem_event_s *event = (wfd_oem_event_s *)user_data;
	if(!event || !event->edata)
		return;

	wfd_oem_conn_data_s *conn = (wfd_oem_conn_data_s *)event->edata;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "peer_object") == 0) {
		static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
		const char *path;

		g_variant_get(value, "o", &path);
		g_strlcpy(peer_path, path, DBUS_OBJECT_PATH_MAX);
		WDP_LOGD("Retrive peer path [%s]", peer_path);

	} else if (g_strcmp0(key, "status") == 0) {
		int status = 0;

		g_variant_get(value, "i", &status);
		WDP_LOGD("Retrive status [%d]", status);
		conn->status = status;
	}
	return;
}

void __ws_extract_gonegsuccess_details(const char *key, GVariant *value, void *user_data)
{
	wfd_oem_event_s *event = (wfd_oem_event_s *)user_data;
	if(!event || !event->edata)
		return;

	wfd_oem_conn_data_s *edata = (wfd_oem_conn_data_s *)event->edata;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "peer_object") == 0) {

	} else if (g_strcmp0(key, "status") == 0) {

	} else if (g_strcmp0(key, "passphrase") == 0) {

	} else if (g_strcmp0(key, "role_go") == 0) {
		//local device role
		const char *role = NULL;

		g_variant_get(value, "s", &role);
		if (!strncmp(role, "GO", 2))
			event->dev_role = WFD_OEM_DEV_ROLE_GO;
		else if (!strncmp(role, "client", 6))
			event->dev_role = WFD_OEM_DEV_ROLE_GC;

	} else if (g_strcmp0(key, "ssid") == 0) {
		unsigned char ssid[WS_SSID_LEN +1] = {0,};

		__ws_unpack_ay(ssid, value, WS_SSID_LEN);
			memcpy(edata->ssid, ssid, WS_SSID_LEN+1);
			WDP_LOGD("ssid [%s]", edata->ssid);

	} else if (g_strcmp0(key, "peer_device_addr") == 0) {

		if(__ws_unpack_ay(edata->peer_device_addr, value, WS_MACADDR_LEN))
			WDP_LOGD("Device address[" MACSTR "]", MAC2STR(edata->peer_device_addr));

	} else if(g_strcmp0(key, "peer_interface_addr") == 0) {

		if(__ws_unpack_ay(edata->peer_intf_addr, value, WS_MACADDR_LEN))
			WDP_LOGD("Interface address [" MACSTR "]", MAC2STR(edata->peer_intf_addr));

	} else if (g_strcmp0(key, "wps_method") == 0) {

	} else if (g_strcmp0(key, "frequency_list") == 0) {

	} else if (g_strcmp0(key, "persistent_group") == 0) {

		g_variant_get(value, "i", &(edata->persistent_group));
		WDP_LOGD("persistent_group [%d]", edata->persistent_group);

	} else if (g_strcmp0(key, "peer_config_timeout") == 0) {

	}
	return;
}

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
void __ws_extract_peer_service(wfd_oem_event_s *data, unsigned char *service_hex, int tlvs_len)
{
	GList *services = NULL;
	wfd_oem_new_service_s *new_service = NULL;
	char *segment = NULL;
	int count = 0;
	int ptr = 0;
	int length = 0;
	int res = 0;

	while(ptr + 2 < WS_MAX_SERVICE_LEN &&
			(length = (service_hex[ptr+1]*256) + service_hex[ptr]) > 0) {
		segment = (char*) g_try_malloc0(length*2+1);
		if(segment) {
			__ws_byte_to_hex(segment, length * 2 + 1, &service_hex[ptr + 3], length);
			res = __ws_segment_to_service(segment, &new_service);
			if (res < 0) {
				WDP_LOGE("Failed to convert segment as service instance");
				g_free(segment);
				segment = NULL;
				continue;
			}
			services = g_list_append(services, new_service);
			count++;
			ptr += length + 4;
			g_free(segment);
			segment = NULL;
		}
		data->edata_type = WFD_OEM_EDATA_TYPE_NEW_SERVICE;
		data->dev_role = count;
		data->edata = (void*) services;
	}
}

void __ws_extract_servicediscoveryresponse_details(const char *key, GVariant *value, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s *event = (wfd_oem_event_s *)user_data;

	if(!event)
		return;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "peer_object") == 0) {
		static unsigned char peer_dev[WS_MACSTR_LEN] = {'\0',};
		const char *path = NULL;
		char *loc = NULL;

		g_variant_get(value, "o", &path);
		if(path == NULL)
			return;

		WDP_LOGD("Retrive Added path [%s]", path);
		loc = strrchr(path,'/');
		if(loc != NULL)
			__ws_mac_compact_to_normal(loc + 1, peer_dev);
		__ws_txt_to_mac(peer_dev, event->dev_addr);

	} else if (g_strcmp0(key, "update_indicator")) {

	} else if (g_strcmp0(key, "tlvs")) {
		GVariantIter *iter = NULL;
		unsigned char service_hex[WS_MAX_SERVICE_LEN];
		int byte_length = 0;

		g_variant_get(value, "ay", &iter);
		if (iter == NULL) {
			WDP_LOGE("failed to get iterator");
			return;
		}

		memset(service_hex, 0x0, WS_MAX_SERVICE_LEN);
		while (g_variant_iter_loop (iter, "y", &service_hex[byte_length]))
			byte_length++;

		__ws_extract_peer_service(event, service_hex, byte_length);
	}

	__WDP_LOG_FUNC_EXIT__;
}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

static void _ws_process_device_found(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	wfd_oem_dev_data_s *edata = NULL;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};

	edata = (wfd_oem_dev_data_s *) g_try_malloc0(sizeof(wfd_oem_dev_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_PEER_FOUND;

	__ws_path_to_addr(peer_path, event.dev_addr, parameters);

	dbus_property_get_all(peer_path, g_pd->g_dbus, SUPPLICANT_P2P_PEER,
			__ws_peer_property, event.edata);

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_device_lost(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};

	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata_type = WFD_OEM_EDATA_TYPE_NONE;
	event.event_id = WFD_OEM_EVENT_PEER_DISAPPEARED;

	__ws_path_to_addr(peer_path, event.dev_addr, parameters);

	g_pd->callback(g_pd->user_data, &event);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_find_stoppped(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;

	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata_type = WFD_OEM_EDATA_TYPE_NONE;
	event.event_id = WFD_OEM_EVENT_DISCOVERY_FINISHED;

	g_pd->callback(g_pd->user_data, &event);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_prov_disc_req_display_pin(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;

	wfd_oem_event_s event;
	wfd_oem_dev_data_s *edata = NULL;

	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	static unsigned char peer_dev[OEM_MACSTR_LEN] = {'\0',};
	const char *path = NULL;
	const char *pin = NULL;
	char *loc = NULL;

	edata = (wfd_oem_dev_data_s *) g_try_malloc0(sizeof(wfd_oem_dev_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_PROV_DISC_REQ;
	event.wps_mode = WFD_OEM_WPS_MODE_DISPLAY;

	g_variant_get(parameters, "(os)", &path, &pin);
	g_strlcpy(peer_path, path, DBUS_OBJECT_PATH_MAX);
	WDP_LOGD("Retrive Added path [%s]", peer_path);

	loc = strrchr(peer_path,'/');
	__ws_mac_compact_to_normal(loc + 1, peer_dev);
	__ws_txt_to_mac(peer_dev, event.dev_addr);
	WDP_LOGD("peer mac [" MACSTR "]", MAC2STR(event.dev_addr));

	g_strlcpy(event.wps_pin, pin, WS_PINSTR_LEN + 1);
	WDP_LOGD("Retrive pin [%s]", event.wps_pin);

	dbus_property_get_all(peer_path, g_pd->g_dbus, SUPPLICANT_P2P_PEER,
			__ws_peer_property, event.edata);

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_prov_disc_resp_display_pin(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;

	wfd_oem_event_s event;
	wfd_oem_dev_data_s *edata = NULL;

	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	static unsigned char peer_dev[OEM_MACSTR_LEN] = {'\0',};
	const char *path = NULL;
	const char *pin = NULL;
	char *loc = NULL;

	edata = (wfd_oem_dev_data_s *) g_try_malloc0(sizeof(wfd_oem_dev_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_PROV_DISC_RESP;
	event.wps_mode = WFD_OEM_WPS_MODE_DISPLAY;

	g_variant_get(parameters, "(os)", &path, &pin);
	g_strlcpy(peer_path, path, DBUS_OBJECT_PATH_MAX);
	WDP_LOGD("Retrive Added path [%s]", peer_path);

	loc = strrchr(peer_path,'/');
	__ws_mac_compact_to_normal(loc + 1, peer_dev);
	__ws_txt_to_mac(peer_dev, event.dev_addr);
	WDP_LOGD("peer mac [" MACSTR "]", MAC2STR(event.dev_addr));

	g_strlcpy(event.wps_pin, pin, WS_PINSTR_LEN + 1);
	WDP_LOGD("Retrive pin [%s]", event.wps_pin);

	dbus_property_get_all(peer_path, g_pd->g_dbus, SUPPLICANT_P2P_PEER,
			__ws_peer_property, event.edata);

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_prov_disc_req_enter_pin(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	wfd_oem_dev_data_s *edata = NULL;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};

	edata = (wfd_oem_dev_data_s *) g_try_malloc0(sizeof(wfd_oem_dev_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_PROV_DISC_REQ;
	event.wps_mode = WFD_OEM_WPS_MODE_KEYPAD;

	__ws_path_to_addr(peer_path, event.dev_addr, parameters);

	dbus_property_get_all(peer_path, g_pd->g_dbus, SUPPLICANT_P2P_PEER,
			__ws_peer_property, event.edata);

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_prov_disc_resp_enter_pin(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	wfd_oem_dev_data_s *edata = NULL;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};

	edata = (wfd_oem_dev_data_s *) g_try_malloc0(sizeof(wfd_oem_dev_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_PROV_DISC_RESP;
	event.wps_mode = WFD_OEM_WPS_MODE_KEYPAD;

	__ws_path_to_addr(peer_path, event.dev_addr, parameters);

	dbus_property_get_all(peer_path, g_pd->g_dbus, SUPPLICANT_P2P_PEER,
			__ws_peer_property, event.edata);

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_prov_disc_pbc_req(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	wfd_oem_dev_data_s *edata = NULL;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};

	edata = (wfd_oem_dev_data_s *) g_try_malloc0(sizeof(wfd_oem_dev_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_PROV_DISC_REQ;
	event.wps_mode = WFD_OEM_WPS_MODE_PBC;

	__ws_path_to_addr(peer_path, event.dev_addr, parameters);

	dbus_property_get_all(peer_path, g_pd->g_dbus, SUPPLICANT_P2P_PEER,
			__ws_peer_property, event.edata);

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_prov_disc_pbc_resp(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	wfd_oem_dev_data_s *edata = NULL;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};

	edata = (wfd_oem_dev_data_s *) g_try_malloc0(sizeof(wfd_oem_dev_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_PROV_DISC_RESP;
	event.wps_mode = WFD_OEM_WPS_MODE_PBC;

	__ws_path_to_addr(peer_path, event.dev_addr, parameters);

	dbus_property_get_all(peer_path, g_pd->g_dbus, SUPPLICANT_P2P_PEER,
			__ws_peer_property, event.edata);

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_prov_disc_failure(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	static unsigned char peer_dev[OEM_MACSTR_LEN] = {'\0',};
	const char *path = NULL;
	int prov_status = 0;
	char *loc = NULL;

	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_PROV_DISC_FAIL;

	g_variant_get(parameters, "(oi)", &path, &prov_status);
	g_strlcpy(peer_path, path, DBUS_OBJECT_PATH_MAX);
	WDP_LOGD("Retrive Added path [%s]", peer_path);
	WDP_LOGD("Retrive Failure stateus [%d]", prov_status);

	loc = strrchr(peer_path,'/');
	__ws_mac_compact_to_normal(loc + 1, peer_dev);
	__ws_txt_to_mac(peer_dev, event.dev_addr);
	WDP_LOGE("peer mac [" MACSTR "]", MAC2STR(event.dev_addr));

	g_pd->callback(g_pd->user_data, &event);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_group_started(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	GVariantIter *iter = NULL;
	wfd_oem_event_s event;
	wfd_oem_group_data_s *edata = NULL;

	edata = (wfd_oem_group_data_s*)calloc(1, sizeof(wfd_oem_group_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_GROUP;
	event.event_id = WFD_OEM_EVENT_GROUP_CREATED;

	if(parameters != NULL){
		g_variant_get(parameters, "(a{sv})", &iter);

		if (iter != NULL) {
			dbus_property_foreach(iter, __ws_extract_group_details, &event);
			g_variant_iter_free(iter);
		}
	} else {
		WDP_LOGE("No properties");
	}

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_go_neg_success(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	GVariantIter *iter = NULL;
	wfd_oem_event_s event;
	wfd_oem_conn_data_s *edata = NULL;

	edata = (wfd_oem_conn_data_s*)calloc(1, sizeof(wfd_oem_conn_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_CONN;
	event.event_id = WFD_OEM_EVENT_GO_NEG_DONE;

	if (parameters != NULL){
		g_variant_get(parameters, "(a{sv})", &iter);

		if (iter != NULL) {
			dbus_property_foreach(iter, __ws_extract_gonegsuccess_details, &event);
			g_variant_iter_free(iter);
		}
	} else {
		WDP_LOGE("No properties");
	}

	g_pd->callback(g_pd->user_data, &event);
	g_free(edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_go_neg_failure(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	GVariantIter *iter = NULL;
	wfd_oem_event_s event;
	wfd_oem_conn_data_s *edata = NULL;

	edata = (wfd_oem_conn_data_s *) g_try_malloc0(sizeof(wfd_oem_conn_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_GO_NEG_FAIL;

	if (parameters != NULL) {
		g_variant_get(parameters, "(a{sv})", &iter);

		if (iter != NULL) {
			dbus_property_foreach(iter, __ws_extract_gonegfailaure_details, &event);
			g_variant_iter_free(iter);
		}
	} else {
		WDP_LOGE("No properties");
	}

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_go_neg_request(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	wfd_oem_dev_data_s *edata = NULL;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	static unsigned char peer_dev[OEM_MACSTR_LEN] = {'\0',};
	const char *path = NULL;
	char * loc = NULL;

	int dev_pwd_id = 0;

	edata = (wfd_oem_dev_data_s *) g_try_malloc0(sizeof(wfd_oem_dev_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
	event.event_id = WFD_OEM_EVENT_GO_NEG_REQ;

	g_variant_get(parameters, "(oq)", &path, &dev_pwd_id);
	g_strlcpy(peer_path, path, DBUS_OBJECT_PATH_MAX);
	WDP_LOGD("Retrive peer path [%s]", peer_path);

	WDP_LOGD("Retrive dev_passwd_id [%d]", dev_pwd_id);

	if (dev_pwd_id == WS_DEV_PASSWD_ID_PUSH_BUTTON)
		event.wps_mode = WFD_OEM_WPS_MODE_PBC;
	else if (dev_pwd_id == WS_DEV_PASSWD_ID_REGISTRAR_SPECIFIED)
		event.wps_mode = WFD_OEM_WPS_MODE_DISPLAY;
	else if (dev_pwd_id == WS_DEV_PASSWD_ID_USER_SPECIFIED)
		event.wps_mode = WFD_OEM_WPS_MODE_KEYPAD;
	else
		event.wps_mode = WFD_OEM_WPS_MODE_NONE;

	g_variant_get(parameters, "(o)", &path);
	g_strlcpy(peer_path, path, DBUS_OBJECT_PATH_MAX);
	WDP_LOGD("Retrive Added path [%s]", peer_path);

	loc = strrchr(peer_path,'/');
	__ws_mac_compact_to_normal(loc + 1, peer_dev);
	__ws_txt_to_mac(peer_dev, event.dev_addr);
	WDP_LOGD("peer mac [" MACSTR "]", MAC2STR(event.dev_addr));

	dbus_property_get_all(peer_path, g_pd->g_dbus, SUPPLICANT_P2P_PEER,
			__ws_peer_property, event.edata);

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}
static void _ws_process_invitation_received(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	GVariantIter *iter = NULL;
	wfd_oem_event_s event;
	wfd_oem_invite_data_s *edata = NULL;

	edata = (wfd_oem_invite_data_s *) g_try_malloc0(sizeof(wfd_oem_invite_data_s));
	if (!edata) {
		WDP_LOGF("Failed to allocate memory for event. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return;
	}
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.edata = (void*) edata;
	event.edata_type = WFD_OEM_EDATA_TYPE_INVITE;
	event.event_id = WFD_OEM_EVENT_INVITATION_REQ;

	if (parameters != NULL) {
		g_variant_get(parameters, "(a{sv})", &iter);

		if (iter != NULL) {
			dbus_property_foreach(iter, __ws_extract_invitation_details, &event);
			g_variant_iter_free(iter);
		}
	} else {
		WDP_LOGE("No properties");
	}
	memcpy(&(event.dev_addr), edata->sa, OEM_MACADDR_LEN);

	g_pd->callback(g_pd->user_data, &event);
	g_free(event.edata);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_invitation_result(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

//	g_pd->callback(g_pd->user_data, event);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_group_finished(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;

	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.event_id = WFD_OEM_EVENT_GROUP_DESTROYED;
	event.edata_type = WFD_OEM_EDATA_TYPE_NONE;

	g_dbus_connection_signal_unsubscribe(g_pd->g_dbus, g_pd->group_sub_id);
	memset(g_pd->group_iface_path, 0x0, DBUS_OBJECT_PATH_MAX);

	g_pd->callback(g_pd->user_data, &event);

	__WDP_LOG_FUNC_EXIT__;
}

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
static void _ws_process_service_discovery_response(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	GVariantIter *iter = NULL;
	wfd_oem_event_s event;

	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.event_id = WFD_OEM_EVENT_SERV_DISC_RESP;

	if(parameters != NULL) {
		g_variant_get(parameters, "(a{sv})", &iter);
		if(iter != NULL) {
			dbus_property_foreach(iter, __ws_extract_servicediscoveryresponse_details, &event);
			event.edata_type = WFD_OEM_EDATA_TYPE_NEW_SERVICE;
			g_variant_iter_free(iter);
		}
	} else {
		WDP_LOGE("No Properties");
	}

	g_pd->callback(g_pd->user_data, &event);

	if (event.edata_type == WFD_OEM_EDATA_TYPE_NEW_SERVICE)
		g_list_free((GList*) event.edata);

	__WDP_LOG_FUNC_EXIT__;
}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

static void _ws_process_persistent_group_added(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

//	g_pd->callback(g_pd->user_data, &event);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_persistent_group_removed(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;
	memset(&event, 0x0, sizeof(wfd_oem_event_s));

//	g_pd->callback(g_pd->user_data, &event);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_wps_failed(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	GVariantIter *iter = NULL;
	wfd_oem_event_s event;
	const char *name = NULL;

	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.event_id = WFD_OEM_EVENT_WPS_FAIL;
	event.edata_type = WFD_OEM_EDATA_TYPE_NONE;

	g_variant_get(parameters, "(sa{sv})", &name, &iter);

	WDP_LOGD("code [%s]", name);

	if (iter != NULL) {

		gchar *key = NULL;
		GVariant *value = NULL;

		while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
#if defined (TIZEN_DEBUG_DBUS_VALUE)
			CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
		}
		g_variant_iter_free(iter);
	}

	g_pd->callback(g_pd->user_data, &event);

	__WDP_LOG_FUNC_EXIT__;
}

static void _ws_process_group_formation_failure(GDBusConnection *connection,
		const gchar *object_path, GVariant *parameters)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_event_s event;

	memset(&event, 0x0, sizeof(wfd_oem_event_s));

	event.event_id = WFD_OEM_EVENT_WPS_FAIL;
	event.edata_type = WFD_OEM_EDATA_TYPE_NONE;

	g_pd->callback(g_pd->user_data, &event);

	__WDP_LOG_FUNC_EXIT__;
}

static struct {
	const char *interface;
	const char *member;
	void (*function) (GDBusConnection *connection,const gchar *object_path,
			GVariant *parameters);
} ws_p2pdevice_signal_map[] = {
	{
		SUPPLICANT_P2PDEVICE,
		"DeviceFound",
		_ws_process_device_found
	},
	{
		SUPPLICANT_P2PDEVICE,
		"DeviceLost",
		_ws_process_device_lost
	},
	{
		SUPPLICANT_P2PDEVICE,
		"FindStopped",
		_ws_process_find_stoppped
	},
	{
		SUPPLICANT_P2PDEVICE,
		"ProvisionDiscoveryRequestDisplayPin",
		_ws_process_prov_disc_req_display_pin
	},
	{
		SUPPLICANT_P2PDEVICE,
		"ProvisionDiscoveryResponseDisplayPin",
		_ws_process_prov_disc_resp_display_pin
	},
	{
			SUPPLICANT_P2PDEVICE,
		"ProvisionDiscoveryRequestEnterPin",
		_ws_process_prov_disc_req_enter_pin
	},
	{
		SUPPLICANT_P2PDEVICE,
		"ProvisionDiscoveryResponseEnterPin",
		_ws_process_prov_disc_resp_enter_pin
	},
	{
		SUPPLICANT_P2PDEVICE,
		"ProvisionDiscoveryPBCRequest",
		_ws_process_prov_disc_pbc_req
	},
	{
		SUPPLICANT_P2PDEVICE,
		"ProvisionDiscoveryPBCResponse",
		_ws_process_prov_disc_pbc_resp
	},
	{
		SUPPLICANT_P2PDEVICE,
		"ProvisionDiscoveryFailure",
		_ws_process_prov_disc_failure
	},
	{
		SUPPLICANT_P2PDEVICE,
		"GroupStarted",
		_ws_process_group_started
	},
	{
		SUPPLICANT_P2PDEVICE,
		"GONegotiationSuccess",
		_ws_process_go_neg_success
	},
	{
		SUPPLICANT_P2PDEVICE,
		"GONegotiationFailure",
		_ws_process_go_neg_failure
	},
	{
		SUPPLICANT_P2PDEVICE,
		"GONegotiationRequest",
		_ws_process_go_neg_request
	},
	{
		SUPPLICANT_P2PDEVICE,
		"InvitationReceived",
		_ws_process_invitation_received
	},
	{
		SUPPLICANT_P2PDEVICE,
		"InvitationResult",
		_ws_process_invitation_result
	},
	{
		SUPPLICANT_P2PDEVICE,
		"GroupFinished",
		_ws_process_group_finished
	},
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	{
		SUPPLICANT_P2PDEVICE,
		"ServiceDiscoveryResponse",
		_ws_process_service_discovery_response
	},
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
	{
		SUPPLICANT_P2PDEVICE,
		"PersistentGroupAdded",
		_ws_process_persistent_group_added
	},
	{
		SUPPLICANT_P2PDEVICE,
		"PersistentGroupRemoved",
		_ws_process_persistent_group_removed
	},
	{
		SUPPLICANT_P2PDEVICE,
		"WpsFailed",
		_ws_process_wps_failed
	},
	{
		SUPPLICANT_P2PDEVICE,
		"GroupFormationFailure",
		_ws_process_group_formation_failure
	},
	{
		NULL,
		NULL,
		NULL
	}
};

static void _p2pdevice_signal_cb(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path, const gchar *interface,
		const gchar *signal, GVariant *parameters, gpointer user_data)
{
	int i = 0;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	DEBUG_SIGNAL(sender, object_path, interface, signal, parameters);
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	for (i = 0; ws_p2pdevice_signal_map[i].member != NULL; i++) {
		if (!g_strcmp0(signal, ws_p2pdevice_signal_map[i].member) &&
				ws_p2pdevice_signal_map[i].function != NULL)
			ws_p2pdevice_signal_map[i].function(connection, object_path, parameters);
	}
}


static void __ws_parse_peer_joined(char *peer_path,
		unsigned char *dev_addr, unsigned char *ip_addr, GVariant *parameter)
{
	__WDP_LOG_FUNC_ENTER__;

	GVariantIter *iter;
	static unsigned char peer_dev[WS_MACSTR_LEN] = {'\0',};
	const char *path = NULL;
	char *loc = NULL;
	int i = 0;

	g_variant_get(parameter, "(oay)", &path, &iter);
	g_strlcpy(peer_path, path, DBUS_OBJECT_PATH_MAX);
	WDP_LOGD("Retrive Added path [%s]", peer_path);

	loc = strrchr(peer_path,'/');
	__ws_mac_compact_to_normal(loc + 1, peer_dev);

	__ws_txt_to_mac(peer_dev, dev_addr);
	WDP_LOGD("peer mac [" MACSTR "]", MAC2STR(dev_addr));

	for(i = 0; i < OEM_IPADDR_LEN; i++)
		g_variant_iter_loop (iter, "y", &ip_addr[i]);

	WDP_LOGD("peer ip [" IPSTR "]", IP2STR(ip_addr));

	return;
	__WDP_LOG_FUNC_EXIT__;
}


static void _group_signal_cb(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path, const gchar *interface,
		const gchar *signal, GVariant *parameters, gpointer user_data)
{
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	DEBUG_SIGNAL(sender, object_path, interface, signal, parameters);
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	if(!g_strcmp0(signal,"PeerJoined")){

			wfd_oem_event_s event;
			wfd_oem_dev_data_s *edata = NULL;

			static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};

			edata = (wfd_oem_dev_data_s *) g_try_malloc0(sizeof(wfd_oem_dev_data_s));
			if (!edata) {
				WDP_LOGF("Failed to allocate memory for event. [%s]",
						strerror(errno));
				__WDP_LOG_FUNC_EXIT__;
				return;
			}
			memset(&event, 0x0, sizeof(wfd_oem_event_s));

			event.edata = (void*) edata;
			event.edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
			event.event_id = WFD_OEM_EVENT_STA_CONNECTED;

			__ws_parse_peer_joined(peer_path, event.dev_addr, event.ip_addr_peer, parameters);

			dbus_property_get_all(peer_path, g_pd->g_dbus, SUPPLICANT_P2P_PEER,
						__ws_peer_property, event.edata);

			g_pd->callback(g_pd->user_data, &event);
			g_free(edata);

	} else if (!g_strcmp0(signal,"PeerDisconnected")) {

		wfd_oem_event_s event;

		static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};

		memset(&event, 0x0, sizeof(wfd_oem_event_s));

		event.edata_type = WFD_OEM_EDATA_TYPE_NONE;
		event.event_id = WFD_OEM_EVENT_STA_DISCONNECTED;

		__ws_path_to_addr(peer_path, event.dev_addr, parameters);

		g_pd->callback(g_pd->user_data, &event);
	}
}

static void __register_p2pdevice_signal(GVariant *value, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_dbus_plugin_data_s * pd_data;
	static char interface_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	const char *path = NULL;

	pd_data = (ws_dbus_plugin_data_s *)g_pd;

	g_variant_get(value, "(o)", &path);
	g_strlcpy(interface_path, path, DBUS_OBJECT_PATH_MAX);
	g_strlcpy(pd_data->iface_path, path, DBUS_OBJECT_PATH_MAX);

	WDP_LOGD("interface object path [%s]", interface_path);
	/* subscribe interface p2p signal */
	WDP_LOGD("register P2PDevice iface signal");
	pd_data->p2pdevice_sub_id = g_dbus_connection_signal_subscribe(
		pd_data->g_dbus,
		SUPPLICANT_SERVICE, /* bus name */
		SUPPLICANT_P2PDEVICE, /* interface */
		NULL, /* member */
		NULL, /* object path */
		NULL, /* arg0 */
		G_DBUS_SIGNAL_FLAGS_NONE,
		_p2pdevice_signal_cb,
		NULL, NULL);
	__WDP_LOG_FUNC_EXIT__;
}

static int _ws_create_interface(const char *iface_name, handle_reply function, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	dbus_method_param_s params;

	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "CreateInterface", SUPPLICANT_PATH, g_dbus);

	builder = g_variant_builder_new(G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add(builder, "{sv}", "Ifname", g_variant_new_string(iface_name));
	g_variant_builder_add(builder, "{sv}", "ConfigFile", g_variant_new_string(CONF_FILE_PATH));
	params.params = g_variant_new("(a{sv})", builder);
	g_variant_builder_unref(builder);
	res = dbus_method_call(&params, SUPPLICANT_INTERFACE, function, user_data);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to CreateInterface");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static int _ws_get_interface(const char *iface_name, handle_reply function, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}

	dbus_set_method_param(&params, SUPPLICANT_METHOD_GETINTERFACE,
			SUPPLICANT_PATH, g_pd->g_dbus);

	params.params = g_variant_new("(s)", iface_name);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGE("param [%s]", g_variant_print(params.params, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	res = dbus_method_call(&params, SUPPLICANT_INTERFACE,
			function, user_data);

	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to get interface");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

#if defined (TIZEN_MOBILE) && (TIZEN_WLAN_BOARD_SPRD)
static void __ws_remove_interface(GVariant *value, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	dbus_method_param_s params;
	const char *path = NULL;
	static char interface_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return;
	}

	g_variant_get(value, "(o)", &path);
	g_strlcpy(interface_path, path, DBUS_OBJECT_PATH_MAX);
	WDP_LOGD("interface object path [%s]", interface_path);

	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "RemoveInterface", SUPPLICANT_PATH, g_dbus);
	params.params = g_variant_new("(o)", interface_path);

	res = dbus_method_call(&params, SUPPLICANT_INTERFACE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to RemoveInterface");

	__WDP_LOG_FUNC_EXIT__;
	return;
}
#endif /* (TIZEN_MOBILE) && (TIZEN_WLAN_BOARD_SPRD) */

static int _ws_init_dbus_connection(void)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	int res = 0;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);

	if (conn == NULL) {
		if(error != NULL){
			WDP_LOGE("Error! Failed to connect to the D-BUS daemon: [%s]",
					error->message);
			g_error_free(error);
		}
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	g_pd->g_dbus = conn;

	WDP_LOGD("register supplicant signal");
	/* subscribe supplicant signal */
	g_pd->supp_sub_id = g_dbus_connection_signal_subscribe(
		g_pd->g_dbus,
		SUPPLICANT_SERVICE, /* bus name */
		SUPPLICANT_INTERFACE, /* interface */
		NULL, /* member */
		SUPPLICANT_PATH, /* object path */
		NULL, /* arg0 */
		G_DBUS_SIGNAL_FLAGS_NONE,
		_supplicant_signal_cb,
		NULL, NULL);
#if defined (TIZEN_MOBILE) && (TIZEN_WLAN_BOARD_SPRD)
	if(_ws_get_interface(COMMON_IFACE_NAME, NULL, NULL) < 0)
		_ws_create_interface(COMMON_IFACE_NAME, NULL, NULL);
	if(_ws_get_interface(P2P_IFACE_NAME, __register_p2pdevice_signal, NULL) < 0)
		res = _ws_create_interface(P2P_IFACE_NAME, __register_p2pdevice_signal, NULL);
#else /* (TIZEN_MOBILE) && (TIZEN_WLAN_BOARD_SPRD) */
	if(_ws_get_interface(COMMON_IFACE_NAME, __register_p2pdevice_signal, NULL) < 0)
		res = _ws_create_interface(COMMON_IFACE_NAME, __register_p2pdevice_signal, NULL);
#endif /* (TIZEN_MOBILE) && (TIZEN_WLAN_BOARD_SPRD) */

	if (res < 0)
			WDP_LOGE("Failed to subscribe interface signal");
	else
		WDP_LOGI("Successfully register signal filters");
	return res;
	__WDP_LOG_FUNC_EXIT__;
}

static int _ws_deinit_dbus_connection(void)
{
	GDBusConnection *g_dbus = NULL;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	if(g_pd != NULL) {
		g_dbus_connection_signal_unsubscribe(g_dbus, g_pd->supp_sub_id);
		g_dbus_connection_signal_unsubscribe(g_dbus, g_pd->p2pdevice_sub_id);
		g_dbus_connection_signal_unsubscribe(g_dbus, g_pd->group_sub_id);
	}
	g_pd->group_iface_sub_id = 0;
	g_pd->p2pdevice_sub_id = 0;
	g_pd->group_sub_id = 0;
	memset(g_pd->group_iface_path, 0x0, DBUS_OBJECT_PATH_MAX);
	memset(g_pd->iface_path, 0x0, DBUS_OBJECT_PATH_MAX);

	g_object_unref(g_dbus);
	return 0;
}

int wfd_plugin_load(wfd_oem_ops_s **ops)
{
	if (!ops) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	*ops = &supplicant_ops;

	return 0;
}

static int _ws_reset_plugin(ws_dbus_plugin_data_s *g_pd)
{
	__WDP_LOG_FUNC_ENTER__;

	if (!g_pd) {
		WDP_LOGE("Invalid parameter");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	_ws_deinit_dbus_connection();

	if (g_pd->activated)
		ws_deactivate(g_pd->concurrent);

	g_free(g_pd);
	g_pd = NULL;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}


static int __ws_check_net_interface(char* if_name)
{
	struct ifreq ifr;
	int fd;

	if (if_name == NULL) {
		WDP_LOGE("Invalid param");
		return -1;
	}

	fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		WDP_LOGE("socket create error: %d", fd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	ifr.ifr_name[IFNAMSIZ-1] = '\0';

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		WDP_LOGE("ioctl error: SIOCGIFFLAGS: %s [ %s ]", strerror(errno), if_name); /* interface is not found. */
		return -3;
	}

	close(fd);

	if (ifr.ifr_flags & IFF_UP) {
		WDP_LOGD("%s interface is up", if_name);
		return 1;
	} else if (!(ifr.ifr_flags & IFF_UP)) {
		WDP_LOGD("%s interface is down", if_name);
		return 0;
	}
	return 0;
}

int ws_init(wfd_oem_event_cb callback, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;

	if (g_pd)
		_ws_reset_plugin(g_pd);

	errno = 0;
	g_pd = (ws_dbus_plugin_data_s*) g_try_malloc0 (sizeof(ws_dbus_plugin_data_s));
	if (!g_pd) {
		WDP_LOGE("Failed to allocate memory for plugin data. [%s]", strerror(errno));
		return -1;
	}

	g_pd->callback = callback;
	g_pd->user_data = user_data;
	g_pd->initialized = TRUE;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_deinit()
{
	__WDP_LOG_FUNC_ENTER__;

	if (g_pd) {
		_ws_reset_plugin(g_pd);
		g_pd = NULL;
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

gboolean _ws_util_execute_file(const char *file_path,
	char *const args[], char *const envs[])
{
	pid_t pid = 0;
	int rv = 0;
	errno = 0;
	register unsigned int index = 0;

	while (args[index] != NULL) {
		WDP_LOGD("[%s]", args[index]);
		index++;
	}

	if (!(pid = fork())) {
		WDP_LOGD("pid(%d), ppid(%d)", getpid(), getppid());
		WDP_LOGD("Inside child, exec (%s) command", file_path);

		errno = 0;
		if (execve(file_path, args, envs) == -1) {
			WDP_LOGE("Fail to execute command (%s)", strerror(errno));
			exit(1);
		}
	} else if (pid > 0) {
		if (waitpid(pid, &rv, 0) == -1)
			WDP_LOGD("wait pid (%u) rv (%d)", pid, rv);
		if (WIFEXITED(rv)) {
			WDP_LOGD("exited, rv=%d", WEXITSTATUS(rv));
		} else if (WIFSIGNALED(rv)) {
			WDP_LOGD("killed by signal %d", WTERMSIG(rv));
		} else if (WIFSTOPPED(rv)) {
			WDP_LOGD("stopped by signal %d", WSTOPSIG(rv));
		} else if (WIFCONTINUED(rv)) {
			WDP_LOGD("continued");
		}

		return TRUE;
	}

	WDP_LOGE("failed to fork (%s)", strerror(errno));
	return FALSE;
}

static int __ws_p2p_firmware_start(void)
{
	GError *error = NULL;
	GVariant *reply = NULL;
	GVariant *param = NULL;
	GDBusConnection *connection = NULL;
	const char *device = "p2p";

	connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (connection == NULL) {
		if(error != NULL){
			WDP_LOGE("Error! Failed to connect to the D-BUS daemon: [%s]",
					error->message);
			g_error_free(error);
		}
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	param = g_variant_new("(s)", device);

	reply = g_dbus_connection_call_sync (connection,
			NETCONFIG_SERVICE, /* bus name */
			NETCONFIG_WIFI_PATH, /* object path */
			NETCONFIG_WIFI_INTERFACE ".Firmware", /* interface name */
			"Start", /* method name */
			param, /* GVariant *params */
			NULL, /* reply_type */
			G_DBUS_CALL_FLAGS_NONE, /* flags */
			NETCONFIG_DBUS_REPLY_TIMEOUT , /* timeout */
			NULL, /* cancellable */
			&error); /* error */

	if(error != NULL){
		if(strstr(error->message, ".AlreadyExists") != NULL) {
			WDP_LOGD("p2p already enabled");
			g_error_free(error);

		} else {
			WDP_LOGE("Error! Failed to call net-config method: [%s]",
					error->message);
			g_error_free(error);
			if(reply)
				 g_variant_unref(reply);
			g_object_unref(connection);
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
	}
	if(reply)
		 g_variant_unref(reply);
	g_object_unref(connection);
	return 0;
}

static int __ws_p2p_firmware_stop(void)
{
	GError *error = NULL;
	GVariant *reply = NULL;
	GVariant *param = NULL;
	GDBusConnection *connection = NULL;
	const char *device = "p2p";

	connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (connection == NULL) {
		if(error != NULL){
			WDP_LOGE("Error! Failed to connect to the D-BUS daemon: [%s]",
					error->message);
			g_error_free(error);
		}
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	param = g_variant_new("(s)", device);

	reply = g_dbus_connection_call_sync (connection,
			NETCONFIG_SERVICE, /* bus name */
			NETCONFIG_WIFI_PATH, /* object path */
			NETCONFIG_WIFI_INTERFACE ".Firmware", /* interface name */
			"Stop", /* method name */
			param, /* GVariant *params */
			NULL, /* reply_type */
			G_DBUS_CALL_FLAGS_NONE, /* flags */
			NETCONFIG_DBUS_REPLY_TIMEOUT , /* timeout */
			NULL, /* cancellable */
			&error); /* error */

	if(error != NULL){
		if(strstr(error->message, ".AlreadyExists") != NULL) {
			WDP_LOGD("p2p already disabled");
			g_error_free(error);

		} else {
			WDP_LOGE("Error! Failed to call net-config method: [%s]",
					error->message);
			g_error_free(error);
			if(reply)
				 g_variant_unref(reply);
			g_object_unref(connection);
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
	}
	if(reply)
		 g_variant_unref(reply);
	g_object_unref(connection);
	return 0;
}


static int __ws_p2p_supplicant_start(void)
{
	gboolean rv = FALSE;
	const char *path = "/usr/sbin/p2p_supp.sh";
	char *const args[] = { "/usr/sbin/p2p_supp.sh", "start_dbus", NULL };
	char *const envs[] = { NULL };

	rv = _ws_util_execute_file(path, args, envs);

	if (rv != TRUE) {
		WDP_LOGE("Failed to start p2p_supp.sh");
		return -1;
	}

	WDP_LOGI("Successfully started p2p_supp.sh");
	return 0;
}


static int __ws_p2p_supplicant_stop(void)
{
	gboolean rv = FALSE;
	const char *path = "/usr/sbin/p2p_supp.sh";
	char *const args[] = { "/usr/sbin/p2p_supp.sh", "stop", NULL };
	char *const envs[] = { NULL };

	rv = _ws_util_execute_file(path, args, envs);

	if (rv != TRUE) {
		WDP_LOGE("Failed to stop p2p_supp.sh");
		return -1;
	}

	WDP_LOGI("Successfully stopped p2p_supp.sh");
	return 0;
}
#if 0
static int __ws_p2p_on(void)
{
	DBusError error;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		WDP_LOGE("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE, "LoadP2pDriver");
	if (message == NULL) {
		WDP_LOGE("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);
	if (dbus_error_is_set(&error) == TRUE) {
		if (NULL != strstr(error.message, ".AlreadyExists")) {
			// p2p already enabled
		} else {
			WDP_LOGE("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
		}

		dbus_error_free(&error);
	}

	if (reply != NULL)
		dbus_message_unref(reply);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return 0;
}

static int __ws_p2p_off(void)
{
	DBusError error;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		WDP_LOGE("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE, "RemoveP2pDriver");
	if (message == NULL) {
		WDP_LOGE("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);
	if (dbus_error_is_set(&error) == TRUE) {
		if (NULL != strstr(error.message, ".AlreadyExists")) {
			// p2p already disabled
		} else {
			WDP_LOGE("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
		}

		dbus_error_free(&error);
	}

	if (reply != NULL)
		dbus_message_unref(reply);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return 0;
}
#endif

int __ws_init_p2pdevice()
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;

	GVariant *value = NULL;
	GVariant *param = NULL;
	GVariantBuilder *builder = NULL;
	GVariantBuilder *type_builder = NULL;
	dbus_method_param_s params;

	const char *primary_device_type = PRIMARY_DEVICE_TYPE;
	const char *ip_addr_go = DEFAULT_IP_GO;
	const char *ip_addr_mask = DEFAULT_IP_MASK;
	const char *ip_addr_start = DEFAULT_IP_START;
	const char *ip_addr_end = DEFAULT_IP_END;
	int i = 0;
	int res = 0;

	for(i = 0; i < WS_DEVTYPE_LEN; i++)
		WDP_LOGD("device type[%02x]", primary_device_type[i]);

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, DBUS_PROPERTIES_METHOD_SET, g_pd->iface_path,
			 g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (builder, "{sv}", "DeviceName",
					g_variant_new_string(DEFAULT_DEVICE_NAME));

	g_variant_builder_add (builder, "{sv}", "GOIntent",
					g_variant_new_uint32(DEFAULT_GO_INTENT));

	g_variant_builder_add (builder, "{sv}", "PersistentReconnect",
					g_variant_new_boolean(DEFAULT_PERSISTENT_RECONNECT));

	g_variant_builder_add (builder, "{sv}", "ListenRegClass",
					g_variant_new_uint32(DEFAULT_LISTEN_REG_CLASS));

	g_variant_builder_add (builder, "{sv}", "ListenChannel",
					g_variant_new_uint32(DEFAULT_LISTEN_CHANNEL));

	g_variant_builder_add (builder, "{sv}", "OperRegClass",
					g_variant_new_uint32(DEFAULT_OPER_REG_CLASS));

	g_variant_builder_add (builder, "{sv}", "OperChannel",
					g_variant_new_uint32(DEFAULT_OPER_CHANNEL));

	g_variant_builder_add (builder, "{sv}", "SsidPostfix",
					g_variant_new_string(DEFAULT_DEVICE_NAME));

	g_variant_builder_add (builder, "{sv}", "NoGroupIface",
					g_variant_new_boolean(DEFAULT_NO_GROUP_IFACE));

	type_builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
	for(i = 0; i < WS_DEVTYPE_LEN; i++)
		g_variant_builder_add(type_builder, "y", primary_device_type[i]);
	g_variant_builder_add (builder, "{sv}", "PrimaryDeviceType",
			g_variant_new ("ay", type_builder));
	g_variant_builder_unref (type_builder);

	type_builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
	for(i = 0; i < OEM_IPADDR_LEN; i++)
		g_variant_builder_add(type_builder, "y", ip_addr_go[i]);
	g_variant_builder_add (builder, "{sv}", "IpAddrGO",
			g_variant_new ("ay", type_builder));
	g_variant_builder_unref (type_builder);

	type_builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
	for(i = 0; i < OEM_IPADDR_LEN; i++)
		g_variant_builder_add(type_builder, "y", ip_addr_mask[i]);
	g_variant_builder_add (builder, "{sv}", "IpAddrMask",
			g_variant_new ("ay", type_builder));
	g_variant_builder_unref (type_builder);

	type_builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
	for(i = 0; i < OEM_IPADDR_LEN; i++)
		g_variant_builder_add(type_builder, "y", ip_addr_start[i]);
	g_variant_builder_add (builder, "{sv}", "IpAddrStart",
			g_variant_new ("ay", type_builder));
	g_variant_builder_unref (type_builder);

	type_builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
	for(i = 0; i < OEM_IPADDR_LEN; i++)
		g_variant_builder_add(type_builder, "y", ip_addr_end[i]);
	g_variant_builder_add (builder, "{sv}", "IpAddrEnd",
			g_variant_new ("ay", type_builder));
	g_variant_builder_unref (type_builder);

	value = g_variant_new ("a{sv}", builder);
	g_variant_builder_unref (builder);

	param = g_variant_new("(ssv)", SUPPLICANT_P2PDEVICE, "P2PDeviceConfig", value);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("init param [%s]", g_variant_print(param, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = param;

	res = dbus_method_call(&params, DBUS_PROPERTIES_INTERFACE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGE("Succeeded to initialize p2pdevice");
	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int __ws_set_config_methods()
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;

	GVariant *value = NULL;
	GVariant *param = NULL;

	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, DBUS_PROPERTIES_METHOD_SET, g_pd->iface_path,
			 g_dbus);

	value = g_variant_new_string(DEFAULT_CONFIG_METHOD);

	param = g_variant_new("(ssv)", SUPPLICANT_WPS, "ConfigMethods", value);
	params.params = param;

	res = dbus_method_call(&params, DBUS_PROPERTIES_INTERFACE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to set config method(%s)", DEFAULT_CONFIG_METHOD);

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_activate(int concurrent)
{
	__WDP_LOG_FUNC_ENTER__;
	int res = 0;
	int retry_count = 0;

	res = __ws_p2p_supplicant_start();
	if (res < 0) {
		res = __ws_p2p_supplicant_stop();
		WDP_LOGI("P2P supplicant stopped with error %d", res);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	while (retry_count < WS_CONN_RETRY_COUNT) {
		/* load wlan driver */
		if(concurrent == 0)
			res = __ws_p2p_firmware_start();
		if (res < 0) {
			WDP_LOGE("Failed to load driver [ret=%d]", res);
			return -1;
		}
		WDP_LOGI("P2P firmware started with error %d", res);

		if (__ws_check_net_interface(COMMON_IFACE_NAME) < 0) {
			usleep(150000); // wait for 150ms
			concurrent = 0;
			retry_count++;
			WDP_LOGE("interface is not up: retry, %d", retry_count);
		} else {
			break;
		}
	}

	if (retry_count >= WS_CONN_RETRY_COUNT) {
		WDP_LOGE("Driver loading is failed", res);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	if (retry_count > 0) {
		// Give driver marginal time to config net
		WDP_LOGE("Driver loading is done. Wait marginal time for driver");
		sleep(1); // 1s
	}

	g_pd->concurrent = concurrent;

	res = _ws_init_dbus_connection();
	if (res < 0) {
		res = __ws_p2p_supplicant_stop();
		WDP_LOGI("[/usr/sbin/p2p_supp.sh stop] returns %d", res);
		res = __ws_p2p_firmware_stop();
		WDP_LOGI("P2P firmware stopped with error %d", res);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	g_pd->activated = TRUE;
	__ws_init_p2pdevice();
	__ws_set_config_methods();

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_deactivate(int concurrent)
{
	__WDP_LOG_FUNC_ENTER__;
	int res = 0;

	if (!g_pd->activated) {
		WDP_LOGE("Wi-Fi Direct is not activated");
		return -1;
	}

	ws_stop_scan();

	g_pd->concurrent = concurrent;
#if defined (TIZEN_MOBILE) && (TIZEN_WLAN_BOARD_SPRD)
	_ws_get_interface(P2P_IFACE_NAME, __ws_remove_interface, NULL);
	if(concurrent == 0)
		_ws_get_interface(COMMON_IFACE_NAME, __ws_remove_interface, NULL);
#endif /* (TIZEN_MOBILE) && (TIZEN_WLAN_BOARD_SPRD) */

	_ws_deinit_dbus_connection();

	if(concurrent == 0) {
		res = __ws_p2p_supplicant_stop();
		WDP_LOGI("[/usr/sbin/p2p_supp.sh stop] returns %d", res);

		res = __ws_p2p_firmware_stop();
		WDP_LOGI("P2P firmware stopped with error %d", res);
	}
	g_pd->activated = FALSE;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static int _ws_flush()
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "Flush", g_pd->iface_path, g_dbus);
	params.params = NULL;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to flush");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static int _ws_cancel()
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "Cancel", g_pd->iface_path , g_dbus);
	params.params = NULL;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to cancel");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

#if 0
static gboolean _retry_start_scan(gpointer data)
{
	__WDP_LOG_FUNC_ENTER__;

	WDP_LOGD("Succeeded to start scan");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}
#endif

int ws_start_scan(wfd_oem_scan_param_s *param)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	int res = 0;

	if (!param) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	if (param->scan_mode == WFD_OEM_SCAN_MODE_ACTIVE) {

		dbus_set_method_param(&params, "Find",  g_pd->iface_path, g_dbus);

		builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}") );

			if (param->scan_time)
				g_variant_builder_add (builder, "{sv}", "Timeout",
							g_variant_new_int32(param->scan_time));
			if (param->scan_type == WFD_OEM_SCAN_TYPE_SOCIAL)
				g_variant_builder_add (builder, "{sv}", "DiscoveryType",
							g_variant_new_string("social"));

			value = g_variant_new ("(a{sv})", builder);
			g_variant_builder_unref (builder);
	} else {

		dbus_set_method_param(&params, "Listen", g_pd->iface_path, g_dbus);
		value = g_variant_new ("(i)", param->scan_time);
	}

	params.params = value;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to start scan");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_restart_scan(int freq)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "Find", g_pd->iface_path, g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}") );
	g_variant_builder_add (builder, "{sv}", "Timeout", g_variant_new_int32(2));
	g_variant_builder_add (builder, "{sv}", "DiscoveryType",
				g_variant_new_string("social"));
	value = g_variant_new ("(a{sv})", builder);
	g_variant_builder_unref (builder);

	params.params = value;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to start scan");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_stop_scan()
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "StopFind", g_pd->iface_path, g_dbus);
	params.params = NULL;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
			WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to stop scan");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_get_visibility(int *visibility)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_visibility(int visibility)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_scan_result(GList **peers, int *peer_count)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_peer_info(unsigned char *peer_addr, wfd_oem_device_s **peer)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	wfd_oem_device_s *ws_dev = NULL;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	int res = 0;

	if (!peer_addr || !peer) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}

	ws_dev = (wfd_oem_device_s *) g_try_malloc0(sizeof(wfd_oem_device_s));
	if (!ws_dev) {
		WDP_LOGF("Failed to allocate memory device. [%s]",
				strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	g_snprintf(peer_path, DBUS_OBJECT_PATH_MAX, "%s/Peers/"
			COMPACT_MACSTR, g_pd->iface_path, MAC2STR(peer_addr));

	WDP_LOGD("get peer path [%s]", peer_path);

	res = dbus_property_get_all(peer_path, g_dbus, SUPPLICANT_P2P_PEER,
				__ws_get_peer_property, ws_dev);

	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			g_free(ws_dev);
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	} else {
		WDP_LOGD("succeeded to get peer info");
		*peer = ws_dev;
	}
	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_prov_disc_req(unsigned char *peer_addr, wfd_oem_wps_mode_e wps_mode, int join)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	int res = 0;

	if (!peer_addr) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "ProvisionDiscoveryRequest", g_pd->iface_path, g_dbus);

	g_snprintf(peer_path, DBUS_OBJECT_PATH_MAX, "%s/Peers/"
			COMPACT_MACSTR, g_pd->iface_path, MAC2STR(peer_addr));
	WDP_LOGD("get peer path [%s]", peer_path);

	value = g_variant_new ("(os)", peer_path, __ws_wps_to_txt(wps_mode));
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = value;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to send prov disc to peer[" MACSTR "]", MAC2STR(peer_addr));

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_connect(unsigned char *peer_addr, wfd_oem_conn_param_s *param)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	int res = 0;

	if (!peer_addr || !param) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "Connect", g_pd->iface_path, g_dbus);

	g_snprintf(peer_path, DBUS_OBJECT_PATH_MAX, "%s/Peers/"
			COMPACT_MACSTR, g_pd->iface_path, MAC2STR(peer_addr));
	WDP_LOGD("get peer path [%s]", peer_path);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}") );
	g_variant_builder_add (builder, "{sv}", "peer", g_variant_new_object_path(peer_path));
	if (param->conn_flags & WFD_OEM_CONN_TYPE_PERSISTENT)
		g_variant_builder_add (builder, "{sv}", "persistent", g_variant_new_boolean(TRUE));

	if (param->conn_flags & WFD_OEM_CONN_TYPE_JOIN)
		g_variant_builder_add (builder, "{sv}", "join", g_variant_new_boolean(TRUE));

	if (param->conn_flags& WFD_OEM_CONN_TYPE_AUTH)
		g_variant_builder_add (builder, "{sv}", "autorize_only", g_variant_new_boolean(TRUE));

	if (param->wps_pin[0] != '\0')
		g_variant_builder_add (builder, "{sv}", "pin", g_variant_new_string(param->wps_pin));

	g_variant_builder_add (builder, "{sv}", "wps_method",
				g_variant_new_string(__ws_wps_to_txt(param->wps_mode)));

	value = g_variant_new ("(a{sv})", builder);
	g_variant_builder_unref (builder);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = value;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to send connection command to peer[" MACSTR "]", MAC2STR(peer_addr));

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_disconnect(unsigned char *peer_addr)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	int res = 0;

	if (!peer_addr) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "RemoveClient", g_pd->iface_path ,g_dbus);

	g_snprintf(peer_path, DBUS_OBJECT_PATH_MAX, "%s/Peers/"
			COMPACT_MACSTR, g_pd->iface_path, MAC2STR(peer_addr));
	WDP_LOGE("get peer path [%s]", peer_path);

	value = g_variant_new ("(oi)", peer_path, 0);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = value;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to stop scan");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_reject_connection(unsigned char *peer_addr)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	int res = 0;

	if (!peer_addr) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "RejectPeer", g_pd->iface_path ,g_dbus);

	g_snprintf(peer_path, DBUS_OBJECT_PATH_MAX, "%s/Peers/"
			COMPACT_MACSTR, g_pd->iface_path, MAC2STR(peer_addr));
	WDP_LOGE("get peer path [%s]", peer_path);

	value = g_variant_new ("(o)", peer_path);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = value;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to reject peer[" MACSTR "]", MAC2STR(peer_addr));

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_cancel_connection(unsigned char *peer_addr)
{
	__WDP_LOG_FUNC_ENTER__;

	_ws_cancel();

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_connected_peers(GList **peers, int *peer_count)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_pin(char *pin)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_pin(char *pin)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static void __ws_get_pin(GVariant *value, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;
	const char *pin = NULL;

	g_variant_get(value, "(s)", &pin);
	g_strlcpy((char *)user_data, pin, OEM_PINSTR_LEN + 1);

	__WDP_LOG_FUNC_EXIT__;
	return;
}

int ws_generate_pin(char **pin)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	dbus_method_param_s params;
	char n_pin[9] = {0,};
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "GeneratePin", g_pd->iface_path ,g_dbus);
	params.params = NULL;

	res = dbus_method_call(&params, SUPPLICANT_WPS, __ws_get_pin, (void *)n_pin);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to generate_pin [ %s ]", n_pin);

	*pin = strndup(n_pin, OEM_PINSTR_LEN);
	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_supported_wps_mode()
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static void __store_group_iface_path(GVariant *value, void *user_data) {
	__WDP_LOG_FUNC_ENTER__;
	ws_dbus_plugin_data_s * pd_data;
	const char *path = NULL;

	pd_data = (ws_dbus_plugin_data_s *) g_pd;

	g_variant_get(value, "(o)", &path);
	g_strlcpy(pd_data->group_iface_path, path, DBUS_OBJECT_PATH_MAX);

	WDP_LOGD("group object path [%s]", pd_data->group_iface_path);
	/* subscribe interface p2p signal */
}

int ws_create_group(int persistent, int freq, const char *passphrase)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "GroupAdd", g_pd->iface_path, g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}") );

	if (persistent)
		g_variant_builder_add(builder, "{sv}", "persistent",
				g_variant_new_boolean(TRUE));
	else
		g_variant_builder_add(builder, "{sv}", "persistent",
				g_variant_new_boolean(FALSE));

	if (passphrase && strlen(passphrase) > 0)
		g_variant_builder_add(builder, "{sv}", "passphrase",
				g_variant_new_string(passphrase));

	if (freq)
		g_variant_builder_add(builder, "{sv}", "frequency",
				g_variant_new_int32(freq));

	value = g_variant_new ("(a{sv})", builder);
	g_variant_builder_unref (builder);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	params.params = value;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE,
			__store_group_iface_path, g_pd);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to add group");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_destroy_group(const char *ifname)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	dbus_method_param_s params;
	int res = 0;

	if (!ifname) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}

	if (g_pd->group_iface_path[0] == 0) {
		WDP_LOGE("group iface path is NULL");
		return -1;
	}

	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "Disconnect", g_pd->group_iface_path, g_dbus);
	params.params = NULL;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	} else {
		_ws_flush();
		WDP_LOGD("Succeeded to remove group");
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_invite(unsigned char *peer_addr, wfd_oem_invite_param_s *param)
{
	__WDP_LOG_FUNC_ENTER__;
		GDBusConnection *g_dbus = NULL;
		GVariantBuilder *builder = NULL;
		GVariant *value = NULL;
		dbus_method_param_s params;
		static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
		int res = 0;

		if (!peer_addr || !param) {
			WDP_LOGE("Invalid parameter");
			return -1;
		}
		g_dbus = g_pd->g_dbus;
		if (!g_dbus) {
			WDP_LOGE("DBus connection is NULL");
			return -1;
		}
		memset(&params, 0x0, sizeof(dbus_method_param_s));

		dbus_set_method_param(&params, "Invite", g_pd->group_iface_path, g_dbus);

		g_snprintf(peer_path, DBUS_OBJECT_PATH_MAX, "%s/Peers/"
				COMPACT_MACSTR, g_pd->iface_path, MAC2STR(peer_addr));
		WDP_LOGE("get peer path [%s]", peer_path);

		builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}") );
		g_variant_builder_add (builder, "{sv}", "peer", g_variant_new_object_path(peer_path));
		value = g_variant_new ("(a{sv})", builder);
		g_variant_builder_unref (builder);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
		WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */
		params.params = value;

		res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
		if (res < 0)
			WDP_LOGE("Failed to send command to wpa_supplicant");
		else
			WDP_LOGD("Succeeded to invite peer[" MACSTR "]", MAC2STR(peer_addr));

		__WDP_LOG_FUNC_EXIT__;
		return 0;
}

// Only group owner can use this command
int ws_wps_start(unsigned char *peer_addr, int wps_mode, const char *pin)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;
	GVariant *dev_addr = NULL;
	dbus_method_param_s params;
	int i = 0;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}

	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "Start", g_pd->group_iface_path, g_dbus);

	if (peer_addr != NULL) {
		builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
		for(i = 0; i < WS_MACADDR_LEN; i++)
			g_variant_builder_add(builder, "y", peer_addr[i]);

		dev_addr = g_variant_new ("ay", builder);
		g_variant_builder_unref (builder);
	}

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}") );
	g_variant_builder_add (builder, "{sv}", "Role", g_variant_new_string("enrollee"));
	if (peer_addr != NULL)
		g_variant_builder_add (builder, "{sv}", "P2PDeviceAddress", dev_addr);

	if (pin != NULL && pin[0] != '\0') {
		g_variant_builder_add (builder, "{sv}", "Type", g_variant_new_string("pin"));
		g_variant_builder_add (builder, "{sv}", "Pin", g_variant_new_string(pin));
	} else {
		g_variant_builder_add (builder, "{sv}", "Type", g_variant_new_string("pbc"));
	}

	value = g_variant_new ("(a{sv})", builder);
	g_variant_builder_unref (builder);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	params.params = value;

	res = dbus_method_call(&params, SUPPLICANT_WPS, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to run wps");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_enrollee_start(unsigned char *peer_addr, int wps_mode, const char *pin)
{
	__WDP_LOG_FUNC_ENTER__;

	WDP_LOGD("Succeeded to start WPS");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_wps_cancel()
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "Cancel", g_pd->group_iface_path, g_dbus);
	params.params = NULL;

	res = dbus_method_call(&params, SUPPLICANT_WPS, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to cancel WPS");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_dev_name(char *dev_name)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_dev_name(char *dev_name)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;

	GVariant *value = NULL;
	GVariant *param = NULL;
	GVariantBuilder *builder = NULL;
	dbus_method_param_s params;
	int res = 0;

	if (!dev_name) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, DBUS_PROPERTIES_METHOD_SET, g_pd->iface_path,
			 g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (builder, "{sv}", "DeviceName",
				g_variant_new_string(dev_name));
	g_variant_builder_add (builder, "{sv}", "SsidPostfix",
				 g_variant_new_string(dev_name));
	value = g_variant_new ("a{sv}", builder);
	g_variant_builder_unref (builder);

	param = g_variant_new("(ssv)", SUPPLICANT_P2PDEVICE,
				"P2PDeviceConfig", value);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(param, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = param;

	res = dbus_method_call(&params, DBUS_PROPERTIES_INTERFACE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to set device name");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_get_dev_mac(char *dev_mac)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_dev_type(int *pri_dev_type, int *sec_dev_type)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_dev_type(int pri_dev_type, int sec_dev_type)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_go_intent(int *go_intent)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariant *param = NULL;
	GVariant *reply = NULL;
	GError *error = NULL;
	GVariantIter *iter = NULL;


	if (!go_intent) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}

	param = g_variant_new("(ss)", SUPPLICANT_P2PDEVICE, "P2PDeviceConfig");
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(param, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	reply = g_dbus_connection_call_sync (
			g_dbus,
			SUPPLICANT_SERVICE, /* bus name */
			g_pd->iface_path, /* object path */
			DBUS_PROPERTIES_INTERFACE, /* interface name */
			DBUS_PROPERTIES_METHOD_GET, /* method name */
			param, /* GVariant *params */
			NULL, /* reply_type */
			G_DBUS_CALL_FLAGS_NONE, /* flags */
			SUPPLICANT_TIMEOUT , /* timeout */
			NULL, /* cancellable */
			&error); /* error */

	if(error != NULL) {
		WDP_LOGE("Error! Failed to get interface State: [%s]",
				error->message);
		g_error_free(error);
		if(reply)
			g_variant_unref(reply);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if(reply != NULL){
		g_variant_get(reply, "(a{sv})", &iter);

		if(iter != NULL){

			gchar *key = NULL;
			GVariant *value = NULL;

			while(g_variant_iter_loop(iter, "{sv}", &key, &value)) {
#if defined (TIZEN_DEBUG_DBUS_VALUE)
				CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
				if(g_strcmp0(key, "GOIntent") == 0)
					g_variant_get(value, "u", go_intent);
			}
			g_variant_iter_free(iter);
		}
		g_variant_unref(reply);
	}
	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_go_intent(int go_intent)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;

	GVariant *value = NULL;
	GVariant *param = NULL;
	GVariantBuilder *builder = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, DBUS_PROPERTIES_METHOD_SET, g_pd->iface_path,
			 g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (builder, "{sv}", "GOIntent",
				g_variant_new_uint32(go_intent));
	value = g_variant_new ("a{sv}", builder);
	g_variant_builder_unref (builder);

	param = g_variant_new("(ssv)", SUPPLICANT_P2PDEVICE, "P2PDeviceConfig", value);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("param [%s]", g_variant_print(param, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = param;

	res = dbus_method_call(&params, DBUS_PROPERTIES_INTERFACE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGE("Succeeded to set go intent");
	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_set_country(char *ccode)
{
	__WDP_LOG_FUNC_ENTER__;
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;

	GVariant *value = NULL;
	GVariant *param = NULL;

	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, DBUS_PROPERTIES_METHOD_SET, g_pd->iface_path,
			 g_dbus);

	value = g_variant_new_string(ccode);

	param = g_variant_new("(ssv)", SUPPLICANT_IFACE, "Country", value);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("param [%s]", g_variant_print(param, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = param;

	res = dbus_method_call(&params, DBUS_PROPERTIES_INTERFACE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to set country(%s)", ccode);

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int _parsing_networks(char* buf, ws_network_info_s networks[], int *network_cnt)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

void __parsing_networks (const char *key, GVariant *value, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;
	if(!user_data) {
		__WDP_LOG_FUNC_EXIT__;
		return;
	}

	ws_network_info_s *network = (ws_network_info_s *)user_data;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "ssid") == 0) {
		const char *ssid = NULL;
		g_variant_get(value, "s", &ssid);
		WDP_LOGD("ssid [%s]", ssid);
		g_strlcpy(network->ssid, ssid + 1, WS_SSID_LEN + 1);
		network->ssid[strlen(ssid) - 2] = '\0';

	} else if (g_strcmp0(key, "bssid") == 0) {
		unsigned char *bssid = NULL;
		g_variant_get(value, "s", &bssid);
		WDP_LOGD("bssid [%s]", bssid);
		__ws_txt_to_mac(bssid, network->bssid);

	} else if (g_strcmp0(key, "mode") == 0) {

	}
	return;
}

void __ws_extract_p2pdevice_details(const char *key, GVariant *value, void *user_data)
{

	__WDP_LOG_FUNC_ENTER__;
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	CHECK_KEY_VALUE(key, value);
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	if (g_strcmp0(key, "PersistentGroups") == 0) {
		GVariantIter *iter = NULL;
		const char *path = NULL;
		int num = 0;

		ws_network_info_s *networks = NULL;
		networks = (ws_network_info_s *)user_data;
		if(!networks) {
			WDP_LOGE("network is NULL");
			__WDP_LOG_FUNC_EXIT__;
			return;
		}

		g_variant_get(value, "ao", &iter);
		while(g_variant_iter_loop(iter, "o", &path)) {
			if(num >= WS_MAX_PERSISTENT_COUNT)
				break;
			WDP_LOGD("Retrive persistent path [%s]", path);
			g_strlcpy(networks[num].persistent_path, path, DBUS_OBJECT_PATH_MAX);
			WDP_LOGD("Retrive persistent path [%s]", networks[num].persistent_path);
			dbus_property_get_all(networks[num].persistent_path, g_pd->g_dbus,
					SUPPLICANT_P2P_PERSISTENTGROUP, __parsing_networks, &networks[num]);
			num++;
		}
		networks[0].total = num;
		WDP_LOGE("total number [%d]", num);

	}
	__WDP_LOG_FUNC_EXIT__;
}


int ws_get_persistent_groups(wfd_oem_persistent_group_s **groups, int *group_count)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;

	ws_network_info_s networks[WS_MAX_PERSISTENT_COUNT];
	wfd_oem_persistent_group_s *wfd_persistent_groups = NULL;
	int i, cnt = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	dbus_property_get_all(g_pd->iface_path, g_dbus, SUPPLICANT_P2PDEVICE, __ws_extract_p2pdevice_details, &networks[0]);

	cnt = networks[0].total;

	WDP_LOGD("Persistent Group Count=%d", cnt);
	if (cnt > WS_MAX_PERSISTENT_COUNT) {
		WDP_LOGE("Persistent group count exceeded or parsing error");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if(cnt == 0) {
		WDP_LOGE("Persistent group count zero");
		*group_count = 0;
		*groups = NULL;
		__WDP_LOG_FUNC_EXIT__;
		return 0;
	}

	wfd_persistent_groups = (wfd_oem_persistent_group_s*) g_try_malloc0(cnt * sizeof(wfd_oem_persistent_group_s));
	if (wfd_persistent_groups == NULL) {
		WDP_LOGE("Failed to allocate memory for wfd_persistent_groups ");
		return -1;
	}

	for(i = 0; i < cnt; i++) {
		WDP_LOGD("----persistent group [%d]----", i);
		WDP_LOGD("network_id=%d", networks[i].network_id);
		WDP_LOGD("ssid=%s", networks[i].ssid);
		WDP_LOGD("bssid=" MACSTR, MAC2STR(networks[i].bssid));

		wfd_persistent_groups[i].network_id = networks[i].network_id;
		g_strlcpy(wfd_persistent_groups[i].ssid, networks[i].ssid, WS_SSID_LEN + 1);
		memcpy(wfd_persistent_groups[i].go_mac_address, networks[i].bssid, WS_MACADDR_LEN);
	}

	*group_count = cnt;
	*groups = wfd_persistent_groups;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_remove_persistent_group(char *ssid, unsigned char *bssid)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;

	dbus_method_param_s params;
	ws_network_info_s networks[WS_MAX_PERSISTENT_COUNT];
	int i, cnt = 0;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	dbus_property_get_all(g_pd->iface_path, g_dbus, SUPPLICANT_P2PDEVICE, __ws_extract_p2pdevice_details, networks);

	cnt = networks[0].total;

	WDP_LOGD("Persistent Group Count=%d", cnt);
	if (cnt > WS_MAX_PERSISTENT_COUNT) {
		WDP_LOGE("Persistent group count exceeded or parsing error");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	for(i=0;i<cnt;i++) {
		WDP_LOGD("----persistent group [%d]----", i);
		WDP_LOGD("network_id=%d", networks[i].network_id);
		WDP_LOGD("network ssid=%s", networks[i].ssid);
		WDP_LOGD("network bssid=" MACSTR, MAC2STR(networks[i].bssid));

		WDP_LOGD("ssid=%s", ssid);
		WDP_LOGD("bssid=" MACSTR, MAC2STR(bssid));


		if (!memcmp(bssid, networks[i].bssid, WS_MACADDR_LEN) &&
				!strcmp(ssid, networks[i].ssid)) {

			WDP_LOGD("Persistent group found [%d: %s]", networks[i].network_id, ssid);

			memset(&params, 0x0, sizeof(dbus_method_param_s));
			dbus_set_method_param(&params, "RemovePersistentGroup",
					g_pd->iface_path, g_dbus);
			params.params = g_variant_new ("(o)", networks[i].persistent_path);

			WDP_LOGD("params [%s]", g_variant_print(params.params, TRUE));
			res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
			if (res < 0) {
				WDP_LOGE("Failed to send command to wpa_supplicant");
				__WDP_LOG_FUNC_EXIT__;
				return -1;
			}
			WDP_LOGD("Succeeded to remove persistent group");;
			break;
		}
	}

	if (i == cnt) {
		WDP_LOGE("Persistent group not found [%s]", ssid);
		return -1;
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_persistent_reconnect(unsigned char *bssid, int reconnect)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;

	GVariant *value = NULL;
	GVariant *param = NULL;
	GVariantBuilder *builder = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, DBUS_PROPERTIES_METHOD_SET, g_pd->iface_path,
			g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (builder, "{sv}", "PersistentReconnect",
				g_variant_new_boolean(reconnect));
	value = g_variant_new ("a{sv}", builder);
	g_variant_builder_unref (builder);

	param = g_variant_new("(ssv)", SUPPLICANT_P2PDEVICE, "P2PDeviceConfig", value);
	WDP_LOGE("param [%s]", g_variant_print(param,TRUE));

	params.params = param;

	res = dbus_method_call(&params, DBUS_PROPERTIES_INTERFACE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to set persistent reconnect");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
static int __ws_compress_query(char *compressed, char *query, int qtype)
{
	char *token = NULL;
	char *temp = NULL;
	int token_num = 0;
	int token_len = 0;
	int length = 0;

	token = strtok_r(query, ".", &temp);
	while (token) {
		if (!strcmp(token, "local")) {
			WDP_LOGD("Query conversion done");
			break;

		} else if (!strncmp(token, "_tcp", 4)) {
			memcpy(&compressed[length], WS_TCP_PTR_HEX, 2);
			length+=2;

		} else if (!strncmp(token, "_udp", 4)) {
			memcpy(&compressed[length], WS_UDP_PTR_HEX, 2);
			length+=2;

		} else {
			WDP_LOGD("Token: [%s]", token);
			token_len = strlen(token);
			compressed[length] = token_len;
			length++;

			memcpy(&compressed[length], token, token_len);
			length+=token_len;
		}
		token_num++;
		token = strtok_r(NULL, ".", &temp);
	}
	if(qtype == WS_QTYPE_PTR || token_num == 2) {
		memcpy(&compressed[length], WS_PTR_TYPE_HEX, 3);
	} else if (qtype == WS_QTYPE_TXT || token_num == 3) {
		memcpy(&compressed[length], WS_TXT_TYPE_HEX, 3);
	}
	length+=3;
	WDP_LOGD("converted query length [%d] token num [%d]", length, token_num);

	return length;
}

static int __ws_compress_rdata(char *compressed, char *rdata, int qtype)
{
	char *token = NULL;
	char *temp = NULL;
	int token_len = 0;
	int length = 0;

	if (qtype == WS_QTYPE_PTR) {

		token = strtok_r(rdata, ".", &temp);
		if (token) {
			WDP_LOGD("Token: %s", token);
			token_len = strlen(token);
			compressed[length] = token_len;
			length++;

			memcpy(&compressed[length], token, token_len);
			length+=token_len;
		}

		compressed[length] = 0xc0;
		compressed[length+1] = 0x27;
		length+=2;

	} else if (qtype == WS_QTYPE_TXT) {

		token = strtok_r(rdata, ",", &temp);

		while (token) {
			WDP_LOGD("Token: [%s]", token);

			token_len = strlen(token);
			compressed[length] = token_len;
			length++;

			memcpy(&compressed[length], token, token_len);
			length+=token_len;

			token = strtok_r(NULL, ",", &temp);
		}
	} else {
		WDP_LOGD("RDATA is NULL");
	}
	return length;
}

int _convert_bonjour_to_args(char *query, char *rdata, GVariantBuilder *builder)
{
	GVariantBuilder *args = NULL;
	char compressed[256] = {0, };
	char *temp = NULL;
	int length = 0;
	int qtype = 0;
	int i = 0;

	if (!query || !builder) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	if (!rdata || !strlen(rdata)) {
		WDP_LOGD("RDATA is NULL\n");
	} else {
		temp = strstr(rdata, query);

		if(temp != NULL && temp - rdata > 0)
			qtype = WS_QTYPE_PTR;
		else
			qtype = WS_QTYPE_TXT;
		temp = NULL;
	}

	/* compress query */
	length = __ws_compress_query(compressed, query, qtype);

	args = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
	for (i = 0; i < length; i++)
		g_variant_builder_add(args, "y", compressed[i]);
	g_variant_builder_add (builder, "{sv}", "query", g_variant_new ("ay", args));
	g_variant_builder_unref (args);

	memset(compressed, 0x0, 256);
	length = 0;
	args = NULL;

	if(qtype != 0) {
		length = __ws_compress_rdata(compressed, rdata, qtype);

		args = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
		for (i = 0; i < length; i++)
			g_variant_builder_add(args, "y", compressed[i]);
		g_variant_builder_add (builder, "{sv}", "response", g_variant_new ("ay", args));
		g_variant_builder_unref (args);
	}

	return 0;
}

int _check_service_query_exists(wfd_oem_service_s *service)
{
	int count = 0;
	wfd_oem_service_s *data = NULL;

	for (count = 0; count < g_list_length(service_list); count ++) {
		data = (wfd_oem_service_s*) g_list_nth_data(service_list, count);
		if (strncmp(service->query_id, data->query_id, OEM_QUERY_ID_LEN) == 0) {
			WDP_LOGD("Query already exists");
			return 1;
		}
	}
	return 0;
}

static wfd_oem_service_s* _remove_service_query(char * s_type, char *mac_str, char *query_id)
{
	if (NULL == s_type || NULL == mac_str || NULL == query_id)
		return NULL;

	int count = 0;
	wfd_oem_service_s *data = NULL;

	for (count = 0; count < g_list_length(service_list); count ++) {
		data = (wfd_oem_service_s*) g_list_nth_data(service_list, count);
		if (data && !strncmp(data->service_type, s_type, SERVICE_TYPE_LEN) &&
				memcmp(data->dev_addr, mac_str, OEM_MACSTR_LEN - 1) == 0) {
			strncpy(query_id, data->query_id, OEM_QUERY_ID_LEN);
			break;
		}
	}
	if (strlen(query_id) <= 0) {
		WDP_LOGD("!! Query ID not found !!");
		return NULL;
	}

	WDP_LOGD("query id :[0x%s]",query_id);

	return data;
}

void __add_service_query(GVariant *value, void *mac_addr)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_service_s *service = NULL;

	long long unsigned ref = 0;
	unsigned char *mac_address = (unsigned char *)mac_addr;
	char mac_str[18] = {0, };

	int res = 0;

	g_variant_get(value, "(t)", &ref);

	service = (wfd_oem_service_s*) g_try_malloc0(sizeof(wfd_oem_service_s));
	if (!service) {
		WDP_LOGE("Failed to allocate memory for service");
		return;
	}

	if (mac_address[0] == 0 && mac_address[1] == 0 && mac_address[2] == 0 &&
			mac_address[3] == 0 && mac_address[4] == 0 && mac_address[5] == 0) {
		g_snprintf(mac_str, WS_MACSTR_LEN , "%s", SERV_BROADCAST_ADDRESS);
	} else {
		g_snprintf(mac_str, WS_MACSTR_LEN, MACSTR, MAC2STR(mac_address));
	}

	g_strlcpy(service->dev_addr, mac_str, OEM_MACSTR_LEN);
	g_snprintf(service->query_id, OEM_QUERY_ID_LEN + 1, "0x%llx", ref);

	res = _check_service_query_exists(service);
	if(res) {
		free(service);
	} else {
		service_list = g_list_append(service_list, service);
	}

	__WDP_LOG_FUNC_EXIT__;
	return;

}

/* for now, supplicant dbus interface only provides upnp service fully */
int ws_start_service_discovery(unsigned char *mac_addr, int service_type)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	static char peer_path[DBUS_OBJECT_PATH_MAX] = {'\0',};
	int i = 0;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "ServiceDiscoveryRequest", g_pd->iface_path, g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}") );

	if(mac_addr) {
		g_snprintf(peer_path, DBUS_OBJECT_PATH_MAX, "%s/Peers/"
				COMPACT_MACSTR, g_pd->iface_path, MAC2STR(mac_addr));
		WDP_LOGD("get peer path [%s]", peer_path);
		g_variant_builder_add (builder, "{sv}", "peer", g_variant_new_object_path(peer_path));
	}

	if (service_type == WFD_OEM_SERVICE_TYPE_ALL) {

		char *service_all = "\x02\x00\x00\x01";
		GVariantBuilder *query = NULL;

		query = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
		for (i = 0; i < SERVICE_QUERY_LEN; i++)
			g_variant_builder_add(query, "y", service_all[i]);
		g_variant_builder_add (builder, "{sv}", "query", g_variant_new ("ay", query));
		g_variant_builder_unref (query);

		} else if (service_type == WFD_OEM_SERVICE_TYPE_UPNP) {

		g_variant_builder_add (builder, "{sv}", "service_type", g_variant_new_string("upnp"));
		g_variant_builder_add (builder, "{sv}", "version", g_variant_new_uint16(TRUE));

	} else if (service_type == WFD_OEM_SERVICE_TYPE_BONJOUR) {

		char *service_bonjour = "\x02\x00\x01\x01";
		GVariantBuilder *query = NULL;

		query = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
		for (i = 0; i < SERVICE_QUERY_LEN; i++)
			g_variant_builder_add(query, "y", service_bonjour[i]);
		g_variant_builder_add (builder, "{sv}", "query", g_variant_new ("ay", query));
		g_variant_builder_unref (query);
	}

	value = g_variant_new ("(a{sv})", builder);
	g_variant_builder_unref (builder);

#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = value;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, __add_service_query, mac_addr);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to start service discovery");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_cancel_service_discovery(unsigned char *mac_addr, int service_type)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	dbus_method_param_s params;
	wfd_oem_service_s *data = NULL;
	char query_id[OEM_QUERY_ID_LEN + 1] = {0, };
	char s_type[OEM_SERVICE_TYPE_LEN + 1] ={0, };
	char mac_str[18] = {0, };

	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}

	if (mac_addr[0] == 0 && mac_addr[1] == 0 && mac_addr[2] == 0 &&
		mac_addr[3] == 0 && mac_addr[4] == 0 && mac_addr[5] == 0) {
		snprintf(mac_str, WS_MACSTR_LEN , "%s", SERV_BROADCAST_ADDRESS);
	} else {
		snprintf(mac_str, WS_MACSTR_LEN, MACSTR, MAC2STR(mac_addr));
	}

	switch(service_type) {
		case WFD_OEM_SERVICE_TYPE_ALL:
			strncpy(s_type, SERV_DISC_REQ_ALL, OEM_SERVICE_TYPE_LEN);
		break;
		case WFD_OEM_SERVICE_TYPE_BONJOUR:
			strncpy(s_type, SERV_DISC_REQ_BONJOUR, OEM_SERVICE_TYPE_LEN);
		break;
		case WFD_OEM_SERVICE_TYPE_UPNP:
			strncpy(s_type, SERV_DISC_REQ_UPNP, OEM_SERVICE_TYPE_LEN);
		break;
		default:
			__WDP_LOG_FUNC_EXIT__;
			WDP_LOGE("Invalid Service type");
			return -1;
	}

	WDP_LOGD("Cancel service discovery service_type [%d]", service_type);
	WDP_LOGD("Cancel service discovery s_type [%s]", s_type);

	data = _remove_service_query(s_type, mac_str, query_id);
	if (NULL == data)
		return -1;

	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "ServiceDiscoveryCancelRequest", g_pd->iface_path, g_dbus);

	params.params = g_variant_new ("(t)", strtoul(query_id, NULL, 16));

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to cancel service discovery");

	service_list = g_list_remove(service_list, data);
	free(data);

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_serv_add(wfd_oem_new_service_s *service)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "AddService", g_pd->iface_path, g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}") );

	if (service->protocol == WFD_OEM_SERVICE_TYPE_BONJOUR) {

		WDP_LOGD("Service type: WFD_OEM_SERVICE_TYPE_BONJOUR");
		WDP_LOGD("Query: %s", service->data.bonjour.query);
		WDP_LOGD("RData: %s", service->data.bonjour.rdata);

		res = _convert_bonjour_to_args(service->data.bonjour.query,
							    service->data.bonjour.rdata, builder);
		if (res < 0) {
			WDP_LOGE("Failed to convert Key string");
			g_variant_builder_unref (builder);
			return -1;
		}

	} else if (service->protocol == WFD_OEM_SERVICE_TYPE_UPNP) {
		g_variant_builder_add (builder, "{sv}", "service_type", g_variant_new_string("upnp"));
		g_variant_builder_add (builder, "{sv}", "version", g_variant_new_uint16(TRUE));
		g_variant_builder_add (builder, "{sv}", "service", g_variant_new_string(service->data.upnp.service));
	}

	value = g_variant_new ("(a{sv})", builder);
	g_variant_builder_unref (builder);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGE("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	params.params = value;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to add service");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_serv_del(wfd_oem_new_service_s *service)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, "DeleteService", g_pd->iface_path, g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));

	if (service->protocol == WFD_OEM_SERVICE_TYPE_BONJOUR) {

		WDP_LOGD("Service type: WFD_OEM_SERVICE_TYPE_BONJOUR");
		WDP_LOGD("Query: %s", service->data.bonjour.query);

		res = _convert_bonjour_to_args(service->data.bonjour.query,
							    NULL, builder);
		if (res < 0) {
			WDP_LOGE("Failed to convert Key string");
			g_variant_builder_unref (builder);
			return -1;
		}

	} else if (service->protocol == WFD_OEM_SERVICE_TYPE_UPNP) {
		g_variant_builder_add (builder, "{sv}", "service_type", g_variant_new_string("upnp"));
		g_variant_builder_add (builder, "{sv}", "version", g_variant_new_uint16(TRUE));
		g_variant_builder_add (builder, "{sv}", "service", g_variant_new_string(service->data.upnp.service));
	}

	value = g_variant_new ("(a{sv})", builder);
	g_variant_builder_unref (builder);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("params [%s]", g_variant_print(value, TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	params.params = value;

	res = dbus_method_call(&params, SUPPLICANT_P2PDEVICE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to del service");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY

int _ws_disable_display()
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *value = NULL;
	GVariant *param = NULL;
	dbus_method_param_s params;
	int res = 0;

	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, DBUS_PROPERTIES_METHOD_SET, SUPPLICANT_PATH,
			 g_dbus);

	builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
	value = g_variant_new ("ay", builder);
	g_variant_builder_unref (builder);

	param = g_variant_new("(ssv)", SUPPLICANT_INTERFACE, "WFDIEs", value);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("param [%s]", g_variant_print(param,TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	params.params = param;

	res = dbus_method_call(&params, DBUS_PROPERTIES_INTERFACE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to disable Wi-Fi display");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_miracast_init(int enable)
{
	__WDP_LOG_FUNC_ENTER__;
	wfd_oem_display_s wifi_display;
	int res = 0;

	memset(&wifi_display, 0x0, sizeof(wfd_oem_display_s));

	wifi_display.availablity = enable;
	wifi_display.hdcp_support = 1;
	wifi_display.port = 0x07E6;
	wifi_display.max_tput = 0x0028;

	res = ws_set_display(&wifi_display);
	if (res < 0) {
		WDP_LOGE("Failed to set miracast parameter(device info)");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if(!enable) {
		res = _ws_disable_display();
		if (res < 0)
			WDP_LOGE("Failed to disable wifi display");
		else
			WDP_LOGD("Succeeded to disable wifi display");
	}
	__WDP_LOG_FUNC_EXIT__;
	return res;
}

int ws_set_display(wfd_oem_display_s *wifi_display)
{
	__WDP_LOG_FUNC_ENTER__;
	GDBusConnection *g_dbus = NULL;

	GVariant *value = NULL;
	GVariant *param = NULL;
	GVariantBuilder *builder = NULL;
	dbus_method_param_s params;
	int i = 0;
	int res = 0;

	unsigned char ies[WFD_SUBELEM_LEN_DEV_INFO + 3] = {0,};

	if (!wifi_display) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	g_dbus = g_pd->g_dbus;
	if (!g_dbus) {
		WDP_LOGE("DBus connection is NULL");
		return -1;
	}
	memset(&params, 0x0, sizeof(dbus_method_param_s));

	dbus_set_method_param(&params, DBUS_PROPERTIES_METHOD_SET, SUPPLICANT_PATH,
			 g_dbus);

	ies[2] = WFD_SUBELEM_LEN_DEV_INFO;
	ies[3] = wifi_display->hdcp_support;
	ies[4] = (wifi_display->type) | (wifi_display->availablity<<4);
	ies[5] = wifi_display->port>>8;
	ies[6] = wifi_display->port&0xff;
	ies[7] = wifi_display->max_tput>>8;
	ies[8] = wifi_display->max_tput&0xff;

	builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));
	for(i = 0; i < WFD_SUBELEM_LEN_DEV_INFO + 3; i++)
		g_variant_builder_add(builder, "y", ies[i]);
	value = g_variant_new ("ay", builder);
	g_variant_builder_unref (builder);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("value [%s]", g_variant_print(value,TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */
	param = g_variant_new("(ssv)", SUPPLICANT_INTERFACE, "WFDIEs", value);
	WDP_LOGE("param [%s]", g_variant_print(param,TRUE));

	params.params = param;

	res = dbus_method_call(&params, DBUS_PROPERTIES_INTERFACE, NULL, NULL);
	if (res < 0)
		WDP_LOGE("Failed to send command to wpa_supplicant");
	else
		WDP_LOGD("Succeeded to set Wi-Fi Display");

	__WDP_LOG_FUNC_EXIT__;
	return res;
}
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

int ws_refresh()
{
	__WDP_LOG_FUNC_ENTER__;

	_ws_cancel();
	_ws_flush();

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}
