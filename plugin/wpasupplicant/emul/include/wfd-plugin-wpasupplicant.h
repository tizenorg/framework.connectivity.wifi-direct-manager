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

#define __WDP_LOG_FUNC_ENTER__ LOGD("Enter")
#define __WDP_LOG_FUNC_EXIT__ LOGD("Quit")

#define WDP_SECLOGI(format, args...) SECURE_LOG(LOG_INFO, LOG_TAG, format, ##args)
#define WDP_SECLOGD(format, args...) SECURE_LOG(LOG_DEBUG, LOG_TAG, format, ##args)

#else /* USE_DLOG */

#define WDP_LOGV(format, args...)
#define WDP_LOGD(format, args...)
#define WDP_LOGI(format, args...)
#define WDP_LOGW(format, args...)
#define WDP_LOGE(format, args...)
#define WDP_LOGF(format, args...)

#define __WDP_LOG_FUNC_ENTER__
#define __WDP_LOG_FUNC_EXIT__

#define WDP_SECLOGI(format, args...)
#define WDP_SECLOGD(format, args...)

#endif /* USE_DLOG */

typedef struct {
	int initialized;	// check whether plugin is initialized or not. block init function if initialized
	int activated;
	int concurrent;
	int global_sock;
	ws_sock_data_s *common;
	ws_sock_data_s *group;
	unsigned char local_dev_addr[WS_MACADDR_LEN];
	wfd_oem_event_cb callback;
	void *user_data;
} ws_plugin_data_s;

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
