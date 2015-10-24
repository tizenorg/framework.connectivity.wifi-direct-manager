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
 * This file implements wifi direct manager functions.
 *
 * @file		wifi-direct-manager.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/utsname.h>
#include <time.h>
#include <errno.h>

#include <glib.h>
#include <glib-object.h>

#include <wifi-direct.h>

#include "wifi-direct-ipc.h"
#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-session.h"
#include "wifi-direct-group.h"
#include "wifi-direct-peer.h"
#include "wifi-direct-state.h"
#include "wifi-direct-client.h"
#include "wifi-direct-event.h"
#include "wifi-direct-util.h"

wfd_manager_s *g_manager;

wfd_manager_s *wfd_get_manager()
{
	return g_manager;
}

static gboolean _wfd_exit_timeout_cb(void *user_data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) user_data;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return TRUE;
	}

	if (manager->client_count > 0) {
		WDS_LOGD("Client count [%d]", manager->client_count);
		return TRUE;
	}

	if (manager->state == WIFI_DIRECT_STATE_DEACTIVATED) {
		WDS_LOGD("Terminate Wi-Fi Direct Manager");
		g_main_quit(manager->main_loop);
	}
	manager->exit_timer = 0;
	WDS_LOGD( "Stop exit timer. State [%d]", manager->state);

	__WDS_LOG_FUNC_EXIT__;
	return FALSE;
}

static int _wfd_local_init_device(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = NULL;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	errno = 0;
	local = (wfd_device_s*) g_try_malloc0(sizeof(wfd_device_s));
	if (!local) {
		WDS_LOGE("Failed to allocate memory for local device [%s]", strerror(errno));
		return -1;
	}

	res = wfd_util_get_phone_name(local->dev_name);
	if (res < 0) {
		WDS_LOGE("Failed to get phone name of local device. Use default device name");
		g_strlcpy(local->dev_name, DEFAULT_DEVICE_NAME, DEV_NAME_LEN + 1);
	}
	WDS_LOGD("Local Device name [%s]", local->dev_name);
	wfd_util_set_dev_name_notification();

	res = wfd_util_get_local_dev_mac(local->dev_addr);
	if (res < 0) {
		WDS_LOGE("Failed to get local device MAC address");
	}

	memcpy(local->intf_addr, local->dev_addr, MACADDR_LEN);
	local->intf_addr[4] ^= 0x80;
	WDS_LOGD("Local Interface MAC address [" MACSECSTR "]",
					MAC2SECSTR(local->intf_addr));

	local->config_methods = WFD_WPS_MODE_PBC | WFD_WPS_MODE_DISPLAY | WFD_WPS_MODE_KEYPAD;
	local->wps_mode = WFD_WPS_MODE_PBC;
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	local->services = NULL;
	local->service_count = 0;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
	// TODO: initialize other local device datas
	manager->local = local;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static int _wfd_local_deinit_device(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	wfd_util_unset_dev_name_notification();

	// TODO: free member of local device
	g_free(manager->local);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_reset_data(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = NULL;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	local = manager->local;
	/* init local device data */
	local->dev_role = WFD_DEV_ROLE_NONE;
	local->wps_mode = WFD_WPS_MODE_PBC;
	memset(local->go_dev_addr, 0x0, MACADDR_LEN);
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	memset(&(local->display), 0x0, sizeof(wfd_display_s));
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
	memset(local->ip_addr, 0x0, IPADDR_LEN);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_dev_name(char *dev_name)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!dev_name) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_strlcpy(dev_name, local->dev_name, DEV_NAME_LEN + 1);
	WDS_LOGD("Local device name [%s]", dev_name);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_set_dev_name(char *dev_name)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!dev_name) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_strlcpy(local->dev_name, dev_name, DEV_NAME_LEN + 1);

	if (g_manager->state >= WIFI_DIRECT_STATE_ACTIVATED) {
		wfd_oem_set_dev_name(g_manager->oem_ops, dev_name);
		WDS_LOGD("Device name changed.");
	} else {
		WDS_LOGE("Device name can't changed: state is %d",g_manager->state);
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_dev_mac(char *dev_mac)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!dev_mac) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_snprintf(dev_mac, MACSTR_LEN, MACSTR, MAC2STR(local->dev_addr));
	WDS_SECLOGD("Local device MAC address [%s]", dev_mac);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

#if 0
int wfd_local_get_intf_mac(unsigned char *intf_mac)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!intf_mac) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_snprintf(intf_mac, MACSTR_LEN, MACSTR, MAC2STR(local->intf_addr));
	WDS_SECLOGD("Local interface MAC address [%s]", intf_mac);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
#endif

int wfd_local_get_ip_addr(char *ip_str)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!ip_str) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	snprintf(ip_str, IPSTR_LEN, IPSTR, IP2STR(local->ip_addr));
	WDS_SECLOGD("Local IP address [" IPSECSTR "]", IP2SECSTR(local->ip_addr));

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_supported_wps_mode(int *config_methods)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!config_methods) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*config_methods = local->config_methods;
	WDS_LOGD("Local config method [0x%x]", *config_methods);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_local_get_wps_mode(int *wps_mode)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!wps_mode) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*wps_mode = local->wps_mode;
	WDS_LOGD("Local wps mode [0x%x]", *wps_mode);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

#if 0
int wfd_local_set_wps_mode(int wps_mode)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (!wps_mode) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	local->wps_mode = wps_mode;
	WDS_LOGD("Local wps mode [0x%x]", wps_mode);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
#endif

int wfd_manager_get_go_intent(int *go_intent)
{
	__WDS_LOG_FUNC_ENTER__;
	if (!go_intent) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*go_intent = g_manager->go_intent;
	WDS_LOGD("Local GO intent [%d]", *go_intent);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_set_go_intent(int go_intent)
{
	__WDS_LOG_FUNC_ENTER__;

	if (go_intent < 0 || go_intent > 15) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_manager->go_intent = go_intent;
	if (g_manager->state >= WIFI_DIRECT_STATE_ACTIVATED)
		wfd_oem_set_go_intent(g_manager->oem_ops, go_intent);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_get_max_station(int *max_station)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!max_station) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*max_station = g_manager->max_station;
	WDS_LOGD("Local max station[%d]", *max_station);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_set_max_station(int max_station)
{
	__WDS_LOG_FUNC_ENTER__;

	if (max_station < 1) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_manager->max_station = max_station;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_get_autoconnection(int *autoconnection)
{
	__WDS_LOG_FUNC_ENTER__;
	if (!autoconnection) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*autoconnection = g_manager->autoconnection;
	WDS_LOGD("Local autoconnection [%s]", *autoconnection ? "TRUE":"FALSE");

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_set_autoconnection(int autoconnection)
{
	__WDS_LOG_FUNC_ENTER__;
	if (autoconnection < 0) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_manager->autoconnection = autoconnection;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_get_req_wps_mode(int *req_wps_mode)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!req_wps_mode) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	*req_wps_mode = g_manager->req_wps_mode;
	WDS_LOGD("Requested wps mode [0x%x]", *req_wps_mode);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_set_req_wps_mode(int req_wps_mode)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = g_manager->local;

	if (req_wps_mode != WIFI_DIRECT_WPS_TYPE_PBC &&
			req_wps_mode != WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY &&
			req_wps_mode != WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_manager->req_wps_mode = req_wps_mode;
	WDS_LOGD("Requested wps mode [0x%x]", req_wps_mode);
	if (req_wps_mode == WFD_WPS_MODE_DISPLAY)
		local->wps_mode = WFD_WPS_MODE_KEYPAD;
	else if (req_wps_mode == WFD_WPS_MODE_KEYPAD)
		local->wps_mode = WFD_WPS_MODE_DISPLAY;
	else
		local->wps_mode = req_wps_mode;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_manager_local_config_set(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *local = NULL;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	local = manager->local;

	local->wps_mode = WFD_WPS_MODE_PBC;
	WDS_LOGD("Device name set as %s", local->dev_name);
	res = wfd_oem_set_dev_name(manager->oem_ops, local->dev_name);
	if (res < 0) {
		WDS_LOGE("Failed to set device name");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	res = wfd_oem_set_dev_type(manager->oem_ops, local->pri_dev_type, local->sec_dev_type);
	if (res < 0) {
		WDS_LOGE("Failed to set device type");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	res = wfd_oem_set_go_intent(manager->oem_ops, manager->go_intent);
	if (res < 0) {
		WDS_LOGE("Failed to set go intent");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	return WIFI_DIRECT_ERROR_NONE;
}

int wfd_manager_activate(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	int prev_state = 0;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	if (manager->state > WIFI_DIRECT_STATE_ACTIVATING) {
		WDS_LOGE("Already activated");
		return 1;
	}

	wfd_state_get(manager, &prev_state);
	wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATING);
#if defined(TIZEN_WLAN_CONCURRENT_ENABLE) && defined(TIZEN_MOBILE)
	res = wfd_util_check_wifi_state();
	if (res < 0) {
		WDS_LOGE("Failed to get wifi state");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	} else if (res == 0) {
#endif /* TIZEN_WLAN_CONCURRENT_ENABLE && TIZEN_MOBILE */
	res = wfd_oem_activate(manager->oem_ops, 0);
	if (res < 0) {
		WDS_LOGE("Failed to activate");
		wfd_state_set(manager, prev_state);
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}
#if defined(TIZEN_WLAN_CONCURRENT_ENABLE) && defined(TIZEN_MOBILE)
	} else {
		res = wfd_oem_activate(manager->oem_ops, res);
		if (res < 0) {
			WDS_LOGE("Failed to activate");
			wfd_state_set(manager, prev_state);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}
#endif /* TIZEN_WLAN_CONCURRENT_ENABLE && TIZEN_MOBILE */
	WDS_LOGE("Succeeded to activate");

	wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);

	wfd_manager_local_config_set(manager);
	wfd_util_set_country();
#ifdef TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT
	wfd_util_start_wifi_direct_popup();
#endif /* TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT */

	res = wfd_util_get_local_dev_mac(manager->local->dev_addr);
	if (res < 0) {
		WDS_LOGE("Failed to get local device MAC address");
	}

	memcpy(manager->local->intf_addr, manager->local->dev_addr, MACADDR_LEN);
	manager->local->intf_addr[4] ^= 0x80;
	WDS_LOGD("Local Interface MAC address [" MACSECSTR "]",
					MAC2SECSTR(manager->local->intf_addr));

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wfd_manager_deactivate(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	int prev_state = 0;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	if (manager->state < WIFI_DIRECT_STATE_ACTIVATING) {
		WDS_LOGE("Already deactivated");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	wfd_state_get(manager, &prev_state);
	wfd_state_set(manager, WIFI_DIRECT_STATE_DEACTIVATING);

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	res = wfd_oem_miracast_init(manager->oem_ops, false);
	if (res < 0)
		WDS_LOGE("Failed to initialize miracast");
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

	res = wfd_oem_destroy_group(manager->oem_ops, GROUP_IFNAME);
	if (res < 0)
		WDS_LOGE("Failed to destroy group before deactivation");

#if defined(TIZEN_WLAN_CONCURRENT_ENABLE) && defined(TIZEN_MOBILE)
	res = wfd_util_check_wifi_state();
	if (res < 0) {
		WDS_LOGE("Failed to get wifi state");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	} else if (res == 0) {
#endif /* TIZEN_WLAN_CONCURRENT_ENABLE && TIZEN_MOBILE */
		res = wfd_oem_deactivate(manager->oem_ops, 0);
		if (res < 0) {
			WDS_LOGE("Failed to deactivate");
			wfd_state_set(manager, prev_state);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
#if defined(TIZEN_WLAN_CONCURRENT_ENABLE) && defined(TIZEN_MOBILE)
	} else {
		// FIXME: We should do something to stop p2p feature of Driver
		res = wfd_oem_deactivate(manager->oem_ops, res);
		if (res < 0) {
			WDS_LOGE("Failed to deactivate");
			wfd_state_set(manager, prev_state);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
		WDS_LOGE("Do not need to deactivate Wi-Fi");
	}
#endif /* TIZEN_WLAN_CONCURRENT_ENABLE && TIZEN_MOBILE */
	WDS_LOGE("Succeeded to deactivate");

	wfd_state_set(manager, WIFI_DIRECT_STATE_DEACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_DEACTIVATED);

	manager->req_wps_mode = WFD_WPS_MODE_PBC;

	wfd_destroy_group(manager, GROUP_IFNAME);
	wfd_destroy_session(manager);
	wfd_peer_clear_all(manager);
	wfd_local_reset_data(manager);

#ifdef TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT
	wfd_util_stop_wifi_direct_popup();
#endif /* TIZEN_FEATURE_DEFAULT_CONNECTION_AGENT */
	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wfd_manager_connect(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_session_s *session = NULL;
	int res = 0;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	session = (wfd_session_s*) manager->session;
	if (session && session->type != SESSION_TYPE_INVITE) {
		WDS_LOGE("Session already exist and it's not an invitation session");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	if (!session) {
		session = wfd_create_session(manager, peer_addr,
					manager->req_wps_mode, SESSION_DIRECTION_OUTGOING);
		if (!session) {
			WDS_LOGE("Failed to create new session");
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_GO &&
			session->type != SESSION_TYPE_INVITE) {
		session->type = SESSION_TYPE_INVITE;
		res = wfd_session_invite(session);
	} else {
		res = wfd_session_start(session);
	}
	if (res < 0) {
		WDS_LOGE("Failed to start session");
		wfd_destroy_session(manager);
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}
	wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTING);

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wfd_manager_accept_connection(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_session_s *session = NULL;
	wfd_device_s *peer = NULL;
	int res = 0;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Session not found");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	peer = wfd_peer_find_by_dev_addr(manager, peer_addr);
	if (!peer) {
		WDS_LOGE("Peer is NULL");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	// TODO: check peer_addr with session's peer_addr

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		WDS_LOGD("My device is GO and peer want to join my group, so WPS will be started");
		res = wfd_session_wps(session);
	} else if (peer->dev_role == WFD_DEV_ROLE_GO) {
		WDS_LOGD("Peer device is GO, so Prov_Disc or Join will be started");
		if (session->type == SESSION_TYPE_INVITE) {
			if (session->state == SESSION_STATE_CREATED) {
				WDS_LOGD("Invitation session. PD will be started");
				res = wfd_session_start(session);
			} else {
				WDS_LOGD("Invitation session. Join will be started");
				res = wfd_session_join(session);
			}
		} else {
			if (manager->autoconnection && (manager->auto_pin[0] != 0))
				g_strlcpy(session->wps_pin, manager->auto_pin, PINSTR_LEN + 1);

			WDS_LOGD("Peer device is GO, so WPS will be started");
			res = wfd_session_connect(session);
		}
	} else {
		/* We should wait GO_NEGO_REQ from peer(MO) in autoconnection mode. */
		/* Otherwise, GO Nego is sometimes failed. */
		if (manager->autoconnection == FALSE) {
			WDS_LOGD("My device is Device, so Negotiation will be started");
			res = wfd_session_connect(session);
		}
	}
	if (res < 0) {
		WDS_LOGE("Failed to start session");
		if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
			wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
		} else {
			wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
			wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
		}
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}
	wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTING);

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wfd_manager_cancel_connection(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = NULL;
	int res = 0;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	res = wfd_session_cancel(manager->session, peer_addr);
	if (res < 0) {
		WDS_LOGE("Failed to cancel session");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	if (manager->local->dev_role != WFD_DEV_ROLE_GO)
		wfd_oem_destroy_group(manager->oem_ops, GROUP_IFNAME);

	group = (wfd_group_s*) manager->group;
	if (group) {
		wfd_group_remove_member(group, peer_addr);
		if ((wfd_group_is_autonomous(manager->group) != TRUE) && !group->member_count) {
			wfd_oem_destroy_group(manager->oem_ops, group->ifname);
			wfd_destroy_group(manager, group->ifname);
		} else {
			wfd_oem_disconnect(manager->oem_ops, peer_addr);
		}
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wfd_manager_reject_connection(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_session_s *session = NULL;
	int res = 0;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Session not found");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	res = wfd_session_reject(session, peer_addr);
	if (res < 0) {
		WDS_LOGE("Failed to reject connection");
		// TODO: check whether set state and break
	}
	wfd_destroy_session(manager);

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wfd_manager_disconnect(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = NULL;
	wfd_device_s *peer = NULL;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	if (!peer_addr) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	group = (wfd_group_s*) manager->group;
	if (!group) {
		WDS_LOGE("Group not found");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	peer = wfd_group_find_member_by_addr(group, peer_addr);
	if (!peer) {
		WDS_LOGE("Connected peer not found");
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wfd_state_set(manager, WIFI_DIRECT_STATE_DISCONNECTING);

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
#ifdef CTRL_IFACE_DBUS
		/* dbus using device address to identify the peer */
		res = wfd_oem_disconnect(manager->oem_ops, peer->dev_addr);
#else /* CTRL_IFACE_DBUS */
		res = wfd_oem_disconnect(manager->oem_ops, peer->intf_addr);
#endif /* CTRL_IFACE_DBUS */
	} else {
		res = wfd_oem_destroy_group(manager->oem_ops, group->ifname);
	}
	if (res < 0) {
		WDS_LOGE("Failed to disconnect peer");
		res = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		goto failed;
	}
	WDS_LOGE("Succeeded to disconnect peer");

	wfd_group_remove_member(group, peer_addr);
	if (!group->member_count) {
		wfd_oem_destroy_group(manager->oem_ops, group->ifname);
		wfd_destroy_group(manager, group->ifname);
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;

failed:
	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_CONNECTED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_disconnect_all(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = NULL;
	int res = 0;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	group = (wfd_group_s*) manager->group;
	if (!group) {
		WDS_LOGE("Group not found");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	wfd_state_set(manager, WIFI_DIRECT_STATE_DISCONNECTING);

	res = wfd_oem_destroy_group(manager->oem_ops, group->ifname);
	if (res < 0) {
		WDS_LOGE("Failed to destroy group");
		res = WIFI_DIRECT_ERROR_OPERATION_FAILED;
		goto failed;
	}
	WDS_LOGE("Succeeded to disconnect all peer");

	wfd_destroy_group(manager, group->ifname);

	wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
	wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);

	__WDS_LOG_FUNC_EXIT__;
	return WIFI_DIRECT_ERROR_NONE;

failed:
	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_CONNECTED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_get_peer_info(wfd_manager_s *manager, unsigned char *addr, wfd_discovery_entry_s **peer)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *peer_dev = NULL;
	wfd_discovery_entry_s *peer_info;
	wfd_oem_device_s *oem_dev = NULL;
	int res = 0;

	if (!manager || !addr) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	unsigned long time = 0;
#if !(__GNUC__ <= 4 && __GNUC_MINOR__ < 8)
	wfd_util_get_current_time(&time);
#else
	struct timeval tval;
	gettimeofday(&tval, NULL);
	time = tval.tv_sec;
#endif
	WDS_LOGI("Current time [%ld]", time);

	res = wfd_oem_get_peer_info(manager->oem_ops, addr, &oem_dev);
	if (res < 0 || !oem_dev) {
		WDS_LOGE("Failed to get peer information");
		return -1;
	}

	peer_dev = wfd_peer_find_by_addr(manager, addr);
	if(!peer_dev) {
		peer_dev = (wfd_device_s*) g_try_malloc0(sizeof(wfd_device_s));
		if (!peer_dev) {
			WDS_LOGE("Failed to allocate memory for peer device. [%s]", strerror(errno));
			free(oem_dev);
			return -1;
		}
		memcpy(peer_dev->dev_addr, addr, MACADDR_LEN);
		manager->peers = g_list_prepend(manager->peers, peer_dev);
		manager->peer_count++;
		peer_dev->time = time;
		WDS_LOGD("peer_count[%d]", manager->peer_count);
	} else {
		if (oem_dev->age > 30 && peer_dev->state == WFD_PEER_STATE_DISCOVERED) {
			WDS_LOGE("Too old age to update peer");
			free(oem_dev);
			return -1;
		}
	}

	g_strlcpy(peer_dev->dev_name, oem_dev->dev_name, DEV_NAME_LEN + 1);
	memcpy(peer_dev->intf_addr, oem_dev->intf_addr, MACADDR_LEN);
	memcpy(peer_dev->go_dev_addr, oem_dev->go_dev_addr, MACADDR_LEN);
	peer_dev->dev_role = oem_dev->dev_role;
	peer_dev->config_methods = oem_dev->config_methods;
	peer_dev->pri_dev_type = oem_dev->pri_dev_type;
	peer_dev->sec_dev_type = oem_dev->sec_dev_type;
	peer_dev->dev_flags = oem_dev->dev_flags;
	peer_dev->group_flags = oem_dev->group_flags;
	peer_dev->wps_mode =  oem_dev->wps_mode;

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	memcpy(&(peer_dev->display), &(oem_dev->display), sizeof(wfd_display_s));
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

	peer_dev->time = time;
	peer_dev->channel = oem_dev->channel;

	free(oem_dev);

	peer_info = (wfd_discovery_entry_s*) g_try_malloc0(sizeof(wfd_discovery_entry_s));
	if (!(peer_info)) {
		WDS_LOGE("Failed to allocate memory for peer data. [%s]", strerror(errno));
		return -1;
	}

	g_strlcpy(peer_info->device_name, peer_dev->dev_name, DEV_NAME_LEN + 1);
	memcpy(peer_info->mac_address, peer_dev->dev_addr, MACADDR_LEN);
	memcpy(peer_info->intf_address, peer_dev->intf_addr, MACADDR_LEN);
	peer_info->channel = peer_dev->channel;
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	peer_info->services = 0;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
	peer_info->is_group_owner = peer_dev->dev_role == WFD_DEV_ROLE_GO;
	peer_info->is_persistent_go = peer_dev->group_flags & WFD_OEM_GROUP_FLAG_PERSISTENT_GROUP;
	peer_info->is_connected = peer_dev->dev_role == WFD_DEV_ROLE_GC;
	peer_info->wps_device_pwd_id = 0;
	peer_info->wps_cfg_methods = peer_dev->config_methods;
	peer_info->category = peer_dev->pri_dev_type;
	peer_info->subcategory = peer_dev->sec_dev_type;

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	if (peer_dev->display.availablity && peer_dev->display.port)
		peer_info->is_wfd_device = 1;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

	*peer = peer_info;

	__WDS_LOG_FUNC_EXIT__;
	return res;
}


int wfd_manager_get_peers(wfd_manager_s *manager, wfd_discovery_entry_s **peers_data)
{
	__WDS_LOG_FUNC_ENTER__;
	GList *temp = NULL;
	wfd_device_s *peer = NULL;
	wfd_discovery_entry_s *peers = NULL;
	int peer_count = 0;
	int count = 0;
	int res = 0;

	if (!manager || !peers_data) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	unsigned long time = 0;
#if !(__GNUC__ <= 4 && __GNUC_MINOR__ < 8)
	wfd_util_get_current_time(&time);
#else
	struct timeval tval;
	gettimeofday(&tval, NULL);
	time = tval.tv_sec;
#endif
	WDS_LOGI("Current time [%ld]", time);

	peer_count = manager->peer_count;
	WDS_LOGI("peer count [%ld]", peer_count);
	if (peer_count < 0)
		return -1;
	else if (peer_count == 0)
		return 0;

	errno = 0;
	peers = (wfd_discovery_entry_s*) g_try_malloc0_n(peer_count, sizeof(wfd_discovery_entry_s));
	if (!peers) {
		WDS_LOGE("Failed to allocate memory for peer data. [%s]", strerror(errno));
		return -1;
	}

	temp = g_list_first(manager->peers);
	while (temp && count < peer_count) {
		peer = temp->data;
		if (!peer)
			goto next;
		if (peer->time + 8 < time) {
			WDS_LOGD("Device data is too old to report to application [%s]", peer->dev_name);
			res = wfd_update_peer(manager, peer);
			if (res < 0) {
				WDS_LOGE("This device is disappeared [%s]", peer->dev_name);
				temp = g_list_next(temp);
				manager->peers = g_list_remove(manager->peers, peer);
				manager->peer_count--;
				g_free(peer);
				peer = NULL;
				continue;
			}
		}

		g_strlcpy(peers[count].device_name, peer->dev_name, DEV_NAME_LEN + 1);
		memcpy(peers[count].mac_address, peer->dev_addr, MACADDR_LEN);
		memcpy(peers[count].intf_address, peer->intf_addr, MACADDR_LEN);
		peers[count].channel = peer->channel;
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
		peers[count].services = 0;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
		peers[count].is_group_owner = peer->dev_role == WFD_DEV_ROLE_GO;
		peers[count].is_persistent_go = peer->group_flags & WFD_OEM_GROUP_FLAG_PERSISTENT_GROUP;
		peers[count].is_connected = peer->dev_role == WFD_DEV_ROLE_GC;
		peers[count].wps_device_pwd_id = 0;
		peers[count].wps_cfg_methods = peer->config_methods;
		peers[count].category = peer->pri_dev_type;
		peers[count].subcategory = peer->sec_dev_type;

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
		if (peer->display.availablity && peer->display.port)
			peers[count].is_wfd_device = 1;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
		count++;
		WDS_LOGD("%dth peer [%s]", count, peer->dev_name);
next:
		temp = g_list_next(temp);
		peer = NULL;
	}
	WDS_LOGD("%d peers converted", count);
	WDS_LOGD("Final peer count is %d", manager->peer_count);

	*peers_data = peers;

	__WDS_LOG_FUNC_EXIT__;
	return count;
}

int wfd_manager_get_connected_peers(wfd_manager_s *manager, wfd_connected_peer_info_s **peers_data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_connected_peer_info_s *peers = NULL;
	wfd_group_s *group = NULL;
	wfd_device_s *peer = NULL;
	GList *temp = NULL;
	int peer_count = 0;
	int count = 0;

	if (!manager || !peers_data) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	group = manager->group;
	if (!group) {
		WDS_LOGE("Group not exist");
		return -1;
	}

	peer_count = group->member_count;
	if (peer_count == 0) {
		WDS_LOGD("Member not exist");
		return 0;
	}

	errno = 0;
	peers = (wfd_connected_peer_info_s*) g_try_malloc0_n(peer_count, sizeof(wfd_connected_peer_info_s));
	if (!peers) {
		WDS_LOGE("Failed to allocate memory for connected peer data. [%s]", strerror(errno));
		return -1;
	}

	temp = g_list_first(group->members);
	while (temp && count < group->member_count) {
		peer = temp->data;
		{
			g_strlcpy(peers[count].device_name, peer->dev_name, DEV_NAME_LEN + 1);
			memcpy(peers[count].mac_address, peer->dev_addr, MACADDR_LEN);
			memcpy(peers[count].intf_address, peer->intf_addr, MACADDR_LEN);
			memcpy(peers[count].ip_address, peer->ip_addr, IPADDR_LEN);
			peers[count].category = peer->pri_dev_type;
			peers[count].subcategory = peer->sec_dev_type;
			peers[count].channel = peer->channel;
			peers[count].is_p2p = 1;
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
			peers[count].services = 0;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
			if (peer->display.availablity && peer->display.port)
				peers[count].is_wfd_device = 1;

#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

			WDS_LOGD("%dth member converted[%s]", count, peers[count].device_name);
			count++;
		}
		temp = g_list_next(temp);
		peer = NULL;
	}
	WDS_LOGD("%d members converted", count);

	*peers_data = peers;

	__WDS_LOG_FUNC_EXIT__;
	return count;
}

#if 0
wfd_device_s *wfd_manager_find_connected_peer(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *peer = NULL;

	if (!manager || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		return NULL;
	}

	peer = wfd_group_find_member_by_addr(manager->group, peer_addr);

	__WDS_LOG_FUNC_EXIT__;
	return peer;
}
#endif

int wfd_manager_get_goup_ifname(char **ifname)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = g_manager->group;

	if (!ifname) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (!group) {
		WDS_LOGE("Group not exist");
		return -1;
	}

	*ifname = group->ifname;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
int wfd_manager_set_display_device(int type, int port, int hdcp)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s * device = g_manager->local;
	wfd_oem_display_s display;
	int res = 0;

	if (!device) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	memset(&display, 0x0, sizeof(wfd_oem_display_s));

	display.type = type;
	display.port = port;
	display.hdcp_support = hdcp;

	display.availablity = device->display.availablity;
	display.max_tput = device->display.max_tput;

	res = wfd_oem_set_display(g_manager->oem_ops, (wfd_oem_display_s*)&display);
	if (res < 0) {
		WDS_LOGE("Failed to set wifi display");
		return -1;
	}

	device->display.type = type;
	device->display.port = port;
	device->display.hdcp_support = hdcp;

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

int wfd_manager_set_session_availability(int availability)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s * device = g_manager->local;
	wfd_oem_display_s display;
	int res = 0;

	if (!device) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	memset(&display, 0x0, sizeof(wfd_oem_display_s));

	display.availablity = availability;

	display.type = device->display.type;
	display.hdcp_support = device->display.hdcp_support;
	display.port = device->display.port;
	display.max_tput = device->display.max_tput;

	res = wfd_oem_set_display(g_manager->oem_ops, (wfd_oem_display_s*)&display);
	if (res < 0) {
		WDS_LOGE("Failed to set wifi display session availability");
		return -1;
	}

	device->display.availablity = availability;

	__WDS_LOG_FUNC_EXIT__;
	return res;
}

#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

wfd_device_s *wfd_manager_get_peer_by_addr(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *peer = NULL;
	if(manager->group) {
		peer = wfd_group_find_member_by_addr(manager->group, peer_addr);
	}

	if(peer) {
		return peer;
	}

	peer = wfd_peer_find_by_addr(manager, peer_addr);

	return peer;
	__WDS_LOG_FUNC_EXIT__;
}

static wfd_manager_s *wfd_manager_init()
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = NULL;
	int res = 0;

	manager = (wfd_manager_s*) g_try_malloc0(sizeof(wfd_manager_s));
	if (!manager) {
		WDS_LOGE("Failed to allocate memory for wfd_manager structure");
		return NULL;
	}

	manager->go_intent = 7;
	manager->req_wps_mode = WFD_WPS_MODE_PBC;
	manager->max_station = 8;
	res = _wfd_local_init_device(manager);
	if (res < 0) {
		WDS_LOGE("Failed to initialize local device");
		g_free(manager);
		return NULL;		// really stop manager?
	}
	WDS_LOGD("Succeeded to initialize local device");

	manager->exit_timer = g_timeout_add(120000,
						(GSourceFunc) _wfd_exit_timeout_cb, manager);
	WDS_LOGD("Exit timer started");

	__WDS_LOG_FUNC_EXIT__;
	return manager;
}

int wfd_manager_deinit(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (manager->exit_timer > 0)
		g_source_remove(manager->exit_timer);
	manager->exit_timer = 0;

	_wfd_local_deinit_device(manager);

	g_free(manager);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static void *wfd_plugin_init(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;
	void *handle;
	struct utsname kernel_info;
	int res;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	res = uname(&kernel_info);
	if (res) {
		WDS_LOGE("Failed to detect target type");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}
	WDS_LOGD("Node name [%s], HW ID [%s]", kernel_info.nodename, kernel_info.machine);

	errno = 0;
	handle = dlopen(SUPPL_PLUGIN_PATH, RTLD_NOW);
	if (!handle) {
		WDS_LOGE("Failed to open shared object. [%s]", dlerror());
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	errno = 0;
	int (*plugin_load)(wfd_oem_ops_s **ops) = NULL;
	plugin_load = (int (*)(wfd_oem_ops_s **ops)) dlsym(handle, "wfd_plugin_load");
	if (!plugin_load) {
		WDS_LOGE( "Failed to load symbol. Error = [%s]", strerror(errno));
		dlclose(handle);
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	wfd_oem_ops_s *temp_ops;
	(*plugin_load)(&temp_ops);
	manager->oem_ops = temp_ops;

	res = wfd_oem_init(temp_ops, (wfd_oem_event_cb) wfd_process_event, manager);
	if (res < 0) {
		WDS_LOGE("Failed to initialize OEM");
		dlclose(handle);
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}
	WDS_LOGD("Succeeded to initialize OEM");

	__WDS_LOG_FUNC_EXIT__;
	return handle;
}

static int wfd_plugin_deinit(wfd_manager_s *manager)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!manager || !manager->plugin_handle) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	dlclose(manager->plugin_handle);
	manager->plugin_handle = NULL;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int main(int argc, char *argv[])
{
	__WDS_LOG_FUNC_ENTER__;
	GMainLoop *main_loop = NULL;
	int res = 0;

#if !GLIB_CHECK_VERSION(2,32,0)
	if (!g_thread_supported())
		g_thread_init(NULL);
#endif

#if !GLIB_CHECK_VERSION(2,36,0)
	g_type_init();
#endif

	// TODO: Parsing argument
	/* Wi-Fi direct connection for S-Beam can be optimized using argument */

	g_manager = wfd_manager_init();
	if (!g_manager) {
		WDS_LOGE("Failed to initialize wifi-direct manager");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGD("Succeeded to initialize manager");

	g_manager->plugin_handle = wfd_plugin_init(g_manager);
	if (!g_manager->plugin_handle) {
		WDS_LOGE("Failed to initialize plugin");
		wfd_manager_deinit(g_manager);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGD("Succeeded to load plugin");

	res = wfd_client_handler_init(g_manager);
	if (res < 0) {
		WDS_LOGE("Failed to initialize client handler");
		wfd_plugin_deinit(g_manager);
		wfd_manager_deinit(g_manager);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	WDS_LOGD("Succeeded to initialize client handler");

	main_loop = g_main_loop_new(NULL, FALSE);
	if (main_loop == NULL) {
		WDS_LOGE("Failed to create GMainLoop structure");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	g_manager->main_loop = main_loop;

	g_main_loop_run(main_loop);

	wfd_client_handler_deinit(g_manager);
	wfd_plugin_deinit(g_manager);
	wfd_manager_deinit(g_manager);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
