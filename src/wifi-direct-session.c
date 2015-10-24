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
 * This file implements wifi direct session functions.
 *
 * @file		wifi-direct-session.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include <wifi-direct.h>

#include "wifi-direct-ipc.h"
#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-peer.h"
#include "wifi-direct-group.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-util.h"
#include "wifi-direct-session.h"
#include "wifi-direct-client.h"
#include "wifi-direct-state.h"


static gboolean _session_timeout_cb(gpointer *user_data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_session_s *session = (wfd_session_s*) manager->session;
	wifi_direct_client_noti_s noti;
	unsigned char *peer_addr = NULL;

	if (!session) {
		WDS_LOGE("Invalid parameter");
		return FALSE;
	}
	session->connecting_120 = 0;
	session->timer = 0;
	WDS_LOGD("Session timer expired");

	peer_addr = wfd_session_get_peer_addr(session);

	memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
	noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
	noti.error = WIFI_DIRECT_ERROR_CONNECTION_CANCELED;
	if(peer_addr != NULL)
		g_snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));
	wfd_client_send_event(manager, &noti);

	wfd_session_cancel(session, peer_addr);

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	__WDS_LOG_FUNC_EXIT__;
	return FALSE;
}

static void _wfd_notify_session_failed(wfd_manager_s *manager, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wifi_direct_client_noti_s noti;
	memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
	noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
	noti.error = WIFI_DIRECT_ERROR_CONNECTION_FAILED;
	snprintf(noti.param1, MACSTR_LEN, MACSTR, MAC2STR(peer_addr));

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		wfd_state_set(manager, WIFI_DIRECT_STATE_GROUP_OWNER);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	} else {
		wfd_state_set(manager, WIFI_DIRECT_STATE_ACTIVATED);
		wfd_util_set_wifi_direct_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	wfd_client_send_event(manager, &noti);
	__WDS_LOG_FUNC_EXIT__;
}

int wfd_session_timer(wfd_session_s *session, int start)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!session) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (start) {
		if (!session->connecting_120)
			session->connecting_120 = 1;

		if (session->timer > 0) {
			WDS_LOGE("Session timer already started");
			__WDS_LOG_FUNC_EXIT__;
			return -1;
		}
		session->timer = g_timeout_add(120000,
							(GSourceFunc) _session_timeout_cb,
							session);
		WDS_LOGD("Session timer started");
	} else {
		session->connecting_120 = 0;
		if (session->timer > 0) {
			g_source_remove(session->timer);
			session->timer = 0;
			WDS_LOGD("Session timer stoped");
		}
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

// Check the session instance which has same peer address, before using this function
wfd_session_s *wfd_create_session(void *data, unsigned char *peer_addr, int wps_mode, int direction)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_session_s *session = NULL;
	wfd_device_s *peer = NULL;

	if (!data || !peer_addr) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	WDS_LOGD("create session for peer[" MACSTR "]", MAC2STR(peer_addr));

	if (manager->session) {
		WDS_LOGE("Session already exist");
		return NULL;
	}

	session = (wfd_session_s*) g_try_malloc0(sizeof(wfd_session_s));
	if (!session) {
		WDS_LOGE("Failed to allocate memory for session");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	peer = wfd_peer_find_by_dev_addr(manager, peer_addr);
	if (!peer) {
		WDS_LOGE("Failed to find peer info[" MACSECSTR "]", MAC2SECSTR(peer_addr));
		g_free(session);
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}
	peer->state = WFD_PEER_STATE_CONNECTING;

	session->peer = peer;
	session->req_wps_mode = wps_mode;
	if (wps_mode == WFD_WPS_MODE_DISPLAY)
		session->wps_mode = WFD_WPS_MODE_KEYPAD;
	else if (wps_mode == WFD_WPS_MODE_KEYPAD)
		session->wps_mode = WFD_WPS_MODE_DISPLAY;
	else
		session->wps_mode = wps_mode;
	session->direction = direction;
	session->state = SESSION_STATE_CREATED;

	manager->session = session;
	manager->local->wps_mode = session->wps_mode;

	if (peer->dev_role == WFD_DEV_ROLE_GO &&
			manager->local->wps_mode == WFD_WPS_MODE_DISPLAY) {
			char *generated_pin = NULL;
			session->wps_mode = WFD_WPS_MODE_DISPLAY;
			session->req_wps_mode = WFD_WPS_MODE_KEYPAD;

			if (wfd_oem_generate_pin(manager->oem_ops, &generated_pin) != 0) {
				WDS_LOGE("Failed to generate pin");
				g_free(session);
				__WDS_LOG_FUNC_EXIT__;
				return NULL;
			}

			g_strlcpy(session->wps_pin, generated_pin, PINSTR_LEN + 1);
			g_free(generated_pin);
	}

	if (peer->dev_role == WFD_DEV_ROLE_GO && manager->local->dev_role != WFD_DEV_ROLE_GO)
		manager->local->dev_role = WFD_DEV_ROLE_GC;

	__WDS_LOG_FUNC_EXIT__;
	return session;
}

int wfd_destroy_session(void *data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_session_s *session = NULL;
	wfd_device_s *peer = NULL;

	if (!manager) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	session = (wfd_session_s*) manager->session;
	if (!session) {
		WDS_LOGE("Session not found");	// self prevent 13029
		return -1;
	}
	wfd_session_timer(session, 0);
	peer = session->peer;

	if(peer) {
		if (session->state == SESSION_STATE_COMPLETED)
			peer->state = WFD_PEER_STATE_CONNECTED;
		else
			peer->state = WFD_PEER_STATE_DISCOVERED;
	} else {
		WDS_LOGE("Peer not found");
	}

	g_free(session);
	manager->session = NULL;
	manager->local->wps_mode = WFD_WPS_MODE_PBC;
	manager->autoconnection = 0;
	memset(manager->auto_pin, 0x0, PINSTR_LEN);
	if (manager->local->dev_role == WFD_DEV_ROLE_GC)
		manager->local->dev_role = WFD_DEV_ROLE_NONE;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_start(wfd_session_s *session)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_device_s *peer = NULL;
	int join = 0;
	int res = 0;

	if (!session) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (session->state > SESSION_STATE_STARTED) {
		WDS_LOGE("Invalid session state(%d)", session->state);
		return -1;
	}

	// Check: Invitation Received in Incomming case -> send prov_disc join
	// Check: User select peer to connect with in Outgoing case -> send prov_disc wps_mdde

	wfd_oem_stop_scan(manager->oem_ops);

	session->state = SESSION_STATE_STARTED;
	peer = session->peer;
	if (peer->dev_role == WFD_DEV_ROLE_GO || session->type == SESSION_TYPE_INVITE)
		join = 1;
	res = wfd_oem_prov_disc_req(manager->oem_ops, peer->dev_addr,
					session->req_wps_mode, join);
	if (res < 0) {
		WDS_LOGD("Failed to send provision discovery request to peer [" MACSECSTR "]",
									MAC2SECSTR(peer->dev_addr));
		wfd_destroy_session(manager);
		// TODO: send notification to App
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	wfd_session_timer(session, 1);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

#if 0
int wfd_session_stop(wfd_session_s *session)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_device_s *peer = NULL;
	int res = 0;

	if (!session) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (session->state > SESSION_STATE_CREATED) {
		peer = session->peer;
		if (session->direction == SESSION_DIRECTION_INCOMING) {
			res  = wfd_oem_reject_connection(manager->oem_ops, peer->dev_addr);
		} else if (session->direction == SESSION_DIRECTION_OUTGOING) {
			res = wfd_oem_cancel_connection(manager->oem_ops, peer->dev_addr);
		}
		if (res < 0) {
			WDS_LOGE("Failed to reject or cancel connection");
			__WDS_LOG_FUNC_EXIT__;
			return -1;
		}
	}

	session->state = SESSION_STATE_STOPPED;
	wfd_destroy_session(manager);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
#endif

/* In case of incomming session, when user accept connection request, this function should be called.
 * In case of outgoing session, when prov_disc response arrived, this function should be called.
 * Even though peer is GO, we can use this function, which can decide using join itself.
 */
int wfd_session_connect(wfd_session_s *session)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_oem_conn_param_s param;
	wfd_device_s *peer = NULL;
	int res = 0;

	if (!session) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (session->state > SESSION_STATE_GO_NEG) {
		WDS_LOGE("Session already finished GO Negotiation");
		return -1;
	}

	wfd_oem_stop_scan(manager->oem_ops);

	session->state = SESSION_STATE_GO_NEG;
	peer = session->peer;

	memset(&param, 0x00, sizeof(wfd_oem_conn_param_s));
	param.wps_mode = session->wps_mode;
	if (peer->dev_role == WFD_DEV_ROLE_GO || session->type == SESSION_TYPE_INVITE)
		param.conn_flags |= WFD_OEM_CONN_TYPE_JOIN;
	param.go_intent = session->go_intent;
	param.freq = session->freq;
	if(manager->local->group_flags & WFD_GROUP_FLAG_PERSISTENT)
		param.conn_flags |= WFD_OEM_CONN_TYPE_PERSISTENT;

	if (session->wps_pin[0] != '\0') {
		g_strlcpy(param.wps_pin, session->wps_pin, OEM_PINSTR_LEN + 1);
	}

	res = wfd_oem_connect(manager->oem_ops, peer->dev_addr, &param);
	if (res < 0) {
		WDS_LOGD("Failed to connect peer [" MACSECSTR "]", MAC2SECSTR(peer->dev_addr));
		wfd_destroy_session(manager);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	wfd_session_timer(session, 1);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_cancel(wfd_session_s *session, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	int res = 0;

	if (!session || !session->peer) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	if (memcmp(peer_addr, session->peer->dev_addr, MACADDR_LEN)) {
		WDS_LOGE("Peer is not included in this session");
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	if (manager->local->dev_role == WFD_DEV_ROLE_GO && session->state > SESSION_STATE_GO_NEG)
		res = wfd_oem_wps_cancel(manager->oem_ops);
	else
		res = wfd_oem_cancel_connection(manager->oem_ops, peer_addr);

	if (res < 0) {
		WDS_LOGE("Failed to cancel connection");
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	wfd_destroy_session(manager);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_reject(wfd_session_s *session, unsigned char *peer_addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_device_s *peer = NULL;
	int res = 0;

	if (!session || !manager) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	/* Invite received case state is just created */
	if (session->state < SESSION_STATE_CREATED ||
		session->state >= SESSION_STATE_STOPPED) {
		WDS_LOGE("Session state is Invalid [%d]", session->state);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	/*
	 * TODO: check session status and do proper work
	 * for example, reject prov_disc, reject nego, stop wps, etc.
	 *
	 */

	peer = session->peer;

	if (SESSION_TYPE_INVITE == session->type || SESSION_TYPE_JOIN == session->type)
		res = wfd_oem_wps_cancel(manager->oem_ops);
	else
		res = wfd_oem_reject_connection(manager->oem_ops, peer->dev_addr);
	if (res < 0) {
		WDS_LOGE("Failed to reject connection");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	wfd_destroy_session(manager);
	// TODO: send notification to App

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_join(wfd_session_s *session)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_oem_conn_param_s param;
	wfd_device_s *peer = NULL;
	int res = 0;

	if (!session) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	session->state = SESSION_STATE_WPS;
	peer = session->peer;

	memset(&param, 0x00, sizeof(wfd_oem_conn_param_s));
	param.wps_mode = session->wps_mode;
	if (peer->dev_role == WFD_DEV_ROLE_GO)
		param.conn_flags |= WFD_OEM_CONN_TYPE_JOIN;
	param.go_intent = session->go_intent;
	param.freq = session->freq;
	g_strlcpy(param.wps_pin, session->wps_pin, OEM_PINSTR_LEN + 1);

	res = wfd_oem_connect(manager->oem_ops, peer->dev_addr, &param);
	if (res < 0) {
		WDS_LOGD("Failed to join with peer [" MACSECSTR "]", MAC2SECSTR(peer->dev_addr));
		wfd_destroy_session(manager);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	wfd_session_timer(session, 1);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_invite(wfd_session_s *session)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_oem_invite_param_s param;
	wfd_device_s *peer = NULL;
	wfd_group_s *group = NULL;
	int res = 0;

	if (!session) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (session->state > SESSION_STATE_CREATED) {
		WDS_LOGE("Invalid session state(%d)", session->state);
		return -1;
	}

	peer = session->peer;
	group = (wfd_group_s*) manager->group;

	memset(&param, 0x00, sizeof(wfd_oem_invite_param_s));
	param.ifname = strdup(group->ifname);
	memcpy(param.go_dev_addr, group->go_dev_addr, MACADDR_LEN);

	WDS_LOGD("Invite: Peer[" MACSTR "], GO Addr[" MACSTR "]",
				MAC2STR(peer->dev_addr), MAC2STR(param.go_dev_addr));

	res = wfd_oem_invite(manager->oem_ops, peer->dev_addr, &param);
	if (res < 0) {
		WDS_LOGE("Failed to invite with peer [" MACSECSTR "]", MAC2SECSTR(peer->dev_addr));
		wfd_destroy_session(manager);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	wfd_session_timer(session, 1);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_wps(wfd_session_s *session)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_device_s *peer = NULL;
	int res = 0;

	if (!session) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (session->state > SESSION_STATE_WPS) {
		WDS_LOGE("Session already starts WPS");
		return -1;
	}

	session->state = SESSION_STATE_WPS;
	peer = session->peer;

	if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
		WDS_LOGD("My device is GO, so WPS will be started. WPS mode[%d]", session->wps_mode);
		res = wfd_oem_wps_start(manager->oem_ops, peer->dev_addr, session->wps_mode, session->wps_pin);
	} else {
		WDS_LOGD("My device is not GO, so Enrollee will be started. WPS mode[%d]", session->wps_mode);
		wfd_oem_conn_param_s param;
		memset(&param, 0x00, sizeof(wfd_oem_conn_param_s));
		param.wps_mode = session->wps_mode;
		param.conn_flags |= WFD_OEM_CONN_TYPE_JOIN;
		param.freq = session->freq;	// currently not used
		g_strlcpy(param.wps_pin, session->wps_pin, OEM_PINSTR_LEN + 1);
		res = wfd_oem_connect(manager->oem_ops, peer->dev_addr, &param);
	}
	if (res < 0) {
		WDS_LOGE("Failed to start wps with peer [" MACSECSTR "]", MAC2SECSTR(peer->dev_addr));
		wfd_destroy_session(manager);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

wfd_device_s *wfd_session_get_peer(wfd_session_s *session)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *peer = NULL;

	if (!session) {
		WDS_LOGE("Invalid parameter");
		return NULL;
	}

	peer = session->peer;

	__WDS_LOG_FUNC_EXIT__;
	return peer;
}

unsigned char *wfd_session_get_peer_addr(wfd_session_s *session)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *peer = NULL;

	if (!session || !session->peer) {
		WDS_LOGE("Invalid parameter");
		return NULL;
	}

	peer = session->peer;

	__WDS_LOG_FUNC_EXIT__;
	return peer->dev_addr;
}

#if 0
int wfd_session_get_wps_pin(wfd_session_s *session, unsigned char *pin)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_set_wps_pin(wfd_session_s *session, unsigned char *pin)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_set_freq(wfd_session_s *session, int freq)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_get_state(wfd_session_s *session)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_session_set_state(wfd_session_s *session, int state)
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
#endif

int wfd_session_process_event(wfd_manager_s *manager, wfd_oem_event_s *event)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_session_s *session = NULL;
	int res = 0;

	if (!manager || !event) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	WDS_LOGD("event ID [%d]", event->event_id);
	session = manager->session;

	switch (event->event_id) {
	case WFD_OEM_EVENT_PROV_DISC_REQ:
	{
		int req_wps_mode = WFD_WPS_MODE_NONE;

		if (event->wps_mode == WFD_WPS_MODE_DISPLAY) {
			req_wps_mode = WFD_WPS_MODE_KEYPAD;
		} else if (event->wps_mode == WFD_WPS_MODE_KEYPAD) {
			req_wps_mode = WFD_WPS_MODE_DISPLAY;
		} else {
			req_wps_mode = WFD_WPS_MODE_PBC;
		}

		/* Only peer initiated connection or invitation session can be allowed */
		if (session) {
			if (session->type != SESSION_TYPE_INVITE) {
				WDS_LOGE("Unexpected event. Session is exist [peer: " MACSECSTR "]",
								MAC2SECSTR(event->dev_addr));
				break;
			}
			WDS_LOGD("=====> session already exist. (invitation session)");
			session->req_wps_mode = req_wps_mode;
			session->wps_mode = event->wps_mode;
		} else {
			session = wfd_create_session(manager, event->dev_addr,
								req_wps_mode, SESSION_DIRECTION_INCOMING);
			if (!session) {
				WDS_LOGE("Failed to create session with peer [" MACSECSTR "]",
								MAC2SECSTR(event->dev_addr));
				break;
			}
		}

		/* Update session */
		if (event->wps_mode == WFD_WPS_MODE_DISPLAY) {
			g_strlcpy(session->wps_pin, event->wps_pin, PINSTR_LEN + 1);
		}
		session->state = SESSION_STATE_STARTED;
		if (session->type == SESSION_TYPE_INVITE) {
			WDS_LOGD("Invitation session");
		} else if (WFD_DEV_ROLE_GO == manager->local->dev_role) {
			session->type = SESSION_TYPE_JOIN;
		} else {
			session->type = SESSION_TYPE_NORMAL;
		}
		wfd_session_timer(session, 1);

		/* Update local device */
		manager->local->wps_mode = event->wps_mode;

		wfd_state_set(manager, WIFI_DIRECT_STATE_CONNECTING);

		if (session->type == SESSION_TYPE_INVITE) {
			WDS_LOGD("Start WPS corresponding to OEM event [%d]", event->event_id);
			if (session->wps_mode != WFD_WPS_MODE_PBC) {
				wifi_direct_client_noti_s noti;
				memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
				noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ;
				g_snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(event->dev_addr));
				wfd_client_send_event(manager, &noti);
				if (session->wps_mode == WFD_WPS_MODE_KEYPAD) {
					/* We have to wait until user type PIN using Keypad */
					break;
				}
			}
			res = wfd_session_wps(session);
			if (res < 0)
				_wfd_notify_session_failed(manager, event->dev_addr);
		} else {
			wifi_direct_client_noti_s noti;
			memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ;
			noti.error = WIFI_DIRECT_ERROR_NONE;
			snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(event->dev_addr));
			wfd_client_send_event(manager, &noti);
		}
	}
	break;
	case WFD_OEM_EVENT_PROV_DISC_RESP:
	{
		if (!session) {		// TODO: check validity of Event
			WDS_LOGE("Unexpected event. Session is NULL [peer: " MACSECSTR "]",
										MAC2SECSTR(event->dev_addr));
			break;
		}

		if (session->state > SESSION_STATE_STARTED) {
			WDS_LOGE("Unexpected event. Session is already started");
			break;
		}

		if (session->type == SESSION_TYPE_INVITE) {
			WDS_LOGE("Session type is invite, ignore provision discovery response");
			break;
		}

		/* Update session */
		session->wps_mode = event->wps_mode;
		if (event->wps_mode == WFD_WPS_MODE_DISPLAY) {
			session->req_wps_mode = WFD_WPS_MODE_KEYPAD;
			g_strlcpy(session->wps_pin, event->wps_pin, PINSTR_LEN + 1);
		} else if (event->wps_mode == WFD_WPS_MODE_KEYPAD) {
			session->req_wps_mode = WFD_WPS_MODE_DISPLAY;
		} else {
			session->req_wps_mode = WFD_WPS_MODE_PBC;
		}
		session->state = SESSION_STATE_STARTED;
		wfd_session_timer(session, 1);

		/* Update local device */
		manager->local->wps_mode = event->wps_mode;
		WDS_LOGD("Local WPS mode is %d", session->wps_mode);

		if (session->wps_mode != WFD_WPS_MODE_PBC) {
			wifi_direct_client_noti_s noti;
			memset(&noti, 0x0, sizeof(wifi_direct_client_noti_s));
			noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ;
			g_snprintf(noti.param1, sizeof(noti.param1), MACSTR, MAC2STR(event->dev_addr));
			wfd_client_send_event(manager, &noti);
			if (session->wps_mode == WFD_WPS_MODE_KEYPAD) {
				/* We have to wait until user type PIN using Keypad */
				break;
			}
		}

		if (manager->local->dev_role == WFD_DEV_ROLE_GO) {
			WDS_LOGD("Start WPS corresponding to OEM event [%d]", event->event_id);
			res = wfd_session_wps(session);
		} else if (session->peer->dev_role == WFD_DEV_ROLE_GO) {
			WDS_LOGD("Start WPS(join) corresponding to OEM event [%d]", event->event_id);
			res = wfd_session_join(session);
		} else {
			WDS_LOGD("Start connection corresponding to OEM event [%d]", event->event_id);
			res = wfd_session_connect(session);
		}
	}
	if (res < 0)
		_wfd_notify_session_failed(manager, event->dev_addr);
	break;
	case WFD_OEM_EVENT_GO_NEG_REQ:
		if (!session) {
			// TODO: check whether connection is started by negotiation not by prov_disc
			WDS_LOGE("Unexpected event. Session not exist [peer: " MACSECSTR "]",
						MAC2SECSTR(event->dev_addr));
			break;
		} else {
			/* Sometimes, Provision Discovery response is not received.
			 * At this time, connection should be triggered by GO Negotiation request event */
			if (session->direction == SESSION_DIRECTION_OUTGOING) {
				res = wfd_session_connect(session);
			} else {
				/* In autoconnection mode, MT should not send GO Nego Req
				   before receving the GO Nego Req from peer (MO). */
				if (manager->autoconnection == TRUE)
					res  = wfd_session_connect(session);
			}
			if (res < 0)
				_wfd_notify_session_failed(manager, event->dev_addr);
		}
		break;
	case WFD_OEM_EVENT_GO_NEG_DONE:
		if (!session) {
			WDS_LOGE("Unexpected event. Session is NULL [peer: " MACSECSTR "]",
						MAC2SECSTR(event->dev_addr));
			break;
		} else {
			session->state = SESSION_STATE_WPS;
		}

		break;
	case WFD_OEM_EVENT_WPS_DONE:
		if (!session) {
			WDS_LOGE("Unexpected event. Session is NULL [peer: " MACSECSTR "]",
						MAC2SECSTR(event->dev_addr));
			break;
		} else {
			session->state = SESSION_STATE_KEY_NEG;
		}

		break;
	case WFD_OEM_EVENT_CONNECTED:
	{
		if (!session) {
			WDS_LOGE("Unexpected event. Session is NULL [peer: " MACSECSTR "]",
						MAC2SECSTR(event->dev_addr));
			break;
		} else {
			wfd_group_s *group = manager->group;
			if (!group) {
				group = wfd_create_pending_group(manager, event->intf_addr);
				if (!group) {
					WDS_LOGE("Failed to create pending group");
					break;
				}
				manager->group = group;
			} else {	// multiconnection, additional client connected
				WDS_LOGE("Unexpected event. Group already exist");
				//wfd_group_add_member(manager, event->intf_addr, peer->dev_addr);
				break;
			}
			session->state = SESSION_STATE_COMPLETED;
		}
	}
	break;
	case WFD_OEM_EVENT_STA_CONNECTED:
		if (!session) {
			WDS_LOGE("Unexpected event. Session is NULL [peer: " MACSECSTR "]",
						MAC2SECSTR(event->dev_addr));
			break;
		} else {
			session->state = SESSION_STATE_COMPLETED;
		}

		break;
	default:
		break;
	}
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
