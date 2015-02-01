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
 * This file declares wifi direct session functions and structures.
 *
 * @file		wifi-direct-session.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_SESSION_H__
#define __WIFI_DIRECT_SESSION_H__

typedef enum {
	SESSION_TYPE_NORMAL,
	SESSION_TYPE_INVITE,
	SESSION_TYPE_JOIN,
	SESSION_TYPE_MULTI,
} session_type_e;

typedef enum {
	SESSION_STATE_CREATED,
	SESSION_STATE_STARTED,
	SESSION_STATE_GO_NEG,
	SESSION_STATE_WPS,
	SESSION_STATE_KEY_NEG,
	SESSION_STATE_COMPLETED,
	SESSION_STATE_STOPPED,
} session_state_e;

typedef enum {
	SESSION_DIRECTION_INCOMING,
	SESSION_DIRECTION_OUTGOING,
} session_direction_e;

typedef struct {
	int type;
	int state;
	int timer;
	int connecting_120;
	unsigned int retry_gsrc;
	int direction;
	wfd_device_s *peer;
	int wps_mode;
	int req_wps_mode;
	int go_intent;
	int freq;
	char wps_pin[PINSTR_LEN+1];
} wfd_session_s;

wfd_session_s *wfd_create_session(void *data, unsigned char *peer_addr, int wps_mode, int direction);
int wfd_destroy_session(void *data);
int wfd_session_start(wfd_session_s *session);
int wfd_session_connect(wfd_session_s *session);
int wfd_session_cancel(wfd_session_s *session, unsigned char *peer_addr);
int wfd_session_reject(wfd_session_s *session, unsigned char *peer_addr);
int wfd_session_wps(wfd_session_s *session);
int wfd_session_invite(wfd_session_s *session);
int wfd_session_join(wfd_session_s *session);
wfd_device_s *wfd_session_get_peer(wfd_session_s *session);
unsigned char *wfd_session_get_peer_addr(wfd_session_s *session);
#if 0
int wfd_session_get_state(wfd_session_s *session);
int wfd_session_stop(wfd_session_s *session);
#endif
int wfd_session_complete(wfd_session_s *session);
int wfd_session_timer(wfd_session_s *session, int start);

int wfd_session_process_event(wfd_manager_s *manager, wfd_oem_event_s *event);

#endif /* __WIFI_DIRECT_SESSION_H__ */
