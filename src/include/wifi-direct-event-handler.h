/*
 * Network Configuration Module
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd. All rights reserved.
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

#ifndef __WIFI_DIRECT_EVENT_HANDLER_H_
#define __WIFI_DIRECT_EVENT_HANDLER_H_

/**
 * @enum wfd_event_t
 * Wi-Fi Direct event
 */
typedef enum {
	WFD_EVENT_INVALID = -1,
	WFD_EVENT_DISCOVER_START_80211_SCAN,
	WFD_EVENT_DISCOVER_START_SEARCH_LISTEN,
	WFD_EVENT_DISCOVER_FOUND_PEERS,
	WFD_EVENT_DISCOVER_FOUND_P2P_GROUPS,
	WFD_EVENT_DISCOVER_CANCEL,
	WFD_EVENT_DISCOVER_COMPLETE,
	WFD_EVENT_DISCOVER_FAIL,
	WFD_EVENT_DISCOVER_RESUMED,
	WFD_EVENT_DISCOVER_SUSPENDED,
	WFD_EVENT_DISCOVER_START_LISTEN_ONLY,

	WFD_EVENT_PROV_DISCOVERY_REQUEST,
	WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_DISPLAY,
	WFD_EVENT_PROV_DISCOVERY_REQUEST_WPS_KEYPAD,
	WFD_EVENT_PROV_DISCOVERY_RESPONSE,
	WFD_EVENT_PROV_DISCOVERY_TIMEOUT,
	WFD_EVENT_PROV_DISCOVERY_RESPONSE_WPS_DISPLAY,
	WFD_EVENT_PROV_DISCOVERY_RESPONSE_WPS_KEYPAD,

	WFD_EVENT_INVITE_REQUEST,
	WFD_EVENT_INVITE_RESPONSE,

	WFD_EVENT_GROUP_OWNER_NEGOTIATION_START,
	WFD_EVENT_GROUP_OWNER_NEGOTIATION_AP_ACK,
	WFD_EVENT_GROUP_OWNER_NEGOTIATION_STA_ACK,
	WFD_EVENT_GROUP_OWNER_NEGOTIATION_REQUEST_RECEIVED,
	WFD_EVENT_GROUP_OWNER_NEGOTIATION_COMPLETE,
	WFD_EVENT_GROUP_OWNER_NEGOTIATION_ALREADY_CONNECTED,
	WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL,
	WFD_EVENT_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO,
	WFD_EVENT_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL,
	WFD_EVENT_GROUP_OWNER_NEGOTIATION_FAIL_INTENT,
	WFD_EVENT_CREATE_LINK_START,
	WFD_EVENT_CREATE_LINK_CANCEL,
	WFD_EVENT_CREATE_LINK_DOWN,
	WFD_EVENT_CREATE_LINK_TIMEOUT,
	WFD_EVENT_CREATE_LINK_AUTH_FAIL,
	WFD_EVENT_CREATE_LINK_FAIL,
	WFD_EVENT_CREATE_LINK_COMPLETE,

	WFD_EVENT_IP_ASSIGNED,
	WFD_EVENT_IP_LEASED,
	
	WFD_EVENT_CONNECT_PBC_START,

	WFD_EVENT_SOFTAP_START,
	WFD_EVENT_SOFTAP_READY,
	WFD_EVENT_SOFTAP_STA_ASSOC,
	WFD_EVENT_SOFTAP_STA_DISASSOC,
	WFD_EVENT_SOFTAP_FAIL,
	WFD_EVENT_SOFTAP_STOP,

	WFD_EVENT_WPS_START,
	WFD_EVENT_WPS_STATUS_SCANNING,
	WFD_EVENT_WPS_STATUS_SCANNING_OVER,
	WFD_EVENT_WPS_STATUS_ASSOCIATING,
	WFD_EVENT_WPS_STATUS_ASSOCIATED,
	WFD_EVENT_WPS_STATUS_WPS_MSG_EXCHANGE,
	WFD_EVENT_WPS_STATUS_DISCONNECTING,
	WFD_EVENT_WPS_PROTOCOL_FAIL,
	WFD_EVENT_WPS_FAIL,
	WFD_EVENT_WPS_WRONG_PIN,
	WFD_EVENT_WPS_TIMEOUT,
	WFD_EVENT_WPS_SESSION_OVERLAP,
	WFD_EVENT_WPS_COMPLETE,

	WFD_EVENT_PRIMARY_IF_DISCONNECTION,
	WFD_EVENT_SVC_REQ_RECEIVED,
	WFD_EVENT_SVC_RESP_RECEIVED,
	WFD_EVENT_SVC_COMEBACK_REQ_RECEIVED,
	WFD_EVENT_SVC_COMEBACK_RESP_RECEIVED,
	WFD_EVENT_DEV_DISCOVERABILITY_REQ,
	WFD_EVENT_DEV_DISCOVERABILITY_RSP,
	WFD_EVENT_GO_DISCOVERABILITY_REQ,

	WFD_EVENT_MAX,
} wfd_event_t;

typedef void (*wfd_oem_event_cb) (wfd_event_t event);

#endif 			//__WIFI_DIRECT_EVENT_HANDLER_H_

