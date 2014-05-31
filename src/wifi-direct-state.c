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

#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "vconf-keys.h"

#include "wifi-direct-service.h"
#include "wifi-direct-utils.h"

#include <app_service.h>

int wfd_server_check_valid(wifi_direct_cmd_e cmd)
{
	int state;
	int valid = false;
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	__WDS_LOG_FUNC_ENTER__;

	state = wfd_server->state;
	switch (cmd)
	{
	case WIFI_DIRECT_CMD_ACTIVATE:
		{
			if (state == WIFI_DIRECT_STATE_DEACTIVATED)
				valid = true;
			else
				valid = false;
		}
		break;
	case WIFI_DIRECT_CMD_DEACTIVATE:
		{
			if (state == WIFI_DIRECT_STATE_DEACTIVATED ||
				state == WIFI_DIRECT_STATE_DEACTIVATING ||
				state == WIFI_DIRECT_STATE_ACTIVATING)
				valid = false;
			else
				valid = true;
		}
		break;
	case WIFI_DIRECT_CMD_START_DISCOVERY:
	case WIFI_DIRECT_CMD_CANCEL_DISCOVERY:
		{
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING ||
				state == WIFI_DIRECT_STATE_CONNECTED ||
				state == WIFI_DIRECT_STATE_GROUP_OWNER)
				valid = true;
			else
				valid = false;
		}
		break;
	case WIFI_DIRECT_CMD_CONNECT:
		{
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING ||
				state == WIFI_DIRECT_STATE_GROUP_OWNER)
				valid = true;
			else
				valid = false;
		}
		break;
	case WIFI_DIRECT_CMD_CREATE_GROUP:
		{
			if (state == WIFI_DIRECT_STATE_ACTIVATED ||
				state == WIFI_DIRECT_STATE_DISCOVERING)
				valid = true;
			else
				valid = false;
		}
		break;
	case WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON:
	case WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE:
	case WIFI_DIRECT_CMD_GET_GO_INTENT:
	case WIFI_DIRECT_CMD_SET_GO_INTENT:
	case WIFI_DIRECT_CMD_IS_DISCOVERABLE:
	case WIFI_DIRECT_CMD_IS_LISTENING_ONLY:
	case WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL:
	case WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO:
	case WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP:
		{
			if (state == WIFI_DIRECT_STATE_DEACTIVATED ||
				state == WIFI_DIRECT_STATE_DEACTIVATING ||
				state == WIFI_DIRECT_STATE_ACTIVATING)
				valid = false;
			else
				valid = true;
		}
		break;

	case WIFI_DIRECT_CMD_CANCEL_GROUP:
		{
			if (state == WIFI_DIRECT_STATE_GROUP_OWNER)
				valid = true;
			else if ((state == WIFI_DIRECT_STATE_CONNECTING) && (wfd_server->autonomous_group_owner == true))
				valid = true;
			else
				valid = false;
		}
		break;

	case WIFI_DIRECT_CMD_DISCONNECT:
		{
			if (state == WIFI_DIRECT_STATE_GROUP_OWNER ||
				state == WIFI_DIRECT_STATE_CONNECTED ||
				state == WIFI_DIRECT_STATE_CONNECTING)
				valid = true;
			else
				valid = false;
		}
		break;

	case WIFI_DIRECT_CMD_GET_SSID:
		{
			if (state < WIFI_DIRECT_STATE_CONNECTED)
				valid = false;
			else
				valid = true;
		}
		break;

	default:
		valid = true;
		break;
	}

	__WDS_LOG_FUNC_EXIT__;

	return valid;
}

#if 0
void start_wifi_direct_service()
{
	__WDS_LOG_FUNC_ENTER__;

	//system("launch_app org.tizen.fileshare-service");
	service_h service;
	service_create(&service);
	service_set_operation(service, SERVICE_OPERATION_DEFAULT);
	service_set_package(service, "org.tizen.fileshare-service");
	service_send_launch_request(service, NULL, NULL);
	service_destroy(service);

	__WDS_LOG_FUNC_EXIT__;
	
}
#endif

void stop_wifi_direct_service()
{
	// 2012-01-04: Dongwook. Let ftm-serviced quit by itself for gracefull termination.
	// system("killall ftm-serviced");
}

void start_wifi_direct_ui_appl()
{
	__WDS_LOG_FUNC_ENTER__;

	//system("launch_app org.tizen.wifi-direct-popup");
	service_h service;
	service_create(&service);
	service_set_operation(service, SERVICE_OPERATION_DEFAULT);
	service_set_package(service, "org.tizen.wifi-direct-popup");
	service_send_launch_request(service, NULL, NULL);
	service_destroy(service);

	__WDS_LOG_FUNC_EXIT__;

}


void stop_wifi_direct_ui_appl()
{
	// 2012-02-24: Dongwook. Let wifi-direct-popup quit by itself for gracefull termination.
	// system("killall wifi-direct-popup");
}



void wfd_server_set_state(int state)
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	__WDS_LOG_FUNC_ENTER__;

	if (state < WIFI_DIRECT_STATE_DEACTIVATED
		|| state > WIFI_DIRECT_STATE_GROUP_OWNER)
	{
		WDS_LOGF( "Error : Invalid State\n");
		return;
	}

	WDS_LOGF( "State Change: [%d,%s] ---->[%d,%s]\n",
				   wfd_server->state, wfd_print_state(wfd_server->state),
				   state, wfd_print_state(state));

	if (wfd_server->state != WIFI_DIRECT_STATE_CONNECTING &&
		state == WIFI_DIRECT_STATE_CONNECTING)
	{

		// stop timer for discover
		wfd_timer_discovery_cancel();

		// start timer for connection
		wfd_timer_connection_start();
	}
#if 0
	if (wfd_server->state < WIFI_DIRECT_STATE_CONNECTED &&
		state >= WIFI_DIRECT_STATE_CONNECTED)
	{
		start_wifi_direct_service();
	}
#endif
	if (wfd_server->state == WIFI_DIRECT_STATE_CONNECTING &&
		state != WIFI_DIRECT_STATE_CONNECTING)
	{
		// stop timer for connection
		wfd_timer_connection_cancel();
	}

	if (wfd_server->state >= WIFI_DIRECT_STATE_CONNECTED &&
		state < WIFI_DIRECT_STATE_CONNECTED)
	{
		stop_wifi_direct_service();
	}

	if (wfd_server->state != WIFI_DIRECT_STATE_DEACTIVATED &&
		state == WIFI_DIRECT_STATE_DEACTIVATED)
	{
		wfd_termination_timer_start();
		wfd_timer_discovery_cancel();
	}
	else
	{
		wfd_termination_timer_cancel();
	}

	if (wfd_server->state < WIFI_DIRECT_STATE_ACTIVATED &&
		state == WIFI_DIRECT_STATE_ACTIVATED)
	{
		start_wifi_direct_ui_appl();
	}

	// Reset autonomous group owner flag
	if (wfd_server->state == WIFI_DIRECT_STATE_GROUP_OWNER &&
		state != WIFI_DIRECT_STATE_GROUP_OWNER && state != WIFI_DIRECT_STATE_CONNECTING)
	{
		if (wfd_server->autonomous_group_owner == true)
		{
			WDS_LOGD( "[Reset autonomous group owner flag]\n");
			wfd_server->autonomous_group_owner = false;
		}
	}


	wfd_server->state = state;

#if 0
	// Check discovery state...
	if (state == WIFI_DIRECT_STATE_ACTIVATED
		&& wfd_oem_is_discovery_enabled() == true)
	{
		WDS_LOGD( "state is changed to [WIFI_DIRECT_STATE_DISCOVERING]\n");
		wfd_server->state = WIFI_DIRECT_STATE_DISCOVERING;
	}
#endif

	switch (wfd_server->state)
	{
		//if (wfd_check_wifi_direct_state() < 0)
		//WDS_LOGF( "wfd_check_wifi_direct_state() failed\n");

	case WIFI_DIRECT_STATE_DEACTIVATED:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_DEACTIVATED) < 0)
				WDS_LOGF( "wfd_set_wifi_direct_state() failed\n");
			else
				stop_wifi_direct_ui_appl();
		}
		break;

	case WIFI_DIRECT_STATE_ACTIVATED:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_ACTIVATED) < 0)
				WDS_LOGF( "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	case WIFI_DIRECT_STATE_DISCOVERING:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_DISCOVERING) < 0)
				WDS_LOGF( "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	case WIFI_DIRECT_STATE_CONNECTED:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_CONNECTED) < 0)
				WDS_LOGF( "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	case WIFI_DIRECT_STATE_GROUP_OWNER:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_GROUP_OWNER) < 0)
				WDS_LOGF( "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	// for Net-Config can check the status of wifi-direct 
	case WIFI_DIRECT_STATE_ACTIVATING:
		{
			if (wfd_set_wifi_direct_state(VCONFKEY_WIFI_DIRECT_ACTIVATED) < 0)
				WDS_LOGF( "wfd_set_wifi_direct_state() failed\n");
		}
		break;

	default:
		break;
	}

	__WDS_LOG_FUNC_EXIT__;

	return;
}

int wfd_server_get_state()
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	return wfd_server->state;
}
