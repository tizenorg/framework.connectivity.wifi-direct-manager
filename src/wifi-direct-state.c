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
 * This file implements wifi direct state functions.
 *
 * @file		wifi-direct-state.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <glib.h>
#include <wifi-direct.h>

#include "wifi-direct-ipc.h"
#include "wifi-direct-manager.h"
#include "wifi-direct-state.h"
#include "wifi-direct-util.h"

static char *_wfd_state_string(int state)
{
	switch (state) {
		case WIFI_DIRECT_STATE_DEACTIVATED:
			return "DEACTIVATED";
		case WIFI_DIRECT_STATE_DEACTIVATING:
			return "DEACTIVATING";
		case WIFI_DIRECT_STATE_ACTIVATING:
			return "ACTIVATING";
		case WIFI_DIRECT_STATE_ACTIVATED:
			return "ACTIVATED";
		case WIFI_DIRECT_STATE_DISCOVERING:
			return "DISCOVERING";
		case WIFI_DIRECT_STATE_CONNECTING:
			return "CONNECTING";
		case WIFI_DIRECT_STATE_DISCONNECTING:
			return "DISCONNECTING";
		case WIFI_DIRECT_STATE_CONNECTED:
			return "CONNECTED";
		case WIFI_DIRECT_STATE_GROUP_OWNER:
			return "GROUP_OWNER";
		default:
			return "Unknown State";
	}
	
}

int wfd_state_set(wfd_manager_s *manager, int state)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!manager || state < WIFI_DIRECT_STATE_DEACTIVATED || state > WIFI_DIRECT_STATE_GROUP_OWNER) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	WDS_LOGI("wifi-direct-manager state set [%s] -> [%s]",
				_wfd_state_string(manager->state), _wfd_state_string(state));

	manager->state = state;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_state_get(wfd_manager_s *manager, int *state)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!manager || !state) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	*state = manager->state;
	WDS_LOGD("wifi-direct-manager state is %d", *state);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
