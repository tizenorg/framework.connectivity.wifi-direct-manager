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
 * This file declares wifi direct client functions and structures.
 *
 * @file		wifi-direct-client.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_CLIENT_H__
#define __WIFI_DIRECT_CLIENT_H__

#define WFD_SERVER_SOCK_PATH "/tmp/wfd_client_socket"
#define WFD_SERVER_SOCK_MODE (S_IRWXU | S_IRWXG | S_IRWXO)
#define WFD_MAX_CLIENT 16
#define WFD_CLIENT_PENDING_SOCKET -999

#define SOCK_FD_MIN 3
#define WFD_POLL_TIMEOUT 2000

typedef struct {
	int ssock;
	int asock;
	int client_id;
	int gsource_id;
} wfd_client_s;

int wfd_client_handler_deinit(wfd_manager_s *manager);
int wfd_client_handler_init(wfd_manager_s *manager);
int wfd_client_send_event(wfd_manager_s *manager, wifi_direct_client_noti_s *noti);

#endif /* __WIFI_DIRECT_CLIENT_H__ */
