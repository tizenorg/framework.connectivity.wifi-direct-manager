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

#ifndef __WIFI_DIRECT_STUB_H_
#define __WIFI_DIRECT_STUB_H_

#include "wifi-direct-internal.h"
#include "wifi-direct-utils.h"

int wfd_server_is_fd_writable(int fd);
bool wfd_server_register_client(int sockfd);
void wfd_server_process_client_request(wifi_direct_client_request_s * client_req);
void wfd_server_reset_client(int sync_sockfd);
void wfd_server_print_client();
int wfd_server_read_socket_event(int sockfd, char* dataptr, int datalen);

#endif		//__WIFI_DIRECT_STUB_H_

