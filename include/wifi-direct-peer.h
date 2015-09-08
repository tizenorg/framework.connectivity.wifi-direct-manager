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
 * This file declares wifi direct peer functions.
 *
 * @file		wifi-direct-peer.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_PEER_H__
#define __WIFI_DIRECT_PEER_H__


wfd_device_s *wfd_add_peer(void *data, unsigned char *dev_addr, char *dev_name);
int wfd_remove_peer(void *data, unsigned char *dev_addr);
int wfd_update_peer(void *data, wfd_device_s *peer);
int wfd_update_peer_time(void*data, unsigned char *peer_addr);
int wfd_peer_clear_all(void *data);
wfd_device_s *wfd_peer_find_by_dev_addr(void *data, unsigned char *dev_addr);
#if 0
wfd_device_s *wfd_peer_find_by_intf_addr(void *data, unsigned char *intf_addr);
wfd_device_s *wfd_peer_find_current_peer(void *data);
int wfd_peer_get_data(unsigned char *dev_addr, int type, int data);
int wfd_peer_set_data(unsigned char *dev_addr, int type, int data);
#endif
wfd_device_s *wfd_peer_find_by_addr(void *data, unsigned char *addr);
#endif /* __WIFI_DIRECT_PEER_H__ */
