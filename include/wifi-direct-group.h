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
 * This file declares wifi direct group functions and structures.
 *
 * @file		wifi-direct-group.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_GROUP_H__
#define __WIFI_DIRECT_GROUP_H__

#define IFACE_NAME_LEN 16

typedef enum {
	WFD_GROUP_FLAG_NONE,
	WFD_GROUP_FLAG_PERSISTENT,
	WFD_GROUP_FLAG_AUTONOMOUS,
} wfd_group_flag_e;

typedef struct {
	int pending;
	char ifname[IFACE_NAME_LEN+1];
	char ssid[DEV_NAME_LEN+1];
	unsigned char bssid[MACADDR_LEN];
	unsigned char go_dev_addr[MACADDR_LEN];
	int flags;		// Autonomous, Persistent
	int role;		// local device role
	int freq;		// MHz
	GList *members;
	int member_count;
	char passphrase[PASSPHRASE_LEN_MAX + 1];
} wfd_group_s;


wfd_group_s *wfd_create_group(void *data, wfd_oem_event_s *group_info);
wfd_group_s *wfd_create_pending_group(void *data, unsigned char * bssid);
int wfd_group_complete(void *data, wfd_oem_event_s *group_info);
int wfd_destroy_group(void * data, char *ifname);
int wfd_group_add_member(wfd_group_s *group, unsigned char *addr);
int wfd_group_remove_member(wfd_group_s *group, unsigned char *addr);
#if 0
int wfd_group_get_channel(wfd_group_s *group);
int wfd_group_get_flags(wfd_group_s *group);
int wfd_group_get_members();
int wfd_group_make_persistent();
#endif
int wfd_group_is_autonomous(wfd_group_s *group);
wfd_device_s *wfd_group_find_member_by_addr(wfd_group_s *group, unsigned char *addr);

#endif /* __WIFI_DIRECT_GROUP_H__ */
