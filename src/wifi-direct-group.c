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
 * This file implements wifi direct group functions.
 *
 * @file		wifi-direct-group.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <glib.h>

#include <wifi-direct.h>

#include "wifi-direct-ipc.h"
#include "wifi-direct-manager.h"
#include "wifi-direct-state.h"
#include "wifi-direct-peer.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-group.h"
#include "wifi-direct-util.h"
#include "wifi-direct-session.h"
#include "wifi-direct-client.h"

// Check the group instance which has same interface name, before using this function
wfd_group_s *wfd_create_group(void *data, wfd_oem_event_s *group_info)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = NULL;
	wfd_manager_s *manager = (wfd_manager_s*) data;

	if (!manager || !group_info) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}
	wfd_oem_group_data_s *edata = (wfd_oem_group_data_s *)group_info->edata;

	if (!edata) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	group = manager->group;
	if (group) {
		WDS_LOGE("Group already exist");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	errno = 0;
	group = (wfd_group_s*) calloc(1, sizeof(wfd_group_s));
	if (!group) {
		WDS_LOGE("Failed to allocate memory for group. [%s]", strerror(errno));
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	memcpy(group->ifname, group_info->ifname, IFACE_NAME_LEN);
	group->ifname[IFACE_NAME_LEN] = '\0';
	group->role = group_info->dev_role;
	memcpy(group->go_dev_addr, edata->go_dev_addr, MACADDR_LEN);
	group->pending = 0;

	g_strlcpy(group->ssid, edata->ssid, DEV_NAME_LEN + 1);
	g_strlcpy(group->passphrase, edata->pass, PASSPHRASE_LEN_MAX + 1);
	memset(manager->local->passphrase, 0x0, PASSPHRASE_LEN_MAX + 1);
	group->freq = edata->freq;

	manager->group = group;
	manager->local->dev_role = group_info->dev_role;

	wfd_util_dhcps_start();
	WDS_LOGD("Role is Group Owner. DHCP Server started");

	__WDS_LOG_FUNC_EXIT__;
	return group;
}

// Used for CTRL-EVENT_CONNECTED event that comes before group created
wfd_group_s *wfd_create_pending_group(void *data, unsigned char * bssid)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = NULL;
	wfd_manager_s *manager = (wfd_manager_s*) data;

	if (!manager || !bssid) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	group = manager->group;
	if (group) {
		WDS_LOGE("Group already exist");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	errno = 0;
	group = (wfd_group_s*) g_try_malloc0(sizeof(wfd_group_s));
	if (!group) {
		WDS_LOGE("Failed to allocate memory for group. [%s]", strerror(errno));
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	memcpy(group->bssid, bssid, MACADDR_LEN);
	group->pending = 1;

	__WDS_LOG_FUNC_EXIT__;
	return group;
}

int wfd_group_complete(void *data, wfd_oem_event_s *group_info)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	wfd_session_s *session = NULL;
	wfd_group_s *group = NULL;
	wfd_device_s *peer = NULL;

	if (!manager || !group_info) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	wfd_oem_group_data_s *edata = (wfd_oem_group_data_s *)group_info->edata;

	if (!edata) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	group = manager->group;
	if (!group) {
		WDS_LOGE("Group not found");
		return -1;
	}

	if (!group->pending) {
		WDS_LOGE("This is not pending group");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	g_strlcpy(group->ifname, group_info->ifname, IFACE_NAME_LEN + 1);
	group->role = group_info->dev_role;
	memcpy(group->go_dev_addr, edata->go_dev_addr, MACADDR_LEN);
	group->pending = 0;

	g_strlcpy(group->ssid, edata->ssid, DEV_NAME_LEN + 1);
	g_strlcpy(group->passphrase, edata->pass, PASSPHRASE_LEN_MAX + 1);
	memset(manager->local->passphrase, 0x0, PASSPHRASE_LEN_MAX + 1);
	group->freq = edata->freq;

	manager->local->dev_role = group_info->dev_role;

	session = manager->session;
	peer = wfd_session_get_peer(session);
	if (!peer && !(group->flags & WFD_GROUP_FLAG_AUTONOMOUS)) {
		WDS_LOGD("Failed to find peer by device address[" MACSECSTR "]",
						MAC2SECSTR(edata->go_dev_addr));
		return -1;
	}

	if (group->role == WFD_DEV_ROLE_GO) {
		wfd_util_dhcps_start();
		WDS_LOGD("Role is Group Owner. DHCP Server started");
	} else {
#ifdef CTRL_IFACE_DBUS
		WDS_LOGD("Role is Group Client.complete session and add peer to member");
		if (peer) {
			memcpy(peer->intf_addr, group->go_dev_addr, MACADDR_LEN);
			wfd_group_add_member(group, peer->dev_addr);
			session->state = SESSION_STATE_COMPLETED;
			/* memcpy(peer->intf_addr, event->intf_addr, MACADDR_LEN); */
			peer->state = WFD_PEER_STATE_CONNECTED;
			if(edata->ip_addr[3] && edata->ip_addr_go[3]) {
				peer->ip_type = WFD_IP_TYPE_OVER_EAPOL;
				memcpy(peer->client_ip_addr, edata->ip_addr, IPADDR_LEN);
				WDS_LOGE("Peer's client IP [" IPSTR "]", IP2STR((char*) &peer->client_ip_addr));
				memcpy(peer->go_ip_addr, edata->ip_addr_go, IPADDR_LEN);
				WDS_LOGE("Peer's GO IP [" IPSTR "]", IP2STR((char*) &peer->go_ip_addr));
			}
		}
		if(peer && peer->ip_type != WFD_IP_TYPE_OVER_EAPOL)
#endif /* CTRL_IFACE_DBUS */
		wfd_util_dhcpc_start(peer);
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_destroy_group(void *data, char *ifname)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_group_s *group = NULL;
	wfd_manager_s *manager = (wfd_manager_s*) data;
	GList *temp = NULL;
	wfd_device_s *member = NULL;
	int count = 0;

	if (!data || !ifname) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	group = manager->group;
	if (!group) {
		WDS_LOGE("Group not exist");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	manager->group = NULL;

	if (group->role == WFD_DEV_ROLE_GO)
		wfd_util_dhcps_stop();
	else
		wfd_util_dhcpc_stop();
	memset(manager->local->ip_addr, 0x0, IPADDR_LEN);

	temp = g_list_first(group->members);
	while(temp && count < group->member_count) {
		member = temp->data;
		WDS_LOGD("%dth member[%s] will be removed", count, member->dev_name);
		g_free(member);
		member = NULL;
		temp = g_list_next(temp);
		count++;
	}

	if (group->members) {
		g_list_free(group->members);
		group->members = NULL;
	}

	g_free(group);

	manager->local->dev_role = WFD_DEV_ROLE_NONE;
	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

#if 0
int wfd_group_get_channel(wfd_group_s *group)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!group) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDS_LOG_FUNC_EXIT__;
	return group->freq;
}
#endif

int wfd_group_is_autonomous(wfd_group_s *group)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!group) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDS_LOG_FUNC_EXIT__;
	return ((group->flags & WFD_GROUP_FLAG_AUTONOMOUS) == WFD_GROUP_FLAG_AUTONOMOUS);
}

#if 0
int wfd_group_get_members()
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_group_make_persistent()
{
	__WDS_LOG_FUNC_ENTER__;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_group_get_flags(wfd_group_s *group)
{
	__WDS_LOG_FUNC_ENTER__;

	if (!group) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDS_LOG_FUNC_EXIT__;
	return group->flags;
}
#endif

wfd_device_s *wfd_group_find_member_by_addr(wfd_group_s *group, unsigned char *addr)
{
	__WDS_LOG_FUNC_ENTER__;
	GList *temp = NULL;
	wfd_device_s *member = NULL;

	if (!group || !addr) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	if (!group->member_count) {
		WDS_LOGE("There is no members");
		__WDS_LOG_FUNC_EXIT__;
		return NULL;
	}

	temp = g_list_first(group->members);
	while (temp) {
		member = temp->data;
		if (!memcmp(member->intf_addr, addr, MACADDR_LEN) ||
				!memcmp(member->dev_addr, addr, MACADDR_LEN)) {
			WDS_LOGD("Member found");
			break;
		}
		temp = g_list_next(temp);
		member = NULL;
	}

	__WDS_LOG_FUNC_EXIT__;
	return member;
}

int wfd_group_add_member(wfd_group_s *group, unsigned char *addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *member = NULL;
	wfd_manager_s *manager = wfd_get_manager();

	if (!group || !addr) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	member = wfd_group_find_member_by_addr(group, addr);
	if (member) {
		WDS_LOGE("Member already exist");
		return -1;
	}

	member = wfd_peer_find_by_addr(manager, addr);
	if (!member) {
		WDS_LOGE("Peer not found");
	}

	group->members = g_list_prepend(group->members, member);
	group->member_count++;

	manager->peers = g_list_remove(manager->peers, member);
	manager->peer_count--;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_group_remove_member(wfd_group_s *group, unsigned char *addr)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_device_s *member = NULL;

	if (!group || !addr) {
		WDS_LOGE("Invalid parameter");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	if (group->member_count == 0) {
		WDS_LOGE("There is no members");
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	member = wfd_group_find_member_by_addr(group, addr);
	if (!member) {
		WDS_LOGD("Member not found [MAC: " MACSECSTR "]",
						MAC2SECSTR(addr));
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	group->members = g_list_remove(group->members, member);
	g_free(member);
	group->member_count--;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}
