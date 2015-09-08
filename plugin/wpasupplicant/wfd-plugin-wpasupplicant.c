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
 * This file implements wifi direct wpasupplicant plugin functions.
 *
 * @file		wfd_plugin_wpasupplicant.c
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <poll.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "wifi-direct-oem.h"
#include "wfd-plugin-wpasupplicant.h"

#define NETCONFIG_SERVICE				"net.netconfig"
#define NETCONFIG_WIFI_INTERFACE		"net.netconfig.wifi"
#define NETCONFIG_WIFI_PATH				"/net/netconfig/wifi"

#define NETCONFIG_DBUS_REPLY_TIMEOUT	(10 * 1000)

ws_string_s ws_event_strs[] = {
	// discovery
	{"P2P-DEVICE-FOUND", WS_EVENT_DEVICE_FOUND},
	{"P2P-DEVICE-LOST", WS_EVENT_DEVICE_LOST},
	{"P2P-FIND-STOPPED", WS_EVENT_FIND_STOPED},

	// provision discovery
	{"P2P-PROV-DISC-PBC-REQ", WS_EVENT_PROV_DISC_PBC_REQ},
	{"P2P-PROV-DISC-SHOW-PIN", WS_EVENT_PROV_DISC_SHOW_PIN},
	{"P2P-PROV-DISC-ENTER-PIN", WS_EVENT_PROV_DISC_ENTER_PIN},
	{"P2P-PROV-DISC-PBC-RESP", WS_EVENT_PROV_DISC_PBC_RESP},
	{"P2P-PROV-DISC-FAILURE", WS_EVENT_PROV_DISC_FAILURE},

	// connection
	{"P2P-GO-NEG-REQUEST", WS_EVENT_GO_NEG_REQUEST},
	{"P2P-GO-NEG-FAILURE", WS_EVENT_GO_NEG_FAILURE},
	{"P2P-GO-NEG-SUCCESS", WS_EVENT_GO_NEG_SUCCESS},
	{"WPS-FAIL", WS_EVENT_WPS_FAIL},
	{"P2P-GROUP-FORMATION-FAILURE", WS_EVENT_GROUP_FORMATION_FAILURE},
	{"WPS-SUCCESS", WS_EVENT_WPS_SUCCESS},
	{"WPS-REG-SUCCESS", WS_EVENT_WPS_REG_SUCCESS},
	{"P2P-GROUP-FORMATION-SUCCESS", WS_EVENT_GROUP_FORMATION_SUCCESS},

	{"CTRL-EVENT-CONNECTED", WS_EVENT_CONNECTED},
	{"AP-STA-CONNECTED", WS_EVENT_STA_CONNECTED},

	// invite
	{"P2P-INVITATION-RECEIVED", WS_EVENT_INVITATION_RECEIVED},
	{"P2P-INVITATION-RESULT", WS_EVENT_INVITATION_RESULT},

	{"CTRL-EVENT-DISCONNECTED", WS_EVENT_DISCONNECTED},
	{"AP-STA-DISCONNECTED", WS_EVENT_STA_DISCONNECTED},

	// group
	{"P2P-GROUP-STARTED", WS_EVENT_GROUP_STARTED},
	{"P2P-GROUP-REMOVED", WS_EVENT_GROUP_REMOVED},

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	{"P2P-SERV-DISC-RESP", WS_EVENT_SERV_DISC_RESP},
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

	{"CTRL-EVENT-TERMINATING", WS_EVENT_TERMINATING},

	};

ws_string_s ws_dev_info_strs[] = {
	{"p2p_dev_addr", WS_DEV_INFO_P2P_DEV_ADDR},
	{"name", WS_DEV_INFO_DEV_NAME},
	{"pri_dev_type", WS_DEV_INFO_DEV_TYPE},
	{"config_methods", WS_DEV_INFO_CONFIG_METHODS},
	{"dev_capab", WS_DEV_INFO_DEV_CAP},
	{"group_capab", WS_DEV_INFO_GROUP_CAP},
	{"p2p_go_addr", WS_DEV_INFO_P2P_GO_ADDR},
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	{"wfd_dev_info", WS_DEV_INFO_WFD_DEV_INFO},
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
	{"", WS_DEV_INFO_LIMIT},
	};

ws_string_s ws_conn_info_strs[] = {
	{"dev_passwd_id", WS_CONN_INFO_DEV_PWD_ID},
	{"status", WS_CONN_INFO_STATUS},
	{"config_error", WS_CONN_INFO_ERROR},
	{"", WS_CONN_INFO_LIMIT},
	};

ws_string_s ws_invite_info_strs[] = {
	{"sa", WS_INVITE_INFO_SRC_ADDR},
	{"go_dev_addr", WS_INVITE_INFO_GO_DEV_ADDR},
	{"bssid", WS_INVITE_INFO_BSSID},
	{"listen", WS_INVITE_INFO_LISTEN},
	{"status", WS_INVITE_INFO_STATUS},
	{"", WS_INVITE_INFO_LIMIT},
	};

ws_string_s ws_group_info_strs[] = {
	{"ssid", WS_GROUP_INFO_SSID},
	{"freq", WS_GROUP_INFO_FREQ},
	{"passphrase", WS_GROUP_INFO_PASS},
	{"go_dev_addr", WS_GROUP_INFO_GO_DEV_ADDR},
	{"status", WS_GROUP_INFO_STATUS},
	{"", WS_GROUP_INFO_LIMIT},

	};

ws_string_s ws_peer_info_strs[] = {
	{"age", WS_PEER_INFO_AGE},
	{"listen_freq", WS_PEER_INFO_LISTEN_FREQ},
	{"level", WS_PEER_INFO_LEVEL},
	{"wps_method", WS_PEER_INFO_WPS_METHOD},
	{"interface_addr", WS_PEER_INFO_INTERFACE_ADDR},
	{"member_in_go_dev", WS_PEER_INFO_MEMBER_IN_GO_DEV},
	{"member_in_go_iface", WS_PEER_INFO_MEMBER_IN_GO_IFACE},
	{"pri_dev_type", WS_PEER_INFO_PRI_DEV_TYPE},
	{"device_name", WS_PEER_INFO_DEVICE_NAME},
	{"manufacturer", WS_PEER_INFO_MANUFACTURER},
	{"model_name", WS_PEER_INFO_MODEL_NAME},
	{"model_number", WS_PEER_INFO_MODEL_NUMBER},
	{"serial_number", WS_PEER_INFO_SERIAL_NUMBER},
	{"config_methods", WS_PEER_INFO_CONFIG_METHODS},
	{"dev_capab", WS_PEER_INFO_DEV_CAPAB},
	{"group_capab", WS_PEER_INFO_GROUP_CAPAB},
	{"go_neg_req_sent", WS_PEER_INFO_GO_NEG_REQ_SENT},
	{"go_state", WS_PEER_INFO_GO_STATE},
	{"dialog_token", WS_PEER_INFO_DIALOG_TOKEN},
	{"intended_addr", WS_PEER_INFO_INTENDED_ADDR},
	{"country", WS_PEER_INFO_COUNTRY},
	{"oper_freq", WS_PEER_INFO_OPER_FREQ},
	{"req_config_methods", WS_PEER_INFO_REQ_CONFIG_METHODS},
	{"flags", WS_PEER_INFO_FLAGS},
	{"status", WS_PEER_INFO_STATUS},
	{"wait_count", WS_PEER_INFO_WAIT_COUNT},
	{"invitation_reqs", WS_PEER_INFO_INVITATION_REQS},
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	{"wfd_subelems", WS_PEER_INFO_WFD_SUBELEMS},
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
	};

static wfd_oem_ops_s supplicant_ops = {
	.init = ws_init,
	.deinit = ws_deinit,
	.activate = ws_activate,
	.deactivate = ws_deactivate,

	.start_scan = ws_start_scan,
	.stop_scan = ws_stop_scan,
	.get_visibility = ws_get_visibility,
	.set_visibility = ws_set_visibility,
	.get_scan_result = ws_get_scan_result,
	.get_peer_info = ws_get_peer_info,

	.prov_disc_req = ws_prov_disc_req,

	.connect = ws_connect,
	.disconnect = ws_disconnect,
	.reject_connection = ws_reject_connection,
	.cancel_connection = ws_cancel_connection,

	.get_connected_peers = ws_get_connected_peers,
	.get_pin = ws_get_pin,
	.set_pin = ws_set_pin,
	.get_supported_wps_mode = ws_get_supported_wps_mode,

	.create_group = ws_create_group,
	.destroy_group = ws_destroy_group,
	.invite = ws_invite,
	.wps_start = ws_wps_start,
	.enrollee_start = ws_enrollee_start,
	.wps_cancel = ws_wps_cancel,

	.get_dev_name = ws_get_dev_name,
	.set_dev_name = ws_set_dev_name,
	.get_dev_mac = ws_get_dev_mac,
	.get_dev_type = ws_get_dev_type,
	.set_dev_type = ws_set_dev_type,
	.get_go_intent = ws_get_go_intent,
	.set_go_intent = ws_set_go_intent,
	.set_country = ws_set_country,
	.get_persistent_groups = ws_get_persistent_groups,
	.remove_persistent_group = ws_remove_persistent_group,
	.set_persistent_reconnect = ws_set_persistent_reconnect,

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	.register_local_service = ws_register_local_service,
	.deregister_local_service = ws_deregister_local_service,
	.start_service_discovery = ws_start_service_discovery,
	.cancel_service_discovery = ws_cancel_service_discovery,

	.serv_add = ws_serv_add,
	.serv_del = ws_serv_del,
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
	.miracast_init = ws_miracast_init,
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

	.refresh = ws_refresh,

	};

static ws_plugin_data_s *g_pd;

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
static GList *service_list;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

static gboolean ws_event_handler(GIOChannel *source,
							   GIOCondition condition,
							   gpointer data);

int wfd_plugin_load(wfd_oem_ops_s **ops)
{
	if (!ops) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	*ops = &supplicant_ops;

	return 0;
}

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
static int _change_str_order(char *src, int length, int unit, char *dest)
{
	int i = 0;

	if (!src || length < 0 || length < unit || !dest) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	for (i=0; i<length/unit; i++)
		memcpy(dest + length - (i+1)*unit, src + i*unit, unit);

	return 0;
}

static int _string_to_hexstring(char *dest, char *source)
{
	if (dest == NULL || source == NULL)
		return 0;

	int i = 0;
	int len = strlen(source);

	while(i < len) {
		char temp[3] = {0, };
		sprintf(temp, "%x", source[i]);
		strncat(dest, temp, 2);
		i++;
	}

	if(i != len)
		return 0;

	return 1;
}

static int _ws_hex_to_num(char *src, int len)
{
	char *temp = NULL;
	int num = 0;

	if (!src || len < 0) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	temp = (char*) g_try_malloc0(len+1);
	if (!temp) {
		WDP_LOGE("Failed to allocate memory");
		return -1;
	}

	memcpy(temp, src, len);
	num = strtoul(temp, NULL, 16);
	free(temp);

	return num;
}

static int _ws_hex_to_txt(char *src, int length, char *dest)
{
	// TODO: check it is good to change dest parameter as double pointer.
	// It could be better to allocate memory for dest parameter here.
	char *temp = NULL;
	char *ptr = NULL;
	int len = 0;
	int i = 0;

	if (!src || length < 0 || !dest) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	// TODO: flush destination memory

	ptr = src;
	temp = dest;

	if (!length)
		len = strlen(src);
	else
		len = length;

	for (i=0; i<len/2 && *ptr!=0; i++) {
		temp[i] = (char) _ws_hex_to_num(ptr, 2);
		if (temp[i] < 0) {
			WDP_LOGE("Failed to convert hexa string to num");
			return -1;
		}
		ptr += 2;
	}

	return 0;
}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

static int _ws_txt_to_devtype(char *txt, int *pri, int *sec)
{
	if (!txt || !pri || !sec) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (strlen(txt) > WS_DEVTYPESTR_LEN) {
		WDP_LOGE("Device type string is invalid [%s]", txt);
		return -1;
	}

	*pri = (int) strtoul(txt, &txt, 0);
	txt = strrchr(txt, '-');
	*sec = (int) strtoul(txt+1, &txt, 16);

	return 0;
}

static int _ws_txt_to_mac(char *txt, unsigned char *mac)
{
	int i = 0;

	if (!txt || !mac) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	for (;;) {
		mac[i++] = (char) strtoul(txt, &txt, 16);
		if (!*txt++ || i == 6)
			break;
	}

	if (i != OEM_MACADDR_LEN)
		return -1;

	return 0;
}

static char *_ws_wps_to_txt(int wps_mode)
{
	switch (wps_mode) {
	case WFD_OEM_WPS_MODE_PBC:
		return WS_STR_PBC;
		break;
	case WFD_OEM_WPS_MODE_DISPLAY:
		return WS_STR_DISPLAY;
		break;
	case WFD_OEM_WPS_MODE_KEYPAD:
		return WS_STR_KEYPAD;
		break;
	default:
		return "";
		break;
	}
}

static int _ws_freq_to_channel(int freq)
{
	if (freq < 2412 || freq > 5825) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (freq >= 5180)
		return 36 + (freq - 5180)/5;
	else if (freq <= 2472)
		return 1 + (freq - 2412)/5;
	else if (freq == 2484)
		return 14;
	else
		return -1;
}

gboolean _ws_util_execute_file(const char *file_path,
	char *const args[], char *const envs[])
{
	pid_t pid = 0;
	int rv = 0;
	errno = 0;
	register unsigned int index = 0;

	while (args[index] != NULL) {
		WDP_LOGD("[%s]", args[index]);
		index++;
	}

	if (!(pid = fork())) {
		WDP_LOGD("pid(%d), ppid(%d)", getpid(), getppid());
		WDP_LOGD("Inside child, exec (%s) command", file_path);

		errno = 0;
		if (execve(file_path, args, envs) == -1) {
			WDP_LOGE("Fail to execute command (%s)", strerror(errno));
			exit(1);
		}
	} else if (pid > 0) {
		if (waitpid(pid, &rv, 0) == -1)
			WDP_LOGD("wait pid (%u) rv (%d)", pid, rv);
		if (WIFEXITED(rv)) {
			WDP_LOGD("exited, rv=%d", WEXITSTATUS(rv));
		} else if (WIFSIGNALED(rv)) {
			WDP_LOGD("killed by signal %d", WTERMSIG(rv));
		} else if (WIFSTOPPED(rv)) {
			WDP_LOGD("stopped by signal %d", WSTOPSIG(rv));
		} else if (WIFCONTINUED(rv)) {
			WDP_LOGD("continued");
		}

		return TRUE;
	}

	WDP_LOGE("failed to fork (%s)", strerror(errno));
	return FALSE;
}

static int _ws_check_socket(int sock)
{
	struct pollfd p_fd;
	int res = 0;

	p_fd.fd = sock;
	p_fd.events = POLLIN | POLLOUT | POLLERR | POLLHUP | POLLNVAL;
	res = poll((struct pollfd *) &p_fd, 1, 1);

	if (res < 0) {
		WDP_LOGE("Polling error from socket[%d]. [%s]", sock, strerror(errno));
		return -1;
	} else if (res == 0) {
		WDP_LOGD( "poll timeout. socket is busy\n");
		return 1;
	} else {

		if (p_fd.revents & POLLERR) {
			WDP_LOGE("Error! POLLERR from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLHUP) {
			WDP_LOGE("Error! POLLHUP from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLNVAL) {
			WDP_LOGE("Error! POLLNVAL from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLIN) {
			WDP_LOGD("POLLIN from socket [%d]", sock);
			return 0;
		} else if (p_fd.revents & POLLOUT) {
			WDP_LOGD("POLLOUT from socket [%d]", sock);
			return 0;
		}
	}

	WDP_LOGD("Unknown poll event [%d]", p_fd.revents);
	return -1;
}

static int _ws_read_sock(int sock, char *data, int data_len)
{
	__WDP_LOG_FUNC_ENTER__;
	struct pollfd p_fd;
	int p_ret = 0;
	int rbytes = 0;

	if(sock < SOCK_FD_MIN || !data || data_len <= 0) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	p_fd.fd = sock;
	p_fd.events = POLLIN | POLLERR | POLLHUP;
	p_ret = poll(&p_fd, 1, WS_POLL_TIMEOUT);

	errno = 0;
	if (p_ret > 0) {
		if (p_fd.revents & POLLIN) {
			WDP_LOGD("POLLIN from socket [%d]", sock);
			errno = 0;
			rbytes = read(sock, data, data_len);
			if (rbytes < 0) {
				WDP_LOGE("Failed to read data from socket[%d]. [%s]", sock, strerror(errno));
				return -1;
			}
			data[data_len-1] = '\0';
			__WDP_LOG_FUNC_EXIT__;
			return rbytes;
		} else if (p_fd.revents & POLLERR) {
			WDP_LOGE("Error! POLLERR from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLHUP) {
			WDP_LOGE("Error! POLLHUP from socket[%d]", sock);
			return -1;
		}
	} else if (p_ret == 0) {
		WDP_LOGE("Polling timeout from socket[%d]", sock);
	} else {
		WDP_LOGE("Polling error from socket[%d]. [%s]", sock, strerror(errno));
	}

	__WDP_LOG_FUNC_EXIT__;
	return -1;
}

static int _ws_send_cmd(int sock, char *cmd, char *reply, int reply_len)
{
	__WDP_LOG_FUNC_ENTER__;
	int wbytes = 0;
	int res = 0;

	if (sock < SOCK_FD_MIN || !cmd || !reply || reply_len < 0) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	WDP_SECLOG("Sending command [%s]", cmd);

	res = _ws_check_socket(sock);
	if (res < 0) {
		WDP_LOGE("Socket error");
		return -1;
	} else if (res > 0) {
		WDP_LOGE("Socket is busy");
		return -2;
	}

	errno = 0;
	wbytes = write(sock, cmd, strlen(cmd));
	if (wbytes < 0) {
		WDP_LOGE("Failed to write into socket[%d]. [%s]", sock, strerror(errno));
		return -1;
	}

	res = _ws_read_sock(sock, reply, reply_len);
	if (res < 0) {
		WDP_LOGE("Failed to read return for command");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static int _ws_flush()
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char reply[1024]={0,};
	int res = 0;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	res = _ws_send_cmd(sock->ctrl_sock, WS_CMD_P2P_FLUSH, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to flush");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to flush");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static int _ws_cancel()
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char reply[1024]={0,};
	int res = 0;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	res = _ws_send_cmd(sock->ctrl_sock, WS_CMD_P2P_CANCEL, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to cancel");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to cancel");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static int _create_ctrl_intf(char *ctrl_intf_path, char *supp_path)
{
	__WDP_LOG_FUNC_ENTER__;
	struct sockaddr_un srv_addr;
	struct sockaddr_un local_addr;
	int sock = 0;
	int res = 0;

	if(!ctrl_intf_path || !supp_path) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}
	unlink(ctrl_intf_path);

	errno = 0;
	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock < SOCK_FD_MIN) {
		WDP_LOGE("Failed to create socket. [%s]", strerror(errno));
		if (sock >= 0)
			close(sock);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGI( "Succeeded to create socket [%d]\n", sock);

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sun_family = AF_UNIX;
	snprintf(srv_addr.sun_path, sizeof(srv_addr.sun_path), "%s", supp_path);

	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sun_family = AF_UNIX;
	snprintf(local_addr.sun_path, sizeof(local_addr.sun_path), "%s", ctrl_intf_path);

	res = bind(sock, (struct sockaddr*) &local_addr, sizeof(local_addr));
	if (res < 0)
	{
		WDP_LOGE("Failed to bind local socket [%s]. Try again...", strerror(errno));
		unlink(ctrl_intf_path);

		close(sock);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	res = connect(sock, (struct sockaddr*) &srv_addr, sizeof(srv_addr));
	if (res < 0) {
		WDP_LOGE("Failed to connect to server socket [%s]", strerror(errno));
		close(sock);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGI("Succeeded to connect to server socket [%d]", sock);

	__WDP_LOG_FUNC_EXIT__;
	return sock;
}

static int _attach_mon_intf(int sock)
{
	__WDP_LOG_FUNC_ENTER__;
	char cmd[8] = {0};
	char reply[8]={0,};
	int res= 0;

	if (sock < SOCK_FD_MIN) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_ATTACH);
	res = _ws_send_cmd(sock, cmd, reply,  sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
	 	__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE( "Failed to operate command(wpa_supplicant)");
	 	__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static int _connect_to_supplicant(char *ifname, ws_sock_data_s **sock_data)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = NULL;
	int ctrl_sock = -1;
	int mon_sock = -1;
	char ctrl_path[32] = {0, };
	char mon_path[32] = {0, };
	char suppl_path[40] = {0, };
	int res = 0;
	int i = 0;

	if (!ifname || !sock_data) {
		WDP_LOGE("Invalie parameter");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	sock = (ws_sock_data_s*) g_try_malloc0(sizeof(ws_sock_data_s));
	if (!sock) {
		WDP_LOGE("Failed to allocate memory for socket data", strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	snprintf(ctrl_path, sizeof(ctrl_path), "/tmp/%s_control", ifname);
	snprintf(mon_path, sizeof(mon_path), "/tmp/%s_monitor", ifname);
	if (strncmp(ifname, GROUP_IFACE_NAME, 11))
		snprintf(suppl_path, sizeof(suppl_path), SUPPL_IFACE_PATH "%s", ifname);
	else
		snprintf(suppl_path, sizeof(suppl_path), SUPPL_GROUP_IFACE_PATH "%s", ifname);


	for(i = 0; i < WS_CONN_RETRY_COUNT; i++) {
		ctrl_sock = _create_ctrl_intf(ctrl_path, suppl_path);
		if (ctrl_sock < SOCK_FD_MIN) {
			WDP_LOGE("Failed to create control interface socket for %s", ifname);
			continue;
		}
		WDP_LOGD("Succeeded to create control interface socket[%d] for %s", ctrl_sock, ifname);

		mon_sock = _create_ctrl_intf(mon_path, suppl_path);
		if (mon_sock < SOCK_FD_MIN) {
			WDP_LOGE("Failed to create monitor interface socket for %s", ifname);
			close(ctrl_sock);
			ctrl_sock = -1;
			continue;
		}
		WDP_LOGD("Succeeded to create monitor interface socket[%d] for %s", mon_sock, ifname);

		res = _attach_mon_intf(mon_sock);
		if (res < 0) {
			WDP_LOGE("Failed to attach monitor interface for event");
			close(ctrl_sock);
			ctrl_sock = -1;
			close(mon_sock);
			mon_sock = -1;
			continue;
		}
		WDP_LOGD("Succeeded to attach monitor interface for event");
		break;
	}

	if (i == WS_CONN_RETRY_COUNT) {
		if (ctrl_sock >= 0)
			close(ctrl_sock);
		if (mon_sock >= 0)
			close(mon_sock);

		free(sock);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	sock->ctrl_sock = ctrl_sock;
	sock->mon_sock = mon_sock;
	sock->ifname = strdup(ifname);

	GIOChannel *gio;
	int gsource = 0;
	gio = g_io_channel_unix_new(mon_sock);
	if (!strstr(ifname, GROUP_IFACE_PREFIX))
		gsource = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP, (GIOFunc) ws_event_handler, sock);
	g_io_channel_unref(gio);

	sock->gsource = gsource;

	*sock_data = sock;
	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static gboolean _remove_event_source(gpointer data)
{
	__WDP_LOG_FUNC_ENTER__;
	int source_id = (int) data;
	int res = 0;

	if (source_id < 0) {
		WDP_LOGE("Invalid source ID [%d]", source_id);
		return FALSE;
	}

	res = g_source_remove(source_id);
	if (!res) {
		WDP_LOGE("Failed to remove GSource(%d)", source_id);
		return FALSE;
	}
	WDP_LOGD("Succeeded to remove GSource");

	__WDP_LOG_FUNC_EXIT__;
	return FALSE;
}

static int _disconnect_from_supplicant(char *ifname, ws_sock_data_s *sock_data)
{
	__WDP_LOG_FUNC_ENTER__;
	int res = 0;
	char ctrl_path[32] = {0, };
	char mon_path[32] = {0, };
	char cmd[8] = {0, };
	char reply[1024] = {0, };

	if (!ifname || !sock_data) {
		WDP_LOGE("Invalie parameter");
		return -1;
	}

	// detach monitor interface
	snprintf(cmd, sizeof(cmd), WS_CMD_DETACH);
	res = _ws_send_cmd(sock_data->mon_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant. Keep going to close socket.");
	} else {
		if (!strncmp(reply, "FAIL", 4)) {
			WDP_LOGE( "Failed to detach monitor sock [%d]", sock_data->mon_sock);
			// TODO: I think there is no need to exit
		 	__WDP_LOG_FUNC_EXIT__;
		 	return -1;
		}
		WDP_LOGD("Succeeded to detach monitor sock for %s", ifname ? ifname : "NULL");
	}

	if (sock_data->gsource > 0)
		g_idle_add(_remove_event_source, (gpointer) sock_data->gsource);
	sock_data->gsource = 0;

	// close control interface
	snprintf(ctrl_path, sizeof(ctrl_path), "/tmp/%s_control", ifname);
	snprintf(mon_path, sizeof(mon_path), "/tmp/%s_monitor", ifname);

	if (sock_data->ctrl_sock >= SOCK_FD_MIN)
		close(sock_data->ctrl_sock);
	sock_data->ctrl_sock = -1;
	unlink(ctrl_path);

	if (sock_data->mon_sock >= SOCK_FD_MIN)
		close(sock_data->mon_sock);
	sock_data->mon_sock = -1;
	unlink(mon_path);

	if (sock_data->ifname)
		free(sock_data->ifname);

	free(sock_data);

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
int _check_service_query_exists(wfd_oem_service_s *service)
{
	int count = 0;
	wfd_oem_service_s *data = NULL;

	for (count = 0; count < g_list_length(service_list); count ++) {
		data = (wfd_oem_service_s*) g_list_nth_data(service_list, count);
		if (strncmp(service->query_id, data->query_id, OEM_QUERY_ID_LEN) == 0) {
			WDP_LOGD("Query already exists");
			return 1;
		}
	}
	return 0;
}

static wfd_oem_service_s* _remove_service_query(char * s_type, char *mac_str, char *query_id)
{
	if (NULL == s_type || NULL == mac_str || NULL == query_id)
		return NULL;

	int count = 0;
	wfd_oem_service_s *data = NULL;

	for (count = 0; count < g_list_length(service_list); count ++) {
		data = (wfd_oem_service_s*) g_list_nth_data(service_list, count);
		if (data && !strncmp(data->service_type, s_type, SERVICE_TYPE_LEN) &&
				memcmp(data->dev_addr, mac_str, OEM_MACSTR_LEN - 1) == 0) {
			strncpy(query_id, data->query_id, OEM_QUERY_ID_LEN);
			break;
		}
	}
	if (strlen(query_id) <= 0) {
		WDP_LOGD("!! Query ID not found !!");
		return NULL;
	}

	WDP_LOGD("query id :[0x%s]",query_id);

	return data;

}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

static int _extract_word(const char *data, char **value)
{
	int i = 0;

	if(!data || !value) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	for(i = 0; data[i]; i++) {
		if(data[i] == '\n' || data[i] == '\r' || data[i] == ' ' || data[i] == '\t') {
			break;
		}
	}

	if (i > 0) {
		*value = (char*) g_try_malloc0 (i+1);
		if(!(*value)) {
			WDP_LOGE("Failed to allocate memory for value");
			return -1;
		}
		strncpy(*value, data, i);
		(*value)[i] = '\0';
		WDP_LOGV("Extracted word: %s", *value);
	}

	return i;
}

static int _extract_value_str(const char *data, const char *key, char **value)
{
	char *tmp_str = NULL;
	int i = 0;

	if(!data || !key || !value) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	tmp_str = strstr(data, key);
	if(!tmp_str) {
		WDP_LOGE("Key[%s] is not found", key);
		return -1;
	}
	tmp_str = tmp_str + strlen(key) + 1;

	if (tmp_str[0] == '\'' || tmp_str[0] == '\"') {
		tmp_str +=1;
		for(i = 0; tmp_str[i]; i++) {
			if(tmp_str[i] == '\'' || tmp_str[i] == '\"')
				break;
		}
	} else {
		for(i = 0; tmp_str[i]; i++) {
			if(tmp_str[i] == '\n' || tmp_str[i] == '\r' || tmp_str[i] == ' ')
				break;
		}
	}

	if (i > 0) {
		*value = (char*) g_try_malloc0(i+1);
		if(!(*value)) {
			WDP_LOGE("Failed to allocate memory for value");
			return -1;
		}
		strncpy(*value, tmp_str, i);
		(*value)[i] = '\0';
		WDP_LOGV("Extracted string: %s", *value);
		return i;
	}

	return 0;
}

static int _extract_peer_value_str(const char *data, const char *key, char **value)
{
	char *tmp_str = NULL;
	int i = 0;

	if(!data || !key || !value) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	tmp_str = strstr(data, key);
	if(!tmp_str) {
		WDP_LOGE("Key[%s] is not found", key);
		return -1;
	}
	tmp_str = tmp_str + strlen(key) + 1;

	for(i = 0; tmp_str[i]; i++) {
		if(tmp_str[i] == '\n' || tmp_str[i] == '\r')
			break;
	}

	if (i > 0) {
		*value = (char*) g_try_malloc0(i+1);
		if(!(*value)) {
			WDP_LOGE("Failed to allocate memory for value");
			return -1;
		}
		strncpy(*value, tmp_str, i);
		(*value)[i] = '\0';
		WDP_LOGV("Extracted string: %s", *value);
		return i;
	}

	return 0;
}

#if 0
static int _check_dev_type(unsigned char *dev_addr, int *pri_dev_type, int *sec_dev_type)
{
	ws_sock_data_s *sock = g_pd->common;
	char cmd[32] = {0, };
	char reply[1024] = {0,};
	char *manufacturer = NULL;
	char *model_name = NULL;
	char *model_number = NULL;
	int res = 0;

	if (!dev_addr || !pri_dev_type || !sec_dev_type) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_P2P_PEER MACSTR, MAC2STR(dev_addr));
	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_SECLOG("Failed to get peer info [" MACSTR "]", MAC2STR(dev_addr));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_SECLOG("Succeeded to get peer info [" MACSTR "]", MAC2STR(dev_addr));

	res = _extract_peer_value_str(reply, "model_number", &model_number);
	if (res > 0 && !strncmp(model_number, "EAD-T10", 7)) {
		*pri_dev_type = 8;
		*sec_dev_type = 5;
		free(model_number);
		WDP_LOGD("peer device type set as Dongle");
		return 0;
	}
	if (model_number)
		free(model_number);

	_extract_peer_value_str(reply, "manufacturer", &manufacturer);
	_extract_peer_value_str(reply, "model_name", &model_name);
	if (!manufacturer || !model_name) {
		WDP_LOGE("parsing error");
		if (manufacturer)
			free(manufacturer);
		if (model_name)
			free(model_name);
		return -1;
	}

	if (!strncmp(manufacturer, "SAMSUNG_ELECTRONICS", 19) &&
				!strncmp(model_name, "SAMSUNG_MOBILE", 14)) {
		*pri_dev_type = 8;
		*sec_dev_type = 4;
		WDP_LOGD("peer device type set as Homesync");
		free(manufacturer);
		free(model_name);
		return 0;
	}
	if (manufacturer)
		free(manufacturer);
	if (model_name)
		free(model_name);

	return -1;
}
#endif

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
wfd_oem_display_s *_parsing_display_info(char *msg)
{
	__WDP_LOG_FUNC_ENTER__;
	char *ptr = NULL;
	char id_str[3] = {0, };
	char length_str[5] = {0, };
	char wfd_info_str[5] = {0, };
	char port_str[5] = {0, };
	char max_tput_str[5] = {0, };
	int id = 0;
	int length = 0;
	int wfd_info = 0;
	wfd_oem_display_s *display = NULL;

	if (!msg || strlen(msg) < 6) {
		WDP_LOGE("Invalid parameter");
		return NULL;
	}

	/* 00 0006 015d 022a 0032 */
	WDP_LOGD("Message to parse: %s", msg);
	ptr = msg;
	while (ptr) {
		strncpy(id_str, ptr, 2);
		id = strtoul(id_str, NULL, 16);
		strncpy(length_str, ptr+2, 4);
		length = strtoul(length_str, NULL, 16);

		if (id == WFD_SUBELM_ID_DEV_INFO) {
			display = (wfd_oem_display_s*) g_try_malloc0(sizeof(wfd_oem_display_s));
			if(!display) {
				WDP_LOGE("Failed to allocate memory for display");
				return NULL;
			}

			strncpy(wfd_info_str, ptr+6, 4);
			WDP_LOGV("wfd_info [0x%s]", wfd_info_str);
			wfd_info = strtoul(wfd_info_str, NULL, 16);
			if (wfd_info & WS_WFD_INFO_PRIMARY_SINK)
				display->type |= WFD_OEM_DISPLAY_TYPE_PRISINK;
			if (wfd_info & WS_WFD_INFO_SECONDARY_SINK)
				display->type |= WFD_OEM_DISPLAY_TYPE_SECSINK;
			display->availablity = wfd_info & WS_WFD_INFO_AVAILABLITY;
			display->wsd_support = wfd_info & WS_WFD_INFO_WSD_SUPPORT;
			display->tdls_support = wfd_info & WS_WFD_INFO_TDLS_SUPPORT;
			display->hdcp_support = wfd_info & WS_WFD_INFO_HDCP_SUPPORT;
			display->sync_support = wfd_info & WS_WFD_INFO_SYNC_SUPPORT;

			strncpy(port_str, msg+10, 4);
			display->port =  strtoul(port_str, NULL, 16);

			strncpy(max_tput_str, msg+14, 4);
			display->max_tput =  strtoul(max_tput_str, NULL, 16);
			return display;
		}
		ptr = ptr + 6 + length*2;
	}

	__WDP_LOG_FUNC_EXIT__;
	return NULL;
}
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

static int _parsing_peer_info(char *msg, wfd_oem_device_s *peer)
{
	__WDP_LOG_FUNC_ENTER__;
	int i, info_cnt = 0;
	ws_string_s infos[WS_PEER_INFO_LIMIT];
	int config_methods = 0x00;
	int group_capab = 0x00;
	int res = 0;

	if (!msg || !peer) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	_ws_txt_to_mac(msg, peer->dev_addr);
	msg += OEM_MACSTR_LEN;

	memset(infos, 0x0, (WS_PEER_INFO_LIMIT) * sizeof(ws_string_s));
	for (i = 0; i < WS_PEER_INFO_LIMIT; i++) {
		res = _extract_peer_value_str(msg, ws_peer_info_strs[i].string, &infos[info_cnt].string);
		if (res > 0) {
			infos[info_cnt].index = ws_peer_info_strs[i].index;
			info_cnt++;
		}
	}

	for (i = 0; i < info_cnt; i++) {
		switch (infos[i].index){
		case WS_PEER_INFO_AGE:
			peer->age = (int) strtoul(infos[i].string, NULL, 10);
			break;
		case WS_PEER_INFO_LISTEN_FREQ:
			{
				int freq = 0;
				freq = (int) strtoul(infos[i].string, NULL, 10);
				peer->channel = _ws_freq_to_channel(freq);
			}
			break;
		case WS_PEER_INFO_LEVEL:
			break;
		case WS_PEER_INFO_WPS_METHOD:
			break;
		case WS_PEER_INFO_INTERFACE_ADDR:
			break;
		case WS_PEER_INFO_MEMBER_IN_GO_DEV:
			{
				res = _ws_txt_to_mac(infos[i].string, peer->go_dev_addr);
				if (res < 0)
					memset(peer->go_dev_addr, 0x00, OEM_MACADDR_LEN);

				unsigned char null_mac[OEM_MACADDR_LEN] = {0, 0, 0, 0, 0, 0};
				if (memcmp(peer->go_dev_addr, null_mac, OEM_MACADDR_LEN))
					peer->dev_role = WFD_OEM_DEV_ROLE_GC;
			}
			break;
		case WS_PEER_INFO_MEMBER_IN_GO_IFACE:
			break;
		case WS_PEER_INFO_PRI_DEV_TYPE:
			res = _ws_txt_to_devtype(infos[i].string, &peer->pri_dev_type, &peer->sec_dev_type);
			if (res < 0) {
				peer->pri_dev_type = 0;
				peer->sec_dev_type = 0;
			}
			break;
		case WS_PEER_INFO_DEVICE_NAME:
			strncpy(peer->dev_name, infos[i].string, OEM_DEV_NAME_LEN);
			peer->dev_name[OEM_DEV_NAME_LEN] = '\0';
			break;
		case WS_PEER_INFO_MANUFACTURER:
			break;
		case WS_PEER_INFO_MODEL_NAME:
			break;
		case WS_PEER_INFO_MODEL_NUMBER:
			break;
		case WS_PEER_INFO_SERIAL_NUMBER:
			break;
		case WS_PEER_INFO_CONFIG_METHODS:
			config_methods = (int) strtoul(infos[i].string, NULL, 16);
			if (config_methods & WS_CONFIG_METHOD_DISPLAY)
				peer->config_methods |= WFD_OEM_WPS_MODE_DISPLAY;
			if (config_methods & WS_CONFIG_METHOD_PUSHBUTTON)
				peer->config_methods |= WFD_OEM_WPS_MODE_PBC;
			if (config_methods & WS_CONFIG_METHOD_KEYPAD)
				peer->config_methods |= WFD_OEM_WPS_MODE_KEYPAD;
			break;
		case WS_PEER_INFO_DEV_CAPAB:
			peer->dev_flags = (int) strtoul(infos[i].string, NULL, 16);
			break;
		case WS_PEER_INFO_GROUP_CAPAB:
			group_capab = (int) strtoul(infos[i].string, NULL, 16);
			if (group_capab & WS_GROUP_CAP_GROUP_OWNER) {
				peer->group_flags = WFD_OEM_GROUP_FLAG_GROUP_OWNER;
				peer->dev_role = WFD_OEM_DEV_ROLE_GO;
			}
			if (group_capab & WS_GROUP_CAP_PERSISTENT_GROUP)
				peer->group_flags = WFD_OEM_GROUP_FLAG_PERSISTENT_GROUP;
			break;
		case WS_PEER_INFO_GO_NEG_REQ_SENT:
			break;
		case WS_PEER_INFO_GO_STATE:
			break;
		case WS_PEER_INFO_DIALOG_TOKEN:
			break;
		case WS_PEER_INFO_INTENDED_ADDR:
			res = _ws_txt_to_mac(infos[i].string, peer->intf_addr);
			if (res < 0)
				memset(peer->intf_addr, 0x00, OEM_MACADDR_LEN);
			break;
		case WS_PEER_INFO_COUNTRY:
			break;
		case WS_PEER_INFO_OPER_FREQ:
			break;
		case WS_PEER_INFO_REQ_CONFIG_METHODS:
			break;
		case WS_PEER_INFO_FLAGS:
			break;
		case WS_PEER_INFO_STATUS:
			break;
		case WS_PEER_INFO_WAIT_COUNT:
			break;
		case WS_PEER_INFO_INVITATION_REQS:
			break;
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
		case WS_PEER_INFO_WFD_SUBELEMS:
			peer->display = _parsing_display_info(infos[i].string);
#if 0
			/* workaround code: for Dongle and HomeSync */
			if (peer->display && peer->display->type == WFD_OEM_DISPLAY_TYPE_PRISINK)
				_check_dev_type(peer->dev_addr, &peer->pri_dev_type, &peer->sec_dev_type);
#endif
			break;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */
		default:
			break;
		}
	}

	for(i = 0; i < info_cnt; i++) {
		if (infos[i].string)
			free(infos[i].string);
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static wfd_oem_dev_data_s *_convert_msg_to_dev_info(char *msg)
{
	__WDP_LOG_FUNC_ENTER__;
	int i;
	int info_cnt = 0;
	ws_string_s infos[WS_DEV_INFO_LIMIT];
	wfd_oem_dev_data_s *edata = NULL;
	int config_methods = 0x00;
	int group_capab = 0x00;
	int res = 0;

	if (!msg) {
		WDP_LOGE("Invalid parameter");
		return NULL;
	}
	WDP_LOGD("msg to be converted [%s]", msg);

	memset(infos, 0x0, (WS_DEV_INFO_LIMIT) * sizeof(ws_string_s));
	for (i = 0; i < WS_DEV_INFO_LIMIT; i++) {
		res = _extract_value_str(msg, ws_dev_info_strs[i].string, &infos[info_cnt].string);
		if (res > 0) {
			infos[info_cnt].index = ws_dev_info_strs[i].index;
			WDP_LOGD("%dth info [%d:%s]", i, infos[info_cnt].index, infos[info_cnt].string);
			info_cnt++;
		}
	}

	if (!info_cnt) {
		WDP_LOGE("There is no item converted");
		return NULL;
	}

	errno = 0;
	edata = (wfd_oem_dev_data_s*) g_try_malloc0 (sizeof(wfd_oem_dev_data_s));
	if (!edata) {
		WDP_LOGE("Failed to allocate memory for device information [%s]", strerror(errno));
		return NULL;
	}

	for (i = 0; i < info_cnt; i++) {
		switch (infos[i].index) {
		case WS_DEV_INFO_P2P_DEV_ADDR:
			res = _ws_txt_to_mac(infos[i].string, edata->p2p_dev_addr);
			if (res < 0)
				memset(edata->p2p_dev_addr, 0x00, OEM_MACADDR_LEN);
			break;
		case WS_DEV_INFO_DEV_NAME:
			strncpy(edata->name, infos[i].string, OEM_DEV_NAME_LEN);
			edata->name[OEM_DEV_NAME_LEN] = '\0';
			break;
		case WS_DEV_INFO_DEV_TYPE:
			res = _ws_txt_to_devtype(infos[i].string, &edata->pri_dev_type, &edata->sec_dev_type);
			if (res < 0) {
				edata->pri_dev_type = 0;
				edata->sec_dev_type = 0;
			}
			break;
		case WS_DEV_INFO_CONFIG_METHODS:
			config_methods = (int) strtoul(infos[i].string, NULL, 16);
			if (config_methods & WS_CONFIG_METHOD_DISPLAY)
				edata->config_methods |= WFD_OEM_WPS_MODE_DISPLAY;
			if (config_methods & WS_CONFIG_METHOD_PUSHBUTTON)
				edata->config_methods |= WFD_OEM_WPS_MODE_PBC;
			if (config_methods & WS_CONFIG_METHOD_KEYPAD)
				edata->config_methods |= WFD_OEM_WPS_MODE_KEYPAD;
			break;
		case WS_DEV_INFO_DEV_CAP:
			edata->dev_flags = (int) strtoul(infos[i].string, NULL, 16);
			break;
		case WS_DEV_INFO_GROUP_CAP:
			group_capab = (int) strtoul(infos[i].string, NULL, 16);
			if (group_capab & WS_GROUP_CAP_GROUP_OWNER) {
				edata->group_flags = WFD_OEM_GROUP_FLAG_GROUP_OWNER;
				edata->dev_role = WFD_OEM_DEV_ROLE_GO;
			}
			if (group_capab & WS_GROUP_CAP_PERSISTENT_GROUP)
				edata->group_flags = WFD_OEM_GROUP_FLAG_PERSISTENT_GROUP;
			break;
		case WS_DEV_INFO_P2P_GO_ADDR:
			edata->dev_role = WFD_OEM_DEV_ROLE_GC;
			res = _ws_txt_to_mac(infos[i].string, edata->p2p_go_addr);
			if (res < 0)
				memset(edata->p2p_go_addr, 0x00, OEM_MACADDR_LEN);
			break;
#ifdef TIZEN_FEATURE_WIFI_DISPLAY
		case WS_DEV_INFO_WFD_DEV_INFO:
			/* wfd_dev_info=0x00 0006 015d 022a0032 */
			edata->display = _parsing_display_info(infos[i].string+2);;
#if 0
			/* workaround code: for Dongle and HomeSync */
			if (edata->display && edata->display->type == WFD_OEM_DISPLAY_TYPE_PRISINK)
				_check_dev_type(edata->p2p_dev_addr, &edata->pri_dev_type, &edata->sec_dev_type);
#endif
			break;
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

		default:
			WDP_LOGE("Unknown parameter [%d:%s]", infos[i].index, infos[i].string);
			break;
		}
		if (infos[i].string)
			free(infos[i].string);
	}

	__WDP_LOG_FUNC_EXIT__;
	return edata;
}

static wfd_oem_conn_data_s *_convert_msg_to_conn_info(char *msg)
{
	__WDP_LOG_FUNC_ENTER__;
	int i;
	int info_cnt = 0;
	ws_string_s infos[WS_CONN_INFO_LIMIT];
	wfd_oem_conn_data_s *edata = NULL;
	int dev_pwd_id;
	int res = 0;

	if (!msg) {
		WDP_LOGE("Invalid parameter");
		return NULL;
	}
	WDP_LOGD("msg to convert [%s]", msg);

	memset(infos, 0x0, (WS_CONN_INFO_LIMIT) * sizeof(ws_string_s));
	for (i = 0; i < WS_CONN_INFO_LIMIT; i++) {
		res = _extract_value_str(msg, ws_conn_info_strs[i].string, &infos[info_cnt].string);
		if (res > 0) {
			infos[info_cnt].index = ws_conn_info_strs[i].index;
			info_cnt++;
		}
	}

	if (!info_cnt) {
		WDP_LOGE("There is no item converted");
		return NULL;
	}

	errno = 0;
	edata = (wfd_oem_conn_data_s*) g_try_malloc0(sizeof(wfd_oem_conn_data_s));
	if (!edata) {
		WDP_LOGE("Failed to allocate memory for connection information [%s]", strerror(errno));
		return NULL;
	}

	for (i = 0; i < info_cnt; i++) {
		switch (infos[i].index) {
		case WS_CONN_INFO_DEV_PWD_ID:
			dev_pwd_id = atoi(infos[i].string);
			if (dev_pwd_id == WS_DEV_PASSWD_ID_PUSH_BUTTON)
				edata->wps_mode = WFD_OEM_WPS_MODE_PBC;
			else if (dev_pwd_id == WS_DEV_PASSWD_ID_REGISTRAR_SPECIFIED)
				edata->wps_mode = WFD_OEM_WPS_MODE_DISPLAY;
			else if (dev_pwd_id == WS_DEV_PASSWD_ID_USER_SPECIFIED)
				edata->wps_mode = WFD_OEM_WPS_MODE_KEYPAD;
			else
				edata->wps_mode = WFD_OEM_WPS_MODE_NONE;
			break;
		case WS_CONN_INFO_STATUS:
			edata->status = atoi(infos[i].string);
			break;
		case WS_CONN_INFO_ERROR:
			edata->error = atoi(infos[i].string);
			break;
		default:
			WDP_LOGE("Unknown information [%d:%s]", infos[i].index, infos[i].string);
			break;
		}
		if (infos[i].string)
			free(infos[i].string);
	}

	__WDP_LOG_FUNC_EXIT__;
	return edata;
}

static wfd_oem_invite_data_s *_convert_msg_to_invite_info(char *msg)
{
	__WDP_LOG_FUNC_ENTER__;
	int i;
	int info_cnt = 0;
	ws_string_s infos[WS_INVITE_INFO_LIMIT];
	wfd_oem_invite_data_s *edata = NULL;
	int res = 0;

	if (!msg) {
		WDP_LOGE("Invalid parameter");
		return NULL;
	}
	WDP_LOGD("msg to convert [%s]", msg);

	memset(infos, 0x0, (WS_INVITE_INFO_LIMIT) * sizeof(ws_string_s));
	for (i = 0; i < WS_INVITE_INFO_LIMIT; i++) {
		res = _extract_value_str(msg, ws_invite_info_strs[i].string, &infos[info_cnt].string);
		if (res > 0) {
			infos[info_cnt].index = ws_invite_info_strs[i].index;
			info_cnt++;
		}
	}

	if (!info_cnt) {
		WDP_LOGE("There is no item converted");
		return NULL;
	}

	errno = 0;
	edata = (wfd_oem_invite_data_s*) g_try_malloc0(sizeof(wfd_oem_invite_data_s));
	if (!edata) {
		WDP_LOGE("Failed to allocate memory for invite information [%s]", strerror(errno));
		return NULL;
	}

	for (i = 0; i < info_cnt; i++) {
		switch (infos[i].index) {
		case WS_INVITE_INFO_GO_DEV_ADDR:
			res = _ws_txt_to_mac(infos[i].string, edata->go_dev_addr);
			if (res < 0)
				memset(edata->go_dev_addr, 0x00, OEM_MACADDR_LEN);
			break;
		case WS_INVITE_INFO_BSSID:
			res = _ws_txt_to_mac(infos[i].string, edata->bssid);
			if (res < 0)
				memset(edata->bssid, 0x00, OEM_MACADDR_LEN);
			break;
		case WS_INVITE_INFO_LISTEN:
			edata->listen = atoi(infos[i].string);
			break;
		case WS_INVITE_INFO_STATUS:
			edata->status = atoi(infos[i].string);
			break;
		default:
			WDP_LOGE("Unknown parameter [%d:%s]", infos[i].index, infos[i].string);
			break;
		}
		if (infos[i].string)
			free(infos[i].string);
	}

	__WDP_LOG_FUNC_EXIT__;
	return edata;
}

static wfd_oem_group_data_s *_convert_msg_to_group_info(char *msg)
{
	__WDP_LOG_FUNC_ENTER__;
	int i;
	int info_cnt = 0;
	ws_string_s infos[WS_GROUP_INFO_LIMIT];
	wfd_oem_group_data_s *edata = NULL;
	int res = 0;

	if (!msg) {
		WDP_LOGE("Invalid parameter");
		return NULL;
	}
	WDP_LOGD("msg to convert [%s]", msg);

	memset(infos, 0x0, WS_GROUP_INFO_LIMIT * sizeof(ws_string_s));
	for (i = 0; i < WS_GROUP_INFO_LIMIT; i++) {
		res = _extract_value_str(msg, ws_group_info_strs[i].string, &infos[info_cnt].string);
		if (res > 0) {
			infos[info_cnt].index = ws_group_info_strs[i].index;
			info_cnt++;
		}
	}

	if (!info_cnt) {
		WDP_LOGE("There is no item converted");
		return NULL;
	}

	errno = 0;
	edata = (wfd_oem_group_data_s*) g_try_malloc0(sizeof(wfd_oem_group_data_s));
	if (!edata) {
		WDP_LOGE("Failed to allocate memory for group information [%s]", strerror(errno));
		return NULL;
	}

	for (i = 0; i < info_cnt; i++) {
		switch (infos[i].index) {
		case WS_GROUP_INFO_SSID:
			g_strlcpy(edata->ssid, infos[i].string, OEM_DEV_NAME_LEN + 1);
			WDP_LOGD("ssid [%s]", edata->ssid);
			break;
		case WS_GROUP_INFO_FREQ:
			edata->freq = atoi(infos[i].string);
			break;
		case WS_GROUP_INFO_PASS:
			g_strlcpy(edata->pass, infos[i].string, OEM_PASS_PHRASE_LEN + 1);
			WDP_LOGD("passphrase [%s]", edata->pass);
			break;
		case WS_GROUP_INFO_GO_DEV_ADDR:
			res = _ws_txt_to_mac(infos[i].string, edata->go_dev_addr);
			if (res < 0)
				memset(edata->go_dev_addr, 0x00, OEM_MACADDR_LEN);
			break;
		default:
			WDP_LOGE("Unknown parameter [%d:%s]", infos[i].index, infos[i].string);
			break;
		}
		g_free(infos[i].string);
	}

	__WDP_LOG_FUNC_EXIT__;
	return edata;
}

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
static int _ws_segment_to_service(char *segment, wfd_oem_new_service_s **service)
{
	wfd_oem_new_service_s *serv_tmp = NULL;
	char *ptr = NULL;
	char *temp = NULL;
	int len = 0;
	int i = 0;

	if (!segment || !service) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	ptr = segment;
	WDP_LOGD("Segment: %s", segment);

	serv_tmp = (wfd_oem_new_service_s*) g_try_malloc0(sizeof(wfd_oem_new_service_s));
	if (!serv_tmp) {
		WDP_LOGE("Failed to allocate memory for service");
		return -1;
	}

	serv_tmp->protocol = _ws_hex_to_num(ptr, 2);
	serv_tmp->trans_id = _ws_hex_to_num(ptr+2, 2);
	serv_tmp->status = _ws_hex_to_num(ptr+4, 2);
	ptr += 6;
	WDP_LOGD("Protocol[%d], Transaction ID[%d], Status[%d]", serv_tmp->protocol, serv_tmp->trans_id, serv_tmp->status);

	if (serv_tmp->status != 0) {
		WDP_LOGE("Service status is not success");
		g_free(serv_tmp);
		return -1;
	}

	if (serv_tmp->protocol == WFD_OEM_SERVICE_TYPE_BONJOUR) {
		WDP_LOGD("===== Bonjour service =====");
		char compr[5] = {0, };
		char query[256] = {0, };
		char rdata[256] = {0, };
		int dns_type = 0;

		while (*ptr != 0 && strncmp(ptr, "c0", 2)) {
			len = _ws_hex_to_num(ptr, 2);
			ptr +=2;
			if (len) {
				temp = (char*) g_try_malloc0(len+2);
				if (!temp) {
					WDP_LOGE("Failed to allocate memory for temp");
					g_free(serv_tmp);
					return -1;
				}
				temp[0] = '.';
				for (i=0; i<len; i++) {
					temp[i+1] = (char) _ws_hex_to_num(ptr, 2);
					ptr += 2;
				}
				strncat(query, temp, len+1);
				g_free(temp);
				temp = NULL;
			}
		}

		if (!strncmp(ptr, "c0", 2)) {
			memcpy(compr, ptr, 4);
			ptr += 2;

			if (!strncmp(ptr, "27", 2)) {
				WDP_LOGD("Segment ended");
				ptr += 2;
			} else {
				ptr += 2;
				dns_type = _ws_hex_to_num(ptr, 4);
				ptr += 6;
				if (dns_type == 12) {
					if (!strncmp(compr, "c011", 4))
						strncat(query, ".local.", 7);
					else if (!strncmp(compr, "c00c", 4))
						strncat(query, "._tcp.local.", 12);
					else if (!strncmp(compr, "c01c", 4))
						strncat(query, "._udp.local.", 12);
				}
			}
		}
		serv_tmp->data.bonjour.query = strdup(query + 1);
		while (*ptr != 0 && strncmp(ptr, "c0", 2)) {
			len = _ws_hex_to_num(ptr, 2);
			ptr += 2;
			if (len) {
				temp = (char*) g_try_malloc0(len+2);
				if (!temp) {
					WDP_LOGE("Failed to allocate memory for temp");
					g_free(serv_tmp);
					return -1;
				}
				temp[0] = '.';
				for (i=0; i<len; i++) {
					temp[i+1] = (char) _ws_hex_to_num(ptr, 2);
					ptr += 2;
				}
				strncat(rdata, temp, len+1);
				g_free(temp);
				temp = NULL;
			}
		}
		serv_tmp->data.bonjour.rdata = strdup(rdata + 1);

		WDP_LOGD("Query: %s", serv_tmp->data.bonjour.query);
		WDP_LOGD("RData: %s", serv_tmp->data.bonjour.rdata);
	} else if (serv_tmp->protocol == WFD_OEM_SERVICE_TYPE_VENDOR) {
		WDP_LOGD("===== Vendor specific service =====");
		if (!strncmp(ptr, "0000f00b", 8)) {
			WDP_LOGD("\tSAMSUNG_BT_ADDR");
			ptr += 16;
			serv_tmp->protocol = WFD_OEM_SERVICE_TYPE_BT_ADDR;
			serv_tmp->data.vendor.data1 = (char*) g_try_malloc0(9);
			if (!serv_tmp->data.vendor.data1) {
				WDP_LOGE("Failed to allocate memory for data.vendor.data1");
				g_free(serv_tmp);
				return -1;
			}
			g_strlcpy(serv_tmp->data.vendor.data1, "0000f00b", 9);
			serv_tmp->data.vendor.data2 = (char*) g_try_malloc0(18);
			if (!serv_tmp->data.vendor.data2) {
				WDP_LOGE("Failed to allocate memory for data.vendor.data2");
				g_free(serv_tmp->data.vendor.data1);
				g_free(serv_tmp);
				return -1;
			}
			_ws_hex_to_txt(ptr, 0, serv_tmp->data.vendor.data2);
		}
		WDP_LOGD("Info1: %s", serv_tmp->data.vendor.data1);
		WDP_LOGD("Info2: %s", serv_tmp->data.vendor.data2);
	} else {
		WDP_LOGE("Not supported yet. Only bonjour and samsung vendor service supproted [%d]",
					serv_tmp->protocol);
		free(serv_tmp);
		return -1;
	}

	*service = serv_tmp;

	return 0;
}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

static int _parsing_event_info(char *ifname, char *msg, wfd_oem_event_s *data)
{
	__WDP_LOG_FUNC_ENTER__;
	int i;
	int res = 0;
	char *info_str = NULL;

	if (!msg || !data) {
		WDP_LOGE("Invalid parameter");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Event message [%s]", msg);

	// parsing event string
	for(i = 0; i < WS_EVENT_LIMIT; i++) {
		if (!strncmp(ws_event_strs[i].string, msg, strlen(ws_event_strs[i].string))) {
			break;
		}
	}
	data->event_id = i;
	WDP_LOGD("Event ID [%d]", i);

	if (i == WS_EVENT_LIMIT) {
		WDP_LOGE("Unknown event [%d]", i);
		return 1;
	}

	// parsing event info
	info_str = msg + strlen(ws_event_strs[i].string) + 1;
	if (!strlen(info_str)) {
		WDP_LOGD("Nothing to parse anymore");
		data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
		__WDP_LOG_FUNC_EXIT__;
		return 0;
	}

	switch (data->event_id) {
	case WS_EVENT_DEVICE_FOUND:
		{
			_ws_txt_to_mac(info_str, data->dev_addr);
			info_str += OEM_MACSTR_LEN;

			wfd_oem_dev_data_s *edata = NULL;
			edata = _convert_msg_to_dev_info(info_str);
			if (!edata) {
				WDP_LOGE("Failed to convert information string to device data");
				data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
				break;
			}

			if (edata->dev_role == WFD_OEM_DEV_ROLE_GO) {
				memcpy(edata->p2p_intf_addr, data->dev_addr, OEM_MACADDR_LEN);
				memcpy(data->dev_addr, edata->p2p_dev_addr, OEM_MACADDR_LEN);
			}
			data->edata_type = WFD_OEM_EDATA_TYPE_DEVICE;
			data->edata = (void*) edata;

		}
		break;
	case WS_EVENT_PROV_DISC_PBC_REQ:
	case WS_EVENT_PROV_DISC_SHOW_PIN:
	case WS_EVENT_PROV_DISC_ENTER_PIN:
	case WS_EVENT_PROV_DISC_PBC_RESP:
		{
			_ws_txt_to_mac(info_str, data->dev_addr);
			info_str += OEM_MACSTR_LEN;

			if (data->event_id == WS_EVENT_PROV_DISC_PBC_REQ) {
				data->wps_mode = WFD_OEM_WPS_MODE_PBC;
			} else if (data->event_id == WS_EVENT_PROV_DISC_ENTER_PIN) {
				data->wps_mode = WFD_OEM_WPS_MODE_KEYPAD;
			} else if (data->event_id == WS_EVENT_PROV_DISC_SHOW_PIN) {
				data->wps_mode = WFD_OEM_WPS_MODE_DISPLAY;
				strncpy(data->wps_pin, info_str, OEM_PINSTR_LEN);
				data->wps_pin[OEM_PINSTR_LEN] = '\0';
				info_str += OEM_PINSTR_LEN +1;
			}

			WDP_LOGD("info string left [%s]", info_str ? info_str:"NULL");

			data->edata_type = WFD_OEM_EDATA_TYPE_NONE;

		}
		break;
	case WS_EVENT_DEVICE_LOST:
		{
			char *temp_mac = NULL;
			res = _extract_value_str(info_str, "p2p_dev_addr", &temp_mac);
			if (res < 0) {
				WDP_LOGE("Failed to extract device address");
				break;
			}
			_ws_txt_to_mac(temp_mac, data->dev_addr);
			if (temp_mac)
				g_free(temp_mac);
			data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
		}
		break;
	case WS_EVENT_FIND_STOPED:
		break;
	case WS_EVENT_GO_NEG_REQUEST:
		{
			_ws_txt_to_mac(info_str, data->dev_addr);
			info_str += OEM_MACSTR_LEN;

			if (!strlen(info_str)) {
				WDP_LOGD("Nothing to parse anymore");
				data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
				break;
			}

			wfd_oem_conn_data_s *edata = NULL;
			edata = _convert_msg_to_conn_info(info_str);
			if (!edata) {
				WDP_LOGE("Failed to convert information string to connection data");
				data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
				break;
			}
			data->edata_type = WFD_OEM_EDATA_TYPE_CONN;
			data->edata = (void*) edata;
		}
		break;
	case WS_EVENT_PROV_DISC_FAILURE:
	case WS_EVENT_WPS_FAIL:		// M_id(msg), error(config_error)
		break;
	case WS_EVENT_GO_NEG_FAILURE:
		{
			wfd_oem_conn_data_s *edata = NULL;
			edata = _convert_msg_to_conn_info(info_str);
			if (!edata) {
				WDP_LOGE("Failed to convert information string to connection data");
				data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
				break;
			}
			data->edata_type = WFD_OEM_EDATA_TYPE_CONN;
			data->edata = (void*) edata;
		}
		break;
	case WS_EVENT_GROUP_FORMATION_FAILURE:	// No incofmation sring
	case WS_EVENT_GO_NEG_SUCCESS:
	case WS_EVENT_WPS_SUCCESS:
	case WS_EVENT_GROUP_FORMATION_SUCCESS:
		/* No information string */
		data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
		break;
	case WS_EVENT_WPS_REG_SUCCESS:	// "intf_addr"
		/* Interface address of peer will come up */
		break;
	case WS_EVENT_CONNECTED:	// intf_addr(to)
		{
			/* Interface address of connected peer will come up */
			char *temp_mac = NULL;
			res = _extract_value_str(info_str, "to", &temp_mac);
			if (res < 0) {
				WDP_LOGE("Failed to extract interface address");
				break;
			}
			_ws_txt_to_mac(temp_mac, data->intf_addr);
			if (temp_mac)
				g_free(temp_mac);
			data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
		}
		break;
	case WS_EVENT_DISCONNECTED:
		{
			/* Interface address of disconnected peer will come up */
			char *temp_mac = NULL;
			res = _extract_value_str(info_str, "bssid", &temp_mac);
			if (res < 0) {
				WDP_LOGE("Failed to extract interface address");
				break;
			}
			_ws_txt_to_mac(temp_mac, data->intf_addr);
			if (temp_mac)
				free(temp_mac);
			data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
		}
		break;
	case WS_EVENT_STA_CONNECTED:	// "intf_addr", dev_addr(dev_addr)
	case WS_EVENT_STA_DISCONNECTED:
		{
			/* Interface address of connected peer will come up */
			_ws_txt_to_mac(info_str, data->intf_addr);

			char *temp_mac = NULL;
			res = _extract_value_str(info_str, "p2p_dev_addr", &temp_mac);
			if (res < 0) {
				WDP_LOGE("Failed to extract interface address");
				break;
			}
			_ws_txt_to_mac(temp_mac, data->dev_addr);
			if (temp_mac)
				g_free(temp_mac);
			data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
		}
		break;
	case WS_EVENT_INVITATION_RECEIVED:
	case WS_EVENT_INVITATION_RESULT:
		{
			char *peer_addr_str = NULL;
			res = _extract_value_str(info_str, "sa", &peer_addr_str);
			if (res == 17/*(OEM_MACSTR_LEN-1)*/) {
				_ws_txt_to_mac(peer_addr_str, data->dev_addr);
				if (peer_addr_str)
					g_free(peer_addr_str);
			} else if (res < 0) {
				WDP_LOGE("Failed to extract source address");
			} else {
				WDP_LOGE("Wrong source address");
				g_free(peer_addr_str);
			}

			if (!strlen(info_str)) {
				WDP_LOGD("Nothing to parse anymore");
				data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
				break;
			}

			wfd_oem_invite_data_s* edata = NULL;
			edata = _convert_msg_to_invite_info(info_str);
			if (!edata) {
				WDP_LOGE("Failed to convert information string to invite data");
				data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
				break;
			}

			data->edata_type = WFD_OEM_EDATA_TYPE_INVITE;
			data->edata = (void*) edata;

		}
		break;
	case WS_EVENT_GROUP_STARTED:
	case WS_EVENT_GROUP_REMOVED:
		{
			char *ifname_str = NULL;
			res = _extract_word(info_str, &ifname_str);
			if (res < 0) {
				WDP_LOGE("Failed to extract event param string");
			} else if (res == 0) {
				WDP_LOGE("Nothing extracted");
				g_free(ifname_str);
			} else {
				if (!ifname_str) {
					WDP_LOGE("Parsing error(interface name)");
					return -1;
				}
				strncpy(data->ifname, ifname_str, OEM_IFACE_NAME_LEN);
				data->ifname[OEM_IFACE_NAME_LEN] = '\0';

				info_str += strlen(ifname_str) + 1;
				g_free(ifname_str);
			}

			char *dev_role_str = NULL;
			res = _extract_word(info_str, &dev_role_str);
			if (res < 0) {
				WDP_LOGE("Failed to extract event param string");
			} else if (res == 0) {
				WDP_LOGE("Nothing extracted");
				g_free(dev_role_str);
			} else {
				if (!dev_role_str) {
					WDP_LOGE("Parsing error(device role)");
					return -1;
				}
				if (!strncmp(dev_role_str, "GO", 2))
					data->dev_role = WFD_OEM_DEV_ROLE_GO;
				else if (!strncmp(dev_role_str, "client", 6))
					data->dev_role = WFD_OEM_DEV_ROLE_GC;
				else
					WDP_LOGE("Unknown device role [%s]", dev_role_str);

				info_str += strlen(dev_role_str) + 1;
				g_free(dev_role_str);
			}

			if (!strlen(info_str)) {
				WDP_LOGD("Nothing to parse anymore");
				data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
				break;
			}

			wfd_oem_group_data_s* edata = NULL;
			edata= _convert_msg_to_group_info(info_str);
			if (!edata) {
				WDP_LOGE("Failed to convert information string to group data");
				data->edata_type = WFD_OEM_EDATA_TYPE_NONE;
				break;
			}

			data->edata_type = WFD_OEM_EDATA_TYPE_GROUP;
			data->edata = (void*) edata;

		}
		break;
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	case WS_EVENT_SERV_DISC_RESP:
		{
			char mac_addr[OEM_MACSTR_LEN] ={0, };
			char *up_indic = NULL;
			int len = 0;

			_ws_txt_to_mac(info_str, data->dev_addr);
			info_str += OEM_MACSTR_LEN;
			snprintf(mac_addr, WS_MACSTR_LEN, MACSTR, MAC2STR(data->dev_addr));

			_extract_word(info_str, &up_indic);
			if (up_indic) {
				WDP_LOGD("Update indicator: %s", up_indic);
				info_str += strlen(up_indic) + 1;
				g_free(up_indic);
			}
			WDP_LOGD("Info string [%s]", info_str);

			char seglen_str[5] = {0, };
			char *segment = NULL;
			char *ptr = info_str;
			GList *services = NULL;
			wfd_oem_new_service_s *new_service = NULL;
			int count = 0;

			while (*ptr != '\0') {
				_change_str_order(ptr, 4, 2, seglen_str);
				len = strtoul(seglen_str, NULL, 16);
				if (len == 0)
					break;
				segment = (char*) g_try_malloc0(len*2+1);
				if (!segment) {
					WDP_LOGE("Failed to allocate memory for segment");
					return -1;
				}
				memcpy(segment, ptr+4, len*2);
				ptr = ptr + 4 + len*2;
				res = _ws_segment_to_service(segment, &new_service);
				if (res < 0) {
					WDP_LOGE("Failed to convert segment as service instance");
					free(segment);
					segment = NULL;
					continue;
				}
				services = g_list_append(services, new_service);
				count++;
				free(segment);
				segment = NULL;
			}
			data->edata_type = WFD_OEM_EDATA_TYPE_NEW_SERVICE;
			data->dev_role = count;
			data->edata = (void*) services;
		}
		break;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

	default:
		WDP_LOGE("Unknown event");
		break;
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static gboolean ws_event_handler(GIOChannel *source,
								GIOCondition condition,
								gpointer data)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s * sd = (ws_sock_data_s*) data;
	char msg[1024] = {0, };
	char *param;
	int event_id = -1;
	wfd_oem_event_s event;
	int res = 0;

	if (!sd) {
		WDP_LOGE("Invalid parameter");
		// TODO: if error count is more than 10, disconnect this interface and reset sock data
		return FALSE;
	}

	res = _ws_read_sock(sd->mon_sock, msg, sizeof(msg));
	if (res < 0) {
		WDP_LOGE("Failed to read socket. [%d]", sd->mon_sock);
		return FALSE;
	}

	errno = 0;
	memset(&event, 0, sizeof(wfd_oem_event_s));

	param = &msg[3];
	res = _parsing_event_info(sd->ifname, param, &event);
	if (res < 0) {
		WDP_LOGE("Failed to parse event string");
		return FALSE;
	}

	if (res == 1) {
		// This means event->event_data is NULL
	}

	switch (event.event_id) {
	case WS_EVENT_DEVICE_FOUND:
		event_id = WFD_OEM_EVENT_PEER_FOUND;
		break;
	case WS_EVENT_DEVICE_LOST:
		event_id = WFD_OEM_EVENT_PEER_DISAPPEARED;
		break;
	case WS_EVENT_FIND_STOPED:
		event_id = WFD_OEM_EVENT_DISCOVERY_FINISHED;
		break;
	case WS_EVENT_PROV_DISC_PBC_REQ:
		event_id = WFD_OEM_EVENT_PROV_DISC_REQ;
		break;
	case WS_EVENT_PROV_DISC_PBC_RESP:
		event_id = WFD_OEM_EVENT_PROV_DISC_RESP;
		break;
	case WS_EVENT_PROV_DISC_SHOW_PIN:
		event_id = WFD_OEM_EVENT_PROV_DISC_DISPLAY;
		break;
	case WS_EVENT_PROV_DISC_ENTER_PIN:
		event_id = WFD_OEM_EVENT_PROV_DISC_KEYPAD;
		break;
	case WS_EVENT_GO_NEG_REQUEST:
		event_id = WFD_OEM_EVENT_GO_NEG_REQ;
		break;
	case WS_EVENT_GO_NEG_FAILURE:
		event_id = WFD_OEM_EVENT_GO_NEG_FAIL;
		break;
	case WS_EVENT_GO_NEG_SUCCESS:
		event_id = WFD_OEM_EVENT_GO_NEG_DONE;
		break;
	case WS_EVENT_WPS_FAIL:
	case WS_EVENT_GROUP_FORMATION_FAILURE:
		event_id = WFD_OEM_EVENT_WPS_FAIL;
		break;
	case WS_EVENT_WPS_SUCCESS:
	case WS_EVENT_WPS_REG_SUCCESS:
	case WS_EVENT_GROUP_FORMATION_SUCCESS:
		event_id = WFD_OEM_EVENT_WPS_DONE;
		// TODO: connect to supplicant via group interface
		break;
	case WS_EVENT_CONNECTED:
		{
			unsigned char null_mac[OEM_MACADDR_LEN] = {0, 0, 0, 0, 0, 0};
			if (!memcmp(event.intf_addr, null_mac, OEM_MACADDR_LEN))
				goto done;
			event_id = WFD_OEM_EVENT_CONNECTED;
		}
		break;
	case WS_EVENT_STA_CONNECTED:
		event_id = WFD_OEM_EVENT_STA_CONNECTED;
		break;
	case WS_EVENT_GROUP_STARTED:
		event_id = WFD_OEM_EVENT_GROUP_CREATED;
		res = _connect_to_supplicant(GROUP_IFACE_NAME, &g_pd->group);
		if (res < 0) {
			WDP_LOGE("Failed to connect to group interface of supplicant");
			// goto done;
		}
		break;
	case WS_EVENT_GROUP_REMOVED:
		event_id = WFD_OEM_EVENT_GROUP_DESTROYED;
		if (g_pd->group) {
			res = _disconnect_from_supplicant(GROUP_IFACE_NAME, g_pd->group);
			if (res < 0) {
				WDP_LOGE("Failed to disconnect from group interface of supplicant");
				// goto done;
			}
			g_pd->group = NULL;
		}
		break;
	case WS_EVENT_INVITATION_RECEIVED:
		event_id = WFD_OEM_EVENT_INVITATION_REQ;
		break;
	case WS_EVENT_INVITATION_RESULT:
		event_id = WFD_OEM_EVENT_INVITATION_RES;
		break;
	case WS_EVENT_DISCONNECTED:
		{
			unsigned char null_mac[OEM_MACADDR_LEN] = {0, 0, 0, 0, 0, 0};
			if (!memcmp(event.intf_addr, null_mac, OEM_MACADDR_LEN))
				goto done;
			event_id = WFD_OEM_EVENT_DISCONNECTED;
		}
		break;
	case WS_EVENT_STA_DISCONNECTED:
		event_id = WFD_OEM_EVENT_STA_DISCONNECTED;
		break;
	case WS_EVENT_TERMINATING:
		event_id = WFD_OEM_EVENT_DEACTIVATED;
		break;
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
	case WS_EVENT_SERV_DISC_RESP:
		event_id = WFD_OEM_EVENT_SERV_DISC_RESP;
		break;
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
	default:
		WDP_LOGD("Unknown event [%d]", event.event_id);
		goto done;
		break;
	}
	event.event_id = event_id;
	g_pd->callback(g_pd->user_data, &event);

done:
	if (event.edata) {
#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
		if (event.edata_type == WFD_OEM_EDATA_TYPE_NEW_SERVICE)
			g_list_free((GList*) event.edata);
		else
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */
		g_free(event.edata);
	}

	__WDP_LOG_FUNC_EXIT__;
	return TRUE;
}

static int _ws_reset_plugin(ws_plugin_data_s *pd)
{
	__WDP_LOG_FUNC_ENTER__;

	if (!pd) {
		WDP_LOGE("Invalid parameter");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (pd->activated)
		ws_deactivate(g_pd->concurrent);

	g_free(pd);

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}


static int __ws_check_net_interface(char* if_name)
{
	struct ifreq ifr;
	int fd;

	if (if_name == NULL) {
		WDP_LOGE("Invalid param");
		return -1;
	}

	fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		WDP_LOGE("socket create error: %d", fd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	ifr.ifr_name[IFNAMSIZ-1] = '\0';

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		WDP_LOGE("ioctl error: SIOCGIFFLAGS: %s", strerror(errno));  // interface is not found..
		return -3;
	}

	close(fd);

	if (ifr.ifr_flags & IFF_UP) {
		WDP_LOGD("%s interface is up", if_name);
		return 1;
	} else if (!(ifr.ifr_flags & IFF_UP)) {
		WDP_LOGD("%s interface is down", if_name);
		return 0;
	}
	return 0;
}

int ws_init(wfd_oem_event_cb callback, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;

	if (g_pd)
		_ws_reset_plugin(g_pd);

	errno = 0;
	g_pd = (ws_plugin_data_s*) g_try_malloc0 (sizeof(ws_plugin_data_s));
	if (!g_pd) {
		WDP_LOGE("Failed to allocate memory for plugin data. [%s]", strerror(errno));
		return -1;
	}

	g_pd->callback = callback;
	g_pd->user_data = user_data;
	g_pd->initialized = TRUE;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_deinit()
{
	__WDP_LOG_FUNC_ENTER__;

	if (g_pd) {
		_ws_reset_plugin(g_pd);
		g_pd = NULL;
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}


#if 0
static int __ws_p2p_firmware_start(void)
{
	DBusError error;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;
	const char *device = "p2p";

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		WDP_LOGE("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE ".Firmware", "Start");
	if (message == NULL) {
		WDP_LOGE("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &device);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);
	if (dbus_error_is_set(&error) == TRUE) {
		if (NULL != strstr(error.message, ".AlreadyExists")) {
			// p2p already enabled
		} else {
			WDP_LOGE("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
		}

		dbus_error_free(&error);
	}

	if (reply != NULL)
		dbus_message_unref(reply);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return 0;
}

static int __ws_p2p_firmware_stop(void)
{
	DBusError error;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;
	const char *device = "p2p";

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		WDP_LOGE("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE ".Firmware", "Stop");
	if (message == NULL) {
		WDP_LOGE("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &device);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);
	if (dbus_error_is_set(&error) == TRUE) {
		if (NULL != strstr(error.message, ".AlreadyExists")) {
			// p2p already disabled
		} else {
			WDP_LOGE("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
		}

		dbus_error_free(&error);
	}

	if (reply != NULL)
		dbus_message_unref(reply);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return 0;
}

static int __ws_p2p_supplicant_start(void)
{
	gboolean rv = FALSE;
	const char *path = "/usr/sbin/p2p_supp.sh";
	char *const args[] = { "/usr/sbin/p2p_supp.sh", "start", NULL };
	char *const envs[] = { NULL };

	rv = _ws_util_execute_file(path, args, envs);

	if (rv != TRUE) {
		WDP_LOGE("Failed to start p2p_supp.sh");
		return -1;
	}

	WDP_LOGI("Successfully started p2p_supp.sh");
	return 0;
}

static int __ws_p2p_supplicant_stop(void)
{
	gboolean rv = FALSE;
	const char *path = "/usr/sbin/p2p_supp.sh";
	char *const args[] = { "/usr/sbin/p2p_supp.sh", "stop", NULL };
	char *const envs[] = { NULL };

	rv = _ws_util_execute_file(path, args, envs);

	if (rv != TRUE) {
		WDP_LOGE("Failed to stop p2p_supp.sh");
		return -1;
	}

	WDP_LOGI("Successfully stopped p2p_supp.sh");
	return 0;
}
#endif

static int __ws_p2p_on(void)
{
	DBusError error;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		WDP_LOGE("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE, "LoadP2pDriver");
	if (message == NULL) {
		WDP_LOGE("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);
	if (dbus_error_is_set(&error) == TRUE) {
		if (NULL != strstr(error.message, ".AlreadyExists")) {
			// p2p already enabled
		} else {
			WDP_LOGE("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
		}

		dbus_error_free(&error);
	}

	if (reply != NULL)
		dbus_message_unref(reply);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return 0;
}

static int __ws_p2p_off(void)
{
	DBusError error;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		WDP_LOGE("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE, "RemoveP2pDriver");
	if (message == NULL) {
		WDP_LOGE("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);
	if (dbus_error_is_set(&error) == TRUE) {
		if (NULL != strstr(error.message, ".AlreadyExists")) {
			// p2p already disabled
		} else {
			WDP_LOGE("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
		}

		dbus_error_free(&error);
	}

	if (reply != NULL)
		dbus_message_unref(reply);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return 0;
}

static int _ws_update_local_dev_addr_from_file()
{
	__WDP_LOG_FUNC_ENTER__;
	FILE *fd = NULL;
	char local_mac[WS_MACSTR_LEN] = {0, };
	char *ptr = NULL;
	int res = 0;

	errno = 0;
	fd = fopen(DEFAULT_MAC_FILE_PATH, "r");
	if (!fd) {
		WDP_LOGE("Failed to open MAC info file (%s)", strerror(errno));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	ptr = fgets(local_mac, WS_MACSTR_LEN, fd);
	if (!ptr) {
		WDP_LOGE("Failed to read file or no data read(%s)", strerror(errno));
		fclose(fd);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_SECLOG("Local MAC address [%s]", ptr);

	res = _ws_txt_to_mac(local_mac, g_pd->local_dev_addr);
	if (res < 0) {
		WDP_LOGE("Failed to convert text to MAC address");
		fclose(fd);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	g_pd->local_dev_addr[0] |= 0x2;
	WDP_SECLOG("Local Device MAC address [" MACSTR "]", MAC2STR(g_pd->local_dev_addr));

	fclose(fd);
	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static int _ws_update_local_dev_addr()
{
	int res = 0;
	char reply[96] = {0, };
	char *mac_str = NULL;

	res = _ws_send_cmd(g_pd->common->ctrl_sock, "status", reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		goto failed;
	}

	res = _extract_value_str(reply, "p2p_device_address", &mac_str);
	if (res < 0) {
		WDP_LOGE("Failed to parsing p2p_device_address");
		goto failed;
	}

	res = _ws_txt_to_mac(mac_str, g_pd->local_dev_addr);
	if (res < 0) {
		WDP_LOGE("Failed to convert MAC string to address");
		free(mac_str);
		goto failed;
	}

	free(mac_str);

	return 0;

failed:
	res = _ws_update_local_dev_addr_from_file();
	if (res < 0) {
		WDP_LOGE("Failed to update local device address from file");
		return -1;
	}

	return 1;
}

int ws_activate(int concurrent)
{
	__WDP_LOG_FUNC_ENTER__;
	int res = 0;
	int retry_count = 0;

	while (retry_count < 10) {
#if 0
		/* load wlan driver */
		res = __ws_p2p_firmware_start();
		if (res < 0) {
			WDP_LOGE("Failed to load driver [ret=%d]", res);
			return -1;
		}
		WDP_LOGI("P2P firmware started with error %d", res);
#else
		/* load wlan driver and p2p_supplicant */
		res = __ws_p2p_on();
		if (res < 0) {
			WDP_LOGE("Failed to load driver and p2p_supplicant [ret=%d]", res);
			return -1;
		}
		WDP_LOGI("P2P firmware and p2p_supplicant started with error %d", res);
#endif
		if (__ws_check_net_interface("wlan0") < 0) {
			usleep(150000); // wait for 150ms
			retry_count++;
			WDP_LOGE("interface is not up: retry, %d", retry_count);
		} else {
			break;
		}
	}

	if (retry_count >= 10) {
		WDP_LOGE("Driver loading is failed", res);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	if (retry_count > 0) {
		// Give driver marginal time to config net
		WDP_LOGE("Driver loading is done. Wait marginal time for driver");
		sleep(1); // 1s
	}

	g_pd->concurrent = concurrent;

#if 0
	/* load wpa_supplicant */
	res = __ws_p2p_supplicant_start();
	if (res == -1) {
		WDP_LOGE("Failed to start p2p_supplicant [%d: %s]", res, strerror(errno));
		return -1;
	}
#endif

	res = _connect_to_supplicant(COMMON_IFACE_NAME, &g_pd->common);
	if (res < 0) {
		res = __ws_p2p_off();
		WDP_LOGI("[ __ws_p2p_off returns %d", res);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	g_pd->activated = TRUE;

	_ws_update_local_dev_addr();

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_deactivate(int concurrent)
{
	__WDP_LOG_FUNC_ENTER__;
	char cmd[32] = {0, };
	char reply[1024]={0,};
	int res = 0;

	if (!g_pd->activated) {
		WDP_LOGE("Wi-Fi Direct is not activated");
		return -1;
	}
	g_pd->concurrent = concurrent;

	if (g_pd->group) {
		_disconnect_from_supplicant(GROUP_IFACE_NAME, g_pd->group);
		g_pd->group = NULL;
	}

	// terminate wpasupplicant
	snprintf(cmd, sizeof(cmd), WS_CMD_TERMINATE);
	res = _ws_send_cmd(g_pd->common->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		goto done;
	}

	if (!strncmp(reply, "FAIL", 4)) {
		WDP_LOGE( "Failed to terminate wpa_supplicant");
		goto done;
	}

	res = _disconnect_from_supplicant(COMMON_IFACE_NAME, g_pd->common);
	if (res < 0) {
		WDP_LOGE("Failed to disconnect common interface(%s) from supplicant. ",
			COMMON_IFACE_NAME);
	}

done:
#if 0
	res = __ws_p2p_supplicant_stop();
	WDP_LOGI("[/usr/sbin/p2p_supp.sh stop] returns %d", res);

	if (!concurrent) {
		res = __ws_p2p_firmware_stop();
		WDP_LOGI("P2P firmware stopped with error %d", res);
	}
#else
	__ws_p2p_off();
#endif
	g_pd->activated = FALSE;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

static gboolean _retry_start_scan(gpointer data)
{
	ws_sock_data_s *sock = g_pd->common;
	char reply[1024] = {0, };
	static int retry_cnt = 0;
	int res = 0;
	char *cmd = (char *)data;

	if (NULL == sock || NULL == cmd) {
		WDP_LOGE("Data is NULL, Retry Scan Failed !!!");
		goto done;
	}

	if (WS_SCAN_RETRY_COUNT == retry_cnt) {
		WDP_LOGE("Maximum Retry Reached. Aborting Scan.");
		goto done;
	}

	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		goto done;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Retry Scan Failed, Retry after 100ms...");
		retry_cnt++;
		return TRUE;
	}

	WDP_LOGD("Retry Scan Succeeded.");

done:
	retry_cnt = 0;
	if (NULL != cmd) {
		free(cmd);
		cmd = NULL;
	}
	return FALSE;
}

int ws_start_scan(wfd_oem_scan_param_s *param)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[40] = {0, };
	char reply[1024] = {0, };
	char time_str[4] = {0, };
	char type_str[20] = {0, };
	int res = 0;
	char *retry_cmd = NULL;

	if (!param) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	if (param->refresh)
		_ws_flush();

	if (param->scan_time)
		snprintf(time_str, 4, " %d", param->scan_time);

	if (param->scan_type == WFD_OEM_SCAN_TYPE_SOCIAL)
		snprintf(type_str, 20, " type=social");
	else if (param->scan_type == WFD_OEM_SCAN_TYPE_SPECIFIC &&
			param->freq > 0)
		snprintf(type_str, 20, " freq=%d", param->freq);
	else if (param->scan_type == WFD_OEM_SCAN_TYPE_CHANNEL1)
		snprintf(type_str, 20, " type=specific1");
	else if (param->scan_type == WFD_OEM_SCAN_TYPE_CHANNEL6)
		snprintf(type_str, 20, " type=specific6");
	else if (param->scan_type == WFD_OEM_SCAN_TYPE_CHANNEL11)
		snprintf(type_str, 20, " type=specific11");
	else if (param->scan_type == WFD_OEM_SCAN_TYPE_GO_FREQ)
		snprintf(type_str, 20, " type=frequency");

	if (param->scan_mode == WFD_OEM_SCAN_MODE_ACTIVE)
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_FIND "%s%s",
					(param->scan_time > 0) ? time_str : "",
					(param->scan_type) ? type_str : "");
	else
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_LISTEN);

	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to start scan, Retry");
		retry_cmd = strdup(cmd);
		/* Add Timeout of 100ms for retry SCAN */
		g_timeout_add(100, _retry_start_scan, (gpointer) retry_cmd);
		__WDP_LOG_FUNC_EXIT__;
		return 0;
	}
	WDP_LOGD("Succeeded to start scan");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_restart_scan(int freq)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[32] = {0, };
	char reply[1024] = {0, };
	int res = 0;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	if (freq)
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_FIND " 2 freq=%d", freq);
	else
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_FIND " 2 type=social");

	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to start scan");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to start scan");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_stop_scan()
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char reply[1024] = {0, };
	int res = 0;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	res = _ws_send_cmd(sock->ctrl_sock, WS_CMD_P2P_STOP_FIND, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to stop scan");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to stop scan");


	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_visibility(int *visibility)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_visibility(int visibility)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_scan_result(GList **peers, int *peer_count)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[32] = {0, };
	char reply[1024] = {0,};
	wfd_oem_device_s *peer = NULL;
	int res = 0;

	if (!peers || !peer_count) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_P2P_PEER_FIRST);
	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to get first peer info");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to get first peer info");

	peer = (wfd_oem_device_s *) g_try_malloc0(sizeof(wfd_oem_device_s));
	if (!peer) {
		WDP_LOGF("Failed to allocate memory for peer.");
		return -1;
	}

	res = _parsing_peer_info(reply, peer);
	if (res < 0) {
			WDP_LOGE("Failed to parsing peer info");
			g_free(peer);
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	*peers = g_list_prepend(*peers, peer);

	do {
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_PEER_NEXT MACSTR, MAC2STR(peer->dev_addr));
		res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
		if (res < 0) {
				WDP_LOGE("Failed to send command to wpa_supplicant");
				break;
		}

		if (strstr(reply, "FAIL")) {
			WDP_LOGE("Failed to get first peer info");
			break;
		}
		WDP_LOGD("Succeeded to get first peer info");

		peer = (wfd_oem_device_s *) g_try_malloc0(sizeof(wfd_oem_device_s));
		if (!peer) {
			WDP_LOGF("Failed to allocate memory for peer");
			break;
		}

		res = _parsing_peer_info(reply, peer);
		if (res < 0) {
			WDP_LOGE("Failed to parsing peer info");
			g_free(peer);
			break;
		}

		*peers = g_list_prepend(*peers, peer);
	} while(1);

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_peer_info(unsigned char *peer_addr, wfd_oem_device_s **peer)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[32] = {0, };
	char reply[1024] = {0,};
	wfd_oem_device_s *ws_dev = NULL;
	int res = 0;

	if (!peer_addr || !peer) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_P2P_PEER MACSTR, MAC2STR(peer_addr));
	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_SECLOG("Failed to get peer info [" MACSTR "]", MAC2STR(peer_addr));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_SECLOG("Succeeded to get peer info [" MACSTR "]", MAC2STR(peer_addr));

	ws_dev = (wfd_oem_device_s*) g_try_malloc0 (sizeof(wfd_oem_device_s));
	if (!ws_dev) {
		WDP_LOGF("Failed to allocate memory for device");
		return -1;
	}

	res = _parsing_peer_info(reply, ws_dev);
	if (res < 0) {
		WDP_LOGE("Failed to parsing peer info");
		g_free(ws_dev);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	*peer = ws_dev;
	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_prov_disc_req(unsigned char *peer_addr, wfd_oem_wps_mode_e wps_mode, int join)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[64] = {0, };
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_P2P_PROV_DISC MACSTR "%s",
					MAC2STR(peer_addr), _ws_wps_to_txt(wps_mode));

	if (join)
		strncat(cmd, WS_STR_JOIN, 5);

	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_SECLOG("Failed to send provision discovery to peer[" MACSTR "]", MAC2STR(peer_addr));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_SECLOG("Succeeded to send provision discovery to peer[" MACSTR "]", MAC2STR(peer_addr));

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_connect(unsigned char *peer_addr, wfd_oem_conn_param_s *param)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[64] = {0, };
	char reply[1024] = {0, };
	int res = 0;

	if (!peer_addr) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	if (param->wps_pin[0] != '\0')
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_CONNECT MACSTR " %s%s" ,
							MAC2STR(peer_addr), param->wps_pin,
							_ws_wps_to_txt(param->wps_mode));
	else
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_CONNECT MACSTR "%s",
							MAC2STR(peer_addr),
							_ws_wps_to_txt(param->wps_mode));

	if (param->conn_flags & WFD_OEM_CONN_TYPE_JOIN)
		strncat(cmd, WS_STR_JOIN, 5);
	else if (param->conn_flags& WFD_OEM_CONN_TYPE_AUTH)
		strncat(cmd, WS_STR_AUTH, 5);

	if (param->conn_flags & WFD_OEM_CONN_TYPE_PERSISTENT)
		strncat(cmd, WS_STR_PERSISTENT, 11);

	WDP_LOGI("Connection command [%s]", cmd);

	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_SECLOG("Failed to connect with peer[" MACSTR "]", MAC2STR(peer_addr));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_SECLOG("Succeeded to send connection command to peer[" MACSTR "]", MAC2STR(peer_addr));

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_disconnect(unsigned char *peer_addr)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[48] = {0, };
	char reply[1024]={0,};
	int res;

	if (!peer_addr) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	WDP_SECLOG("Peer address is [" MACSTR "]. Disconnect selected peer", MAC2STR(peer_addr));

	snprintf(cmd, sizeof(cmd), WS_CMD_DISCONNECT MACSTR " %s", MAC2STR(peer_addr), GROUP_IFACE_NAME);
	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_SECLOG("Failed to disconnect with peer[" MACSTR "]", MAC2STR(peer_addr));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_SECLOG("Succeeded to send disconnection command to peer[" MACSTR "]", MAC2STR(peer_addr));

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_reject_connection(unsigned char *peer_addr)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[64] = {0, };
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_P2P_REJECT MACSTR, MAC2STR(peer_addr));
	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_SECLOG("Failed to reject connection with peer[" MACSTR "]", MAC2STR(peer_addr));
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_SECLOG("Succeeded to send reject connection command to peer[" MACSTR "]", MAC2STR(peer_addr));

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_cancel_connection(unsigned char *peer_addr)
{
	__WDP_LOG_FUNC_ENTER__;

	_ws_cancel();

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_connected_peers(GList **peers, int *peer_count)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_pin(char *pin)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_pin(char *pin)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_supported_wps_mode()
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_create_group(int persistent, int freq)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[44] = {0, };
	char reply[1024]={0,};
	int res = 0;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	if (persistent)
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_GROUP_ADD WS_STR_PERSISTENT);
	else
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_GROUP_ADD);

	// TODO: add frequency option

	strncat(cmd, WS_STR_FREQ_2G, 8);

	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to add group");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to add group");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_destroy_group(const char *ifname)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[32] = {0, };
	char reply[1024]={0,};
	int res = 0;

	if (!ifname) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_P2P_GROUP_REMOVE "%s", ifname);

	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to remove group");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to remove group");

	_ws_flush();

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_invite(unsigned char *peer_addr, wfd_oem_invite_param_s *param)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[128] = {0, };
	char reply[1024]={0,};
	int res = 0;

	if (!peer_addr || !param) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Group interface not connected");
		return -1;
	}

	WDP_SECLOG("Invite: Peer[" MACSTR "], GO Addr[" MACSTR "]", MAC2STR(peer_addr), MAC2STR(param->go_dev_addr));

	if (param->net_id)
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_INVITE "persistent=%d peer=" MACSTR " go_dev_addr=" MACSTR,
								param->net_id, MAC2STR(peer_addr),
								MAC2STR(param->go_dev_addr));
	else
		snprintf(cmd, sizeof(cmd), WS_CMD_P2P_INVITE "group=%s peer=" MACSTR " go_dev_addr=" MACSTR,
								param->ifname, MAC2STR(peer_addr),
								MAC2STR(param->go_dev_addr));

	res = _ws_send_cmd(sock->ctrl_sock, cmd, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to invite peer");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to invite peer");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

// Only group owner can use this command
int ws_wps_start(unsigned char *peer_addr, int wps_mode, const char *pin)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->group;
	char cmd[40] = {0, };
	char reply[1024]={0,};
	int res;

	if (!peer_addr || !pin) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Group interface not connected");
		return -1;
	}

	if (wps_mode == WFD_OEM_WPS_MODE_PBC)
		snprintf(cmd, sizeof(cmd), WS_CMD_WPS_PBC "p2p_dev_addr=" MACSTR, MAC2STR(peer_addr));
	else
		snprintf(cmd, sizeof(cmd), WS_CMD_WPS_PIN MACSTR " %s", MAC2STR(peer_addr), pin);

	res = _ws_send_cmd(sock->ctrl_sock, cmd,reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to start WPS");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to start WPS");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_enrollee_start(unsigned char *peer_addr, int wps_mode, const char *pin)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->group;
	char cmd[64] = {0, };
	char reply[1024]={0,};
	int res;

	if (!peer_addr || !pin) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	if (wps_mode == WFD_OEM_WPS_MODE_PBC)
		snprintf(cmd, sizeof(cmd), WS_CMD_WPS_ENROLLEE MACSTR "%s",
					MAC2STR(peer_addr), _ws_wps_to_txt(wps_mode));
	else
		snprintf(cmd, sizeof(cmd), WS_CMD_WPS_ENROLLEE MACSTR " %s%s",
					MAC2STR(peer_addr), pin, _ws_wps_to_txt(wps_mode));

	res = _ws_send_cmd(sock->ctrl_sock, cmd,reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to start WPS");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to start WPS");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_wps_cancel()
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->group;
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	res = _ws_send_cmd(sock->ctrl_sock, WS_CMD_WPS_CANCEL, reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to cancel WPS");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to cancel WPS");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_dev_name(char *dev_name)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_dev_name(char *dev_name)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[128] = {0, };
	char reply[1024]={0,};
	int res;

	if (!dev_name || !strlen(dev_name)) {
		WDP_LOGE( "Invalid parameter");
	 	__WDP_LOG_FUNC_EXIT__;
	 	return 1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_SET "device_name %s", dev_name);
	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to set device name");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to set device name");

	memset(cmd, 0x0, 128);
	memset(reply, 0x0, 1024);

	snprintf(cmd, sizeof(cmd), WS_CMD_SET "p2p_ssid_postfix %s", dev_name);
	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to set SSID postfix");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to set SSID postfix");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_dev_mac(char *dev_mac)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_dev_type(int *pri_dev_type, int *sec_dev_type)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_dev_type(int pri_dev_type, int sec_dev_type)
{
	__WDP_LOG_FUNC_ENTER__;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_go_intent(int *go_intent)
{
	__WDP_LOG_FUNC_ENTER__;

	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	if (go_intent == NULL)
	{
		WDP_LOGE("p2p_go_intent is NULL");
	 	__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_GET "p2p_go_intent");
	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to set go intent");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	*go_intent = atoi(reply);
	WDP_LOGD("Succeeded to get go intent(%d)", *go_intent);

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_go_intent(int go_intent)
{
	__WDP_LOG_FUNC_ENTER__;

	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_SET "p2p_go_intent %d", go_intent);

	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to set go intent");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to set go intent(%d)", go_intent);

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_country(char *ccode)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_SET "country %s", ccode);

	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to set country");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to set country(%s)", ccode);

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int _parsing_networks(char* buf, ws_network_info_s networks[], int *network_cnt)
{
	__WDP_LOG_FUNC_ENTER__;
	char *ptr = buf;
	int count = 0;
	char *tmp_str = NULL;
	int res = 0;

	// Passing first line : "network id / ssid / bssid / flags"
	while (*ptr != '\n') {
		ptr++;
	}
	ptr++;

	count = 0;
	while(*ptr != '\0') {
		res = _extract_word(ptr, &tmp_str);
		if (res > 0) {
			networks[count].network_id = atoi(tmp_str);
			g_free(tmp_str);
			tmp_str = NULL;
			ptr += res;
		}
		ptr++;

		res = _extract_word(ptr, &tmp_str);
		if (res > 0) {
			snprintf(networks[count].ssid, WS_SSID_LEN, "%s", tmp_str);
			free(tmp_str);
			tmp_str = NULL;
			ptr += res;
		}
		ptr++;

		res = _extract_word(ptr, &tmp_str);
		if (res > 0) {
			_ws_txt_to_mac(tmp_str, networks[count].bssid);
			g_free(tmp_str);
			tmp_str = NULL;
			ptr += res;
		}
		ptr++;

		res = _extract_word(ptr, &tmp_str);
		if (res > 0) {
			if (strstr(tmp_str, "CURRENT"))
				networks[count].flags |= WFD_OEM_NETFLAG_CURRENT;
			if (strstr(tmp_str, "DISABLED"))
				networks[count].flags |= WFD_OEM_NETFLAG_DISABLED;
			if (strstr(tmp_str, "TEMP-DISABLED"))
				networks[count].flags |= WFD_OEM_NETFLAG_TEMP_DISABLED;
			if (strstr(tmp_str, "P2P-PERSISTENT"))
				networks[count].flags |= WFD_OEM_NETFLAG_P2P_PERSISTENT;
			g_free(tmp_str);
			tmp_str = NULL;
			ptr += res;
		}
		ptr++;

		count++;
	}

	*network_cnt = count;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_get_persistent_groups(wfd_oem_persistent_group_s **groups, int *group_count)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	ws_network_info_s networks[WS_MAX_PERSISTENT_COUNT];
	wfd_oem_persistent_group_s *wfd_persistent_groups = NULL;
	int res;
	int i, cnt;

	if (!groups || !group_count) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	memset(networks, 0, (sizeof(ws_network_info_s) * WS_MAX_PERSISTENT_COUNT));

	/* Reading lists the configured networks, including stored information for persistent groups.
	The identifier in this is used with p2p_group_add and p2p_invite to indicate witch persistent
	group is to be reinvoked. */
	snprintf(cmd, sizeof(cmd), WS_CMD_LIST_NETWORKS);
	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to get list of networks");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to get list of networks");

	_parsing_networks(reply, networks, &cnt);
	WDP_LOGD("Persistent Group Count=%d", cnt);
	if (cnt > WS_MAX_PERSISTENT_COUNT) {
		WDP_LOGE("Persistent group count exceeded or parsing error");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if(cnt == 0) {
		*group_count = cnt;
		*groups = wfd_persistent_groups;

		__WDP_LOG_FUNC_EXIT__;
		return 0;
	}

	wfd_persistent_groups = (wfd_oem_persistent_group_s*) g_try_malloc0(cnt * sizeof(wfd_oem_persistent_group_s));
	if (wfd_persistent_groups == NULL) {
		WDP_LOGE("Failed to allocate memory for wfd_persistent_groups ");
		return -1;
	}

	for(i = 0; i < cnt; i++) {
		WDP_LOGD("----persistent group [%d]----", i);
		WDP_LOGD("network_id=%d", networks[i].network_id);
		WDP_LOGD("ssid=%s", networks[i].ssid);
		WDP_SECLOG("bssid=" MACSTR, MAC2STR(networks[i].bssid));
		WDP_LOGD("flags=%x", networks[i].flags);

		wfd_persistent_groups[i].network_id = networks[i].network_id;
		strncpy(wfd_persistent_groups[i].ssid, networks[i].ssid, WS_SSID_LEN);
		wfd_persistent_groups[i].ssid[WS_SSID_LEN] = '\0';
		memcpy(wfd_persistent_groups[i].go_mac_address, networks[i].bssid, WS_MACADDR_LEN);
	}

	*group_count = cnt;
	*groups = wfd_persistent_groups;

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_remove_persistent_group(char *ssid, unsigned char *bssid)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	int res;
	int i;
	ws_network_info_s networks[WS_MAX_PERSISTENT_COUNT];
	int network_count;

	if (!ssid || !bssid) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	memset(networks, 0, (sizeof(ws_network_info_s) * WS_MAX_PERSISTENT_COUNT));

	strncpy(cmd, WS_CMD_LIST_NETWORKS, sizeof(cmd));
	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to get list of networks");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to get list of networks");

	_parsing_networks(reply, networks, &network_count);

	for(i=0;i<network_count;i++) {
		WDP_LOGD("----persistent group [%d]----", i);
		WDP_LOGD("network_id=%d", networks[i].network_id);
		WDP_LOGD("ssid=%s", networks[i].ssid);
		WDP_SECLOG("bssid=" MACSTR, MAC2STR(networks[i].bssid));
		WDP_LOGD("flags=%x", networks[i].flags);

		if (!memcmp(bssid, networks[i].bssid, WS_MACADDR_LEN) && !strcmp(ssid, networks[i].ssid)) {

			WDP_LOGD("Persistent group found [%d: %s]", networks[i].network_id, ssid);

			memset(cmd, 0x0, sizeof(cmd));
			memset(reply, 0x0, sizeof(reply));

			snprintf(cmd, sizeof(cmd), WS_CMD_REMOVE_NETWORK " %d", networks[i].network_id);
			res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
			if (res < 0) {
				WDP_LOGE("Failed to send command to wpa_supplicant");
				__WDP_LOG_FUNC_EXIT__;
				return -1;
			}

			if (strstr(reply, "FAIL")) {
				WDP_LOGE("Failed to remove persistent group");
				__WDP_LOG_FUNC_EXIT__;
				return -1;
			}
			WDP_LOGD("Succeeded to remove persistent group");

			break;
		}
	}

	if (i == network_count) {
		WDP_LOGE("Persistent group not found [%s]", ssid);
		return -1;
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_set_persistent_reconnect(unsigned char *bssid, int reconnect)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), "%spersistent_reconnect %d", WS_CMD_SET, reconnect);
	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to register WFDS service");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to register WFDS service");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

#ifdef TIZEN_FEATURE_SERVICE_DISCOVERY
int ws_register_local_service(int service_type, char *value)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[100] = {0, };
	char reply[1024]={0,};
	int res;
	char hex[100] = {0, };
	int status;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	memset(cmd, 0x00, 80);
	memset(reply, 0x00, WS_REPLY_LEN);

	switch (service_type) {
		case WFD_OEM_SERVICE_TYPE_BT_ADDR:
			WDP_LOGD("Service type: WIFI_DIRECT_SERVICE_TYPE_BT_ADDR");
			status = _string_to_hexstring(hex, value);
			if (!status)
				return -1;

			WDP_LOGD("bt addr in hex [%s]", hex);
			snprintf(cmd, sizeof(cmd), WS_CMD_SERVICE_ADD " vendor_samsung %s %s%s" ,
					SERVICE_TYPE_BT_ADDR, SERVICE_TYPE_BT_ADDR, hex);
			break;
		case WFD_OEM_SERVICE_TYPE_CONTACT_INFO:
			WDP_LOGD("Service type: WFD_OEM_SERVICE_TYPE_CONTACT_INFO");
			WDP_LOGD("Service value [%s]", value);

			status = _string_to_hexstring(hex, value);
			if (!status)
				return -1;

			WDP_LOGD("Service value in hex [%s]", hex);
			snprintf(cmd, sizeof(cmd), WS_CMD_SERVICE_ADD " vendor_samsung %s %s%s" ,
					SERVICE_TYPE_CONTACT_INFO, SERVICE_TYPE_CONTACT_INFO, hex);
			break;
		default:
			WDP_LOGE("Invalid service type");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to register local service");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to register local service");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_deregister_local_service(int service_type)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	memset(cmd, 0x00, 80);
	memset(reply, 0x00, WS_REPLY_LEN);

	switch (service_type) {
		case WFD_OEM_SERVICE_TYPE_BT_ADDR:
			WDP_LOGD("Service type: WIFI_DIRECT_SERVICE_TYPE_BT_ADDR");
			snprintf(cmd, sizeof(cmd), WS_CMD_SERVICE_DEL " vendor_samsung %s",
					SERVICE_TYPE_BT_ADDR);
			break;
		case WFD_OEM_SERVICE_TYPE_CONTACT_INFO:
			WDP_LOGD("Service type: WFD_OEM_SERVICE_TYPE_CONTACT_INFO");
			snprintf(cmd, sizeof(cmd), WS_CMD_SERVICE_DEL " vendor_samsung %s",
					SERVICE_TYPE_CONTACT_INFO);
			break;
		default:
			WDP_LOGE("Invalid Service type");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
	}

	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to deregister local service");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to deregister local service");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_start_service_discovery(unsigned char *mac_addr, int service_type)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	int res;
	char query[30] = {'0','2','0','0','F','F','0','1'};
	char mac_str[18] = {0, };
	wfd_oem_service_s *service = NULL;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	memset(cmd, 0x00, 80);
	memset(reply, 0x00, WS_REPLY_LEN);

	query[1] += OEM_SERVICE_TYPE_LEN /2;
	service = (wfd_oem_service_s*) g_try_malloc0(sizeof(wfd_oem_service_s));
	if (!service) {
		WDP_LOGE("Failed to allocate memory for service");
		return -1;
	}
	if (!service) {
		WDP_LOGE("Failed to allocate memory for service");
		return -1;
	}

	if (mac_addr[0] == 0 && mac_addr[1] == 0 && mac_addr[2] == 0 &&
		mac_addr[3] == 0 && mac_addr[4] == 0 && mac_addr[5] == 0) {
		snprintf(mac_str, WS_MACSTR_LEN , "%s", SERV_BROADCAST_ADDRESS);
	} else {
		snprintf(mac_str, WS_MACSTR_LEN, MACSTR, MAC2STR(mac_addr));
	}

	switch(service_type) {
		case WFD_OEM_SERVICE_TYPE_ALL:
			snprintf(cmd, sizeof(cmd), WS_CMD_SERV_DISC_REQ " %s %s", mac_str, SERV_DISC_REQ_ALL);
			strncpy(service->service_type, SERV_DISC_REQ_ALL, OEM_SERVICE_TYPE_LEN);
			service->service_type[OEM_SERVICE_TYPE_LEN] = '\0';
		break;
		case WFD_OEM_SERVICE_TYPE_BONJOUR:
			snprintf(cmd, sizeof(cmd), WS_CMD_SERV_DISC_REQ " %s %s", mac_str, SERV_DISC_REQ_BONJOUR);
			strncpy(service->service_type, SERV_DISC_REQ_BONJOUR, OEM_SERVICE_TYPE_LEN);
			service->service_type[OEM_SERVICE_TYPE_LEN] = '\0';
		break;
		case WFD_OEM_SERVICE_TYPE_UPNP:
			snprintf(cmd, sizeof(cmd), WS_CMD_SERV_DISC_REQ " %s %s", mac_str, SERV_DISC_REQ_UPNP);
			strncpy(service->service_type, SERV_DISC_REQ_UPNP, OEM_SERVICE_TYPE_LEN);
			service->service_type[OEM_SERVICE_TYPE_LEN] = '\0';
		break;
		case WFD_OEM_SERVICE_TYPE_BT_ADDR:
			strncat(query, SERVICE_TYPE_BT_ADDR, OEM_SERVICE_TYPE_LEN);
			snprintf(cmd, sizeof(cmd), WS_CMD_SERV_DISC_REQ " %s %s", mac_str, query);
			strncpy(service->service_type, SERVICE_TYPE_BT_ADDR, OEM_SERVICE_TYPE_LEN);
			service->service_type[OEM_SERVICE_TYPE_LEN] = '\0';
			break;
		case WFD_OEM_SERVICE_TYPE_CONTACT_INFO:
			strncat(query, SERVICE_TYPE_CONTACT_INFO, OEM_SERVICE_TYPE_LEN);
			snprintf(cmd, sizeof(cmd), WS_CMD_SERV_DISC_REQ " %s %s", mac_str, query);
			strncpy(service->service_type, SERVICE_TYPE_CONTACT_INFO, OEM_SERVICE_TYPE_LEN);
			service->service_type[OEM_SERVICE_TYPE_LEN] = '\0';
			break;
		default:
			WDP_LOGE("Invalid Service type");
			__WDP_LOG_FUNC_EXIT__;
			if (service)
				free(service);
			return -1;
	}

	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		if (service)
			free(service);
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to start service discovery");
		__WDP_LOG_FUNC_EXIT__;
		if (service)
			free(service);
		return -1;
	}
	WDP_LOGD("Succeeded to start service discovery");

	strncpy(service->dev_addr, mac_str, OEM_MACSTR_LEN - 1);
	service->dev_addr[OEM_MACSTR_LEN - 1] = '\0';
	WDP_LOGD("query id :[0x%s]",reply);
	strncpy(service->query_id, reply, OEM_QUERY_ID_LEN);
	service->query_id[OEM_QUERY_ID_LEN] = '\0';

	res = _check_service_query_exists(service);
	if(res) {
		free(service);
	} else {
		service_list = g_list_append(service_list, service);
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_cancel_service_discovery(unsigned char *mac_addr, int service_type)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	int res;
	char query_id[OEM_QUERY_ID_LEN + 1] = {0, };
	char mac_str[18] = {0, };
	wfd_oem_service_s *data = NULL;
	char s_type[OEM_SERVICE_TYPE_LEN + 1] ={0, };

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	memset(cmd, 0x00, 80);
	memset(reply, 0x00, WS_REPLY_LEN);

	if (mac_addr[0] == 0 && mac_addr[1] == 0 && mac_addr[2] == 0 &&
		mac_addr[3] == 0 && mac_addr[4] == 0 && mac_addr[5] == 0) {
		snprintf(mac_str, WS_MACSTR_LEN , "%s", SERV_BROADCAST_ADDRESS);
	} else {
		snprintf(mac_str, WS_MACSTR_LEN, MACSTR, MAC2STR(mac_addr));
	}

	switch(service_type) {
		case WFD_OEM_SERVICE_TYPE_ALL:
			strncpy(s_type, SERV_DISC_REQ_ALL, OEM_SERVICE_TYPE_LEN);
		break;
		case WFD_OEM_SERVICE_TYPE_BONJOUR:
			strncpy(s_type, SERV_DISC_REQ_BONJOUR, OEM_SERVICE_TYPE_LEN);
		break;
		case WFD_OEM_SERVICE_TYPE_UPNP:
			strncpy(s_type, SERV_DISC_REQ_UPNP, OEM_SERVICE_TYPE_LEN);
		break;
		case WFD_OEM_SERVICE_TYPE_BT_ADDR:
			strncpy(s_type, SERVICE_TYPE_BT_ADDR, OEM_SERVICE_TYPE_LEN);
			break;
		case WFD_OEM_SERVICE_TYPE_CONTACT_INFO:
			strncpy(s_type, SERVICE_TYPE_CONTACT_INFO, OEM_SERVICE_TYPE_LEN);
			break;
		default:
			__WDP_LOG_FUNC_EXIT__;
			WDP_LOGE("Invalid Service type");
			return -1;
	}

	WDP_LOGD("Cancel service discovery service_type [%d]", service_type);
	WDP_LOGD("Cancel service discovery s_type [%s]", s_type);

	data = _remove_service_query(s_type, mac_str, query_id);
	if (NULL == data)
		return -1;

	snprintf(cmd, sizeof(cmd), WS_CMD_SERV_DISC_CANCEL " %s", query_id);
	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to cancel service discovery");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to cancel service discovery");

	service_list = g_list_remove(service_list, data);
	free(data);

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int _convert_bonjour_to_hex(char *query, char *rdata, char **hex)
{
	char hex_key[256] = {0, };;
	char hex_value[256] = {0, };;
	char *token = NULL;
	char *temp = NULL;
	int len = 0;
	int tot_len = 0;
	int i = 0;
	char temp_str[256] = {0, };
	char *result_str = NULL;

	if (!query || !hex) {
		WDP_LOGE("Invalid parameter");
		return -1;
	}

	token = strtok_r(query, ".", &temp);
	while (token) {
		if (!strcmp(token, "local")) {
			WDP_LOGD("Query conversion done");
			break;
		}
		WDP_LOGD("Token: %s", token);
		len = strlen(token);
		sprintf(temp_str, "%02x", len);
		for (i=0; i<len; i++) {
			sprintf(temp_str+i*2+2, "%02x", token[i]);
		}
		strncat(hex_key, temp_str, 2+2*len);
		WDP_LOGD("Converting: %s", hex_key);
		memset(temp_str, 0x0, 256);

		token = strtok_r(NULL, ".", &temp);
	}

	if (token && strstr(token, "local")) {
		strncat(hex_key, "c011", 4);
		strncat(hex_key, "000c", 4);
		strncat(hex_key, "01", 2);
	} else {
		strncat(hex_key, "c011", 4);
		strncat(hex_key, "0010", 4);
		strncat(hex_key, "01", 2);
	}

	if (!rdata || !strlen(rdata)) {
		WDP_LOGD("RDATA is NULL");
		strncat(hex_value, "00", 2);
	} else {
		token = strtok_r(rdata, ".", &temp);
		while (token) {
			WDP_LOGD("Token: %s", token);
			len = strlen(token);
			sprintf(temp_str, "%02x", len);
			for (i=0; i<len; i++) {
				sprintf(temp_str+i*2+2, "%02x", token[i]);
			}
			strncat(hex_value, temp_str, 2+2*len);
			WDP_LOGD("Converting: %s", hex_value);
			memset(temp_str, 0x0, 256);

			token = strtok_r(NULL, ".", &temp);
		}
	}

	strncat(hex_value, "c027", 4);

	tot_len = strlen(hex_key) + strlen(hex_value);
	result_str = (char*) g_try_malloc0(tot_len+2);
	if (!result_str) {
		WDP_LOGE("Failed to allocate memory for result string");
		return -1;
	}
	snprintf(result_str, tot_len+2, "%s %s", hex_key, hex_value);

	*hex = result_str;

	return 0;
}

int ws_serv_add(wfd_oem_new_service_s *service)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[256] = {0, };
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	switch (service->protocol) {
	case WFD_OEM_SERVICE_TYPE_BONJOUR:
		{
			WDP_LOGD("Service type: WFD_OEM_SERVICE_TYPE_BONJOUR");
			WDP_LOGD("Query: %s", service->data.bonjour.query);
			WDP_LOGD("RData: %s", service->data.bonjour.rdata);
			char *hex = NULL;

			res = _convert_bonjour_to_hex(service->data.bonjour.query,
								    service->data.bonjour.rdata,
								    &hex);
			if (res < 0) {
				WDP_LOGE("Failed to convert Key string as hex string");
				return -1;
			}

			WDP_LOGD("Converted Hexadecimal string [%s]", hex);
			snprintf(cmd, sizeof(cmd), WS_CMD_SERVICE_ADD " bonjour %s", hex);
			g_free(hex);

		}
		break;
	case WFD_OEM_SERVICE_TYPE_UPNP:
		{
			WDP_LOGD("Service type: WFD_OEM_SERVICE_TYPE_UPNP");

			snprintf(cmd, sizeof(cmd), WS_CMD_SERVICE_ADD " upnp %s %s",
					service->data.upnp.version, service->data.upnp.service);
		}
		break;
	default:
		WDP_LOGE("This service type is not supported [%d]", service->protocol);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to add service");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to add service");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int ws_serv_del(wfd_oem_new_service_s *service)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[256] = {0, };
	char reply[1024]={0,};
	int res;

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	switch (service->protocol) {
	case WFD_OEM_SERVICE_TYPE_BONJOUR:
		{
			WDP_LOGD("Service type: WFD_OEM_SERVICE_TYPE_BONJOUR, Data: %s", service);
			char *hex_key = NULL;

			res = _convert_bonjour_to_hex(service->data.bonjour.query, NULL, &hex_key);
			if (res != 0) {
				WDP_LOGE("Failed to convert Key string as hex string");
				return -1;
			}

			WDP_LOGD("Converted Hexadecimal string [%s]", hex_key);
			snprintf(cmd, sizeof(cmd), WS_CMD_SERVICE_DEL " bonjour %s", hex_key);
			g_free(hex_key);
		}
		break;
	case WFD_OEM_SERVICE_TYPE_UPNP:
		{
			WDP_LOGD("Service type: WFD_OEM_SERVICE_TYPE_UPNP");

			snprintf(cmd, sizeof(cmd), WS_CMD_SERVICE_DEL " upnp %s %s",
					service->data.upnp.version, service->data.upnp.service);
		}
		break;
	default:
		WDP_LOGE("This service type is not supported");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to add service");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to add service");

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}
#endif /* TIZEN_FEATURE_SERVICE_DISCOVERY */

#ifdef TIZEN_FEATURE_WIFI_DISPLAY
int ws_miracast_init(int enable)
{
	__WDP_LOG_FUNC_ENTER__;
	ws_sock_data_s *sock = g_pd->common;
	char cmd[80] = {0, };
	char reply[1024]={0,};
	int res;

	unsigned int length = 0x0006;
	unsigned int dev_info = 0x0110;
	unsigned int ctrl_port = 0x07E6;
	unsigned int max_tput = 0x0028;
	//unsigned int bssid = 0x00;
	unsigned int cpled_sink_status = 0x00;
	/* param : enable or disable*/

	if (!sock) {
		WDP_LOGE("Socket is NULL");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), WS_CMD_SET "wifi_display %d", enable);

	res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
	if (res < 0) {
		WDP_LOGE("Failed to send command to wpa_supplicant");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (strstr(reply, "FAIL")) {
		WDP_LOGE("Failed to initialize miracast");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}
	WDP_LOGD("Succeeded to initialize miracast");

	if (enable) {
		/* param : dev_info */
		memset(cmd, 0x0, 80);
		memset(reply, 0x0, WS_REPLY_LEN);

		snprintf(cmd, sizeof(cmd), WS_CMD_SUBELEM_SET "%d %04x%04x%04x%04x",
								WFD_SUBELM_ID_DEV_INFO, length, dev_info, ctrl_port, max_tput);
		res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
		if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}

		if (strstr(reply, "FAIL")) {
			WDP_LOGE("Failed to set miracast parameter(device info)");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
		WDP_LOGD("Succeeded to set miracast parameter(device info)");

		/* param : Associated BSSID Subelement */
		memset(cmd, 0x0, 80);
		memset(reply, 0x0, WS_REPLY_LEN);

		snprintf(cmd, sizeof(cmd), WS_CMD_SUBELEM_SET "%d %04x%s",
								WFD_SUBELM_ID_ASSOC_BSSID, 0x06, "000000000000");
		res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
		if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}

		if (strstr(reply, "FAIL")) {
			WDP_LOGE("Failed to set miracast parameter(BSSID subelement)");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
		WDP_LOGD("Succeeded to set miracast parameter(BSSID subelement)");

		/* param : cpled_sink_status */
		memset(cmd, 0x0, 80);
		memset(reply, 0x0, WS_REPLY_LEN);

		snprintf(cmd, sizeof(cmd), WS_CMD_SUBELEM_SET "%d %04x%02x",
								WFD_SUBELM_ID_CUPLED_SYNC_INFO, 0x01, cpled_sink_status);
		res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
		if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}

		if (strstr(reply, "FAIL")) {
			WDP_LOGE("Failed to set miracast parameter(Cuppled sink status)");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
		WDP_LOGD("Succeeded to set miracast parameter(Cuppled sink status)");


		/* param : WFD Extended Capability */
		memset(cmd, 0x0, 80);
		memset(reply, 0x0, WS_REPLY_LEN);

		snprintf(cmd, sizeof(cmd), WS_CMD_SUBELEM_SET "%d %04x%04x",
								WFD_SUBELM_ID_EXT_CAPAB, 0x02, 0x00);
		res = _ws_send_cmd(sock->ctrl_sock, cmd, (char*) reply, sizeof(reply));
		if (res < 0) {
			WDP_LOGE("Failed to send command to wpa_supplicant");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}

		if (strstr(reply, "FAIL")) {
			WDP_LOGE("Failed to set miracast parameter(Extended Capability)");
			__WDP_LOG_FUNC_EXIT__;
			return -1;
		}
		WDP_LOGD("Succeeded to set miracast parameter(Extended Capability)");

	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}
#endif /* TIZEN_FEATURE_WIFI_DISPLAY */

int ws_refresh()
{
	__WDP_LOG_FUNC_ENTER__;

	_ws_cancel();
	_ws_flush();

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}
