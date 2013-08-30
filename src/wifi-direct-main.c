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


/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <stdbool.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <linux/unistd.h>
#include <glib.h>
#include <glib-object.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/utsname.h>

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/
#include "vconf-keys.h"

/*****************************************************************************
 * 	Wi-Fi Direct Server headers
 *****************************************************************************/
#include "wifi-direct.h"
#include "wifi-direct-stub.h"
#include "wifi-direct-service.h"
#include "wifi-direct-utils.h"
#include "wifi-direct-event-handler.h"
#include "wifi-direct-oem.h"

/*****************************************************************************
 * 	Wi-Fi Macros
 *****************************************************************************/


/*****************************************************************************
 * 	Wi-Fi Global variables
 *****************************************************************************/
wfd_server_control_t g_wfd_server;


void wfd_server_process_event(wfd_event_t event);


char *wfd_server_print_cmd(wifi_direct_cmd_e cmd)
{
	switch (cmd)
	{
	case WIFI_DIRECT_CMD_REGISTER:
		return "WIFI_DIRECT_CMD_REGISTER";
	case WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET:
		return "WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET";
	case WIFI_DIRECT_CMD_DEREGISTER:
		return "WIFI_DIRECT_CMD_DEREGISTER";
	case WIFI_DIRECT_CMD_ACTIVATE:
		return "WIFI_DIRECT_CMD_ACTIVATE";
	case WIFI_DIRECT_CMD_DEACTIVATE:
		return "WIFI_DIRECT_CMD_DEACTIVATE";
	case WIFI_DIRECT_CMD_START_DISCOVERY:
		return "WIFI_DIRECT_CMD_START_DISCOVERY";
	case WIFI_DIRECT_CMD_CANCEL_DISCOVERY:
		return "WIFI_DIRECT_CMD_CANCEL_DISCOVERY";
	case WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT:
		return "WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT";
	case WIFI_DIRECT_CMD_GET_LINK_STATUS:
		return "WIFI_DIRECT_CMD_GET_LINK_STATUS";
	case WIFI_DIRECT_CMD_CONNECT:
		return "WIFI_DIRECT_CMD_CONNECT";

	case WIFI_DIRECT_CMD_DISCONNECT_ALL:
		return "WIFI_DIRECT_CMD_DISCONNECT_ALL";
	case WIFI_DIRECT_CMD_CREATE_GROUP:
		return "WIFI_DIRECT_CMD_CREATE_GROUP";
	case WIFI_DIRECT_CMD_IS_GROUPOWNER:
		return "WIFI_DIRECT_CMD_IS_GROUPOWNER";
	case WIFI_DIRECT_CMD_GET_SSID:
		return "WIFI_DIRECT_CMD_GET_SSID";
	case WIFI_DIRECT_CMD_SET_SSID:
		return "WIFI_DIRECT_CMD_SET_SSID";
	case WIFI_DIRECT_CMD_GET_IP_ADDR:
		return "WIFI_DIRECT_CMD_GET_IP_ADDR";
	case WIFI_DIRECT_CMD_GET_CONFIG:
		return "WIFI_DIRECT_CMD_GET_CONFIG";
	case WIFI_DIRECT_CMD_SET_CONFIG:
		return "WIFI_DIRECT_CMD_SET_CONFIG";
	case WIFI_DIRECT_CMD_SEND_PROVISION_DISCOVERY_REQ:
		return "WIFI_DIRECT_CMD_SEND_PROVISION_DISCOVERY_REQ";
	case WIFI_DIRECT_CMD_SEND_CONNECT_REQ:
		return "WIFI_DIRECT_CMD_SEND_CONNECT_REQ";

	case WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON:
		return "WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON";
	case WIFI_DIRECT_CMD_SET_WPS_PIN:
		return "WIFI_DIRECT_CMD_SET_WPS_PIN";
	case WIFI_DIRECT_CMD_GET_WPS_PIN:
		return "WIFI_DIRECT_CMD_GET_WPS_PIN";
	case WIFI_DIRECT_CMD_GENERATE_WPS_PIN:
		return "WIFI_DIRECT_CMD_GENERATE_WPS_PIN";
	case WIFI_DIRECT_CMD_GET_INCOMMING_PEER_INFO:
		return "WIFI_DIRECT_CMD_GET_INCOMMING_PEER_INFO";
	case WIFI_DIRECT_CMD_SET_WPA:
		return "WIFI_DIRECT_CMD_SET_WPA";
	case WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE:
		return "WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE";
	case WIFI_DIRECT_CMD_SET_CURRENT_WPS_MODE:
		return "WIFI_DIRECT_CMD_SET_CURRENT_WPS_MODE";
	case WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO:
		return "WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO";
	case WIFI_DIRECT_CMD_CANCEL_GROUP:
		return "WIFI_DIRECT_CMD_CANCEL_GROUP";

	case WIFI_DIRECT_CMD_DISCONNECT:
		return "WIFI_DIRECT_CMD_DISCONNECT";
	case WIFI_DIRECT_CMD_SET_GO_INTENT:
		return "WIFI_DIRECT_CMD_SET_GO_INTENT";
	case WIFI_DIRECT_CMD_GET_GO_INTENT:
		return "WIFI_DIRECT_CMD_GET_GO_INTENT";
	case WIFI_DIRECT_CMD_GET_DEVICE_MAC:
		return "WIFI_DIRECT_CMD_GET_DEVICE_MAC";
	case WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP:
		return "WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP";
	case WIFI_DIRECT_CMD_SET_MAX_CLIENT:
		return "WIFI_DIRECT_CMD_SET_MAX_CLIENT";
	case WIFI_DIRECT_CMD_GET_MAX_CLIENT:
		return "WIFI_DIRECT_CMD_GET_MAX_CLIENT";
	case WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE:
		return "WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE";
	case WIFI_DIRECT_CMD_IS_AUTOCONNECTION_MODE:
		return "WIFI_DIRECT_CMD_IS_AUTOCONNECTION_MODE";
	case WIFI_DIRECT_CMD_IS_DISCOVERABLE:
		return "WIFI_DIRECT_CMD_IS_DISCOVERABLE";
	case WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL:
		return "WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL";
	case WIFI_DIRECT_CMD_DEACTIVATE_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_DEACTIVATE_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_IS_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_IS_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO:
		return "WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO";
	case WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_GET_DEVICE_NAME:
		return "WIFI_DIRECT_CMD_GET_DEVICE_NAME";
	case WIFI_DIRECT_CMD_SET_DEVICE_NAME:
		return "WIFI_DIRECT_CMD_SET_DEVICE_NAME";
	case WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL:
		return "WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL";

	default:
		return "WIFI_DIRECT_CMD_INVALID";

	}
}

wfd_server_control_t *wfd_server_get_control()
{
	return &g_wfd_server;
}

static gboolean wfd_server_accept_client_socket(GIOChannel* source, GIOCondition condition, gpointer data)
{
	int clientfd = -1;
	socklen_t clientlen = 0;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int servfd = wfd_server->async_sockfd;

	__WDS_LOG_FUNC_ENTER__;

	if (servfd < 0)
	{
		WDS_LOGE("Invalid sockfd argument = [%d]", servfd);
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	}

	errno = 0;
	clientfd = accept(servfd, NULL, &clientlen);
	if (clientfd == -1)
	{
		WDS_LOGE("Failed to accept client socket. Error = [%s]. Server socket = [%d]", strerror(errno), servfd);

		int ret = 0;
		char req[10] = "";
		int reqlen = 10;

		errno = 0;
		ret = read(servfd, req, reqlen);
		if (ret == 0)
		{
			WDS_LOGD("Server Socket got closed");
		}
		else if (ret < 0)
		{
			WDS_LOGE( "Failed to read server socket. Error = [%s]", strerror(errno));
		}
		else
			WDS_LOGD( "Read [%d] data\n", ret);

		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	WDS_LOGD("Succeeded to accept client: [%d]", clientfd);

	if (!(wfd_server_register_client(clientfd)))
	{
		WDS_LOGE("Failed to add new client\n");
		close(clientfd);
	}
	__WDS_LOG_FUNC_EXIT__;
	return true;
}

static int wfd_server_create_socket(void)
{
	int len = 0;
	int sockfd = -1;
	struct sockaddr_un servAddr;
	mode_t sock_mode;
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	__WDS_LOG_FUNC_ENTER__;

	/** It is safe to Unlink the path.*/
	unlink(WFD_SERVER_SOCKET_PATH);
	errno = 0;
	sockfd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sockfd < 3)
	{
		WDS_LOGE( "Failed to create UNIX socket. Error = [%s]", strerror(errno));
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sun_family = AF_UNIX;
	strcpy(servAddr.sun_path, WFD_SERVER_SOCKET_PATH);
	len = sizeof(servAddr.sun_family) + strlen(WFD_SERVER_SOCKET_PATH);

	errno = 0;

	sock_mode = (S_IRWXU | S_IRWXG | S_IRWXO);

	if (bind(sockfd, (struct sockaddr *) &servAddr, len) == -1)
	{
		WDS_LOGE( "Failed to bind server socket. Error = [%s]", strerror(errno));
		if (sockfd > 2)
			close(sockfd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	WDS_LOGD("Succeeded to bind server socket.");

	if (chmod(WFD_SERVER_SOCKET_PATH, sock_mode) < 0)
	{
		WDS_LOGD( "Failed to change server socket file mode");
		if (sockfd > 2)
			close(sockfd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	errno = 0;
	if (listen(sockfd, WFD_MAX_CLIENTS) == -1)
	{
		WDS_LOGF( "Failed to listen server socket. Error = [%s]", strerror(errno));
		if (sockfd > 2)
			close(sockfd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	wfd_server->async_sockfd = sockfd;

	WDS_LOGD( "Succeeded to create server socket [%d]", sockfd);
	__WDS_LOG_FUNC_EXIT__;
	return 1;
}

static void *wfd_load_plugin()
{
	void *handle;
	struct utsname kernel_info;
	int res;    

	res = uname(&kernel_info);
	if(res != 0)
		WDS_LOGE("Failed to detect target type");
	else
		WDS_LOGD("Node name [%s], HW ID [%s]", kernel_info.nodename, kernel_info.machine);

	handle = dlopen("/usr/lib/wifi-direct-plugin-wpasupplicant.so", RTLD_NOW);
	if (!handle) {
		WDS_LOGE("Failed to open shared object");
		fputs(dlerror(), stderr);
		return NULL;
	}

	int (*plugin_load)(struct wfd_oem_operations **ops) = NULL;
	plugin_load = (int (*)(struct wfd_oem_operations **ops))dlsym(handle, "wfd_plugin_load");

	if (!plugin_load) {
		WDS_LOGF( "Failed to load symbol. Error = [%s]", strerror(errno));
		dlclose(handle);
		return NULL;
	}

	struct wfd_oem_operations *temp_ops;
	(*plugin_load)(&temp_ops);
	g_ops = temp_ops;

	return handle;
}


/*****************************************************************************
 * 	Wi-Fi Global Function Definition
 *****************************************************************************/

static int wfd_server_init(void)
{
	__WDS_LOG_FUNC_ENTER__;

	memset(&g_wfd_server, 0x00, sizeof(wfd_server_control_t));
	g_wfd_server.async_sockfd = -1;
	g_wfd_server.sync_sockfd = -1;

	// ToDo: Read them from repository.
	g_wfd_server.config_data.channel = 11;
	g_wfd_server.config_data.wps_config = WIFI_DIRECT_WPS_TYPE_PBC;
	g_wfd_server.config_data.req_wps_config = WIFI_DIRECT_WPS_TYPE_PBC;
	g_wfd_server.config_data.auto_connection = false;
	g_wfd_server.config_data.want_persistent_group = false;
	g_wfd_server.config_data.max_clients = WFD_MAX_ASSOC_STA;
	g_wfd_server.config_data.hide_SSID = false;
	g_wfd_server.config_data.group_owner_intent = 8;
	g_wfd_server.config_data.primary_dev_type = WIFI_DIRECT_PRIMARY_DEVICE_TYPE_TELEPHONE;	// Telephone
	g_wfd_server.config_data.secondary_dev_type = WIFI_DIRECT_SECONDARY_DEVICE_TYPE_PHONE_SM_DUAL;	// smart phone dual mode (wifi and cellular)

	g_wfd_server.plugin_handle = wfd_load_plugin();
	if (g_wfd_server.plugin_handle == NULL)
		return -1;

	wfd_oem_init(wfd_server_process_event);

	wfd_set_device_name_from_phone_name();

	wfd_set_DHCP_event_handler();

	if (wfd_set_wifi_direct_state(WIFI_DIRECT_STATE_DEACTIVATED) < 0)
		WDS_LOGE( "Failed to  set Wi-Fi Direct state");

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static int wfd_server_destroy()
{
	__WDS_LOG_FUNC_ENTER__;

	if (g_wfd_server.async_sockfd>0)
		close(g_wfd_server.async_sockfd);
	unlink(WFD_SERVER_SOCKET_PATH);

	memset(&g_wfd_server, 0, sizeof(wfd_server_control_t));

	wfd_oem_destroy();

	if (g_wfd_server.plugin_handle != NULL)
		dlclose(g_wfd_server.plugin_handle);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

static gboolean wfd_connection_timeout_cb(void *user_data)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();
	wifi_direct_client_noti_s noti;

	g_source_remove(wfd_server->connection_timer);
	wfd_server->connection_timer = 0;
	wfd_server->connecting_120 = 0;
	wfd_oem_reject_connection(wfd_server->current_peer.mac_address);

	if (wfd_oem_is_groupowner())
		wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	else
		wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);

	memset(&noti, 0, sizeof(wifi_direct_client_noti_s));
	snprintf(noti.param1, sizeof(noti.param1),MACSTR, MAC2STR(wfd_server->current_peer.mac_address));

	noti.event = WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP;
	noti.error = WIFI_DIRECT_ERROR_CONNECTION_TIME_OUT;

	wfd_server_reset_connecting_peer();
	wfd_server_clear_connected_peer();

	__wfd_server_send_client_event(&noti);

	__WDS_LOG_FUNC_EXIT__;
	return FALSE;
}

void wfd_timer_connection_start()
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->connection_timer > 0)
		g_source_remove(wfd_server->connection_timer);

	wfd_server->connection_timer = 0;
	wfd_server->connecting_120 = 1;

	wfd_server->connection_timer = g_timeout_add(120000 /* 120 seconds*/, (GSourceFunc)wfd_connection_timeout_cb , NULL);

	__WDS_LOG_FUNC_EXIT__;
}

void wfd_timer_connection_cancel()
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->connection_timer > 0)
		g_source_remove(wfd_server->connection_timer);

	wfd_server->connection_timer = 0;

	__WDS_LOG_FUNC_EXIT__;
}


static gboolean wfd_termination_timeout_cb(void *user_data)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->active_clients > 0)
	{
		WDS_LOGD( "There is an active clients(Num=[%d]). Run timer again...", wfd_server->active_clients);
		// Restart timer by returning true.
		return TRUE;
	}

	int state = wfd_server_get_state();

	if (state != WIFI_DIRECT_STATE_DEACTIVATED)
	{
		WDS_LOGD( "State is not 'deactivated' ( state=[%d] ).  Cancel timer.", state);
		// Cancel timer by returning false.
		return FALSE;
	}

	if (wfd_server->async_sockfd > 0)
		close(wfd_server->async_sockfd);

	g_main_quit(wfd_server->mainloop);

	WDS_LOGD( "g_main_quit()...");
	__WDS_LOG_FUNC_EXIT__;

	// Cancel timer by returning false.
	return FALSE;
}


void wfd_termination_timer_start()
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->termination_timer > 0)
	{
		g_source_remove(wfd_server->termination_timer);
		WDS_LOGD( "Termination timer is restarted..\n");
	}
	else
	{
		WDS_LOGD( "Termination timer is started..\n");
	}

	wfd_server->termination_timer = 0;

	wfd_server->termination_timer = g_timeout_add(120000 /* 120 seconds*/, (GSourceFunc)wfd_termination_timeout_cb , NULL);


	__WDS_LOG_FUNC_EXIT__;
}


void wfd_termination_timer_cancel()
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->termination_timer > 0)
		g_source_remove(wfd_server->termination_timer);

	wfd_server->termination_timer = 0;
	WDS_LOGD( "Termination timer is canceled..\n");

	__WDS_LOG_FUNC_EXIT__;
}

static gboolean wfd_discovery_timeout_cb(void *user_data)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int ret;

	g_source_remove(wfd_server->discovery_timer);
	wfd_server->discovery_timer = 0;

	if (wfd_oem_is_groupowner())
	{
		wfd_server_set_state(WIFI_DIRECT_STATE_GROUP_OWNER);
	}
	else
	{
		wfd_server_set_state(WIFI_DIRECT_STATE_ACTIVATED);
	}

	ret = wfd_oem_cancel_discovery();
	if (ret == false)
	{
		WDS_LOGE( "Error!! wfd_oem_cancel_discovery() failed..\n");
	}

	__WDS_LOG_FUNC_EXIT__;
	return FALSE;
}

void wfd_timer_discovery_start(int seconds)
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->discovery_timer> 0)
		g_source_remove(wfd_server->discovery_timer);

	wfd_server->discovery_timer = 0;

	wfd_server->discovery_timer = g_timeout_add((seconds*1000), (GSourceFunc)wfd_discovery_timeout_cb , NULL);

	__WDS_LOG_FUNC_EXIT__;
}

void wfd_timer_discovery_cancel()
{
	__WDS_LOG_FUNC_ENTER__;

	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (wfd_server->discovery_timer > 0)
		g_source_remove(wfd_server->discovery_timer);

	wfd_server->discovery_timer = 0;

	__WDS_LOG_FUNC_EXIT__;
}

int main(gint argc, gchar * argv[])
{
	GMainLoop *mainloop = NULL;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int i = -1;

	__WDS_LOG_FUNC_ENTER__;

	WDS_LOGD("========================================\n");
	WDS_LOGD("=                                      		=\n");
	WDS_LOGD("=         WiFi Direct Server          	=\n");
	WDS_LOGD("=                                      		=\n");
	WDS_LOGD("========================================\n");

	for (i = 0; i < argc; i++)
		WDS_LOGD( "arg[%d]= %s", i, argv[i]);

#if !GLIB_CHECK_VERSION (2, 31, 0)
	if (!g_thread_supported())
		g_thread_init(NULL);
#endif

#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init();
#endif

	mainloop = g_main_loop_new(NULL, FALSE);

	wfd_server_init();

	if (wfd_server_create_socket() == -1)
	{
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	GIOChannel* gio2 = g_io_channel_unix_new(wfd_server->async_sockfd);
	g_io_add_watch(gio2, G_IO_IN, (GIOFunc)wfd_server_accept_client_socket, NULL);
	g_io_channel_unref(gio2);


	wfd_server->mainloop = mainloop;
	wfd_termination_timer_start();

	g_main_loop_run(mainloop);

	WDS_LOGD( "Leave g_main_loop_run()...");

	wfd_server_destroy();

	WDS_LOGD( "WLAN engine is destroyed...");

	WDS_LOGD( "=================================");
	WDS_LOGD( "     Quit WiFi Direct Manager main()");
	WDS_LOGD( "=================================");
	WDS_LOGD( "Bye...\n");

	__WDS_LOG_FUNC_EXIT__;

	return 0;
}
