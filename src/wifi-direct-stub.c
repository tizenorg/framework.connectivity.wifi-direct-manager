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
#include <sys/poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/poll.h>

#include "wifi-direct-client-handler.h"
#include "wifi-direct-service.h"
#include "wifi-direct-internal.h"
#include "wifi-direct-stub.h"

bool wfd_server_client_request_callback(GIOChannel* source, GIOCondition condition, gpointer data);


int wfd_server_is_fd_writable(int fd)
{
	struct pollfd pevent;
	int retval = 0;

	pevent.fd = fd;
	pevent.events = POLLERR | POLLHUP | POLLNVAL | POLLOUT;
	retval = poll((struct pollfd *) &pevent, 1, 1);

	if (retval < 0)
	{
		WDS_LOGD( "fd [%d]: poll error ret=[%d] !!\n", fd, retval);
		return -1;
	}
	else if (retval == 0)
	{
		// fd might be busy.
		WDS_LOGD( "poll timeout. fd is busy\n");
		return 0;
	}

	if (pevent.revents & POLLERR)
	{
		WDS_LOGD( "fd [%d]: POLLERR !!\n", fd);
		return -1;
	}
	else if (pevent.revents & POLLHUP)
	{
		WDS_LOGD( "fd [%d]: POLLHUP !!\n", fd);
		return -1;
	}
	else if (pevent.revents & POLLNVAL)
	{
		WDS_LOGD( "fd [%d]: POLLNVAL !!\n", fd);
		return -1;
	}
	else if (pevent.revents & POLLOUT)
	{
		// fd is writable..
		// WDS_LOGD( "fd [%d]: POLLOUT !!\n", fd);
		return 1;
	}

	return -1;
}


int wfd_server_read_socket_event(int sockfd, char *dataptr, int datalen)
{
	int pollret = 0;
	struct pollfd pollfd;
	int timeout = 1000;			/* For 1 sec */
	int retval = 0;
	int total_data_recd = 0;

	__WDS_LOG_FUNC_ENTER__;

	if (sockfd < 0)
	{
		WDS_LOGE( "Error!!! Invalid socket FD [%d]\n", sockfd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	pollfd.fd = sockfd;
	pollfd.events = POLLIN | POLLERR | POLLHUP;
	pollret = poll(&pollfd, 1, timeout);

	WDS_LOGD( "POLL ret = %d\n", pollret);

	if (pollret > 0)
	{
		if (pollfd.revents == POLLIN)
		{
			WDS_LOGD( "POLLIN \n");

			while (datalen)
			{
				errno = 0;
				retval = read(sockfd, (char*)dataptr, datalen);
				WDS_LOGD( "sockfd %d retval %d\n",sockfd,retval);
				if (retval <= 0)
				{
					WDS_LOGE( "Error!!! reading data, error [%s]\n", strerror(errno));
					__WDS_LOG_FUNC_EXIT__;
					return retval;
				}
				total_data_recd += retval;
				dataptr += retval;
				datalen -= retval;
			}
			__WDS_LOG_FUNC_EXIT__;
			return total_data_recd;
		}
		else if (pollfd.revents & POLLHUP)
		{
			WDS_LOGE( "Error!!! POLLHUP: connection disconnected fd=[%d]\n", sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return -1;
		}
		else if (pollfd.revents & POLLERR)
		{
			WDS_LOGE( "Error!!! POLLERR: error happens at the socket. fd=[%d]\n", sockfd);
			__WDS_LOG_FUNC_EXIT__;
			return -1;
		}
	}
	else if (pollret == 0)
	{
		WDS_LOGD( "POLLing timeout fd=[%d]\n", sockfd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}
	else
	{
		WDS_LOGE( "Error!!! Polling unknown error fd=[%d]\n", sockfd);
		__WDS_LOG_FUNC_EXIT__;
		return -1;
	}

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

void wfd_server_reset_client(int sync_sockfd)
{
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int index = 0;

	__WDS_LOG_FUNC_ENTER__;

	for (index = 0; index < WFD_MAX_CLIENTS; index++)
	{
		if ((wfd_server->client[index].isUsed == TRUE) &&
			(wfd_server->client[index].sync_sockfd == sync_sockfd))
		{
			WDS_LOGI(
					"Reset client[%d]: ClientID=%d, socketfd=(%d,%d), handle=[%d] total active clients = [%d]\n",
					index,
					wfd_server->client[index].client_id,
					wfd_server->client[index].sync_sockfd,
					wfd_server->client[index].async_sockfd,
					wfd_server->client[index].dev_handle,
					wfd_server->active_clients-1);

			g_source_remove(wfd_server->client[index].g_source_id);

			// Protect standard input / output / error
			if (wfd_server->client[index].async_sockfd > 2)
				close(wfd_server->client[index].async_sockfd);

			if (wfd_server->client[index].sync_sockfd > 2)
				close(wfd_server->client[index].sync_sockfd);

			/* Reset Entity */
			wfd_server->client[index].isUsed = FALSE;
			wfd_server->client[index].client_id = -1;
			wfd_server->client[index].sync_sockfd = -1;
			wfd_server->client[index].async_sockfd = -1;
			wfd_server->client[index].g_source_id = -1;
			wfd_server->client[index].dev_handle = -1;

			wfd_server->active_clients--;
			break;
		}
	}

	if (wfd_server->active_clients == 0)
		wfd_termination_timer_start();

	if (index == WFD_MAX_CLIENTS)
	{
		WDS_LOGE("Error!!! Reset client fail: socketfd=%d is not found\n", sync_sockfd);
		__WDS_LOG_FUNC_EXIT__;
		return;
	}

	__WDS_LOG_FUNC_EXIT__;
	return;
}

void wfd_server_print_client()
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_server_control_t *wfd_server = wfd_server_get_control();
	int index = 0;

	WDS_LOGI( "--------------------\n");
	for (index = 0; index < WFD_MAX_CLIENTS; index++)
	{
		if (wfd_server->client[index].isUsed == TRUE)
		{
			WDS_LOGI(
					"+ CLIENT[%d]: ClientID=%d, sktfd=(%d,%d), g_src_id= [%d]\n",
					index,
					wfd_server->client[index].client_id,
					wfd_server->client[index].sync_sockfd,
					wfd_server->client[index].async_sockfd,
					wfd_server->client[index].g_source_id
					);
		}
	}
	WDS_LOGI( "Total active client=[%d]\n", wfd_server->active_clients);
	WDS_LOGI( "--------------------\n");

	__WDS_LOG_FUNC_EXIT__;
	return;
}



bool wfd_server_client_request_callback(GIOChannel* source, GIOCondition condition, gpointer data)
{
	__WDS_LOG_FUNC_ENTER__;
	int sockfd = (int) data;
	wifi_direct_client_request_s client_req;
	int req_len = sizeof(wifi_direct_client_request_s);

	memset(&client_req, 0x00, req_len);

	if (wfd_server_read_socket_event(sockfd, (char *) &client_req, req_len) < 0)
	{
		wfd_server_reset_client(sockfd);
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	}

	wfd_server_process_client_request(&client_req);

	__WDS_LOG_FUNC_EXIT__;
	return TRUE;
}


/* Function to connect client with wfd_server */
bool wfd_server_register_client(int sockfd)
{
	__WDS_LOG_FUNC_ENTER__;
	int index = 0;
	int status = 0;
	wifi_direct_client_request_s register_req;
	wifi_direct_client_response_s register_rsp;
	wfd_server_control_t *wfd_server = wfd_server_get_control();

	if (sockfd <= 0)
	{
		WDS_LOGE( "Error!!! Invalid sockfd argument = [%d] \n", sockfd);
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	}

	/** Read the Register socket type*/
	errno = 0;
	status = read(sockfd, (char*)&register_req, sizeof(wifi_direct_client_request_s));
	if(status <= 0)
	{
		WDS_LOGE( "Error!!! reading data, error [%s]\n", strerror(errno));
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	}

	if (register_req.cmd == WIFI_DIRECT_CMD_REGISTER)
	{
		WDS_LOGD( "Client socket for sync data transfer, from client [%d] \n", register_req.client_id);

		for (index = 0; index < WFD_MAX_CLIENTS; index++)
		{
			if (wfd_server->client[index].isUsed == FALSE)
			{
				/*Send Client id to the application */
				int datasent = 0;

				memset(&register_rsp, 0, sizeof(wifi_direct_client_response_s));
				register_rsp.cmd = WIFI_DIRECT_CMD_REGISTER;
				register_rsp.client_id = sockfd;
				register_rsp.result = WIFI_DIRECT_ERROR_NONE;
				errno = 0;
				datasent = write(sockfd, (char*)&register_rsp, sizeof(wifi_direct_client_response_s));

				WDS_LOGD(
						"Written RSP of [%d] data into client socket [%d], errinfo [%s] \n",
						datasent, sockfd, strerror(errno));

				/** register socket watcher to g_main_loop */
				GIOChannel* gio;
				gio = g_io_channel_unix_new(sockfd);
				int source_id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP,
						(GIOFunc)wfd_server_client_request_callback, (gpointer)sockfd);

				/** Found Free Entity */
				wfd_server->client[index].isUsed = TRUE;
				wfd_server->client[index].client_id = sockfd;
				wfd_server->client[index].sync_sockfd = sockfd;
				wfd_server->client[index].g_source_id = source_id;

				wfd_server->active_clients++;

				WDS_LOGD( "Client stored in index [%d], total active clients = [%d]\n", index, wfd_server->active_clients);
				__WDS_LOG_FUNC_EXIT__;
				return TRUE;
			}
		}

		if (index == WFD_MAX_CLIENTS)
		{
			int datasent = 0;
			memset(&register_rsp, 0, sizeof(wifi_direct_client_response_s));
			register_rsp.cmd = WIFI_DIRECT_CMD_REGISTER;
			register_rsp.client_id = sockfd;
			register_rsp.result = WIFI_DIRECT_ERROR_RESOURCE_BUSY;
			errno = 0;
			datasent = write(sockfd, (char*)&register_rsp, sizeof(wifi_direct_client_response_s));

			WDS_LOGE( "Error!!! Too Many Client\n");
			__WDS_LOG_FUNC_EXIT__;
			return FALSE;
		}
	}
	else if (register_req.cmd == WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET)
	{
		WDS_LOGD( "Client socket for Async Event notification from client [%d]\n", register_req.client_id);

		for (index = 0; index < WFD_MAX_CLIENTS; index++)
		{
			if ((wfd_server->client[index].isUsed == TRUE)
				&& (wfd_server->client[index].client_id ==
					register_req.client_id))
			{
				wfd_server->client[index].async_sockfd = sockfd;

				WDS_LOGD( "Client stored in index [%d], total active clients = [%d]\n", index, wfd_server->active_clients);

				wfd_server_print_client();

				__WDS_LOG_FUNC_EXIT__;
				return TRUE;
			}
		}

		if (index == WFD_MAX_CLIENTS)
		{
			WDS_LOGE( "Error!!! Client not found \n");
			__WDS_LOG_FUNC_EXIT__;
			return FALSE;
		}
	}
	else
	{
		WDS_LOGE( "Error!!! Received unknown command [%d] \n", register_req.cmd);
		__WDS_LOG_FUNC_EXIT__;
		return FALSE;
	}

	WDS_LOGE( "Error!!! Unknown...\n");
	__WDS_LOG_FUNC_EXIT__;
	return FALSE;
}
