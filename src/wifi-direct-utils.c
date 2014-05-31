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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>

#define _GNU_SOURCE		
#include <unistd.h>
#include <sys/syscall.h>		


#include "wifi-direct-utils.h"
#include "wifi-direct-service.h"

int wfd_gettid()
{
#ifdef __NR_gettid
	return syscall(__NR_gettid);
#else
	WDS_LOGE("__NR_gettid is not defined, please include linux/unistd.h ");
	return -1;
#endif
}

char *wfd_trim_path(const char *filewithpath)
{
	static char *filename[100];
	char *strptr = NULL;
	int start = 0;
	const char *space = "                                        ";
	int len = strlen(filewithpath);

	if (len >= 20)
	{
		strptr = (char *) filewithpath + (len - 20);
		start = 0;
	}
	else
	{
		strptr = (char *) filewithpath;
		start = 20 - len;
	}
	strncpy((char *) filename, space, strlen(space));
	strncpy((char *) filename + start, strptr, 50);

	return (char *) filename;
}

char *wfd_debug_print(char *file, int line, char *format, ...)
{
	static char buffer_internal[512];
	char prefix_buffer[64];
	char *prefix;
	va_list args;
	char buf[512];
	int header_max = 35;

	va_start(args, format);
	vsnprintf(buf, 512, format, args);
	va_end(args);

	snprintf(prefix_buffer, 64, "[%s:%d,%d]", file, line, wfd_gettid());
	int len = 0;
	len = strlen(prefix_buffer);
	if (len > header_max)
	{
		prefix = prefix_buffer + (len - header_max);
	}
	else
	{
		prefix = prefix_buffer;
	}

	snprintf(buffer_internal, 512, "%s%s", prefix, buf);

	return buffer_internal;
}

char *wfd_print_state(wifi_direct_state_e s)
{
	switch (s)
	{
	case WIFI_DIRECT_STATE_DEACTIVATED:
		return "DEACTIVATED";
		break;

	case WIFI_DIRECT_STATE_DEACTIVATING:
		return "DEACTIVATING";
		break;
	case WIFI_DIRECT_STATE_ACTIVATING:
		return "ACTIVATING";
		break;
	case WIFI_DIRECT_STATE_ACTIVATED:
		return "ACTIVATED";
		break;
	case WIFI_DIRECT_STATE_DISCOVERING:
		return "DISCOVERING";
		break;
	case WIFI_DIRECT_STATE_CONNECTING:
		return "CONNECTING";
		break;
	case WIFI_DIRECT_STATE_DISCONNECTING:
		return "DISCONNECTING";
		break;
	case WIFI_DIRECT_STATE_CONNECTED:
		return "CONNECTED";
		break;
	case WIFI_DIRECT_STATE_GROUP_OWNER:
		return "GROUP OWNER";
		break;
	default:
		return "Unknown";
	}
}

int wfd_macaddr_atoe(char *p, unsigned char mac[])
{
	int i = 0;

	WDS_LOGD("MAC [%s]\n", p);

	for (;;)
	{
		mac[i++] = (char) strtoul(p, &p, 16);
		if (!*p++ || i == 6)
			break;
	}

	return (i == 6);
}

