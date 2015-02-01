/*
 * Network Configuration Module
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * This file declares wifi direct service functions and structures.
 *
 * @file		wifi-direct-service.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WIFI_DIRECT_SERVICE_H__
#define __WIFI_DIRECT_SERVICE_H__

typedef enum {
	WFD_SERVICE_TYPE_ALL,
	WFD_SERVICE_TYPE_BONJOUR,
	WFD_SERVICE_TYPE_UPNP,
	WFD_SERVICE_TYPE_WS_DISCOVERY,
	WFD_SERVICE_TYPE_WIFI_DISPLAY,
	WFD_SERVICE_TYPE_VENDOR = 0xff,
} wfd_service_type_e;

typedef enum {
	WFD_BONJOUR_RDATA_PTR = 0x0c,
	WFD_BONJOUR_RDATA_TXT = 0x10,
}wfd_bonjour_rdata_type_e;

typedef struct {
	int version;
	char *service;
} wfd_service_upnp_s;

typedef struct {
	char *query;
	wfd_bonjour_rdata_type_e rdata_type;
	char *rdata;
} wfd_service_bonjour_s;

typedef struct {
	int type;
	int id;
	int status;
	char *str_ptr;
	union {
		struct {
			char *version;
			char *service;
		} upnp;
		struct {
			char *query;
			char *rdata;
			wfd_bonjour_rdata_type_e rdata_type;
		} bonjour;
		struct {
			char *info1;
			char *info2;
		} vendor;
	} data;
} wfd_service_s;


int wfd_service_add(GList **services, int type, char *data, int *service_id);
int wfd_service_del(GList *services, int service_id);
#if 0
int wfd_service_disc_req(unsigned char *addr, int type, char *data);
int wfd_service_disc_cancel(int handle);
#endif


#endif /* __WIFI_DIRECT_SERVICE_H__ */
