#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <wifi-direct.h>

#include "wifi-direct-ipc.h"
#include "wifi-direct-manager.h"
#include "wifi-direct-oem.h"
#include "wifi-direct-service.h"
#include "wifi-direct-util.h"


int wfd_service_add(GList **services, int type, char *info_str, int *service_id)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	wfd_service_s *service = NULL;
//	wfd_oem_new_service_s *oem_service = NULL;
	char *info1 = NULL;
	char *info2 = NULL;
	char *sep = NULL;
	int res = 0;

	if (!info_str) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	if (type < WIFI_DIRECT_SERVICE_TYPE_BONJOUR || type > WIFI_DIRECT_SERVICE_TYPE_VENDOR){
		WDS_LOGE("Invalid service type");
		return -1;
	}

	service = (wfd_service_s*) g_try_malloc0(sizeof(wfd_service_s));
	if (!service) {
		WDS_LOGE("Failed to allocate memory for service");
		return -1;
	}

	service->type = type;
	service->id = (int) &service;

	info1 = g_strndup(info_str, strlen(info_str));
	if(info1 == NULL) {
		WDS_LOGE("Failed to allocate memory for service");
		g_free(service);
		return -1;
	}
	sep = strchr(info1, '|');
	if(sep == NULL) {
		WDS_LOGE("Failed to find delimiter");
		g_free(info1);
		g_free(service);
		return -1;
	}

	*sep = '\0';
	info2 = sep + 1;

	switch (service->type) {
		case WIFI_DIRECT_SERVICE_TYPE_BONJOUR:
			service->data.bonjour.query = info1;
			if(strstr(info2, "ptr")){
				service->data.bonjour.rdata_type = WFD_BONJOUR_RDATA_PTR;
			} else {
				service->data.bonjour.rdata_type = WFD_BONJOUR_RDATA_TXT;
			}
			service->data.bonjour.rdata = info2 +3;
		break;
		case WIFI_DIRECT_SERVICE_TYPE_UPNP:
			service->data.upnp.version = info1;
			service->data.upnp.service = info2;
		break;
		case WIFI_DIRECT_SERVICE_TYPE_WS_DISCOVERY:
		case WIFI_DIRECT_SERVICE_TYPE_WIFI_DISPLAY:
			WDS_LOGE("Not supported yet");
			g_free(info1);
			g_free(service);
			return-1;
		break;
		case WIFI_DIRECT_SERVICE_TYPE_VENDOR:
			service->data.vendor.info1 = info1;
			service->data.vendor.info2 = info2;
		break;
		default:
			WDS_LOGE("Invalid service type");
			g_free(info1);
			g_free(service);
			return-1;
		break;
	}

//	oem_service = (wfd_oem_new_service_s*) calloc(1, sizeof(wfd_oem_new_service_s));
//	oem_service->protocol = service->type;
//	oem_service->data = service->data;

	res = wfd_oem_serv_add(manager->oem_ops, (wfd_oem_new_service_s*) service);
	if (res < 0) {
		WDS_LOGE("Failed to add service");
		g_free(info1);
		g_free(service);
		return -1;
	}

//	free(oem_service);

	service->str_ptr = info1;
	*services = g_list_prepend(*services, service);
	*service_id = service->id;

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

int wfd_service_del(GList *services, int service_id)
{
	__WDS_LOG_FUNC_ENTER__;
	wfd_manager_s *manager = wfd_get_manager();
	GList *temp = NULL;
	wfd_service_s *service = NULL;
	int res = 0;

	if (!services) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	temp = g_list_first(services);
	while (temp) {
		service = (wfd_service_s*) temp->data;
		if (service->id == service_id) {
			WDS_LOGD("Service found");
			break;
		}
		service = NULL;
		temp = g_list_next(temp);
	}

	if (!service) {
		WDS_LOGE("Service not found");
		return -1;
	}

	res = wfd_oem_serv_del(manager->oem_ops, (wfd_oem_new_service_s*) service);
	if (res < 0) {
		WDS_LOGE("Failed to add service");
		return -1;
	}

	services = g_list_remove(services, service);

	g_free(service->str_ptr);
	g_free(service);

	__WDS_LOG_FUNC_EXIT__;
	return 0;
}

#if 0
int wfd_service_disc_req(unsigned char *addr, int type, char *data)
{
	__WDS_LOG_FUNC_ENTER__;
	int handle = 0;
	// TODO: return identifier(handle) for the pending query

	if (!addr) {
		WDS_LOGE("Invalid parameter");
		return -1;
	}

	if (type < WFD_SERVICE_TYPE_ALL || type > WFD_SERVICE_TYPE_VENDOR){
		WDS_LOGE("Invalid service type");
		return -1;
	}

	// TODO: call oem function
	// TODO: add service information into service list

	__WDS_LOG_FUNC_EXIT__;
	return handle;
}

int wfd_service_disc_cancel(int handle)
{
	return 0;
}
#endif
