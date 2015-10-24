#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <gio/gio.h>

#include "wfd-plugin-log.h"
#include "wfd-plugin-supplicant-dbus.h"

int dbus_set_method_param(dbus_method_param_s *params, char *method_name,
		char *object_path, GDBusConnection *connection)
{
	__WDP_LOG_FUNC_ENTER__;

	if(params == NULL || connection == NULL || object_path == NULL ||
		 method_name == NULL)
	{
		WDP_LOGE("Invalid Arguments!");
		return -1;
	}

	params->connection = connection;
	g_strlcpy(params->object_path, object_path, DBUS_OBJECT_PATH_MAX);
	g_strlcpy(params->method_name, method_name, DBUS_METHOD_NAME_MAX);

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

int dbus_method_call(dbus_method_param_s *params, char *interface_name,
		handle_reply function, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;
	GVariant *reply = NULL;
	GError *error = NULL;

	if(!params || !params->connection) {
		WDP_LOGE("Invalid parameters");
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	WDP_LOGD("method [%s]", params->method_name);

	reply = g_dbus_connection_call_sync (
			params->connection,
			SUPPLICANT_SERVICE, /* bus name */
			params->object_path, /* object path */
			interface_name, /* interface name */
			params->method_name, /* method name */
			params->params, /* GVariant *params */
			NULL, /* reply_type */
			G_DBUS_CALL_FLAGS_NONE, /* flags */
			SUPPLICANT_TIMEOUT , /* timeout */
			NULL, /* cancellable */
			&error); /* error */

	if(error != NULL) {
		WDP_LOGE("Error! Failed to call method: [%s]",error->message);
		g_error_free(error);
		if(reply)
			g_variant_unref(reply);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if(reply != NULL) {
#if defined (TIZEN_DEBUG_DBUS_VALUE)
		WDP_LOGD("reply [%s]", g_variant_print(reply,TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */
		if(function)
			function(reply, user_data);
		g_variant_unref(reply);
	} else {
		WDP_LOGD("reply is NULL");
	}

	__WDP_LOG_FUNC_EXIT__;
	return 0;
}

void dbus_property_foreach(GVariantIter *iter,
		dbus_property_function function, void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;

	gchar *key = NULL;
	GVariant *value = NULL;

	while(g_variant_iter_loop(iter, "{sv}", &key, &value)) {

		if (key) {
			if (strcmp(key, "Properties") == 0) {
				WDP_LOGE("Properties");
				GVariantIter *iter_raw = NULL;
				g_variant_get(value, "a{sv}", &iter_raw);
				dbus_property_foreach(iter_raw, function, user_data);
			} else if (function) {
				WDP_LOGE("function");
				function(key, value, user_data);
			}
			WDP_LOGE("do nothing");
		}
	}
	if(function)
		function(NULL, NULL, user_data);
	__WDP_LOG_FUNC_EXIT__;
	return;
}

int dbus_property_get_all(const char *path, GDBusConnection *connection,
			const char *interface, dbus_property_function function,
			void *user_data)
{
	__WDP_LOG_FUNC_ENTER__;
	GVariant *param = NULL;
	GVariant *reply = NULL;
	GError *error = NULL;
	GVariantIter *iter = NULL;

	if (!connection) {
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if (!path || !interface) {
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	param = g_variant_new("(s)", interface);
#if defined (TIZEN_DEBUG_DBUS_VALUE)
	WDP_LOGD("param [%s]", g_variant_print(param,TRUE));
#endif /* TIZEN_DEBUG_DBUS_VALUE */

	reply = g_dbus_connection_call_sync (
			connection,
			SUPPLICANT_SERVICE, /* bus name */
			path, /* object path */
			DBUS_PROPERTIES_INTERFACE, /* interface name */
			DBUS_PROPERTIES_METHOD_GETALL, /* method name */
			param, /* GVariant *params */
			NULL, /* reply_type */
			G_DBUS_CALL_FLAGS_NONE, /* flags */
			SUPPLICANT_TIMEOUT , /* timeout */
			NULL, /* cancellable */
			&error); /* error */

	if(error != NULL) {
		WDP_LOGE("Error! Failed to get properties: [%s]",	error->message);
		g_error_free(error);
		__WDP_LOG_FUNC_EXIT__;
		return -1;
	}

	if(reply != NULL) {
		g_variant_get(reply, "(a{sv})", &iter);

		if(iter != NULL){

			gchar *key = NULL;
			GVariant *value = NULL;

			while(g_variant_iter_loop(iter, "{sv}", &key, &value)) {

				if(strcmp(key, "Properties") == 0){
					GVariantIter *iter_raw = NULL;
					g_variant_get(value, "a{sv}", &iter_raw);
					dbus_property_foreach(iter_raw, function, user_data);
				} else {
					function(key, value, user_data);
				}
			}
			g_variant_iter_free(iter);
		}
		g_variant_unref(reply);
	} else{
		WDP_LOGE("No properties");
	}
	if(function)
		function(NULL, NULL, user_data);
	__WDP_LOG_FUNC_EXIT__;
	return 0;
}
