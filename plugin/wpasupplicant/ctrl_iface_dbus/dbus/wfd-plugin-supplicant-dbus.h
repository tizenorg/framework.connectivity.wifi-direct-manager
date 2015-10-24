#ifndef WFD_PLUGIN_SUPPLICANT_DBUS_H
#define WFD_PLUGIN_SUPPLICANT_DBUS_H


#define COMPACT_MACSTR "%02x%02x%02x%02x%02x%02x"

#define SUPPLICANT_TIMEOUT (10 * 1000)

#define SUPPLICANT_SERVICE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_PATH "/fi/w1/wpa_supplicant1"

#define SUPPLICANT_IFACE SUPPLICANT_INTERFACE ".Interface"
#define SUPPLICANT_NETWORK SUPPLICANT_INTERFACE ".Network"
#define SUPPLICANT_WPS SUPPLICANT_IFACE ".WPS"
#define SUPPLICANT_P2PDEVICE SUPPLICANT_IFACE ".P2PDevice"
#define SUPPLICANT_P2P_PEER SUPPLICANT_INTERFACE ".Peer"
#define SUPPLICANT_P2P_GROUP SUPPLICANT_INTERFACE ".Group"
#define SUPPLICANT_P2P_PERSISTENTGROUP SUPPLICANT_INTERFACE ".PersistentGroup"

#define SUPPLICANT_METHOD_GETINTERFACE "GetInterface"
#define SUPPLICANT_METHOD_REMOVEINTERFACE "RemoveInterface"
#define SUPPLICANT_METHOD_CREATEINTERFACE "CreateInterface"

#define DBUS_METHOD_NAME_MAX 32
#define DBUS_OBJECT_PATH_MAX 150
#define DBUS_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define DBUS_PROPERTIES_METHOD_GET "Get"
#define DBUS_PROPERTIES_METHOD_SET "Set"
#define DBUS_PROPERTIES_METHOD_GETALL "GetAll"

#define SIGNAL_PROPERTIES_CHANGED "PropertiesChanged"

#if defined (TIZEN_DEBUG_DBUS_VALUE)
#define CHECK_KEY_VALUE(key, value)\
	do {\
		if (key)\
			WDP_LOGD("Key : [%s]", key);\
		if (value) {\
			WDP_LOGD("value [%s]", g_variant_print(value,TRUE));\
			WDP_LOGD("value type [%s]", g_variant_get_type_string(value));\
		}\
	} while (0)

#define DEBUG_SIGNAL(sender_name, object_path, interface_name, signal_name, parameters)\
	do {\
		WDP_LOGD("signal sender name [%s]", sender_name);\
		WDP_LOGD("signal object path [%s]", object_path);\
		WDP_LOGD("signal interface name [%s]", interface_name);\
		WDP_LOGD("signal signal name [%s]", signal_name);\
		WDP_LOGD("signal params [%s]", g_variant_print(parameters, TRUE));\
		WDP_LOGD("signal params type [%s]", g_variant_get_type_string(parameters));\
	} while (0)
#endif /* TIZEN_DEBUG_DBUS_VALUE */

typedef void (*handle_reply) (GVariant *value, void *user_data);

typedef void (*dbus_property_function) (const char *key,
		GVariant *value, void *user_data);

typedef struct {
	GDBusConnection *connection;
	char object_path[DBUS_OBJECT_PATH_MAX];
	char method_name[DBUS_METHOD_NAME_MAX];
	GVariant *params;
}dbus_method_param_s;

int dbus_set_method_param(dbus_method_param_s *params, char *method_name,
		char *object_path, GDBusConnection *connection);

int dbus_method_call(dbus_method_param_s *params, char *interface_name,
		handle_reply function, void *user_data);

int dbus_property_get_all(const char *path, GDBusConnection *connection,
		const char *interface, dbus_property_function function,
		void *user_data);

void dbus_property_foreach(GVariantIter *iter,
		dbus_property_function function, void *user_data);

#endif //WFD_PLUGIN_SUPPLICANT_DBUS_H
