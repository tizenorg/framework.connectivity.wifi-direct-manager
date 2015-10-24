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
 * This file declares wifi direct wpasupplicant plugin functions and structures.
 *
 * @file		wfd-plugin-log.h
 * @author	Gibyoung Kim (lastkgb.kim@samsung.com)
 * @version	0.7
 */

#ifndef __WFD_PLUGIN_LOG_H_
#define __WFD_PLUGIN_LOG_H_

#ifdef USE_DLOG
#include <dlog.h>

#undef LOG_TAG
#define LOG_TAG "WIFI_DIRECT_PLUGIN"

#define WDP_LOGV(format, args...) LOGV(format, ##args)
#define WDP_LOGD(format, args...) LOGD(format, ##args)
#define WDP_LOGI(format, args...) LOGI(format, ##args)
#define WDP_LOGW(format, args...) LOGW(format, ##args)
#define WDP_LOGE(format, args...) LOGE(format, ##args)
#define WDP_LOGF(format, args...) LOGF(format, ##args)

#define __WDP_LOG_FUNC_ENTER__ LOGD("Enter")
#define __WDP_LOG_FUNC_EXIT__ LOGD("Quit")

#define WDP_SECLOGI(format, args...) SECURE_LOG(LOG_INFO, LOG_TAG, format, ##args)
#define WDP_SECLOGD(format, args...) SECURE_LOG(LOG_DEBUG, LOG_TAG, format, ##args)

#else /* USE_DLOG */

#define WDP_LOGV(format, args...)
#define WDP_LOGD(format, args...)
#define WDP_LOGI(format, args...)
#define WDP_LOGW(format, args...)
#define WDP_LOGE(format, args...)
#define WDP_LOGF(format, args...)

#define __WDP_LOG_FUNC_ENTER__
#define __WDP_LOG_FUNC_EXIT__

#define WDP_SECLOGI(format, args...)
#define WDP_SECLOGD(format, args...)

#endif /* USE_DLOG */

#endif /* __WFD_PLUGIN_LOG_H_ */
