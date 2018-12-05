/*
 * Copyright (c) 2014-2016 Alibaba Group. All rights reserved.
 * License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include <rom/ets_sys.h>

#include "iot_import.h"

#include "divoom.h"

#ifdef MQTT_ID2_AUTH
#include "tfs.h"
#endif /**< MQTT_ID2_AUTH*/

//#define DIVOOM_MQTT_ALIYUN_TAG		"Divoom_Aliyun"

typedef xSemaphoreHandle osi_mutex_t;

char _product_key[PRODUCT_KEY_LEN + 1];
char _product_secret[PRODUCT_SECRET_LEN + 1];
char _device_name[DEVICE_NAME_LEN + 1];
char _device_secret[DEVICE_SECRET_LEN + 1];

#define UNUSED(expr) do { (void)(expr); } while (0)

void *HAL_MutexCreate(void)
{
    osi_mutex_t *p_mutex = NULL;
    //p_mutex = (osi_mutex_t *)malloc(sizeof(osi_mutex_t));
    p_mutex = (osi_mutex_t *)HAL_Malloc(sizeof(osi_mutex_t));
    if(p_mutex == NULL)
        return NULL;

    *p_mutex = xSemaphoreCreateMutex();
    return p_mutex;
}

void HAL_MutexDestroy(_IN_ void *mutex)
{
    vSemaphoreDelete(*((osi_mutex_t*)mutex));
    free(mutex);
}

void HAL_MutexLock(_IN_ void *mutex)
{
    xSemaphoreTake(*((osi_mutex_t*)mutex), portMAX_DELAY);
}

void HAL_MutexUnlock(_IN_ void *mutex)
{
    xSemaphoreGive(*((osi_mutex_t*)mutex));
}

int HAL_ThreadCreate(
            _OU_ void **thread_handle,
            _IN_ void *(*work_routine)(void *),
            _IN_ void *arg,
            _IN_ hal_os_thread_param_t *hal_os_thread_param,
            _OU_ int *stack_used)
{
	int		priority = 2;
	size_t	stack_size = 0;
	char	name[64];
	
	if(hal_os_thread_param == NULL)
	{
		//如果没有给，暂时给4k吧
		stack_size = 4<<10;
		strcpy(name, "Task_aliyun_use");
	}
	else
	{
		if(hal_os_thread_param->priority > 0)
		{
			priority = 5;
		}
		else
		{
			priority = 2;
		}
		stack_size = 4<<10;
		if(hal_os_thread_param->name != NULL)
		{
			strcpy(name, hal_os_thread_param->name);
		}
	}
	
	if(stack_used)
	{
		*stack_used = 1;
	}

	return xTaskCreate(work_routine, name, stack_size, arg, priority, thread_handle);
}

void HAL_ThreadDetach(_IN_ void *thread_handle)
{
	if(thread_handle)
	{
	}
}

void HAL_ThreadDelete(_IN_ void *thread_handle)
{
	if(thread_handle)
	{
		vTaskDelete(thread_handle);
	}
	return;
}

void *HAL_SemaphoreCreate(void)
{
	return xSemaphoreCreateCounting(255, 0);
}

void HAL_SemaphoreDestroy(_IN_ void *sem)
{
	if(sem)
	{
		vSemaphoreDelete(sem);
	}
}

int HAL_SemaphoreWait(_IN_ void *sem, _IN_ uint32_t timeout_ms)
{
	if(sem)
	{
		if(timeout_ms == PLATFORM_WAIT_INFINITE)
			xSemaphoreTake(sem, (portTickType)portMAX_DELAY);
		else
			xSemaphoreTake(sem, timeout_ms / portTICK_PERIOD_MS);

		return 1;
	}
	return 0;
}

void HAL_SemaphorePost(_IN_ void *sem)
{
	if(sem)
	{
		xSemaphoreGive(sem);
	}
}

void *HAL_Malloc(_IN_ uint32_t size)
{
    void *data =  NULL;
    //data = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_32BIT);
    data = divoom_malloc(size, 100, __LINE__, "aliyun");
    if (data) {
        memset(data, 0, size);
    }
	return data;
    //return malloc(size);
}

void *HAL_Realloc(_IN_ void *ptr, _IN_ uint32_t size)
{
	if(ptr)
	{
		free(ptr);
		ptr = HAL_Malloc(size);
	}

	return ptr;
}

void *HAL_Calloc(_IN_ uint32_t nmemb, _IN_ uint32_t size)
{
	return HAL_Malloc(nmemb * size);
}

void HAL_Free(_IN_ void *ptr)
{
    free(ptr);
}

uint64_t HAL_UptimeMs(void)
{
    struct timeval tv = { 0 };
    uint64_t time_ms;

    gettimeofday(&tv, NULL);

    time_ms = (uint64_t)tv.tv_sec * 1000LL + tv.tv_usec / 1000;

    return time_ms;
}

void HAL_SleepMs(_IN_ uint32_t ms)
{
    if ((ms > 0) && (ms < portTICK_RATE_MS)) {
        ms = portTICK_RATE_MS;
    }

    vTaskDelay(ms / portTICK_RATE_MS);
}

char *HAL_GetTimeStr(_IN_ char *buf, _IN_ int len)
{
    struct timeval tv;
    struct tm      tm;
    int str_len    = 0;

    if (buf == NULL || len < 28) {
        return NULL;
    }
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);
    strftime(buf, 28, "%m-%d %H:%M:%S", &tm);
    str_len = strlen(buf);
    if (str_len + 3 < len) {
        snprintf(buf + str_len, len, ".%3.3d", (int)(tv.tv_usec) / 1000);
    }
    return buf;
}

void HAL_Srandom(uint32_t seed)
{
    return;
}

uint32_t HAL_Random(uint32_t region)
{
    //return esp_random();
	return (region > 0) ? (esp_random() % region) : 0;
}

void HAL_HEAP_PRINT(void)
{
	HAL_Printf("HEAP OF CAPS:%d\n", heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
}

int HAL_Snprintf(_IN_ char *str, const int len, const char *fmt, ...)
{
    va_list args;
    int     rc;

    va_start(args, fmt);
    rc = vsnprintf(str, len, fmt, args);
    va_end(args);

    return rc;
}

int HAL_Vsnprintf(_IN_ char *str, _IN_ const int len, _IN_ const char *format, va_list ap)
{
    return vsnprintf(str, len, format, ap);
}

void HAL_Printf(_IN_ const char *fmt, ...)
{

    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
	//ESP_LOGI(DIVOOM_MQTT_ALIYUN_TAG, fmt, args);
    va_end(args);

    fflush(stdout);
}

char *HAL_Wifi_Get_Mac(_OU_ char mac_str[HAL_MAC_LEN])
{
	uint8 mac[6];
	esp_read_mac(mac, ESP_MAC_WIFI_STA);
	sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    //strcpy(mac_str, "18:FE:34:12:33:44");
    return mac_str;
}

uint32_t HAL_Wifi_Get_IP(_OU_ char ip_str[NETWORK_ADDR_LEN], _IN_ const char *ifname)
{
	tcpip_adapter_ip_info_t device_ip_info;
	struct in_addr sock_info;
	tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &device_ip_info);

	memset(ip_str, 0, NETWORK_ADDR_LEN);
	bzero(&sock_info, sizeof(struct in_addr));

	sprintf(ip_str, "%d.%d.%d.%d", (device_ip_info.ip.addr>>0) & 0xFF,
			(device_ip_info.ip.addr>>8) & 0xFF,(device_ip_info.ip.addr>>16) & 0xFF,(device_ip_info.ip.addr>>24) & 0xFF);

	inet_aton(ip_str, &sock_info);

	return sock_info.s_addr;
}

//不要给reboot的权限，因为没有配网功能
void HAL_Reboot(void)
{
	return;
}

//get流程：仅仅对key == DyncRegDeviceSecret
//先去nvs里面去读，读不到再去spiffs读取
//nvs读到了,重新写进文件;nvs读不到，文件读到了，重新写进nvs
#define KV_KEY_DEVICE_SECRET            "DyncRegDeviceSecret"
int HAL_Kv_Get(const char *key, void *buffer, int *buffer_len)
{
#ifdef DIVOOM_MQTT_ALIYUN_VERSION_V_2_3_0
	if(strcmp(key, KV_KEY_DEVICE_SECRET) == 0)
	{
		return divoom_mqtt_model_get_devicesecret_for_kv(buffer, buffer_len);
	}
#endif
    return 0;
}

//set流程，仅仅对key == DyncRegDeviceSecret
//写文件，写nvs
int HAL_Kv_Set(const char *key, const void *val, int len, int sync)
{
#ifdef DIVOOM_MQTT_ALIYUN_VERSION_V_2_3_0
	if(strcmp(key, KV_KEY_DEVICE_SECRET) == 0)
	{
		return divoom_mqtt_model_set_devicesecret_for_kv(val, len);
	}
#endif
    return 0;
}

int HAL_Kv_Del(const char *key)
{
	return 0;
}

//应该都是awss，配网的
void   *HAL_Timer_Create(const char *name, void (*func)(void *), void *user_data)
{
	return NULL;
}
int     HAL_Timer_Start(void *t, int ms)
{
	return 0;
}
int     HAL_Timer_Stop(void *t)
{
	return 0;
}
int     HAL_Timer_Delete(void *timer)
{
	return 0;
}

void HAL_UTC_Set(long long ms)
{
	return;
}

long long HAL_UTC_Get(void)
{
    struct timeval tv;
    long long ms;
    gettimeofday(&tv, NULL);
    ms = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
    return ms;
}

int HAL_GetPartnerID(char* pid_str)
{
    memset(pid_str, 0x0, PID_STRLEN_MAX);
    strcpy(pid_str, "espressif");
    return strlen(pid_str);
}

int HAL_GetModuleID(char* mid_str)
{
    memset(mid_str, 0x0, MID_STRLEN_MAX);
    strcpy(mid_str, "wroom-32");
    return strlen(mid_str);
}

char *HAL_GetChipID(_OU_ char* cid_str)
{
    memset(cid_str, 0x0, HAL_CID_LEN);
    strncpy(cid_str, "esp32", HAL_CID_LEN);
    cid_str[HAL_CID_LEN - 1] = '\0';
    return cid_str;
}

int HAL_GetDeviceID(_OU_ char* device_id)
{
    memset(device_id, 0x0, DEVICE_ID_LEN);
    HAL_Snprintf(device_id, DEVICE_ID_LEN, "%s.%s", _product_key, _device_name);
    device_id[DEVICE_ID_LEN - 1] = '\0';
    return strlen(device_id);
}

#ifdef MQTT_ID2_AUTH
int HAL_GetID2(_OU_ char* id2_str)
{
    int rc;
    uint8_t                 id2[TFS_ID2_LEN + 1] = {0};
    uint32_t                id2_len = TFS_ID2_LEN + 1;
    memset(id2_str, 0x0, TFS_ID2_LEN + 1);
    rc = tfs_get_ID2(id2, &id2_len);
    if (rc < 0) return rc;
    strncpy(id2_str, (const char*)id2, TFS_ID2_LEN);
    return strlen(id2_str);
}
#endif /**< MQTT_ID2_AUTH*/

int HAL_SetProductKey(_IN_ char* product_key)
{
    int len = strlen(product_key);
    if (len > PRODUCT_KEY_LEN) return -1;
    memset(_product_key, 0x0, PRODUCT_KEY_LEN + 1);
    strncpy(_product_key, product_key, len);
    return len;
}

int HAL_SetDeviceName(_IN_ char* device_name)
{
    int len = strlen(device_name);
    if (len > DEVICE_NAME_LEN) return -1;
    memset(_device_name, 0x0, DEVICE_NAME_LEN + 1);
    strncpy(_device_name, device_name, len);
    return len;
}

int HAL_SetDeviceSecret(_IN_ char* device_secret)
{
    int len = strlen(device_secret);
    if (len > DEVICE_SECRET_LEN) return -1;
    memset(_device_secret, 0x0, DEVICE_SECRET_LEN + 1);
    strncpy(_device_secret, device_secret, len);
    return len;
}

int HAL_SetProductSecret(_IN_ char* product_secret)
{
    int len = strlen(product_secret);
    if (len > PRODUCT_SECRET_LEN) return -1;
    memset(_product_secret, 0x0, PRODUCT_SECRET_LEN + 1);
    strncpy(_product_secret, product_secret, len);
    return len;
}

int HAL_GetProductKey(_OU_ char* product_key)
{
    memset(product_key, 0x0, PRODUCT_KEY_LEN);
    strncpy(product_key, _product_key, PRODUCT_KEY_LEN);
    return strlen(product_key);
}

int HAL_GetDeviceName(_OU_ char* device_name)
{
    memset(device_name, 0x0, DEVICE_NAME_LEN);
    strncpy(device_name, _device_name, DEVICE_NAME_LEN);
    return strlen(device_name);
}

int HAL_GetProductSecret(_OU_ char* product_secret)
{
    memset(product_secret, 0x0, PRODUCT_SECRET_LEN);
    strncpy(product_secret, _product_secret, PRODUCT_SECRET_LEN);
    return strlen(product_secret);
}

int HAL_GetDeviceSecret(_OU_ char* device_secret)
{
    memset(device_secret, 0x0, DEVICE_SECRET_LEN);
    strncpy(device_secret, _device_secret, DEVICE_SECRET_LEN);
    return strlen(device_secret);
}

//给出WiFi的mac地址应该就OK了
int HAL_GetNetifInfo(char *nif_str)
{
	uint8 mac[6];

    memset(nif_str, 0x0, NIF_STRLEN_MAX);

	esp_read_mac(mac, ESP_MAC_WIFI_STA);
	sprintf(nif_str, "WiFi|%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return strlen(nif_str);
}

int HAL_GetFirmwareVersion(_OU_ char* version)
{
    char *ver = "v2.x.2.10";
    int len = strlen(ver);
    if (len > FIRMWARE_VERSION_MAXLEN)
        return 0;
    memset(version, 0x0, FIRMWARE_VERSION_MAXLEN);
    strncpy(version, ver, FIRMWARE_VERSION_MAXLEN);
    return len;
}

void HAL_Firmware_Persistence_Start(void)
{
    return;
}

int HAL_Firmware_Persistence_Write(_IN_ char *buffer, _IN_ uint32_t length)
{
    return 0;
}

int HAL_Firmware_Persistence_Stop(void)
{
    return 0;
}
