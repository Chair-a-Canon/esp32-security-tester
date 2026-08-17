#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

void packet_injection_task(void *pvParameters);
esp_err_t inject_custom_packet_from_json(const char *json_payload);

#ifdef __cplusplus
}
#endif