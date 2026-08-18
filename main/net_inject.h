#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

void packet_injection_task(void *pvParameters);

// Parses a JSON packet spec and, if the destination IP is inside the
// currently armed scope (see scope.h), crafts and sends it via raw socket.
// Source IP is ALWAYS the ESP32's own interface address - never taken
// from the JSON payload. Returns ESP_OK if a packet was sent,
// ESP_ERR_INVALID_STATE if no scope is armed, ESP_ERR_NOT_ALLOWED if the
// destination is outside the armed scope, ESP_FAIL on parse/send errors.
esp_err_t inject_custom_packet_from_json(const char *json_payload);

#ifdef __cplusplus
}
#endif
