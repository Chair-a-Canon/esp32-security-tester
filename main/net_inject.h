#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INJECT_RESPONSE_SUMMARY_LEN 128

typedef struct {
    uint32_t packet_id;                                  // monotonic, unique per injection this session
    bool     responded;                                   // true if a matching response was captured
    char     response_summary[INJECT_RESPONSE_SUMMARY_LEN]; // human-readable, e.g. "TCP RST,ACK from 192.168.1.1:80"
} inject_result_t;

void packet_injection_task(void *pvParameters);

// Parses a JSON packet spec and, if the destination IP is inside the
// currently armed scope (see scope.h), crafts and sends it via raw socket,
// then listens briefly for a matching response. Source IP is ALWAYS the
// ESP32's own interface address - never taken from the JSON payload.
// *result is always filled in on ESP_OK (packet_id, responded, summary).
// Returns ESP_ERR_INVALID_STATE if no scope is armed, ESP_ERR_NOT_ALLOWED
// if the destination is outside the armed scope, ESP_FAIL on parse/send
// errors, ESP_OK if the packet was sent (regardless of whether a response
// was captured - check result->responded for that).
esp_err_t inject_custom_packet_from_json(const char *json_payload, inject_result_t *result);

#ifdef __cplusplus
}
#endif
