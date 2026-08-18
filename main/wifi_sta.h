#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

void wifi_init_sta(void);

// Returns the device's current IPv4 address (host byte order) in *ip_host_order.
// ESP_ERR_INVALID_STATE if no IP has been acquired yet.
esp_err_t wifi_sta_get_ip(uint32_t *ip_host_order);

#ifdef __cplusplus
}
#endif