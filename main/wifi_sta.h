#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "esp_wifi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_SCAN_MAX_RESULTS 20

typedef struct {
    char    ssid[33];
    int8_t  rssi;
    bool    secured; // false = open network, no password needed
} wifi_scan_result_t;

// Brings up Wi-Fi in AP+STA mode: starts the device's own open setup
// SoftAP immediately (so the web UI is reachable before any target
// network is joined) and readies the STA interface for scanning/connecting.
// Does NOT auto-connect to anything - there are no baked-in credentials.
void wifi_manager_init(void);

// Blocking scan for nearby APs. Fills results[] (capped at max_results)
// and sets *num_found. Requires the STA interface to be up (satisfied by
// wifi_manager_init()).
esp_err_t wifi_scan_networks(wifi_scan_result_t *results, size_t max_results, size_t *num_found);

// Attempts to join the given network, blocking up to timeout_ms. password
// may be an empty string for an open network. Returns ESP_OK on success
// (device now has an IP - check wifi_sta_get_ip()), ESP_ERR_TIMEOUT if no
// result within timeout_ms, ESP_FAIL on association/auth failure.
esp_err_t wifi_connect_to_network(const char *ssid, const char *password, uint32_t timeout_ms);

// Switches from AP+STA to STA-only, dropping the setup SoftAP. Call this
// only after a successful wifi_connect_to_network() - and only once the
// caller has had a chance to get a response back to the client first,
// since the SoftAP disappearing will drop that connection.
void wifi_stop_ap(void);

// True if currently connected to a target network with an IP.
bool wifi_sta_is_connected(void);

// Returns the currently connected SSID, or empty string if not connected.
void wifi_sta_get_ssid(char *buf, size_t buf_len);

// Returns the device's current IPv4 address (host byte order) in *ip_host_order.
// ESP_ERR_INVALID_STATE if no IP has been acquired yet.
esp_err_t wifi_sta_get_ip(uint32_t *ip_host_order);

#ifdef __cplusplus
}
#endif
