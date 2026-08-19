#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include <arpa/inet.h>
#include "esp_netif.h"
#include "wifi_sta.h"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t s_wifi_event_group;
static const char *TAG = "wifi_mgr";
static esp_netif_t *s_sta_netif = NULL;
static esp_netif_t *s_ap_netif = NULL;

static volatile bool s_is_connected = false;
static char s_current_ssid[33] = {0};

static void event_handler(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *disconnect = (wifi_event_sta_disconnected_t *)event_data;

        // Log the exact reason code given by the AP for diagnosis.
        // Common reason codes:
        // 2   = WIFI_REASON_AUTH_EXPIRE
        // 15  = WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT (usually a wrong password)
        // 201 = WIFI_REASON_NO_AP_FOUND (SSID does not exist or out of range)
        ESP_LOGW(TAG, "Disconnected from AP. Reason code: %d", disconnect->reason);

        s_is_connected = false;
        memset(s_current_ssid, 0, sizeof(s_current_ssid));
        // No automatic retry here - this is an interactive, on-demand
        // connect flow (wifi_connect_to_network), not a boot-time one.
        // The caller's xEventGroupWaitBits() picks this up as a failure.
        xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_is_connected = true;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_manager_init(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_sta_netif = esp_netif_create_default_wifi_sta();
    s_ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    // Open setup SoftAP - no target-network credentials are ever baked
    // into firmware. Connect to this network first, then use the GUI's
    // scan/connect flow to join a real target network.
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = 0, // 0 = derive from strlen(ssid)
            .channel = 1,
            .authmode = WIFI_AUTH_OPEN,
            .max_connection = 4,
        },
    };
    strncpy((char *)ap_config.ap.ssid, CONFIG_TOOL_AP_SSID, sizeof(ap_config.ap.ssid) - 1);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Setup SoftAP '%s' is up (open, no password). Connect to it, "
                   "then use the web UI to scan for and join a target network.",
             CONFIG_TOOL_AP_SSID);
}

esp_err_t wifi_scan_networks(wifi_scan_result_t *results, size_t max_results, size_t *num_found)
{
    if (results == NULL || num_found == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    *num_found = 0;

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
    };

    esp_err_t err = esp_wifi_scan_start(&scan_config, true); // blocking
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Wi-Fi scan failed: %s", esp_err_to_name(err));
        return err;
    }

    uint16_t total_found = 0;
    esp_wifi_scan_get_ap_num(&total_found);
    if (total_found == 0) {
        return ESP_OK;
    }

    uint16_t to_fetch = total_found;
    if (to_fetch > WIFI_SCAN_MAX_RESULTS) {
        to_fetch = WIFI_SCAN_MAX_RESULTS;
    }

    wifi_ap_record_t *ap_records = calloc(to_fetch, sizeof(wifi_ap_record_t));
    if (ap_records == NULL) {
        ESP_LOGE(TAG, "Failed to allocate scan results buffer");
        return ESP_ERR_NO_MEM;
    }

    err = esp_wifi_scan_get_ap_records(&to_fetch, ap_records);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to retrieve scan records: %s", esp_err_to_name(err));
        free(ap_records);
        return err;
    }

    size_t copy_count = to_fetch < max_results ? to_fetch : max_results;
    for (size_t i = 0; i < copy_count; i++) {
        strncpy(results[i].ssid, (const char *)ap_records[i].ssid, sizeof(results[i].ssid) - 1);
        results[i].ssid[sizeof(results[i].ssid) - 1] = '\0';
        results[i].rssi = ap_records[i].rssi;
        results[i].secured = (ap_records[i].authmode != WIFI_AUTH_OPEN);
    }
    *num_found = copy_count;

    free(ap_records);
    return ESP_OK;
}

esp_err_t wifi_connect_to_network(const char *ssid, const char *password, uint32_t timeout_ms)
{
    if (ssid == NULL || strlen(ssid) == 0 || strlen(ssid) > 32) {
        return ESP_ERR_INVALID_ARG;
    }
    if (password != NULL && strlen(password) > 63) {
        return ESP_ERR_INVALID_ARG;
    }

    xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    esp_wifi_disconnect(); // ignore error - fine if not currently connected

    wifi_config_t sta_config = {0};
    strncpy((char *)sta_config.sta.ssid, ssid, sizeof(sta_config.sta.ssid) - 1);
    bool has_password = (password != NULL && strlen(password) > 0);
    if (has_password) {
        strncpy((char *)sta_config.sta.password, password, sizeof(sta_config.sta.password) - 1);
        sta_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        sta_config.sta.threshold.authmode = WIFI_AUTH_OPEN;
    }

    strncpy(s_current_ssid, ssid, sizeof(s_current_ssid) - 1);

    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_set_config failed: %s", esp_err_to_name(err));
        memset(s_current_ssid, 0, sizeof(s_current_ssid));
        return err;
    }

    ESP_LOGI(TAG, "Attempting connection to SSID: %s", ssid);
    err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_connect failed: %s", esp_err_to_name(err));
        memset(s_current_ssid, 0, sizeof(s_current_ssid));
        return err;
    }

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                            pdFALSE, pdFALSE,
                                            pdMS_TO_TICKS(timeout_ms));

    if (bits & WIFI_CONNECTED_BIT) {
        return ESP_OK;
    } else if (bits & WIFI_FAIL_BIT) {
        memset(s_current_ssid, 0, sizeof(s_current_ssid));
        return ESP_FAIL;
    } else {
        ESP_LOGW(TAG, "Connection attempt to %s timed out after %" PRIu32 " ms", ssid, timeout_ms);
        esp_wifi_disconnect();
        memset(s_current_ssid, 0, sizeof(s_current_ssid));
        return ESP_ERR_TIMEOUT;
    }
}

void wifi_stop_ap(void)
{
    ESP_LOGW(TAG, "Dropping setup SoftAP - switching to STA-only mode.");
    esp_wifi_set_mode(WIFI_MODE_STA);
}

bool wifi_sta_is_connected(void)
{
    return s_is_connected;
}

void wifi_sta_get_ssid(char *buf, size_t buf_len)
{
    if (buf == NULL || buf_len == 0) {
        return;
    }
    strncpy(buf, s_current_ssid, buf_len - 1);
    buf[buf_len - 1] = '\0';
}

// Returns the device's currently assigned IPv4 address in host byte order.
// This is the ONLY source of the source IP used anywhere in this project -
// the injector must never accept a source address from user input.
esp_err_t wifi_sta_get_ip(uint32_t *ip_host_order)
{
    if (s_sta_netif == NULL || ip_host_order == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_netif_ip_info_t ip_info;
    esp_err_t err = esp_netif_get_ip_info(s_sta_netif, &ip_info);
    if (err != ESP_OK) {
        return err;
    }
    if (ip_info.ip.addr == 0) {
        return ESP_ERR_INVALID_STATE; // no IP acquired yet
    }
    // esp_netif stores the address in network byte order already (u32 addr)
    *ip_host_order = ntohl(ip_info.ip.addr);
    return ESP_OK;
}
