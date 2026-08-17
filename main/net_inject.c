#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "esp_log.h"
#include "esp_err.h"
#include "net_inject.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "net_inject";

void packet_injection_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Packet injection task background watcher started.");
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

esp_err_t inject_custom_packet_from_json(const char *json_payload)
{
    cJSON *root = cJSON_Parse(json_payload);
    if (root == NULL) {
        ESP_LOGE(TAG, "Failed to parse JSON configuration payload");
        return ESP_FAIL;
    }

    cJSON *j_proto   = cJSON_GetObjectItem(root, "proto");
    cJSON *j_dip     = cJSON_GetObjectItem(root, "dip");
    cJSON *j_sport   = cJSON_GetObjectItem(root, "sport");
    cJSON *j_dport   = cJSON_GetObjectItem(root, "dport");
    cJSON *j_syn     = cJSON_GetObjectItem(root, "flag_syn");
    cJSON *j_ack     = cJSON_GetObjectItem(root, "flag_ack");
    cJSON *j_fin     = cJSON_GetObjectItem(root, "flag_fin");
    cJSON *j_rst     = cJSON_GetObjectItem(root, "flag_rst");

    char proto_str[16] = "tcp";
    if (j_proto && cJSON_IsString(j_proto)) {
        strncpy(proto_str, j_proto->valuestring, sizeof(proto_str) - 1);
    }

    char dip_str[16] = "10.0.0.163";
    if (j_dip && cJSON_IsString(j_dip)) {
        strncpy(dip_str, j_dip->valuestring, sizeof(dip_str) - 1);
    }
    
    uint16_t sport = (j_sport && cJSON_IsString(j_sport)) ? atoi(j_sport->valuestring) : 12345;
    uint16_t dport = (j_dport && cJSON_IsString(j_dport)) ? atoi(j_dport->valuestring) : 80;

    bool is_tcp = (strcasecmp(proto_str, "tcp") == 0);
    int sock = socket(AF_INET, is_tcp ? SOCK_STREAM : SOCK_DGRAM, is_tcp ? IPPROTO_TCP : IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket for protocol: %s", proto_str);
        cJSON_Delete(root);
        return ESP_FAIL;
    }

    struct sockaddr_in source_addr;
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin_family = AF_INET;
    source_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    source_addr.sin_port = htons(sport);

    if (bind(sock, (struct sockaddr *)&source_addr, sizeof(source_addr)) < 0) {
        ESP_LOGW(TAG, "Failed to bind custom source port %u", sport);
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dport);
    inet_pton(AF_INET, dip_str, &dest_addr.sin_addr);

    int syn_f = (j_syn && (cJSON_IsTrue(j_syn) || (cJSON_IsNumber(j_syn) && j_syn->valueint))) ? 1 : 0;
    int ack_f = (j_ack && (cJSON_IsTrue(j_ack) || (cJSON_IsNumber(j_ack) && j_ack->valueint))) ? 1 : 0;
    int fin_f = (j_fin && (cJSON_IsTrue(j_fin) || (cJSON_IsNumber(j_fin) && j_fin->valueint))) ? 1 : 0;
    int rst_f = (j_rst && (cJSON_IsTrue(j_rst) || (cJSON_IsNumber(j_rst) && j_rst->valueint))) ? 1 : 0;

    if (is_tcp) {
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const void *)&tv, sizeof(tv));

        int err = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err == 0) {
            ESP_LOGI(TAG, "Successfully connected TCP stream to %s:%u from port %u [SYN:%d, ACK:%d, FIN:%d, RST:%d]", 
                     dip_str, dport, sport, syn_f, ack_f, fin_f, rst_f);
        } else {
            ESP_LOGW(TAG, "TCP connection attempt returned error status (code: %d)", err);
        }
    } else {
        const char *payload_msg = "ESP32-Security-Test-Packet";
        int sent = sendto(sock, payload_msg, strlen(payload_msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (sent < 0) {
            ESP_LOGW(TAG, "UDP sendto failed");
        } else {
            ESP_LOGI(TAG, "Successfully sent UDP packet to %s:%u from port %u", dip_str, dport, sport);
        }
    }

    close(sock);
    cJSON_Delete(root);
    return ESP_OK;
}