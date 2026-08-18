#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "esp_log.h"
#include "esp_err.h"
#include "net_inject.h"
#include "scope.h"
#include "wifi_sta.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "net_inject";

// ---------------------------------------------------------------------
// Raw TCP header struct (packed, network byte order on the wire).
// Defined locally rather than relying on netinet/tcp.h, which is not
// reliably available across lwIP/ESP-IDF versions.
//
// NOTE: lwIP's BSD socket layer on ESP-IDF does NOT implement IP_HDRINCL -
// it is not a real setsockopt() in lwIP (only an internal sentinel used by
// lwIP's own C code, not exposed to applications). A SOCK_RAW socket lets
// us hand-craft everything ABOVE the IP layer (full TCP header control:
// every flag, seq/ack numbers, checksum) but lwIP always builds the IP
// header itself - source address is always the interface's real IP, TTL
// is controllable via the standard IP_TTL sockopt, but IP ID and IP
// checksum are not application-settable. This is a hard platform
// limitation, not a bug: it also means source-IP spoofing is structurally
// impossible here, not just avoided by convention.
// ---------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;   // header length in 32-bit words (4 bits) << 4
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header_t;

typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
} tcp_pseudo_header_t;

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} icmp_echo_header_t;
#pragma pack(pop)

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
#define TCP_FLAG_ECE  0x40
#define TCP_FLAG_CWR  0x80

// Standard internet checksum (RFC 1071).
static uint16_t checksum16(const void *data, size_t len)
{
    const uint16_t *buf = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)buf;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

void packet_injection_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Packet injection task background watcher started.");
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

static bool json_flag_true(cJSON *item)
{
    return item && (cJSON_IsTrue(item) ||
                    (cJSON_IsString(item) && (strcmp(item->valuestring, "1") == 0)) ||
                    (cJSON_IsNumber(item) && item->valueint != 0));
}

static esp_err_t send_raw_tcp(uint32_t src_ip_host, uint32_t dst_ip_host,
                               uint16_t sport, uint16_t dport,
                               uint32_t seq, uint32_t ack, uint8_t flags,
                               uint8_t ttl, const char *payload, size_t payload_len)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to open raw TCP socket (errno %d). "
                       "Check CONFIG_LWIP_MAX_RAW_PCBS in menuconfig.", errno);
        return ESP_FAIL;
    }

    if (ttl > 0) {
        int ttl_val = ttl;
        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val));
    }

    if (payload_len > 512) {
        payload_len = 512;
    }
    size_t tcp_total_len = sizeof(tcp_header_t) + payload_len;

    // Heap-allocate rather than stack: this runs inside the httpd worker
    // task, which shares its stack with JSON parsing and other locals
    // further up the call chain.
    uint8_t *packet = calloc(1, tcp_total_len);
    if (packet == NULL) {
        ESP_LOGE(TAG, "Failed to allocate packet buffer");
        close(sock);
        return ESP_FAIL;
    }
    tcp_header_t *tcp_hdr = (tcp_header_t *)packet;
    uint8_t *payload_ptr = packet + sizeof(tcp_header_t);

    if (payload && payload_len > 0) {
        memcpy(payload_ptr, payload, payload_len);
    }

    tcp_hdr->src_port    = htons(sport);
    tcp_hdr->dst_port    = htons(dport);
    tcp_hdr->seq_num     = htonl(seq);
    tcp_hdr->ack_num     = htonl(ack);
    tcp_hdr->data_offset = (sizeof(tcp_header_t) / 4) << 4;
    tcp_hdr->flags       = flags;
    tcp_hdr->window      = htons(65535);
    tcp_hdr->checksum    = 0;
    tcp_hdr->urgent_ptr  = 0;

    // TCP checksum over pseudo-header + TCP segment. Source/dest here are
    // only used for checksum math - the real source address on the wire
    // is whatever lwIP fills in (the device's own interface IP).
    {
        size_t csum_len = sizeof(tcp_pseudo_header_t) + tcp_total_len;
        uint8_t *csum_buf = malloc(csum_len);
        if (csum_buf == NULL) {
            ESP_LOGE(TAG, "Failed to allocate checksum buffer");
            free(packet);
            close(sock);
            return ESP_FAIL;
        }
        tcp_pseudo_header_t pseudo = {
            .src_addr = htonl(src_ip_host),
            .dst_addr = htonl(dst_ip_host),
            .zero     = 0,
            .protocol = IPPROTO_TCP,
            .tcp_len  = htons((uint16_t)tcp_total_len),
        };
        memcpy(csum_buf, &pseudo, sizeof(pseudo));
        memcpy(csum_buf + sizeof(pseudo), tcp_hdr, tcp_total_len);
        tcp_hdr->checksum = checksum16(csum_buf, csum_len);
        free(csum_buf);
    }

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = htonl(dst_ip_host);

    int sent = sendto(sock, packet, tcp_total_len, 0,
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    free(packet);
    close(sock);

    if (sent < 0) {
        ESP_LOGE(TAG, "Raw TCP sendto failed (errno %d)", errno);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Sent raw TCP packet: sport=%u dport=%u seq=%" PRIu32 " ack=%" PRIu32 " "
                   "flags=0x%02x ttl=%u len=%d",
             sport, dport, seq, ack, flags, ttl, sent);
    return ESP_OK;
}

static esp_err_t send_raw_udp(uint32_t src_ip_host, uint32_t dst_ip_host,
                               uint16_t sport, uint16_t dport, uint8_t ttl,
                               const char *payload, size_t payload_len)
{
    // Standard UDP socket - kernel builds UDP/IP headers, but we still
    // enforce TTL and never accept a spoofed source (binds to our own IP).
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create UDP socket (errno %d)", errno);
        return ESP_FAIL;
    }

    if (ttl > 0) {
        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    }

    struct sockaddr_in source_addr = {0};
    source_addr.sin_family = AF_INET;
    source_addr.sin_addr.s_addr = htonl(src_ip_host);
    source_addr.sin_port = htons(sport);
    if (bind(sock, (struct sockaddr *)&source_addr, sizeof(source_addr)) < 0) {
        ESP_LOGW(TAG, "Failed to bind UDP source port %u (errno %d)", sport, errno);
    }

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dport);
    dest_addr.sin_addr.s_addr = htonl(dst_ip_host);

    int sent = sendto(sock, payload, payload_len, 0,
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    close(sock);

    if (sent < 0) {
        ESP_LOGW(TAG, "UDP sendto failed (errno %d)", errno);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Sent UDP packet: sport=%u dport=%u ttl=%u len=%d", sport, dport, ttl, sent);
    return ESP_OK;
}

static esp_err_t send_raw_icmp_echo(uint32_t dst_ip_host, uint8_t ttl,
                                     const char *payload, size_t payload_len)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to open raw ICMP socket (errno %d)", errno);
        return ESP_FAIL;
    }
    if (ttl > 0) {
        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    }

    if (payload_len > 512) {
        payload_len = 512;
    }
    uint8_t *packet = malloc(sizeof(icmp_echo_header_t) + payload_len);
    if (packet == NULL) {
        ESP_LOGE(TAG, "Failed to allocate ICMP packet buffer");
        close(sock);
        return ESP_FAIL;
    }
    size_t total_len = sizeof(icmp_echo_header_t) + payload_len;

    icmp_echo_header_t *icmp_hdr = (icmp_echo_header_t *)packet;
    icmp_hdr->type = 8; // Echo Request
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->id = htons((uint16_t)(xTaskGetTickCount() & 0xFFFF));
    icmp_hdr->seq = htons(1);
    if (payload && payload_len > 0) {
        memcpy(packet + sizeof(icmp_echo_header_t), payload, payload_len);
    }
    icmp_hdr->checksum = checksum16(packet, total_len);

    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = htonl(dst_ip_host);

    int sent = sendto(sock, packet, total_len, 0,
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    free(packet);
    close(sock);

    if (sent < 0) {
        ESP_LOGE(TAG, "Raw ICMP sendto failed (errno %d)", errno);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Sent ICMP echo request: ttl=%u len=%d", ttl, sent);
    return ESP_OK;
}

esp_err_t inject_custom_packet_from_json(const char *json_payload)
{
    if (!scope_is_armed()) {
        ESP_LOGW(TAG, "Injection blocked: no authorization scope is armed. POST /scope first.");
        return ESP_ERR_INVALID_STATE;
    }

    cJSON *root = cJSON_Parse(json_payload);
    if (root == NULL) {
        ESP_LOGE(TAG, "Failed to parse JSON injection payload");
        return ESP_FAIL;
    }

    cJSON *j_proto = cJSON_GetObjectItem(root, "proto");
    cJSON *j_dip   = cJSON_GetObjectItem(root, "dst_ip");
    cJSON *j_sport = cJSON_GetObjectItem(root, "src_port");
    cJSON *j_dport = cJSON_GetObjectItem(root, "dst_port");
    cJSON *j_ttl   = cJSON_GetObjectItem(root, "ttl");
    cJSON *j_seq   = cJSON_GetObjectItem(root, "seq_num");
    cJSON *j_ack   = cJSON_GetObjectItem(root, "ack_num");
    cJSON *j_payload = cJSON_GetObjectItem(root, "payload");

    char proto_str[16] = "tcp";
    if (j_proto && cJSON_IsString(j_proto)) {
        strncpy(proto_str, j_proto->valuestring, sizeof(proto_str) - 1);
    }

    char dip_str[16] = {0};
    if (j_dip && cJSON_IsString(j_dip) && strlen(j_dip->valuestring) > 0) {
        strncpy(dip_str, j_dip->valuestring, sizeof(dip_str) - 1);
    } else {
        ESP_LOGE(TAG, "Missing required dst_ip field");
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    struct in_addr dip_addr;
    if (inet_pton(AF_INET, dip_str, &dip_addr) != 1) {
        ESP_LOGE(TAG, "Invalid dst_ip: %s", dip_str);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t dst_ip_host = ntohl(dip_addr.s_addr);

    // --- Enforce scope on every single injection request, server-side ---
    if (!scope_contains(dst_ip_host)) {
        ESP_LOGW(TAG, "Injection BLOCKED: %s is outside the armed scope", dip_str);
        cJSON_Delete(root);
        return ESP_ERR_NOT_ALLOWED;
    }

    // --- Source IP is NEVER taken from the request; always the device's own IP ---
    uint32_t src_ip_host = 0;
    if (wifi_sta_get_ip(&src_ip_host) != ESP_OK) {
        ESP_LOGE(TAG, "Could not determine device IP for source address");
        cJSON_Delete(root);
        return ESP_FAIL;
    }

    uint16_t sport = (j_sport && cJSON_IsString(j_sport)) ? (uint16_t)atoi(j_sport->valuestring) : 12345;
    uint16_t dport = (j_dport && cJSON_IsString(j_dport)) ? (uint16_t)atoi(j_dport->valuestring) : 80;
    uint8_t  ttl   = (j_ttl && cJSON_IsString(j_ttl)) ? (uint8_t)atoi(j_ttl->valuestring) : 64;
    uint32_t seq   = (j_seq && cJSON_IsString(j_seq)) ? (uint32_t)strtoul(j_seq->valuestring, NULL, 10) : 0;
    uint32_t ackn  = (j_ack && cJSON_IsString(j_ack)) ? (uint32_t)strtoul(j_ack->valuestring, NULL, 10) : 0;

    const char *payload_str = (j_payload && cJSON_IsString(j_payload)) ? j_payload->valuestring : "";
    size_t payload_len = strlen(payload_str);

    esp_err_t result;

    if (strcasecmp(proto_str, "tcp") == 0) {
        uint8_t flags = 0;
        flags |= json_flag_true(cJSON_GetObjectItem(root, "flag_syn")) ? TCP_FLAG_SYN : 0;
        flags |= json_flag_true(cJSON_GetObjectItem(root, "flag_ack")) ? TCP_FLAG_ACK : 0;
        flags |= json_flag_true(cJSON_GetObjectItem(root, "flag_fin")) ? TCP_FLAG_FIN : 0;
        flags |= json_flag_true(cJSON_GetObjectItem(root, "flag_rst")) ? TCP_FLAG_RST : 0;
        flags |= json_flag_true(cJSON_GetObjectItem(root, "flag_psh")) ? TCP_FLAG_PSH : 0;
        flags |= json_flag_true(cJSON_GetObjectItem(root, "flag_urg")) ? TCP_FLAG_URG : 0;
        flags |= json_flag_true(cJSON_GetObjectItem(root, "flag_ece")) ? TCP_FLAG_ECE : 0;
        flags |= json_flag_true(cJSON_GetObjectItem(root, "flag_cwr")) ? TCP_FLAG_CWR : 0;

        result = send_raw_tcp(src_ip_host, dst_ip_host, sport, dport, seq, ackn,
                               flags, ttl, payload_str, payload_len);
    } else if (strcasecmp(proto_str, "udp") == 0) {
        result = send_raw_udp(src_ip_host, dst_ip_host, sport, dport, ttl,
                               payload_str, payload_len);
    } else if (strcasecmp(proto_str, "icmp") == 0) {
        result = send_raw_icmp_echo(dst_ip_host, ttl, payload_str, payload_len);
    } else {
        ESP_LOGE(TAG, "Unknown protocol: %s", proto_str);
        result = ESP_ERR_INVALID_ARG;
    }

    cJSON_Delete(root);
    return result;
}
