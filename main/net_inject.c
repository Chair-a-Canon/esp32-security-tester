#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "net_inject.h"
#include "scope.h"
#include "wifi_sta.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "net_inject";

// How long to listen for a response after sending, before giving up.
#define RESPONSE_TIMEOUT_US (3 * 1000000LL)
// Scratch buffer size for reading candidate response packets.
#define RESPONSE_BUF_LEN 256

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
//
// On RECEIVE, lwIP raw sockets deliver the full IP packet (header +
// payload) - unlike send, where we only hand it the post-IP portion. All
// response-parsing code below accounts for this asymmetry.
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

#define ICMP_TYPE_ECHO_REPLY        0
#define ICMP_TYPE_DEST_UNREACHABLE  3
#define ICMP_CODE_PORT_UNREACHABLE  3

// ---------------------------------------------------------------------
// Monotonic packet ID - unique per injection this session, RAM-only
// (matches the scope model: resets on reboot). Used to correlate a
// logged injection with its captured response and with an external
// Wireshark capture.
// ---------------------------------------------------------------------
static portMUX_TYPE s_pkt_id_lock = portMUX_INITIALIZER_UNLOCKED;
static uint32_t s_next_packet_id = 1;

static uint32_t next_packet_id(void)
{
    uint32_t id;
    portENTER_CRITICAL(&s_pkt_id_lock);
    id = s_next_packet_id++;
    portEXIT_CRITICAL(&s_pkt_id_lock);
    return id;
}

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

static void tcp_flags_to_str(uint8_t flags, char *out, size_t out_len)
{
    out[0] = '\0';
    struct { uint8_t bit; const char *name; } table[] = {
        {TCP_FLAG_SYN, "SYN"}, {TCP_FLAG_ACK, "ACK"}, {TCP_FLAG_FIN, "FIN"},
        {TCP_FLAG_RST, "RST"}, {TCP_FLAG_PSH, "PSH"}, {TCP_FLAG_URG, "URG"},
        {TCP_FLAG_ECE, "ECE"}, {TCP_FLAG_CWR, "CWR"},
    };
    bool first = true;
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (flags & table[i].bit) {
            size_t cur = strlen(out);
            snprintf(out + cur, out_len - cur, "%s%s", first ? "" : ",", table[i].name);
            first = false;
        }
    }
    if (first) {
        snprintf(out, out_len, "none");
    }
}

// Remaining microseconds until deadline, or 0 if already passed.
static int64_t remaining_us(int64_t deadline_us)
{
    int64_t now = esp_timer_get_time();
    int64_t remain = deadline_us - now;
    return remain > 0 ? remain : 0;
}

static void set_recv_timeout(int sock, int64_t us)
{
    struct timeval tv = { .tv_sec = (long)(us / 1000000), .tv_usec = (long)(us % 1000000) };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

// Listens on an already-open raw TCP socket for a reply from target_ip_host
// matching the (swapped) port pair of the request we just sent.
static void wait_for_tcp_response(int sock, uint32_t target_ip_host,
                                   uint16_t our_sport, uint16_t our_dport,
                                   inject_result_t *result)
{
    uint8_t buf[RESPONSE_BUF_LEN];
    int64_t deadline = esp_timer_get_time() + RESPONSE_TIMEOUT_US;

    while (remaining_us(deadline) > 0) {
        set_recv_timeout(sock, remaining_us(deadline));
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) {
            break; // timeout or socket error - stop waiting
        }
        if (n < 20) {
            continue; // too short to even be an IP header
        }
        uint8_t ihl = (buf[0] & 0x0F) * 4;
        if (n < ihl + 20 || buf[9] != IPPROTO_TCP) {
            continue; // not enough for a TCP header, or not TCP
        }

        uint32_t src_ip = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                           ((uint32_t)buf[14] << 8) | buf[15];
        uint16_t rsp_sport = ((uint16_t)buf[ihl] << 8) | buf[ihl + 1];
        uint16_t rsp_dport = ((uint16_t)buf[ihl + 2] << 8) | buf[ihl + 3];
        uint8_t  rsp_flags = buf[ihl + 13];

        if (src_ip == target_ip_host && rsp_sport == our_dport && rsp_dport == our_sport) {
            char flag_str[48];
            tcp_flags_to_str(rsp_flags, flag_str, sizeof(flag_str));
            char ipstr[16];
            uint32_t src_be = htonl(src_ip);
            inet_ntop(AF_INET, &src_be, ipstr, sizeof(ipstr));
            result->responded = true;
            snprintf(result->response_summary, INJECT_RESPONSE_SUMMARY_LEN,
                     "TCP %s from %s:%u", flag_str, ipstr, rsp_sport);
            return;
        }
        // Not our packet's reply - keep listening until the deadline.
    }

    result->responded = false;
    snprintf(result->response_summary, INJECT_RESPONSE_SUMMARY_LEN,
             "No response within %lld s (filtered, dropped, or no listener)",
             (long long)(RESPONSE_TIMEOUT_US / 1000000));
}

// Listens on an already-open raw ICMP socket for an Echo Reply matching our
// ID, or any Destination/Port Unreachable (which may come from a router
// rather than the target itself).
static void wait_for_icmp_response(int sock, uint32_t target_ip_host,
                                    uint16_t our_icmp_id, inject_result_t *result)
{
    uint8_t buf[RESPONSE_BUF_LEN];
    int64_t deadline = esp_timer_get_time() + RESPONSE_TIMEOUT_US;

    while (remaining_us(deadline) > 0) {
        set_recv_timeout(sock, remaining_us(deadline));
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        if (n < 20) {
            continue;
        }
        uint8_t ihl = (buf[0] & 0x0F) * 4;
        if (n < ihl + 8 || buf[9] != IPPROTO_ICMP) {
            continue;
        }

        uint32_t src_ip = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                           ((uint32_t)buf[14] << 8) | buf[15];
        uint8_t icmp_type = buf[ihl];
        uint8_t icmp_code = buf[ihl + 1];
        uint16_t icmp_id  = ((uint16_t)buf[ihl + 4] << 8) | buf[ihl + 5];

        char ipstr[16];
        uint32_t src_be = htonl(src_ip);
        inet_ntop(AF_INET, &src_be, ipstr, sizeof(ipstr));

        if (icmp_type == ICMP_TYPE_ECHO_REPLY && src_ip == target_ip_host && icmp_id == our_icmp_id) {
            result->responded = true;
            snprintf(result->response_summary, INJECT_RESPONSE_SUMMARY_LEN,
                     "ICMP Echo Reply from %s", ipstr);
            return;
        }
        if (icmp_type == ICMP_TYPE_DEST_UNREACHABLE) {
            result->responded = true;
            snprintf(result->response_summary, INJECT_RESPONSE_SUMMARY_LEN,
                     "ICMP Destination Unreachable (code %u) from %s", icmp_code, ipstr);
            return;
        }
    }

    result->responded = false;
    snprintf(result->response_summary, INJECT_RESPONSE_SUMMARY_LEN,
             "No response within %lld s (filtered, dropped, or no listener)",
             (long long)(RESPONSE_TIMEOUT_US / 1000000));
}

// Listens on a raw ICMP socket for a Port Unreachable referencing our UDP
// packet's destination port (embedded in the ICMP payload).
static void wait_for_udp_icmp_response(uint32_t target_ip_host, uint16_t our_dport,
                                        inject_result_t *result)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        result->responded = false;
        snprintf(result->response_summary, INJECT_RESPONSE_SUMMARY_LEN,
                 "Could not open listener for response (errno %d)", errno);
        return;
    }

    uint8_t buf[RESPONSE_BUF_LEN];
    int64_t deadline = esp_timer_get_time() + RESPONSE_TIMEOUT_US;

    while (remaining_us(deadline) > 0) {
        set_recv_timeout(sock, remaining_us(deadline));
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        uint8_t ihl = (buf[0] & 0x0F) * 4;
        if (n < ihl + 8 || buf[9] != IPPROTO_ICMP) {
            continue;
        }
        uint8_t icmp_type = buf[ihl];
        uint8_t icmp_code = buf[ihl + 1];
        if (icmp_type != ICMP_TYPE_DEST_UNREACHABLE || icmp_code != ICMP_CODE_PORT_UNREACHABLE) {
            continue;
        }

        // ICMP payload (after the 8-byte ICMP header) contains: the
        // original IP header, then the first 8 bytes of the original UDP
        // header (src port, dst port, length, checksum).
        size_t embedded_off = ihl + 8;
        if ((size_t)n < embedded_off + 20 + 4) {
            continue;
        }
        uint8_t orig_ihl = (buf[embedded_off] & 0x0F) * 4;
        size_t orig_udp_off = embedded_off + orig_ihl;
        if ((size_t)n < orig_udp_off + 4) {
            continue;
        }
        uint16_t embedded_dport = ((uint16_t)buf[orig_udp_off + 2] << 8) | buf[orig_udp_off + 3];

        uint32_t src_ip = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                           ((uint32_t)buf[14] << 8) | buf[15];
        char ipstr[16];
        uint32_t src_be = htonl(src_ip);
        inet_ntop(AF_INET, &src_be, ipstr, sizeof(ipstr));

        if (embedded_dport == our_dport) {
            result->responded = true;
            snprintf(result->response_summary, INJECT_RESPONSE_SUMMARY_LEN,
                     "ICMP Port Unreachable from %s (port %u closed)", ipstr, our_dport);
            close(sock);
            return;
        }
    }

    close(sock);
    result->responded = false;
    snprintf(result->response_summary, INJECT_RESPONSE_SUMMARY_LEN,
             "No response within %lld s (port open/filtered, or no listener)",
             (long long)(RESPONSE_TIMEOUT_US / 1000000));
}

static esp_err_t send_raw_tcp(uint32_t src_ip_host, uint32_t dst_ip_host,
                               uint16_t sport, uint16_t dport,
                               uint32_t seq, uint32_t ack, uint8_t flags,
                               uint8_t ttl, const char *payload, size_t payload_len,
                               inject_result_t *result)
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

    if (sent < 0) {
        ESP_LOGE(TAG, "[pkt #%" PRIu32 "] Raw TCP sendto failed (errno %d)", result->packet_id, errno);
        close(sock);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "[pkt #%" PRIu32 "] Sent raw TCP: sport=%u dport=%u seq=%" PRIu32 " ack=%" PRIu32 " "
                   "flags=0x%02x ttl=%u len=%d - listening for response...",
             result->packet_id, sport, dport, seq, ack, flags, ttl, sent);

    wait_for_tcp_response(sock, dst_ip_host, sport, dport, result);
    close(sock);

    ESP_LOGI(TAG, "[pkt #%" PRIu32 "] Result: %s", result->packet_id, result->response_summary);
    return ESP_OK;
}

static esp_err_t send_raw_udp(uint32_t src_ip_host, uint32_t dst_ip_host,
                               uint16_t sport, uint16_t dport, uint8_t ttl,
                               const char *payload, size_t payload_len,
                               inject_result_t *result)
{
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
        ESP_LOGW(TAG, "[pkt #%" PRIu32 "] UDP sendto failed (errno %d)", result->packet_id, errno);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "[pkt #%" PRIu32 "] Sent UDP: sport=%u dport=%u ttl=%u len=%d - listening for response...",
             result->packet_id, sport, dport, ttl, sent);

    // UDP has no direct "response" protocol - a closed port typically
    // shows up as an ICMP Port Unreachable, which requires its own
    // listener since it doesn't arrive on the UDP socket itself.
    wait_for_udp_icmp_response(dst_ip_host, dport, result);

    ESP_LOGI(TAG, "[pkt #%" PRIu32 "] Result: %s", result->packet_id, result->response_summary);
    return ESP_OK;
}

static esp_err_t send_raw_icmp_echo(uint32_t dst_ip_host, uint8_t ttl,
                                     const char *payload, size_t payload_len,
                                     inject_result_t *result)
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

    uint16_t icmp_id = (uint16_t)(esp_timer_get_time() & 0xFFFF);
    icmp_echo_header_t *icmp_hdr = (icmp_echo_header_t *)packet;
    icmp_hdr->type = 8; // Echo Request
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->id = htons(icmp_id);
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

    if (sent < 0) {
        ESP_LOGE(TAG, "[pkt #%" PRIu32 "] Raw ICMP sendto failed (errno %d)", result->packet_id, errno);
        close(sock);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "[pkt #%" PRIu32 "] Sent ICMP echo: ttl=%u len=%d - listening for response...",
             result->packet_id, ttl, sent);

    wait_for_icmp_response(sock, dst_ip_host, icmp_id, result);
    close(sock);

    ESP_LOGI(TAG, "[pkt #%" PRIu32 "] Result: %s", result->packet_id, result->response_summary);
    return ESP_OK;
}

esp_err_t inject_custom_packet_from_json(const char *json_payload, inject_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->packet_id = next_packet_id();

    if (!scope_is_armed()) {
        ESP_LOGW(TAG, "[pkt #%" PRIu32 "] Injection blocked: no authorization scope is armed. "
                       "POST /scope first.", result->packet_id);
        return ESP_ERR_INVALID_STATE;
    }

    cJSON *root = cJSON_Parse(json_payload);
    if (root == NULL) {
        ESP_LOGE(TAG, "[pkt #%" PRIu32 "] Failed to parse JSON injection payload", result->packet_id);
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
        ESP_LOGE(TAG, "[pkt #%" PRIu32 "] Missing required dst_ip field", result->packet_id);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }

    struct in_addr dip_addr;
    if (inet_pton(AF_INET, dip_str, &dip_addr) != 1) {
        ESP_LOGE(TAG, "[pkt #%" PRIu32 "] Invalid dst_ip: %s", result->packet_id, dip_str);
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t dst_ip_host = ntohl(dip_addr.s_addr);

    if (!scope_contains(dst_ip_host)) {
        ESP_LOGW(TAG, "[pkt #%" PRIu32 "] Injection BLOCKED: %s is outside the armed scope",
                 result->packet_id, dip_str);
        cJSON_Delete(root);
        return ESP_ERR_NOT_ALLOWED;
    }

    uint32_t src_ip_host = 0;
    if (wifi_sta_get_ip(&src_ip_host) != ESP_OK) {
        ESP_LOGE(TAG, "[pkt #%" PRIu32 "] Could not determine device IP for source address",
                 result->packet_id);
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

    esp_err_t send_result;

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

        send_result = send_raw_tcp(src_ip_host, dst_ip_host, sport, dport, seq, ackn,
                                    flags, ttl, payload_str, payload_len, result);
    } else if (strcasecmp(proto_str, "udp") == 0) {
        send_result = send_raw_udp(src_ip_host, dst_ip_host, sport, dport, ttl,
                                    payload_str, payload_len, result);
    } else if (strcasecmp(proto_str, "icmp") == 0) {
        send_result = send_raw_icmp_echo(dst_ip_host, ttl, payload_str, payload_len, result);
    } else {
        ESP_LOGE(TAG, "[pkt #%" PRIu32 "] Unknown protocol: %s", result->packet_id, proto_str);
        send_result = ESP_ERR_INVALID_ARG;
    }

    cJSON_Delete(root);
    return send_result;
}
