#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "scope.h"

static const char *TAG = "scope";

typedef struct {
    uint32_t network;   // host byte order, e.g. 192.168.1.0
    uint32_t netmask;   // host byte order, always 0xFFFFFF00 for /24
    bool     armed;
} scope_state_t;

static scope_state_t s_scope = {0};
static SemaphoreHandle_t s_scope_mutex = NULL;

void scope_init(void)
{
    s_scope_mutex = xSemaphoreCreateMutex();
    memset(&s_scope, 0, sizeof(s_scope));
    ESP_LOGI(TAG, "Scope guardrail initialized - RAM only, no scope armed. "
                  "Injection is BLOCKED until scope is set via /scope.");
}

esp_err_t scope_set(const char *cidr_str, bool ack)
{
    if (!ack) {
        ESP_LOGW(TAG, "Scope set rejected: ownership/authorization acknowledgment was not true");
        return ESP_FAIL;
    }
    if (cidr_str == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    char ip_part[32] = {0};
    int prefix = -1;

    const char *slash = strchr(cidr_str, '/');
    if (slash == NULL) {
        ESP_LOGW(TAG, "Scope set rejected: missing /prefix in '%s'", cidr_str);
        return ESP_ERR_INVALID_ARG;
    }

    size_t ip_len = (size_t)(slash - cidr_str);
    if (ip_len == 0 || ip_len >= sizeof(ip_part)) {
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(ip_part, cidr_str, ip_len);
    ip_part[ip_len] = '\0';
    prefix = atoi(slash + 1);

    // Hard limit: exactly a single Class C. A different /24 requires an
    // explicit new scope_set() call (re-acknowledgment), never a silent
    // widening from the injector.
    if (prefix != 24) {
        ESP_LOGW(TAG, "Scope set rejected: prefix /%d not allowed, only /24 is supported", prefix);
        return ESP_ERR_INVALID_ARG;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part, &addr) != 1) {
        ESP_LOGW(TAG, "Scope set rejected: invalid IPv4 address '%s'", ip_part);
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t ip_host = ntohl(addr.s_addr);
    uint32_t mask_host = 0xFFFFFF00u; // /24
    uint32_t network_host = ip_host & mask_host;

    xSemaphoreTake(s_scope_mutex, portMAX_DELAY);
    s_scope.network = network_host;
    s_scope.netmask = mask_host;
    s_scope.armed = true;
    xSemaphoreGive(s_scope_mutex);

    {
        uint32_t net_be = htonl(network_host);
        char ipbuf[16];
        inet_ntop(AF_INET, &net_be, ipbuf, sizeof(ipbuf));
        ESP_LOGW(TAG, "SCOPE ARMED: %s/24 - authorization acknowledged. "
                      "Injection now permitted ONLY to this range.", ipbuf);
    }
    return ESP_OK;
}

void scope_clear(void)
{
    xSemaphoreTake(s_scope_mutex, portMAX_DELAY);
    memset(&s_scope, 0, sizeof(s_scope));
    xSemaphoreGive(s_scope_mutex);
    ESP_LOGW(TAG, "Scope cleared. Injection blocked until re-armed.");
}

bool scope_is_armed(void)
{
    bool armed;
    xSemaphoreTake(s_scope_mutex, portMAX_DELAY);
    armed = s_scope.armed;
    xSemaphoreGive(s_scope_mutex);
    return armed;
}

bool scope_contains(uint32_t ip_host_order)
{
    bool result = false;
    xSemaphoreTake(s_scope_mutex, portMAX_DELAY);
    if (s_scope.armed) {
        result = (ip_host_order & s_scope.netmask) == s_scope.network;
    }
    xSemaphoreGive(s_scope_mutex);
    return result;
}

void scope_describe(char *buf, size_t buf_len)
{
    xSemaphoreTake(s_scope_mutex, portMAX_DELAY);
    if (s_scope.armed) {
        uint32_t net_be = htonl(s_scope.network);
        char ipbuf[16];
        inet_ntop(AF_INET, &net_be, ipbuf, sizeof(ipbuf));
        snprintf(buf, buf_len, "%s/24 (armed)", ipbuf);
    } else {
        snprintf(buf, buf_len, "no scope set");
    }
    xSemaphoreGive(s_scope_mutex);
}
