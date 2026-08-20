#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "esp_log.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "campaign.h"
#include "net_inject.h"

static const char *TAG = "campaign";

// Everything below is guarded by `state_mutex` - the HTTP worker task(s)
// (start/stop/status) and the campaign task itself all touch this struct,
// so every access takes the mutex rather than relying on individual field
// atomicity.
typedef struct {
    bool             active;
    bool             complete;
    bool             was_aborted;
    bool             abort_requested;
    int              current_index;
    int              total;
    uint32_t         delay_ms;
    cJSON           *root;           // owns the whole request; freed when the task exits
    cJSON           *packets_array;  // borrowed pointer into root
    inject_result_t  results[CAMPAIGN_MAX_PACKETS];
} campaign_state_t;

static campaign_state_t state;
static SemaphoreHandle_t state_mutex = NULL;

void campaign_init(void)
{
    memset(&state, 0, sizeof(state));
    state_mutex = xSemaphoreCreateMutex();
    if (state_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create campaign state mutex - campaign mode will be unavailable");
    }
}

bool campaign_is_active(void)
{
    bool active;
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    active = state.active;
    xSemaphoreGive(state_mutex);
    return active;
}

static void campaign_task(void *pvParameters)
{
    (void)pvParameters;

    for (int i = 0; i < state.total; i++) {
        xSemaphoreTake(state_mutex, portMAX_DELAY);
        bool abort_now = state.abort_requested;
        xSemaphoreGive(state_mutex);
        if (abort_now) {
            ESP_LOGW(TAG, "Campaign aborted after %d/%d packets", i, state.total);
            break;
        }

        cJSON *pkt = cJSON_GetArrayItem(state.packets_array, i);
        inject_result_t result = {0};
        if (pkt != NULL) {
            // Same parsing/scope-check/craft/response-capture path as a
            // one-off /inject call - this call may block up to ~3s
            // listening for a response, same as /inject does.
            inject_custom_packet_from_cjson(pkt, &result);
        }

        xSemaphoreTake(state_mutex, portMAX_DELAY);
        state.results[i] = result;
        state.current_index = i + 1;
        xSemaphoreGive(state_mutex);

        ESP_LOGI(TAG, "[campaign %d/%d] pkt #%" PRIu32 " responded=%d",
                 i + 1, state.total, result.packet_id, (int)result.responded);

        if (i < state.total - 1) {
            vTaskDelay(pdMS_TO_TICKS(state.delay_ms));
        }
    }

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    state.was_aborted = state.abort_requested;
    state.complete = true;
    state.active = false;
    cJSON_Delete(state.root);
    state.root = NULL;
    state.packets_array = NULL;
    xSemaphoreGive(state_mutex);

    ESP_LOGI(TAG, "Campaign finished (%d/%d packets processed, aborted=%d)",
             state.current_index, state.total, (int)state.was_aborted);

    vTaskDelete(NULL);
}

esp_err_t campaign_start(cJSON *root, int *out_total)
{
    xSemaphoreTake(state_mutex, portMAX_DELAY);

    if (state.active) {
        xSemaphoreGive(state_mutex);
        return ESP_ERR_INVALID_STATE;
    }

    cJSON *j_delay   = cJSON_GetObjectItem(root, "delay_ms");
    cJSON *j_packets = cJSON_GetObjectItem(root, "packets");

    if (j_packets == NULL || !cJSON_IsArray(j_packets)) {
        xSemaphoreGive(state_mutex);
        return ESP_ERR_INVALID_ARG;
    }

    int total = cJSON_GetArraySize(j_packets);
    if (total <= 0 || total > CAMPAIGN_MAX_PACKETS) {
        xSemaphoreGive(state_mutex);
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t delay_ms = 1000;
    if (j_delay != NULL) {
        if (cJSON_IsNumber(j_delay) && j_delay->valuedouble >= 0) {
            delay_ms = (uint32_t)j_delay->valuedouble;
        } else if (cJSON_IsString(j_delay)) {
            delay_ms = (uint32_t)strtoul(j_delay->valuestring, NULL, 10);
        } else {
            xSemaphoreGive(state_mutex);
            return ESP_ERR_INVALID_ARG;
        }
    }

    memset(state.results, 0, sizeof(state.results));
    state.active          = true;
    state.complete         = false;
    state.was_aborted      = false;
    state.abort_requested  = false;
    state.current_index    = 0;
    state.total            = total;
    state.delay_ms         = delay_ms;
    state.root             = root;
    state.packets_array    = j_packets;

    xSemaphoreGive(state_mutex);

    *out_total = total;

    BaseType_t created = xTaskCreate(campaign_task, "campaign_task", 8192, NULL, 5, NULL);
    if (created != pdPASS) {
        // Roll back - task never started, so ownership of `root` did not transfer.
        xSemaphoreTake(state_mutex, portMAX_DELAY);
        state.active = false;
        state.root = NULL;
        state.packets_array = NULL;
        xSemaphoreGive(state_mutex);
        ESP_LOGE(TAG, "Failed to create campaign task");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Campaign started: %d packets, %" PRIu32 "ms delay", total, delay_ms);
    return ESP_OK;
}

void campaign_stop(void)
{
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    if (state.active) {
        state.abort_requested = true;
        ESP_LOGI(TAG, "Campaign stop requested");
    }
    xSemaphoreGive(state_mutex);
}

int campaign_get_status(campaign_summary_t *summary, inject_result_t *results, int max_results)
{
    xSemaphoreTake(state_mutex, portMAX_DELAY);

    summary->active         = state.active;
    summary->complete       = state.complete;
    summary->was_aborted    = state.was_aborted;
    summary->current_index  = state.current_index;
    summary->total          = state.total;

    uint32_t sent = 0, responded = 0;
    int copy_count = (state.current_index < max_results) ? state.current_index : max_results;

    for (int i = 0; i < state.current_index; i++) {
        sent++;
        if (state.results[i].responded) responded++;
    }
    for (int i = 0; i < copy_count; i++) {
        results[i] = state.results[i];
    }

    summary->sent_count      = sent;
    summary->responded_count = responded;

    xSemaphoreGive(state_mutex);
    return copy_count;
}
