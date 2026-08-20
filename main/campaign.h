#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "net_inject.h"

#ifdef __cplusplus
extern "C" {
#endif

// Sequenced "campaign" mode: steps through a list of packets against the
// armed scope automatically, pausing `delay_ms` between each send. Reuses
// the same per-packet parsing/crafting/response-capture path as /inject
// (inject_custom_packet_from_cjson), so scope enforcement and response
// matching behave identically to a one-off injection.
//
// Only one campaign may be active at a time. While a campaign is active:
//   - POST /inject is rejected (409) to avoid two callers touching the
//     same raw socket.
//   - POST /scope is rejected (409) - no re-scoping mid-campaign. Use
//     POST /campaign/stop as the emergency-abort path instead.

#define CAMPAIGN_MAX_PACKETS 32

// Must be called once at startup, before the HTTP server begins accepting
// requests (same pattern as scope_init()).
void campaign_init(void);

// True if a campaign is currently running. Checked by the /inject and
// /scope handlers to enforce the lockout described above.
bool campaign_is_active(void);

// Starts a new campaign from a parsed JSON body:
//   { "delay_ms": 1000, "packets": [ {...same fields as /inject...}, ... ] }
// Ownership of `root` transfers to the campaign task on ESP_OK - caller
// must NOT cJSON_Delete it in that case. On any error return, `root` is
// untouched and remains the caller's to free.
// Returns:
//   ESP_OK                   - campaign accepted and started
//   ESP_ERR_INVALID_STATE    - a campaign is already active
//   ESP_ERR_INVALID_ARG      - missing/empty/oversized "packets" array,
//                               or delay_ms missing/invalid
esp_err_t campaign_start(cJSON *root, int *out_total);

// Requests the running campaign stop after its current in-flight packet
// (does not abort mid-send). No-op if no campaign is active.
void campaign_stop(void);

// Snapshot of campaign progress for GET /campaign/status.
typedef struct {
    bool     active;             // true while running
    bool     complete;           // true once the run has finished (active is false too)
    bool     was_aborted;        // true if campaign_stop() cut the run short
    int      current_index;      // number of packets processed so far
    int      total;              // total packets in this campaign
    uint32_t sent_count;         // packets successfully sent (result valid)
    uint32_t responded_count;    // of those, how many got a matched response
} campaign_summary_t;

// Fills `summary` and up to `max_results` entries of `results` with the
// per-packet outcomes processed so far (safe to call while active).
// Returns the number of result entries written into `results`.
int campaign_get_status(campaign_summary_t *summary, inject_result_t *results, int max_results);

#ifdef __cplusplus
}
#endif
