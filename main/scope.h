#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RAM-only authorization scope guardrail.
 *
 * No target IP is ever accepted by the injector unless it falls inside
 * the currently armed /24 scope. Scope is intentionally NOT persisted to
 * NVS: it is wiped on every reboot and must be re-set (with an explicit
 * ownership/authorization acknowledgment) each session.
 */

// Must be called once at startup before the HTTP server begins accepting requests.
void scope_init(void);

// Sets and arms the scope from a CIDR string, e.g. "192.168.1.0/24".
// Prefix MUST be exactly /24 (single Class C). ack must be true - this is
// the explicit "I own this / have written authorization" confirmation.
// Returns ESP_OK on success, ESP_ERR_INVALID_ARG on bad CIDR or non-/24
// prefix, ESP_FAIL if ack was not set to true.
esp_err_t scope_set(const char *cidr_str, bool ack);

// Clears the current scope, requiring re-acknowledgment before further
// injection is allowed.
void scope_clear(void);

// True if a scope has been set AND acknowledged.
bool scope_is_armed(void);

// True if the given IPv4 address (host byte order) falls inside the
// currently armed scope. Always false if no scope is armed.
bool scope_contains(uint32_t ip_host_order);

// Writes a human-readable description of current scope state into buf,
// e.g. "192.168.1.0/24 (armed)" or "no scope set". Always NUL-terminated.
void scope_describe(char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif
