# ESP32-S3 Packet Injection Tool — Architecture & Progress Log

A running record of the design decisions, tradeoffs, and current state of
this project, for continuity between sessions.

## Project Purpose

Self-contained ESP32-S3 firmware for testing IP stack resilience of IoT
devices via crafted packet injection (TCP/UDP/ICMP), restricted to
networks/devices the operator owns or is explicitly authorized to test.

## Core Architectural Decisions

### 1. Authorization scope guardrail (`scope.c`/`scope.h`)
- RAM-only, wiped on every reboot — never persisted to NVS/flash.
- Limited to exactly one `/24` (single Class C) per session.
- Requires an explicit `ack: true` (ownership/authorization confirmation)
  before arming — rejected without it.
- Enforced **server-side in firmware** on every `/inject` request, not
  just in the browser — a raw `curl` POST is checked identically to a GUI
  submission.
- A different `/24` requires clearing and re-acknowledging; no silent
  widening.

### 2. No source-IP spoofing — structural, not just conventional
- Source IP is always read from `wifi_sta_get_ip()` (via
  `esp_netif_get_ip_info()`), never from the JSON request body.
- This was reinforced, not weakened, by a platform discovery: ESP-IDF's
  lwIP **does not implement `IP_HDRINCL`** at the BSD socket layer (it's
  only an internal lwIP sentinel, not a real `setsockopt`). This means
  the application literally cannot hand lwIP a custom IP header —
  lwIP always builds it, always using the real interface address. What
  started as an intentional design choice became a hard platform
  guarantee once we hit that limitation.

### 3. Raw packet crafting — what's controllable vs. not
- **TCP**: full application control of every flag (SYN/ACK/FIN/RST/PSH/
  URG/ECE/CWR — including NULL and XMAS scans), sequence/ack numbers,
  ports, and a correctly computed TCP checksum (with pseudo-header). Sent
  via `SOCK_RAW`/`IPPROTO_TCP`.
- **UDP**: standard `SOCK_DGRAM`, TTL settable via `IP_TTL`.
- **ICMP**: raw `SOCK_RAW`/`IPPROTO_ICMP`, Echo Request (type 8, code 0)
  with configurable payload.
- **Not controllable** (platform limitation, not a bug): IP ID, IP header
  checksum. TTL *is* controllable for all three protocols via the
  standard `IP_TTL` sockopt (confirmed against Espressif's supported
  socket-options documentation) even though `IP_HDRINCL` is not.

### 4. Response capture
- After sending, the same socket (or, for UDP, an auxiliary raw ICMP
  socket) listens for up to **3 seconds** before giving up — timeout
  itself is logged as a result ("no response"), not silently dropped.
- **TCP**: matches replies by source IP + swapped port pair on the same
  raw socket used to send.
- **ICMP**: matches Echo Reply by echoed ID; also reports any
  Destination Unreachable regardless of source (may legitimately come
  from an intermediate router rather than the target).
- **UDP**: has no native reply, so a short-lived raw ICMP listener runs
  alongside the send, matching a Port Unreachable message by the
  original destination port embedded in its payload.
- Every result (packet ID, responded true/false, human-readable summary)
  is returned in the `/inject` JSON response *and* logged to serial,
  tagged `[pkt #N]` for correlation with an external Wireshark capture.

### 5. Wi-Fi provisioning — moved off hardcoded credentials
- Original design had the target network's SSID/password as plaintext
  Kconfig defaults (and briefly, a real password was committed to the
  public repo — since flagged for rotation/history scrub).
- Replaced with: device boots into **AP+STA mode**, bringing up its own
  **open** SoftAP (`CONFIG_TOOL_AP_SSID`, no password by design) so the
  web UI is reachable before any target network is joined.
- New endpoints: `GET /wifi/status`, `GET /wifi/scan` (blocking scan,
  heap-allocated result buffer), `POST /wifi/connect` (`{ssid, password}`,
  ~15s connect timeout).
- On successful connect, the SoftAP is dropped (`wifi_stop_ap()`) via a
  task delayed ~2s after the HTTP response is sent — long enough for the
  client to receive the new IP before losing the setup connection. This
  is a deliberate UX tradeoff (chosen over keeping AP+STA concurrent):
  smaller footprint, at the cost of the operator having to manually
  reconnect their own device to their normal network afterward.
- No target-network credentials are ever baked into firmware.

### 6. Stack-safety fixes (from real crash debugging)
- The httpd worker task's default stack size was too small once packet
  crafting + JSON parsing + response capture buffers stacked up in one
  call chain — this caused a real observed crash/reboot mid-request.
  Fixed by raising `config.stack_size` to 8192 **and** moving the largest
  packet/checksum buffers from stack arrays to heap (`malloc`/`calloc`,
  freed on every return path).

### 7. GUI-side additions
- Destination port dropdown covering the operator's specified well-known
  ports (20/21, 22, 23, 25, 53, 67/68, 69, 80, 110, 119, 123, 135–139,
  143, 161/162, 179, 389, 443, 500, 636, 989/990), still backed by a
  free-text field for anything else.
- Quick Presets: one-click SYN Scan, NULL Scan, FIN Scan, XMAS Scan, ACK
  Scan, UDP Probe, ICMP Echo — sets protocol + flags together.
- Network panel (status, scan, click-to-select SSID list, password field,
  connect) sits above the Scope panel in the page layout.

## Known Platform Limitations (confirmed, not assumed)

- `IP_HDRINCL` does not exist in ESP-IDF's lwIP — confirmed against
  Espressif's own lwIP documentation.
- `IP_TTL` **is** a supported `IPPROTO_IP` sockopt — also confirmed
  against the same documentation, which is why TTL control survived the
  `IP_HDRINCL` pivot even though full custom IP headers did not.
- `uint32_t` resolves to `long unsigned int` (not `unsigned int`) on this
  toolchain — affects `%u` vs. `PRIu32` format-specifier choices under
  `-Werror=format`.

## Current Status

Items completed and confirmed working end-to-end on hardware:
1. ✅ Response capture (TCP/UDP/ICMP-unreachable/ICMP echo reply)
2. ✅ Packet ID in log line, correlated with response capture and GUI
3. ✅ Quick-access port dropdown + preset packet templates
4. ✅ SSID scan + connect flow, hardcoded credentials removed

**Open issue (in progress):** ICMP Echo Request/Reply — the request
sends successfully (confirmed on the wire), but the reply is not being
logged as captured by the tool, despite the target responding normally
to a manual `ping`. Diagnosis in progress: next step is comparing a
Wireshark capture of the crafted request/reply pair against the TCP path
(which does correctly capture responses) to isolate whether this is a
capture-side matching bug or something specific to how the crafted
request differs from a normal OS-generated ping.

## Remaining Roadmap

5. Sequenced "campaign" mode — step through a list of packets against a
   target automatically, pausing between them.
6. Rate limiting / injection throttle — safety rail for fragile targets
   and the ESP32's own resources.

## Ideas Not Yet Scoped

- Scope audit log (in-memory, session-scoped list of armed scopes and
  injected packets, viewable in the GUI).
