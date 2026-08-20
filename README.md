# ESP32-S3 Packet Injection Security Testing Tool

A self-contained ESP32-S3 firmware tool for testing the IP stack resilience
of IoT devices via crafted packet injection. The device joins a Wi-Fi
network, hosts a small web UI, and sends TCP, UDP, or ICMP packets with
attacker-controlled fields (TCP flags, sequence/ack numbers, ports, TTL,
payload) to a target you specify — either one at a time or as a sequenced
campaign.

> **Authorized use only.** This tool is intended exclusively for testing
> networks and devices you own or have explicit written authorization to
> test. It enforces a scope/authorization guardrail (see below), but that
> guardrail is a safety net, not a substitute for actually having
> permission. Do not point this at anything you don't own or aren't
> authorized to test.

## Hardware / Software

- **Target:** ESP32-S3 development board
- **Framework:** ESP-IDF v5.x (FreeRTOS, lwIP, Wi-Fi AP+STA mode, `esp_http_server`, `cJSON`)
- **Client:** any browser on the same network as the device (desktop or mobile)

## Capabilities

- **TCP** — full control of source/destination port, sequence number, ack
  number, and every TCP flag individually (SYN, ACK, FIN, RST, PSH, URG,
  ECE, CWR), including non-standard combinations such as NULL scans (no
  flags set) and XMAS scans (FIN+PSH+URG). Sent via a raw socket with a
  correctly computed TCP checksum.
- **UDP** — arbitrary source/destination port and payload, TTL settable via
  `IP_TTL`.
- **ICMP** — Echo Request (type 8, code 0) with configurable payload.
- **TTL** — settable per-packet via the standard `IP_TTL` socket option for
  all three protocols.
- **Custom payload** — ASCII payload data attached to any of the above.
- **Response capture** — after sending, the tool listens up to 3 seconds
  for a matching reply and reports it (see below) instead of requiring an
  external packet capture.
- **Quick presets** — one-click SYN Scan, NULL Scan, FIN Scan, XMAS Scan,
  ACK Scan, UDP Probe, and ICMP Echo, each setting protocol + flags
  together. A destination-port dropdown covers common well-known ports,
  backed by a free-text field for anything else.
- **Campaign mode** — queue up multiple crafted packets in the GUI and run
  them as a sequenced, paced batch against the armed scope (see below).

### Platform limitations (by design, not oversight)

ESP-IDF's lwIP does **not** implement `IP_HDRINCL` — confirmed against
Espressif's own lwIP documentation, not assumed. Concretely:

- **Source IP is always the device's real interface address**, read via
  `esp_netif_get_ip_info()`, never from the request body. There is no code
  path, GUI field, or API parameter that can override it — spoofing is
  structurally impossible here, not just avoided by convention.
- **IP ID and the IP header checksum are not application-controllable** —
  lwIP sets these when it builds the IP header itself.
- **`IP_TTL` *is* a supported `IPPROTO_IP` sockopt** (also confirmed
  against Espressif's docs), so TTL control survived the `IP_HDRINCL`
  limitation even though full custom IP headers did not.
- Everything **above** the IP layer (TCP/UDP/ICMP headers, flags, sequence
  numbers, payload) is fully hand-crafted by this tool.

## Authorization Scope Guardrail

Before any packet can be sent, a scope must be armed via the GUI's Scope
panel (or `POST /scope` directly):

```json
{ "cidr": "192.168.1.0/24", "ack": true }
```

- Scope is limited to exactly one `/24` (a single Class C) per session.
- `ack: true` is a required, explicit acknowledgment that you own the range
  or have written authorization to test it — omitting it or setting it to
  `false` is rejected.
- **Scope is RAM-only.** It is never written to flash/NVS and is wiped on
  every reboot, so the acknowledgment must be given fresh each session.
- Every `/inject` request (and every packet inside a campaign) is checked
  against the armed scope **in firmware**, not just in the browser — a
  request sent directly with curl or any other client is checked the same
  way the GUI's requests are.
- Testing a different `/24` requires clearing/resetting scope and
  re-acknowledging; there's no way to silently widen an existing scope.
- **Scope cannot be changed while a campaign is running** (see below) —
  `POST /scope` returns `409 Conflict` until the campaign finishes or is
  stopped.

## Wi-Fi Provisioning

No target-network credentials are ever baked into firmware. On boot, the
device brings up **AP+STA mode**: it hosts its own **open** SoftAP so the
web UI is reachable immediately, before any target network is joined.

- `GET /wifi/status` — current connection state.
- `GET /wifi/scan` — blocking scan of nearby networks.
- `POST /wifi/connect` — `{ "ssid": "...", "password": "..." }`, ~15s
  connect timeout.

On a successful connect, the SoftAP is dropped a couple seconds after the
HTTP response is sent (long enough for the client to receive the device's
new IP first) — you'll need to manually reconnect your own device to its
normal network afterward. This is a deliberate size/simplicity tradeoff
over keeping AP+STA concurrent.

The GUI's Network panel handles this: **Scan for Networks**, click a
network in the list, enter a password if needed, **Connect**.

## GUI Walkthrough

The device serves a single page at `http://<device-ip>/`.

**Network panel (top)** — connection status, **Scan for Networks**, and a
click-to-select network list with a password field. See Wi-Fi Provisioning
above.

**Scope panel** — enter the target `/24` in CIDR notation, check the
ownership/authorization box, and click **Set / Confirm Scope**. The
current scope status is shown above the form. The **Inject Packet** button
stays disabled until scope is successfully armed, and both this panel and
**Inject Packet** are disabled while a campaign is running.

**Network Layer (IP)** — target IP address (must fall inside the armed
scope) and TTL.

**Quick Presets** — one click sets protocol + TCP flags for a common test
case (SYN/NULL/FIN/XMAS/ACK scan, UDP probe, ICMP echo); target IP/port and
payload are left as you've set them.

**Transport Layer** — protocol selector (TCP/UDP/ICMP), source/destination
ports (with a common-ports quick-select dropdown), sequence/ack numbers,
and the TCP flag checkboxes.

**Payload** — free-text ASCII payload appended after the transport header.

**Inject Packet** — sends the request to `POST /inject` and waits (up to
~3s) for a captured response. A status banner reports success/failure and,
on success, whether and how the target responded.

**Add to Campaign** — pushes whatever's currently filled in the form above
into the campaign queue below, without sending it.

**Campaign panel** — see Campaign Mode below.

## Response Capture

After a packet is sent, the tool listens briefly for a matching reply
instead of requiring an external capture:

- **TCP** — matches replies by source IP + swapped port pair on the same
  raw socket used to send.
- **ICMP** — matches Echo Reply by echoed ID; also reports any Destination
  Unreachable regardless of source (it may legitimately come from an
  intermediate router rather than the target itself).
- **UDP** — has no native reply, so a short-lived auxiliary raw ICMP
  listener runs alongside the send, matching a Port Unreachable message by
  the original destination port embedded in its payload.
- A 3-second timeout with no match is logged and reported as "no response"
  — not silently dropped.
- Every result (packet ID, responded true/false, a human-readable summary)
  comes back in the `/inject` (or campaign) JSON response *and* is logged
  to serial tagged `[pkt #N]`, so it can still be correlated against an
  external Wireshark capture if you're running one.

> **Known issue:** ICMP Echo Request/Reply currently sends successfully
> (confirmed on the wire) but the reply is not being logged as captured by
> the tool, despite the target responding normally to a manual `ping`. TCP
> response capture works correctly. Under investigation — likely a
> capture-side matching bug or something specific to how the crafted
> request differs from an OS-generated ping.

## Campaign Mode

Queue up a batch of crafted packets in the GUI and run them as a single
paced sequence against the armed scope, instead of clicking **Inject
Packet** one at a time.

1. Set up a packet in the form (protocol, target, flags, payload, etc.) and
   click **Add to Campaign** to push it onto the queue — repeat for each
   packet you want in the sequence. Queued packets are listed with a
   **Remove** button each.
2. Set the delay between packets with the slider (100ms–5000ms).
3. Click **Run Campaign**. Packets are sent in order, each going through
   the same scope-check → craft → response-capture path as a one-off
   `/inject` call, pausing for the configured delay between each.
4. Results stream in live (per-packet responded/no-response, plus a
   running progress count) and a final summary (packets sent, packets
   responded) is shown once the run completes.
5. **Stop Campaign** halts the run after whatever packet is currently
   in-flight — it doesn't abort mid-send.

**While a campaign is running:**
- `POST /scope` is locked out (`409 Conflict`) — no re-scoping mid-run.
- `POST /inject` is locked out (`409 Conflict`) — only one thing uses the
  raw socket at a time.
- Only one campaign can be active at once; a second `POST /campaign/start`
  while one is running is rejected the same way.

**API:**

```
POST /campaign/start
{ "delay_ms": 1000, "packets": [ { ...same fields as /inject... }, ... ] }
→ JSON: { "status": "started", "total": N }

GET /campaign/status
→ { "active": bool, "complete": bool, "aborted": bool,
    "current_index": N, "total": N,
    "sent_count": N, "responded_count": N,
    "results": [ { "packet_id": N, "responded": bool, "response": "..." }, ... ] }

POST /campaign/stop
→ { "status": "success", "message": "..." }
```

A campaign currently holds up to **32 packets** (`CAMPAIGN_MAX_PACKETS` in
`campaign.h`).

## Build & Flash

```bash
idf.py set-target esp32s3
idf.py build
idf.py -p <PORT> flash monitor
```

Wi-Fi credentials are **not** set at build time — see Wi-Fi Provisioning
above. There's no `menuconfig` credential step anymore.

**Before building, verify `CONFIG_LWIP_MAX_RAW_PCBS` is non-zero** in
`sdkconfig` (`Component config → LWIP → Enable RAW PCBs support` in
menuconfig, naming varies by IDF version). Raw sockets fail at runtime,
not compile time, if this is disabled.

## Roadmap

1. **Fix ICMP Echo Reply capture** (see Known issue above) — compare a
   Wireshark capture of the crafted request/reply pair against the
   working TCP path to isolate the bug.
2. **Rate limiting / injection throttle** — a safety rail against
   accidentally hammering a fragile target, and to avoid saturating the
   ESP32's own resources, independent of the per-campaign delay slider.

## Ideas for Further Improvement

*(Not yet scoped — for discussion before adding to the roadmap.)*

- **Scope audit log:** keep an in-memory (RAM-only, matching the scope
  model) log of every armed scope and every injected packet this session,
  viewable from the GUI — useful for after-action reporting without
  persisting anything sensitive to flash.
