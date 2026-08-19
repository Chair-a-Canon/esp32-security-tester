# ESP32-S3 Packet Injection Security Testing Tool

A self-contained ESP32-S3 firmware tool for testing the IP stack resilience
of IoT devices via crafted packet injection. The device joins a Wi-Fi
network, hosts a small web UI, and sends TCP, UDP, or ICMP packets with
attacker-controlled fields (TCP flags, sequence/ack numbers, ports, TTL,
payload) to a target you specify.

> **Authorized use only.** This tool is intended exclusively for testing
> networks and devices you own or have explicit written authorization to
> test. It enforces a scope/authorization guardrail (see below), but that
> guardrail is a safety net, not a substitute for actually having
> permission. Do not point this at anything you don't own or aren't
> authorized to test.

## Hardware / Software

- **Target:** ESP32-S3 development board
- **Framework:** ESP-IDF v5.x (FreeRTOS, lwIP, Wi-Fi Station mode, `esp_http_server`)
- **Client:** any browser on the same network as the device (desktop or mobile)

## Capabilities

- **TCP** — full control of source/destination port, sequence number, ack
  number, and every TCP flag individually (SYN, ACK, FIN, RST, PSH, URG,
  ECE, CWR), including non-standard combinations such as NULL scans (no
  flags set) and XMAS scans (FIN+PSH+URG). Sent via a raw socket with a
  correctly computed TCP checksum.
- **UDP** — arbitrary source/destination port and payload.
- **ICMP** — Echo Request (type 8) with configurable payload.
- **TTL** — settable per-packet via the standard `IP_TTL` socket option for
  all three protocols.
- **Custom payload** — ASCII payload data attached to any of the above.

### Platform limitations (by design, not oversight)

ESP-IDF's lwIP does **not** implement `IP_HDRINCL`, so this tool cannot hand
lwIP a fully custom IP header. Concretely:

- **Source IP is always the device's real interface address.** There is no
  code path, GUI field, or API parameter that can override it — spoofing is
  structurally impossible here, not just avoided by convention.
- **IP ID and the IP header checksum are not application-controllable** —
  lwIP sets these when it builds the IP header itself.
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
- Every `/inject` request is checked against the armed scope **in
  firmware**, not just in the browser — a request sent directly with curl
  or any other client is checked the same way the GUI's requests are.
- Testing a different `/24` requires clearing/resetting scope and
  re-acknowledging; there's no way to silently widen an existing scope.

## GUI Walkthrough

The device serves a single page at `http://<device-ip>/`.

**Scope panel (top)** — enter the target `/24` in CIDR notation, check the
ownership/authorization box, and click **Set / Confirm Scope**. The
current scope status is shown above the form. The **Inject Packet** button
stays disabled until scope is successfully armed.

**Network Layer (IP)** — target IP address (must fall inside the armed
scope) and TTL.

**Transport Layer** — protocol selector (TCP/UDP/ICMP), source/destination
ports, sequence/ack numbers, and the TCP flag checkboxes. Destination port
has quick-set links for common ports (80/443/22).

**Payload** — free-text ASCII payload appended after the transport header.

**Inject Packet** — sends the request to `POST /inject`. A status banner
reports success or the reason for a block (no scope armed, target outside
scope, invalid parameters, etc.).

## Monitoring Effectiveness

The firmware currently only sends — it does not listen for or capture
responses from the target device. **To observe how a target reacts to an
injected packet (or whether it reacts at all), run Wireshark on a machine
that can see the relevant network segment** (e.g., a span/mirror port, a
hub, or the same host if testing loopback-adjacent services) and filter on
the target IP and/or the source port used in the injection. Capturing the
response on-device is on the roadmap (see below).

## Build & Flash

```bash
idf.py set-target esp32s3
idf.py menuconfig   # set Wi-Fi SSID/password under "Example Configuration"
idf.py build
idf.py -p <PORT> flash monitor
```

**Before building, verify `CONFIG_LWIP_MAX_RAW_PCBS` is non-zero** in
`sdkconfig` (`Component config → LWIP → Enable RAW PCBs support` in
menuconfig, naming varies by IDF version). Raw sockets fail at runtime,
not compile time, if this is disabled.

### Known credential-handling issue

Wi-Fi SSID/password are currently set via Kconfig defaults, which get
written to `sdkconfig` — **do not commit real credentials into
`Kconfig.projbuild` defaults or a checked-in `sdkconfig`.** Set them
locally via `idf.py menuconfig` instead, and keep `sdkconfig` out of
version control if it contains a real password. This is expected to be
replaced by the Wi-Fi provisioning work below.

## Roadmap

1. **Capture target responses in-firmware.** Add a listener (raw socket or
   promiscuous-mode capture) so the tool can log/display RST, ICMP
   Destination Unreachable, or other reactions to a malformed packet
   without requiring an external Wireshark capture.
2. **Expand the quick-access port list.** Replace the current three
   hardcoded shortcuts with a dropdown covering the top ~100 common ports,
   plus a free-text field for anything not listed.
3. **SSID scanning + AP-side authentication capture**, to move off
   hardcoded Wi-Fi credentials in Kconfig — let the tool scan for and
   select an SSID and handle authentication dynamically instead of baking
   a network's credentials into firmware defaults.

## Ideas for Further Improvement

*(Not yet scoped — for discussion before adding to the roadmap.)*

- **Scope audit log:** keep an in-memory (RAM-only, matching the scope
  model) log of every armed scope and every injected packet this session,
  viewable from the GUI — useful for after-action reporting without
  persisting anything sensitive to flash.
- **Rate limiting / injection throttle:** a minimum interval between
  injections, partly as a safety rail against accidentally hammering a
  fragile IoT device, partly to avoid saturating the ESP32's own resources.
- **Preset packet templates:** one-click common test cases (SYN scan probe,
  NULL scan, XMAS scan, UDP flood single-packet, oversized payload) so you
  don't have to hand-set flags each time.
- **Sequenced test runs:** a "campaign" mode that steps through a list of
  packets (e.g., one of each TCP flag combination against one target) and
  pauses between them, rather than one manual injection at a time.
- **Result correlation stub:** even before full response capture, add a
  monotonic packet ID surfaced in the ESP32 log line so it's easier to
  cross-reference a specific injected packet against a simultaneous
  Wireshark capture.
