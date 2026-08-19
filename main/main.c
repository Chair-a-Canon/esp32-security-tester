#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "cJSON.h"

#include "wifi_sta.h"
#include "net_inject.h"
#include "scope.h"

static const char *TAG = "main";

static esp_err_t root_get_handler(httpd_req_t *req) {
    const char *resp_html =
        "<!DOCTYPE html>"
        "<html>"
        "<head>"
        "    <meta charset=\"UTF-8\">"
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "    <title>ESP32-S3 Packet Injector</title>"
        "    <style>"
        "        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f111a; color: #a9b7c6; padding: 15px; max-width: 700px; margin: auto; }"
        "        h1 { color: #ff5370; font-size: 1.4rem; text-align: center; margin-bottom: 20px; }"
        "        fieldset { border: 1px solid #2f3542; padding: 15px; margin-bottom: 15px; border-radius: 6px; background: #1e222d; }"
        "        fieldset.scope-panel { border-color: #ffcb6b; }"
        "        fieldset.network-panel { border-color: #82aaff; }"
        "        fieldset.network-panel legend { color: #82aaff; }"
        "        #netStatus { font-size: 0.9rem; margin-bottom: 8px; }"
        "        .net-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 10px; margin-top: 6px; background: #151821; border: 1px solid #3f4451; border-radius: 4px; cursor: pointer; font-size: 0.85rem; }"
        "        .net-item:hover { border-color: #82aaff; }"
        "        .net-item.selected { border-color: #82aaff; background: #1a2233; }"
        "        .net-item .lock { color: #ffcb6b; margin-left: 8px; }"
        "        legend { color: #82aaff; font-weight: bold; padding: 0 5px; }"
        "        fieldset.scope-panel legend { color: #ffcb6b; }"
        "        label { display: block; margin-top: 10px; font-size: 0.9rem; font-weight: 600; color: #d5d8dc; }"
        "        input[type=\"text\"], select, textarea { width: 100%; padding: 10px; margin-top: 5px; background: #151821; border: 1px solid #3f4451; color: #fff; border-radius: 4px; box-sizing: border-box; font-size: 0.95rem; }"
        "        input[type=\"text\"]:focus, select:focus, textarea:focus { border-color: #82aaff; outline: none; }"
        "        .row { display: flex; gap: 10px; }"
        "        .col { flex: 1; }"
        "        .checkbox-group { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-top: 8px; background: #151821; padding: 10px; border-radius: 4px; border: 1px solid #3f4451; }"
        "        .checkbox-label { display: flex; align-items: center; gap: 5px; font-size: 0.85rem; cursor: pointer; color: #e2e8f0; font-weight: normal; }"
        "        .ack-label { display: flex; align-items: flex-start; gap: 8px; font-size: 0.85rem; font-weight: normal; color: #ffcb6b; margin-top: 12px; }"
        "        .ack-label input { width: auto; margin-top: 2px; }"
        "        .preset-group { display: flex; flex-wrap: wrap; gap: 8px; }"
        "        .preset-btn { flex: 1 1 auto; min-width: 90px; width: auto; margin-top: 0; padding: 10px; background: #3f4451; color: #e2e8f0; font-size: 0.85rem; }"
        "        #dst_port_quick { margin-top: 8px; }"
        "        button { background: #ff5370; color: white; border: none; padding: 14px; width: 100%; margin-top: 10px; font-size: 1rem; font-weight: bold; border-radius: 4px; cursor: pointer; transition: background 0.2s; }"
        "        button.scope-btn { background: #ffcb6b; color: #1e222d; }"
        "        button:hover { filter: brightness(1.1); }"
        "        button:disabled { background: #3f4451; color: #7f8c8d; cursor: not-allowed; }"
        "        .hint { font-size: 0.75rem; color: #7f8c8d; margin-top: 2px; }"
        "        #status, #scopeStatus { margin-top: 15px; padding: 10px; text-align: center; font-weight: bold; border-radius: 4px; display: none; }"
        "        .success { background: #2ecc71; color: #fff; }"
        "        .error { background: #e74c3c; color: #fff; }"
        "        #scopeLabel { text-align: center; font-size: 0.85rem; margin-bottom: 10px; color: #ffcb6b; }"
        "    </style>"
        "    <script>"
        "        function setPort(elementId, port) {"
        "            document.getElementById(elementId).value = port;"
        "        }"
        "        function applyPreset(name) {"
        "            const presets = {"
        "                syn_scan:  { proto: 'tcp', flags: ['syn'] },"
        "                null_scan: { proto: 'tcp', flags: [] },"
        "                fin_scan:  { proto: 'tcp', flags: ['fin'] },"
        "                xmas_scan: { proto: 'tcp', flags: ['fin', 'psh', 'urg'] },"
        "                ack_scan:  { proto: 'tcp', flags: ['ack'] },"
        "                udp_probe: { proto: 'udp', flags: [] },"
        "                icmp_echo: { proto: 'icmp', flags: [] },"
        "            };"
        "            const p = presets[name];"
        "            if (!p) return;"
        "            document.getElementById('proto').value = p.proto;"
        "            const allFlags = ['syn', 'ack', 'fin', 'rst', 'psh', 'urg', 'ece', 'cwr'];"
        "            const form = document.getElementById('injectForm');"
        "            allFlags.forEach(f => {"
        "                form.elements['flag_' + f].checked = p.flags.includes(f);"
        "            });"
        "        }"
        "        function refreshScopeLabel(text) {"
        "            document.getElementById('scopeLabel').innerText = 'Current scope: ' + text;"
        "        }"
        "        let selectedSsid = null;"
        "        function checkWifiStatus() {"
        "            fetch('/wifi/status').then(r => r.json()).then(body => {"
        "                const div = document.getElementById('netStatus');"
        "                if (body.connected) {"
        "                    div.innerText = 'Connected to \\'' + body.ssid + '\\' as ' + body.ip;"
        "                    document.getElementById('scanBtn').style.display = 'none';"
        "                } else {"
        "                    div.innerText = 'Not connected - scan below and pick a network to join.';"
        "                }"
        "            }).catch(() => {"
        "                document.getElementById('netStatus').innerText = 'Could not reach device.';"
        "            });"
        "        }"
        "        function scanNetworks() {"
        "            const resultsDiv = document.getElementById('scanResults');"
        "            resultsDiv.innerHTML = '<div class=\\\"hint\\\">Scanning (a few seconds)...</div>';"
        "            fetch('/wifi/scan').then(r => r.json()).then(body => {"
        "                resultsDiv.innerHTML = '';"
        "                (body.networks || []).sort((a, b) => b.rssi - a.rssi).forEach(net => {"
        "                    const item = document.createElement('div');"
        "                    item.className = 'net-item';"
        "                    item.innerHTML = '<span>' + net.ssid + ' (' + net.rssi + ' dBm)</span>' +"
        "                        (net.secured ? '<span class=\\\"lock\\\">&#128274;</span>' : '<span></span>');"
        "                    item.onclick = () => selectNetwork(net.ssid, net.secured, item);"
        "                    resultsDiv.appendChild(item);"
        "                });"
        "                if ((body.networks || []).length === 0) {"
        "                    resultsDiv.innerHTML = '<div class=\\\"hint\\\">No networks found.</div>';"
        "                }"
        "            }).catch(() => { resultsDiv.innerHTML = '<div class=\\\"hint\\\">Scan failed.</div>'; });"
        "        }"
        "        function selectNetwork(ssid, secured, el) {"
        "            selectedSsid = ssid;"
        "            document.querySelectorAll('.net-item').forEach(n => n.classList.remove('selected'));"
        "            el.classList.add('selected');"
        "            document.getElementById('connectPanel').style.display = 'block';"
        "            document.getElementById('wifi_password').value = '';"
        "            document.getElementById('wifi_password').placeholder = secured ? 'Wi-Fi password' : 'Open network - no password needed';"
        "        }"
        "        function connectNetwork() {"
        "            if (!selectedSsid) return;"
        "            const password = document.getElementById('wifi_password').value;"
        "            const statusDiv = document.getElementById('netConnectStatus');"
        "            statusDiv.style.display = 'block';"
        "            statusDiv.className = '';"
        "            statusDiv.innerText = 'Connecting to \\'' + selectedSsid + '\\' (up to 15s)...';"
        "            fetch('/wifi/connect', {"
        "                method: 'POST',"
        "                headers: { 'Content-Type': 'application/json' },"
        "                body: JSON.stringify({ ssid: selectedSsid, password: password })"
        "            })"
        "            .then(response => response.json().then(body => ({ ok: response.ok, body })))"
        "            .then(({ ok, body }) => {"
        "                statusDiv.className = ok ? 'success' : 'error';"
        "                if (ok) {"
        "                    statusDiv.innerText = 'Connected! New address: http://' + body.ip + '/ - ' + body.note;"
        "                } else {"
        "                    statusDiv.innerText = 'Failed: ' + body.message;"
        "                }"
        "            })"
        "            .catch(() => {"
        "                statusDiv.className = 'error';"
        "                statusDiv.innerText = 'Connecting... (this setup network may drop shortly if it succeeded - check the new network for the device.)';"
        "            });"
        "        }"
        "        window.addEventListener('load', checkWifiStatus);"
        "        function setScope(event) {"
        "            event.preventDefault();"
        "            const cidr = document.getElementById('scope_cidr').value;"
        "            const ack = document.getElementById('scope_ack').checked;"
        "            const statusDiv = document.getElementById('scopeStatus');"
        "            statusDiv.style.display = 'block';"
        "            fetch('/scope', {"
        "                method: 'POST',"
        "                headers: { 'Content-Type': 'application/json' },"
        "                body: JSON.stringify({ cidr: cidr, ack: ack })"
        "            })"
        "            .then(response => response.json().then(body => ({ ok: response.ok, body })))"
        "            .then(({ ok, body }) => {"
        "                statusDiv.className = ok ? 'success' : 'error';"
        "                statusDiv.innerText = body.message;"
        "                if (ok) {"
        "                    refreshScopeLabel(body.scope);"
        "                    document.getElementById('injectBtn').disabled = false;"
        "                }"
        "            })"
        "            .catch(() => { statusDiv.className = 'error'; statusDiv.innerText = 'Failed to set scope.'; });"
        "        }"
        "        function sendPacket(event) {"
        "            event.preventDefault();"
        "            const form = document.getElementById('injectForm');"
        "            const formData = new FormData(form);"
        "            const data = {};"
        "            formData.forEach((value, key) => { data[key] = value; });"
        "            const checkboxes = ['flag_syn', 'flag_ack', 'flag_fin', 'flag_rst', 'flag_psh', 'flag_urg', 'flag_ece', 'flag_cwr'];"
        "            checkboxes.forEach(box => {"
        "                data[box] = form.elements[box].checked;"
        "            });"
        "            const statusDiv = document.getElementById('status');"
        "            statusDiv.style.display = 'block';"
        "            statusDiv.className = '';"
        "            statusDiv.innerText = 'Sending and listening for a response (up to 3s)...';"
        "            fetch('/inject', {"
        "                method: 'POST',"
        "                headers: { 'Content-Type': 'application/json' },"
        "                body: JSON.stringify(data)"
        "            })"
        "            .then(response => response.json().then(body => ({ ok: response.ok, body })))"
        "            .then(({ ok, body }) => {"
        "                statusDiv.className = ok ? 'success' : 'error';"
        "                let text = (ok ? 'Success' : 'Blocked') + ' (packet #' + body.packet_id + '): ' + body.message;"
        "                if (ok && body.response) { text += ' | Response: ' + body.response; }"
        "                statusDiv.innerText = text;"
        "            })"
        "            .catch(error => {"
        "                statusDiv.className = 'error';"
        "                statusDiv.innerText = 'Error sending request - connection failed.';"
        "                console.error('Error:', error);"
        "            });"
        "        }"
        "    </script>"
        "</head>"
        "<body>"
        "    <h1>ESP32-S3 Packet Injector</h1>"

        "    <fieldset class=\"network-panel\">"
        "        <legend>Network</legend>"
        "        <div id=\"netStatus\">Checking connection...</div>"
        "        <button type=\"button\" id=\"scanBtn\" onclick=\"scanNetworks()\">Scan for Networks</button>"
        "        <div id=\"scanResults\"></div>"
        "        <div id=\"connectPanel\" style=\"display:none;\">"
        "            <label for=\"wifi_password\">Password (leave blank if open):</label>"
        "            <input type=\"text\" id=\"wifi_password\" placeholder=\"Wi-Fi password\">"
        "            <button type=\"button\" class=\"scope-btn\" onclick=\"connectNetwork()\">Connect</button>"
        "        </div>"
        "        <div id=\"netConnectStatus\"></div>"
        "    </fieldset>"

        "    <div id=\"scopeLabel\">Current scope: no scope set</div>"

        "    <form id=\"scopeForm\" onsubmit=\"setScope(event)\">"
        "        <fieldset class=\"scope-panel\">"
        "            <legend>Authorization Scope (required before injection)</legend>"
        "            <label for=\"scope_cidr\">Target range (CIDR, /24 only):</label>"
        "            <input type=\"text\" id=\"scope_cidr\" name=\"scope_cidr\" placeholder=\"192.168.1.0/24\" required>"
        "            <div class=\"hint\">Only a single Class C is allowed per session. A different /24 requires resetting scope here.</div>"
        "            <label class=\"ack-label\">"
        "                <input type=\"checkbox\" id=\"scope_ack\" required>"
        "                I own this network/range, or have explicit written authorization to test it."
        "            </label>"
        "            <button type=\"submit\" class=\"scope-btn\">Set / Confirm Scope</button>"
        "            <div id=\"scopeStatus\"></div>"
        "        </fieldset>"
        "    </form>"

        "    <form id=\"injectForm\" onsubmit=\"sendPacket(event)\">"
        "        <fieldset>"
        "            <legend>Network Layer (IP)</legend>"
        "            <div class=\"row\">"
        "                <div class=\"col\">"
        "                    <label for=\"dst_ip\">Target IP *:</label>"
        "                    <input type=\"text\" id=\"dst_ip\" name=\"dst_ip\" value=\"192.168.1.1\" required>"
        "                    <div class=\"hint\">Must fall inside the armed scope above</div>"
        "                </div>"
        "                <div class=\"col\">"
        "                    <label for=\"ttl\">TTL:</label>"
        "                    <input type=\"text\" id=\"ttl\" name=\"ttl\" value=\"64\">"
        "                </div>"
        "            </div>"
        "        </fieldset>"

        "        <fieldset>"
        "            <legend>Quick Presets</legend>"
        "            <div class=\"preset-group\">"
        "                <button type=\"button\" class=\"preset-btn\" onclick=\"applyPreset('syn_scan')\">SYN Scan</button>"
        "                <button type=\"button\" class=\"preset-btn\" onclick=\"applyPreset('null_scan')\">NULL Scan</button>"
        "                <button type=\"button\" class=\"preset-btn\" onclick=\"applyPreset('fin_scan')\">FIN Scan</button>"
        "                <button type=\"button\" class=\"preset-btn\" onclick=\"applyPreset('xmas_scan')\">XMAS Scan</button>"
        "                <button type=\"button\" class=\"preset-btn\" onclick=\"applyPreset('ack_scan')\">ACK Scan</button>"
        "                <button type=\"button\" class=\"preset-btn\" onclick=\"applyPreset('udp_probe')\">UDP Probe</button>"
        "                <button type=\"button\" class=\"preset-btn\" onclick=\"applyPreset('icmp_echo')\">ICMP Echo</button>"
        "            </div>"
        "            <div class=\"hint\">Sets protocol + TCP flags for a common test case. Target IP/port and payload are left as-is.</div>"
        "        </fieldset>"

        "        <fieldset>"
        "            <legend>Transport Layer</legend>"
        "            <label for=\"proto\">Protocol:</label>"
        "            <select id=\"proto\" name=\"proto\">"
        "                <option value=\"tcp\" selected>TCP</option>"
        "                <option value=\"udp\">UDP</option>"
        "                <option value=\"icmp\">ICMP</option>"
        "            </select>"
        "            <div class=\"row\">"
        "                <div class=\"col\">"
        "                    <label for=\"src_port\">Source Port:</label>"
        "                    <input type=\"text\" id=\"src_port\" name=\"src_port\" value=\"12345\">"
        "                </div>"
        "                <div class=\"col\">"
        "                    <label for=\"dst_port\">Destination Port:</label>"
        "                    <input type=\"text\" id=\"dst_port\" name=\"dst_port\" value=\"80\">"
        "                    <select id=\"dst_port_quick\" onchange=\"if(this.value){setPort('dst_port', this.value); this.value='';}\">"
        "                        <option value=\"\">-- Common ports --</option>"
        "                        <option value=\"20\">20 - FTP (data)</option>"
        "                        <option value=\"21\">21 - FTP (control)</option>"
        "                        <option value=\"22\">22 - SSH</option>"
        "                        <option value=\"23\">23 - Telnet</option>"
        "                        <option value=\"25\">25 - SMTP</option>"
        "                        <option value=\"53\">53 - DNS</option>"
        "                        <option value=\"67\">67 - DHCP (server)</option>"
        "                        <option value=\"68\">68 - DHCP (client)</option>"
        "                        <option value=\"69\">69 - TFTP</option>"
        "                        <option value=\"80\">80 - HTTP</option>"
        "                        <option value=\"110\">110 - POP3</option>"
        "                        <option value=\"119\">119 - NNTP</option>"
        "                        <option value=\"123\">123 - NTP</option>"
        "                        <option value=\"135\">135 - MS RPC</option>"
        "                        <option value=\"136\">136 - NetBIOS</option>"
        "                        <option value=\"137\">137 - NetBIOS Name</option>"
        "                        <option value=\"138\">138 - NetBIOS Datagram</option>"
        "                        <option value=\"139\">139 - NetBIOS Session</option>"
        "                        <option value=\"143\">143 - IMAP</option>"
        "                        <option value=\"161\">161 - SNMP</option>"
        "                        <option value=\"162\">162 - SNMP Trap</option>"
        "                        <option value=\"179\">179 - BGP</option>"
        "                        <option value=\"389\">389 - LDAP</option>"
        "                        <option value=\"443\">443 - HTTPS</option>"
        "                        <option value=\"500\">500 - IKE/IPsec</option>"
        "                        <option value=\"636\">636 - LDAPS</option>"
        "                        <option value=\"989\">989 - FTPS (data)</option>"
        "                        <option value=\"990\">990 - FTPS (control)</option>"
        "                    </select>"
        "                </div>"
        "            </div>"
        "            <div class=\"row\">"
        "                <div class=\"col\">"
        "                    <label for=\"seq_num\">Sequence Number:</label>"
        "                    <input type=\"text\" id=\"seq_num\" name=\"seq_num\" value=\"0\">"
        "                </div>"
        "                <div class=\"col\">"
        "                    <label for=\"ack_num\">Acknowledgment Number:</label>"
        "                    <input type=\"text\" id=\"ack_num\" name=\"ack_num\" value=\"0\">"
        "                </div>"
        "            </div>"
        "            <label>TCP Flags:</label>"
        "            <div class=\"checkbox-group\">"
        "                <label class=\"checkbox-label\"><input type=\"checkbox\" name=\"flag_syn\" checked> SYN</label>"
        "                <label class=\"checkbox-label\"><input type=\"checkbox\" name=\"flag_ack\"> ACK</label>"
        "                <label class=\"checkbox-label\"><input type=\"checkbox\" name=\"flag_fin\"> FIN</label>"
        "                <label class=\"checkbox-label\"><input type=\"checkbox\" name=\"flag_rst\"> RST</label>"
        "                <label class=\"checkbox-label\"><input type=\"checkbox\" name=\"flag_psh\"> PSH</label>"
        "                <label class=\"checkbox-label\"><input type=\"checkbox\" name=\"flag_urg\"> URG</label>"
        "                <label class=\"checkbox-label\"><input type=\"checkbox\" name=\"flag_ece\"> ECE</label>"
        "                <label class=\"checkbox-label\"><input type=\"checkbox\" name=\"flag_cwr\"> CWR</label>"
        "            </div>"
        "        </fieldset>"

        "        <fieldset>"
        "            <legend>Payload</legend>"
        "            <label for=\"payload\">Payload Data (ASCII):</label>"
        "            <textarea id=\"payload\" name=\"payload\" rows=\"3\">ESP32 Security Test</textarea>"
        "        </fieldset>"

        "        <button type=\"submit\" id=\"injectBtn\" disabled>Inject Packet</button>"
        "        <div id=\"status\"></div>"
        "    </form>"
        "</body>"
        "</html>";

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, resp_html, strlen(resp_html));
    return ESP_OK;
}

// GET /wifi/status - current connection state, for the GUI to render on load.
static esp_err_t wifi_status_get_handler(httpd_req_t *req) {
    char ssid[33] = {0};
    wifi_sta_get_ssid(ssid, sizeof(ssid));
    bool connected = wifi_sta_is_connected();

    char resp[192];
    if (connected) {
        uint32_t ip_host = 0;
        char ip_str[16] = "unknown";
        if (wifi_sta_get_ip(&ip_host) == ESP_OK) {
            struct in_addr addr = { .s_addr = htonl(ip_host) };
            strncpy(ip_str, inet_ntoa(addr), sizeof(ip_str) - 1);
        }
        snprintf(resp, sizeof(resp),
                 "{\"connected\":true,\"ssid\":\"%s\",\"ip\":\"%s\"}", ssid, ip_str);
    } else {
        snprintf(resp, sizeof(resp),
                 "{\"connected\":false,\"ap_ssid\":\"%s\"}", CONFIG_TOOL_AP_SSID);
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);
    return ESP_OK;
}

// GET /wifi/scan - blocking scan (a few seconds), returns nearby SSIDs.
static esp_err_t wifi_scan_get_handler(httpd_req_t *req) {
    wifi_scan_result_t results[WIFI_SCAN_MAX_RESULTS];
    size_t num_found = 0;

    esp_err_t err = wifi_scan_networks(results, WIFI_SCAN_MAX_RESULTS, &num_found);
    httpd_resp_set_type(req, "application/json");

    if (err != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"status\":\"error\",\"message\":\"Scan failed\"}");
        return ESP_OK;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *networks = cJSON_CreateArray();
    for (size_t i = 0; i < num_found; i++) {
        cJSON *net = cJSON_CreateObject();
        cJSON_AddStringToObject(net, "ssid", results[i].ssid);
        cJSON_AddNumberToObject(net, "rssi", results[i].rssi);
        cJSON_AddBoolToObject(net, "secured", results[i].secured);
        cJSON_AddItemToArray(networks, net);
    }
    cJSON_AddItemToObject(root, "networks", networks);
    char *json_str = cJSON_PrintUnformatted(root);
    httpd_resp_sendstr(req, json_str);
    free(json_str);
    cJSON_Delete(root);
    return ESP_OK;
}

// POST /wifi/connect - { "ssid": "...", "password": "..." }
// Blocks up to ~15s while attempting the connection. On success, drops the
// setup SoftAP shortly AFTER this response is sent (see delayed_ap_shutdown_task).
static void delayed_ap_shutdown_task(void *arg) {
    vTaskDelay(pdMS_TO_TICKS(2000)); // give the HTTP response time to reach the client
    wifi_stop_ap();
    vTaskDelete(NULL);
}

static esp_err_t wifi_connect_post_handler(httpd_req_t *req) {
    char content[192];
    size_t recv_size = (req->content_len < sizeof(content) - 1) ? req->content_len : sizeof(content) - 1;

    int ret = httpd_req_recv(req, content, recv_size);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (root == NULL) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"status\":\"error\",\"message\":\"Invalid JSON\"}");
        return ESP_OK;
    }

    cJSON *j_ssid = cJSON_GetObjectItem(root, "ssid");
    cJSON *j_pass = cJSON_GetObjectItem(root, "password");
    const char *ssid = (j_ssid && cJSON_IsString(j_ssid)) ? j_ssid->valuestring : NULL;
    const char *password = (j_pass && cJSON_IsString(j_pass)) ? j_pass->valuestring : "";

    if (ssid == NULL || strlen(ssid) == 0) {
        cJSON_Delete(root);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"status\":\"error\",\"message\":\"Missing ssid\"}");
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Attempting to join network: %s", ssid);
    esp_err_t result = wifi_connect_to_network(ssid, password, 15000);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");
    char resp[256];

    if (result == ESP_OK) {
        uint32_t ip_host = 0;
        char ip_str[16] = "unknown";
        if (wifi_sta_get_ip(&ip_host) == ESP_OK) {
            struct in_addr addr = { .s_addr = htonl(ip_host) };
            strncpy(ip_str, inet_ntoa(addr), sizeof(ip_str) - 1);
        }
        snprintf(resp, sizeof(resp),
                 "{\"status\":\"success\",\"message\":\"Connected\",\"ip\":\"%s\","
                 "\"note\":\"This setup network will shut off in a moment - reconnect "
                 "your device to your normal network and browse to the new address above.\"}",
                 ip_str);
        httpd_resp_sendstr(req, resp);
        // Drop the SoftAP shortly after - not immediately, so this response
        // has a chance to actually reach the client first.
        xTaskCreate(delayed_ap_shutdown_task, "ap_shutdown", 2048, NULL, 5, NULL);
    } else {
        httpd_resp_set_status(req, "502 Bad Gateway");
        const char *reason = "Connection failed";
        if (result == ESP_ERR_TIMEOUT) reason = "Connection timed out";
        else if (result == ESP_ERR_INVALID_ARG) reason = "Invalid SSID or password length";
        snprintf(resp, sizeof(resp), "{\"status\":\"error\",\"message\":\"%s\"}", reason);
        httpd_resp_sendstr(req, resp);
    }
    return ESP_OK;
}

// POST /scope - sets and arms the authorization scope for this session.
// { "cidr": "192.168.1.0/24", "ack": true }
static esp_err_t scope_post_handler(httpd_req_t *req) {
    char content[256];
    size_t recv_size = (req->content_len < sizeof(content) - 1) ? req->content_len : sizeof(content) - 1;

    int ret = httpd_req_recv(req, content, recv_size);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (root == NULL) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"status\":\"error\",\"message\":\"Invalid JSON\"}");
        return ESP_OK;
    }

    cJSON *j_cidr = cJSON_GetObjectItem(root, "cidr");
    cJSON *j_ack  = cJSON_GetObjectItem(root, "ack");
    bool ack = j_ack && cJSON_IsTrue(j_ack);
    const char *cidr = (j_cidr && cJSON_IsString(j_cidr)) ? j_cidr->valuestring : NULL;

    esp_err_t result = cidr ? scope_set(cidr, ack) : ESP_ERR_INVALID_ARG;
    cJSON_Delete(root);

    char scope_desc[48];
    scope_describe(scope_desc, sizeof(scope_desc));

    httpd_resp_set_type(req, "application/json");
    char resp[192];
    if (result == ESP_OK) {
        snprintf(resp, sizeof(resp),
                 "{\"status\":\"success\",\"message\":\"Scope armed\",\"scope\":\"%s\"}", scope_desc);
        httpd_resp_sendstr(req, resp);
    } else {
        httpd_resp_set_status(req, "400 Bad Request");
        const char *reason = (result == ESP_FAIL)
            ? "Ownership/authorization acknowledgment is required"
            : "Invalid CIDR - only a single /24 is accepted";
        snprintf(resp, sizeof(resp),
                 "{\"status\":\"error\",\"message\":\"%s\",\"scope\":\"%s\"}", reason, scope_desc);
        httpd_resp_sendstr(req, resp);
    }
    return ESP_OK;
}

static esp_err_t inject_post_handler(httpd_req_t *req) {
    char content[1024];
    size_t recv_size = (req->content_len < sizeof(content) - 1) ? req->content_len : sizeof(content) - 1;

    int ret = httpd_req_recv(req, content, recv_size);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    content[ret] = '\0';

    ESP_LOGI(TAG, "Received JSON injection payload: %s", content);

    // Response capture (see net_inject.c) can block up to ~3s waiting for
    // a reply before this handler returns - that's expected, not a bug.
    inject_result_t inj_result = {0};
    esp_err_t result = inject_custom_packet_from_json(content, &inj_result);

    httpd_resp_set_type(req, "application/json");
    char resp[384];
    if (result == ESP_OK) {
        snprintf(resp, sizeof(resp),
                 "{\"status\":\"success\",\"message\":\"Packet sent\","
                 "\"packet_id\":%" PRIu32 ",\"responded\":%s,\"response\":\"%s\"}",
                 inj_result.packet_id, inj_result.responded ? "true" : "false",
                 inj_result.response_summary);
        httpd_resp_sendstr(req, resp);
    } else {
        httpd_resp_set_status(req, "403 Forbidden");
        const char *reason = "Injection failed";
        if (result == ESP_ERR_INVALID_STATE) reason = "No authorization scope is armed - set scope first";
        else if (result == ESP_ERR_NOT_ALLOWED) reason = "Target is outside the armed authorization scope";
        else if (result == ESP_ERR_INVALID_ARG) reason = "Invalid packet parameters";
        snprintf(resp, sizeof(resp),
                 "{\"status\":\"error\",\"message\":\"%s\",\"packet_id\":%" PRIu32 "}",
                 reason, inj_result.packet_id);
        httpd_resp_sendstr(req, resp);
    }
    return ESP_OK;
}

static const httpd_uri_t root_uri = {
    .uri = "/", .method = HTTP_GET, .handler = root_get_handler, .user_ctx = NULL
};
static const httpd_uri_t wifi_status_uri = {
    .uri = "/wifi/status", .method = HTTP_GET, .handler = wifi_status_get_handler, .user_ctx = NULL
};
static const httpd_uri_t wifi_scan_uri = {
    .uri = "/wifi/scan", .method = HTTP_GET, .handler = wifi_scan_get_handler, .user_ctx = NULL
};
static const httpd_uri_t wifi_connect_uri = {
    .uri = "/wifi/connect", .method = HTTP_POST, .handler = wifi_connect_post_handler, .user_ctx = NULL
};
static const httpd_uri_t scope_uri = {
    .uri = "/scope", .method = HTTP_POST, .handler = scope_post_handler, .user_ctx = NULL
};
static const httpd_uri_t inject_uri = {
    .uri = "/inject", .method = HTTP_POST, .handler = inject_post_handler, .user_ctx = NULL
};

static httpd_handle_t start_webserver(void) {
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    config.max_uri_handlers = 8;
    config.max_resp_headers = 8;
    // Packet-crafting handlers use several hundred bytes of stack for
    // header/checksum buffers on top of the JSON parse buffer - the
    // default worker stack size is cutting it close and has been
    // observed to crash the task mid-request. Bump it up.
    config.stack_size = 8192;

    ESP_LOGI(TAG, "Starting HTTP server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &root_uri);
        httpd_register_uri_handler(server, &wifi_status_uri);
        httpd_register_uri_handler(server, &wifi_scan_uri);
        httpd_register_uri_handler(server, &wifi_connect_uri);
        httpd_register_uri_handler(server, &scope_uri);
        httpd_register_uri_handler(server, &inject_uri);
        return server;
    }

    ESP_LOGI(TAG, "Failed to start server!");
    return NULL;
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    scope_init(); // RAM-only, unarmed until POST /scope with ack=true

    ESP_LOGI(TAG, "Initializing Wi-Fi (AP+STA)...");
    wifi_manager_init(); // brings up the open setup SoftAP; no auto-connect

    ESP_LOGI(TAG, "Starting Web Server...");
    start_webserver();
}
