#include <string.h>
#include <stdlib.h>
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

#include "wifi_sta.h"
#include "net_inject.h"

static const char *TAG = "main";

/* Expanded hping3-style mobile-responsive security test GUI with AJAX/Fetch submission */
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
        "        legend { color: #82aaff; font-weight: bold; padding: 0 5px; }"
        "        label { display: block; margin-top: 10px; font-size: 0.9rem; font-weight: 600; color: #d5d8dc; }"
        "        input[type=\"text\"], select, textarea { width: 100%; padding: 10px; margin-top: 5px; background: #151821; border: 1px solid #3f4451; color: #fff; border-radius: 4px; box-sizing: border-box; font-size: 0.95rem; }"
        "        input[type=\"text\"]:focus, select:focus, textarea:focus { border-color: #82aaff; outline: none; }"
        "        .row { display: flex; gap: 10px; }"
        "        .col { flex: 1; }"
        "        .checkbox-group { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-top: 8px; background: #151821; padding: 10px; border-radius: 4px; border: 1px solid #3f4451; }"
        "        .checkbox-label { display: flex; align-items: center; gap: 5px; font-size: 0.85rem; cursor: pointer; color: #e2e8f0; font-weight: normal; }"
        "        button { background: #ff5370; color: white; border: none; padding: 14px; width: 100%; margin-top: 10px; font-size: 1rem; font-weight: bold; border-radius: 4px; cursor: pointer; transition: background 0.2s; }"
        "        button:hover { background: #ff6b81; }"
        "        .hint { font-size: 0.75rem; color: #7f8c8d; margin-top: 2px; }"
        "        #status { margin-top: 15px; padding: 10px; text-align: center; font-weight: bold; border-radius: 4px; display: none; }"
        "        .success { background: #2ecc71; color: #fff; }"
        "        .error { background: #e74c3c; color: #fff; }"
        "    </style>"
        "    <script>"
        "        function setPort(elementId, port) {"
        "            document.getElementById(elementId).value = port;"
        "        }"
        "        function sendPacket(event) {"
        "            event.preventDefault();"
        "            const form = document.getElementById('injectForm');"
        "            const formData = new FormData(form);"
        "            const data = {};"
        "            formData.forEach((value, key) => { data[key] = value; });"
        "            // Handle checkboxes explicitly if unchecked"
        "            const checkboxes = ['flag_syn', 'flag_ack', 'flag_fin', 'flag_rst', 'flag_psh', 'flag_urg', 'flag_ece', 'flag_cwr'];"
        "            checkboxes.forEach(box => {"
        "                data[box] = form.elements[box].checked ? '1' : '0';"
        "            });"
        "            const statusDiv = document.getElementById('status');"
        "            statusDiv.style.display = 'block';"
        "            statusDiv.className = '';"
        "            statusDiv.innerText = 'Sending packet parameters...';"
        "            fetch('/inject', {"
        "                method: 'POST',"
        "                headers: { 'Content-Type': 'application/json' },"
        "                body: JSON.stringify(data)"
        "            })"
        "            .then(response => response.json())"
        "            .then(result => {"
        "                statusDiv.className = 'success';"
        "                statusDiv.innerText = 'Success: ' + result.message;"
        "            })"
        "            .catch(error => {"
        "                statusDiv.className = 'error';"
        "                statusDiv.innerText = 'Error sending request connection failed.';"
        "                console.error('Error:', error);"
        "            });"
        "        }"
        "    </script>"
        "</head>"
        "<body>"
        "    <h1>ESP32-S3 Packet Injector (hping3-mode)</h1>"
        "    <form id=\"injectForm\" onsubmit=\"sendPacket(event)\">"
        "        <!-- Network Layer Settings -->"
        "        <fieldset>"
        "            <legend>Network Layer (IP)</legend>"
        "            <label for=\"ip_ver\">IP Version:</label>"
        "            <select id=\"ip_ver\" name=\"ip_ver\">"
        "                <option value=\"ipv4\" selected>IPv4</option>"
        "                <option value=\"ipv6\">IPv6</option>"
        "            </select>"
        "            "
        "            <div class=\"row\">"
        "                <div class=\"col\">"
        "                    <label for=\"src_ip\">Source IP:</label>"
        "                    <input type=\"text\" id=\"src_ip\" name=\"src_ip\" placeholder=\"Auto (ESP32 IP)\">"
        "                    <div class=\"hint\">Leave blank to use device IP</div>"
        "                </div>"
        "                <div class=\"col\">"
        "                    <label for=\"dst_ip\">Target IP *:</label>"
        "                    <input type=\"text\" id=\"dst_ip\" name=\"dst_ip\" value=\"192.168.1.1\" required>"
        "                </div>"
        "            </div>"
        "            "
        "            <div class=\"row\">"
        "                <div class=\"col\">"
        "                    <label for=\"ttl\">TTL / Hop Limit:</label>"
        "                    <input type=\"text\" id=\"ttl\" name=\"ttl\" value=\"64\">"
        "                </div>"
        "                <div class=\"col\">"
        "                    <label for=\"ip_chksum\">IP Checksum:</label>"
        "                    <input type=\"text\" id=\"ip_chksum\" name=\"ip_chksum\" placeholder=\"Auto-calculate\">"
        "                    <div class=\"hint\">Leave blank for correct checksum</div>"
        "                </div>"
        "            </div>"
        "        </fieldset>"

        "        <!-- Transport Layer Settings -->"
        "        <fieldset>"
        "            <legend>Transport Layer</legend>"
        "            <label for=\"proto\">Protocol:</label>"
        "            <select id=\"proto\" name=\"proto\">"
        "                <option value=\"tcp\" selected>TCP</option>"
        "                <option value=\"udp\">UDP</option>"
        "                <option value=\"icmp\">ICMP</option>"
        "            </select>"
        "            "
        "            <div class=\"row\">"
        "                <div class=\"col\">"
        "                    <label for=\"src_port\">Source Port:</label>"
        "                    <input type=\"text\" id=\"src_port\" name=\"src_port\" value=\"12345\">"
        "                </div>"
        "                <div class=\"col\">"
        "                    <label for=\"dst_port\">Destination Port:</label>"
        "                    <input type=\"text\" id=\"dst_port\" name=\"dst_port\" value=\"80\">"
        "                    <div class=\"hint\">Common: <a href=\"#\" onclick=\"setPort('dst_port', 80); return false;\">80</a> | <a href=\"#\" onclick=\"setPort('dst_port', 443); return false;\">443</a> | <a href=\"#\" onclick=\"setPort('dst_port', 22); return false;\">22</a></div>"
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

        "        <!-- Payload & Rate -->"
        "        <fieldset>"
        "            <legend>Payload & Options</legend>"
        "            <label for=\"packet_count\">Packet Count:</label>"
        "            <input type=\"text\" id=\"packet_count\" name=\"packet_count\" value=\"1\">"
        "            "
        "            <label for=\"payload\">Payload Data (ASCII):</label>"
        "            <textarea id=\"payload\" name=\"payload\" rows=\"3\">ESP32 Security Test</textarea>"
        "        </fieldset>"

        "        <button type=\"submit\">Inject Packets</button>"
        "        <div id=\"status\"></div>"
        "    </form>"
        "</body>"
        "</html>";

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, resp_html, strlen(resp_html));
    return ESP_OK;
}

/* POST handler for packet injection JSON stream */
static esp_err_t inject_post_handler(httpd_req_t *req) {
    char content[1024];
    
    size_t content_len = req->content_len;
    size_t max_len = sizeof(content) - 1;
    size_t recv_size = (content_len < max_len) ? content_len : max_len;
    
    int ret = httpd_req_recv(req, content, recv_size);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    content[ret] = '\0';

    ESP_LOGI(TAG, "Received JSON injection payload: %s", content);

    #ifdef NET_INJECT_PROCESS_EXISTS
    net_inject_process(content);
    #endif

    const char *resp = "{\"status\":\"success\",\"message\":\"Packet parameters received and queued for injection\"}";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, strlen(resp));
    return ESP_OK;
}

static const httpd_uri_t root_uri = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = root_get_handler,
    .user_ctx  = NULL
};

static const httpd_uri_t inject_uri = {
    .uri       = "/inject",
    .method    = HTTP_POST,
    .handler   = inject_post_handler,
    .user_ctx  = NULL
};

static httpd_handle_t start_webserver(void) {
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    
    config.max_uri_handlers = 8;
    config.max_resp_headers = 8;

    ESP_LOGI(TAG, "Starting HTTP server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &root_uri);
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

    ESP_LOGI(TAG, "Initializing Wi-Fi Station...");
    wifi_init_sta();

    ESP_LOGI(TAG, "Starting Web Server...");
    start_webserver();
}