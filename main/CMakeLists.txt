idf_component_register(SRCS "main.c" "net_inject.c" "wifi_sta.c" "scope.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_wifi esp_netif esp_http_server cjson)