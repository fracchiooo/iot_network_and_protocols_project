#ifndef WIFI_WRAPPER_H
#define WIFI_WRAPPER_H


#include "sdkconfig.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "nvs_flash.h"


#define WIFI_SSID   CONFIG_WIFI_SSID
#define WIFI_PASS   CONFIG_WIFI_PASS


QueueHandle_t publish_queue=NULL;



static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                    int32_t event_id, void* event_data) {
    if (event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_id == WIFI_EVENT_STA_CONNECTED) {
        ESP_LOGI("WIFI", "Connesso al punto di accesso");
    } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI("WIFI", "Disconnesso dal punto di accesso");
        esp_wifi_connect();
    } else if (event_id == IP_EVENT_STA_GOT_IP) {
        if(publish_queue!=NULL){
          printf("got ip, proceeding to unblock mqtt");
          fflush(stdout);
          bool res=true;
          xQueueSend(publish_queue, &res, (TickType_t)0);
        }
    }
}

static void wifi_start_connection(QueueHandle_t queue){

    publish_queue=queue;
    
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip);

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();
    
    vTaskDelete(NULL);

}


static void disconnect_wifi(){

  ESP_ERROR_CHECK(esp_wifi_disconnect());
  
  ESP_ERROR_CHECK(esp_wifi_stop());
  
  ESP_ERROR_CHECK(esp_wifi_deinit());
  
  ESP_LOGI("WIFI", "WIFI disconnected and deallocated");

}

#endif
