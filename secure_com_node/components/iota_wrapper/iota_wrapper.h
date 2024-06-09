#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"

#include <stdlib.h>
#include <ctype.h>
#include "json_parser.h"
#include "sys/param.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_tls.h"

#include "esp_http_client.h"
#include "iota_defines.h"

#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048

void iota_testnet_get_tips(char * parents[], int * n_tips);
void iota_testnet_send_hash(char * parents[], int n_parents, char * data, char * nonce, char * b_id);
void iota_testnet_get_hash(char * block_id, char * hash_buffer);
void init_iota_module();
void cleanup_iota_module();
