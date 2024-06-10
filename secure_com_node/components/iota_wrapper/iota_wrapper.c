#include "iota_wrapper.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "json_parser.h"
#include "cJSON.h"

static const char *TAG = "IOTA_OVER_HTTPS_CLIENT";

extern const char iota_testnet_root_cert_pem_start[] asm("_binary_iota_testnet_pem_start");
extern const char iota_testnet_root_cert_pem_end[]   asm("_binary_iota_testnet_pem_end");

//extern const char shimmer_testnet_root_cert_pem_start[] asm("_binary_howsmyssl_com_root_cert_pem_start");
//extern const char shimmer_testnet_root_cert_pem_end[]   asm("_binary_howsmyssl_com_root_cert_pem_end");

static char * local_response_buffer;

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer;
    static int output_len;
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            // Clean the buffer in case of a new request
            if (output_len == 0 && evt->user_data) {
                // we are just starting to copy the output data into the use
                memset(evt->user_data, 0, MAX_HTTP_OUTPUT_BUFFER);
            }
            if (esp_http_client_is_chunked_response(evt->client)) {
                // If user_data buffer is configured, copy the response into the buffer
                int copy_len = 0;
                if (evt->user_data) {
                    // The last byte in evt->user_data is kept for the NULL character in case of out-of-bound access.
                    copy_len = MIN(evt->data_len, (MAX_HTTP_OUTPUT_BUFFER - output_len));
                    if (copy_len) {
                        memcpy(evt->user_data + output_len, evt->data, copy_len);
                    }
                } else {
                    int content_len = esp_http_client_get_content_length(evt->client);
                    if (output_buffer == NULL) {
                        // We initialize output_buffer with 0 because it is used by strlen() and similar functions therefore should be null terminated.
                        output_buffer = (char *) calloc(content_len + 1, sizeof(char));
                        output_len = 0;
                        if (output_buffer == NULL) {
                            ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                            return ESP_FAIL;
                        }
                    }
                    copy_len = MIN(evt->data_len, (content_len - output_len));
                    if (copy_len) {
                        memcpy(output_buffer + output_len, evt->data, copy_len);
                    }
                }
                output_len += copy_len;
            }

            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
            if (output_buffer != NULL) {
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            if (output_buffer != NULL) {
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            esp_http_client_set_header(evt->client, "From", "user@example.com");
            esp_http_client_set_header(evt->client, "Accept", "text/html");
            esp_http_client_set_redirection(evt->client);
            break;
    }
    return ESP_OK;
}

void iota_testnet_get_tips(char * parents[], int * n_tips) {

    //char local_response_buffer[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};
    //char * local_response_buffer = (char *) calloc(MAX_HTTP_OUTPUT_BUFFER + 1, sizeof(char));

    esp_http_client_config_t iota_testnet_config = {
        .url = "https://"IOTA_TESTNET_HOSTNAME""TIP_API_ROUTE"",
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,
        .cert_pem = (const char *)iota_testnet_root_cert_pem_start,
    };

    esp_http_client_handle_t client = esp_http_client_init(&iota_testnet_config);
    esp_http_client_set_url(client, "https://"IOTA_TESTNET_HOSTNAME""TIP_API_ROUTE);
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    esp_http_client_set_header(client, "Content-Type", "application/json");

    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        esp_http_client_fetch_headers(client);
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));

        // Parse data here.
        jparse_ctx_t jctx;

        int ret = json_parse_start(&jctx, local_response_buffer, strlen(local_response_buffer));
        if (ret == OS_SUCCESS) {
            int num_elem;
            char str_val[80];

            if (json_obj_get_array(&jctx, "tips", &num_elem) == OS_SUCCESS) {
                ESP_LOGI(TAG, "number of elements: %d", num_elem);
                for (int i = 0; i < MIN(num_elem, *n_tips); i++) {
                    json_arr_get_string(&jctx, i, str_val, sizeof(str_val));
                    strcpy(parents[i], str_val);
                    ESP_LOGI(TAG, "val: %s", str_val);
                }
                *n_tips = num_elem;
                json_obj_leave_array(&jctx);
            }

        } else {
            ESP_LOGI(TAG, "PARSING_FAILURE");
        }
        json_parse_end(&jctx);

    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    //ESP_LOGI(TAG, "%s", local_response_buffer);
    ESP_LOGI(TAG, "TIPS CALL DONE");

    //memset(local_response_buffer, 0, MAX_HTTP_OUTPUT_BUFFER);

    esp_http_client_cleanup(client);

}

void iota_testnet_send_hash(char * parents[], int n_parents, char * data, char * nonce, char * b_id) {

    // Data tag in hex
    // char data_tag[80] = "0x62636861696e7461676765646461746174657374"

    char * post_data = (char *) calloc(1024, sizeof(char));
    strcpy(post_data, "{\"protocolVersion\": 2, \"parents\": [\"");
    for (int i = 0; i < n_parents-1; i++) {
        strcat(post_data, parents[i]);
        strcat(post_data, "\", \"");
    }
    strcat(post_data, parents[n_parents-1]);
    strcat(post_data, "\"], \"payload\": { \"type\": 5, \
\"tag\": \"0x62636861696e7461676765646461746174657374\", \
\"data\": \"");
    strcat(post_data, data);
    strcat(post_data, "\" }, \"nonce\": \"");
    strcat(post_data, nonce);
    strcat(post_data, "\"}");

    ESP_LOGI(TAG, "post data: %s", post_data);

    esp_http_client_config_t iota_testnet_config = {
        .url = "https://api.testnet.iotaledger.net/api/core/v2/blocks",
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,
        .cert_pem = iota_testnet_root_cert_pem_start,
    };

    esp_http_client_handle_t client = esp_http_client_init(&iota_testnet_config);

    esp_http_client_set_url(client, "https://api.testnet.iotaledger.net/api/core/v2/blocks");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Accept", "application/json");
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_err_t err = esp_http_client_perform(client);

    jparse_ctx_t jctx;
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));

        ESP_LOGI(TAG, "%s", local_response_buffer);


        int ret = json_parse_start(&jctx, local_response_buffer, strlen(local_response_buffer));
        if (ret == OS_SUCCESS) {
            char * str_val = (char *) calloc(256, sizeof(char));

            if (json_obj_get_string(&jctx, "blockId", str_val, sizeof(str_val)) == OS_SUCCESS) {
                strcpy(b_id, str_val);
            }
            free(str_val);
        } else {
            ESP_LOGE(TAG, "PARSING_FAILURE");
        }
    } else {
        ESP_LOGE(TAG, "%s", local_response_buffer);
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    free(post_data);

    //memset(local_response_buffer, 0, MAX_HTTP_OUTPUT_BUFFER);

    json_parse_end(&jctx);
    esp_http_client_cleanup(client);
}

void iota_testnet_get_hash(char * block_id, char * hash_buffer) {

  char * block_uri = (char *) calloc(241, sizeof(char));
  strcpy(block_uri, "https://"IOTA_TESTNET_HOSTNAME""BLOCK_API_ROUTE"/");
  strcat(block_uri, block_id);

  esp_http_client_config_t iota_testnet_config = {
      .url = "https://api.testnet.iotaledger.net/api/core/v2/blocks/",
      .transport_type = HTTP_TRANSPORT_OVER_SSL,
      .event_handler = _http_event_handler,
      .user_data = (char *)local_response_buffer,
      .cert_pem = (const char *)iota_testnet_root_cert_pem_start,
  };

  esp_http_client_handle_t client = esp_http_client_init(&iota_testnet_config);

  esp_http_client_set_url(client, block_uri);
  esp_http_client_set_method(client, HTTP_METHOD_GET);

  esp_err_t err = esp_http_client_perform(client);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
      esp_http_client_get_status_code(client),
      esp_http_client_get_content_length(client));

    cJSON *json = cJSON_Parse(local_response_buffer);
    if (json != NULL) {
      cJSON *msg_payload = cJSON_GetObjectItem(json, "payload");
      cJSON *data_payload = cJSON_GetObjectItem(msg_payload, "data");
      if (cJSON_IsString(data_payload) && (data_payload->valuestring != NULL)) {
        ESP_LOGI(TAG, "hash: %s", data_payload->valuestring);
        strcpy(hash_buffer, data_payload->valuestring);
      }
      //cJSON_Delete(data_payload);
      //cJSON_Delete(msg_payload);
      cJSON_Delete(json);
    }
  }

  else {
      ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
  }

  ESP_LOGI(TAG, "found hash for block id: %s", hash_buffer);

  //ESP_LOGI(TAG, "%s", local_response_buffer);
  free(block_uri);

  //memset(local_response_buffer, 0, MAX_HTTP_OUTPUT_BUFFER);

  esp_http_client_cleanup(client);
}

void init_iota_module() {

    local_response_buffer = (char *) calloc(MAX_HTTP_OUTPUT_BUFFER + 1, sizeof(char));
}

void cleanup_iota_module() {
    free(local_response_buffer);
}

//curl -L -X POST 'https://api.testnet.iotaledger.net/api/core/v2/blocks'
//-H 'Content-Type: application/json'
//-H 'Accept: application/json'
//--data-raw '{"protocolVersion": 2, "parents": ["0x00974d9fb276b192b043be13d92f05ad4b2919a6ffd92405f34deea4f4642591", "0xa5535f3e8cbac4a7958da1d79cb281b75bea8a189f97df383ed5ddc8966c908d", "0xa885e011eeffea65ab2adf1c0ce413880469498000a8be70d84ba56925c2e034", "0xf6df4bb2689aa76a20295391661d4e2f74fa75e628ad541a715bb25b44654953"], "payload": { "type": 5, "tag": "0x62636861696e7461676765646461746174657374" "data": "0xcafecafe" }, "nonce": "��d31271d6f8a2dd41b00c2fa5c7bb50a5"}'
