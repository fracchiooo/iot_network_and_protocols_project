#include "iota_wrapper.h"
#include "esp_err.h"
#include "esp_http_client.h"
#include "json_parser.h"

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
    //esp_http_client_set_url(client, "https://"IOTA_TESTNET_HOSTNAME""TIP_API_ROUTE);
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    //esp_http_client_set_header(client, "Content-Type", "application/json");

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
            ESP_LOGI(TAG, "test");
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
            json_obj_leave_object(&jctx);

        } else {
            ESP_LOGI(TAG, "PARSING_FAILURE");
        }

    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    //ESP_LOGI(TAG, "%s", local_response_buffer);
    ESP_LOGI(TAG, "TIPS CALL DONE");

    //const char *post_data = "{\"parents\";[]
    esp_http_client_set_url(client, "https://"IOTA_TESTNET_HOSTNAME""BLOCK_API_ROUTE"");
    esp_http_client_set_method(client, HTTP_METHOD_POST);

    esp_http_client_cleanup(client);

    // ESP_LOG_BUFFER_HEX(TAG, local_response_buffer, strlen(local_response_buffer));
    //free(local_response_buffer);
    //ESP_LOGI(TAG, "FREED");
}

void iota_testnet_send_hash(char parents[][80], char * nonce) {

    esp_http_client_config_t iota_testnet_config = {
        .host = IOTA_TESTNET_ROUTE,
        .path = BLOCK_API_ROUTE,
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .event_handler = _http_event_handler,
        .user_data = local_response_buffer,
        .cert_pem = iota_testnet_root_cert_pem_start,
    };


    esp_http_client_handle_t client = esp_http_client_init(&iota_testnet_config);

    const char *post_data = "";
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }
}

void iota_testnet_get_hash(char * block_id, char ** hash_buffer) {

    char * block_uri = (char *) calloc(241, sizeof(char));
    strcpy(block_uri, "https://"IOTA_TESTNET_HOSTNAME""BLOCK_API_ROUTE"/");
    strcat(block_uri, block_id);

    ESP_LOGI(TAG, "composed uri: %s", block_uri);

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
    //esp_http_client_set_header(client, "Accept", "application/json");

    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %"PRId64,
                esp_http_client_get_status_code(client),
                esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
    }

    ESP_LOGI(TAG, "%s", local_response_buffer);
    free(block_uri);
    esp_http_client_cleanup(client);
}

void init_iota_module() {
    //esp_err_t ret = nvs_flash_init();
    //if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      //ESP_ERROR_CHECK(nvs_flash_erase());
      //ret = nvs_flash_init();
    //}
    //ESP_ERROR_CHECK(ret);

    //ESP_ERROR_CHECK(esp_netif_init());

    local_response_buffer = (char *) calloc(MAX_HTTP_OUTPUT_BUFFER + 1, sizeof(char));
    //ESP_ERROR_CHECK(esp_event_loop_create_default());
}

void cleanup_iota_module() {
    free(local_response_buffer);
}
