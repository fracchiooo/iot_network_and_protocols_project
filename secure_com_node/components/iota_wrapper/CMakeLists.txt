idf_component_register( SRCS "iota_wrapper.c" "cJSON.c" "cJSON_Utils.c"
			INCLUDE_DIRS "."
			EMBED_TXTFILES "./certs/iota_testnet.pem"
			REQUIRES esp_http_client json nvs_flash esp_netif esp-tls jsmn
			)
