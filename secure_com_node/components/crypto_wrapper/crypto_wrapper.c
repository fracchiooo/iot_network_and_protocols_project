#include "crypto_wrapper.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"

static const char * TAG = "CRYPTO_WRAPPER";

void init_rng(mbedtls_ctr_drbg_context * ctr_drbg) {
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    char * personalization = "esp32_crypto_wrapper_component";

    mbedtls_ctr_drbg_init(ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, &entropy,
          (const unsigned char *) personalization,
          strlen(personalization));

    if (ret != 0) {
        ESP_LOGE(TAG, "failed to init rng");
    }
}

void base64stringcat(char * strings[], size_t n_of_strings, char * buffer, size_t buffer_size) {

    int buffer_used = 0;
    strcpy(buffer, strings[0]);
    for (int i = 1; i < n_of_strings && buffer_used < buffer_size; i++) {
        unsigned char b64[80];
        size_t outlen;
        strcat(buffer, ":");
        mbedtls_base64_encode(b64, 80, &outlen, (const unsigned char *)strings[i], strlen(strings[i]));
        strcat((char*)b64, strings[i]);
        buffer_used += strlen(strings[i])+1;
    };
}

void give_me_a_nonce(mbedtls_ctr_drbg_context * ctr_drbg, unsigned char * nonce_buffer, size_t nonce_size) {
    mbedtls_ctr_drbg_random(ctr_drbg, nonce_buffer, nonce_size);
}
