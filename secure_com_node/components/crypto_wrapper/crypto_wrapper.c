#include "crypto_wrapper.h"
#include "mbedtls/ctr_drbg.h"

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

void gimme_a_nonce(mbedtls_ctr_drbg_context * ctr_drbg, unsigned char * nonce_buffer, size_t nonce_size) {
    mbedtls_ctr_drbg_random(ctr_drbg, nonce_buffer, nonce_size);
}
