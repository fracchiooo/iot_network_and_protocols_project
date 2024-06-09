#include <string.h>
#include <stlib.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_log.h"

void init_rng(mbedtls_ctr_drbg_context * ctr_drbg);

void give_me_a_nonce(mbedtls_ctr_drbg_context * ctr_drbg, char * nonce_buffer, size_t nonce_size);
