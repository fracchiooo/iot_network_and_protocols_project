#include <string.h>
#include <stdlib.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_log.h"

void init_rng(mbedtls_ctr_drbg_context * ctr_drbg);

void give_me_a_nonce(mbedtls_ctr_drbg_context * ctr_drbg, unsigned char * nonce_buffer, size_t nonce_size);

void base64stringcat(char * strings[], size_t n_of_strings, char * buffer, size_t buffer_size);
