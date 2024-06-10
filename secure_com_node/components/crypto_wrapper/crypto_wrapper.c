#include "crypto_wrapper.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"
#include <string.h>

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
    }
}

void base64cat_decode(char * in_string, char * out_strings[], size_t n_strings, size_t string_size) {
  int last_dot = 0, j = 0, outlen = 0;
  char * buffer = (char *) calloc(256, sizeof(char));
  char * dec_buffer = (char *) calloc(256, sizeof(char));
  for (int i = 0; i < strlen(in_string) && j < n_strings; i++) {
    if (in_string[i] == ':') {
      strncpy(buffer, in_string + last_dot, (strlen(in_string) - 1) - last_dot);
      last_dot = i+1;
      mbedtls_base64_decode(out_strings[j], string_size, &outlen, (const unsigned char *)buffer, strlen(buffer));
      j++;
    }
  }
  strncpy(buffer, in_string + last_dot, (strlen(in_string) - 1) - last_dot);
  last_dot = i+1;
  mbedtls_base64_decode(out_strings[j], string_size, &outlen, (const unsigned char *)buffer, strlen(buffer));

  free(dec_buffer);
  free(buffer);
}

void construct_conn_init_message(mbedtls_ctr_drbg_context *rng, char * out_string, size_t out_string_size) {
  char * nonce_buffer = (char *) calloc(NONCE_SIZE, sizeof(char));
  size_t nonce_size = NONCE_SIZE;

  char * AES_key[32];

  give_me_a_nonce(rng, nonce_buffer, nonce_size);

  // This is our AES key. Yes, this is what the documentation says
  int ret = mbedtls_ctr_drbg_random(rng, AES_key, 32);
  if (ret != 0 ) {
    ESP_LOGE(TAG, "Failed to generate key");
  }

  // What do we need? A cert, B's MAC and a key signed with B's pubkey
  char * values[] = {"CONN_REQUEST", CERT_A, "0", nonce_buffer, MAC_B, KEY_SIGNED_WITH_B_KEY};
}

void give_me_a_nonce(mbedtls_ctr_drbg_context * ctr_drbg, unsigned char * nonce_buffer, size_t nonce_size) {
    mbedtls_ctr_drbg_random(ctr_drbg, nonce_buffer, nonce_size);
}
