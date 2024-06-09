#include "com_node_utils.h"
/*
void calculateSHA256Hash(unsigned char * msg, size_t msg_size, unsigned char * output_buffer, size_t buf_size) {
  if (buf_size == 32) {
    mbedtls_sha256(msg, msg_size, output_buffer, 0);
  }
#ifdef DEBUG
  else {
    ESP_LOGI("UTILS_DEBUG", "sha256 buffer not of adequate size");
  }
#endif
}

int initRandomGen(mbedtls_ctr_drbg_context * ctr_ctx) {
// Init mbed tls entropy systemd
  mbedtls_entropy_context entrpy;
  mbedtls_entropy_init(&entrpy);

  char * pers = "iotnp";

  mbedtls_ctr_drbg_init(ctr_ctx);

  int ret = mbedtls_ctr_drbg_seed(ctr_ctx, mbedtls_entropy_func, &entrpy,
		  (const unsigned char *) pers,
		  strlen(pers));

  if (ret != 0) {
	  ESP_LOGI("UTILS_DEBUG", "failed to init RNG system");
  }

  return 1;
}

void generateNonce(mbedtls_ctr_drbg_context * rng, unsigned char * nonce_buffer, size_t nonce_len) {
  mbedtls_ctr_drbg_random(rng, nonce_buffer, nonce_len);
}*/
