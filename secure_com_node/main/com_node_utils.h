#pragma once

#include "esp_tls.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <stdint.h>
#include <string.h>

#define UTILS_SHA256_OUTPUT_SIZE 32

// Expects the buffer to be able to be already allocated, and to be able to contain at least 32+1 elements
void calculateSHA256Hash(unsigned char * msg, size_t msg_size, unsigned char * output_buffer, size_t buf_size);

void generateNonce();

int initRandomGen(mbedtls_ctr_drbg_context * ctr_ctx);
