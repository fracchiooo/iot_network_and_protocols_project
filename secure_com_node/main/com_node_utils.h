#pragma once

#include "esp_tls.h"
#include "mbedtls/sha256.h"
#include <stdint.h>

#define UTILS_SHA256_OUTPUT_SIZE 32

// Expects the buffer to be able to be already allocated, and to be able to contain at least 32+1 elements
void calculateSHA256Hash(unsigned char * msg, size_t msg_size, unsigned char * output_buffer, size_t buf_size);

void construct_msg_and_block(unsigned char * message, unsigned char * block_id, unsigned char * cert);
