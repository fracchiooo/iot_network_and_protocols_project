#include "com_node_utils.h"

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
