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

const unsigned char * construct_msg_and_block(unsigned char * data, unsigned char * block_id, unsigned char * cert) {
  const unsigned char * message;
  message[0] = '\0';
  // leave room to encrypt data, just put the message together now.
  const unsigned char encrypted_data[80];

  // provvisorio, replace with encryption
  strcpy(encrypted_data, data); 

  message = (const unsigned char *) calloc(strnlen(encrypted_data)+strnlen(block_id)+2, sizeof(unsigned char));
  strcat(message, encrypted_data);
  strcat(message, "-");
  strcat(message, block_id);

  return message;
}
