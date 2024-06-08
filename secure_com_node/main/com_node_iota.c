#include "com_node_iota.h"

int addHashToBlockchain(unsigned char * msg, size_t msg_size) {
  // Calculate SHA256 Hash
  unsigned char * hash_buffer = (unsigned char *) calloc(UTILS_SHA256_OUTPUT_SIZE, sizeof(unsigned char));

  calculateSHA256Hash(msg, msg_size, hash_buffer, UTILS_SHA256_OUTPUT_SIZE);

  // Send data to Iota blockchain

  // cleanup
  free(hash_buffer);
}
