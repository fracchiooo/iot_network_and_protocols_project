#pragma once

#include "com_node_utils.h"

enum transactionResult {
  IOTA_SUCCESS,
  IOTA_FAILURE
};

int addHashToBlockchain(unsigned char * hash_buf, size_t hash_size);
