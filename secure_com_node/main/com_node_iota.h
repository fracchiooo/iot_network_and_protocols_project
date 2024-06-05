#pragma once

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"

#include "client/api/restful/get_block.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/iota_str.h"

#include "com_node_utils.h"

// IOTA CONTEXT MACROS
#define IOTA_HOST localhost
#define IOTA_PORT 14265
#define IOTA_USE_TLS false
#define IOTA_TAG  "iota.c\xF0\x9F\xA6\x8B"

#define LOG_TAG "IOTA"

enum transactionResult {
  IOTA_SUCCESS,
  IOTA_FAILURE
};

// Returns block id, meant to be "user facing"
int addHashToBlockchain(unsigned char * msg, size_t msg_size, char * block_id);

// Returns block id, overwrites block id, which is assumedly already allocated
int sendDataBlock(unsigned char * data, size_t data_size, char * block_id);

// Returns IOTA SUCCESS io IOTA FAILURE
int retrieveDataBlock(char * block_id, char * block_data);
