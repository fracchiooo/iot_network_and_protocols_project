#include "com_node_iota.h"

int addHashToBlockchain(unsigned char * msg, size_t msg_size, char * block_id) {
  // Calculate SHA256 Hash
  unsigned char * hash_buffer = (unsigned char *) calloc(UTILS_SHA256_OUTPUT_SIZE, sizeof(unsigned char));

  calculateSHA256Hash(msg, msg_size, hash_buffer, UTILS_SHA256_OUTPUT_SIZE);

  // Send data to Iota blockchain
  if (sendDataBlock(msg, msg_size, block_id) != IOTA_SUCCESS) {
    ESP_LOGI(LOG_TAG, "Failed to send data to IOTA testnet");
    return IOTA_FAILURE;
  }

  // cleanup
  free(hash_buffer);

  return IOTA_SUCCESS;
}

int sendDataBlock(unsigned char * data, size_t data_size, char * block_id) {
  // config context
  iota_client_conf_t ctx = {
    .host = IOTA_HOST,
    .port = IOTA_PORT,
    .use_TLS = IOTA_USE_TLS,
  };

  res_send_block_t res = {0};
  ESP_LOGI(LOG_TAG, "Sending hash to tangle...");
  if (send_tagged_data_block(&ctx, 2, (byte_t *)IOTA_TAG, strlen(IOTA_TAG), (byte_t *) data, data_size, &res) == 0) {
    if (res.is_error) {
      ESP_LOGI(LOG_TAG, "IOTA API Failure : %s", res.u.error->msg);
      return IOTA_FAILURE;
    }
  } else {
    ESP_LOGI(LOG_TAG, "IOTA API Generic Failure!");
    return IOTA_FAILURE;
  }
  
  ESP_LOGI(LOG_TAG, "Hash block succesfully sent.");
  ESP_LOGI(LOG_TAG, "Block ID: %s", res.u.blk_id);

  *block_id = res.u.blk_id;

  return IOTA_SUCCESS;
}

int retrieveDataBlock(char * block_id, char * block_data) {
  res_block_t *blk = res_block_new();

  if (!blk) {
    ESP_LOGI(LOG_TAG, "Failed to create response block object");
    return IOTA_FAILURE;
  }

  ESP_LOGI(LOG_TAG, "Fetching hash data from tangle...");
  if (get_block_by_id(&ctx, block_id, blk) == 0) {
    if (blk->is_error) {
      ESP_LOGI(LOG_TAG, "IOTA API Failure: %s", blk->u.error->msg);
      res_block_free(blk);
      return IOTA_FAILURE;
    }
  } else {
    ESP_LOGI(LOG_TAG, "IOTA API Failure : %s", res.u.error->msg);
    res_block_free(blk);
    return IOTA_FAILURE;
  }

  ESP_LOGI(LOG_TAG, "hash block succesfully fetched");
  
  // Check if it is an actual tagged data block
  if (blk->u.blk->payload_type != CORE_BLOCK_PAYLOAD_TAGGED) {
    ESP_LOGI(LOG_TAG, "Fetched block not a tagged data block!");
    res_block_free(blk);
    return IOTA_FAILURE;
  }

  // Convert block payload to string
  if (!byte_buf2str(((tagged_data_payload_t *)blk->u.blk->payload)->data)) {
    ESP_LOGI("Failed to convert payload into string");
    res_block_free(blk);
    return IOTA_FAILURE;
  }
  
  *block_data = ((tagged_data_payload_t *)blk->u.blk->payload)->data->data;

  res_block_free(blk);

  return IOTA_SUCCESS;
}
