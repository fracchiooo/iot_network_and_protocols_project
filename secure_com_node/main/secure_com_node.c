#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "sdkconfig.h"
#include "wifi_wrapper.h"
#include "mqtt_wrapper.h"
#include "iota_wrapper.h"
#include "crypto_wrapper.h"
#include "com_node_utils.h"
#include "freertos/queue.h"
#include "esp_mac.h"

#define RECEIVER 0
#define NONCE_LEN 8


QueueHandle_t queue;
  mbedtls_ctr_drbg_context * rng;


char* get_unique_MAC_address(){
  char res[6*8];
  unsigned char mac_base[6] = {0};
  esp_efuse_mac_get_default(mac_base);
  esp_read_mac(mac_base, ESP_MAC_WIFI_STA);
  //unsigned char mac_local_base[6] = {0};
  //unsigned char mac_uni_base[6] = {0};
  //esp_derive_local_mac(mac_local_base, mac_uni_base);
  //printf("Local Address: ")
  //print_mac(mac_local_base);
  //printf("\nUni Address: ");
  //print_mac(mac_uni_base);
  printf("MAC Address: ");
  //print_mac(mac_base);

  sprintf(res, "%02X:%02X:%02X:%02X:%02X:%02X", mac_base[0],mac_base[1],mac_base[2],mac_base[3],mac_base[4],mac_base[5]);
  return res;

}

void request_public_keys(char * key_buffer, char * keylen)
{
  // Send mqtt general message that requests key resend?
  printf("not implem yet");
}

void establish_connection(char* MAC_identity_dest){

//establishing key = true

//generate the nounce N, half session key k, rsa encrypt key with dest public key (you have in certs list) and sign the total message with my private key
//send the total message to topic /MAC_identity_dest
 unsigned char nonce[NONCE_LEN] = {0};
 generateNonce(rng, nonce, NONCE_LEN);

//wait for answer in my /My_MAC_identity topic

//decrypt second half key received

//respond with the signature of the received Nounce N'


//concatenate the keys

//send AES 128 encrypted message on the /MAC_identity_dest

}


void request_establish_connection(char* MAC_identity_src, char* src_mess){
//establishing key = true

//generate the nounce N', half session key k', rsa encrypt key with src public key (you have in certs list) and sign the total message with my private key considering src_mess nounce N
 unsigned char nonce2[NONCE_LEN] = {0};
 generateNonce(rng, nonce2, NONCE_LEN);

//concatenate the keys

//send AES 128 encrypted message on the /MAC_identity_src, responding to its messages

}

void app_main(void)
{


// TODO trovare come deployare il codice su piu esp, ma facendogli usare diversi certificates
// TODO rigenerare i client certificates, aggiungendo il mac address come nome dell host del certificato

  queue = xQueueCreate(5, sizeof(bool));
  xTaskCreatePinnedToCore(wifi_start_connection, "WiFi Task", 4096, queue, 0, NULL, 1);

  // TODO questa parte va rifatta meglio, per ora blocco qua per non far andare in errore mwtt client
  //while(1){
  //if(xQueueReceive(queue, &value, (TickType_t)5)){
  //  if(value==true){
  //    printf("mqtt could proceed, connection established and ip address received\n");
  //    fflush(stdout);
  //    break;
  //  }
  //}

  //initRandomGen(rng);
  init_iota_module();

  printf("\n");
  vTaskDelay(2000/ portTICK_PERIOD_MS);
  //}

  unsigned char nonce[4];
  char nonce_hex[9];
  char * block_id = (char *) calloc(241, sizeof(char));
  mbedtls_ctr_drbg_context rng;
  init_rng(&rng);
  ESP_LOGI("MAIN", "generate nonce");
  give_me_a_nonce(&rng, nonce, 20);

  for(int i = 0; i < 2; i++)
    sprintf(nonce_hex+2*i, "%d", nonce[i]);

  printf("%s\n",nonce_hex);

  int max_tips = 8;
  char * tips[max_tips];
  for (int i = 0; i < max_tips; i++) {
    tips[i] = (char *) calloc(256, sizeof(char));
  }

  char * hash_buffer = (char *) calloc(512, sizeof(char));
  ESP_LOGI("MAIN", "getting tips");
  iota_testnet_get_tips(tips, &max_tips);
  ESP_LOGI("MAIN", "tips obtained");
  iota_testnet_send_hash(tips, max_tips, "0xcafecafe", nonce_hex, block_id);
  ESP_LOGI("MAIN", "hash sent");
  iota_testnet_get_hash(tips[0], hash_buffer);
  ESP_LOGI("MAIN","final hash: %s", hash_buffer);

  free(hash_buffer);
  for (int i = 0; i < max_tips; i++) {
    free(tips[i]);
  }
  free(block_id);

  cleanup_iota_module();
  disconnect_wifi();
  vQueueDelete(queue);
  return;
}
