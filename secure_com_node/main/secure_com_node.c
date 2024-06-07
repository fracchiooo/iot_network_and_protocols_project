#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "sdkconfig.h"
#include "wifi_wrapper.h"
#include "mqtt_wrapper.h"
//#include "com_node_utils.h"
#include "freertos/queue.h"
#include "esp_mac.h"

#define RECEIVER 0
#define NONCE_LEN 8


QueueHandle_t queue;
//  mbedtls_ctr_drbg_context * rng;
  
  
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
 //generateNonce(rng, nonce, NONCE_LEN);

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
 //generateNonce(rng, nonce2, NONCE_LEN);

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
  while(1){
  if(xQueueReceive(queue, &value, (TickType_t)5)){
    if(value==true){
      printf("mqtt could proceed, connection established and ip address received\n");
      fflush(stdout);
      break;
    }
  }

  //initRandomGen(rng);

  vTaskDelay(400/ portTICK_PERIOD_MS);
  }


  // connecting the esp to the broker
  esp_mqtt_client_handle_t client= mqtt_app_start(CONFIG_BROKER_URI, queue);

  mqtt_publish_message(client, "prova di connessione", "broker", 1);

  
  //TODO parte solo indicativa, cosi ancora non funziona

  //char** certs = mqtt_get_node_certificates(client);
  
  //mqtt_get_my_messages(client, get_unique_MAC_address());

  disconnect_mqtt_client(client);
  disconnect_wifi(); 
  vQueueDelete(queue);
  return;
}
