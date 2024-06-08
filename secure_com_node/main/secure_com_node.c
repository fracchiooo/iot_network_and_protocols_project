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


void print_certificates(my_connection_data_pointer* cp){

  my_connection_data* curr= cp->certs;

  while(curr!=NULL){
    printf("%s\n", curr->certificate);


    curr=curr->next;
  }


}

void app_main(void)
{

      my_connection_data_pointer* result=(my_connection_data_pointer*) malloc(sizeof(my_connection_data_pointer));
      result->size=0;
      result->end=false;
      result->certs=NULL;



// TODO trovare come deployare il codice su piu esp, ma facendogli usare diversi certificates
// TODO rigenerare i client certificates, aggiungendo il mac address come nome dell host del certificato

  queue = xQueueCreate(5, sizeof(bool));
  xTaskCreatePinnedToCore(wifi_start_connection, "WiFi Task", 4096, queue, 0, NULL, 1);

  initRandomGen(rng);


  // connecting the esp to the broker
  esp_mqtt_client_handle_t client= mqtt_app_start(CONFIG_BROKER_URI, queue, result);

  mqtt_get_node_certificates(client, result);

  printf("I am printing the certificates\n");
  fflush(stdout);
  print_certificates(result);

  fflush(stdout);


  free_certificate_data(result);

  //mqtt_publish_message(client, "prova di connessione", "abcd", 1);

  
  //TODO parte solo indicativa, cosi ancora non funziona

  //char** certs = mqtt_get_node_certificates(client);
  
  //mqtt_get_my_messages(client, get_unique_MAC_address());


  disconnect_mqtt_client(client);
  disconnect_wifi(); 
  vQueueDelete(queue);
  return;
}
