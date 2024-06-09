#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "sdkconfig.h"
#include "wifi_wrapper.h"
#include "mqtt_wrapper.h"
#include "com_node_utils.h"
#include "freertos/queue.h"
#include "esp_mac.h"

#define RECEIVER 0
#define NONCE_LEN 8


QueueHandle_t queue;
mbedtls_ctr_drbg_context * rng;

const uint8_t init_device[6]={0x48,0x27,0xE2,0xE2,0xE5,0xE4};
  
  
void get_unique_MAC_address(uint8_t mac[6]){

  esp_efuse_mac_get_default(mac);
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  return;
  
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
    //printf("%s\n", curr->certificate);
    printf("\n----------------------------------\n");
    char buf[1024];
    mbedtls_x509_crt_info(buf, sizeof(buf)-1, "", &curr->certificate);
    printf("%s\n", buf);

    printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",curr->MAC[0],curr->MAC[1],curr->MAC[2],curr->MAC[3],curr->MAC[4],curr->MAC[5]);

    mbedtls_x509_crt *certificate = &(curr->certificate);  // Assuming curr is a pointer to a structure containing the certificate
    /*mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Extract public key from the certificate
    mbedtls_pk_parse_public_key(&pk, certificate->pk.p, certificate->pk.len);



    unsigned char buffer[1024];
    mbedtls_pk_write_pubkey_pem(&pk, buffer, sizeof(buffer));
    printf("public key: %s\n", buffer);*/

    printf("\n----------------------------------\n");
    fflush(stdout);


    curr=curr->next;
  }


}

void app_main(void)
{




      //struct for callback
      char* mess=(char*) malloc(max_mess_size);
      memset(mess, 0, max_mess_size);



// TODO trovare come deployare il codice su piu esp, ma facendogli usare diversi certificates
// TODO rigenerare i client certificates, aggiungendo il mac address come nome dell host del certificato

  queue = xQueueCreate(5, sizeof(bool));
  xTaskCreatePinnedToCore(wifi_start_connection, "WiFi Task", 4096, queue, 0, NULL, 1);

  //initRandomGen(rng);


  // connecting the esp to the broker
  esp_mqtt_client_handle_t client= mqtt_app_start(CONFIG_BROKER_URI, queue, mess);

  my_connection_data_pointer* result=mqtt_get_node_certificates(client, mess);

  printf("I am printing the certificates\n");
  fflush(stdout);
  print_certificates(result);
  fflush(stdout);

  uint8_t my_mac[6];
  get_unique_MAC_address(my_mac);
  printf("MAC Address: ");
  printf("MAC mio device: %02X:%02X:%02X:%02X:%02X:%02X\n",my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);

  if(memcmp(init_device,my_mac, sizeof(my_mac))==0){

    printf("sono il device che vuole iniziare una connessione\n");
    fflush(stdout);



  }

  else{
    printf("sono il device che riceve una connessione e la accetta dopo handshaking\n");
    fflush(stdout);


  }



  //mqtt_publish_message(client, "prova di connessione", "abcd", 1);

  
  //TODO parte solo indicativa, cosi ancora non funziona

  //char** certs = mqtt_get_node_certificates(client);
  
  //mqtt_get_my_messages(client, get_unique_MAC_address());

  free(mess);
  free_certificate_data(result);

  disconnect_mqtt_client(client);
  disconnect_wifi(); 
  return;
}
