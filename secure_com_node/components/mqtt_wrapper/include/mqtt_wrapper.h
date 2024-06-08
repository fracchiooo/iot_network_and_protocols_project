#ifndef MQTT_WRAPPER_H
#define MQTT_WRAPPER_H
#include "mqtt_client.h"
#include <string.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include "esp_err.h"


typedef struct my_connection_data{

    uint8_t MAC[6];
    char* certificate;
    uint8_t sim_key[16];
    struct my_connection_data * next;

} my_connection_data;

typedef struct {

    my_connection_data* certs;
    size_t size;
    bool end;

} my_connection_data_pointer;



static const char *TAG_mqtt = "MQTT";

//certficate of the eclipese broker
extern const uint8_t server_cert_start[] asm("_binary_server_crt_start");
extern const uint8_t server_cert_end[] asm("_binary_server_crt_end");
extern const uint8_t client_cert_pem_start[] asm("_binary_client_crt_start");
extern const uint8_t client_cert_pem_end[] asm("_binary_client_crt_end");
extern const uint8_t client_key_pem_start[] asm("_binary_client_key_start");
extern const uint8_t client_key_pem_start[] asm("_binary_client_key_end");


esp_err_t extract_cn_and_verify_mac(char* certificate, uint8_t mac[6]) {
     mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);

    // Parse the certificate
    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)certificate, strlen(certificate) + 1);
    if (ret != 0) {
        mbedtls_x509_crt_free(&cert);
        return ESP_FAIL; // Parsing failed
    }

    const mbedtls_x509_name *name = &cert.subject;
    char cn_value[256] = {0}; // Buffer for CN value, assuming it won't exceed 255 characters

    while (name != NULL) {
        if ((name->oid.tag == MBEDTLS_ASN1_OID) &&
            (name->oid.len == MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) &&
            (memcmp(name->oid.p, MBEDTLS_OID_AT_CN, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) == 0)) {
            strncpy(cn_value, (const char *)name->val.p, name->val.len);
            cn_value[name->val.len] = '\0';
            break;
        }
        name = name->next;
    }

    // Verify if CN is in MAC format
    if (strlen(cn_value) == 17) {
        // Convert MAC address string to uint8_t array
        sscanf(cn_value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        mbedtls_x509_crt_free(&cert);
        return ESP_OK; // MAC address successfully extracted and stored
    } else {
        mbedtls_x509_crt_free(&cert);
        return ESP_FAIL; // CN is not in MAC format
    }
    
}


static void free_certificate_data(my_connection_data_pointer* cn){

  my_connection_data* curr= cn->certs;

  while(curr!=NULL){
    my_connection_data* temp=curr;
    curr=curr->next;
    if(temp->certificate!=NULL){
        free(temp->certificate);
    }
    free(temp);

  }
  free(cn);
  return;
}



static void log_error_if_nonzero(const char *message, int error_code)
{
    if (error_code != 0) {
        ESP_LOGE(TAG_mqtt, "Last error %s: 0x%x", message, error_code);
    }
}

static int mqtt_publish_message(esp_mqtt_client_handle_t client, char* message, char* topic, int qos){
  int msg_id;
  msg_id = esp_mqtt_client_publish(client, topic, message, 0, qos, 0);
  ESP_LOGI(TAG_mqtt, "sent publish successful, msg_id=%d", msg_id);
  return msg_id;
}




static char** mqtt_get_node_certificates(esp_mqtt_client_handle_t client, my_connection_data_pointer* result){

  int msg_id;
  //int msg_id = esp_mqtt_client_subscribe(client, "retrieve_certificates/#", 1);
  int i=0;
  int s=0;
  char curr_topic[]="retrieve_certificates/";
  while(result->end==false){
  printf("the current size of certs is %d\n", result->size);
  char buffer[100];
  snprintf(buffer, sizeof(buffer), "%s%d", curr_topic, s);
  printf("buffer is: %s\n",buffer);
  fflush(stdout);

  msg_id = esp_mqtt_client_subscribe(client, buffer, 1);
  ESP_LOGI(TAG_mqtt, "sent subscribe successful, msg_id=%d", msg_id);

 
  while(result->size==s && result->end==false){
    vTaskDelay(400/ portTICK_PERIOD_MS);
  }
  s++;
  }  
  
  printf("il numero di certificati retrieved è %d\n", result->size);
  fflush(stdout);

  printf("I have subscribed to %d certificate topics (considering the stopping one)\n", s);


  msg_id = esp_mqtt_client_unsubscribe(client, "retrieve_certificates/#");
  ESP_LOGI(TAG_mqtt, "sent unsubscribe successful, msg_id=%d", msg_id);
  return NULL;


}

static int mqtt_get_my_messages(esp_mqtt_client_handle_t client, char* topic){
  int msg_id = esp_mqtt_client_subscribe(client, topic, 1);
  ESP_LOGI(TAG_mqtt, "sent subscribe successful, msg_id=%d", msg_id);
  return msg_id;
}




static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{

    ESP_LOGD(TAG_mqtt, "Event dispatched from event loop base=%s, event_id=%" PRIi32 "", base, event_id);
    esp_mqtt_event_handle_t event = event_data;
    
    //esp_mqtt_client_handle_t client = event->client;
    int msg_id=-1000;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG_mqtt, "MQTT_EVENT_CONNECTED");
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG_mqtt, "MQTT_EVENT_DISCONNECTED");
        break;

    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG_mqtt, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        ESP_LOGI(TAG_mqtt, "sent publish successful, msg_id=%d", msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG_mqtt, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        //I have received the PubACK
        ESP_LOGI(TAG_mqtt, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG_mqtt, "MQTT_EVENT_DATA");
        char *topic = strndup(event->topic, event->topic_len);
        char *data = strndup(event->data, event->data_len);


        // TODO could be done better using regex
        if(strstr(topic, "retrieve_certificates/")!=NULL){
            my_connection_data_pointer* res=(my_connection_data_pointer*) handler_args;
            //printf("%s\n", data);
            //fflush(stdout);
            if(strcmp(data,"end_certificates")==0){
                res->end=true;

            }
            else{
                
                my_connection_data* curr_cert = (my_connection_data*) malloc(sizeof(my_connection_data));
                curr_cert->certificate= (char*) malloc(event->data_len+1);
                strncpy(curr_cert->certificate, data, event->data_len);
                curr_cert->certificate[event->data_len]='\0';

                
                uint8_t mac[6];
                if((extract_cn_and_verify_mac(curr_cert->certificate, mac)) == ESP_OK){
                    memcpy(curr_cert->MAC, mac, sizeof(curr_cert->MAC));
                }
                else{
                    memset(curr_cert->MAC, 0, sizeof(curr_cert->MAC));
                }


                
                curr_cert->next=NULL;

                if(res->certs==NULL){
                    res->certs=curr_cert;

                }else{        
                    my_connection_data* c=res->certs;
                    while(c->next!=NULL){
                        c=c->next;
                    }
                    c->next=curr_cert;
                }


                res->size=res->size+1;
            }
        }
        else{
            printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
            printf("DATA=%.*s\r\n", event->data_len, event->data);
        }

        free(topic);
        free(data);

        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG_mqtt, "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
            log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
            log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
            log_error_if_nonzero("captured as transport's socket errno",  event->error_handle->esp_transport_sock_errno);
            ESP_LOGI(TAG_mqtt, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));

        }
        break;
    default:
        ESP_LOGI(TAG_mqtt, "Other event id:%d", event->event_id);
        break;
    }
}





static esp_mqtt_client_handle_t mqtt_app_start(char* broker_url, QueueHandle_t queue, my_connection_data_pointer* result){

    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = broker_url,
        .broker.address.port = 8883,
        //.broker.verification.certificate=(const char *)server_cert_start, self signed certificate in this case
        .credentials = {
          .authentication = {
          .certificate = (const char *)client_cert_pem_start,
          .key = (const char *)client_key_pem_start,
          },
        }
    };

    bool value; 
 
    while(1){
    if(xQueueReceive(queue, &value, (TickType_t)5)){
        if(value==true){
        printf("mqtt could proceed, connection established and ip address received\n");
        fflush(stdout);
        break;
        }
    }

    vTaskDelay(400/ portTICK_PERIOD_MS);
    }
    

    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);

    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, (void*) result);
    esp_mqtt_client_start(client);
    
    return client;
}


static void disconnect_mqtt_client(esp_mqtt_client_handle_t client){

  ESP_ERROR_CHECK(esp_mqtt_client_stop(client));
  
  ESP_ERROR_CHECK(esp_mqtt_client_destroy(client));
  
  ESP_LOGI(TAG_mqtt, "MQTT client disconnected and deallocated");


} 



#endif
