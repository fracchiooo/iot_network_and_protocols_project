#ifndef MQTT_WRAPPER_H
#define MQTT_WRAPPER_H
#include "mqtt_client.h"
#include <string.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include "esp_err.h"
#include "mbedtls/ctr_drbg.h"

#define max_mess_size 4096


typedef struct my_connection_data{

    uint8_t MAC[6];
    mbedtls_x509_crt certificate;
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
extern const uint8_t client_key_pem_end[] asm("_binary_client_key_end");


void print_sha256_hash(const unsigned char hash[32]){
    for(int i=0; i<32; ++i){
        printf("%02x", hash[i]);
    }
    printf("\n");
}




unsigned char* digital_sign_pem(const unsigned char* message, mbedtls_pk_context pub_k, mbedtls_pk_context pk, size_t* signature_len){

    printf("starting digital signature process\n");
    fflush(stdout);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const char* pers= "mbedtls_pk_sign\0";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret= mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*) pers, strlen(pers));
    if(ret!=0){
        printf("mbedtls drbg seed error\n");
        return NULL;
    }

    unsigned char hash[32];

    ret= mbedtls_md(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        message, strlen((char*) message), hash
    );
    print_sha256_hash(hash);

    if(ret!=0){
        printf("error in hashing the message for dig. signature\n");
        return NULL;
    }

    unsigned char* sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t sig_len;

    ret= mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, MBEDTLS_PK_SIGNATURE_MAX_SIZE ,&sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    if(ret!=0){
        printf("error in signin the hashed message, message code: %d\n", ret);
        return NULL;

    }

    printf("generated siganture!\n");


    //TODO
    //mbedtls_entropy_free(&entropy);
    //mbedtls_ctr_drbg_free(&ctr_drbg);

    *signature_len= sig_len;
    return sig;
}


bool verify_signature(unsigned char* message, mbedtls_pk_context* pub_k, unsigned char* signature, size_t sig_len){
    printf("let's verify it..., the signature length is%d\n", sig_len);
    fflush(stdout);


    unsigned char hash[32];

    int ret= mbedtls_md(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        message, strlen((char*) message), hash
    );
    print_sha256_hash(hash);
    if(ret!=0){
        printf("error in hashing the message for dig. signature\n");
        return false;
    }



    ret= mbedtls_pk_verify(pub_k, MBEDTLS_MD_SHA256, hash, 32, signature, sig_len);
    if(ret!=0){
        printf("error in verifying the signature, the code is %d\n", ret);
        return false;
    }
    return true;
}




mbedtls_x509_crt parse_certificate(char* certificate){
    //printf("%s\n", certificate);
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    // Parse the certificate
    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)certificate, strlen(certificate) + 1);
    if (ret != 0) {
        mbedtls_x509_crt_free(&cert);
        printf("failed to parse!\n");
    }
    return cert;

}


esp_err_t extract_cn_and_verify_mac(mbedtls_x509_crt cert, uint8_t mac[6]) {

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
    //mbedtls_x509_crt_free(&(temp->certificate));
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




mbedtls_pk_context get_local_private_key(){

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    printf("the private key is (in char*):\n %s\n", client_key_pem_start);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const char* pers= "mbedtls_pk_sign";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret= mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*) pers, strlen(pers));
    if(ret!=0){
        printf("mbedtls drbg seed error\n");
        mbedtls_pk_free(&pk);
    }
    else {
        ret= mbedtls_pk_parse_key(&pk, (const unsigned char*) client_key_pem_start, 
        strlen((const char*)client_key_pem_start)+1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg
        );
        if(ret!=0){
            printf("error in parsing local private key\n");
            mbedtls_pk_free(&pk);
        }


    }


    return pk;
}

mbedtls_pk_context* get_pub_key_from_cert(mbedtls_x509_crt cert){
    mbedtls_pk_context *pk = &cert.pk;

    //unsigned char buffer[4096];
    unsigned char* buffer=(unsigned char*) malloc(sizeof(unsigned char)*16000);
    //memset(buffer, 0, 16000);
    int ret= mbedtls_pk_write_pubkey_pem(pk, buffer, 16000);
    if(ret!=0){
        printf("Failed to write public key in PEM format\n");
        abort();
        return NULL;
    }
    
    /*if (!mbedtls_pk_can_do(pk, MBEDTLS_PK_RSA)) {
        printf("The key in the certificate is not an RSA key\n");
        return NULL;
    }
    unsigned char buffer[4096];
    int ret = mbedtls_pk_write_pubkey_pem(pk, buffer, sizeof(buffer)-1);
    if (ret != 0) {
        printf("Failed to write public key in PEM format\n");
        return NULL;
    }*/
    buffer[16000 - 1] = '\0'; 
    printf("Public key: \n%s\n", buffer);
    free(buffer);
    return pk;
}


my_connection_data_pointer* mqtt_get_node_certificates(esp_mqtt_client_handle_t client, char* message){

    my_connection_data_pointer* result=(my_connection_data_pointer*) malloc(sizeof(my_connection_data_pointer));
    result->size=0;
    result->end=false;
    result->certs=NULL;

    int msg_id;
    char* mess=message;
    int s=0;
    char base_topic[]="retrieve_certificates/";

    //subscribe to the anchor topic
    char curr_topic[100];
    snprintf(curr_topic, sizeof(curr_topic), "%s%d", base_topic, s);
    msg_id = esp_mqtt_client_subscribe(client, curr_topic, 1);



    while(strcmp(message, "reply_cert_end")!=0){
        if(strstr(message, "reply_cert")!=NULL){
            mess=message;
            my_connection_data* curr_cert = (my_connection_data*) malloc(sizeof(my_connection_data));
            mess=mess+strlen("reply_cert");
            size_t data_len= strlen(mess);
            //create the certificate from mess and data_len
            char char_certificate[data_len+1];
            strncpy(char_certificate, mess, data_len);
            char_certificate[data_len]='\0';
            mbedtls_x509_crt cert=parse_certificate(char_certificate);
            curr_cert->certificate=cert;
            //extract the mac vlue from certificate || 0s
            uint8_t mac[6];
            if((extract_cn_and_verify_mac(curr_cert->certificate, mac)) == ESP_OK){
                memcpy(curr_cert->MAC, mac, sizeof(curr_cert->MAC));
            }
            else{
                memset(curr_cert->MAC, 0, sizeof(curr_cert->MAC));
            }

            // adds the certificate to the linked list of certificates structure
            curr_cert->next=NULL;
            if(result->certs==NULL){
                result->certs=curr_cert;
            }else{        
                my_connection_data* c=result->certs;
                while(c->next!=NULL){
                    c=c->next;
                }
                c->next=curr_cert;
            }
            result->size=result->size+1;

            //clear the message
            memset(mess, 0, max_mess_size);
            s++;
            snprintf(curr_topic, sizeof(curr_topic), "%s%d", base_topic, s);
            printf("the new subscribed topic is: %s\n", curr_topic);
            fflush(stdout);
            msg_id = esp_mqtt_client_subscribe(client, curr_topic, 1);

        }

        vTaskDelay(400/ portTICK_PERIOD_MS);

    }

    printf("il numero di certificati retrieved è %d\n", result->size);
    fflush(stdout);

    msg_id = esp_mqtt_client_unsubscribe(client, "retrieve_certificates/#");
    ESP_LOGI(TAG_mqtt, "sent unsubscribe successful, msg_id=%d", msg_id);
    return result;
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
        char* ret_mess= (char*) handler_args;
        memset(ret_mess, 0, max_mess_size);

        char *topic = strndup(event->topic, event->topic_len);
        char *data = strndup(event->data, event->data_len);

        char* tmp=ret_mess;
        // TODO could be done better using regex
        if(strstr(topic, "retrieve_certificates/")!=NULL){
            if(strcmp(data,"end_certificates")==0){
                strcpy(tmp,"reply_cert_end");
            }
            else{
                strcpy(tmp,"reply_cert");
                tmp=tmp+strlen("reply_cert");
                strcpy(tmp,data);
            } 
            printf("the mess which is now written by callback: %s\n", tmp);
            fflush(stdout);
                
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





static esp_mqtt_client_handle_t mqtt_app_start(char* broker_url, QueueHandle_t queue, char* mess){

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
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, (void*) mess);
    esp_mqtt_client_start(client);
    
    return client;
}


static void disconnect_mqtt_client(esp_mqtt_client_handle_t client){

  ESP_ERROR_CHECK(esp_mqtt_client_stop(client));
  
  ESP_ERROR_CHECK(esp_mqtt_client_destroy(client));
  
  ESP_LOGI(TAG_mqtt, "MQTT client disconnected and deallocated");


} 



#endif
