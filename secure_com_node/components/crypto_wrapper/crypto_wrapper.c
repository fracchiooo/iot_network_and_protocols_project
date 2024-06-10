#include "crypto_wrapper.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"
#include <string.h>





static const char * TAG = "CRYPTO_WRAPPER";

void init_rng(mbedtls_ctr_drbg_context * ctr_drbg) {
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    char * personalization = "esp32_crypto_wrapper_component";

    mbedtls_ctr_drbg_init(ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, &entropy,
          (const unsigned char *) personalization,
          strlen(personalization));

    if (ret != 0) {
        ESP_LOGE(TAG, "failed to init rng");
    }
}

void base64stringcat(char * strings[], size_t n_of_strings, char * buffer, size_t buffer_size) {

    int buffer_used = 0;
    strcpy(buffer, strings[0]);
    for (int i = 1; i < n_of_strings && buffer_used < buffer_size; i++) {
        unsigned char b64[80];
        size_t outlen;
        strcat(buffer, ":");
        mbedtls_base64_encode(b64, 80, &outlen, (const unsigned char *)strings[i], strlen(strings[i]));
        strcat((char*)b64, strings[i]);
        buffer_used += strlen(strings[i])+1;
    }
}

void base64cat_decode(char * in_string, char * out_strings[], size_t n_strings, size_t string_size) {
  int last_dot = 0, j = 0, outlen = 0;
  char * buffer = (char *) calloc(256, sizeof(char));
  char * dec_buffer = (char *) calloc(256, sizeof(char));
  for (int i = 0; i < strlen(in_string) && j < n_strings; i++) {
    if (in_string[i] == ':') {
      strncpy(buffer, in_string + last_dot, (strlen(in_string) - 1) - last_dot);
      last_dot = i+1;
      mbedtls_base64_decode(out_strings[j], string_size, &outlen, (const unsigned char *)buffer, strlen(buffer));
      j++;
    }
  }
  strncpy(buffer, in_string + last_dot, (strlen(in_string) - 1) - last_dot);
  last_dot = i+1;
  mbedtls_base64_decode(out_strings[j], string_size, &outlen, (const unsigned char *)buffer, strlen(buffer));

  free(dec_buffer);
  free(buffer);
}

void construct_conn_init_message(mbedtls_ctr_drbg_context *rng, char * out_string, size_t out_string_size) {
  char * nonce_buffer = (char *) calloc(NONCE_SIZE, sizeof(char));
  size_t nonce_size = NONCE_SIZE;

  char * AES_key[32];

  give_me_a_nonce(rng, nonce_buffer, nonce_size);

  // This is our AES key. Yes, this is what the documentation says
  int ret = mbedtls_ctr_drbg_random(rng, AES_key, 32);
  if (ret != 0 ) {
    ESP_LOGE(TAG, "Failed to generate key");
  }

  // What do we need? A cert, B's MAC and a key signed with B's pubkey
  char * values[] = {"CONN_REQUEST", CERT_A, "0", nonce_buffer, MAC_B, KEY_SIGNED_WITH_B_KEY};
}

void give_me_a_nonce(mbedtls_ctr_drbg_context * ctr_drbg, unsigned char * nonce_buffer, size_t nonce_size) {
    mbedtls_ctr_drbg_random(ctr_drbg, nonce_buffer, nonce_size);
}


void print_rsa_key(mbedtls_rsa_context pk, int k){
    unsigned char* buffer=(unsigned char*) malloc(sizeof(unsigned char)*16000);
    int ret;
    if(k==1) ret= mbedtls_pk_write_pubkey_pem(&pk, buffer, 16000-1);
    else ret= mbedtls_pk_write_key_pem(&pk, buffer, 16000-1);
    if(ret!=0){
        printf("Failed to write public key in PEM format\n");
        fflush(stdout);
        return;
    }
    

    buffer[16000-1]='\0';
    printf("the key is: \n%s\n", buffer);
    free(buffer);


}

void print_exadecimal(const unsigned char* buff, size_t size){
    for(int i=0; i<size; ++i){
        printf("%02x", buff[i]);
    }
    printf("\n");
}


void print_key(mbedtls_pk_context pk, int k){
    unsigned char* buffer=(unsigned char*) malloc(sizeof(unsigned char)*16000);
    int ret;
    if(k==1) ret= mbedtls_pk_write_pubkey_pem(&pk, buffer, 16000-1);
    else ret= mbedtls_pk_write_key_pem(&pk, buffer, 16000-1);
    if(ret!=0){
        printf("Failed to write public key in PEM format\n");
        fflush(stdout);
        return;
    }
    buffer[16000-1]='\0';
    printf("the key is: \n%s\n", buffer);
    free(buffer);
}



mbedtls_x509_crt parse_certificate(char* certificate){
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)certificate, strlen(certificate) + 1);
    if (ret != 0) {
        mbedtls_x509_crt_free(&cert);
        printf("failed to parse!\n");
    }
    return cert;
}


void digital_sign_pem(const unsigned char* message, mbedtls_pk_context pub_k, mbedtls_pk_context pk, size_t* signature_len, unsigned char* sig){

    printf("starting digital signature process\n");
    fflush(stdout);

    //TODO da eliminare forse

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    const char* pers= "mbedtls_pk_sign\0";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret= mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*) pers, strlen(pers));
    if(ret!=0){
        printf("mbedtls drbg seed error\n");
        return;
    }

    unsigned char hash[32];

    ret= mbedtls_md(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        message, strlen((char*) message), hash
    );
    print_exadecimal(hash, 32);

    if(ret!=0){
        printf("error in hashing the message for dig. signature\n");
        return;
    }

    size_t sig_len;

    ret= mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, MBEDTLS_PK_SIGNATURE_MAX_SIZE ,&sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    if(ret!=0){
        printf("error in signin the hashed message, message code: %d\n", ret);
        return;

    }

    printf("generated siganture:\n");

    print_exadecimal(sig, MBEDTLS_PK_SIGNATURE_MAX_SIZE);
    *signature_len= sig_len;
}


bool verify_signature(unsigned char* message, mbedtls_pk_context* pub_k, unsigned char* signature, size_t sig_len){
    printf("let's verify it..., the signature length is%d\n", sig_len);
    fflush(stdout);

    unsigned char hash[32];

    int ret= mbedtls_md(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        message, strlen((char*) message), hash
    );
    print_exadecimal(hash, 32);
    if(ret!=0){
        printf("error in hashing the message for dig. signature\n");
        return false;
    }

    ret= mbedtls_pk_verify(pub_k, MBEDTLS_MD_SHA256, hash, 32, signature, sig_len);
    if(ret!=0){
        char buf[1024];
        mbedtls_strerror(ret, buf, sizeof(buf));
        printf("error in verify signature: %s\n", buf);
        return false;
    }
    return true;
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
        //mbedtls_x509_crt_free(&cert);
        return ESP_OK; // MAC address successfully extracted and stored
    } else {
        //mbedtls_x509_crt_free(&cert);
        return ESP_FAIL; // CN is not in MAC format
    }
    
}



void free_certificate_data(my_connection_data_pointer* cn){
  my_connection_data* curr= cn->certs;
  while(curr!=NULL){
    my_connection_data* temp=curr;
    curr=curr->next;
    mbedtls_x509_crt_free(&(temp->certificate));
    free(temp);
  }
  free(cn);
  return;
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
        strlen((const char*)client_key_pem_start)+1, NULL, 0, NULL, 0
        );
        if(ret!=0){
            printf("error in parsing local private key\n");
            mbedtls_pk_free(&pk);
        }


    }
    print_key(pk, 0);

    return pk;
}

mbedtls_pk_context* get_pub_key_from_cert(mbedtls_x509_crt cert){

    mbedtls_pk_context* pk=&cert.pk;
    printf("breakpoint 11\n");
    print_key(*pk, 1);
    fflush(stdout);

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
            //memcpy(&(curr_cert->certificate), &cert, sizeof(cert));
            //mbedtls_x509_crt_free(&cert);
            curr_cert->certificate=cert;

            //print the certificate





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


void print_certificates(my_connection_data_pointer* cp){

  my_connection_data* curr= cp->certs;
  char buf[1200];
  while(curr!=NULL){
    memset(buf, 0, sizeof(buf));
    printf("\n----------------------------------\n");
    mbedtls_x509_crt_info(buf, sizeof(buf)-1, "", &curr->certificate);
    buf[sizeof(buf)-1]='\0';

    printf("%s\n", buf);
    fflush(stdout);


    printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",curr->MAC[0],curr->MAC[1],curr->MAC[2],curr->MAC[3],curr->MAC[4],curr->MAC[5]);


    mbedtls_x509_crt *certificate = &(curr->certificate);  // Assuming curr is a pointer to a structure containing the certificate
    char buf[1200];
    memset(buf, 0, sizeof(buf));
    mbedtls_x509_crt_info(buf, sizeof(buf)-1, "", certificate);
    buf[sizeof(buf)-1]='\0';
    printf("%s\n", buf);
    fflush(stdout);

    fflush(stdout);

    

    printf("\n----------------------\n");
    fflush(stdout);


    curr=curr->next;
  }


}