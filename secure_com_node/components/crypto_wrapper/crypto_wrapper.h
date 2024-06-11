#include <string.h>
#include <stdlib.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_log.h"
#include "mqtt_wrapper.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

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


#define NONCE_SIZE 16

void init_rng(mbedtls_ctr_drbg_context * ctr_drbg);

void give_me_a_nonce(mbedtls_ctr_drbg_context * ctr_drbg, unsigned char * nonce_buffer, size_t nonce_size);

void base64stringcat(char * strings[], size_t n_of_strings, char * buffer, size_t buffer_size);

my_connection_data_pointer* mqtt_get_node_certificates(esp_mqtt_client_handle_t client, char* message);

mbedtls_pk_context* get_pub_key_from_cert(mbedtls_x509_crt cert);

mbedtls_pk_context get_local_private_key();

void free_certificate_data(my_connection_data_pointer* cn);

esp_err_t extract_cn_and_verify_mac(mbedtls_x509_crt cert, uint8_t mac[6]);

bool verify_signature(unsigned char* message, mbedtls_pk_context* pub_k, unsigned char* signature, size_t sig_len);

void digital_sign_pem(const unsigned char* message, mbedtls_pk_context pk, size_t* signature_len, unsigned char* sig);

mbedtls_x509_crt parse_certificate(char* certificate);

void print_key(mbedtls_pk_context pk, int k);

void print_certificates(my_connection_data_pointer* cp);

void base64cat_decode(char * in_string, char * out_strings[], size_t n_strings, size_t string_size);

void construct_conn_init_message(mbedtls_ctr_drbg_context *rng, char * out_string, size_t out_string_size, mbedtls_pk_context pka, mbedtls_pk_context pub_kb, uint8_t mac_a, uint8_t mac_b);

void construct_conn_reply_message(mbedtls_ctr_drbg_context *rng, char * out_string, size_t out_string_size, mbedtls_pk_context pka, mbedtls_pk_context pub_kb, char * old_nonce, uint8_t mac_a, uint8_t mac_b);

void construct_nonce_signed(mbedtls_pk_context pka, uint8_t mac_a, char * nonce1, char * nonce2);
