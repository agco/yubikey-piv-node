#ifndef UTIL_H
#define UTIL_H

#include <ykpiv/ykpiv.h>
#include "piv_manager.h"
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

int printf_ByteArray(const unsigned char *data, size_t len);
response extract_data_transfer_error(int sw);
void configure_access_policies(unsigned char pin_policy, unsigned char touch_policy, unsigned char in_data[], unsigned char *in_ptr);
response generate_openssl_key(int key_format, unsigned char algorithm, unsigned char data[], unsigned long recv_len);
response generate_certificate_request(ykpiv_state *piv_state, FILE *input_file, int hash, const char *slot, const char *subject);
response import_certificate(ykpiv_state *piv_state, const char *slot, int cert_format, char *password, FILE *input_file);
const EVP_MD *get_hash(int hash, const unsigned char **oid, size_t *oid_len);
void dump_data(const unsigned char *buf, unsigned int len, FILE *output, bool space);
response print_cert_info(ykpiv_state *state, const char *slot, const EVP_MD *md);
string file_to_str(FILE *pFile);
int get_object_id(int slot);
int get_length(const unsigned char *buffer, int *len);
unsigned char get_algorithm(EVP_PKEY *key);
bool set_component(unsigned char *in_ptr, const BIGNUM *bn, int element_len);
response import_key(ykpiv_state *state, int key_format, const char *key_param, const char *slot, char *password, unsigned char pin_policy, unsigned char touch_policy);
#endif
