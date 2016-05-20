#ifndef UTIL_H
#define UTIL_H

#include <ykpiv/ykpiv.h>
#include "piv_manager.h"

int printf_ByteArray(const unsigned char *data, size_t len);
response extract_data_transfer_error(int sw);
void configure_access_policies(unsigned char pin_policy, unsigned char touch_policy, unsigned char in_data[], unsigned char *in_ptr);
response generate_openssl_key(int key_format, unsigned char algorithm, unsigned char data[], unsigned long recv_len);
#endif
