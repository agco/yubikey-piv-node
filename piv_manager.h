#ifndef PIV_MANAGER_H
#define PIV_MANAGER_H

#include <node.h>
#include <string>
#include <ykpiv/ykpiv.h>

using namespace std;

struct response {
  ykpiv_rc response_code;
  string error_message;
  string message;
  bool success;
};

response verify_pin(const char *pin);
response list_readers();
response reset();
response change_puk(const char *current_puk, const char *new_puk);
response change_pin(const char *current_pin, const char *new_pin);
response version();
response set_management_key(const char *current_mgm_key, const char *new_mgm_key);
response generate_key(const char *mgm_key, const char *slot, unsigned char algorithm, const char *key_format);
#endif
