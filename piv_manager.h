#ifndef PIV_MANAGER_H
#define PIV_MANAGER_H

#include <string>
#include <ykpiv/ykpiv.h>

#ifndef SW_SUCCESS
#define SW_SUCCESS 0x9000
#endif

#ifndef YKPIV_INS_GENERATE_ASYMMETRIC
#define YKPIV_INS_GENERATE_ASYMMETRIC 0x47
#endif

#ifndef YKPIV_ALGO_TAG
#define YKPIV_ALGO_TAG 0x80
#endif

#ifndef SW_ERR_SECURITY_STATUS
#define SW_ERR_SECURITY_STATUS 0x6982
#endif

#ifndef SW_ERR_AUTH_BLOCKED
#define SW_ERR_AUTH_BLOCKED 0x6983
#endif

#ifndef SW_ERR_INCORRECT_PARAM
#define SW_ERR_INCORRECT_PARAM 0x6a80
#endif

#ifndef SW_ERR_INCORRECT_SLOT
#define SW_ERR_INCORRECT_SLOT 0x6b00
#endif

using namespace std;

struct response {
  ykpiv_rc response_code;
  string error_message;
  string message;
  bool success;
};

enum enum_key_format {
  key_format_arg_PEM = 0,
  key_format_arg_PKCS12 = 1,
  key_format_arg_GZIP = 2,
  key_format_arg_DER = 3
};

enum enum_hash {
  hash_arg_SHA1 = 0,
  hash_arg_SHA256 = 1,
  hash_arg_SHA384 = 2,
  hash_arg_SHA512 =3
};

static unsigned const char sha1oid[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
  0x04, 0x14
};

static unsigned const char sha256oid[] = {
  0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static unsigned const char sha384oid[] = {
  0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};

static unsigned const char sha512oid[] = {
  0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

response verify_pin(const char *pin);
response list_readers();
response reset();
response change_puk(const char *current_puk, const char *new_puk);
response change_pin(const char *current_pin, const char *new_pin);
response version();
response set_management_key(const char *current_mgm_key, const char *new_mgm_key);
response generate_key(const char *mgm_key, const char *slot, unsigned char algorithm, unsigned char pin_policy, unsigned char touch_policy, int key_format);
response generate_request(const char *mgm_key, const char *slot, int hash, const char *subject, char *public_key);
response import_certificate(const char *mgm_key, const char *slot, int cert_format, char *password, char *certificate);
response get_status();
response read_slot(const char *slot, int hash);
#endif
