#include <ykpiv/ykpiv.h>
#include "util.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include "piv_manager.h"
#include <sstream>
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

using namespace std;

int printf_ByteArray(const unsigned char *data, size_t len) {
  size_t i;
  int result = 0;
  for (i = 0; i < len; i++) {
    int y;
    int ch = data[i];
    static const char escapec[] = "\a\b\t\n\v\f\n\'\"\?\\";
    const char *p = strchr(escapec, ch);
    if (p && ch) {
      static const char escapev[] = "abtnvfn\'\"\?\\";
      y = printf("\\%c\n", escapev[p - escapec]);
    } else if (isprint(ch)) {
      y = printf("%c\n", ch);
    } else {
      // If at end of array, assume _next_ potential character is a '0'.
      int nch = i >= (len - 1) ? '0' : data[i + 1];
      if (ch < 8 && (nch < '0' || nch > '7')) {
        y = printf("\\%o\n", ch);
      } else if (!isxdigit(nch)) {
        y = printf("\\x%X\n", ch);
      } else {
        y = printf("\\o%03o\n", ch);
      }
    }
    if (y == EOF)
      return EOF;
    result += y;
  }
  return result;
}

int get_length(const unsigned char *buffer, int *len) {
  if(buffer[0] < 0x81) {
    *len = buffer[0];
    return 1;
  } else if((*buffer & 0x7f) == 1) {
    *len = buffer[1];
    return 2;
  } else if((*buffer & 0x7f) == 2) {
    *len = (buffer[1] << 8) + buffer[2];
    return 3;
  }
  return 0;
}

response extract_data_transfer_error(int sw) {
  response resp;
  resp.response_code = YKPIV_GENERIC_ERROR;

  std::ostringstream out_message;
  out_message << "Failed to generate new key (";
  switch(sw) {
    case SW_ERR_SECURITY_STATUS:
      out_message << "security status)";
      break;
    case SW_ERR_AUTH_BLOCKED:
      out_message << "authentication blocked)";
      break;
    case SW_ERR_INCORRECT_PARAM:
      out_message << "incorrect param)";
      break;
    case SW_ERR_INCORRECT_SLOT:
      out_message << "incorrect slot)";
      break;
    default:
      out_message << "error " << sw << ")";
  }

  resp.error_message = out_message.str();

  return resp;
}

void configure_access_policies(unsigned char pin_policy, unsigned char touch_policy, unsigned char in_data[], unsigned char *in_ptr) {
  if (pin_policy != YKPIV_PINPOLICY_DEFAULT) {
    in_data[1] += 3;
    *in_ptr++ = YKPIV_PINPOLICY_TAG;
    *in_ptr++ = 1;
    *in_ptr++ = pin_policy;
  }

  if (touch_policy != YKPIV_TOUCHPOLICY_DEFAULT) {
    in_data[1] += 3;
    *in_ptr++ = YKPIV_TOUCHPOLICY_TAG;
    *in_ptr++ = 1;
    *in_ptr++ = touch_policy;
  }
}

response generate_openssl_key(int key_format, unsigned char algorithm, unsigned char data[], unsigned long recv_len) {
  response resp;

  if(key_format == key_format_arg_PEM) {
    EC_KEY *eckey = NULL;
    EC_POINT *point = NULL;
    RSA *rsa = NULL;
    EVP_PKEY *public_key = EVP_PKEY_new();

    if(algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048) {
      unsigned char *data_ptr = data + 5;
      if(*data_ptr == 0x81) {
        rsa = RSA_new();
        int len = 0;
        data_ptr++;
        data_ptr += get_length(data_ptr, &len);

        BIGNUM *bignum_n = BN_bin2bn(data_ptr, len, NULL);
        if(bignum_n != NULL) {
          data_ptr += len;
          if(*data_ptr == 0x82) {
            data_ptr++;
            data_ptr += get_length(data_ptr, &len);
            BIGNUM *bignum_e = BN_bin2bn(data_ptr, len, NULL);
            if(bignum_e != NULL) {
              rsa->n = bignum_n;
              rsa->e = bignum_e;
              EVP_PKEY_set1_RSA(public_key, rsa);
            } else {
              resp.error_message = "Failed to parse public key exponent.";
              resp.response_code = YKPIV_GENERIC_ERROR;
            }
          } else {
            resp.error_message = "Failed to parse public key structure (2).";
            resp.response_code = YKPIV_GENERIC_ERROR;
          }
        } else {
          resp.error_message = "Failed to parse public key modulus.";
          resp.response_code = YKPIV_GENERIC_ERROR;
        }
      } else {
        resp.error_message = "Failed to parse public key structure.";
        resp.response_code = YKPIV_GENERIC_ERROR;
      }
    } else if(algorithm == YKPIV_ALGO_ECCP256 || algorithm == YKPIV_ALGO_ECCP384) {
      EC_GROUP *group;
      unsigned char *data_ptr = data + 3;
      int nid;
      size_t len;

      if(algorithm == YKPIV_ALGO_ECCP256) {
        nid = NID_X9_62_prime256v1;
        len = 65;
      } else {
        nid = NID_secp384r1;
        len = 97;
      }

      eckey = EC_KEY_new();
      group = EC_GROUP_new_by_curve_name(nid);
      EC_GROUP_set_asn1_flag(group, nid);
      EC_KEY_set_group(eckey, group);
      point = EC_POINT_new(group);

      if(*data_ptr++ == 0x86) {
        if (*data_ptr++ == len) {
          if(EC_POINT_oct2point(group, point, data_ptr, len, NULL) && EC_KEY_set_public_key(eckey, point)) {
            EVP_PKEY_set1_EC_KEY(public_key, eckey);
          } else {
            resp.error_message = "Failed to set the public key.";
            resp.response_code = YKPIV_GENERIC_ERROR;
          }
        } else {
          resp.error_message = "Unexepcted length.";
          resp.response_code = YKPIV_GENERIC_ERROR;
        }
      } else {
        resp.error_message = "Failed to parse public key structure.";
        resp.response_code = YKPIV_GENERIC_ERROR;
      }
    } else {
      resp.error_message = "Wrong algorithm.";
      resp.response_code = YKPIV_GENERIC_ERROR;
    }

    FILE * pFile;
    pFile = tmpfile();
    PEM_write_PUBKEY(pFile, public_key);

    fseek(pFile, 0, SEEK_END);
    size_t size = ftell(pFile);
    char* where = new char[size];
    rewind(pFile);
    fread(where, sizeof(char), size, pFile);
    resp.message = string(where);
    fclose(pFile);

    if(point) {
      EC_POINT_free(point);
    }
    if(eckey) {
      EC_KEY_free(eckey);
    }
    if(rsa) {
      RSA_free(rsa);
    }
    if(public_key) {
      EVP_PKEY_free(public_key);
    }

  } else {
    resp.error_message = "Only PEM is supported as public_key output.";
    resp.response_code = YKPIV_GENERIC_ERROR;
  }

  resp.success = resp.response_code == YKPIV_OK;

  return resp;
}
