#include <stdio.h>
#include <string>
#include <cstring>
#include <list>
#include <sstream>
#include <ykpiv/ykpiv.h>
#include "piv_manager.h"
#include "util.h"
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

#define KEY_LEN 24

const std::string reader = "Yubikey";
size_t reader_size = sizeof(reader);
ykpiv_state *piv_state = NULL;

response start() {
  struct response resp;

  int verbosity = 0;
  ykpiv_rc res = ykpiv_init(&piv_state, verbosity);

  if(res == YKPIV_OK) {
    res = ykpiv_connect(piv_state, reader.c_str());
    if (res != YKPIV_OK) {
      resp.error_message = "Failed to connect to device.";
    }
  } else {
    resp.error_message = "Failed to connect to card reader.";
  }

  resp.response_code = res;

  return resp;
}

void stop() {
  ykpiv_done(piv_state);
}

response authenticate(const char *key_ptr) {

  struct response resp;
  unsigned char key[KEY_LEN];
  size_t key_len = sizeof(key);

  resp.response_code = ykpiv_hex_decode(key_ptr, strlen(key_ptr), key, &key_len);

  if(resp.response_code != YKPIV_OK) {
    resp.error_message = "Failed decoding key!";
  } else {
    resp.response_code = ykpiv_authenticate(piv_state, key);
    if(resp.response_code != YKPIV_OK) {
      resp.error_message = "Failed authentication with the application.";
    }
  }

  resp.success = resp.response_code == YKPIV_OK;

  return resp;
}

// -----------------------------------------------------

response list_readers() {

  struct response resp = start();

  if (resp.response_code == YKPIV_OK) {
    char readers[2048];
    size_t len = sizeof(readers);

    ykpiv_list_readers(piv_state, readers, &len);

    char *reader_ptr;
    resp.message = "";
    for(reader_ptr = readers; *reader_ptr != '\0'; reader_ptr += std::strlen(reader_ptr) + 1) {
      resp.message += reader_ptr;
      resp.message += "\n";
    }
  }

  resp.success = resp.response_code == YKPIV_OK;
  stop();

  return resp;
}

response verify_pin(const char *pin) {
  struct response resp = start();

  if (resp.response_code == YKPIV_OK) {
    std::ostringstream out_message;
    int tries = -1;
    resp.response_code = ykpiv_verify(piv_state, pin, &tries);

    if(resp.response_code == YKPIV_WRONG_PIN) {
      if(tries > 0) {
        out_message << "Pin verification failed, " << tries << " tries left before pin is blocked";
      } else {
        out_message << "Pin code blocked, use unblock-pin action to unblock";
      }
    } else if (resp.response_code != YKPIV_OK) {
      out_message << "Pin code verification failed: " <<  ykpiv_strerror(resp.response_code);
    }
    resp.error_message = out_message.str();
  }

  resp.success = resp.response_code == YKPIV_OK;
  stop();

  return resp;
}

response reset() {
  struct response resp = start();

  if (resp.response_code == YKPIV_OK) {
    unsigned char templ[] = {0, YKPIV_INS_RESET, 0, 0};
    unsigned char data[0xff];
    unsigned long recv_len = sizeof(data);
    int sw;

    resp.response_code = ykpiv_transfer_data(piv_state, templ, NULL, 0, data, &recv_len, &sw);
    if (resp.response_code != YKPIV_OK) {
      resp.error_message = std::string(ykpiv_strerror(resp.response_code));
    } else if (sw != SW_SUCCESS) {
      std::ostringstream out_message;
      out_message << "Impossible to reset, SW code: " << sw;
      resp.response_code = YKPIV_GENERIC_ERROR;
      resp.error_message = out_message.str();
    }
  }

  resp.success = resp.response_code == YKPIV_OK;
  stop();

  return resp;
}

response change_puk(const char *current_puk, const char *new_puk) {

  struct response resp = start();

  if (resp.response_code == YKPIV_OK) {
    int tries = -1;
    resp.response_code = ykpiv_change_puk(piv_state, current_puk, strlen(current_puk), new_puk, strlen(new_puk), &tries);
    std::ostringstream out_message;
    if(resp.response_code == YKPIV_WRONG_PIN) {
        out_message << "Puk verification failed, " << tries << " tries left before device is blocked";
    } else if (resp.response_code == YKPIV_PIN_LOCKED) {
      out_message << "Puk code blocked, reset your device";
    } else if (resp.response_code != YKPIV_OK) {
      out_message << "Puk code verification failed: " <<  resp.response_code;
    }

    resp.error_message = out_message.str();
  }

  resp.success = resp.response_code == YKPIV_OK;
  stop();

  return resp;
}

response change_pin(const char *current_pin, const char *new_pin) {

  struct response resp = start();

  if (resp.response_code == YKPIV_OK) {
    int tries = -1;
    resp.response_code = ykpiv_change_pin(piv_state, current_pin, strlen(current_pin), new_pin, strlen(new_pin), &tries);
    std::ostringstream out_message;
    if(resp.response_code == YKPIV_WRONG_PIN) {
      out_message << "Pin verification failed, " << tries << " tries left before device is blocked";
    } else if (resp.response_code == YKPIV_PIN_LOCKED) {
      out_message << "Pin code blocked, use unblock-pin action to unblock";
    } else if (resp.response_code != YKPIV_OK) {
      out_message << "Pin code verification failed: " <<  ykpiv_strerror(resp.response_code);
    }

    resp.error_message = out_message.str();
  }

  resp.success = resp.response_code == YKPIV_OK;
  stop();

  return resp;
}

response version() {
  struct response resp = start();

  if (resp.response_code == YKPIV_OK) {
    char version[7];
    resp.response_code = ykpiv_get_version(piv_state, version, sizeof(version));
    if(resp.response_code == YKPIV_OK) {
      resp.message = version;
    } else {
      resp.error_message = "Failed to retrieve application version.";
    }
  }
  resp.success = resp.response_code == YKPIV_OK;
  stop();

  return resp;
}

response set_management_key(const char *current_mgm_key, const char *new_mgm_key) {

  struct response resp = start();

  if (resp.response_code == YKPIV_OK) {
    if (strlen(new_mgm_key) == (KEY_LEN * 2)) {

      resp = authenticate(current_mgm_key);
      if (resp.success) {
        unsigned char new_key[KEY_LEN];
        size_t new_key_len = sizeof(new_key);

        resp.response_code = ykpiv_hex_decode(new_mgm_key, strlen(new_mgm_key), new_key, &new_key_len);
        if(resp.response_code != YKPIV_OK) {
          resp.error_message = "Failed decoding new key!";
        } else {
          resp.response_code = ykpiv_set_mgmkey2(piv_state, new_key, 0);
          if(resp.response_code != YKPIV_OK) {
            resp.error_message = "Failed setting the new key!";
          }
        }
      }
    } else {
      resp.response_code = YKPIV_KEY_ERROR;
      std::ostringstream out_message;
      out_message << "The new management key has to be exactly " << KEY_LEN * 2 << " character.";
      resp.error_message = out_message.str();
    }
  }

  resp.success = resp.response_code == YKPIV_OK;
  stop();

  return resp;
}

response generate_key(const char *mgm_key, const char *slot, unsigned char algorithm, const char *key_format) {
  struct response resp = start();

  if (resp.response_code == YKPIV_OK) {
    unsigned char in_data[11];
    unsigned char *in_ptr = in_data;
    unsigned char data[1024];
    unsigned char templ[] = {0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0};
    unsigned long recv_len = sizeof(data);
    int sw;
    int key = 0;
    // EVP_PKEY *public_key = NULL;
    // RSA *rsa = NULL;
    // BIGNUM *bignum_n = NULL;
    // BIGNUM *bignum_e = NULL;
    // EC_KEY *eckey = NULL;
    // EC_POINT *point = NULL;

    sscanf(slot, "%2x", &key);
    templ[3] = key;

    *in_ptr++ = 0xac;
    *in_ptr++ = 3;
    *in_ptr++ = YKPIV_ALGO_TAG;
    *in_ptr++ = 1;
    *in_ptr++ = algorithm;
    if(in_data[4] == 0) {
      fprintf(stderr, "Unexpected algorithm.\n");
    }
    // if(pin_policy != pin_policy__NULL) {
    //   in_data[1] += 3;
    //   *in_ptr++ = YKPIV_PINPOLICY_TAG;
    //   *in_ptr++ = 1;
    //   *in_ptr++ = get_pin_policy(pin_policy);
    // }
    // TODO: take a look on touch policies
    resp.response_code = ykpiv_transfer_data(piv_state, templ, in_data, in_ptr - in_data, data, &recv_len, &sw);

    if(resp.response_code != YKPIV_OK) {
      resp.error_message = "Failed to communicate.";
    } else if(sw != SW_SUCCESS) {
      resp.response_code = YKPIV_GENERIC_ERROR;

      std::ostringstream out_message;
      out_message << "Failed to generate new key (";
      if(sw == SW_ERR_INCORRECT_SLOT) {
        out_message << "slot not supported?)";
      } else if(sw == SW_ERR_INCORRECT_PARAM) {
          out_message << "algorithm not supported?)";
      } else {
        out_message << "error " << sw << ")";
      }
      resp.error_message = out_message.str();
    }

    // if(key_format == key_format_arg_PEM) {
    //   public_key = EVP_PKEY_new();
    //   if(algorithm == algorithm_arg_RSA1024 || algorithm == algorithm_arg_RSA2048) {
    //     unsigned char *data_ptr = data + 5;
    //     int len = 0;
    //     rsa = RSA_new();
    //
    //     if(*data_ptr != 0x81) {
    //       fprintf(stderr, "Failed to parse public key structure.\n");
    //       goto generate_out;
    //     }
    //     data_ptr++;
    //     data_ptr += get_length(data_ptr, &len);
    //     bignum_n = BN_bin2bn(data_ptr, len, NULL);
    //     if(bignum_n == NULL) {
    //       fprintf(stderr, "Failed to parse public key modulus.\n");
    //       goto generate_out;
    //     }
    //     data_ptr += len;
    //
    //     if(*data_ptr != 0x82) {
    //       fprintf(stderr, "Failed to parse public key structure (2).\n");
    //       goto generate_out;
    //     }
    //     data_ptr++;
    //     data_ptr += get_length(data_ptr, &len);
    //     bignum_e = BN_bin2bn(data_ptr, len, NULL);
    //     if(bignum_e == NULL) {
    //       fprintf(stderr, "Failed to parse public key exponent.\n");
    //       goto generate_out;
    //     }
    //
    //     rsa->n = bignum_n;
    //     rsa->e = bignum_e;
    //     EVP_PKEY_set1_RSA(public_key, rsa);
    //   } else if(algorithm == algorithm_arg_ECCP256 || algorithm == algorithm_arg_ECCP384) {
    //     EC_GROUP *group;
    //     unsigned char *data_ptr = data + 3;
    //     int nid;
    //     size_t len;
    //
    //     if(algorithm == algorithm_arg_ECCP256) {
    //       nid = NID_X9_62_prime256v1;
    //       len = 65;
    //     } else {
    //       nid = NID_secp384r1;
    //       len = 97;
    //     }
    //
    //     eckey = EC_KEY_new();
    //     group = EC_GROUP_new_by_curve_name(nid);
    //     EC_GROUP_set_asn1_flag(group, nid);
    //     EC_KEY_set_group(eckey, group);
    //     point = EC_POINT_new(group);
    //     if(*data_ptr++ != 0x86) {
    //       fprintf(stderr, "Failed to parse public key structure.\n");
    //       goto generate_out;
    //     }
    //     if(*data_ptr++ != len) { /* the curve point should always be 65 bytes */
    //       fprintf(stderr, "Unexpected length.\n");
    //       goto generate_out;
    //     }
    //     if(!EC_POINT_oct2point(group, point, data_ptr, len, NULL)) {
    //       fprintf(stderr, "Failed to load public point.\n");
    //       goto generate_out;
    //     }
    //     if(!EC_KEY_set_public_key(eckey, point)) {
    //       fprintf(stderr, "Failed to set the public key.\n");
    //       goto generate_out;
    //     }
    //     EVP_PKEY_set1_EC_KEY(public_key, eckey);
    //   } else {
    //     fprintf(stderr, "Wrong algorithm.\n");
    //     goto generate_out;
    //   }
    //   PEM_write_PUBKEY(output_file, public_key);
    //   ret = true;
    // } else {
    //   fprintf(stderr, "Only PEM is supported as public_key output.\n");
    //   goto generate_out;
    // }
    //
    // if(point) {
    //   EC_POINT_free(point);
    // }
    // if(eckey) {
    //   EC_KEY_free(eckey);
    // }
    // if(rsa) {
    //   RSA_free(rsa);
    // }
    // if(public_key) {
    //   EVP_PKEY_free(public_key);
    // }
  }

  resp.success = resp.response_code == YKPIV_OK;
  stop();

  return resp;
}
