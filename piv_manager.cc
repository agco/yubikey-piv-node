#include <stdio.h>
#include <string>
#include <cstring>
#include <list>
#include <sstream>
#include <ykpiv/ykpiv.h>
#include "piv_manager.h"

const std::string reader = "Yubikey";
size_t reader_size = sizeof(reader);
ykpiv_state *piv_state = NULL;
std::string fail_message;

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

// static bool request_certificate(ykpiv_state *state, enum enum_key_format key_format,
//     const char *input_file_name, const char *slot, char *subject, enum enum_hash hash,
//     const char *output_file_name) {
//   X509_REQ *req = NULL;
//   X509_NAME *name = NULL;
//   FILE *input_file = NULL;
//   FILE *output_file = NULL;
//   EVP_PKEY *public_key = NULL;
//   const EVP_MD *md;
//   bool ret = false;
//   unsigned char digest[EVP_MAX_MD_SIZE + MAX_OID_LEN];
//   unsigned int digest_len;
//   unsigned int md_len;
//   unsigned char algorithm;
//   int key = 0;
//   unsigned char *signinput;
//   size_t len = 0;
//   size_t oid_len;
//   const unsigned char *oid;
//   int nid;
//
//   sscanf(slot, "%2x", &key);
//
//   input_file = open_file(input_file_name, INPUT);
//   output_file = open_file(output_file_name, OUTPUT);
//   if(!input_file || !output_file) {
//     goto request_out;
//   }
//
//   if(isatty(fileno(input_file))) {
//     fprintf(stderr, "Please paste the public key...\n");
//   }
//
//   if(key_format == key_format_arg_PEM) {
//     public_key = PEM_read_PUBKEY(input_file, NULL, NULL, NULL);
//     if(!public_key) {
//       fprintf(stderr, "Failed loading public key for request.\n");
//       goto request_out;
//     }
//   } else {
//     fprintf(stderr, "Only PEM supported for public key input.\n");
//     goto request_out;
//   }
//   algorithm = get_algorithm(public_key);
//   if(algorithm == 0) {
//     goto request_out;
//   }
//
//   md = get_hash(hash, &oid, &oid_len);
//   if(md == NULL) {
//     goto request_out;
//   }
//
//   md_len = (unsigned int)EVP_MD_size(md);
//   digest_len = sizeof(digest) - md_len;
//
//   req = X509_REQ_new();
//   if(!req) {
//     fprintf(stderr, "Failed to allocate request structure.\n");
//     goto request_out;
//   }
//   if(!X509_REQ_set_pubkey(req, public_key)) {
//     fprintf(stderr, "Failed setting the request public key.\n");
//     goto request_out;
//   }
//
//   X509_REQ_set_version(req, 0);
//
//   name = parse_name(subject);
//   if(!name) {
//     fprintf(stderr, "Failed encoding subject as name.\n");
//     goto request_out;
//   }
//   if(!X509_REQ_set_subject_name(req, name)) {
//     fprintf(stderr, "Failed setting the request subject.\n");
//     goto request_out;
//   }
//
//   memcpy(digest, oid, oid_len);
//   /* XXX: this should probably use X509_REQ_digest() but that's buggy */
//   if(!ASN1_item_digest(ASN1_ITEM_rptr(X509_REQ_INFO), md, req->req_info,
//               digest + oid_len, &digest_len)) {
//     fprintf(stderr, "Failed doing digest of request.\n");
//     goto request_out;
//   }
//
//   nid = get_hashnid(hash, algorithm);
//   if(nid == 0) {
//     fprintf(stderr, "Unsupported algorithm %x or hash %x\n", algorithm, hash);
//     goto request_out;
//   }
//   if(YKPIV_IS_RSA(algorithm)) {
//     signinput = digest;
//     len = oid_len + digest_len;
//   } else {
//     signinput = digest + oid_len;
//     len = digest_len;
//   }
//
//   req->sig_alg->algorithm = OBJ_nid2obj(nid);
//   {
//     unsigned char signature[1024];
//     size_t sig_len = sizeof(signature);
//     if(!sign_data(state, signinput, len, signature, &sig_len, algorithm, key)) {
//       fprintf(stderr, "Failed signing request.\n");
//       goto request_out;
//     }
//     M_ASN1_BIT_STRING_set(req->signature, signature, sig_len);
//     /* mark that all bits should be used. */
//     req->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;
//   }
//
//   if(key_format == key_format_arg_PEM) {
//     PEM_write_X509_REQ(output_file, req);
//     ret = true;
//   } else {
//     fprintf(stderr, "Only PEM support available for certificate requests.\n");
//   }
//
// request_out:
//   if(input_file && input_file != stdin) {
//     fclose(input_file);
//   }
//   if(output_file && output_file != stdout) {
//     fclose(output_file);
//   }
//   if(public_key) {
//     EVP_PKEY_free(public_key);
//   }
//   if(req) {
//     X509_REQ_free(req);
//   }
//   if(name) {
//     X509_NAME_free(name);
//   }
//   return ret;
// }
//
//
// static bool import_cert(ykpiv_state *state, enum enum_key_format cert_format,
//     const char *input_file_name, enum enum_slot slot, char *password) {
//   bool ret = false;
//   FILE *input_file = NULL;
//   X509 *cert = NULL;
//   PKCS12 *p12 = NULL;
//   EVP_PKEY *private_key = NULL;
//   int compress = 0;
//   int cert_len = -1;
//
//   input_file = open_file(input_file_name, INPUT);
//   if(!input_file) {
//     return false;
//   }
//
//   if(isatty(fileno(input_file))) {
//     fprintf(stderr, "Please paste the certificate...\n");
//   }
//
//   if(cert_format == key_format_arg_PEM) {
//     cert = PEM_read_X509(input_file, NULL, NULL, password);
//     if(!cert) {
//       fprintf(stderr, "Failed loading certificate for import.\n");
//       goto import_cert_out;
//     }
//   } else if(cert_format == key_format_arg_DER) {
//     cert = d2i_X509_fp(input_file, NULL);
//     if(!cert) {
//       fprintf(stderr, "Failed loading certificate for import.\n");
//       goto import_cert_out;
//     }
//   } else if(cert_format == key_format_arg_PKCS12) {
//     p12 = d2i_PKCS12_fp(input_file, NULL);
//     if(!p12) {
//       fprintf(stderr, "Failed to load PKCS12 from file.\n");
//       goto import_cert_out;
//     }
//     if(!PKCS12_parse(p12, password, &private_key, &cert, NULL)) {
//       fprintf(stderr, "Failed to parse PKCS12 structure.\n");
//       goto import_cert_out;
//     }
//   } else if (cert_format == key_format_arg_GZIP) {
//     struct stat st;
//
//     if(fstat(fileno(input_file), &st) == -1) {
//       fprintf(stderr, "Failed checking input GZIP file.\n");
//       goto import_cert_out;
//     }
//     cert_len = st.st_size;
//     compress = 0x01;
//   } else {
//     /* TODO: more formats go here */
//     fprintf(stderr, "Unknown key format.\n");
//     goto import_cert_out;
//   }
//   if(cert_len == -1) {
//     cert_len = i2d_X509(cert, NULL);
//   }
//
//   {
//     unsigned char certdata[3072];
//     unsigned char *certptr = certdata;
//     int object = get_object_id(slot);
//     ykpiv_rc res;
//
//     if(4 + cert_len + 5 > sizeof(certdata)) { /* 4 is prefix size, 5 is postfix size */
//       fprintf(stderr, "Certificate is too large to fit in buffer.\n");
//       goto import_cert_out;
//     }
//
//     *certptr++ = 0x70;
//     certptr += set_length(certptr, cert_len);
//     if (compress) {
//       if (fread(certptr, 1, (size_t)cert_len, input_file) != (size_t)cert_len) {
//         fprintf(stderr, "Failed to read compressed certificate\n");
//         goto import_cert_out;
//       }
//       certptr += cert_len;
//     } else {
//       /* i2d_X509 increments certptr here.. */
//       i2d_X509(cert, &certptr);
//     }
//     *certptr++ = 0x71;
//     *certptr++ = 1;
//     *certptr++ = compress; /* certinfo (gzip etc) */
//     *certptr++ = 0xfe; /* LRC */
//     *certptr++ = 0;
//
//     if((res = ykpiv_save_object(state, object, certdata, (size_t)(certptr - certdata))) != YKPIV_OK) {
//       fprintf(stderr, "Failed commands with device: %s\n", ykpiv_strerror(res));
//     } else {
//       ret = true;
//     }
//   }
//
// import_cert_out:
//   if(cert) {
//     X509_free(cert);
//   }
//   if(input_file != stdin) {
//     fclose(input_file);
//   }
//   if(p12) {
//     PKCS12_free(p12);
//   }
//   if(private_key) {
//     EVP_PKEY_free(private_key);
//   }
//
//   return ret;
// }
//
// static bool generate_key(ykpiv_state *state, const char *slot,
//     enum enum_algorithm algorithm, const char *output_file_name,
//     enum enum_key_format key_format, enum enum_pin_policy pin_policy,
//     enum enum_touch_policy touch_policy) {
//   unsigned char in_data[11];
//   unsigned char *in_ptr = in_data;
//   unsigned char data[1024];
//   unsigned char templ[] = {0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0};
//   unsigned long recv_len = sizeof(data);
//   int sw;
//   int key = 0;
//   FILE *output_file = NULL;
//   bool ret = false;
//   EVP_PKEY *public_key = NULL;
//   RSA *rsa = NULL;
//   BIGNUM *bignum_n = NULL;
//   BIGNUM *bignum_e = NULL;
//   EC_KEY *eckey = NULL;
//   EC_POINT *point = NULL;
//
//   sscanf(slot, "%2x", &key);
//   templ[3] = key;
//
//   output_file = open_file(output_file_name, OUTPUT);
//   if(!output_file) {
//     return false;
//   }
//
//   *in_ptr++ = 0xac;
//   *in_ptr++ = 3;
//   *in_ptr++ = YKPIV_ALGO_TAG;
//   *in_ptr++ = 1;
//   *in_ptr++ = get_piv_algorithm(algorithm);
//   if(in_data[4] == 0) {
//     fprintf(stderr, "Unexpected algorithm.\n");
//     goto generate_out;
//   }
//   if(pin_policy != pin_policy__NULL) {
//     in_data[1] += 3;
//     *in_ptr++ = YKPIV_PINPOLICY_TAG;
//     *in_ptr++ = 1;
//     *in_ptr++ = get_pin_policy(pin_policy);
//   }
//   if(touch_policy != touch_policy__NULL) {
//     in_data[1] += 3;
//     *in_ptr++ = YKPIV_TOUCHPOLICY_TAG;
//     *in_ptr++ = 1;
//     *in_ptr++ = get_touch_policy(touch_policy);
//   }
//   if(ykpiv_transfer_data(state, templ, in_data, in_ptr - in_data, data,
//         &recv_len, &sw) != YKPIV_OK) {
//     fprintf(stderr, "Failed to communicate.\n");
//     goto generate_out;
//   } else if(sw != SW_SUCCESS) {
//     fprintf(stderr, "Failed to generate new key (");
//     if(sw == SW_ERR_INCORRECT_SLOT) {
//       fprintf(stderr, "slot not supported?)\n");
//     } else if(sw == SW_ERR_INCORRECT_PARAM) {
//       if(pin_policy != pin_policy__NULL) {
//         fprintf(stderr, "pin policy not supported?)\n");
//       } else if(touch_policy != touch_policy__NULL) {
//         fprintf(stderr, "touch policy not supported?)\n");
//       } else {
//         fprintf(stderr, "algorithm not supported?)\n");
//       }
//     } else {
//       fprintf(stderr, "error %x)\n", sw);
//     }
//     goto generate_out;
//   }
//
//   if(key_format == key_format_arg_PEM) {
//     public_key = EVP_PKEY_new();
//     if(algorithm == algorithm_arg_RSA1024 || algorithm == algorithm_arg_RSA2048) {
//       unsigned char *data_ptr = data + 5;
//       int len = 0;
//       rsa = RSA_new();
//
//       if(*data_ptr != 0x81) {
//         fprintf(stderr, "Failed to parse public key structure.\n");
//         goto generate_out;
//       }
//       data_ptr++;
//       data_ptr += get_length(data_ptr, &len);
//       bignum_n = BN_bin2bn(data_ptr, len, NULL);
//       if(bignum_n == NULL) {
//         fprintf(stderr, "Failed to parse public key modulus.\n");
//         goto generate_out;
//       }
//       data_ptr += len;
//
//       if(*data_ptr != 0x82) {
//         fprintf(stderr, "Failed to parse public key structure (2).\n");
//         goto generate_out;
//       }
//       data_ptr++;
//       data_ptr += get_length(data_ptr, &len);
//       bignum_e = BN_bin2bn(data_ptr, len, NULL);
//       if(bignum_e == NULL) {
//         fprintf(stderr, "Failed to parse public key exponent.\n");
//         goto generate_out;
//       }
//
//       rsa->n = bignum_n;
//       rsa->e = bignum_e;
//       EVP_PKEY_set1_RSA(public_key, rsa);
//     } else if(algorithm == algorithm_arg_ECCP256 || algorithm == algorithm_arg_ECCP384) {
//       EC_GROUP *group;
//       unsigned char *data_ptr = data + 3;
//       int nid;
//       size_t len;
//
//       if(algorithm == algorithm_arg_ECCP256) {
//         nid = NID_X9_62_prime256v1;
//         len = 65;
//       } else {
//         nid = NID_secp384r1;
//         len = 97;
//       }
//
//       eckey = EC_KEY_new();
//       group = EC_GROUP_new_by_curve_name(nid);
//       EC_GROUP_set_asn1_flag(group, nid);
//       EC_KEY_set_group(eckey, group);
//       point = EC_POINT_new(group);
//       if(*data_ptr++ != 0x86) {
//         fprintf(stderr, "Failed to parse public key structure.\n");
//         goto generate_out;
//       }
//       if(*data_ptr++ != len) { /* the curve point should always be 65 bytes */
//         fprintf(stderr, "Unexpected length.\n");
//         goto generate_out;
//       }
//       if(!EC_POINT_oct2point(group, point, data_ptr, len, NULL)) {
//         fprintf(stderr, "Failed to load public point.\n");
//         goto generate_out;
//       }
//       if(!EC_KEY_set_public_key(eckey, point)) {
//         fprintf(stderr, "Failed to set the public key.\n");
//         goto generate_out;
//       }
//       EVP_PKEY_set1_EC_KEY(public_key, eckey);
//     } else {
//       fprintf(stderr, "Wrong algorithm.\n");
//       goto generate_out;
//     }
//     PEM_write_PUBKEY(output_file, public_key);
//     ret = true;
//   } else {
//     fprintf(stderr, "Only PEM is supported as public_key output.\n");
//     goto generate_out;
//   }
//
// generate_out:
//   if(output_file != stdout) {
//     fclose(output_file);
//   }
//   if(point) {
//     EC_POINT_free(point);
//   }
//   if(eckey) {
//     EC_KEY_free(eckey);
//   }
//   if(rsa) {
//     RSA_free(rsa);
//   }
//   if(public_key) {
//     EVP_PKEY_free(public_key);
//   }
//
//   return ret;
// }
