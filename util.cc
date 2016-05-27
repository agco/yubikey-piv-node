#include <ykpiv/ykpiv.h>
#include "util.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "piv_manager.h"
#include <sstream>
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <sys/stat.h>

using namespace std;

#define MAX_OID_LEN 19

const EVP_MD *get_hash(int hash, const unsigned char **oid, size_t *oid_len) {
  switch(hash) {
    case hash_arg_SHA1:
      if(oid) {
        *oid = sha1oid;
        *oid_len = sizeof(sha1oid);
      }
      return EVP_sha1();
    case hash_arg_SHA256:
      if(oid) {
        *oid = sha256oid;
        *oid_len = sizeof(sha256oid);
      }
      return EVP_sha256();
    case hash_arg_SHA384:
      if(oid) {
        *oid = sha384oid;
        *oid_len = sizeof(sha384oid);
      }
      return EVP_sha384();
    case hash_arg_SHA512:
      if(oid) {
        *oid = sha512oid;
        *oid_len = sizeof(sha512oid);
      }
      return EVP_sha512();
    default:
      return NULL;
  }
}

int get_hashnid(int hash, unsigned char algorithm) {
  switch(algorithm) {
    case YKPIV_ALGO_RSA1024:
    case YKPIV_ALGO_RSA2048:
      switch(hash) {
        case hash_arg_SHA1:
          return NID_sha1WithRSAEncryption;
        case hash_arg_SHA256:
          return NID_sha256WithRSAEncryption;
        case hash_arg_SHA384:
          return NID_sha384WithRSAEncryption;
        case hash_arg_SHA512:
          return NID_sha512WithRSAEncryption;
        default:
          return 0;
      }
    case YKPIV_ALGO_ECCP256:
    case YKPIV_ALGO_ECCP384:
      switch(hash) {
        case hash_arg_SHA1:
          return NID_ecdsa_with_SHA1;
        case hash_arg_SHA256:
          return NID_ecdsa_with_SHA256;
        case hash_arg_SHA384:
          return NID_ecdsa_with_SHA384;
        case hash_arg_SHA512:
          return NID_ecdsa_with_SHA512;
        default:
          return 0;
      }
    default:
      return 0;
  }
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

string file_to_str(FILE *pFile) {
  fseek(pFile, 0, SEEK_END);
  size_t size = ftell(pFile);
  char* where = new char[size];
  rewind(pFile);
  fread(where, sizeof(char), size, pFile);
  string resp = string(where);
  return resp;
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
    resp.message = file_to_str(pFile);
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

unsigned char get_algorithm(EVP_PKEY *key) {
  int type = EVP_PKEY_type(key->type);
  switch(type) {
    case EVP_PKEY_RSA:
      {
        RSA *rsa = EVP_PKEY_get1_RSA(key);
        int size = RSA_size(rsa);
        if(size == 256) {
          return YKPIV_ALGO_RSA2048;
        } else if(size == 128) {
          return YKPIV_ALGO_RSA1024;
        } else {
          return 0;
        }
      }
    case EVP_PKEY_EC:
      {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
        const EC_GROUP *group = EC_KEY_get0_group(ec);
        int curve = EC_GROUP_get_curve_name(group);
        if(curve == NID_X9_62_prime256v1) {
          return YKPIV_ALGO_ECCP256;
        } else if(curve == NID_secp384r1) {
          return YKPIV_ALGO_ECCP384;
        } else {
          return 0;
        }
      }
    default:
      return 0;
  }
}

X509_NAME *parse_name(const char *orig_name, string error_message) {
  X509_NAME *parsed = NULL;
  char name[1025];
  char *ptr = name;
  char *part;

  if(strlen(orig_name) > 1024) {
    error_message = "Name is to long!";
    return NULL;
  }

  strcpy(name, orig_name);

  if(*name != '/') {
    error_message = "Name does not start with '/'!";
    return NULL;
  }

  parsed = X509_NAME_new();

  std::stringstream errMsg;
  while((part = strtok(ptr, "/"))) {
    char *key;
    char *value;
    char *equals = strchr(part, '=');

    if(!equals) {
      errMsg << "The part " << part << " doesn't seem to contain a =.";
      error_message = errMsg.str();
      goto exception_finish;
    }
    *equals++ = '\0';
    value = equals;
    key = part;

    ptr = NULL;
    if(!key) {
      errMsg << "Malformed name (" << part << ").";
      error_message = errMsg.str();
      goto exception_finish;
    }
    if(!value) {
      errMsg << "Malformed name (" << part << ").";
      error_message = errMsg.str();
      goto exception_finish;
    }
    if(!X509_NAME_add_entry_by_txt(parsed, key, MBSTRING_UTF8, (unsigned char*)value, -1, -1, 0)) {
      errMsg << "Failed adding " << key << "=" << value << " to name.";
      error_message = errMsg.str();
      goto exception_finish;
    }
  }

  return parsed;

  exception_finish:
    if (parsed) {
      X509_NAME_free(parsed);
    }
    return NULL;
}

static bool sign_data(ykpiv_state *state, const unsigned char *in, size_t len, unsigned char *out,
    size_t *out_len, unsigned char algorithm, int key) {

  unsigned char signinput[1024];
  if(YKPIV_IS_RSA(algorithm)) {
    size_t padlen = algorithm == YKPIV_ALGO_RSA1024 ? 128 : 256;
    if(RSA_padding_add_PKCS1_type_1(signinput, padlen, in, len) == 0) {
      fprintf(stderr, "Failed adding padding.\n");
      return false;
    }
    in = signinput;
    len = padlen;
  }
  if(ykpiv_sign_data(state, in, len, out, out_len, algorithm, key) == YKPIV_OK) {
    return true;
  }
  return false;
}

response generate_certificate_request(ykpiv_state *piv_state, FILE *input_file, int hash, const char *slot, const char *subject) {
  response resp;

  X509_REQ *req = NULL;
  X509_NAME *name = NULL;
  EVP_PKEY *public_key = NULL;

  public_key = PEM_read_PUBKEY(input_file, NULL, NULL, NULL);
  if(public_key) {
    size_t oid_len;
    const unsigned char *oid;
    const EVP_MD *md;
    unsigned int md_len;
    unsigned char digest[EVP_MAX_MD_SIZE + MAX_OID_LEN];
    unsigned int digest_len;
    int key = 0;
    unsigned char *signinput;
    size_t len = 0;
    int nid;

    sscanf(slot, "%2x", &key);

    unsigned char algorithm = get_algorithm(public_key);
    md = get_hash(hash, &oid, &oid_len);
    md_len = (unsigned int)EVP_MD_size(md);
    digest_len = sizeof(digest) - md_len;

    req = X509_REQ_new();
    if(!X509_REQ_set_pubkey(req, public_key)) {
      resp.error_message = "Failed setting the request public key.";
      resp.response_code = YKPIV_GENERIC_ERROR;
    } else {
      X509_REQ_set_version(req, 0);

      string error_message;
      name = parse_name(subject, error_message);
      if(name) {

        if(X509_REQ_set_subject_name(req, name)) {
          memcpy(digest, oid, oid_len);
          if(ASN1_item_digest(ASN1_ITEM_rptr(X509_REQ_INFO), md, req->req_info, digest + oid_len, &digest_len)) {
            nid = get_hashnid(hash, algorithm);
            std::stringstream errMsg;
            if(nid == 0) {
              errMsg << "Unsupported algorithm " << algorithm << " or hash " << hash;
              resp.error_message = errMsg.str();
              resp.response_code = YKPIV_GENERIC_ERROR;
            } else {
              if(YKPIV_IS_RSA(algorithm)) {
                signinput = digest;
                len = oid_len + digest_len;
              } else {
                signinput = digest + oid_len;
                len = digest_len;
              }

              req->sig_alg->algorithm = OBJ_nid2obj(nid);
              {
                unsigned char signature[1024];
                size_t sig_len = sizeof(signature);
                sign_data(piv_state, signinput, len, signature, &sig_len, algorithm, key);
                M_ASN1_BIT_STRING_set(req->signature, signature, sig_len);
                req->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;
              }

              FILE * pFile;
              pFile = tmpfile();
              PEM_write_X509_REQ(pFile, req);
              resp.message = file_to_str(pFile);
              fclose(pFile);
            }
          } else {
            resp.error_message = "Failed doing digest of request.";
            resp.response_code = YKPIV_GENERIC_ERROR;
          }
        } else {
          resp.error_message = "Failed setting the request subject.";
          resp.response_code = YKPIV_GENERIC_ERROR;
        }
      } else {
        resp.error_message = error_message;
        resp.response_code = YKPIV_GENERIC_ERROR;
      }
    }
  } else {
    resp.error_message = "Failed loading public key for request.";
    resp.response_code = YKPIV_GENERIC_ERROR;
  }

  if(public_key) {
    EVP_PKEY_free(public_key);
  }
  if(req) {
    X509_REQ_free(req);
  }
  if(name) {
    X509_NAME_free(name);
  }

  resp.success = resp.response_code == YKPIV_OK;
  return resp;
}

int get_object_id(int slot) {
  int object;

  switch(slot) {
    case 154:
      object = YKPIV_OBJ_AUTHENTICATION;
      break;
    case 156:
      object = YKPIV_OBJ_SIGNATURE;
      break;
    case 157:
      object = YKPIV_OBJ_KEY_MANAGEMENT;
      break;
    case 158:
      object = YKPIV_OBJ_CARD_AUTH;
      break;
    default:
      object = 0;
  }
  return object;
}

int set_length(unsigned char *buffer, int length) {
  if(length < 0x80) {
    *buffer++ = length;
    return 1;
  } else if(length < 0xff) {
    *buffer++ = 0x81;
    *buffer++ = length;
    return 2;
  } else {
    *buffer++ = 0x82;
    *buffer++ = (length >> 8) & 0xff;
    *buffer++ = length & 0xff;
    return 3;
  }
}

response import_certificate(ykpiv_state *piv_state, const char *slot, int cert_format, char *password, FILE *input_file) {
  struct response resp;
  X509 *cert = NULL;
  PKCS12 *p12 = NULL;
  EVP_PKEY *private_key = NULL;
  int compress = 0;
  int cert_len = -1;
  string error_message;
  if(cert_format == key_format_arg_PEM) {
    cert = PEM_read_X509(input_file, NULL, NULL, password);
    if(!cert) {
      error_message = "Failed loading certificate for import.";
      goto import_cert_out;
    }
  } else if(cert_format == key_format_arg_DER) {
    cert = d2i_X509_fp(input_file, NULL);
    if(!cert) {
      error_message = "Failed loading certificate for import.";
      goto import_cert_out;
    }
  } else if(cert_format == key_format_arg_PKCS12) {
    p12 = d2i_PKCS12_fp(input_file, NULL);
    if(!p12) {
      error_message = "Failed to load PKCS12 from file.";
      goto import_cert_out;
    }
    if(!PKCS12_parse(p12, password, &private_key, &cert, NULL)) {
      error_message = "Failed to parse PKCS12 structure.";
      goto import_cert_out;
    }
  } else if (cert_format == key_format_arg_GZIP) {
    struct stat st;

    if(fstat(fileno(input_file), &st) == -1) {
      error_message = "Failed checking input GZIP file.";
      goto import_cert_out;
    }
    cert_len = st.st_size;
    compress = 0x01;
  } else {
    error_message = "Unknown key format.";
    goto import_cert_out;
  }
  if(cert_len == -1) {
    cert_len = i2d_X509(cert, NULL);
  }

  {
    unsigned char certdata[3072];
    unsigned char *certptr = certdata;

    int slot_key = 0;
    sscanf(slot, "%2x", &slot_key);
    int object = get_object_id(slot_key);

    if(4 + cert_len + 5 > 3072) { /* 4 is prefix size, 5 is postfix size */
      error_message = "Certificate is to large to fit in buffer.";
      goto import_cert_out;
    }

    *certptr++ = 0x70;
    certptr += set_length(certptr, cert_len);
    if (compress) {
      if (fread(certptr, 1, (size_t)cert_len, input_file) != (size_t)cert_len) {
        error_message = "Failed to read compressed certificate.";
        goto import_cert_out;
      }
      certptr += cert_len;
    } else {
      i2d_X509(cert, &certptr);
    }
    *certptr++ = 0x71;
    *certptr++ = 1;
    *certptr++ = compress; /* certinfo (gzip etc) */
    *certptr++ = 0xfe; /* LRC */
    *certptr++ = 0;

    std::ostringstream out_message;
    resp.response_code = ykpiv_save_object(piv_state, object, certdata, (size_t)(certptr - certdata));
    if (resp.response_code != YKPIV_OK) {
      out_message << "Failed commands with device: " << ykpiv_strerror(resp.response_code);
      resp.error_message = out_message.str();
    }
  }
  return resp;

import_cert_out:
  if(cert) {
    X509_free(cert);
  }
  if(input_file != stdin) {
    fclose(input_file);
  }
  if(p12) {
    PKCS12_free(p12);
  }
  if(private_key) {
    EVP_PKEY_free(private_key);
  }

  resp.response_code = YKPIV_GENERIC_ERROR;
  resp.error_message = error_message;
  return resp;
}

response print_cert_info(ykpiv_state *state, const char *slot, const EVP_MD *md) {
  struct response resp;
  X509 *x509 = NULL;
  BIO *bio = NULL;
  FILE *output = NULL;

  int slot_key = 0;
  sscanf(slot, "%2x", &slot_key);
  int object = get_object_id(slot_key);

  unsigned char data[3072];
  const unsigned char *ptr = data;
  unsigned long len = sizeof(data);

  resp.response_code = ykpiv_fetch_object(state, object, data, &len);
  if(resp.response_code != YKPIV_OK) {
    resp.error_message = "Slot is empty.";
  } else {
    int cert_len;
    X509_NAME *subj;

    output = tmpfile();

    if(*ptr++ == 0x70) {
      unsigned int md_len = sizeof(data);
      ASN1_TIME *not_before, *not_after;

      ptr += get_length(ptr, &cert_len);
      x509 = X509_new();
      x509 = d2i_X509(NULL, &ptr, cert_len);
      EVP_PKEY *key = X509_get_pubkey(x509);
      fprintf(output, "Algorithm:\t");
      switch(get_algorithm(key)) {
        case YKPIV_ALGO_RSA1024:
          fprintf(output, "RSA1024\n");
          break;
        case YKPIV_ALGO_RSA2048:
          fprintf(output, "RSA2048\n");
          break;
        case YKPIV_ALGO_ECCP256:
          fprintf(output, "ECCP256\n");
          break;
        case YKPIV_ALGO_ECCP384:
          fprintf(output, "ECCP384\n");
          break;
        default:
          fprintf(output, "Unknown\n");
      }
      subj = X509_get_subject_name(x509);
      fprintf(output, "Subject DN:\t");
      X509_NAME_print_ex_fp(output, subj, 0, XN_FLAG_COMPAT);
      fprintf(output, "\n");
      subj = X509_get_issuer_name(x509);
      fprintf(output, "Issuer DN:\t");
      X509_NAME_print_ex_fp(output, subj, 0, XN_FLAG_COMPAT);
      fprintf(output, "\n");
      X509_digest(x509, md, data, &md_len);
      fprintf(output, "Fingerprint:\t");
      dump_data(data, md_len, output, false);

      bio = BIO_new_fp(output, BIO_NOCLOSE | BIO_FP_TEXT);
      not_before = X509_get_notBefore(x509);
      if(not_before) {
        fprintf(output, "Not Before:\t");
        ASN1_TIME_print(bio, not_before);
        fprintf(output, "\n");
      }
      not_after = X509_get_notAfter(x509);
      if(not_after) {
        fprintf(output, "Not After:\t");
        ASN1_TIME_print(bio, not_after);
        fprintf(output, "\n");
      }

      resp.message = file_to_str(output);
    } else {
      resp.response_code = YKPIV_GENERIC_ERROR;
      resp.error_message = "Parse error.";
    }
  }

  if (x509) {
    X509_free(x509);
  }
  if (bio) {
    BIO_free(bio);
  }
  if (output) {
    fclose(output);
  }

  return resp;
}

void dump_data(const unsigned char *buf, unsigned int len, FILE *output, bool space) {
  char tmp[3072 * 3 + 1];
  unsigned int i;
  unsigned int step = 2;
  if(space) step += 1;
  if(len > 3072) {
    return;
  }
  for (i = 0; i < len; i++) {
    sprintf(tmp + i * step, "%02x%s", buf[i], space == true ? " " : "");
  }
  fprintf(output, "%s\n", tmp);
  return;
}
