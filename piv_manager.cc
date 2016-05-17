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
