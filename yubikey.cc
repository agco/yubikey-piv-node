#include <node.h>
#include "v8-util.h"
#include "piv_manager.h"
#include <ykpiv/ykpiv.h>
#include <stdio.h>

using namespace v8;

void ListReaders(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  struct response resp = list_readers();
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void VerifyPin(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value pin_param(args[0]);
  const char* pin_pointer = *pin_param;

  struct response resp = verify_pin(pin_pointer);
  if (resp.success) {
    args.GetReturnValue().Set(true);
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void Reset(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  struct response resp = reset();
  if (resp.success) {
    args.GetReturnValue().Set(true);
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void ChangePuk(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value current_puk_param(args[0]);
  const char *current_puk = *current_puk_param;

  String::Utf8Value new_puk_param(args[1]);
  const char *new_puk = *new_puk_param;

  struct response resp = change_puk(current_puk, new_puk);
  if (resp.success) {
    args.GetReturnValue().Set(true);
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void ChangePin(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value current_pin_param(args[0]);
  const char *current_pin = *current_pin_param;

  String::Utf8Value new_pin_param(args[1]);
  const char *new_pin = *new_pin_param;

  struct response resp = change_pin(current_pin, new_pin);
  if (resp.success) {
    args.GetReturnValue().Set(true);
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void Version(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  struct response resp = version();
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void SetManagementKey(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value current_key_param(args[0]);
  const char *current_key = *current_key_param;

  String::Utf8Value new_key_param(args[1]);
  const char *new_key = *new_key_param;

  struct response resp = set_management_key(current_key, new_key);
  if (resp.success) {
    args.GetReturnValue().Set(true);
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void GenerateKey(const FunctionCallbackInfo<Value>& args) {

  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value mgm_key_param(args[0]);
  const char *mgm_key = *mgm_key_param;

  String::Utf8Value slot_param(args[1]);
  const char *slot = *slot_param;

  int algorithm_param = args[2]->IntegerValue();

  int key_format = args[3]->Int32Value();

  unsigned char pin_policy = YKPIV_PINPOLICY_DEFAULT;
  unsigned char touch_policy = YKPIV_TOUCHPOLICY_DEFAULT;

  struct response resp = generate_key(mgm_key, slot, algorithm_param, pin_policy, touch_policy, key_format);
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void GetAvailableAlgorithms(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    Local<Map> algorithmsMap = Map::New(isolate);
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "3DES"), Int32::New(isolate, YKPIV_ALGO_3DES));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "RSA1024"), Int32::New(isolate, YKPIV_ALGO_RSA1024));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "RSA2048"), Int32::New(isolate, YKPIV_ALGO_RSA2048));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "ECP256"), Int32::New(isolate, YKPIV_ALGO_ECCP256));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "ECP384"), Int32::New(isolate, YKPIV_ALGO_ECCP384));

    args.GetReturnValue().Set(algorithmsMap);
}

void GetPinPolicies(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    Local<Map> algorithmsMap = Map::New(isolate);
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "DEFAULT"), Int32::New(isolate, YKPIV_PINPOLICY_DEFAULT));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "NEVER"), Int32::New(isolate, YKPIV_PINPOLICY_NEVER));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "ONCE"), Int32::New(isolate, YKPIV_PINPOLICY_ONCE));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "ALWAYS"), Int32::New(isolate, YKPIV_PINPOLICY_ALWAYS));

    args.GetReturnValue().Set(algorithmsMap);
}

void GetTouchPolicies(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    Local<Map> algorithmsMap = Map::New(isolate);
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "DEFAULT"), Int32::New(isolate, YKPIV_TOUCHPOLICY_DEFAULT));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "NEVER"), Int32::New(isolate, YKPIV_TOUCHPOLICY_NEVER));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "ALWAYS"), Int32::New(isolate, YKPIV_TOUCHPOLICY_ALWAYS));
    algorithmsMap->Set(context, String::NewFromUtf8(isolate, "CACHED"), Int32::New(isolate, YKPIV_TOUCHPOLICY_CACHED));

    args.GetReturnValue().Set(algorithmsMap);
}

void GetAvailableKeyFormats(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  Local<Context> context = isolate->GetCurrentContext();

  Local<Map> algorithmsMap = Map::New(isolate);
  algorithmsMap->Set(context, String::NewFromUtf8(isolate, "PEM"), Int32::New(isolate, key_format_arg_PEM));
  algorithmsMap->Set(context, String::NewFromUtf8(isolate, "PKCS12"), Int32::New(isolate, key_format_arg_PKCS12));
  algorithmsMap->Set(context, String::NewFromUtf8(isolate, "GZIP"), Int32::New(isolate, key_format_arg_GZIP));
  algorithmsMap->Set(context, String::NewFromUtf8(isolate, "DER"), Int32::New(isolate, key_format_arg_DER));

  args.GetReturnValue().Set(algorithmsMap);
}

void GetAvailableHashes(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  Local<Context> context = isolate->GetCurrentContext();

  Local<Map> algorithmsMap = Map::New(isolate);
  algorithmsMap->Set(context, String::NewFromUtf8(isolate, "SHA1"), Int32::New(isolate, hash_arg_SHA1));
  algorithmsMap->Set(context, String::NewFromUtf8(isolate, "SHA256"), Int32::New(isolate, hash_arg_SHA256));
  algorithmsMap->Set(context, String::NewFromUtf8(isolate, "SHA384"), Int32::New(isolate, hash_arg_SHA384));
  algorithmsMap->Set(context, String::NewFromUtf8(isolate, "SHA512"), Int32::New(isolate, hash_arg_SHA512));

  args.GetReturnValue().Set(algorithmsMap);
}

void RequestCertificate(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value mgm_key_param(args[0]);
  const char *mgm_key = *mgm_key_param;

  String::Utf8Value slot_param(args[1]);
  const char *slot = *slot_param;

  int hash = args[2]->IntegerValue();

  String::Utf8Value subject_param(args[3]);
  const char *subject = *subject_param;

  String::Utf8Value public_key_param(args[4]);
  char *public_key = *public_key_param;

  struct response resp = generate_request(mgm_key, slot, hash, subject, public_key);
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void ImportCertificate(const FunctionCallbackInfo<Value>& args) {

  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value mgm_key_param(args[0]);
  const char *mgm_key = *mgm_key_param;

  String::Utf8Value slot_param(args[1]);
  const char *slot = *slot_param;

  int cert_format = args[2]->IntegerValue();

  String::Utf8Value password_param(args[3]);
  char *password = *password_param;

  String::Utf8Value certificate_param(args[4]);
  char *certificate = *certificate_param;

  struct response resp = import_certificate(mgm_key, slot, cert_format, password, certificate);
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void Status(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  struct response resp = get_status();
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void ReadSlot(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value slot_param(args[0]);
  const char *slot = *slot_param;

  int hash = args[1]->IntegerValue();

  struct response resp = read_slot(slot, hash);
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void ReadCertificate(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value slot_param(args[0]);
  const char *slot = *slot_param;

  int key_format = args[1]->Int32Value();

  struct response resp = read_certificate(slot, key_format);
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void DeleteCertificate(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value slot_param(args[0]);
  const char *slot = *slot_param;

  String::Utf8Value mgm_key_param(args[1]);
  const char *mgm_key = *mgm_key_param;

  struct response resp = delete_certificate(slot, mgm_key);
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void UnlockPin(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);

  String::Utf8Value puk_param(args[0]);
  const char *puk = *puk_param;

  String::Utf8Value new_pin_param(args[1]);
  const char *new_pin = *new_pin_param;

  struct response resp = unblock_pin(puk, new_pin);
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void ImportKey(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);


  String::Utf8Value mgm_key_param(args[0]);
  const char *mgm_key = *mgm_key_param;

  String::Utf8Value slot_param(args[1]);
  const char *slot = *slot_param;

  int key_format = args[2]->IntegerValue();

  String::Utf8Value password_param(args[3]);
  char *password = *password_param;

  String::Utf8Value key_param(args[4]);
  char *key = *key_param;

  unsigned char pin_policy = YKPIV_PINPOLICY_DEFAULT;
  unsigned char touch_policy = YKPIV_TOUCHPOLICY_DEFAULT;

  struct response resp = import_key(mgm_key, key_format, key, slot, password, pin_policy, touch_policy);
  if (resp.success) {
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, resp.message.c_str()));
  } else {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, resp.error_message.c_str())));
  }
}

void Init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "listReaders", ListReaders);
  NODE_SET_METHOD(exports, "verifyPin", VerifyPin);
  NODE_SET_METHOD(exports, "reset", Reset);
  NODE_SET_METHOD(exports, "changePuk", ChangePuk);
  NODE_SET_METHOD(exports, "changePin", ChangePin);
  NODE_SET_METHOD(exports, "version", Version);
  NODE_SET_METHOD(exports, "setManagementKey", SetManagementKey);
  NODE_SET_METHOD(exports, "generateKey", GenerateKey);
  NODE_SET_METHOD(exports, "getAvailableAlgorithms", GetAvailableAlgorithms);
  NODE_SET_METHOD(exports, "getAvailableKeyFormats", GetAvailableKeyFormats);
  NODE_SET_METHOD(exports, "getPinPolicies", GetPinPolicies);
  NODE_SET_METHOD(exports, "getTouchPolicies", GetTouchPolicies);
  NODE_SET_METHOD(exports, "getAvailableHashes", GetAvailableHashes);
  NODE_SET_METHOD(exports, "requestCertificate", RequestCertificate);
  NODE_SET_METHOD(exports, "importCertificate", ImportCertificate);
  NODE_SET_METHOD(exports, "status", Status);
  NODE_SET_METHOD(exports, "readSlot", ReadSlot);
  NODE_SET_METHOD(exports, "readCertificate", ReadCertificate);
  NODE_SET_METHOD(exports, "deleteCertificate", DeleteCertificate);
  NODE_SET_METHOD(exports, "unlockPin", UnlockPin);
  NODE_SET_METHOD(exports, "importKey", ImportKey);
}

NODE_MODULE(addon, Init)
