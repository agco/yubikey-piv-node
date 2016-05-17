#include <node.h>
#include "piv_manager.h"

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

void GenerateKey(const FunctionCallbackInfo<Value>& args) {
}

void ImportCertificate(const FunctionCallbackInfo<Value>& args) {
}

void RequestCertificate(const FunctionCallbackInfo<Value>& args) {
}


void Status(const FunctionCallbackInfo<Value>& args) {}
void SetManagementKey(const FunctionCallbackInfo<Value>& args) {}
void Version(const FunctionCallbackInfo<Value>& args) {}
void ImportKey(const FunctionCallbackInfo<Value>& args) {}
void ChangePin(const FunctionCallbackInfo<Value>& args) {}
void ChangePuk(const FunctionCallbackInfo<Value>& args) {}
void UnlockPin(const FunctionCallbackInfo<Value>& args) {}
void DeleteCertificate(const FunctionCallbackInfo<Value>& args) {}
void ReadCertificate(const FunctionCallbackInfo<Value>& args) {}

void Init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "listReaders", ListReaders);
  NODE_SET_METHOD(exports, "verifyPin", VerifyPin);
  NODE_SET_METHOD(exports, "reset", Reset);
  NODE_SET_METHOD(exports, "generateKey", GenerateKey);
  NODE_SET_METHOD(exports, "importCertificate", ImportCertificate);
  NODE_SET_METHOD(exports, "requestCertificate", RequestCertificate);
  NODE_SET_METHOD(exports, "status", Status);
  NODE_SET_METHOD(exports, "setManagementKey", SetManagementKey);
  NODE_SET_METHOD(exports, "version", Version);
  NODE_SET_METHOD(exports, "importKey", ImportKey);
  NODE_SET_METHOD(exports, "changePin", ChangePin);
  NODE_SET_METHOD(exports, "changePuk", ChangePuk);
  NODE_SET_METHOD(exports, "unlockPin", UnlockPin);
  NODE_SET_METHOD(exports, "deleteCertificate", DeleteCertificate);
  NODE_SET_METHOD(exports, "readCertificate", ReadCertificate);
}

NODE_MODULE(addon, Init)
