{
  "targets": [
    {
      "target_name": "yubikey",
      "sources": [ "yubikey.cc", "piv_manager.cc" ],
      "libraries": ["-lykpiv", "-lssl"]
    }
  ]
}
