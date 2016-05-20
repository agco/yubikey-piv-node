{
  "targets": [
    {
      "target_name": "yubikey",
      "sources": [ "yubikey.cc", "piv_manager.cc", "util.cc" ],
    #   "libraries": ["-lykpiv", "-lssl"],
      "link_settings": {
        "libraries": [
          "-lykpiv",
          "-lssl"
        ]
      }
    }
  ]
}
