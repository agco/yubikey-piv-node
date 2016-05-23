{
    "targets": [
    {
        "target_name": "yubikey",
        "sources": [ "yubikey.cc", "piv_manager.cc", "util.cc" ],
        "link_settings": {
            "libraries": [
                "-lykpiv",
                "-lssl"
            ]
        },
    }]
}
