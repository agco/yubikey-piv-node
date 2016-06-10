{
    "targets": [
    {
        "target_name": "yubikey",
        "sources": [
            "src/yubikey.cc",
            "src/piv_manager.cc",
            "src/util.cc"
        ],
        "link_settings": {
            "libraries": [
                "-lykpiv",
                "-lssl"
            ]
        },
    }]
}
