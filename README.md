This project creates a bridge between yubikey devices and node.js programs.

It is meant to mimic the function available on [yubico-piv-tool](https://github.com/Yubico/yubico-piv-tool), with small adaptations.

Functions implemented:

```
function listReaders()
function getVersion()
function verifyPin(pin)
function changePuk(currentPuk, newPuk)
function reset()
function changePin(currentPin, newPin)
function setManagementKey(current_key, new_key)
function getAvailableAlgorithms()
function getAvailableKeyFormats()
function getPinPolicies()
function getTouchPolicies()
function getAvailableHashes()
function generateKey(mgmKey, slot, algorithm, keyFormat)
function requestCertificate(mgmKey, slot, hash, subject, publicKey)
function importCertificate(mgmKey, slot, certFormat, certificate, password)
function readCertificate(slot, keyFormat)
function deleteCertificate(slot, mgmKey)
function importKey(mgmKey, slot, certFormat, certificate, password)
function unlockPin(puk, newPin)
```
