const yubikey = require('bindings')('yubikey');

function listReaders() {
  return yubikey.listReaders();
}

function getVersion() {
  return yubikey.version();
}

function verifyPin(pin) {
  return yubikey.verifyPin(pin);
}

function changePuk(currentPuk, newPuk) {
  return yubikey.changePuk(currentPuk, newPuk);
}

function reset() {
  return yubikey.reset();
}

function changePin(currentPin, newPin) {
  return yubikey.changePin(currentPin, newPin);
}

function setManagementKey(current_key, new_key) {
  return yubikey.setManagementKey(current_key, new_key);
}

function getAvailableAlgorithms() {
  return yubikey.getAvailableAlgorithms();
}

function getAvailableKeyFormats() {
  return yubikey.getAvailableKeyFormats();
}

function getPinPolicies() {
  return yubikey.getPinPolicies();
}

function getTouchPolicies() {
  return yubikey.getTouchPolicies();
}

function getAvailableHashes() {
  return yubikey.getAvailableHashes();
}

function generateKey(mgmKey, slot, algorithm, keyFormat) {
  return yubikey.generateKey(mgmKey, slot, algorithm, keyFormat);
}

function requestCertificate(mgmKey, slot, hash, subject, publicKey) {
  return yubikey.requestCertificate(mgmKey, slot, hash, subject, publicKey);
}

function importCertificate(mgmKey, slot, certFormat, certificate, password) {
  return yubikey.importCertificate(mgmKey, slot, certFormat, password, certificate);
}

module.exports = {
  listReaders,
  verifyPin,
  reset,
  changePuk,
  changePin,
  getVersion,
  setManagementKey,
  generateKey,
  getAvailableAlgorithms,
  getAvailableKeyFormats,
  getPinPolicies,
  getTouchPolicies,
  getAvailableHashes,
  requestCertificate,
  importCertificate
}
