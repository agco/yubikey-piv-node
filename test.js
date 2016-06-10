const yubikey = require('bindings')('yubikey');

// console.log('-- Readers --------------------');
// tryExec(() => { console.log(yubikey.listReaders()) });
//
// console.log('-- Version ---------------------');
// tryExec(() => { console.log(yubikey.version()) });
//
// console.log('-- Blocking ---------------------');
// for (var i = 0; i <= 3; i++) {
//   tryExec(() => { console.log(yubikey.verifyPin(987654)) });
// }
// for (var i = 0; i <= 3; i++) {
//   tryExec(() => { console.log(yubikey.changePuk(98765432, 12345678)) });
// }
// tryExec(() => { console.log('Reset: ', yubikey.reset()) });

// console.log('-- Changing Pin ----------------');
// tryExec(() => { console.log(yubikey.changePin(123456, 654321)) });
//
// console.log('-- Changing Puk ----------------');
// tryExec(() => { console.log(yubikey.changePuk(12345678, 87654321)) });
//
// console.log('-- Changing Management Key -----');
// const buf = new Buffer(24);
// const random_str = Math.random().toString(31).substring(2);
// buf.write(random_str, 0, 24);
// const new_key = buf.toString('hex');
// const current_key = "010203040506070801020304050607080102030405060708";
// tryExec(() => {
//   yubikey.setManagementKey(current_key, new_key);
//   console.log("New key: ", new_key);
// });
//
// console.log('-- Algorithms available -----');
// tryExec(() => {console.log(yubikey.getAvailableAlgorithms());})
//
// console.log('-- Key formats available -----');
// tryExec(() => {console.log(yubikey.getAvailableKeyFormats());})
//
// console.log('-- Pin Policies -----');
// tryExec(() => {console.log(yubikey.getPinPolicies());})
//
// console.log('-- Touch Policies -----');
// tryExec(() => {console.log(yubikey.getTouchPolicies());})
//
// console.log('-- Hashes -----');
// tryExec(() => {console.log(yubikey.getAvailableHashes());})
//
// console.log('-- Generating key RSA1024 -----');
// rsa1024PublicKey = yubikey.generateKey(new_key, "9a", "6", "0");
// console.log(rsa1024PublicKey);
//
// console.log('-- Generating key RSA2048 -----');
// console.log(yubikey.generateKey(new_key, "9c", "7", "0"));
//
// console.log('-- Generating key ECP256 -----');
// console.log(yubikey.generateKey(new_key, "9d", "17", "0"));
//
// console.log('-- Generating key ECP384 -----');
// console.log(yubikey.generateKey(new_key, "9d", "20", "0"));
//
// console.log('-- Generating CSR -----');
// console.log(yubikey.requestCertificate(new_key, "9c", 0, "/CN=foo/OU=test/O=example.com/", rsa1024PublicKey));
//
// console.log('-- Import key PKCS12 -----');
// console.log(yubikey.importKey(new_key, "9c", 1, "ZStGt8qpfX3y8yjn", "/home/tiagodeoliveira/Downloads/gatewayfirmwaresigning.pfx"));
//
// console.log('-- Import cert PKCS12 -----');
// console.log(yubikey.importCertificate(new_key, "9c", 1, "ZStGt8qpfX3y8yjn", "/home/tiagodeoliveira/Downloads/gatewayfirmwaresigning.pfx"));
//
// console.log('-- Status -----------');
// console.log(yubikey.status());
//
// console.log('-- Slot 9a -----------');
// tryExec(() => { console.log(yubikey.readSlot("9a", 2)) });
//
// console.log('-- Slot 9c -----------');
// tryExec(() => {console.log(yubikey.readSlot("9c", 2)) });
//
console.log('-- Read certificate 9c ----');
tryExec(() => {console.log(yubikey.readCertificate("9c", 0)) });
//
// console.log('-- Delete certificate 9c ----');
// tryExec(() => {console.log(yubikey.deleteCertificate("9c", new_key)) });
//
// console.log('-- Slot 9c -----------');
// tryExec(() => {console.log(yubikey.readSlot("9c", 2)) });
//
// console.log('-- Unlock pin ----');
// for (var i = 0; i <= 3; i++) {
//   tryExec(() => { console.log(yubikey.verifyPin(987654)) });
// }
// tryExec(() => { console.log(yubikey.unlockPin(87654321, 123456)) });

function tryExec(func) {
  var result;
  try {
    result = func();
  } catch (ex) {
    console.log(ex.message);
  }
  return result;
}
