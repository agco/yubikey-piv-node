const yubikey = require('bindings')('yubikey');

// console.log(yubikey.listReaders());
// tryExec( () => { console.log(yubikey.verifyPin(123456)) });
// tryExec(() => { console.log(yubikey.changePuk(87654321, 12345678)) });
// tryExec(() => { console.log(yubikey.reset()) });
// tryExec(() => { console.log(yubikey.changePin("654321", "123456")) });

function tryExec(func) {
  var result;
  try {
    result = func();
  } catch (ex) {
    console.log(ex.message);
  }
  return result;
}
