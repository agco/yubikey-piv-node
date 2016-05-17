const yubikey = require('bindings')('yubikey');

console.log(yubikey.listReaders());
tryExec(() => { yubikey.verifyPin(123456) });
tryExec(() => { yubikey.reset() });

function tryExec(func) {
  try {
    console.log(func());
  } catch (ex) {
    console.log(ex.message);
  }
}
