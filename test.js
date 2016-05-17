const yubikey = require('bindings')('yubikey');

// console.log(yubikey.listReaders());
// tryExec( () => { console.log(yubikey.verifyPin(54321)) });
// tryExec(() => { console.log(yubikey.changePuk(12345698, 987654)) });
// tryExec(() => { console.log(yubikey.reset()) });

function tryExec(func) {
  var result;
  try {
    result = func();
  } catch (ex) {
    console.log(ex.message);
  }
  return result;
}
