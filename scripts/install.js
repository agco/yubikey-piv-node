const fs = require('fs');
const http = require('https');
const zlib = require('zlib');

const DEPS_PATH = 'deps';

function download(source, dest) {
  console.log(`Downloading ${source}`);
  const file = fs.createWriteStream(dest);

  http.get(source, (response) => {
    if (response.statusCode === 200) {
      response.pipe(zlib.createGunzip()).pipe(file);
    } else {
      console.error("Impossible to download file ");
    }
  });
}

function checkAndDownload(source) {

  const sourceFileName = source.split('/').pop();
  const destFilename = `${DEPS_PATH}/${sourceFileName}`;

  if (!fs.existsSync(DEPS_PATH)) {
    fs.mkdir(DEPS_PATH);
  }

  fs.exists(destFilename, (exists) => {
    if (!exists) {
      fs.writeFileSync(destFilename);
      download(source, destFilename);
    } else {
      console.log(`${sourceFileName} - already downloaded.`);
    }
  });
}

function fetchLibraries() {
  console.log('Fetching...');
  checkAndDownload('https://developers.yubico.com/yubico-piv-tool/Releases/yubico-piv-tool-1.4.0-win64.zip');
}

fetchLibraries();
