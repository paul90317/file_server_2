let argv = process.argv
let port = 80;
let folder = 'folder'
let password = "123";
let random_boot_code = Math.floor(Math.random() * 100000000);
for (let i = 2; i < argv.length - 1; i++) {
  if (argv[i] == '-p') {
    port = parseInt(argv[i + 1])
  } else if (argv[i] == '-f') {
    folder = argv[i + 1]
  } else if (argv[i] == '-k') {
    password = argv[i + 1]
  }
}

const sha256 = require('js-sha256').sha256;
const aesjs = require('aes-js');
let key = aesjs.utils.hex.toBytes(sha256(random_boot_code + '*' + password))
let used_codes = new Set();

function encrypt(bytes, client_code) {
  let iv = aesjs.utils.hex.toBytes(sha256(random_boot_code + '*' + client_code)).slice(0, 16)
  let cipher = new aesjs.ModeOfOperation.cbc(key, iv)
  let len = bytes.length
  let ret = new Uint8Array(bytes.length + 16 - (bytes.length) % 16)
  for (let i = 0; i < bytes.length; i++) {
    ret[i] = bytes[i]
  }
  return [cipher.encrypt(ret), len]
}

function decrypt(bytes, client_code, size) {
  if (used_codes.has(client_code)) {
    return null
  }
  used_codes.add(client_code)
  let iv = aesjs.utils.hex.toBytes(sha256(random_boot_code + '*' + client_code)).slice(0, 16)
  let cipher = new aesjs.ModeOfOperation.cbc(key, iv)
  return cipher.decrypt(bytes).slice(0, size)
}

const fs = require('fs')
if (!fs.existsSync(folder))
  fs.mkdirSync(folder)

const path = require('path')
const http = require('http');

function parseURL(url) {
  url = url.split('?')
  let upath = url[0]
  let ret = { path: upath, params: {} }
  if (url.length == 1)
    return ret
  url = url[1]
  url = url.split('&')
  for (let i in url) {
    let pair = url[i].split('=')
    if (pair.length != 2)
      continue
    ret.params[pair[0]] = pair[1]
  }
  return ret;
}
function parsePath(path) {
  let temp = path.split('/')
  let paths = [];
  for (let i in temp) {
    if (temp[i] == '')
      continue
    if (temp[i] == '..')
      return null
    paths.push(temp[i])
  }
  return paths
}
function joinPath(paths) {
  let ret = folder
  for (let i in paths) {
    ret = path.join(ret, paths[i])
  }
  return ret;
}
const jszip = require('jszip');

function addFilesFromDirectoryToZip(BasePath, zip, ZipPath = '') {
  fs.readdirSync(BasePath).forEach(filename => {
    let filePath = `${BasePath}${filename}`;
    let savePath = `${ZipPath}${filename}`;
    if (fs.lstatSync(filePath).isFile()) {
      zip.file(savePath, fs.createReadStream(filePath));
    } else
      addFilesFromDirectoryToZip(filePath + '/', zip, savePath + '/');
  });
}
http.createServer((req, res) => {
  //handle cipher
  let url = parseURL(req.url)
  let client_code = url.params.client_code
  let size = url.params.size
  let ciphertext = url.params.ciphertext
  if (client_code == undefined || size == undefined || ciphertext == undefined)
    return res.end(fs.readFileSync('index.htm').toString().replace('{server_code}', random_boot_code))

  try {
    url = aesjs.utils.utf8.fromBytes(decrypt(aesjs.utils.hex.toBytes(ciphertext), client_code, size))
  } catch (err) {
    return res.end()
  }
  url = parseURL(url.toString())
  if (url.params.ac != 'true')
    return res.end()

  //handle request
  let paths = parsePath(url.path)
  if (paths == null)
    return res.end()
  let cmd = paths.shift();
  let filepath = joinPath(paths)
  switch (req.method) {
    case 'GET':
      switch (cmd) {
        case 'dir':
          if (fs.existsSync(filepath) && fs.lstatSync(filepath).isDirectory()) {
            let files = [];
            let dirs = [];
            fs.readdirSync(filepath).forEach(file => {
              if (fs.lstatSync(path.join(filepath, file)).isDirectory())
                dirs.push(file);
              else files.push(file);
            });
            let data = JSON.stringify({
              dirs: dirs,
              files: files,
              ac: true
            });
            data=aesjs.utils.utf8.toBytes(data)
            data=encrypt(data,client_code)
            data[0]=aesjs.utils.hex.fromBytes(data[0])
            return res.end(JSON.stringify(data));
          }
          break
        case 'file':
          if (fs.existsSync(filepath) && fs.lstatSync(filepath).isFile()) {
            return res.end(fs.readFileSync(filepath));
          }
          break
        case 'zip':
          if (fs.existsSync(filepath) && fs.lstatSync(filepath).isDirectory()) {
            let zip = new jszip();
            addFilesFromDirectoryToZip(filepath + '/', zip);
            return zip.generateNodeStream().pipe(res);
          }
          break
      }
      break;
    case 'POST':
      switch (cmd) {
        case 'file':
          let body = [];
          if (fs.existsSync(filepath))
            return res.end('File was existed.');
          return req.on('data', chunk => {
            body.push(chunk);
          }).on('end', () => {
            try {
              fs.writeFileSync(filepath, Buffer.concat(body), { flag: 'w+' });
            } catch (err) {
              return res.end('Directry not found.');
            }
            return res.end('File has been uploaded.');
          });
        case 'dir':
          if (fs.existsSync(filepath))
            return res.end('Folder was existed.');
          try {
            fs.mkdirSync(filepath);
          } catch (err) {
            return res.end('Directry not found.');
          }
          return res.end('Folder has been created.');
      }
    case 'DELETE':
      switch (cmd) {
        case 'file':
          if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isFile())
            return res.end('File not found.')
          fs.unlinkSync(filepath)
          return res.end('File has been deleted.');
        case 'dir':
          if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isDirectory())
            return res.end('Folder not found.')
          if (filepath == folder)
            return res.end('Delete root is not allower')
          fs.rmSync(filepath, { recursive: true });
          return res.end('Folder has been deleted.');
      }
    case 'PATCH':
      let newpath, temp;
      switch (cmd) {
        case 'file':
          if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isFile())
            return res.end('File not found.')
          temp = parsePath(url.params.newpath)
          if (temp == null)
            return res.end('.. is not allowed.')
          newpath = joinPath(temp)
          if (fs.existsSync(newpath))
            return res.end('File existed.')
          try {
            fs.renameSync(filepath, newpath)
          } catch (err) {
            return res.end('Directry not found.');
          }
          return res.end('File has been renamed.');
        case 'dir':
          if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isDirectory())
            return res.end('Folder not found.')
          temp = parsePath(url.params.newpath)
          if (temp == null)
            return res.end('.. is not allowed.')
          newpath = joinPath(temp)
          if (fs.existsSync(newpath))
            return res.end('Folder existed.')
          try {
            fs.renameSync(filepath, newpath)
          } catch (err) {
            return res.end('Directry not found.');
          }
          return res.end('Folder has been renamed.');
      }
  }
  res.end();
}).listen(port, () => {
  console.log(`http://127.0.0.1:${port}`)
});

