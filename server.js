let argv = process.argv
let port = 80;
let folder = 'folder'
let password = "123";
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
const mc=require('./cipher')
const Snonce=mc.random()
const key=aesjs.utils.hex.toBytes(sha256(Snonce+'*'+password))
let used_nonces = new Set();


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
  let Cnonce = url.params.nonce
  let ciphertext = url.params.c
  if (Cnonce == undefined || ciphertext == undefined)
    if (req.method == 'GET') {
      if (req.url=='/')
        return res.end(fs.readFileSync(__dirname+'/index.htm').toString().replace('{server_code}', Snonce))
      if (req.url=='/chipher.js')
        return res.end(fs.readFileSync(__dirname+'/cipher.js'))
      return res.end()
    }


  if (used_nonces.has(Cnonce))
    return res.end()
  let iv=mc.ivGen(Cnonce,Snonce)
  let cipher=new mc.Cipher(key,iv)
  try {
    let temp=cipher.decrypt(aesjs.utils.hex.toBytes(ciphertext))
    if(temp==null){
      return res.end()
    }
    url = aesjs.utils.utf8.fromBytes(temp)
  } catch (err) {
    return res.end()
  }
  url = parseURL(url.toString())
  used_nonces.add(Cnonce)

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
            data = aesjs.utils.utf8.toBytes(data)
            data = cipher.encrypt(data)
            return res.end(data);
          }
          break
        case 'file':
          if (fs.existsSync(filepath) && fs.lstatSync(filepath).isFile()) {
            let data = fs.readFileSync(filepath);
            data = new Uint8Array(data)
            data = cipher.encrypt(data)
            return res.end(data);
          }
          break
        case 'zip':
          if (fs.existsSync(filepath) && fs.lstatSync(filepath).isDirectory()) {
            let zip = new jszip();
            addFilesFromDirectoryToZip(filepath + '/', zip);
            let stream = zip.generateNodeStream()
            let body = []
            return stream.on('data', chunk => {
              body.push(chunk)
            }).on('end', () => {
              body = new Uint8Array(Buffer.concat(body))
              body = cipher.encrypt(body)
              return res.end(body);
            })
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
              body = Buffer.concat(body)
              body = new Uint8Array(body)
              body = cipher.decrypt(body)
              if(body==null)
                return res.end('Decrypt error.');
              fs.writeFileSync(filepath, body, { flag: 'w+' });
            } catch (err) {
              return res.end('0');
            }
            return res.end('1');
          });
        case 'dir':
          if (fs.existsSync(filepath))
            return res.end('0');
          try {
            fs.mkdirSync(filepath);
          } catch (err) {
            return res.end('0');
          }
          return res.end('1');
      }
    case 'DELETE':
      switch (cmd) {
        case 'file':
          if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isFile())
            return res.end('0')
          fs.unlinkSync(filepath)
          return res.end('1');
        case 'dir':
          if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isDirectory())
            return res.end('0')
          if (filepath == folder)
            return res.end('0')
          fs.rmSync(filepath, { recursive: true });
          return res.end('1');
      }
    case 'PATCH':
      let newpath, temp;
      switch (cmd) {
        case 'file':
          if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isFile())
            return res.end('0')
          temp = parsePath(url.params.newpath)
          if (temp == null)
            return res.end('0')
          newpath = joinPath(temp)
          if (fs.existsSync(newpath))
            return res.end('0')
          try {
            fs.renameSync(filepath, newpath)
          } catch (err) {
            return res.end('0');
          }
          return res.end('1');
        case 'dir':
          if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isDirectory())
            return res.end('0')
          temp = parsePath(url.params.newpath)
          if (temp == null)
            return res.end('0')
          newpath = joinPath(temp)
          if (fs.existsSync(newpath))
            return res.end('0')
          try {
            fs.renameSync(filepath, newpath)
          } catch (err) {
            return res.end('0');
          }
          return res.end('1');
      }
  }
  res.end('0');
}).listen(port, () => {
  console.log(`http://127.0.0.1:${port}`)
});

