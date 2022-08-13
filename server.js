var port = 80;
var folder = 'folder'
var password = '123';
let config_filepath = 'config.json'
let add_config = false

for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] == '-a')
    add_config = true;
  else
    config_filepath = process.argv[i]
}

const fs = require('fs')
if (fs.existsSync(config_filepath)) {
  let data = fs.readFileSync(config_filepath)
  data = JSON.parse(data)
  port = data.port
  folder = data.folder
  password = data.password
}

if (add_config) {
  fs.writeFileSync(config_filepath, JSON.stringify({
    folder: folder,
    port: port,
    password: password
  }))
}

const aesjs = require('aes-js');
const mc = require('./cipher')
var Snonce = mc.random()
var key = mc.keyGen(password, Snonce)
var used_nonces = new Set();

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
const { argv } = require('process');

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
  let digest = url.params.digest
  let padding = parseInt(url.params.padding)

  //check format
  if (Cnonce == undefined || ciphertext == undefined || digest == undefined || padding == undefined)
    if (req.method == 'GET') {
      if (req.url == '/')
        return res.end(fs.readFileSync(__dirname + '/index.htm').toString().replace('{server_code}', Snonce))
      if (req.url == '/chipher.js')
        return res.end(fs.readFileSync(__dirname + '/cipher.js'))
      res.statusCode = 404;
      return res.end()
    }

  //check fresh
  if (used_nonces.has(Cnonce)) {
    res.setHeader('status', '1')
    return res.end()
  }
  if (used_nonces.size > 300) {
    Snonce = mc.random()
    key = mc.keyGen(password, Snonce)
    used_nonces.clear();
  }

  //decrypt request
  let iv = mc.ivGen(Cnonce, Snonce)
  let cipher = new mc.Cipher(key, iv)
  try {
    let data = aesjs.utils.hex.toBytes(ciphertext)
    data = cipher.decrypt([padding, digest, data])
    url = aesjs.utils.utf8.fromBytes(data)
    url = parseURL(url)
  } catch (err) {
    console.log(err)
    res.setHeader('status', '2')
    return res.end()
  }
  used_nonces.add(Cnonce)

  //parse request
  let paths = parsePath(url.path)
  if (paths == null) {
    res.setHeader('status', '5')
    return res.end()
  }
  let cmd = paths.shift();
  let filepath = joinPath(paths)
  
  //crud
  switch (cmd) {
    case 'ls': {
      if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isDirectory()) {
        res.setHeader('status', '3')
        return res.end();
      }
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
      res.setHeader('padding', data[0].toString())
      res.setHeader('digest', data[1])
      res.setHeader('status', '0')
      return res.end(Buffer.from(data[2]));
    }
    case 'file': {
      if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isFile()) {
        res.setHeader('status', '3')
        return res.end();
      }
      let data = fs.readFileSync(filepath);
      data = new Uint8Array(data)
      data = cipher.encrypt(data)
      res.setHeader('padding', data[0].toString())
      res.setHeader('digest', data[1])
      res.setHeader('status', '0')
      return res.end(Buffer.from(data[2]));
    }
    case 'zip': {
      if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isDirectory()) {
        res.setHeader('status', '3')
        return res.end()
      }
      let zip = new jszip();
      addFilesFromDirectoryToZip(filepath + '/', zip);
      let stream = zip.generateNodeStream()
      let data = []
      return stream.on('data', chunk => {
        data.push(chunk)
      }).on('end', () => {
        data = new Uint8Array(Buffer.concat(data))
        data = cipher.encrypt(data)
        res.setHeader('padding', data[0].toString())
        res.setHeader('digest', data[1])
        res.setHeader('status', '0')
        return res.end(Buffer.from(data[2]));
      })
    }
    case 'upload': {
      let data = [];
      if (fs.existsSync(filepath)) {
        res.setHeader('status', '3')
        return res.end()
      }
      return req.on('data', chunk => {
        data.push(chunk);
      }).on('end', () => {
        try {
          data = Buffer.concat(data)
          data = new Uint8Array(data)
          digest = url.params.digest
          padding = parseInt(url.params.padding)
          data = cipher.decrypt([padding, digest, data])
          fs.writeFileSync(filepath, data, { flag: 'w+' });
        } catch (err) {
          console.log(err)
          res.setHeader('status', '3')
          return res.end();
        }
        res.setHeader('status', '0')
        return res.end();
      });
    }
    case 'mkdir': {
      if (fs.existsSync(filepath)) {
        res.setHeader('status', '3')
        return res.end();
      }
      try {
        fs.mkdirSync(filepath);
      } catch (err) {
        res.setHeader('status', '3')
        return res.end();
      }
      res.setHeader('status', '0')
      return res.end();
    }
    case 'rnfile': {
      if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isFile()) {
        res.setHeader('status', '3')
        return res.end()
      }
      temp = parsePath(url.params.newpath)
      if (temp == null) {
        res.setHeader('status', '3')
        return res.end()
      }
      newpath = joinPath(temp)
      if (fs.existsSync(newpath)) {
        res.setHeader('status', '3')
        return res.end()
      }
      try {
        fs.renameSync(filepath, newpath)
      } catch (err) {
        res.setHeader('status', '3')
        return res.end();
      }
      res.setHeader('status', '0')
      return res.end();
    }
    case 'rndir': {
      if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isDirectory()) {
        res.setHeader('status', '3')
        return res.end()
      }
      temp = parsePath(url.params.newpath)
      if (temp == null) {
        res.setHeader('status', '3')
        return res.end()
      }
      newpath = joinPath(temp)
      if (fs.existsSync(newpath)) {
        res.setHeader('status', '3')
        return res.end()
      }
      try {
        fs.renameSync(filepath, newpath)
      } catch (err) {
        res.setHeader('status', '3')
        return res.end()
      }
      res.setHeader('status', '0')
      return res.end()
    }
    case 'rmfile': {
      if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isFile()) {
        res.setHeader('status', '3')
        return res.end()
      }
      fs.unlinkSync(filepath)
      res.setHeader('status', '0')
      return res.end()
    }
    case 'rmdir': {
      if (!fs.existsSync(filepath) || !fs.lstatSync(filepath).isDirectory()) {
        res.setHeader('status', '3')
        return res.end()
      }
      if (filepath == folder) {
        res.setHeader('status', '3')
        return res.end()
      }
      fs.rmSync(filepath, { recursive: true });
      res.setHeader('status', '0')
      return res.end()
    }
    default: {
      res.setHeader('status', '4')
      return res.end();
    }
  }
}).listen(port, () => {
  console.log(`http://127.0.0.1:${port}`)
});