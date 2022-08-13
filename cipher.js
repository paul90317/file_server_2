

if (typeof module === 'object') {
    var sha256 = require('js-sha256').sha256;
    var aesjs = require('aes-js');
}

function random() {
    return Math.floor(Math.random() * 100000000);
}

class Cipher {
    constructor(password,Cnonce,Snonce) {
        this.key = aesjs.utils.hex.toBytes(sha256(Cnonce+'*'+password + '*' + Snonce))
        this.iv = aesjs.utils.hex.toBytes(sha256(Snonce + '*' + Cnonce)).slice(0, 16)
        this.salt=sha256(Cnonce + '*' + Snonce)
    }
    hashf(data) {
        return sha256(this.salt+sha256(data))
    }
    encrypt(data) {
        let cipher = new aesjs.ModeOfOperation.cbc(this.key, this.iv)
        let len = data.length
        let rem = len % 16
        let padding = (16 - rem) % 16
        len += padding
        let ret = new Uint8Array(len)
        ret.set(data, 0)
        ret = cipher.encrypt(ret)
        return [padding, this.hashf(data), ret]//cpack
    }
    decrypt(cpack) {
        let cipher = new aesjs.ModeOfOperation.cbc(this.key, this.iv)
        let padding = cpack[0]
        let digest = cpack[1]
        let data = cpack[2]
        data = cipher.decrypt(data)
        if (data.length - padding < 0)
            return null
        data = data.subarray(0, data.length - padding)
        if (this.hashf(data) != digest)
            return null
        return data
    }
    /*encrypt_stream(streamIn, streamOut) {
        return new Promise((resolve, reject) => {
            let cipher = new aesjs.ModeOfOperation.ecb(this.key)
            let block = new Uint8Array(this.iv);
            let hash = sha256.create()
            let j = 0
            return streamIn.on('data', data => {
                hash.update(data)
                for (let i = 0; i < data.length; i++) {
                    if (j == 16) {
                        j = 0;
                        block = cipher.encrypt(block)
                        streamOut.write(Buffer.from(block))
                    }
                    block[j] ^= data[i]
                    j++
                }
            }).on('end', () => {
                block = cipher.encrypt(block)
                streamOut.write(Buffer.from(block))
                streamOut.close();
                return resolve([16 - j, hash.hex()])
            })
        })
    }
    decrypt_stream(streamIn, streamOut, digest, padding) {
        return new Promise((resolve, reject) => {
            let cipher = new aesjs.ModeOfOperation.ecb(this.key)
            let last = new Uint8Array(this.iv)
            let block = new Uint8Array(16)
            let ppart = new Uint8Array(0)
            let hash = sha256.create()
            let j = 0
            if (padding >= 16 || padding < 0)
                return resolve(false)
            streamIn.on('data', chunk => {
                for (let i = 0; i < chunk.length; i++) {
                    block[j] = chunk[i]
                    j++
                    if (j == 16) {
                        let temp = new Uint8Array(block)
                        block = cipher.decrypt(block)
                        j = 0;
                        for (let k = 0; k < 16; k++) {
                            block[k] ^= last[k]
                        }
                        last = temp;
                        hash.update(ppart)
                        hash.update(block.subarray(0,16-padding))
                        ppart=block.slice(16-padding)
                        streamOut.write(Buffer.from(block))
                    }
                }
            }).on('end', () => {
                streamOut.close()
                if(j!=0)
                    return resolve(false)
                if(hash.hex()!=digest)
                    return resolve(false)
                return resolve(true)
            })
        })
    }*/
}

if (typeof module === 'object') {
    module.exports = { random, Cipher }
}