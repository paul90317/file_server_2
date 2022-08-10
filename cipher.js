function random() {
    return Math.floor(Math.random() * 100000000);
}
function number2bytes(num){
    bytes = new Uint8Array(4)
    for (let i = 0; i < 4; i++) {
        bytes[3 - i] = num
        num >>= 8
    }
    return bytes
}
function bytes2number(bytes){
    let num = 0
    for (let i = 0; i < 4; i++) {
        num <<= 8;
        num += bytes[i];
    }
    return num
}
function keyGen(password,Snonce){
    return aesjs.utils.hex.toBytes(sha256(password+'*'+Snonce))
}
function ivGen(Cnonce,Snonce){
    return aesjs.utils.hex.toBytes(sha256(Snonce+'*'+Cnonce)).slice(0,16)
}
class Cipher{
    constructor(key,iv){
        this.cipher=new aesjs.ModeOfOperation.cbc(key,iv)
    }
    encrypt(data){
        let len=data.byteLength+32+4
        if(len%16!=0){
            len+=16-len%16
        }
        
        let ret=new Uint8Array(len)
        ret.set(number2bytes(data.byteLength),0)
        ret.set(aesjs.utils.hex.toBytes(sha256(data)),4)
        ret.set(data,36)
        ret=this.cipher.encrypt(ret)
        return ret
    }
    decrypt(data){
        data=this.cipher.decrypt(data)
        let len= bytes2number(data.subarray(0,4))
        let digest=aesjs.utils.hex.fromBytes(data.subarray(4,36))
        if(len+36>data.byteLength)
            return null
        data=data.subarray(36,len+36)
        if(sha256(data)==digest)
            return data
        return null
    }
}

if(typeof module === 'object'){
    var sha256 = require('js-sha256').sha256;
    var aesjs = require('aes-js');
    module.exports = {random,Cipher,keyGen,ivGen} 
}