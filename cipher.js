function random() {
    return Math.floor(Math.random() * 100000000);
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
        let len=data.byteLength+9//8+1
        let rem=len%16
        if(rem!=0){
            len+=16-rem
        }
        let ret=new Uint8Array(len)
        ret.set(new Uint8Array([(16-rem)%16]),0)
        ret.set(aesjs.utils.hex.toBytes(sha256(data)).slice(3,11),1)
        ret.set(data,9)
        ret=this.cipher.encrypt(ret)
        return ret
    }
    decrypt(data){
        data=this.cipher.decrypt(data)
        let rem= data[0]
        let digest=aesjs.utils.hex.fromBytes(data.subarray(1,9))
        if(9>=data.byteLength-rem)
            return null
        data=data.subarray(9,data.byteLength-rem)
        if(sha256(data).substring(6,22)==digest)
            return data
        return null
    }
}

if(typeof module === 'object'){
    var sha256 = require('js-sha256').sha256;
    var aesjs = require('aes-js');
    module.exports = {random,Cipher,keyGen,ivGen} 
}