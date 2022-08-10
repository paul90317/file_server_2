function random() {
    return Math.floor(Math.random() * 100000000);
}
function number2bytes(num){
    bytes = new Uint8Array(4)
    for (let i = 0; i < 4; i++) {
        bytes[3 - i] = len
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
class Cipher{
    constructor(password,nonce){
        this.Snonce=nonce
        this.key=aesjs.utils.hex.toBytes(sha256(this.Snonce + '*' + password))
    }
    encrypt(data,Cnonce){
        let iv=aesjs.utils.hex.toBytes(sha256(this.Snonce+ '*' + Cnonce)).slice(0,16)
        let cipher=new aesjs.ModeOfOperation.ModeOfOperationCBC(this.key,iv)
        let temp=[number2bytes(data.byteLength)]
        temp.push(aesjs.hex.toBytes(sha256(data)))
        temp.push(data)
        let len=data.byteLength+32+4
        if(len%16!=0){
            temp.push(new Uint8Array(16-len%16))
        }
        return cipher.encrypt(Buffer.concat(temp))
    }
    decrypt(data,Cnonce){
        let iv=aesjs.utils.hex.toBytes(sha256(this.Snonce+ '*' + Cnonce)).slice(0,16)
        let cipher=new aesjs.ModeOfOperation.ModeOfOperationCBC(this.key,iv)
        data=cipher.decrypt(data)
        let len= number2bytes(data.slice(0,4))
        let digest=aesjs.utils.hex.fromBytes(data.slice(4,36))
        data=data.slice(36,len+36)
        if(sha256(data)==digest)
            return data
        return null
    }
}

if(typeof module === 'object')
    module.exports = {sha256,aesjs,random,bytes2number,number2bytes,Cipher}