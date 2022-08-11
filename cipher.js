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
        this.key=key
        this.iv=iv
    }
    encrypt(data){
        let cipher=new aesjs.ModeOfOperation.cbc(this.key,this.iv)
        let len=data.byteLength
        let rem=len%16
        let padding=(16-rem)%16
        len+=padding
        let ret=new Uint8Array(len)
        ret.set(data,0)
        for(let i=ret.byteLength-padding;i<ret.byteLength;i++)
            ret[i]=random()%256
        //console.log(1,ret)
        ret=cipher.encrypt(ret)
        //console.log(2,ret)
        return [padding,sha256(data),ret]//cpack
    }
    decrypt(cpack){
        let cipher=new aesjs.ModeOfOperation.cbc(this.key,this.iv)
        let padding=cpack[0]
        let digest=cpack[1]
        let data=cpack[2]
        //console.log(3,data)
        data=cipher.decrypt(data)
        //console.log(4,data)
        if(data.byteLength-padding<0)
            return null
        data=data.subarray(0,data.byteLength-padding)
        if(sha256(data)!=digest)
            return null
        return data
    }
}
class StreamChipher{
    constructor(key){
        this.key=key
    }
    
    encrypt(streamIn,streamOut,iv){
        let first=true;
        streamIn.on('data',chunk=>{
            if(first){
                first=false;
                
            }else{

            }
        }).on('end',()=>{

        })
    }
    decrypt(streamIn,streamOut){
        
    }
}
if(typeof module === 'object'){
    var sha256 = require('js-sha256').sha256;
    var aesjs = require('aes-js');
    module.exports = {random,Cipher,keyGen,ivGen} 
}