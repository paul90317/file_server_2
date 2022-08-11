# 檔案伺服器
這不是一般的檔案伺服器，這是為了讓使用者在沒有 https 的情況下安全通訊，如果有漏洞 (無論是對 client 或是 server 而言)，歡迎回報。
## 密鑰分發
本伺服器是依靠 server、和 client 都知道密碼的情況下，用該密碼 (password) 與其他隨機碼 (nonce、salt) 產生對稱金鑰 (Session Key) 通訊。
加密演算法 AES，模式 CBC，需要 key、iv，之後會提到如何產生。
信息摘要演算法 sha256
## 禁用 cookie
我雖希望可以常駐登入，但是用 cookie 容易遭受 CSRF 攻擊，所以只會有一個主介面 (index.htm)，透過該介面 fetch 所需要的檔案，這樣密碼就可以存在 memory。
## 重送攻擊
又稱 replay attack，是本伺服器抵禦的重點之一。發生時機是，每次都是由 client 傳送請求，server 再做對檔案操作，並回應 client。就算過程加密，駭客拿 client 請求封包，重新發送，控制 server 完成檔案操作，即便對他沒有意義。url 中，client 將真實的請求加密，並且附帶明文隨機碼 Cnonce，  

>http://127.0.0.1/?c=12685cb59d7229d9f0bb9fbe6120e115&nonce=3675955&padding=7&digest=2b93c1030be447de1f5909bf223180e8277116051f58651bac64e974d60c5e5a
![](https://i.imgur.com/0EkSpBf.png) 
(以上網址表示 ls 指令)  

### 密鑰生成
而 server 每次開機會產生新隨機碼 Snonce 以明文型式隨著腳本 (index.htm) 傳給 client，password 是不洩漏的 (現實通道)，產生 key,iv 的公式如下。
```javascript
function keyGen(password,Snonce){
    return aesjs.utils.hex.toBytes(sha256(password+'*'+Snonce))
}
function ivGen(Cnonce,Snonce){
    return aesjs.utils.hex.toBytes(sha256(Snonce+'*'+Cnonce)).slice(0,16)
}
```
server 確保每次 Cnonce 不一樣，就能抵禦重送攻擊，當 server 重啟時會產生 Snonce，確保不會接受啟動前的重送封包。
## 信息摘要和加密
client、server 為了確認自己的封包是對的，沒被改過，必須要用信息摘要伴隨密文送傳送。
![](https://i.imgur.com/0EkSpBf.png)  
c 就是密文，digest 是摘要，nonce 是隨機碼，padding 是為了將明文填滿一個塊 (16 位元) 所隨機填充的位元組數量 (填隨機位元防止密文填充攻擊)。  
### 傳送資料
可以把 c、digest、padding 視為得到明文並且確認明文沒有被竄改的的必要材料，缺一不可，而 nonce 視為一種工具，用來產生 iv，沒有他也無法解開 c。傳送檔案是特別的情況，因為檔案需要跟網址分開放。網址的材料跟檔案的材料可以分開存，因為如果有人掉包檔案或網址，server 用 nonce 做成的 iv 一定解不開，結論就是這六樣東西隨便放別人也無法竄改，但是可以把檔案跟網址交換，為了避免這件事情，我讓兩者的存放關係不對襯。
* 令 網址明文 $m_0$, 填充 $p_0$,  
* 令 檔案明文 $m_1$, 填充 $p_1$,  
* 令 下載明文 $m_2$, 填充 $p_2$,  
* 令 client 生成隨機數 $c$, server 生成隨機數 $s$, 兩邊都有共識的密碼 $p$
* 雜湊程式 $H(...)$
* 加密程式 $K_{p,c,s}(...)$ 代表以 p,c,s 做成起始向量以及密鑰進行加密，詳請看 [密鑰生成](#密鑰生成)  

server 傳送的 index.htm
* ***In javascript:*** $s$

client 請求檔案、改檔名、刪檔、創資料夾  
* ***In URL:*** $K_{p,c,s}(m_0),\ H(m_0),\ p_0,\ c$  

client 上傳檔案  
* ***In URL:*** $K_{p,c,s}(m_0,\ H(m_1),\ p_1),\ H(m_0),\ p_0,\ c$  
* ***In body:*** $K_{p,c,s}(m_1)$  

server 回傳 response
* ***In headers:*** $K_{p,c,s}(c_2),\ p_2$  
* ***In body:*** $K_{p,c,s}(m_2)$ 

## 編碼流程
以本伺服器最複雜的請求目錄為例子。
1. client 做出 utf-8 請求字串，編碼 bits，進行摘要並加密，解碼成 16 進制字串 (utf-8)，傳送。
2. server 收到 hex (utf-8)，轉二進制 (bits)，解密確認摘要，以 utf-8 解碼成真實請求明文。
3. server 將 dictionary 序列化成字串 (utf-8)，編碼成 bits，摘要並加密，傳送。
4. client 收到 bits，解密並確認摘要，解碼成 utf-8，反序列化成 dictionary。

接這就用 dictionary 渲染網頁，結構如下
```json
{
    "files":["fa.txt","fb.txt"],
    "dirs":["d1","d2"]
}
```
![](https://i.imgur.com/JLIFBln.png)
## 功能
* 順向訪問、逆向訪問 (透過 GUI)
* 上傳 (多檔案)、下載檔案
* 絕對路徑重新命名，包含檔案及資料夾
* 下載資料夾 (zip)
* 刪除資料夾、檔案
## 如何啟動
安裝
```sh
npm init
npm install
```
啟動
```sh
node server.js
```
建立 config 檔並且啟動
```sh
node server.js -a config.json
```