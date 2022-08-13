# 加密檔案伺服器
這不是一般的檔案伺服器，這是為了讓使用者在沒有 https 的情況下安全通訊，如果有漏洞 (無論是對 client 或是 server 而言)，歡迎回報。  
### 動機
對 nas 有興趣，於是自己在家設定路由，買樹梅派，建立自己的檔案伺服器。
## 密鑰分發
本伺服器是依靠 server、和 client 都知道密碼的情況下，用該密碼 (password) 與其他隨機碼 (nonce) 產生對稱金鑰 (Session Key) 通訊。一開始會要求使用者輸入密碼。加密演算法 AES，模式 CBC，需要 key、iv，之後會提到如何產生。
信息摘要演算法 sha256
## 禁用 cookie
我雖希望可以常駐登入，但是用 cookie 容易遭受 CSRF 攻擊，所以只會有一個主介面 (index.htm)，透過該介面 fetch 所需要的檔案，這樣密碼就可以存在 memory。
## 重送攻擊
又稱 replay attack，是本伺服器抵禦的重點之一。發生時機是，每次都是由 client 傳送請求，server 再做對檔案操作，並回應 client。就算過程加密，駭客拿 client 請求封包，重新發送，控制 server 完成檔案操作，即便對他沒有意義。url 中，client 將真實的請求加密，並且附帶明文隨機碼 Cnonce，  

>http://127.0.0.1/?c=12685cb59d7229d9f0bb9fbe6120e115&nonce=3675955&padding=7&digest=2b93c1030be447de1f5909bf223180e8277116051f58651bac64e974d60c5e5a  
![](https://i.imgur.com/0EkSpBf.png)  
(以上網址表示 ls 指令)  

### 隨機密鑰生成
而 server 每次開機會產生新隨機碼 Snonce 以明文型式隨著腳本 (index.htm) 傳給 client，password 是不洩漏的 (現實通道)，產生 key、iv 的公式如下。
```javascript
constructor(password,Cnonce,Snonce) {
    this.key = aesjs.utils.hex.toBytes(sha256(Cnonce+'*'+password + '*' + Snonce))
    this.iv = aesjs.utils.hex.toBytes(sha256(Snonce + '*' + Cnonce)).slice(0, 16)
    this.salt=sha256(Cnonce + '*' + Snonce)
}
```
server 確保每次 Cnonce 不一樣，就能抵禦重送攻擊，當 server 重啟時會產生 Snonce，確保不會接受啟動前的重送封包。
## 信息摘要和加密
client、server 為了確認自己的封包是對的，沒被改過，必須要用信息摘要伴隨密文送傳送。  
![](https://i.imgur.com/0EkSpBf.png)  
c 就是密文，digest 是摘要，nonce 是隨機碼，padding 是為了將明文填滿一個塊 (16 位元) 所填充的位元組數量。  
可以把 c、digest、padding 視為得到明文並且確認明文沒有被竄改的的必要材料，缺一不可，而 nonce、password 視為一種工具，用來產生 iv、key，沒有他們也無法解開 c。傳送檔案是特別的情況，因為檔案需要跟網址分開放。網址的材料跟檔案的材料可以分開存，因為如果有人掉包檔案或網址，接收方一定解不開 (如下圖)，結論就是這六樣東西隨便放別人也無法竄改，但是可以把檔案跟網址交換，為了避免這件事情，我讓兩者的存放關係不對襯。  
生成 client 隨機數 $nc$、server 隨機數 $ns$、兩邊都有共識的密碼 $psw$，由這三樣物品當作參數產生的密鑰及初始向量可以保證不被重送攻擊。  
**加密程式** $(c,\ d,\ p)\ =\ K_{nc,\ ns,\ psw}(m)$ 代表以 $nc,\ ns,\ psw$ 做成起始向量以及密鑰進行加密 (詳請看 [密鑰生成](#密鑰生成)) ，應該要產生 $(c,\ d,\ p)$，也就是 密文、摘要、填充數 (注意，並沒有一種加密演算法可以將明文轉成密文又產生雜湊值，是 AES 產生密文和填充，而 SHA256 生成明文雜湊值，而我的加密程式就是做這兩件事)。而解密就是 $m\ =\ K^{-1}_{nc,\ ns,\ psw}(c,\ d,\ p)$，它不只解密而且可以由摘要(雜湊值)驗證封包是否被駭客修改。加密、解密簡寫成 $K(m)$、 $K^{-1}(c,\ d,\ p)$。SHA256 不會對加密的 padding 進行雜湊，否則駭客可以透過修改 padding 長度來偽造明文。 
### 加密  
![](https://i.imgur.com/sGIDCgi.png)
###  解密  
![](https://i.imgur.com/vLSHtBS.png) 
## 訊息傳送
### server 傳送帶有 $ns$ 的 index.htm  
**In javascript:** $ns$
### client 傳送的 CRUD 命令 $m_0$  
>$(c_0,\ d_0,\ p_0)\ =\ K(m_0)$  

**In URL:** $c_0,\ d_0\,\ p_0,\ nc$  
### client 上傳檔案  
先將 body (檔案) $m_1$ 加密  
>$(c_1,\ d_1,\ p_1)\ =\ K(m_1)$  

將路徑訊息 $m_0$ 與 $d_1$、 $p_1$ 組合成 $m_0'$  
>$m_0'\ =\ (m_0,\ d_1,\ p_1)$  

將 $m_0'$ 加密  
>$(c_0',\ d_0',\ p_0')\ =\ K(m_0')$  

**In URL:** $c_0',\ d_0',\ p_0',\ nc$  
**In body:** $c_1$  

### server 回傳 response $m_2$  
**In headers:** $d_2,\ p_2$  
**In body:** $c_2$  

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
## 更新
### 加鹽雜湊
我原本的加密方法會導致相同的指令，例如取得根目錄，其摘要會是一樣的，這會給駭客留下線索，可能透過一些機器學習得到我們的資料夾結構，為了不要讓駭客得到訊息，我在雜湊中加鹽 [(Cnonce、Snonce 的產物)](#隨機密鑰生成)。  
```javascript
hashf(data) {
    return sha256(this.salt+sha256(data))
}
```
### 讀寫權限
一開始需輸入使用者，如果輸入錯誤將只能讀，使用者會以隨機碼做加鹽雜湊，每次的值皆不同，並且跟著網址一起加密。
