const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const upload = multer({ storage: multer.memoryStorage() });
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 1. OBJEK & FUNGSI DEKRIPTOR HC (URL / DECRYPT)
// ==========================================
const HC = {
  initialXor: Buffer.from("e382e4b8adc386f09f9293", "hex"),
  nonce: Buffer.alloc(8, 0xdb),
  keys: [
    "2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d",
    "3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372",
    "cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3",
    "4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193",
    "f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63",
    "81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c",
    "45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944",
    "3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"
  ].map(x => Buffer.from(x, "hex")),
  rstKeys: [
    "JN1k3YHc2.6_v235", "JN1k3YHc_2.7_v71", "JN1k3YHc2.7.ps69",
    "JN1k3YHc2.7.6950", "Jn1K3yHc2.8.ps08", "Jn1K3yHc2.9.ps6c",
    "Zk:L7>WKaiK*s9>D", "!<f!&WIlM**R.B0X", "b4a5opinx2uloec6"
  ],
  jklOld: Buffer.from([0xd5,0xd4,0xd3,0xd2,0xd1,0xd0,0xcf,0xce,0xcd,0xcc,0xbd,0xbc,0xbb,0xba,0xb9,0xb8,0xb7,0xb6,0xb5,0xb4]),
  jklNew: Buffer.from([8,9,10,11,12,13,14,15,17,17,5,4,3,2,1,0,255,254,253,252]),
  rstXor: Buffer.from(Array.from({length:20}, (_,i)=>i+2)),
  braille: "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚",
  tokenMap: [
    "payload","proxy","lockAllConfig","blockedByRoot","expiryTime","noteEnabled","notes","sshField",
    "mobileDataAndLockProvider","unlockUserAndPass","ovpnConfig","ovpnUserAndPass","sni","unlockUserAndPass2",
    "unknown14","blockedByHwid","cloudconfig","psiphon","name","blockArea","connectionMode","blockedByPassword",
    "unknown22","extraSniffer","psiphon2","v2rayEnabled","v2rayConfig","version","slowdnsEnabled","slowdnsServer",
    "slowdnsPublickey","dnsResolver"
  ]
};

function hcCleanHex(s) {
  if (!s) return "";
  const clean = String(s).replace(/[^0-9a-f]/gi, "");
  return clean.length % 2 ? "0" + clean : clean;
}
function hcIsHex(s) { return !!s && String(s).length >= 16 && /^[0-9a-f]+$/i.test(String(s)); }
function hcPrintable(s, strict=false) {
  if (!s) return false;
  if (s.length < 4) return true;
  let n=0;
  for (const c of s) { const x=c.charCodeAt(0); if ((x>=32 && x<=126) || x===9 || x===10 || x===13) n++; }
  return n/s.length > (strict ? .90 : .80);
}
function hcRotl32(x,n){ return ((x<<n)|(x>>>(32-n)))>>>0; }
function hcQR(s,a,b,c,d){
  s[a]=(s[a]+s[b])>>>0; s[d]^=s[a]; s[d]=hcRotl32(s[d],16);
  s[c]=(s[c]+s[d])>>>0; s[b]^=s[c]; s[b]=hcRotl32(s[b],12);
  s[a]=(s[a]+s[b])>>>0; s[d]^=s[a]; s[d]=hcRotl32(s[d],8);
  s[c]=(s[c]+s[d])>>>0; s[b]^=s[c]; s[b]=hcRotl32(s[b],7);
}
function hcChaCha20(data,key,nonce,counter=0){
  if (key.length!==32 || nonce.length!==8) throw new Error("ChaCha20 key/nonce invalid");
  const out=Buffer.alloc(data.length);
  for(let off=0, block=counter>>>0; off<data.length; off+=64,block++){
    const st=new Uint32Array(16);
    st[0]=0x61707865; st[1]=0x3320646e; st[2]=0x79622d32; st[3]=0x6b206574;
    for(let i=0;i<8;i++) st[4+i]=key.readUInt32LE(i*4);
    st[12]=block; st[13]=0; st[14]=nonce.readUInt32LE(0); st[15]=nonce.readUInt32LE(4);
    const x=new Uint32Array(st);
    for(let i=0;i<10;i++){
      hcQR(x,0,4,8,12); hcQR(x,1,5,9,13); hcQR(x,2,6,10,14); hcQR(x,3,7,11,15);
      hcQR(x,0,5,10,15); hcQR(x,1,6,11,12); hcQR(x,2,7,8,13); hcQR(x,3,4,9,14);
    }
    const stream=Buffer.alloc(64);
    for(let i=0;i<16;i++) stream.writeUInt32LE((x[i]+st[i])>>>0,i*4);
    const n=Math.min(64,data.length-off);
    for(let i=0;i<n;i++) out[off+i]=data[off+i]^stream[i];
  }
  return out;
}
function hcABC(raw,key,nonce=HC.nonce){
  try{
    const hex=hcCleanHex(raw);
    if(!hex) return "";
    const data=Buffer.from(hex,"hex");
    if(data.length<=16) return "";
    return hcChaCha20(data.subarray(0,-16),key,nonce,1).toString("utf8");
  }catch{return "";}
}
function hcZ3A(data,iv){
  if(!data) return "";
  const out=[];
  const re=/(-?\d+)\.(-?\d+)/g;
  let m;
  while((m=re.exec(String(data)))){
    try{
      const a=Number(m[1])-iv, b=Number(m[2])-iv;
      const divisor=2**b;
      if(divisor!==0 && Number.isFinite(divisor)) out.push(((Math.floor(a/divisor)%256)+256)%256);
    }catch{}
  }
  return Buffer.from(out).toString("utf8");
}
function hcBraille(s){
  try{
    const out=[];
    for(let i=0;i<s.length-1;i+=2){
      const a=HC.braille.indexOf(s[i]), b=HC.braille.indexOf(s[i+1]);
      if(a<0||b<0) return s;
      out.push((a*16+b)&255);
    }
    return Buffer.from(out).toString("utf8");
  }catch{return s;}
}
function hcCredentials(raw,isSSH=false){
  if(!raw) return raw;
  if(isSSH && HC.braille.includes(raw[0])) raw=hcBraille(raw);
  const re=isSSH ? /^([\w.-]+):([\d-]+)@(.+):(.+)$/ : /^([^:]+):(.+)$/;
  const m=String(raw).match(re);
  if(!m) return raw;
  const u=m[m.length-2], p=m[m.length-1];
  const uc=(hcZ3A(u,(u.match(/-?\d+\.-?\d+/g)||[]).length)||u);
  const pc=(hcZ3A(p,(p.match(/-?\d+\.-?\d+/g)||[]).length)||p);
  return isSSH ? `${m[1]}:${m[2]}@${uc}:${pc}` : `${uc}:${pc}`;
}
function hcB64Decode(s){
  let x=String(s||"");
  const pad=x.length%4;
  if(pad) x += "=".repeat(4-pad);
  return Buffer.from(x,"base64");
}
function hcJKL(input,isNew=false){
  if(!input) return input;
  try{
    const key=isNew?HC.jklNew:HC.jklOld;
    const data=hcB64Decode(input);
    for(let i=0;i<data.length;i++){
      const d=data[i], k=key[i%20];
      data[i]=(((d^0xff)&0xca)|(d&0x35)) ^ (((k^0xff)&0xca)|(k&0x35));
    }
    return hcB64Decode(data.toString("utf8")).toString("utf8");
  }catch{return input;}
}
function hcRST(input){
  try{
    const src=Buffer.from(String(input),"utf8"), x=Buffer.alloc(src.length);
    for(let i=0;i<src.length;i++) x[i]=src[i]^HC.rstXor[i%20];
    const ct=Buffer.from(x.toString("utf8"),"base64");
    for(const key of HC.rstKeys){
      try{
        const crypto=require("crypto");
        const d=crypto.createDecipheriv("aes-128-ecb",Buffer.from(key),null);
        d.setAutoPadding(true);
        const out=Buffer.concat([d.update(ct),d.final()]).toString("utf8");
        if(out.includes("[splitConfig]")) return out;
      }catch{}
    }
  }catch{}
  return null;
}
function hcDecryptField(token,nonce){
  if(!token || ["true","false","lifeTime","[splitPsiphon][splitPsiphon]"].includes(token) || token.startsWith("<")) return token;
  const candidates=[];
  const clean=hcCleanHex(token);
  if(hcIsHex(clean) && clean.length>=32){ try{ candidates.push(Buffer.from(clean,"hex")); }catch{} }
  if(String(token).length>16){ try{ candidates.push(Buffer.from(token,"latin1")); }catch{} try{ candidates.push(Buffer.from(token,"utf8")); }catch{} }
  const seen=new Set();
  for(const data of candidates){
    const id=data.toString("hex"); if(seen.has(id)) continue; seen.add(id);
    if(data.length<=16) continue;
    const ct=data.subarray(0,-16);
    for(const key of HC.keys){
      try{
        const dec=hcChaCha20(ct,key,nonce,1).toString("utf8");
        for(const isNew of [true,false]){
          const out=hcJKL(dec,isNew);
          if(out!==dec && hcPrintable(out)) return out;
        }
        if((hcPrintable(dec,true) && /HTTP|@|:|\{/.test(dec)) || /^[A-Za-z0-9]+$/.test(dec)) return dec;
      }catch{}
    }
  }
  for(const isNew of [true,false]){
    const out=hcJKL(token,isNew);
    if(out!==token && hcPrintable(out)) return out;
  }
  return token;
}
function hcInitial(fileBytes){
  let latin;
  try { latin = Buffer.from(fileBytes.toString("utf8"), "latin1"); }
  catch { latin = fileBytes; }
  const out=Buffer.alloc(latin.length);
  for(let i=0;i<latin.length;i++) out[i]=latin[i]^HC.initialXor[i%HC.initialXor.length];
  return out.toString("utf8");
}
function hcParseModern(buffer){
  try{
    if(!Buffer.isBuffer(buffer)||!buffer.length) return {success:false,error:"File kosong"};
    const hexPayload=hcInitial(buffer);
    const outer=hcABC(hexPayload,HC.keys[5]);
    if(!outer || !outer.trim().startsWith("{")) return {success:false,error:"Outer decrypt gagal"};
    const obj=JSON.parse(outer);
    if(!obj || typeof obj!=="object") return {success:false,error:"JSON HC tidak valid"};

    const cfg=(obj.cfg && typeof obj.cfg==="object")?obj.cfg:{};
    const isNew=Object.prototype.hasOwnProperty.call(cfg,"content");
    const meta={}, protections={};
    let target, delim;

    if(isNew){
      for(const [k,name] of [["b","hwid"],["f","area"]]){
        const val=String(obj[k] ?? cfg[k] ?? "");
        if(val){meta[name]=val;protections[name]=val;}
      }
      target=cfg.content; delim="[splitConfig]";
    }else{
      const a=(obj.a && typeof obj.a==="object")?obj.a:{};
      for(const [k,name] of [["bb","hwid"],["e","password"],["fe","area"],["ed","provider"]]){
        const val=k==="e"?obj[k]:a[k];
        if(val){ const dec=hcABC(String(val),HC.keys[7]); if(dec){meta[name]=dec;protections[name]=dec;} }
      }
      target=obj.xy || a.xy;
      delim=obj.uv || a.uv;
    }
    if(!target || !delim) return {success:false,error:"Payload/delimiter tidak ditemukan"};

    const toHex=s=>Buffer.from(String(s||""),"utf8").toString("hex");
    const h=meta.hwid,p=meta.password,pr=meta.provider,a=meta.area;
    const derived=(h && !p && !pr && !a) ? toHex(h)+toHex(h) : toHex(p)+toHex(h)+toHex(pr)+toHex(a);
    const dyn=Buffer.from(HC.nonce);
    if(derived){
      try{ const b=Buffer.from(derived,"hex").subarray(0,8); b.copy(dyn,0,0,b.length); }catch{}
    }

    let xyDec=null;
    if(isNew){
      xyDec=hcRST(String(target));
      if(!xyDec){
        for(const key of HC.keys){ const t=hcABC(String(target),key); if(t && t.includes(delim)){xyDec=t;break;} }
      }
    }else{
      xyDec=hcABC(String(target),HC.keys[1]);
    }
    if(!xyDec) return {success:false,error:"Isi konfigurasi gagal didekripsi"};

    const config={};
    const tokens=xyDec.split(String(delim));
    for(let i=0;i<tokens.length;i++){
      if(i===22||i===24) continue;
      const label=HC.tokenMap[i]||`field_${i}`;
      let out=tokens[i];
      if(isNew) out=hcDecryptField(out,dyn);
      else{
        if(hcIsHex(out)) out=hcABC(out,HC.keys[7],dyn);
        out=hcJKL(out,false);
      }
      if(i===7) out=hcCredentials(out,true);
      else if(i===11) out=hcCredentials(out,false);
      if(typeof out==="string"){
        out=out.replace(/88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d/g,"");
        if(/^[\[{]/.test(out)){ try{out=JSON.parse(out);}catch{} }
      }
      if(out && !(typeof out==="string" && hcIsHex(out))) config[label]=out;
    }
    if (config.sshField) {
      const sv = hcCredentials(config.sshField, true);
      const sm = String(sv).match(/^([^:]+):(\d+)@(.+):(.+)$/);
      config.ssh = sm ? {host: sm[1], port: sm[2], username: sm[3], password: sm[4]} : {};
    }
    return {success:true,config,protections,raw:xyDec,format:isNew?"new":"old"};
  }catch(e){ return {success:false,error:e.message||"Decrypt error"}; }
}


// ==========================================
// 2. ENDPOINT API EXPRESS
// ==========================================

// Endpoint API untuk Mendapatkan Daftar Operator dari Folder /bug
app.get('/api/operators', (req, res) => {
  try {
    const bugDir = path.join(__dirname, 'bug');
    if (!fs.existsSync(bugDir)) return res.json({ success: true, operators: [] });
    const files = fs.readdirSync(bugDir);
    const operators = files.filter(f => f.endsWith('.json')).map(file => path.basename(file, '.json'));
    res.json({ success: true, operators });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Endpoint API untuk Dekripsi File .hc
app.post('/api/decrypt', upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: "File .hc tidak ditemukan" });
    const result = hcParseModern(req.file.buffer);
    res.json(result);
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Endpoint API untuk Generate Config berdasarkan Bug Operator
app.post('/api/generate', (req, res) => {
  try {
    const { operator, credential } = req.body;
    if (!operator || !credential) return res.status(400).json({ success: false, error: "Operator dan kredensial wajib diisi!" });

    const bugFilePath = path.join(__dirname, 'bug', `${operator.toLowerCase()}.json`);
    if (!fs.existsSync(bugFilePath)) {
      return res.status(404).json({ success: false, error: `File bug untuk operator ${operator} tidak ditemukan!` });
    }

    const bugData = JSON.parse(fs.readFileSync(bugFilePath, 'utf8'));
    const regex = /^([\w.-]+):(\d+)@([^:]+):(.+)$/;
    const match = credential.trim().match(regex);
    if (!match) return res.status(400).json({ success: false, error: "Format kredensial salah! Gunakan: host:port@username:password" });

    const [, host, port, username, password] = match;
    const configTemplate = new Array(HC.tokenMap.length).fill("");
    
    configTemplate[0] = bugData.payload;
    configTemplate[1] = `${host}:${port}`;
    configTemplate[6] = `Config ${bugData.operator.toUpperCase()} by Web Tools`;
    configTemplate[7] = `${username}:${password}@${host}:${port}`;
    configTemplate[12] = bugData.bug;
    configTemplate[27] = "3.0";

    const rawConfigString = configTemplate.join("[splitConfig]");
    res.json({ success: true, rawConfig: rawConfigString });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

module.exports = app;
