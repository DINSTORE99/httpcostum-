const express = require("express");
const multer = require("multer");
const crypto = require("crypto");
const path = require("path");
const argon2 = require("argon2");

const app = express();

const PORT = process.env.PORT || 3000;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 20 * 1024 * 1024
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));


/* =========================================================
   =========================================================
                  HTTP CUSTOM (.HC)
   =========================================================
   ========================================================= */

const HC = {
  initialXor: Buffer.from(
    "e382e4b8adc386f09f9293",
    "hex"
  ),

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
    "JN1k3YHc2.6_v235",
    "JN1k3YHc_2.7_v71",
    "JN1k3YHc2.7.ps69",
    "JN1k3YHc2.7.6950",
    "Jn1K3yHc2.8.ps08",
    "Jn1K3yHc2.9.ps6c",
    "Zk:L7>WKaiK*s9>D",
    "!<f!&WIlM**R.B0X",
    "b4a5opinx2uloec6"
  ],

  jklOld: Buffer.from([
    0xd5,0xd4,0xd3,0xd2,0xd1,
    0xd0,0xcf,0xce,0xcd,0xcc,
    0xbd,0xbc,0xbb,0xba,0xb9,
    0xb8,0xb7,0xb6,0xb5,0xb4
  ]),

  jklNew: Buffer.from([
    8,9,10,11,12,13,14,15,
    17,17,5,4,3,2,1,0,
    255,254,253,252
  ]),

  rstXor: Buffer.from(
    Array.from({length:20}, (_,i)=>i+2)
  ),

  braille:
    "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚",

  tokenMap: [
    "payload",
    "proxy",
    "lockAllConfig",
    "blockedByRoot",
    "expiryTime",
    "noteEnabled",
    "notes",
    "sshField",
    "mobileDataAndLockProvider",
    "unlockUserAndPass",
    "ovpnConfig",
    "ovpnUserAndPass",
    "sni",
    "unlockUserAndPass2",
    "unknown14",
    "blockedByHwid",
    "cloudconfig",
    "psiphon",
    "name",
    "blockArea",
    "connectionMode",
    "blockedByPassword",
    "unknown22",
    "extraSniffer",
    "psiphon2",
    "v2rayEnabled",
    "v2rayConfig",
    "version",
    "slowdnsEnabled",
    "slowdnsServer",
    "slowdnsPublickey",
    "dnsResolver"
  ]
};


function hcCleanHex(s) {
  if (!s) return "";

  const clean =
    String(s).replace(/[^0-9a-f]/gi, "");

  return clean.length % 2
    ? "0" + clean
    : clean;
}


function hcIsHex(s) {
  return !!s &&
    String(s).length >= 16 &&
    /^[0-9a-f]+$/i.test(String(s));
}


function hcPrintable(s, strict=false) {
  if (!s) return false;

  if (s.length < 4)
    return true;

  let n = 0;

  for (const c of s) {
    const x = c.charCodeAt(0);

    if (
      (x >= 32 && x <= 126) ||
      x === 9 ||
      x === 10 ||
      x === 13
    ) {
      n++;
    }
  }

  return n / s.length >
    (strict ? 0.90 : 0.80);
}


function hcRotl32(x,n) {
  return (
    (x << n) |
    (x >>> (32 - n))
  ) >>> 0;
}


function hcQR(s,a,b,c,d) {

  s[a] =
    (s[a] + s[b]) >>> 0;

  s[d] ^= s[a];

  s[d] =
    hcRotl32(s[d],16);

  s[c] =
    (s[c] + s[d]) >>> 0;

  s[b] ^= s[c];

  s[b] =
    hcRotl32(s[b],12);

  s[a] =
    (s[a] + s[b]) >>> 0;

  s[d] ^= s[a];

  s[d] =
    hcRotl32(s[d],8);

  s[c] =
    (s[c] + s[d]) >>> 0;

  s[b] ^= s[c];

  s[b] =
    hcRotl32(s[b],7);
}


function hcChaCha20(
  data,
  key,
  nonce,
  counter=0
) {

  if (
    key.length !== 32 ||
    nonce.length !== 8
  ) {
    throw new Error(
      "ChaCha20 key/nonce invalid"
    );
  }

  const out =
    Buffer.alloc(data.length);

  for (
    let off=0,
        block=counter >>> 0;
    off < data.length;
    off += 64,
    block++
  ) {

    const st =
      new Uint32Array(16);

    st[0] = 0x61707865;
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;

    for (let i=0;i<8;i++) {
      st[4+i] =
        key.readUInt32LE(i*4);
    }

    st[12] = block;
    st[13] = 0;

    st[14] =
      nonce.readUInt32LE(0);

    st[15] =
      nonce.readUInt32LE(4);

    const x =
      new Uint32Array(st);

    for (let i=0;i<10;i++) {

      hcQR(x,0,4,8,12);
      hcQR(x,1,5,9,13);
      hcQR(x,2,6,10,14);
      hcQR(x,3,7,11,15);

      hcQR(x,0,5,10,15);
      hcQR(x,1,6,11,12);
      hcQR(x,2,7,8,13);
      hcQR(x,3,4,9,14);
    }

    const stream =
      Buffer.alloc(64);

    for (let i=0;i<16;i++) {

      stream.writeUInt32LE(
        (x[i] + st[i]) >>> 0,
        i*4
      );

    }

    const n =
      Math.min(
        64,
        data.length - off
      );

    for (let i=0;i<n;i++) {

      out[off+i] =
        data[off+i] ^ stream[i];

    }
  }

  return out;
}


function hcABC(
  raw,
  key,
  nonce=HC.nonce
) {

  try {

    const hex =
      hcCleanHex(raw);

    if (!hex)
      return "";

    const data =
      Buffer.from(hex,"hex");

    if (data.length <= 16)
      return "";

    return hcChaCha20(
      data.subarray(0,-16),
      key,
      nonce,
      1
    ).toString("utf8");

  } catch {

    return "";
  }
}


function hcZ3A(data,iv) {

  if (!data)
    return "";

  const out = [];

  const re =
    /(-?\d+)\.(-?\d+)/g;

  let m;

  while (
    (m = re.exec(String(data)))
  ) {

    try {

      const a =
        Number(m[1]) - iv;

      const b =
        Number(m[2]) - iv;

      const divisor =
        2 ** b;

      if (
        divisor !== 0 &&
        Number.isFinite(divisor)
      ) {

        out.push(
          (
            (Math.floor(a/divisor)%256)+256
          ) % 256
        );

      }

    } catch {}
  }

  return Buffer
    .from(out)
    .toString("utf8");
}


function hcBraille(s) {

  try {

    const out = [];

    for (
      let i=0;
      i<s.length-1;
      i+=2
    ) {

      const a =
        HC.braille.indexOf(s[i]);

      const b =
        HC.braille.indexOf(s[i+1]);

      if (a < 0 || b < 0)
        return s;

      out.push(
        (a*16+b)&255
      );
    }

    return Buffer
      .from(out)
      .toString("utf8");

  } catch {

    return s;
  }
}


function hcCredentials(
  raw,
  isSSH=false
) {

  if (!raw)
    return raw;

  if (
    isSSH &&
    HC.braille.includes(raw[0])
  ) {
    raw = hcBraille(raw);
  }

  const re =
    isSSH
      ? /^([\w.-]+):([\d-]+)@(.+):(.+)$/
      : /^([^:]+):(.+)$/;

  const m =
    String(raw).match(re);

  if (!m)
    return raw;

  const u =
    m[m.length-2];

  const p =
    m[m.length-1];

  const uc =
    hcZ3A(
      u,
      (u.match(/-?\d+\.-?\d+/g)||[]).length
    ) || u;

  const pc =
    hcZ3A(
      p,
      (p.match(/-?\d+\.-?\d+/g)||[]).length
    ) || p;

  return isSSH
    ? `${m[1]}:${m[2]}@${uc}:${pc}`
    : `${uc}:${pc}`;
}


function hcB64Decode(s) {

  let x =
    String(s || "");

  const pad =
    x.length % 4;

  if (pad)
    x += "=".repeat(4-pad);

  return Buffer.from(
    x,
    "base64"
  );
}


function hcJKL(
  input,
  isNew=false
) {

  if (!input)
    return input;

  try {

    const key =
      isNew
        ? HC.jklNew
        : HC.jklOld;

    const data =
      hcB64Decode(input);

    for (
      let i=0;
      i<data.length;
      i++
    ) {

      const d = data[i];
      const k = key[i%20];

      data[i] =
        (((d^0xff)&0xca) |
         (d&0x35))
        ^
        (((k^0xff)&0xca) |
         (k&0x35));
    }

    return hcB64Decode(
      data.toString("utf8")
    ).toString("utf8");

  } catch {

    return input;
  }
}


function hcRST(input) {

  try {

    const src =
      Buffer.from(
        String(input),
        "utf8"
      );

    const x =
      Buffer.alloc(src.length);

    for (
      let i=0;
      i<src.length;
      i++
    ) {

      x[i] =
        src[i] ^
        HC.rstXor[i%20];

    }

    const ct =
      Buffer.from(
        x.toString("utf8"),
        "base64"
      );

    for (
      const key of HC.rstKeys
    ) {

      try {

        const d =
          crypto.createDecipheriv(
            "aes-128-ecb",
            Buffer.from(key),
            null
          );

        d.setAutoPadding(true);

        const out =
          Buffer.concat([
            d.update(ct),
            d.final()
          ]).toString("utf8");

        if (
          out.includes(
            "[splitConfig]"
          )
        ) {
          return out;
        }

      } catch {}
    }

  } catch {}

  return null;
}


function hcDecryptField(
  token,
  nonce
) {

  if (
    !token ||
    [
      "true",
      "false",
      "lifeTime",
      "[splitPsiphon][splitPsiphon]"
    ].includes(token) ||
    token.startsWith("<")
  ) {
    return token;
  }

  const candidates = [];

  const clean =
    hcCleanHex(token);

  if (
    hcIsHex(clean) &&
    clean.length >= 32
  ) {

    try {
      candidates.push(
        Buffer.from(clean,"hex")
      );
    } catch {}
  }

  if (
    String(token).length > 16
  ) {

    try {
      candidates.push(
        Buffer.from(token,"latin1")
      );
    } catch {}

    try {
      candidates.push(
        Buffer.from(token,"utf8")
      );
    } catch {}
  }

  const seen =
    new Set();

  for (
    const data of candidates
  ) {

    const id =
      data.toString("hex");

    if (seen.has(id))
      continue;

    seen.add(id);

    if (data.length <= 16)
      continue;

    const ct =
      data.subarray(0,-16);

    for (
      const key of HC.keys
    ) {

      try {

        const dec =
          hcChaCha20(
            ct,
            key,
            nonce,
            1
          ).toString("utf8");

        for (
          const isNew of
          [true,false]
        ) {

          const out =
            hcJKL(
              dec,
              isNew
            );

          if (
            out !== dec &&
            hcPrintable(out)
          ) {
            return out;
          }
        }

        if (
          (
            hcPrintable(dec,true) &&
            /HTTP|@|:|\{/.test(dec)
          ) ||
          /^[A-Za-z0-9]+$/.test(dec)
        ) {
          return dec;
        }

      } catch {}
    }
  }

  for (
    const isNew of [true,false]
  ) {

    const out =
      hcJKL(
        token,
        isNew
      );

    if (
      out !== token &&
      hcPrintable(out)
    ) {
      return out;
    }
  }

  return token;
}


function hcInitial(fileBytes) {

  let latin;

  try {

    latin =
      Buffer.from(
        fileBytes.toString("utf8"),
        "latin1"
      );

  } catch {

    latin =
      fileBytes;

  }

  const out =
    Buffer.alloc(
      latin.length
    );

  for (
    let i=0;
    i<latin.length;
    i++
  ) {

    out[i] =
      latin[i] ^
      HC.initialXor[
        i % HC.initialXor.length
      ];
  }

  return out.toString("utf8");
}


function hcParseModern(buffer) {

  try {

    if (
      !Buffer.isBuffer(buffer) ||
      !buffer.length
    ) {
      return {
        success:false,
        error:"File kosong"
      };
    }

    const hexPayload =
      hcInitial(buffer);

    const outer =
      hcABC(
        hexPayload,
        HC.keys[5]
      );

    if (
      !outer ||
      !outer.trim().startsWith("{")
    ) {
      return {
        success:false,
        error:"Outer decrypt gagal"
      };
    }

    const obj =
      JSON.parse(outer);

    if (
      !obj ||
      typeof obj !== "object"
    ) {
      return {
        success:false,
        error:"JSON HC tidak valid"
      };
    }

    const cfg =
      obj.cfg &&
      typeof obj.cfg === "object"
        ? obj.cfg
        : {};

    const isNew =
      Object.prototype
        .hasOwnProperty
        .call(cfg,"content");

    const meta = {};
    const protections = {};

    let target;
    let delim;

    if (isNew) {

      for (
        const [k,name] of
        [["b","hwid"],["f","area"]]
      ) {

        const val =
          String(
            obj[k] ??
            cfg[k] ??
            ""
          );

        if (val) {
          meta[name] = val;
          protections[name] = val;
        }
      }

      target =
        cfg.content;

      delim =
        "[splitConfig]";

    } else {

      const a =
        obj.a &&
        typeof obj.a === "object"
          ? obj.a
          : {};

      for (
        const [k,name] of [
          ["bb","hwid"],
          ["e","password"],
          ["fe","area"],
          ["ed","provider"]
        ]
      ) {

        const val =
          k === "e"
            ? obj[k]
            : a[k];

        if (val) {

          const dec =
            hcABC(
              String(val),
              HC.keys[7]
            );

          if (dec) {
            meta[name] = dec;
            protections[name] = dec;
          }
        }
      }

      target =
        obj.xy ||
        a.xy;

      delim =
        obj.uv ||
        a.uv;
    }

    if (!target || !delim) {

      return {
        success:false,
        error:
          "Payload/delimiter tidak ditemukan"
      };
    }

    const toHex =
      s =>
        Buffer.from(
          String(s||""),
          "utf8"
        ).toString("hex");

    const h = meta.hwid;
    const p = meta.password;
    const pr = meta.provider;
    const a = meta.area;

    const derived =
      (h && !p && !pr && !a)
        ? toHex(h)+toHex(h)
        : toHex(p)+
          toHex(h)+
          toHex(pr)+
          toHex(a);

    const dyn =
      Buffer.from(HC.nonce);

    if (derived) {

      try {

        const b =
          Buffer.from(
            derived,
            "hex"
          ).subarray(0,8);

        b.copy(
          dyn,
          0,
          0,
          b.length
        );

      } catch {}
    }

    let xyDec = null;

    if (isNew) {

      xyDec =
        hcRST(
          String(target)
        );

      if (!xyDec) {

        for (
          const key of HC.keys
        ) {

          const t =
            hcABC(
              String(target),
              key
            );

          if (
            t &&
            t.includes(delim)
          ) {
            xyDec = t;
            break;
          }
        }
      }

    } else {

      xyDec =
        hcABC(
          String(target),
          HC.keys[1]
        );
    }

    if (!xyDec) {

      return {
        success:false,
        error:
          "Isi konfigurasi gagal didekripsi"
      };
    }

    const config = {};

    const tokens =
      xyDec.split(
        String(delim)
      );

    for (
      let i=0;
      i<tokens.length;
      i++
    ) {

      if (
        i === 22 ||
        i === 24
      ) continue;

      const label =
        HC.tokenMap[i] ||
        `field_${i}`;

      let out =
        tokens[i];

      if (isNew) {

        out =
          hcDecryptField(
            out,
            dyn
          );

      } else {

        if (hcIsHex(out)) {

          out =
            hcABC(
              out,
              HC.keys[7],
              dyn
            );
        }

        out =
          hcJKL(
            out,
            false
          );
      }

      if (i === 7) {

        out =
          hcCredentials(
            out,
            true
          );

      } else if (i === 11) {

        out =
          hcCredentials(
            out,
            false
          );
      }

      if (
        typeof out === "string"
      ) {

        out =
          out.replace(
            /88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d/g,
            ""
          );

        if (
          /^[\[{]/.test(out)
        ) {

          try {
            out =
              JSON.parse(out);
          } catch {}
        }
      }

      if (
        out &&
        !(
          typeof out === "string" &&
          hcIsHex(out)
        )
      ) {

        config[label] =
          out;
      }
    }

    if (config.sshField) {

      const sv =
        hcCredentials(
          config.sshField,
          true
        );

      const sm =
        String(sv).match(
          /^([^:]+):(\d+)@(.+):(.+)$/
        );

      config.ssh =
        sm
          ? {
              host:sm[1],
              port:sm[2],
              username:sm[3],
              password:sm[4]
            }
          : {};
    }

    return {
      success:true,
      config,
      protections,
      raw:xyDec,
      format:isNew
        ? "new"
        : "old"
    };

  } catch(e) {

    return {
      success:false,
      error:
        e.message ||
        "Decrypt error"
    };
  }
}


/* =========================================================
   =========================================================
                    HTTP INJECTOR (.EHI)
   =========================================================
   ========================================================= */

const EHIConstants = {

  L1_KEY: Buffer.from(
    "7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c",
    "hex"
  ),

  L2_KEY_STATIC: Buffer.from(
    "b2bc617c32d8b9eb1943a5ffa8051eea",
    "hex"
  ),

  EOO_MASTER_KEY:
    Buffer.from(
      "null=V5kU5+FFrY\u0000",
      "utf8"
    ),

  BYPASS_IVS: [

    Buffer.from(
      "221d572349555f1d112133236b1f4a3f",
      "hex"
    ),

    Buffer.from(
      "5543494c53443e3f4a6a4539384e776a",
      "hex"
    ),

    Buffer.from(
      "374c2541575e4d531a3c327b75431e5f",
      "hex"
    )

  ],

  STANDARD_IVS: [

    Buffer.from(
      "2c5d1147bbad422b3b334d4d235f1a53",
      "hex"
    ),

    Buffer.from(
      "522b01433a5e8b2fc7549e1ad368e541",
      "hex"
    ),

    Buffer.from(
      "337a1035aaedf3458ca167e92d74b839",
      "hex"
    )

  ],

  STD_ALPHABET:
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",

  CUSTOM_ALPHABET:
    "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"

};


/* =========================
   CUSTOM BASE64
   ========================= */

function ehiCustomB64Decode(encoded) {

  let clean =
    String(encoded || "")
      .replace(/\?/g,"");

  const rem =
    clean.length % 4;

  if (rem) {
    clean +=
      "=".repeat(4-rem);
  }

  let translated = "";

  for (
    const char of clean
  ) {

    const index =
      EHIConstants.CUSTOM_ALPHABET
        .indexOf(char);

    if (index >= 0) {

      translated +=
        EHIConstants.STD_ALPHABET[index];

    } else if (
      char === "="
    ) {

      translated += "=";

    }
  }

  return Buffer.from(
    translated,
    "base64"
  );
}


/* =========================
   XOR LAYER
   ========================= */

function ehiDecryptXorLayer(
  ciphertext,
  key
) {

  if (
    !ciphertext ||
    !String(ciphertext).trim()
  ) {
    return ciphertext;
  }

  try {

    const reversed =
      String(ciphertext)
        .split("")
        .reverse()
        .join("");

    const raw =
      ehiCustomB64Decode(
        reversed
      );

    let hexString =
      raw.toString("ascii");

    if (
      hexString.length % 2 !== 0
    ) {
      hexString =
        "0" + hexString;
    }

    const rawBytes =
      Buffer.from(
        hexString,
        "hex"
      );

    const keyLen =
      String(key).length;

    if (!keyLen)
      return null;

    const output = [];

    for (
      let i=0;
      i<rawBytes.length;
      i++
    ) {

      const value =
        rawBytes[i] ^
        String(key).charCodeAt(
          i % keyLen
        );

      if (value !== 0) {
        output.push(value);
      }
    }

    const plaintext =
      Buffer.from(output)
        .toString("utf8");

    let bad = 0;

    for (
      const char of plaintext
    ) {

      const code =
        char.charCodeAt(0);

      if (
        code < 32 &&
        code !== 9 &&
        code !== 10 &&
        code !== 13
      ) {
        bad++;
      }
    }

    if (
      plaintext.length &&
      bad / plaintext.length > 0.5
    ) {
      return null;
    }

    return plaintext;

  } catch {

    return null;
  }
}


/* =========================
   CONFIG MESSAGE
   ========================= */

function ehiDecodeConfigMessage(
  ciphertext
) {

  if (
    !ciphertext ||
    !String(ciphertext).trim()
  ) {
    return ciphertext;
  }

  try {

    let padded =
      String(ciphertext);

    const rem =
      padded.length % 4;

    if (rem) {
      padded +=
        "=".repeat(4-rem);
    }

    const raw =
      Buffer.from(
        padded,
        "base64"
      );

    /*
     * Python implementation converts
     * UTF-8 bytes to UTF-16BE.
     *
     * Recreate the same 16-bit values.
     */

    const utf8Text =
      raw.toString(
        "utf8"
      );

    const utf16be =
      Buffer.from(
        utf8Text,
        "utf16le"
      );

    const key =
      "EHIMSG";

    const chars = [];

    /*
     * Equivalent transformation
     * for Java UTF-16 chars.
     */

    for (
      let i=0;
      i<utf8Text.length;
      i++
    ) {

      const code =
        utf8Text.charCodeAt(i);

      const k =
        key.charCodeAt(
          i % key.length
        );

      chars.push(
        code ^ k
      );
    }

    return String.fromCharCode(
      ...chars
    );

  } catch {

    return ciphertext;
  }
}


/* =========================
   INNER FIELDS
   ========================= */

function ehiDecodeInnerFields(
  parsedJson,
  saltKey
) {

  const cleaned = {};

  const vitalKeys =
    new Set([
      "overwriteServerData"
    ]);

  for (
    const [key,value]
    of Object.entries(parsedJson || {})
  ) {

    if (
      typeof value === "string" &&
      value.trim()
    ) {

      const decrypted =
        key === "configMessage"
          ? ehiDecodeConfigMessage(value)
          : ehiDecryptXorLayer(
              value,
              saltKey
            );

      if (
        decrypted !== null &&
        decrypted !== undefined
      ) {

        cleaned[key] =
          decrypted;

      } else if (
        vitalKeys.has(key)
      ) {

        cleaned[key] =
          value;
      }

    } else {

      cleaned[key] =
        value;
    }
  }

  return cleaned;
}


/* =========================
   XXTEA
   ========================= */

function ehiReadUInt32LE(
  buffer,
  offset
) {

  return (
    buffer[offset] |
    (buffer[offset+1] << 8) |
    (buffer[offset+2] << 16) |
    (buffer[offset+3] << 24)
  ) >>> 0;
}


function ehiWriteUInt32LE(
  value,
  buffer,
  offset
) {

  buffer[offset] =
    value & 255;

  buffer[offset+1] =
    (value >>> 8) & 255;

  buffer[offset+2] =
    (value >>> 16) & 255;

  buffer[offset+3] =
    (value >>> 24) & 255;
}


function ehiXXTeaDecrypt(
  input,
  key
) {

  if (!input.length)
    return Buffer.alloc(0);

  let data =
    Buffer.from(input);

  const rem =
    data.length % 4;

  if (rem) {

    data = Buffer.concat([
      data,
      Buffer.alloc(4-rem)
    ]);

  }

  const n =
    data.length / 4;

  if (n <= 0)
    return Buffer.alloc(0);

  const kbuf =
    Buffer.alloc(16);

  key.copy(
    kbuf,
    0,
    0,
    Math.min(
      key.length,
      16
    )
  );

  const k = [];

  for (let i=0;i<4;i++) {

    k.push(
      ehiReadUInt32LE(
        kbuf,
        i*4
      )
    );

  }

  const v = [];

  for (let i=0;i<n;i++) {

    v.push(
      ehiReadUInt32LE(
        data,
        i*4
      )
    );

  }

  const delta =
    0x9e3779b9;

  let sum =
    Math.imul(
      6 + Math.floor(52/n),
      delta
    ) >>> 0;

  let y =
    v[0];

  while (sum !== 0) {

    const e =
      (sum >>> 2) & 3;

    for (
      let p=n-1;
      p>0;
      p--
    ) {

      const z =
        v[p-1];

      const mx =
        (
          (
            ((z >>> 5) ^
             (y << 2))
            +
            ((y >>> 3) ^
             (z << 4))
          ) ^
          (
            (sum ^ y) +
            (
              k[(p & 3) ^ e] ^
              z
            )
          )
        ) >>> 0;

      v[p] =
        (
          v[p] -
          mx
        ) >>> 0;

      y =
        v[p];
    }

    const z =
      v[n-1];

    const mx =
      (
        (
          ((z >>> 5) ^
           (y << 2))
          +
          ((y >>> 3) ^
           (z << 4))
        ) ^
        (
          (sum ^ y) +
          (
            k[e] ^
            z
          )
        )
      ) >>> 0;

    v[0] =
      (
        v[0] -
        mx
      ) >>> 0;

    y =
      v[0];

    sum =
      (
        sum -
        delta
      ) >>> 0;
  }

  const decrypted =
    Buffer.alloc(
      v.length * 4
    );

  for (
    let i=0;
    i<v.length;
    i++
  ) {

    ehiWriteUInt32LE(
      v[i],
      decrypted,
      i*4
    );

  }

  const length =
    v[v.length-1];

  if (
    length > 0 &&
    length <= decrypted.length
  ) {

    return decrypted.subarray(
      0,
      length
    );
  }

  let end =
    decrypted.length;

  while (
    end > 0 &&
    decrypted[end-1] === 0
  ) {
    end--;
  }

  return decrypted.subarray(
    0,
    end
  );
}


/* =========================
   PARSE EHI FILE
   ========================= */

function ehiParseEhiBytes(
  fileBytes
) {

  try {

    let offset = 0;

    function readBytes(n) {

      const result =
        fileBytes.subarray(
          offset,
          offset+n
        );

      offset += n;

      return result;
    }


    function readUTF() {

      const lengthBuffer =
        readBytes(2);

      if (
        lengthBuffer.length < 2
      ) {
        return "";
      }

      const length =
        lengthBuffer.readUInt16BE(0);

      return readBytes(length)
        .toString(
          "utf8"
        );
    }


    readUTF();

    readBytes(8);

    readUTF();

    readBytes(8);

    const pLenBuffer =
      readBytes(4);

    if (
      pLenBuffer.length < 4
    ) {
      return null;
    }

    const pLen =
      pLenBuffer.readUInt32BE(0);

    readBytes(8);

    return readBytes(
      pLen
    );

  } catch {

    return null;
  }
}


/* =========================
   MASTER KEY
   ========================= */

function ehiGenerateMasterKey(
  config
) {

  const values = [

    config.configAesKey || "",

    config.configIdentifier || "",

    config.configSalt || "",

    String(
      config.configTimestamp || 0
    ),

    String(
      config.configExpiryTimestamp || 0
    ),

    config.lockModes || "",

    config.lockModesHash || "",

    config.configHwid || "",

    config.configLockMobileOperatorId || ""

  ];

  const payload =
    values
      .filter(Boolean)
      .join("");

  return crypto
    .createHash("sha256")
    .update(
      payload,
      "utf8"
    )
    .digest();
}


/* =========================
   ARGON2 RAW KEY
   ========================= */

async function ehiArgon2Key(
  secret,
  salt,
  timeCost,
  memoryCost,
  parallelism
) {

  return await argon2.hash(
    secret,
    {
      type:
        argon2.argon2id,

      salt,

      timeCost,

      memoryCost,

      parallelism,

      hashLength:32,

      raw:true
    }
  );
}


/* =========================
   CHACHA20 POLY1305
   ========================= */

function ehiChaChaDecrypt(
  key,
  nonce,
  aad,
  ciphertext,
  tag
) {

  const decipher =
    crypto.createDecipheriv(
      "chacha20-poly1305",
      key,
      nonce,
      {
        authTagLength:16
      }
    );

  decipher.setAAD(
    aad,
    {
      plaintextLength:
        ciphertext.length
    }
  );

  decipher.setAuthTag(
    tag
  );

  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
}


/* =========================
   EHI MAIN DECRYPT
   ========================= */

async function ehiExecute(
  fileBytes
) {

  const payload =
    ehiParseEhiBytes(
      fileBytes
    );

  if (!payload) {

    return {
      success:false,
      error:
        "Payload EHI tidak ditemukan"
    };

  }

  let config = null;
  let matchedIV = null;

  const allIVs = [
    ...EHIConstants.BYPASS_IVS,
    ...EHIConstants.STANDARD_IVS
  ];

  /*
   * Layer 1 + Layer 2 + XXTEA
   */

  for (
    const iv of allIVs
  ) {

    try {

      const c1 =
        crypto.createDecipheriv(
          "aes-256-cbc",
          EHIConstants.L1_KEY,
          iv
        );

      c1.setAutoPadding(true);

      const l1 =
        Buffer.concat([
          c1.update(payload),
          c1.final()
        ]).toString("utf8");

      const parts =
        l1.split(":");

      if (
        parts.length < 3
      ) {
        continue;
      }

      const iv2 =
        Buffer.from(
          parts[0],
          "base64"
        );

      const ciphertext2 =
        Buffer.from(
          parts[2],
          "base64"
        );

      if (
        iv2.length !== 16 ||
        ciphertext2.length === 0
      ) {
        continue;
      }

      const c2 =
        crypto.createDecipheriv(
          "aes-128-cbc",
          EHIConstants.L2_KEY_STATIC,
          iv2
        );

      c2.setAutoPadding(true);

      const garbage =
        Buffer.concat([
          c2.update(
            ciphertext2
          ),
          c2.final()
        ]);

      const finalRaw =
        ehiXXTeaDecrypt(
          garbage,
          EHIConstants.EOO_MASTER_KEY
        );

      const start =
        finalRaw.indexOf(
          0x7b
        );

      if (start < 0)
        continue;

      const jsonText =
        finalRaw
          .subarray(start)
          .toString(
            "utf8"
          );

      config =
        JSON.parse(
          jsonText
        );

      matchedIV =
        iv;

      break;

    } catch {

      continue;
    }
  }

  if (!config) {

    return {
      success:false,
      error:
        "Layer EHI gagal didecrypt"
    };
  }

  const targetSalt =
    config.configSalt ||
    "EVZJNI";

  let parsedFinal;

  /*
   * BYPASS
   */

  const isBypass =
    EHIConstants.BYPASS_IVS.some(
      x =>
        x.equals(matchedIV)
    );

  if (isBypass) {

    parsedFinal =
      config;

  } else {

    /*
     * STANDARD
     */

    const targetData =
      config.configData;

    if (!targetData) {

      return {
        success:false,
        error:
          "configData tidak ditemukan"
      };
    }

    const aaaResult =
      ehiDecryptXorLayer(
        targetData,
        targetSalt
      );

    if (!aaaResult) {

      return {
        success:false,
        error:
          "configData gagal didecrypt"
      };
    }

    let rawPayload;

    try {

      rawPayload =
        Buffer.from(
          aaaResult,
          "base64"
        );

    } catch {

      return {
        success:false,
        error:
          "Payload Argon2 tidak valid"
      };
    }

    if (
      rawPayload.length <= 50
    ) {

      return {
        success:false,
        error:
          "Payload Argon2 terlalu pendek"
      };
    }

    try {

      const timeCost =
        rawPayload.readUInt32LE(
          1
        );

      const memoryCost =
        rawPayload.readUInt32LE(
          5
        );

      const parallelism =
        rawPayload[9];

      const salt =
        rawPayload.subarray(
          0x0a,
          0x1a
        );

      const nonce =
        rawPayload.subarray(
          0x1a,
          0x32
        );

      const aad =
        rawPayload.subarray(
          0,
          0x1a
        );

      const ciphertext =
        rawPayload.subarray(
          0x32,
          -16
        );

      const tag =
        rawPayload.subarray(
          -16
        );

      const masterKey =
        ehiGenerateMasterKey(
          config
        );

      const argonKey =
        await ehiArgon2Key(
          masterKey,
          salt,
          timeCost,
          memoryCost,
          parallelism
        );

      const decrypted =
        ehiChaChaDecrypt(
          argonKey,
          nonce,
          aad,
          ciphertext,
          tag
        );

      parsedFinal =
        JSON.parse(
          decrypted.toString(
            "utf8"
          )
        );

    } catch (error) {

      return {
        success:false,
        error:
          "Argon2/ChaCha decrypt gagal: " +
          error.message
      };
    }
  }

  /*
   * CLEAN INNER JSON
   */

  let cleanedFinalJson =
    ehiDecodeInnerFields(
      parsedFinal,
      targetSalt
    );

  /*
   * Parse nested JSON
   */

  for (
    const field of [
      "v2rRawJson",
      "overwriteServerData"
    ]
  ) {

    if (
      field in cleanedFinalJson &&
      typeof cleanedFinalJson[field] === "string"
    ) {

      const rawString =
        cleanedFinalJson[field];

      try {

        const start =
          rawString.indexOf("{");

        const end =
          rawString.lastIndexOf("}");

        if (
          start !== -1 &&
          end !== -1
        ) {

          const text =
            rawString.substring(
              start,
              end+1
            );

          let parsed =
            JSON.parse(text);

          if (
            typeof parsed === "string"
          ) {
            parsed =
              JSON.parse(parsed);
          }

          cleanedFinalJson[field] =
            parsed;
        }

      } catch (error) {

        cleanedFinalJson[
          field +
          "_PARSING_ERROR"
        ] =
          error.message;
      }
    }
  }

  return {
    success:true,
    format:"ehi",
    config:cleanedFinalJson,
    raw:JSON.stringify(
      cleanedFinalJson,
      null,
      4
    )
  };
}


/* =========================================================
                         API
   ========================================================= */

app.post(
  "/api/decrypt",
  upload.single("file"),
  async (req,res) => {

    try {

      if (!req.file) {

        return res.status(400).json({
          success:false,
          error:
            "File tidak ditemukan"
        });
      }

      const filename =
        req.file.originalname
          .toLowerCase();


      /*
       * HC
       */

      if (
        filename.endsWith(".hc")
      ) {

        const result =
          hcParseModern(
            req.file.buffer
          );

        if (result.success) {

          return res.json({
            ...result,
            filename:
              req.file.originalname,
            format:
              "HTTP Custom (.hc)"
          });

        }

        return res.status(400).json(
          result
        );
      }


      /*
       * EHI
       */

      if (
        filename.endsWith(".ehi")
      ) {

        const result =
          await ehiExecute(
            req.file.buffer
          );

        if (result.success) {

          return res.json({
            ...result,
            filename:
              req.file.originalname,
            format:
              "HTTP Injector (.ehi)"
          });

        }

        return res.status(400).json(
          result
        );
      }


      /*
       * FORMAT LAIN
       */

      return res.status(400).json({
        success:false,
        error:
          "Format tidak didukung. Gunakan .hc atau .ehi"
      });

    } catch(error) {

      console.error(
        "DECRYPT ERROR:",
        error
      );

      return res.status(500).json({
        success:false,
        error:
          error.message
      });
    }
  }
);


/* =========================================================
                        HEALTH
   ========================================================= */

app.get(
  "/api/health",
  (req,res) => {

    res.json({
      success:true,
      status:"online",
      decryptors:[
        ".hc",
        ".ehi"
      ]
    });

  }
);


/* =========================================================
                      SUPPORTED
   ========================================================= */

app.get(
  "/api/supported",
  (req,res) => {

    res.json({
      success:true,
      formats:[
        {
          name:"HTTP Custom",
          extension:".hc"
        },
        {
          name:"HTTP Injector",
          extension:".ehi"
        }
      ]
    });

  }
);


/* =========================================================
                       START
   ========================================================= */

if (
  require.main === module
) {

  app.listen(
    PORT,
    () => {

      console.log(
        "======================================"
      );

      console.log(
        "       DINSTORE DECRYPTOR v2"
      );

      console.log(
        "======================================"
      );

      console.log(
        "HC  : ENABLED"
      );

      console.log(
        "EHI : ENABLED"
      );

      console.log(
        `PORT: ${PORT}`
      );

      console.log(
        `URL : http://localhost:${PORT}`
      );

    }
  );
}


module.exports = app;
