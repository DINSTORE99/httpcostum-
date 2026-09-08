const crypto = require("crypto");
const EHI = require("../config/ehi.keys");

const argon2 = require("argon2");

let xchacha20poly1305;

async function loadXChaCha() {
if (!xchacha20poly1305) {
const mod = await import("@noble/ciphers/chacha.js");
xchacha20poly1305 = mod.xchacha20poly1305;
}

return xchacha20poly1305;
}

/* ========================================
CUSTOM BASE64
======================================== */

function customB64Decode(input) {

let clean = String(input)
.replace(/?/g, "");

while (clean.length % 4 !== 0) {
clean += "=";
}

const table = new Map();

for (let i = 0; i < EHI.CUSTOM_ALPHABET.length; i++) {
table.set(
EHI.CUSTOM_ALPHABET[i],
EHI.STD_ALPHABET[i]
);
}

let translated = "";

for (const char of clean) {
translated +=
table.get(char) ?? char;
}

return Buffer.from(
translated,
"base64"
);
}

/* ========================================
XOR LAYER
======================================== */

function decryptXorLayer(
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
  customB64Decode(reversed);

let hexString =
  raw.toString("ascii");

if (hexString.length % 2 !== 0) {
  hexString =
    "0" + hexString;
}

const encrypted =
  Buffer.from(hexString, "hex");

const keyBuf =
  Buffer.from(
    String(key),
    "utf8"
  );

if (!keyBuf.length) {
  return null;
}

const output = [];

for (
  let i = 0;
  i < encrypted.length;
  i++
) {

  const value =
    encrypted[i] ^
    keyBuf[i % keyBuf.length];

  if (value !== 0) {
    output.push(value);
  }
}

const plaintext =
  Buffer.from(output)
    .toString("utf8");

if (!plaintext) {
  return plaintext;
}

let bad = 0;

for (const char of plaintext) {

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
  bad / plaintext.length >
  0.5
) {
  return null;
}

return plaintext;

} catch {
return null;
}
}

/* ========================================
CONFIG MESSAGE
======================================== */

function decodeConfigMessage(
ciphertext
) {

if (
!ciphertext ||
!String(ciphertext).trim()
) {
return ciphertext;
}

try {

let value =
  String(ciphertext);

while (value.length % 4 !== 0) {
  value += "=";
}

const raw =
  Buffer.from(
    value,
    "base64"
  );

const utf8Text =
  raw.toString("utf8");

const utf16be =
  Buffer.from(
    utf8Text,
    "utf16le"
  );

const key =
  Buffer.from(
    "EHIMSG",
    "ascii"
  );

const chars = [];

/*
 * Python:
 *
 * decode utf8
 * encode utf16-be
 * unpack >H
 *
 * Node tidak memiliki utf16-be,
 * jadi kita baca dua byte sekaligus.
 */

const length =
  Math.floor(
    utf16be.length / 2
  );

for (let i = 0; i < length; i++) {

  const high =
    utf16be[i * 2];

  const low =
    utf16be[i * 2 + 1];

  const code =
    (high << 8) | low;

  const xor =
    code ^
    key[i % key.length];

  chars.push(xor);
}

const result =
  Buffer.alloc(
    chars.length * 2
  );

for (
  let i = 0;
  i < chars.length;
  i++
) {

  result[i * 2] =
    (chars[i] >> 8) & 0xff;

  result[i * 2 + 1] =
    chars[i] & 0xff;
}

/*
 * UTF-16BE -> UTF-16LE
 */

const swapped =
  Buffer.alloc(
    result.length
  );

for (
  let i = 0;
  i < result.length;
  i += 2
) {

  swapped[i] =
    result[i + 1];

  swapped[i + 1] =
    result[i];
}

return swapped.toString(
  "utf16le"
);

} catch {

return ciphertext;

}
}

/* ========================================
DECODE INNER FIELDS
======================================== */

function decodeInnerFields(
parsedJson,
saltKey
) {

const cleaned = {};

const vitalKeys =
new Set([
"overwriteServerData"
]);

for (
const [key, value]
of Object.entries(parsedJson)
) {

if (
  typeof value === "string" &&
  value.trim()
) {

  const decrypted =
    key === "configMessage"
      ? decodeConfigMessage(value)
      : decryptXorLayer(
          value,
          saltKey
        );

  if (decrypted !== null) {

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

/* ========================================
XXTEA
======================================== */

function xxteaDecrypt(
data,
key
) {

if (!data || !data.length) {
return Buffer.alloc(0);
}

let input =
Buffer.from(data);

const remainder =
input.length % 4;

if (remainder) {

input = Buffer.concat([
  input,
  Buffer.alloc(
    4 - remainder
  )
]);

}

const key16 =
Buffer.alloc(16);

key.copy(
key16,
0,
0,
Math.min(
key.length,
16
)
);

const k = [
key16.readUInt32LE(0),
key16.readUInt32LE(4),
key16.readUInt32LE(8),
key16.readUInt32LE(12)
];

const n =
input.length / 4;

if (n < 2) {
return input;
}

const v =
new Array(n);

for (let i = 0; i < n; i++) {

v[i] =
  input.readUInt32LE(
    i * 4
  );

}

const delta =
0x9e3779b9;

let sum =
Math.imul(
6 + Math.floor(52 / n),
delta
) >>> 0;

let y =
v[0];

while (sum !== 0) {

const e =
  (sum >>> 2) & 3;

for (
  let p = n - 1;
  p > 0;
  p--
) {

  const z =
    v[p - 1];

  const mx =
    (
      (
        (
          ((z >>> 5) ^
          (y << 2)) >>> 0
        ) +
        (
          ((y >>> 3) ^
          (z << 4)) >>> 0
        )
      ) ^
      (
        (
          sum ^ y
        ) +
        (
          k[
            (p & 3) ^ e
          ] ^ z
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
  v[n - 1];

const mx =
  (
    (
      (
        ((z >>> 5) ^
        (y << 2)) >>> 0
      ) +
      (
        ((y >>> 3) ^
        (z << 4)) >>> 0
      )
    ) ^
    (
      (
        sum ^ y
      ) +
      (
        k[e] ^ z
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
n * 4
);

for (let i = 0; i < n; i++) {

decrypted.writeUInt32LE(
  v[i],
  i * 4
);

}

const length =
v[n - 1];

if (
length > 0 &&
length <= decrypted.length
) {

return decrypted.subarray(
  0,
  length
);

}

/*

* Python:
* decrypted.rstrip(b'\x00')
  */

let end =
decrypted.length;

while (
end > 0 &&
decrypted[end - 1] === 0
) {
end--;
}

return decrypted.subarray(
0,
end
);
}

/* ========================================
READ JAVA UTF
======================================== */

function readUTF(
buffer,
offset
) {

if (
offset + 2 >
buffer.length
) {
return {
value: "",
offset: buffer.length
};
}

const length =
buffer.readUInt16BE(
offset
);

offset += 2;

const end =
Math.min(
offset + length,
buffer.length
);

return {
value:
buffer
.subarray(
offset,
end
)
.toString("utf8"),

offset: end

};
}

/* ========================================
PARSE EHI
======================================== */

function parseEhiBytes(
fileBytes
) {

try {

const buffer =
  Buffer.from(fileBytes);

let offset = 0;

let result =
  readUTF(
    buffer,
    offset
  );

offset =
  result.offset;

offset += 8;

result =
  readUTF(
    buffer,
    offset
  );

offset =
  result.offset;

offset += 8;

if (
  offset + 4 >
  buffer.length
) {
  return null;
}

const payloadLength =
  buffer.readUInt32BE(
    offset
  );

offset += 4;

offset += 8;

if (
  payloadLength <= 0 ||
  offset + payloadLength >
  buffer.length
) {
  return null;
}

return buffer.subarray(
  offset,
  offset + payloadLength
);

} catch {

return null;

}
}

/* ========================================
MASTER KEY
======================================== */

function generateMasterKey(
config
) {

const parts = [
config.configAesKey,
config.configIdentifier,
config.configSalt,
String(
config.configTimestamp ?? 0
),
String(
config.configExpiryTimestamp ?? 0
),
config.lockModes,
config.lockModesHash,
config.configHwid,
config.configLockMobileOperatorId
];

const payload =
parts
.filter(Boolean)
.map(String)
.join("");

return crypto
.createHash("sha256")
.update(
payload,
"utf8"
)
.digest();
}

/* ========================================
AES CBC
======================================== */

function aesCbcDecrypt(
key,
iv,
encrypted
) {

const algorithm =
key.length === 32
? "aes-256-cbc"
: key.length === 24
? "aes-192-cbc"
: "aes-128-cbc";

const decipher =
crypto.createDecipheriv(
algorithm,
key,
iv
);

return Buffer.concat([
decipher.update(encrypted),
decipher.final()
]);
}

/* ========================================
MAIN
======================================== */

async function execute(
fileBytes
) {

const payload =
parseEhiBytes(
fileBytes
);

if (!payload) {
throw new Error(
"Format EHI tidak valid"
);
}

let config = null;
let matchedIV = null;

/*

* BYPASS + STANDARD
  */

const allIVs = [
...EHI.BYPASS_IVS,
...EHI.STANDARD_IVS
];

for (const iv of allIVs) {

try {

  const l1 =
    aesCbcDecrypt(
      EHI.L1_KEY,
      iv,
      payload
    ).toString("utf8");


  const parts =
    l1.split(":");


  if (parts.length < 3) {
    continue;
  }


  const c2IV =
    Buffer.from(
      parts[0],
      "base64"
    );


  const encrypted2 =
    Buffer.from(
      parts[2],
      "base64"
    );


  const garbage =
    aesCbcDecrypt(
      EHI.L2_KEY_STATIC,
      c2IV,
      encrypted2
    );


  const finalRaw =
    xxteaDecrypt(
      garbage,
      EHI.EOO_MASTER_KEY
    );


  const start =
    finalRaw.indexOf(
      0x7b
    );

  if (start === -1) {
    continue;
  }


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

throw new Error(
  "Tidak dapat menemukan layer EHI yang valid"
);

}

const targetSalt =
config.configSalt ||
"EVZJNI";

let parsedFinal;

/*

* BYPASS
  */

const isBypass =
EHI.BYPASS_IVS.some(
(iv) =>
matchedIV.equals(iv)
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


if (
  !targetData
) {

  throw new Error(
    "configData tidak ditemukan"
  );
}


const aaaResult =
  decryptXorLayer(
    targetData,
    targetSalt
  );


if (!aaaResult) {

  throw new Error(
    "Gagal decrypt configData"
  );
}


const rawPayload =
  Buffer.from(
    aaaResult,
    "base64"
  );


if (
  rawPayload.length <= 50
) {

  throw new Error(
    "Payload EHI terlalu pendek"
  );
}


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


const masterKey =
  generateMasterKey(
    config
  );


/*
 * Python menggunakan:
 *
 * Argon2id
 * hash_len = 32
 */

const argonKey =
  await argon2.hash(
    masterKey,
    {
      type: argon2.argon2id,

      salt,

      timeCost,

      memoryCost,

      parallelism,

      hashLength: 32,

      raw: true
    }
  );


/*
 * Python:
 *
 * ChaCha20_Poly1305.new(
 *   key=argon_key,
 *   nonce=24-byte nonce
 * )
 *
 * Karena nonce 24 byte,
 * ini adalah XChaCha20-Poly1305.
 */

const xchacha =
  await loadXChaCha();


const aad =
  rawPayload.subarray(
    0,
    0x1a
  );


const ciphertext =
  rawPayload.subarray(
    0x32,
    rawPayload.length - 16
  );


const tag =
  rawPayload.subarray(
    rawPayload.length - 16
  );


/*
 * noble menerima ciphertext
 * + authentication tag
 */

const combined =
  Buffer.concat([
    ciphertext,
    tag
  ]);


const cipher =
  xchacha(
    argonKey,
    nonce,
    aad
  );


const decrypted =
  cipher.decrypt(
    combined
  );


parsedFinal =
  JSON.parse(
    Buffer.from(
      decrypted
    ).toString(
      "utf8"
    )
  );

}

/*

* INNER FIELDS
  */

const cleaned =
decodeInnerFields(
parsedFinal,
targetSalt
);

/*

* PARSE NESTED JSON
  */

for (
const field of [
"v2rRawJson",
"overwriteServerData"
]
) {

if (
  field in cleaned &&
  typeof cleaned[field] ===
    "string"
) {

  const raw =
    cleaned[field];

  try {

    const start =
      raw.indexOf("{");

    const end =
      raw.lastIndexOf("}");


    if (
      start !== -1 &&
      end !== -1
    ) {

      const extracted =
        raw.substring(
          start,
          end + 1
        );


      let parsed =
        JSON.parse(
          extracted
        );


      if (
        typeof parsed ===
        "string"
      ) {

        parsed =
          JSON.parse(
            parsed
          );
      }


      cleaned[field] =
        parsed;
    }

  } catch (error) {

    cleaned[
      `${field}_PARSING_ERROR`
    ] =
      error.message;
  }
}

}

return {
success: true,

format: "EHI",

config: cleaned,

protections: {}

};
}

/* ========================================
EXPORT
======================================== */

module.exports = {
execute
};
