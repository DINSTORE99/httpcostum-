const crypto = require("crypto");
const argon2 = require("argon2");

const {
  xchacha20poly1305
} = require("@noble/ciphers/chacha.js");

const EHI = require("../config/ehi.keys");


// ============================================================
// HELPERS
// ============================================================

function xorBytes(a, b) {
  const out = Buffer.alloc(a.length);

  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i % b.length];
  }

  return out;
}


function aesCbcDecrypt(key, iv, data) {
  const decipher = crypto.createDecipheriv(
    "aes-" + (key.length * 8) + "-cbc",
    key,
    iv
  );

  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
}


function customBase64Decode(value) {

  if (Buffer.isBuffer(value)) {
    value = value.toString("utf8");
  }

  value = String(value);

  let translated = "";

  for (const char of value) {

    const index =
      EHI.CUSTOM_ALPHABET.indexOf(char);

    if (index === -1) {
      translated += char;
    } else {
      translated += EHI.STD_ALPHABET[index];
    }
  }

  translated = translated
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (translated.length % 4 !== 0) {
    translated += "=";
  }

  return Buffer.from(translated, "base64");
}


// ============================================================
// XXTEA
// ============================================================

function toUint32Array(buffer) {

  const n = Math.ceil(buffer.length / 4);

  const out = new Uint32Array(n);

  for (let i = 0; i < n; i++) {

    const p = i * 4;

    out[i] =
      (buffer[p] || 0) |
      ((buffer[p + 1] || 0) << 8) |
      ((buffer[p + 2] || 0) << 16) |
      ((buffer[p + 3] || 0) << 24);
  }

  return out;
}


function fromUint32Array(v, length) {

  const out = Buffer.alloc(v.length * 4);

  for (let i = 0; i < v.length; i++) {

    out[i * 4] =
      v[i] & 0xff;

    out[i * 4 + 1] =
      (v[i] >>> 8) & 0xff;

    out[i * 4 + 2] =
      (v[i] >>> 16) & 0xff;

    out[i * 4 + 3] =
      (v[i] >>> 24) & 0xff;
  }

  return out.subarray(0, length);
}


function xxteaDecrypt(data, key) {

  if (!Buffer.isBuffer(data)) {
    data = Buffer.from(data);
  }

  if (!Buffer.isBuffer(key)) {
    key = Buffer.from(key);
  }

  if (data.length < 8) {
    return data;
  }

  const v = toUint32Array(data);

  const k = toUint32Array(
    Buffer.concat([
      key,
      Buffer.alloc(
        Math.max(0, 16 - key.length)
      )
    ]).subarray(0, 16)
  );

  let n = v.length;

  let rounds =
    6 + Math.floor(52 / n);

  let sum =
    Math.imul(rounds, 0x9e3779b9) >>> 0;

  const delta = 0x9e3779b9;

  while (sum !== 0) {

    const e =
      (sum >>> 2) & 3;

    for (
      let p = n - 1;
      p > 0;
      p--
    ) {

      const z = v[p - 1];

      const y = v[p];

      const mx =
        (
          ((z >>> 5) ^ Math.imul(y << 2, 1)) +
          ((y >>> 3) ^ Math.imul(z << 4, 1))
        ) ^
        (
          (sum ^ y) +
          (k[(p & 3) ^ e] ^ z)
        );

      v[p] =
        (v[p] - mx) >>> 0;
    }

    const z = v[n - 1];

    const y = v[0];

    const mx =
      (
        ((z >>> 5) ^ Math.imul(y << 2, 1)) +
        ((y >>> 3) ^ Math.imul(z << 4, 1))
      ) ^
      (
        (sum ^ y) +
        (k[e] ^ z)
      );

    v[0] =
      (v[0] - mx) >>> 0;

    sum =
      (sum - delta) >>> 0;
  }

  return fromUint32Array(
    v,
    data.length
  );
}


// ============================================================
// CONFIG MESSAGE
// ============================================================

function decodeConfigMessage(buffer) {

  const text = buffer.toString("utf8");

  const start = text.indexOf("{");

  if (start === -1) {
    throw new Error(
      "JSON EHI tidak ditemukan"
    );
  }

  const jsonText =
    text.substring(start);

  return JSON.parse(jsonText);
}


// ============================================================
// MASTER KEY
// ============================================================

function generateMasterKey(config) {

  /*
   * EHI menggunakan material konfigurasi
   * sebagai password untuk Argon2id.
   *
   * Pertahankan representasi JSON yang stabil.
   */

  const source =
    typeof config === "string"
      ? config
      : JSON.stringify(config);

  return Buffer.from(source, "utf8");
}


// ============================================================
// XOR CONFIG DATA
// ============================================================

function decryptConfigData(data, salt) {

  const raw =
    Buffer.isBuffer(data)
      ? data
      : Buffer.from(data, "utf8");

  const saltBytes =
    Buffer.from(
      String(salt || "EVZJNI"),
      "utf8"
    );

  return xorBytes(
    raw,
    saltBytes
  );
}


// ============================================================
// INNER FIELDS
// ============================================================

function decodeInnerFields(obj) {

  if (!obj || typeof obj !== "object") {
    return obj;
  }

  const result = Array.isArray(obj)
    ? []
    : {};

  for (const [key, value] of Object.entries(obj)) {

    if (
      typeof value === "string"
    ) {

      result[key] =
        value;

    } else if (
      value &&
      typeof value === "object"
    ) {

      result[key] =
        decodeInnerFields(value);

    } else {

      result[key] =
        value;
    }
  }

  return result;
}


// ============================================================
// NESTED JSON
// ============================================================

function parseNestedJSON(config) {

  for (
    const key of [
      "v2rRawJson",
      "overwriteServerData"
    ]
  ) {

    if (
      typeof config[key] === "string"
    ) {

      try {

        config[key] =
          JSON.parse(config[key]);

      } catch (_) {
        // Bukan JSON, biarkan string asli
      }
    }
  }

  return config;
}


// ============================================================
// XCHACHA20 POLY1305
// ============================================================

function decryptXChaCha(
  key,
  nonce,
  ciphertext,
  tag,
  aad
) {

  if (key.length !== 32) {
    throw new Error(
      `XChaCha key harus 32 byte, dapat ${key.length}`
    );
  }

  if (nonce.length !== 24) {
    throw new Error(
      `XChaCha nonce harus 24 byte, dapat ${nonce.length}`
    );
  }

  const encrypted =
    Buffer.concat([
      ciphertext,
      tag
    ]);

  const cipher =
    xchacha20poly1305(
      new Uint8Array(key),
      new Uint8Array(nonce)
    );

  const result =
    cipher.decrypt(
      new Uint8Array(encrypted),
      aad
        ? new Uint8Array(aad)
        : undefined
    );

  return Buffer.from(result);
}


// ============================================================
// EHI PARSER
// ============================================================

async function ehiDecrypt(buffer) {

  if (!Buffer.isBuffer(buffer)) {
    throw new Error(
      "Input EHI harus Buffer"
    );
  }

  if (!buffer.length) {
    throw new Error(
      "File EHI kosong"
    );
  }


  const allIVs = [
    ...EHI.BYPASS_IVS.map(iv => ({
      iv,
      bypass: true
    })),

    ...EHI.STANDARD_IVS.map(iv => ({
      iv,
      bypass: false
    }))
  ];


  let parsedConfig = null;
  let matchedBypass = false;


  // ==========================================================
  // LAYER 1 + LAYER 2
  // ==========================================================

  for (const item of allIVs) {

    try {

      const layer1 =
        aesCbcDecrypt(
          EHI.L1_KEY,
          item.iv,
          buffer
        );

      const message =
        layer1.toString("utf8");

      const parts =
        message.split(":");


      if (parts.length < 3) {
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


      const layer2 =
        aesCbcDecrypt(
          EHI.L2_KEY_STATIC,
          iv2,
          ciphertext2
        );


      const xxtea =
        xxteaDecrypt(
          layer2,
          EHI.EOO_MASTER_KEY
        );


      const config =
        decodeConfigMessage(xxtea);


      if (
        config &&
        typeof config === "object"
      ) {

        parsedConfig =
          config;

        matchedBypass =
          item.bypass;

        break;
      }

    } catch (_) {

      continue;

    }
  }


  if (!parsedConfig) {

    throw new Error(
      "Tidak dapat membuka layer EHI. IV/key tidak cocok."
    );

  }


  // ==========================================================
  // BYPASS
  // ==========================================================

  let finalConfig;


  if (matchedBypass) {

    finalConfig =
      parsedConfig;

  } else {

    // ========================================================
    // STANDARD EHI
    // ========================================================

    const targetSalt =
      parsedConfig.configSalt ||
      "EVZJNI";


    if (
      !parsedConfig.configData
    ) {

      throw new Error(
        "configData tidak ditemukan"
      );

    }


    const encoded =
      decryptConfigData(
        Buffer.from(
          parsedConfig.configData,
          "utf8"
        ),
        targetSalt
      );


    const rawPayload =
      customBase64Decode(encoded);


    if (
      rawPayload.length <
      0x32 + 16
    ) {

      throw new Error(
        "Payload EHI terlalu pendek"
      );

    }


    const salt =
      rawPayload.subarray(
        0x0a,
        0x1a
      );


    const timeCost =
      rawPayload.readUInt32LE(1);


    const memoryCost =
      rawPayload.readUInt32LE(5);


    const parallelism =
      rawPayload[9];


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
        rawPayload.length - 16
      );


    const tag =
      rawPayload.subarray(
        rawPayload.length - 16
      );


    const password =
      generateMasterKey(
        parsedConfig
      );


    const key =
      await argon2.hash(
        password,
        {
          type: argon2.argon2id,

          timeCost,

          memoryCost,

          parallelism,

          hashLength: 32,

          salt,

          raw: true
        }
      );


    const decrypted =
      decryptXChaCha(
        key,
        nonce,
        ciphertext,
        tag,
        aad
      );


    finalConfig =
      JSON.parse(
        decrypted.toString("utf8")
      );
  }


  // ==========================================================
  // CLEAN
  // ==========================================================

  finalConfig =
    decodeInnerFields(
      finalConfig
    );


  finalConfig =
    parseNestedJSON(
      finalConfig
    );


  return {

    success: true,

    format: "ehi",

    result:
      `HABIBIxNULLPTRO HTTP INJECTOR SCRIPT\n` +
      `${"=".repeat(30)}\n\n` +
      `${JSON.stringify(
        finalConfig,
        null,
        4
      )}\n\n` +
      `${"=".repeat(30)}\n` +
      `code : @HABIBI_1ST and @NullptrO`,

    data: finalConfig

  };
}


// ============================================================
// INI YANG BENAR
// ============================================================

module.exports = ehiDecrypt;
