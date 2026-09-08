"use strict"

const crypto = require("crypto")
const { argon2id } = require("hash-wasm")
const sodium = require("libsodium-wrappers")

// ============================================================
// HTTP INJECTOR EHI DECRYPTOR
// ============================================================

// -------------------------
// STATIC KEYS
// -------------------------

const L1_KEY = Buffer.from(
  "7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c",
  "hex"
)

const L2_KEY_STATIC = Buffer.from(
  "b2bc617c32d8b9eb1943a5ffa8051eea",
  "hex"
)

const EOO_MASTER_KEY = Buffer.from(
  "null=V5kU5+FFrY\x00",
  "utf8"
)

// -------------------------
// IV LIST
// -------------------------

const BYPASS_IVS = [
  Buffer.from("221d572349555f1d112133236b1f4a3f", "hex"),
  Buffer.from("5543494c53443e3f4a6a4539384e776a", "hex"),
  Buffer.from("374c2541575e4d531a3c327b75431e5f", "hex")
]

const STANDARD_IVS = [
  Buffer.from("2c5d1147bbad422b3b334d4d235f1a53", "hex"),
  Buffer.from("522b01433a5e8b2fc7549e1ad368e541", "hex"),
  Buffer.from("337a1035aaedf3458ca167e92d74b839", "hex")
]

const ALL_IVS = [
  ...BYPASS_IVS.map(iv => ({
    iv,
    mode: "bypass"
  })),
  ...STANDARD_IVS.map(iv => ({
    iv,
    mode: "standard"
  }))
]

// -------------------------
// BASE64 ALPHABET
// -------------------------

const STD_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

const CUSTOM_ALPHABET =
  "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"


// ============================================================
// UTIL
// ============================================================

function safeJson(value) {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function isPrintable(text) {
  if (!text) return false

  let good = 0

  for (const ch of text) {
    const n = ch.charCodeAt(0)

    if (
      n === 9 ||
      n === 10 ||
      n === 13 ||
      (n >= 32 && n <= 126) ||
      n >= 128
    ) {
      good++
    }
  }

  return good / text.length > 0.65
}


// ============================================================
// CUSTOM BASE64
// ============================================================

function customBase64Decode(input) {
  if (typeof input !== "string") {
    throw new Error("custom base64 input bukan string")
  }

  let value = input
    .replace(/\?/g, "")
    .replace(/\s+/g, "")

  while (value.length % 4 !== 0) {
    value += "="
  }

  let standard = ""

  for (const ch of value) {
    if (ch === "=") {
      standard += "="
      continue
    }

    const pos = CUSTOM_ALPHABET.indexOf(ch)

    if (pos === -1) {
      throw new Error(
        `custom base64 karakter tidak dikenal: ${ch}`
      )
    }

    standard += STD_ALPHABET[pos]
  }

  return Buffer.from(standard, "base64")
}


// ============================================================
// PKCS7 UNPAD
// ============================================================

function pkcs7Unpad(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw new Error("buffer kosong")
  }

  const pad = buffer[buffer.length - 1]

  if (pad < 1 || pad > 16) {
    throw new Error("PKCS7 padding invalid")
  }

  if (pad > buffer.length) {
    throw new Error("PKCS7 padding terlalu besar")
  }

  for (let i = buffer.length - pad; i < buffer.length; i++) {
    if (buffer[i] !== pad) {
      throw new Error("PKCS7 padding invalid")
    }
  }

  return buffer.subarray(0, buffer.length - pad)
}


// ============================================================
// AES CBC
// ============================================================

function aesCbcDecrypt(data, key, iv) {
  if (key.length === 32) {
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      key,
      iv
    )

    decipher.setAutoPadding(false)

    return pkcs7Unpad(
      Buffer.concat([
        decipher.update(data),
        decipher.final()
      ])
    )
  }

  if (key.length === 16) {
    const decipher = crypto.createDecipheriv(
      "aes-128-cbc",
      key,
      iv
    )

    decipher.setAutoPadding(false)

    return pkcs7Unpad(
      Buffer.concat([
        decipher.update(data),
        decipher.final()
      ])
    )
  }

  throw new Error("AES key length invalid")
}


// ============================================================
// XOR LAYER
// ============================================================

function decryptXorLayer(value, key) {
  if (typeof value !== "string") {
    throw new Error("XOR layer bukan string")
  }

  let reversed = value
    .split("")
    .reverse()
    .join("")

  const decoded = customBase64Decode(reversed)

  let hex = decoded.toString("ascii").trim()

  if (hex.length % 2 !== 0) {
    hex = "0" + hex
  }

  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("XOR layer bukan hex")
  }

  const encrypted = Buffer.from(hex, "hex")

  const keyBuf = Buffer.from(
    String(key),
    "utf8"
  )

  if (!keyBuf.length) {
    throw new Error("XOR key kosong")
  }

  const output = []

  for (let i = 0; i < encrypted.length; i++) {
    const x =
      encrypted[i] ^
      keyBuf[i % keyBuf.length]

    if (x !== 0) {
      output.push(x)
    }
  }

  const result = Buffer.from(output)
    .toString("utf8")

  if (!isPrintable(result)) {
    throw new Error("hasil XOR tidak valid")
  }

  return result
}


// ============================================================
// CONFIG MESSAGE
// ============================================================

function decodeConfigMessage(value) {
  const raw = Buffer.from(
    String(value),
    "base64"
  )

  const text = raw.toString("utf8")

  // Python implementation:
  //
  // text.encode("utf-16-be")
  //
  // lalu XOR setiap Java char dengan EHIMSG

  const utf16 = Buffer.from(text, "utf16le")

  const key = Buffer.from(
    "EHIMSG",
    "utf16le"
  )

  const chars = []

  for (let i = 0; i + 1 < utf16.length; i += 2) {
    const value16 =
      utf16.readUInt16LE(i)

    const key16 =
      key.readUInt16LE(
        (i % key.length)
      )

    chars.push(
      value16 ^ key16
    )
  }

  const output = Buffer.alloc(
    chars.length * 2
  )

  for (let i = 0; i < chars.length; i++) {
    output.writeUInt16LE(
      chars[i],
      i * 2
    )
  }

  return output.toString("utf16le")
}


// ============================================================
// XXTEA
// ============================================================

function mx(z, y, sum, k, p, e) {
  return (
    (
      (((z >>> 5) ^ (y << 2)) +
        ((y >>> 3) ^ (z << 4))) ^
      ((sum ^ y) + (k[(p & 3) ^ e] ^ z))
    )
  ) >>> 0
}

function xxteaDecrypt(data, key) {
  if (!Buffer.isBuffer(data)) {
    data = Buffer.from(data)
  }

  if (!data.length) {
    return Buffer.alloc(0)
  }

  const k = Buffer.alloc(16)

  Buffer.from(key)
    .subarray(0, 16)
    .copy(k)

  const n = Math.floor(data.length / 4)

  if (n < 2) {
    return data
  }

  const v = new Uint32Array(n)

  for (let i = 0; i < n; i++) {
    v[i] = data.readUInt32LE(i * 4)
  }

  const DELTA = 0x9e3779b9

  let z = v[n - 1]
  let y = v[0]

  let q =
    Math.floor(
      6 + 52 / n
    )

  let sum =
    Math.imul(q, DELTA) >>> 0

  while (sum !== 0) {
    const e =
      (sum >>> 2) & 3

    for (
      let p = n - 1;
      p > 0;
      p--
    ) {
      y = v[p - 1]

      const m = mx(
        z,
        y,
        sum,
        new Uint32Array([
          k.readUInt32LE(0),
          k.readUInt32LE(4),
          k.readUInt32LE(8),
          k.readUInt32LE(12)
        ]),
        p,
        e
      )

      v[p] =
        (v[p] - m) >>> 0

      z = v[p]
    }

    y = v[n - 1]

    const m = mx(
      z,
      y,
      sum,
      new Uint32Array([
        k.readUInt32LE(0),
        k.readUInt32LE(4),
        k.readUInt32LE(8),
        k.readUInt32LE(12)
      ]),
      0,
      e
    )

    v[0] =
      (v[0] - m) >>> 0

    z = v[0]

    sum =
      (sum - DELTA) >>> 0
  }

  const output = Buffer.alloc(
    n * 4
  )

  for (let i = 0; i < n; i++) {
    output.writeUInt32LE(
      v[i] >>> 0,
      i * 4
    )
  }

  // XXTEA implementation stores the
  // original byte length in the final word.

  const byteLength =
    output.readUInt32LE(
      output.length - 4
    )

  if (
    byteLength > 0 &&
    byteLength <= output.length
  ) {
    return output.subarray(
      0,
      byteLength
    )
  }

  return output
}


// ============================================================
// EHI CONTAINER
// ============================================================

function parseEhiContainer(buffer) {
  let offset = 0

  function readUtf() {
    if (offset + 2 > buffer.length) {
      throw new Error("EHI container truncated")
    }

    const len =
      buffer.readUInt16BE(offset)

    offset += 2

    if (
      offset + len >
      buffer.length
    ) {
      throw new Error(
        "EHI UTF length invalid"
      )
    }

    const value =
      buffer
        .subarray(offset, offset + len)
        .toString("utf8")

    offset += len

    return value
  }

  const type = readUtf()

  if (offset + 8 > buffer.length) {
    throw new Error("EHI header invalid")
  }

  offset += 8

  const version = readUtf()

  if (offset + 8 > buffer.length) {
    throw new Error("EHI header invalid")
  }

  offset += 8

  if (offset + 4 > buffer.length) {
    throw new Error("EHI payload header invalid")
  }

  const payloadLength =
    buffer.readUInt32BE(offset)

  offset += 4

  if (offset + 8 > buffer.length) {
    throw new Error("EHI payload header invalid")
  }

  offset += 8

  if (
    offset + payloadLength >
    buffer.length
  ) {
    throw new Error(
      `EHI payload truncated: ${payloadLength}`
    )
  }

  const payload =
    buffer.subarray(
      offset,
      offset + payloadLength
    )

  return {
    type,
    version,
    payload
  }
}


// ============================================================
// MASTER KEY
// ============================================================

function generateMasterKey(config) {
  const values = [
    config.configAesKey,
    config.configIdentifier,
    config.configSalt,
    config.configTimestamp,
    config.configExpiryTimestamp,
    Array.isArray(config.lockModes)
      ? config.lockModes.join("")
      : config.lockModes,
    config.lockModesHash,
    config.configHwid,
    config.configLockMobileOperatorId
  ]

  const input = values
    .filter(
      value =>
        value !== undefined &&
        value !== null &&
        String(value).length > 0
    )
    .map(value => String(value))
    .join("")

  return crypto
    .createHash("sha256")
    .update(
      Buffer.from(input, "utf8")
    )
    .digest()
}


// ============================================================
// INNER FIELDS
// ============================================================

function decodeInnerFields(
  object,
  configSalt
) {
  if (!object || typeof object !== "object") {
    return object
  }

  if (Array.isArray(object)) {
    return object.map(item =>
      decodeInnerFields(
        item,
        configSalt
      )
    )
  }

  const output = {}

  for (const [key, value] of Object.entries(object)) {
    if (
      typeof value === "string" &&
      value.length
    ) {
      try {
        if (key === "configMessage") {
          output[key] =
            decodeConfigMessage(value)
        } else {
          try {
            output[key] =
              decryptXorLayer(
                value,
                configSalt
              )
          } catch {
            output[key] = value
          }
        }
      } catch {
        output[key] = value
      }
    } else if (
      value &&
      typeof value === "object"
    ) {
      output[key] =
        decodeInnerFields(
          value,
          configSalt
        )
    } else {
      output[key] = value
    }
  }

  return output
}


// ============================================================
// EMBEDDED JSON
// ============================================================

function parseEmbeddedJson(config) {
  const fields = [
    "v2rRawJson",
    "overwriteServerData"
  ]

  for (const field of fields) {
    if (
      typeof config[field] !== "string"
    ) {
      continue
    }

    try {
      const parsed =
        JSON.parse(config[field])

      config[field] = parsed
    } catch {
      // ignore
    }
  }

  return config
}


// ============================================================
// LOCKED CONFIG
// ============================================================

async function decryptLockedConfig(
  configData,
  config
) {
  if (
    typeof configData !== "string" ||
    !configData.length
  ) {
    throw new Error(
      "configData kosong"
    )
  }

  const configSalt =
    String(
      config.configSalt || ""
    )

  if (!configSalt) {
    throw new Error(
      "configSalt kosong"
    )
  }

  // ----------------------------------------------------------
  // IMPORTANT:
  // EHI standard configData:
  //
  // XOR characters using configSalt
  // -> Base64
  // -> binary lock payload
  // ----------------------------------------------------------

  let xorDecoded = ""

  for (
    let i = 0;
    i < configData.length;
    i++
  ) {
    xorDecoded += String.fromCharCode(
      configData.charCodeAt(i) ^
      configSalt.charCodeAt(
        i % configSalt.length
      )
    )
  }

  const raw = Buffer.from(
    xorDecoded,
    "base64"
  )

  if (raw.length < 0x32 + 16) {
    throw new Error(
      `locked config terlalu pendek: ${raw.length}`
    )
  }

  // ----------------------------------------------------------
  // HEADER
  // ----------------------------------------------------------

  const timeCost =
    raw.readUInt32LE(1)

  const memoryCost =
    raw.readUInt32LE(5)

  const parallelism =
    raw.readUInt8(9)

  const argonSalt =
    raw.subarray(
      0x0a,
      0x1a
    )

  const nonce =
    raw.subarray(
      0x1a,
      0x32
    )

  const aad =
    raw.subarray(
      0,
      0x1a
    )

  // IMPORTANT:
  // libsodium combined mode requires
  // ciphertext + 16-byte authentication tag.
  const ciphertext =
    raw.subarray(
      0x32
    )

  if (
    argonSalt.length !== 16
  ) {
    throw new Error(
      "Argon2 salt harus 16 byte"
    )
  }

  if (
    nonce.length !== 24
  ) {
    throw new Error(
      "XChaCha nonce harus 24 byte"
    )
  }

  if (
    ciphertext.length <= 16
  ) {
    throw new Error(
      "ciphertext terlalu pendek"
    )
  }

  // ----------------------------------------------------------
  // PARAMETER CHECK
  // ----------------------------------------------------------

  if (
    timeCost < 1 ||
    timeCost > 100
  ) {
    throw new Error(
      `Argon2 timeCost invalid: ${timeCost}`
    )
  }

  if (
    memoryCost < 8 ||
    memoryCost > 1048576
  ) {
    throw new Error(
      `Argon2 memoryCost invalid: ${memoryCost}`
    )
  }

  if (
    parallelism < 1 ||
    parallelism > 64
  ) {
    throw new Error(
      `Argon2 parallelism invalid: ${parallelism}`
    )
  }

  // ----------------------------------------------------------
  // MASTER KEY
  // ----------------------------------------------------------

  const masterKey =
    generateMasterKey(config)

  // ----------------------------------------------------------
  // ARGON2ID
  // ----------------------------------------------------------

  const derived =
    await argon2id({
      password: masterKey,
      salt: argonSalt,
      iterations: timeCost,
      memorySize: memoryCost,
      parallelism,
      hashLength: 32,
      outputType: "binary"
    })

  const key =
    Buffer.from(derived)

  if (key.length !== 32) {
    throw new Error(
      "Argon2 menghasilkan key bukan 32 byte"
    )
  }

  // ----------------------------------------------------------
  // XCHACHA20-POLY1305
  // ----------------------------------------------------------

  await sodium.ready

  let decrypted

  try {
    decrypted =
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        aad,
        nonce,
        key
      )
  } catch (error) {
    throw new Error(
      "XChaCha20 gagal: authentication tag tidak cocok"
    )
  }

  if (!decrypted) {
    throw new Error(
      "XChaCha20 gagal decrypt"
    )
  }

  return Buffer.from(decrypted)
}


// ============================================================
// OUTER EHI
// ============================================================

function parseJsonFromBytes(buffer) {
  const text =
    buffer.toString("utf8")

  const start =
    text.indexOf("{")

  if (start === -1) {
    throw new Error(
      "JSON hasil XXTEA tidak ditemukan"
    )
  }

  const jsonText =
    text.slice(start)

  try {
    return JSON.parse(jsonText)
  } catch {
    // Try until the last }
    const end =
      jsonText.lastIndexOf("}")

    if (end === -1) {
      throw new Error(
        "JSON hasil decrypt invalid"
      )
    }

    return JSON.parse(
      jsonText.slice(0, end + 1)
    )
  }
}


function decryptOuter(
  payload
) {
  let lastError = null

  for (const candidate of ALL_IVS) {
    try {
      const layer1 =
        aesCbcDecrypt(
          payload,
          L1_KEY,
          candidate.iv
        )

      const text =
        layer1.toString("utf8")

      const parts =
        text.split(":")

      if (parts.length < 3) {
        throw new Error(
          "layer 1 bukan format EHI"
        )
      }

      const iv2 =
        Buffer.from(
          parts[0],
          "base64"
        )

      const encrypted2 =
        Buffer.from(
          parts[2],
          "base64"
        )

      if (
        iv2.length !== 16
      ) {
        throw new Error(
          "L2 IV invalid"
        )
      }

      const layer2 =
        aesCbcDecrypt(
          encrypted2,
          L2_KEY_STATIC,
          iv2
        )

      const layer3 =
        xxteaDecrypt(
          layer2,
          EOO_MASTER_KEY
        )

      const config =
        parseJsonFromBytes(
          layer3
        )

      if (
        !config ||
        typeof config !== "object"
      ) {
        throw new Error(
          "config bukan object"
        )
      }

      return {
        config,
        mode: candidate.mode,
        matchedIv:
          candidate.iv.toString("hex")
      }

    } catch (error) {
      lastError = error
    }
  }

  throw new Error(
    `Semua IV EHI gagal: ${
      lastError?.message || "unknown"
    }`
  )
}


// ============================================================
// COMMON FIELD EXTRACTION
// ============================================================

function findValue(
  object,
  names
) {
  if (
    !object ||
    typeof object !== "object"
  ) {
    return undefined
  }

  for (const name of names) {
    if (
      object[name] !== undefined &&
      object[name] !== null &&
      object[name] !== ""
    ) {
      return object[name]
    }
  }

  return undefined
}


function extractCommon(config) {
  const host =
    findValue(config, [
      "host",
      "sshHost",
      "server",
      "address"
    ])

  const port =
    findValue(config, [
      "port",
      "sshPort"
    ])

  const username =
    findValue(config, [
      "username",
      "user",
      "sshUsername",
      "sshUser"
    ])

  const password =
    findValue(config, [
      "password",
      "pass",
      "sshPassword",
      "sshPass"
    ])

  const sni =
    findValue(config, [
      "sniHostname",
      "sni",
      "serverName"
    ])

  const proxy =
    findValue(config, [
      "remoteProxy",
      "proxy",
      "proxyHost"
    ])

  const payload =
    findValue(config, [
      "payload",
      "httpPayload",
      "requestPayload"
    ])

  return {
    host: host ?? null,
    port: port ?? null,
    username: username ?? null,
    password: password ?? null,
    sni: sni ?? null,
    proxy: proxy ?? null,
    payload: payload ?? null
  }
}


// ============================================================
// MAIN DECRYPTOR
// ============================================================

async function decryptEHI(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(buffer)
  }

  if (!buffer.length) {
    throw new Error(
      "File EHI kosong"
    )
  }

  // ----------------------------------------------------------
  // CONTAINER
  // ----------------------------------------------------------

  const container =
    parseEhiContainer(buffer)

  // ----------------------------------------------------------
  // OUTER
  // ----------------------------------------------------------

  const outer =
    decryptOuter(
      container.payload
    )

  let config =
    outer.config

  // ----------------------------------------------------------
  // LOCKED / STANDARD
  // ----------------------------------------------------------

  if (
    outer.mode === "standard" &&
    config.configData
  ) {
    const decrypted =
      await decryptLockedConfig(
        config.configData,
        config
      )

    const decodedText =
      decrypted.toString("utf8")

    let inner

    try {
      inner =
        JSON.parse(decodedText)
    } catch {
      const start =
        decodedText.indexOf("{")

      const end =
        decodedText.lastIndexOf("}")

      if (
        start === -1 ||
        end === -1
      ) {
        throw new Error(
          "Inner config JSON tidak valid"
        )
      }

      inner =
        JSON.parse(
          decodedText.slice(
            start,
            end + 1
          )
        )
    }

    // Merge inner config
    config = {
      ...config,
      ...inner
    }
  }

  // ----------------------------------------------------------
  // INNER FIELD DECODING
  // ----------------------------------------------------------

  config =
    decodeInnerFields(
      config,
      config.configSalt || ""
    )

  config =
    parseEmbeddedJson(
      config
    )

  const common =
    extractCommon(config)

  return {
    success: true,

    type: container.type,

    appVersion:
      container.version,

    mode:
      outer.mode,

    matchedIv:
      outer.matchedIv,

    ...common,

    config
  }
}


// ============================================================
// HTTP BODY
// ============================================================

function getBodyBuffer(req) {
  if (Buffer.isBuffer(req.body)) {
    return req.body
  }

  if (
    req.body &&
    req.body.type === "Buffer" &&
    Array.isArray(req.body.data)
  ) {
    return Buffer.from(
      req.body.data
    )
  }

  if (
    typeof req.body === "string"
  ) {
    return Buffer.from(
      req.body,
      "base64"
    )
  }

  return null
}


// ============================================================
// VERCEL HANDLER
// ============================================================

module.exports = async function handler(
  req,
  res
) {
  res.setHeader(
    "Access-Control-Allow-Origin",
    "*"
  )

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,OPTIONS"
  )

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  )

  if (req.method === "OPTIONS") {
    return res
      .status(204)
      .end()
  }

  // ----------------------------------------------------------
  // TEST GET
  // ----------------------------------------------------------

  if (req.method === "GET") {
    return res.status(200).json({
      success: true,
      api: "HTTP Injector EHI Decrypt API",
      status: "online",
      endpoint: "/api/ehi",
      method: "POST",
      format: "application/octet-stream"
    })
  }

  // ----------------------------------------------------------
  // ONLY POST
  // ----------------------------------------------------------

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    })
  }

  try {
    const buffer =
      getBodyBuffer(req)

    if (!buffer) {
      return res.status(400).json({
        success: false,
        error: "Body file EHI tidak ditemukan"
      })
    }

    if (!buffer.length) {
      return res.status(400).json({
        success: false,
        error: "File EHI kosong"
      })
    }

    const result =
      await decryptEHI(buffer)

    return res.status(200).json(
      result
    )

  } catch (error) {
    console.error(
      "[EHI DECRYPT ERROR]",
      error
    )

    return res.status(400).json({
      success: false,
      error:
        error?.message ||
        "Gagal decrypt EHI"
    })
  }
}
