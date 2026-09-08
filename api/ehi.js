const crypto = require("crypto")
const { argon2id } = require("hash-wasm")
const sodiumModule = require("libsodium-wrappers")

// ============================================================
// EHI CONSTANTS
// ============================================================

const EHI = {

  // AES-256 Layer 1
  L1_KEY: Buffer.from(
    "7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c",
    "hex"
  ),

  // AES-128 Layer 2
  L2_KEY_STATIC: Buffer.from(
    "b2bc617c32d8b9eb1943a5ffa8051eea",
    "hex"
  ),

  // XXTEA
  EOO_MASTER_KEY: Buffer.from(
    "null=V5kU5+FFrY\u0000",
    "utf8"
  ),

  // ----------------------------------------------------------
  // BYPASS IV
  // ----------------------------------------------------------

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

  // ----------------------------------------------------------
  // STANDARD IV
  // ----------------------------------------------------------

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

  // ----------------------------------------------------------
  // BASE64
  // ----------------------------------------------------------

  STD_ALPHABET:
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",

  CUSTOM_ALPHABET:
    "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs",

  // ----------------------------------------------------------
  // MASTER FIELD
  // ----------------------------------------------------------

  MASTER_FIELDS: [
    "configAesKey",
    "configIdentifier",
    "configSalt",
    "configTimestamp",
    "configExpiryTimestamp",
    "lockModes",
    "lockModesHash",
    "configHwid",
    "configLockMobileOperatorId"
  ]
}


// ============================================================
// HELPERS
// ============================================================

function safeJson(res, status, data) {

  res.status(status)

  res.setHeader(
    "Content-Type",
    "application/json; charset=utf-8"
  )

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

  return res.end(
    JSON.stringify(data)
  )
}


// ============================================================
// BUFFER NORMALIZER
// ============================================================

function getBufferBody(req) {

  const body = req.body

  if (!body) {
    throw new Error("Request body kosong")
  }

  if (Buffer.isBuffer(body)) {
    return body
  }

  if (body instanceof Uint8Array) {
    return Buffer.from(body)
  }

  throw new Error(
    "Kirim file EHI dengan Content-Type: application/octet-stream"
  )
}


// ============================================================
// CUSTOM BASE64
// ============================================================

function customBase64Decode(value) {

  if (
    value === null ||
    value === undefined
  ) {
    throw new Error("Base64 kosong")
  }

  let input =
    String(value)
      .replace(/\?/g, "")
      .trim()

  const custom =
    EHI.CUSTOM_ALPHABET

  const standard =
    EHI.STD_ALPHABET

  let translated = ""

  for (const char of input) {

    const index =
      custom.indexOf(char)

    if (index >= 0) {
      translated += standard[index]
    } else {
      translated += char
    }
  }

  while (
    translated.length % 4 !== 0
  ) {
    translated += "="
  }

  return Buffer.from(
    translated,
    "base64"
  )
}


// ============================================================
// AES CBC
// ============================================================

function aesCbcDecrypt(
  ciphertext,
  key,
  iv
) {

  if (
    !Buffer.isBuffer(ciphertext) ||
    ciphertext.length === 0
  ) {
    throw new Error("AES ciphertext kosong")
  }

  if (
    ciphertext.length % 16 !== 0
  ) {
    throw new Error(
      "AES ciphertext bukan kelipatan 16"
    )
  }

  const algorithm =
    key.length === 32
      ? "aes-256-cbc"
      : key.length === 16
        ? "aes-128-cbc"
        : null

  if (!algorithm) {
    throw new Error(
      "Ukuran AES key tidak valid"
    )
  }

  const decipher =
    crypto.createDecipheriv(
      algorithm,
      key,
      iv
    )

  decipher.setAutoPadding(true)

  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ])
}


// ============================================================
// XOR LAYER
// ============================================================

function decryptXorLayer(
  ciphertext,
  key
) {

  if (
    ciphertext === null ||
    ciphertext === undefined
  ) {
    return null
  }

  if (
    !String(ciphertext).trim()
  ) {
    return ciphertext
  }

  try {

    const reversed =
      String(ciphertext)
        .split("")
        .reverse()
        .join("")

    const rawHexText =
      customBase64Decode(reversed)
        .toString("ascii")

    let hex =
      rawHexText.trim()

    if (
      hex.length % 2 !== 0
    ) {
      hex = "0" + hex
    }

    if (
      !/^[0-9a-fA-F]+$/.test(hex)
    ) {
      return null
    }

    const raw =
      Buffer.from(hex, "hex")

    const keyString =
      String(key)

    if (!keyString.length) {
      return null
    }

    const output = []

    for (
      let i = 0;
      i < raw.length;
      i++
    ) {

      const value =
        raw[i] ^
        keyString.charCodeAt(
          i % keyString.length
        )

      // Source format removes zero bytes
      if (value !== 0) {
        output.push(value)
      }
    }

    const plaintext =
      Buffer.from(output)
        .toString("utf8")

    // Reject obviously binary garbage
    if (plaintext.length) {

      let bad = 0

      for (const char of plaintext) {

        const code =
          char.charCodeAt(0)

        if (
          code < 32 &&
          code !== 9 &&
          code !== 10 &&
          code !== 13
        ) {
          bad++
        }
      }

      if (
        bad / plaintext.length > 0.5
      ) {
        return null
      }
    }

    return plaintext

  } catch {
    return null
  }
}


// ============================================================
// CONFIG MESSAGE
// ============================================================

function decodeConfigMessage(
  value
) {

  if (
    !value ||
    !String(value).trim()
  ) {
    return value
  }

  try {

    let input =
      String(value)

    while (
      input.length % 4 !== 0
    ) {
      input += "="
    }

    const raw =
      Buffer.from(
        input,
        "base64"
      )

    // EHI uses Java-char semantics.
    const utf8Text =
      raw.toString("utf8")

    const utf16 =
      Buffer.from(
        utf8Text,
        "utf16le"
      )

    const javaChars = []

    for (
      let i = 0;
      i + 1 < utf16.length;
      i += 2
    ) {

      javaChars.push(
        utf16.readUInt16LE(i)
      )
    }

    const key =
      "EHIMSG"

    const result =
      Buffer.alloc(
        javaChars.length * 2
      )

    for (
      let i = 0;
      i < javaChars.length;
      i++
    ) {

      const value =
        javaChars[i] ^
        key.charCodeAt(
          i % key.length
        )

      result.writeUInt16BE(
        value & 0xffff,
        i * 2
      )
    }

    return result
      .toString("utf16be")

  } catch {

    return value
  }
}


// ============================================================
// XXTEA
// ============================================================

function xxteaDecrypt(
  input,
  key
) {

  if (
    !input ||
    !input.length
  ) {
    return Buffer.alloc(0)
  }

  let data =
    Buffer.from(input)

  const remainder =
    data.length % 4

  if (remainder) {

    data = Buffer.concat([
      data,
      Buffer.alloc(
        4 - remainder
      )
    ])
  }

  const n =
    data.length / 4

  if (n < 2) {
    return data
  }

  const k =
    Buffer.concat([
      key,
      Buffer.alloc(
        Math.max(
          0,
          16 - key.length
        )
      )
    ]).subarray(0, 16)

  const K = [
    k.readUInt32LE(0),
    k.readUInt32LE(4),
    k.readUInt32LE(8),
    k.readUInt32LE(12)
  ]

  const v = new Array(n)

  for (
    let i = 0;
    i < n;
    i++
  ) {
    v[i] =
      data.readUInt32LE(
        i * 4
      )
  }

  const delta =
    0x9e3779b9

  let sum =
    Math.imul(
      6 + Math.floor(52 / n),
      delta
    ) >>> 0

  let y =
    v[0]

  while (sum !== 0) {

    const e =
      (sum >>> 2) & 3

    for (
      let p = n - 1;
      p > 0;
      p--
    ) {

      const z =
        v[p - 1]

      const mx =
        (
          (
            (
              ((z >>> 5) ^
                Math.imul(y, 4))
            ) +
            (
              ((y >>> 3) ^
                Math.imul(z, 16))
            )
          ) ^
          (
            (
              (sum ^ y)
            ) +
            (
              K[
                (p & 3) ^ e
              ] ^ z
            )
          )
        ) >>> 0

      v[p] =
        (v[p] - mx) >>> 0

      y =
        v[p]
    }

    const z =
      v[n - 1]

    const mx =
      (
        (
          (
            (z >>> 5) ^
            Math.imul(y, 4)
          ) +
          (
            (y >>> 3) ^
            Math.imul(z, 16)
          )
        ) ^
        (
          (
            sum ^ y
          ) +
          (
            K[e] ^ z
          )
        )
      ) >>> 0

    v[0] =
      (v[0] - mx) >>> 0

    y =
      v[0]

    sum =
      (sum - delta) >>> 0
  }

  const output =
    Buffer.alloc(
      n * 4
    )

  for (
    let i = 0;
    i < n;
    i++
  ) {

    output.writeUInt32LE(
      v[i] >>> 0,
      i * 4
    )
  }

  const declaredLength =
    v[n - 1] >>> 0

  if (
    declaredLength > 0 &&
    declaredLength <= output.length
  ) {
    return output.subarray(
      0,
      declaredLength
    )
  }

  // fallback
  let end =
    output.length

  while (
    end > 0 &&
    output[end - 1] === 0
  ) {
    end--
  }

  return output.subarray(
    0,
    end
  )
}


// ============================================================
// EHI CONTAINER PARSER
// ============================================================

function parseEhiContainer(
  file
) {

  let offset = 0

  function readU16() {

    if (
      offset + 2 >
      file.length
    ) {
      throw new Error(
        "EHI header terpotong"
      )
    }

    const value =
      file.readUInt16BE(
        offset
      )

    offset += 2

    return value
  }

  function readU32() {

    if (
      offset + 4 >
      file.length
    ) {
      throw new Error(
        "EHI payload length terpotong"
      )
    }

    const value =
      file.readUInt32BE(
        offset
      )

    offset += 4

    return value
  }

  function readUTF8() {

    const length =
      readU16()

    if (
      offset + length >
      file.length
    ) {
      throw new Error(
        "EHI UTF field terpotong"
      )
    }

    const value =
      file
        .subarray(
          offset,
          offset + length
        )
        .toString("utf8")

    offset += length

    return value
  }

  const type =
    readUTF8()

  // reserved
  offset += 8

  const appVersion =
    readUTF8()

  // reserved
  offset += 8

  const payloadLength =
    readU32()

  // reserved
  offset += 8

  if (
    offset + payloadLength >
    file.length
  ) {
    throw new Error(
      "EHI encrypted payload terpotong"
    )
  }

  const payload =
    file.subarray(
      offset,
      offset + payloadLength
    )

  return {
    type,
    appVersion,
    payload
  }
}


// ============================================================
// GENERATE MASTER KEY
// ============================================================

function generateMasterKey(
  config
) {

  let text = ""

  for (
    const field of EHI.MASTER_FIELDS
  ) {

    let value =
      config[field]

    if (
      value === undefined ||
      value === null ||
      value === ""
    ) {
      continue
    }

    if (
      typeof value === "object"
    ) {
      value =
        String(value)
    }

    text += String(value)
  }

  return crypto
    .createHash("sha256")
    .update(
      text,
      "utf8"
    )
    .digest()
}


// ============================================================
// INNER FIELD DECODER
// ============================================================

function decodeInnerFields(
  object,
  salt
) {

  if (
    !object ||
    typeof object !== "object"
  ) {
    return object
  }

  const output = {}

  for (
    const [key, value]
    of Object.entries(object)
  ) {

    if (
      typeof value === "string" &&
      value.trim()
    ) {

      let decoded

      if (
        key === "configMessage"
      ) {

        decoded =
          decodeConfigMessage(
            value
          )

      } else {

        decoded =
          decryptXorLayer(
            value,
            salt
          )
      }

      output[key] =
        decoded !== null
          ? decoded
          : value

    } else {

      output[key] = value
    }
  }

  return output
}


// ============================================================
// PARSE EMBEDDED JSON
// ============================================================

function parseEmbeddedJson(
  object
) {

  const output = {
    ...object
  }

  for (
    const key of [
      "v2rRawJson",
      "overwriteServerData"
    ]
  ) {

    const value =
      output[key]

    if (
      typeof value !== "string"
    ) {
      continue
    }

    try {

      const start =
        value.indexOf("{")

      const end =
        value.lastIndexOf("}")

      if (
        start >= 0 &&
        end > start
      ) {

        const extracted =
          value.slice(
            start,
            end + 1
          )

        let parsed =
          JSON.parse(
            extracted
          )

        if (
          typeof parsed === "string"
        ) {
          parsed =
            JSON.parse(parsed)
        }

        output[key] =
          parsed
      }

    } catch {
      // leave original value
    }
  }

  return output
}


// ============================================================
// TRY OUTER DECRYPT
// ============================================================

function decryptOuter(
  encryptedPayload
) {

  const allIVs = [

    ...EHI.BYPASS_IVS.map(
      iv => ({
        iv,
        mode: "bypass"
      })
    ),

    ...EHI.STANDARD_IVS.map(
      iv => ({
        iv,
        mode: "standard"
      })
    )

  ]

  for (
    const item of allIVs
  ) {

    try {

      const layer1 =
        aesCbcDecrypt(
          encryptedPayload,
          EHI.L1_KEY,
          item.iv
        )

      const text =
        layer1.toString("utf8")

      const parts =
        text.split(":")

      if (
        parts.length < 3
      ) {
        continue
      }

      // First part is the AES-2 IV
      const layer2Iv =
        Buffer.from(
          parts[0],
          "base64"
        )

      if (
        layer2Iv.length !== 16
      ) {
        continue
      }

      const layer2Ciphertext =
        Buffer.from(
          parts[2],
          "base64"
        )

      if (
        !layer2Ciphertext.length ||
        layer2Ciphertext.length % 16 !== 0
      ) {
        continue
      }

      const layer2 =
        aesCbcDecrypt(
          layer2Ciphertext,
          EHI.L2_KEY_STATIC,
          layer2Iv
        )

      const xxtea =
        xxteaDecrypt(
          layer2,
          EHI.EOO_MASTER_KEY
        )

      const jsonStart =
        xxtea.indexOf(
          Buffer.from("{")
        )

      if (
        jsonStart < 0
      ) {
        continue
      }

      const jsonText =
        xxtea
          .subarray(jsonStart)
          .toString("utf8")
          .trim()

      const config =
        JSON.parse(jsonText)

      if (
        config &&
        typeof config === "object"
      ) {

        return {
          config,
          mode: item.mode,
          iv: item.iv.toString("hex")
        }
      }

    } catch {
      // try next IV
    }
  }

  throw new Error(
    "Tidak menemukan IV EHI yang cocok"
  )
}


// ============================================================
// FINAL STANDARD/LOCKED DECRYPT
// ============================================================

async function decryptLockedConfig(
  config,
  salt
) {

  const encrypted =
    config.configData

  if (
    !encrypted
  ) {
    throw new Error(
      "configData tidak ditemukan"
    )
  }

  const xor =
    decryptXorLayer(
      encrypted,
      salt
    )

  if (
    !xor
  ) {
    throw new Error(
      "Gagal XOR configData"
    )
  }

  const raw =
    Buffer.from(
      xor,
      "base64"
    )

  if (
    raw.length <= 50
  ) {
    throw new Error(
      "configData terlalu pendek"
    )
  }

  const timeCost =
    raw.readUInt32LE(1)

  const memoryCost =
    raw.readUInt32LE(5)

  const parallelism =
    raw[9]

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

  const ciphertext =
    raw.subarray(
      0x32,
      raw.length - 16
    )

  const tag =
    raw.subarray(
      raw.length - 16
    )

  if (
    nonce.length !== 24
  ) {
    throw new Error(
      "XChaCha nonce bukan 24 byte"
    )
  }

  if (
    tag.length !== 16
  ) {
    throw new Error(
      "Poly1305 tag bukan 16 byte"
    )
  }

  // Safety guard against pathological configs
  if (
    timeCost < 1 ||
    timeCost > 100
  ) {
    throw new Error(
      "Argon2 timeCost tidak valid"
    )
  }

  if (
    memoryCost < 8 ||
    memoryCost > 1024 * 1024
  ) {
    throw new Error(
      "Argon2 memoryCost tidak valid"
    )
  }

  if (
    parallelism < 1 ||
    parallelism > 64
  ) {
    throw new Error(
      "Argon2 parallelism tidak valid"
    )
  }

  const masterKey =
    generateMasterKey(
      config
    )

  const argonKey =
    await argon2id({

      password:
        masterKey,

      salt:
        argonSalt,

      iterations:
        timeCost,

      parallelism:
        parallelism,

      memorySize:
        memoryCost,

      hashLength:
        32,

      outputType:
        "binary"
    })

  // ==========================================================
  // XChaCha20-Poly1305
  // ==========================================================

  const sodium =
    sodiumModule

  await sodium.ready

  const combined =
    Buffer.concat([
      ciphertext,
      tag
    ])

  const plaintext =
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      combined,
      aad,
      nonce,
      Buffer.from(argonKey)
    )

  if (
    !plaintext
  ) {
    throw new Error(
      "XChaCha20-Poly1305 gagal"
    )
  }

  return JSON.parse(
    Buffer.from(
      plaintext
    ).toString("utf8")
  )
}


// ============================================================
// EXTRACT COMMON CONFIG
// ============================================================

function extractCommon(
  config
) {

  const result = {
    host:
      config.host ||
      config.server ||
      config.address ||
      "",

    port:
      config.port ||
      config.serverPort ||
      "",

    username:
      config.username ||
      config.user ||
      "",

    password:
      config.password ||
      "",

    sni:
      config.sniHostname ||
      config.sni ||
      config.serverName ||
      "",

    proxy:
      config.remoteProxy ||
      config.proxy ||
      "",

    payload:
      config.payload ||
      "",

    config
  }

  // Some EHI versions keep SSH
  // inside sshField
  if (
    typeof config.sshField === "string" &&
    config.sshField.trim()
  ) {

    const ssh =
      config.sshField

    // host:port@user:pass
    const match =
      ssh.match(
        /^(.+?):(\d+)@([^:]+):(.*)$/
      )

    if (match) {

      if (!result.host)
        result.host = match[1]

      if (!result.port)
        result.port = match[2]

      if (!result.username)
        result.username = match[3]

      if (!result.password)
        result.password = match[4]
    }
  }

  return result
}


// ============================================================
// MAIN DECRYPTOR
// ============================================================

async function decryptEHI(
  file
) {

  const container =
    parseEhiContainer(
      file
    )

  if (
    container.type &&
    container.type.toLowerCase() !== "ehi"
  ) {
    throw new Error(
      `Bukan file EHI (${container.type})`
    )
  }

  const outer =
    decryptOuter(
      container.payload
    )

  let config =
    outer.config

  const salt =
    config.configSalt ||
    "EVZJNI"

  // ----------------------------------------------------------
  // BYPASS
  // ----------------------------------------------------------

  if (
    outer.mode === "bypass"
  ) {

    config =
      decodeInnerFields(
        config,
        salt
      )
  }

  // ----------------------------------------------------------
  // STANDARD / LOCKED
  // ----------------------------------------------------------

  else {

    const finalConfig =
      await decryptLockedConfig(
        config,
        salt
      )

    config =
      decodeInnerFields(
        finalConfig,
        salt
      )
  }

  config =
    parseEmbeddedJson(
      config
    )

  const common =
    extractCommon(
      config
    )

  return {

    success: true,

    type:
      container.type,

    appVersion:
      container.appVersion,

    mode:
      outer.mode,

    matchedIv:
      outer.iv,

    ...common
  }
}


// ============================================================
// VERCEL HANDLER
// ============================================================

module.exports = async function handler(
  req,
  res
) {

  // ==========================================================
  // CORS
  // ==========================================================

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

  // ==========================================================
  // OPTIONS
  // ==========================================================

  if (
    req.method === "OPTIONS"
  ) {
    return res.status(200).end()
  }

  // ==========================================================
  // GET
  // ==========================================================

  if (
    req.method === "GET"
  ) {

    return safeJson(
      res,
      200,
      {
        success: true,
        status: "online",
        api: "EHI Decrypt API",
        version: "2.0.0",
        endpoint: "/api/ehi",
        method: "POST"
      }
    )
  }

  // ==========================================================
  // POST
  // ==========================================================

  if (
    req.method !== "POST"
  ) {

    return safeJson(
      res,
      405,
      {
        success: false,
        error: "Method Not Allowed"
      }
    )
  }

  try {

    const file =
      getBufferBody(
        req
      )

    if (
      file.length === 0
    ) {
      throw new Error(
        "File EHI kosong"
      )
    }

    if (
      file.length >
      4 * 1024 * 1024
    ) {
      throw new Error(
        "File EHI terlalu besar"
      )
    }

    const result =
      await decryptEHI(
        file
      )

    return safeJson(
      res,
      200,
      result
    )

  } catch (error) {

    console.error(
      "[EHI]",
      error
    )

    return safeJson(
      res,
      400,
      {
        success: false,

        error:
          error?.message ||
          "Gagal decrypt EHI"
      }
    )
  }
}
