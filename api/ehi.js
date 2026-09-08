"use strict"

const crypto = require("crypto")
const { argon2id } = require("hash-wasm")
const sodium = require("libsodium-wrappers")

// ======================================================
// CONSTANTS
// ======================================================

const L1_KEY = Buffer.from(
  "7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c",
  "hex"
)

const L2_KEY_STATIC = Buffer.from(
  "b2bc617c32d8b9eb1943a5ffa8051eea",
  "hex"
)

const EOO_MASTER_KEY =
  Buffer.from("null=V5kU5+FFrY\x00", "utf8")

const BYPASS_IVS = [
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
]

const STANDARD_IVS = [
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
]

const CUSTOM_ALPHABET =
  "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"

const STD_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// ======================================================
// CUSTOM BASE64
// ======================================================

function customBase64Decode(value) {
  let clean = String(value).replace(/\?/g, "")

  const rem = clean.length % 4

  if (rem) {
    clean += "=".repeat(4 - rem)
  }

  let standard = ""

  for (const char of clean) {
    if (char === "=") {
      standard += "="
      continue
    }

    const index =
      CUSTOM_ALPHABET.indexOf(char)

    if (index === -1) {
      throw new Error(
        "Invalid custom base64 character"
      )
    }

    standard += STD_ALPHABET[index]
  }

  return Buffer.from(
    standard,
    "base64"
  )
}

// ======================================================
// PKCS7 UNPAD
// ======================================================

function pkcs7Unpad(buffer) {
  if (!buffer.length) {
    throw new Error("Empty buffer")
  }

  const pad =
    buffer[buffer.length - 1]

  if (
    pad < 1 ||
    pad > 16 ||
    pad > buffer.length
  ) {
    throw new Error("Invalid padding")
  }

  for (
    let i = buffer.length - pad;
    i < buffer.length;
    i++
  ) {
    if (buffer[i] !== pad) {
      throw new Error("Invalid padding")
    }
  }

  return buffer.subarray(
    0,
    buffer.length - pad
  )
}

// ======================================================
// AES CBC
// ======================================================

function aesDecrypt(
  encrypted,
  key,
  iv
) {
  const algorithm =
    key.length === 32
      ? "aes-256-cbc"
      : "aes-128-cbc"

  const decipher =
    crypto.createDecipheriv(
      algorithm,
      key,
      iv
    )

  decipher.setAutoPadding(false)

  const decrypted =
    Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ])

  return pkcs7Unpad(decrypted)
}

// ======================================================
// XOR LAYER
// EXACT PORT OF PYTHON
// ======================================================

function decryptXorLayer(
  ciphertext,
  key
) {
  if (
    !ciphertext ||
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

    const hexBytes =
      customBase64Decode(reversed)

    let hexString =
      hexBytes.toString("ascii")

    if (hexString.length % 2 !== 0) {
      hexString =
        "0" + hexString
    }

    const raw =
      Buffer.from(hexString, "hex")

    const keyString =
      String(key)

    const result = []

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

      if (value !== 0) {
        result.push(value)
      }
    }

    const plaintext =
      Buffer.from(result)
        .toString("utf8")

    let controls = 0

    for (const char of plaintext) {
      const code =
        char.charCodeAt(0)

      if (
        code < 32 &&
        code !== 9 &&
        code !== 10 &&
        code !== 13
      ) {
        controls++
      }
    }

    if (
      plaintext.length &&
      controls / plaintext.length > 0.5
    ) {
      return null
    }

    return plaintext

  } catch {
    return null
  }
}

// ======================================================
// CONFIG MESSAGE
// ======================================================

function decodeConfigMessage(value) {
  if (
    !value ||
    !String(value).trim()
  ) {
    return value
  }

  try {
    let input =
      String(value)

    const rem =
      input.length % 4

    if (rem) {
      input += "=".repeat(4 - rem)
    }

    const raw =
      Buffer.from(
        input,
        "base64"
      )

    const text =
      raw.toString("utf8")

    const key =
      "EHIMSG"

    const chars = []

    for (
      let i = 0;
      i < text.length;
      i++
    ) {
      const original =
        text.charCodeAt(i)

      const xor =
        original ^
        key.charCodeAt(
          i % key.length
        )

      chars.push(xor)
    }

    return String.fromCharCode(
      ...chars
    )

  } catch {
    return value
  }
}

// ======================================================
// XXTEA
// EXACT PORT
// ======================================================

function xxteaDecrypt(
  data,
  key
) {
  if (!data.length) {
    return Buffer.alloc(0)
  }

  let input =
    Buffer.from(data)

  const rem =
    input.length % 4

  if (rem) {
    input = Buffer.concat([
      input,
      Buffer.alloc(4 - rem)
    ])
  }

  const key16 =
    Buffer.alloc(16)

  Buffer.from(key)
    .subarray(0, 16)
    .copy(key16)

  const k = [
    key16.readUInt32LE(0),
    key16.readUInt32LE(4),
    key16.readUInt32LE(8),
    key16.readUInt32LE(12)
  ]

  const n =
    input.length / 4

  const v =
    new Array(n)

  for (
    let i = 0;
    i < n;
    i++
  ) {
    v[i] =
      input.readUInt32LE(i * 4)
  }

  if (n < 2) {
    return input
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
            ((z >>> 5) ^
              (y << 2)) +
            ((y >>> 3) ^
              (z << 4))
          ) ^
          (
            (sum ^ y) +
            (
              k[
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
          ((z >>> 5) ^
            (y << 2)) +
          ((y >>> 3) ^
            (z << 4))
        ) ^
        (
          (sum ^ y) +
          (k[e] ^ z)
        )
      ) >>> 0

    v[0] =
      (v[0] - mx) >>> 0

    y =
      v[0]

    sum =
      (sum - delta) >>> 0
  }

  const decrypted =
    Buffer.alloc(
      n * 4
    )

  for (
    let i = 0;
    i < n;
    i++
  ) {
    decrypted.writeUInt32LE(
      v[i] >>> 0,
      i * 4
    )
  }

  const length =
    v[n - 1]

  if (
    length > 0 &&
    length <= decrypted.length
  ) {
    return decrypted.subarray(
      0,
      length
    )
  }

  return decrypted
}

// ======================================================
// EHI CONTAINER
// ======================================================

function parseEHI(
  file
) {
  let offset = 0

  function readUTF() {
    if (
      offset + 2 >
      file.length
    ) {
      return ""
    }

    const length =
      file.readUInt16BE(offset)

    offset += 2

    if (
      offset + length >
      file.length
    ) {
      return ""
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

  readUTF()

  offset += 8

  readUTF()

  offset += 8

  if (
    offset + 4 >
    file.length
  ) {
    return null
  }

  const payloadLength =
    file.readUInt32BE(offset)

  offset += 4

  offset += 8

  return file.subarray(
    offset,
    offset + payloadLength
  )
}

// ======================================================
// MASTER KEY
// EXACT PYTHON str() BEHAVIOR
// ======================================================

function pythonString(value) {
  if (Array.isArray(value)) {
    return (
      "[" +
      value
        .map(v => {
          if (
            typeof v === "string"
          ) {
            return `'${v}'`
          }

          return String(v)
        })
        .join(", ") +
      "]"
    )
  }

  return String(value)
}

function generateMasterKey(
  config
) {
  const values = [
    config.configAesKey || "",
    config.configIdentifier || "",
    config.configSalt || "",
    String(
      config.configTimestamp ?? 0
    ),
    String(
      config.configExpiryTimestamp ?? 0
    ),
    config.lockModes || "",
    config.lockModesHash || "",
    config.configHwid || "",
    config.configLockMobileOperatorId || ""
  ]

  const payload =
    values
      .filter(Boolean)
      .map(pythonString)
      .join("")

  return crypto
    .createHash("sha256")
    .update(
      payload,
      "utf8"
    )
    .digest()
}

// ======================================================
// OUTER DECRYPT
// ======================================================

function decryptOuter(
  payload
) {
  const candidates = [
    ...BYPASS_IVS.map(iv => ({
      iv,
      mode: "bypass"
    })),
    ...STANDARD_IVS.map(iv => ({
      iv,
      mode: "standard"
    }))
  ]

  let lastError

  for (const item of candidates) {
    try {
      const layer1 =
        aesDecrypt(
          payload,
          L1_KEY,
          item.iv
        )

      const text =
        layer1.toString("utf8")

      const parts =
        text.split(":")

      if (
        parts.length < 3
      ) {
        throw new Error(
          "Layer 1 invalid"
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

      const garbage =
        aesDecrypt(
          encrypted2,
          L2_KEY_STATIC,
          iv2
        )

      const finalRaw =
        xxteaDecrypt(
          garbage,
          EOO_MASTER_KEY
        )

      const start =
        finalRaw.indexOf(0x7b)

      if (start === -1) {
        throw new Error(
          "JSON tidak ditemukan"
        )
      }

      const config =
        JSON.parse(
          finalRaw
            .subarray(start)
            .toString("utf8")
        )

      return {
        config,
        mode: item.mode,
        iv: item.iv
      }

    } catch (error) {
      lastError = error
    }
  }

  throw new Error(
    "Semua IV EHI gagal: " +
    (
      lastError?.message ||
      "unknown"
    )
  )
}

// ======================================================
// LOCKED CONFIG
// ======================================================

async function decryptLocked(
  config
) {
  const salt =
    config.configSalt ||
    "EVZJNI"

  const configData =
    config.configData

  if (!configData) {
    throw new Error(
      "configData tidak ditemukan"
    )
  }

  // EXACT:
  // _decrypt_xor_layer(configData, salt)

  const decoded =
    decryptXorLayer(
      configData,
      salt
    )

  if (!decoded) {
    throw new Error(
      "configData XOR gagal"
    )
  }

  const raw =
    Buffer.from(
      decoded,
      "base64"
    )

  if (
    raw.length <= 50
  ) {
    throw new Error(
      "Locked payload invalid"
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
      -16
    )

  const tag =
    raw.subarray(
      -16
    )

  const masterKey =
    generateMasterKey(
      config
    )

  // hash-wasm:
  // memorySize = KiB
  const argonKey =
    Buffer.from(
      await argon2id({
        password: masterKey,
        salt: argonSalt,
        timeCost,
        iterations: timeCost,
        memorySize: memoryCost,
        parallelism,
        hashLength: 32,
        outputType: "binary"
      })
    )

  await sodium.ready

  let decrypted

  try {
    decrypted =
      sodium
        .crypto_aead_xchacha20poly1305_ietf_decrypt(
          null,
          Buffer.concat([
            ciphertext,
            tag
          ]),
          aad,
          nonce,
          argonKey
        )
  } catch {
    throw new Error(
      "XChaCha20 authentication gagal"
    )
  }

  if (!decrypted) {
    throw new Error(
      "XChaCha20 decrypt kosong"
    )
  }

  return JSON.parse(
    Buffer.from(decrypted)
      .toString("utf8")
  )
}

// ======================================================
// INNER FIELDS
// ======================================================

function decodeInnerFields(
  config,
  salt
) {
  const result = {}

  for (
    const [key, value]
    of Object.entries(config)
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

      result[key] =
        decoded !== null &&
        decoded !== undefined
          ? decoded
          : value

    } else {
      result[key] =
        value
    }
  }

  return result
}

// ======================================================
// MAIN
// ======================================================

async function decryptEHI(
  file
) {
  const payload =
    parseEHI(file)

  if (!payload) {
    throw new Error(
      "EHI container invalid"
    )
  }

  const outer =
    decryptOuter(
      payload
    )

  let finalConfig

  if (
    outer.mode === "bypass"
  ) {
    finalConfig =
      outer.config
  } else {
    finalConfig =
      await decryptLocked(
        outer.config
      )
  }

  const salt =
    outer.config.configSalt ||
    "EVZJNI"

  finalConfig =
    decodeInnerFields(
      finalConfig,
      salt
    )

  // embedded JSON
  for (
    const field of [
      "v2rRawJson",
      "overwriteServerData"
    ]
  ) {
    if (
      typeof finalConfig[field] === "string"
    ) {
      try {
        const text =
          finalConfig[field]

        const start =
          text.indexOf("{")

        const end =
          text.lastIndexOf("}")

        if (
          start !== -1 &&
          end !== -1
        ) {
          let parsed =
            JSON.parse(
              text.slice(
                start,
                end + 1
              )
            )

          if (
            typeof parsed === "string"
          ) {
            parsed =
              JSON.parse(parsed)
          }

          finalConfig[field] =
            parsed
        }
      } catch {}
    }
  }

  return {
    success: true,

    type: "ehi",

    appVersion:
      outer.config.appVersion ||
      null,

    mode:
      outer.mode,

    matchedIv:
      outer.iv.toString("hex"),

    host:
      finalConfig.host ||
      null,

    port:
      finalConfig.port ||
      null,

    username:
      finalConfig.username ||
      finalConfig.user ||
      null,

    password:
      finalConfig.password ||
      null,

    sni:
      finalConfig.sniHostname ||
      finalConfig.sni ||
      null,

    proxy:
      finalConfig.remoteProxy ||
      finalConfig.proxy ||
      null,

    payload:
      finalConfig.payload ||
      null,

    config:
      finalConfig
  }
}

// ======================================================
// BODY
// ======================================================

function getBody(req) {
  if (
    Buffer.isBuffer(req.body)
  ) {
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

// ======================================================
// VERCEL HANDLER
// ======================================================

module.exports =
  async function handler(
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

    if (
      req.method === "OPTIONS"
    ) {
      return res
        .status(204)
        .end()
    }

    if (
      req.method === "GET"
    ) {
      return res.status(200).json({
        success: true,
        api: "HTTP Injector EHI API",
        status: "online",
        version: "final"
      })
    }

    if (
      req.method !== "POST"
    ) {
      return res.status(405).json({
        success: false,
        error: "Method not allowed"
      })
    }

    try {
      const body =
        getBody(req)

      if (!body) {
        return res.status(400).json({
          success: false,
          error:
            "File EHI tidak ditemukan"
        })
      }

      const result =
        await decryptEHI(body)

      return res
        .status(200)
        .json(result)

    } catch (error) {
      console.error(
        "[EHI]",
        error
      )

      return res.status(400).json({
        success: false,
        error:
          error?.message ||
          "Decrypt EHI gagal"
      })
    }
  }
