"use strict"

const crypto = require("crypto")
const { argon2id } = require("hash-wasm")
const sodium = require("libsodium-wrappers")

// ============================================================
// CONSTANTS
// ============================================================

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

// ============================================================
// CUSTOM BASE64
// ============================================================

function customBase64Decode(value) {
  let s = String(value).replace(/\?/g, "")

  const rem = s.length % 4

  if (rem) {
    s += "=".repeat(4 - rem)
  }

  let out = ""

  for (const ch of s) {
    if (ch === "=") {
      out += "="
      continue
    }

    const index =
      CUSTOM_ALPHABET.indexOf(ch)

    if (index === -1) {
      throw new Error(
        `Invalid custom base64 character: ${ch}`
      )
    }

    out += STD_ALPHABET[index]
  }

  return Buffer.from(out, "base64")
}

// ============================================================
// PKCS7
// ============================================================

function unpad(buffer) {
  if (!buffer.length) {
    throw new Error("empty padded buffer")
  }

  const pad =
    buffer[buffer.length - 1]

  if (
    pad < 1 ||
    pad > 16 ||
    pad > buffer.length
  ) {
    throw new Error("bad padding")
  }

  for (
    let i = buffer.length - pad;
    i < buffer.length;
    i++
  ) {
    if (buffer[i] !== pad) {
      throw new Error("bad padding")
    }
  }

  return buffer.subarray(
    0,
    buffer.length - pad
  )
}

// ============================================================
// AES CBC
// ============================================================

function aesCbcDecrypt(
  data,
  key,
  iv
) {
  if (iv.length !== 16) {
    throw new Error(
      `AES IV harus 16 byte, dapat ${iv.length}`
    )
  }

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

  const result = Buffer.concat([
    decipher.update(data),
    decipher.final()
  ])

  return unpad(result)
}

// ============================================================
// EHI XOR LAYER
// ============================================================

function decryptXorLayer(
  ciphertextStr,
  key
) {
  if (
    !ciphertextStr ||
    !String(ciphertextStr).trim()
  ) {
    return ciphertextStr
  }

  try {
    // Python:
    // ciphertext_str[::-1]
    const reversed =
      String(ciphertextStr)
        .split("")
        .reverse()
        .join("")

    // custom base64
    const hexBytes =
      customBase64Decode(reversed)

    // ASCII hex
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

      if (value !== 0) {
        output.push(value)
      }
    }

    const plaintext =
      Buffer.from(output).toString("utf8")

    let controls = 0

    for (const c of plaintext) {
      const n = c.charCodeAt(0)

      if (
        n < 32 &&
        n !== 9 &&
        n !== 10 &&
        n !== 13
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

// ============================================================
// CONFIG MESSAGE
// ============================================================

function decodeConfigMessage(
  ciphertextStr
) {
  if (
    !ciphertextStr ||
    !String(ciphertextStr).trim()
  ) {
    return ciphertextStr
  }

  try {
    let s = String(ciphertextStr)

    const rem = s.length % 4

    if (rem) {
      s += "=".repeat(4 - rem)
    }

    const raw =
      Buffer.from(s, "base64")

    const utf8Text =
      raw.toString("utf8")

    // Python:
    // encode("utf-16-be")
    //
    // We manually create BE Java chars.

    const javaChars = []

    for (
      let i = 0;
      i < utf8Text.length;
      i++
    ) {
      const code =
        utf8Text.charCodeAt(i)

      javaChars.push(code)
    }

    const key =
      "EHIMSG"

    const result = []

    for (
      let i = 0;
      i < javaChars.length;
      i++
    ) {
      result.push(
        javaChars[i] ^
        key.charCodeAt(
          i % key.length
        )
      )
    }

    let output = ""

    for (const code of result) {
      output += String.fromCharCode(code)
    }

    return output

  } catch {
    return ciphertextStr
  }
}

// ============================================================
// XXTEA
// ============================================================

function xxteaDecrypt(
  data,
  key
) {
  if (!data.length) {
    return Buffer.alloc(0)
  }

  let input = Buffer.from(data)

  const rem = input.length % 4

  if (rem) {
    input = Buffer.concat([
      input,
      Buffer.alloc(4 - rem)
    ])
  }

  const kbuf = Buffer.alloc(16)

  Buffer.from(key)
    .subarray(0, 16)
    .copy(kbuf)

  const k = [
    kbuf.readUInt32LE(0),
    kbuf.readUInt32LE(4),
    kbuf.readUInt32LE(8),
    kbuf.readUInt32LE(12)
  ]

  const n =
    input.length / 4

  const v = new Array(n)

  for (let i = 0; i < n; i++) {
    v[i] =
      input.readUInt32LE(i * 4)
  }

  if (n < 2) {
    return input
  }

  const delta = 0x9e3779b9

  let sum =
    Math.imul(
      6 + Math.floor(52 / n),
      delta
    ) >>> 0

  let y = v[0]

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
            (k[(p & 3) ^ e] ^ z)
          )
        ) >>> 0

      v[p] =
        (v[p] - mx) >>> 0

      y = v[p]
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

    y = v[0]

    sum =
      (sum - delta) >>> 0
  }

  const output =
    Buffer.alloc(n * 4)

  for (let i = 0; i < n; i++) {
    output.writeUInt32LE(
      v[i] >>> 0,
      i * 4
    )
  }

  const length =
    v[n - 1]

  if (
    length > 0 &&
    length <= output.length
  ) {
    return output.subarray(
      0,
      length
    )
  }

  return output
}

// ============================================================
// CONTAINER
// ============================================================

function parseEhi(
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

    const text =
      file
        .subarray(
          offset,
          offset + length
        )
        .toString("utf8")

    offset += length

    return text
  }

  const type =
    readUTF()

  offset += 8

  const version =
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

  const payload =
    file.subarray(
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

function generateMasterKey(
  config
) {
  // PENTING:
  // Harus meniru Python:
  //
  // "".join(str(p) for p in (...) if p)
  //
  // Jadi array lockModes HARUS menjadi
  // String JavaScript seperti Python list,
  // bukan join("").

  const lockModes =
    config.lockModes || ""

  const values = [
    config.configAesKey || "",
    config.configIdentifier || "",
    config.configSalt || "",
    config.configTimestamp || 0,
    config.configExpiryTimestamp || 0,
    Array.isArray(lockModes)
      ? `[${lockModes.map(x => `'${x}'`).join(", ")}]`
      : lockModes,
    config.lockModesHash || "",
    config.configHwid || "",
    config.configLockMobileOperatorId || ""
  ]

  const payload =
    values
      .filter(v => v)
      .map(v => String(v))
      .join("")

  return crypto
    .createHash("sha256")
    .update(payload, "utf8")
    .digest()
}

// ============================================================
// OUTER DECRYPT
// ============================================================

function decryptOuter(
  payload
) {
  const ivs = [
    ...BYPASS_IVS.map(iv => ({
      iv,
      mode: "bypass"
    })),

    ...STANDARD_IVS.map(iv => ({
      iv,
      mode: "standard"
    }))
  ]

  let lastError = null

  for (const item of ivs) {
    try {
      // ------------------------------
      // LAYER 1
      // ------------------------------

      const layer1 =
        aesCbcDecrypt(
          payload,
          L1_KEY,
          item.iv
        )

      const text =
        layer1.toString("utf8")

      const parts =
        text.split(":")

      if (parts.length < 3) {
        throw new Error(
          "Layer 1 format invalid"
        )
      }

      // ------------------------------
      // LAYER 2
      //
      // EXACT Python:
      //
      // AES.new(
      //   L2_KEY_STATIC,
      //   AES.MODE_CBC,
      //   base64.b64decode(parts[0])
      // )
      //
      // ------------------------------

      const iv2 =
        Buffer.from(
          parts[0],
          "base64"
        )

      if (iv2.length !== 16) {
        throw new Error(
          `L2 IV invalid: ${iv2.length} byte`
        )
      }

      const encrypted2 =
        Buffer.from(
          parts[2],
          "base64"
        )

      const garbage =
        aesCbcDecrypt(
          encrypted2,
          L2_KEY_STATIC,
          iv2
        )

      // ------------------------------
      // XXTEA
      // ------------------------------

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
        matchedIv:
          item.iv.toString("hex")
      }

    } catch (err) {
      lastError = err
    }
  }

  throw new Error(
    `Semua IV EHI gagal: ${
      lastError?.message || "unknown"
    }`
  )
}

// ============================================================
// LOCKED CONFIG
// ============================================================

async function decryptLockedConfig(
  config
) {
  const targetSalt =
    config.configSalt || "EVZJNI"

  const targetData =
    config.configData

  if (!targetData) {
    throw new Error(
      "configData tidak ditemukan"
    )
  }

  // PENTING:
  // Harus pakai decryptXorLayer()
  // persis seperti Python source.

  const aaaResult =
    decryptXorLayer(
      targetData,
      targetSalt
    )

  if (!aaaResult) {
    throw new Error(
      "XOR configData gagal"
    )
  }

  const rawPayload =
    Buffer.from(
      aaaResult,
      "base64"
    )

  if (
    rawPayload.length <= 50
  ) {
    throw new Error(
      "locked payload terlalu pendek"
    )
  }

  const timeCost =
    rawPayload.readUInt32LE(1)

  const memoryCost =
    rawPayload.readUInt32LE(5)

  const parallelism =
    rawPayload[9]

  const argonSalt =
    rawPayload.subarray(
      0x0a,
      0x1a
    )

  const nonce =
    rawPayload.subarray(
      0x1a,
      0x32
    )

  const aad =
    rawPayload.subarray(
      0,
      0x1a
    )

  const ciphertext =
    rawPayload.subarray(
      0x32,
      -16
    )

  const tag =
    rawPayload.subarray(
      -16
    )

  const masterKey =
    generateMasterKey(config)

  const argonKey =
    Buffer.from(
      await argon2id({
        password: masterKey,
        salt: argonSalt,
        iterations: timeCost,
        memorySize: memoryCost,
        parallelism,
        hashLength: 32,
        outputType: "binary"
      })
    )

  await sodium.ready

  const combined =
    Buffer.concat([
      ciphertext,
      tag
    ])

  let plaintext

  try {
    plaintext =
      sodium
        .crypto_aead_xchacha20poly1305_ietf_decrypt(
          null,
          combined,
          aad,
          nonce,
          argonKey
        )
  } catch (err) {
    throw new Error(
      "XChaCha20 authentication gagal"
    )
  }

  if (!plaintext) {
    throw new Error(
      "XChaCha20 menghasilkan data kosong"
    )
  }

  return JSON.parse(
    Buffer.from(plaintext)
      .toString("utf8")
  )
}

// ============================================================
// INNER FIELD
// ============================================================

function decodeInnerFields(
  config,
  salt
) {
  const output = {}

  for (
    const [key, value]
    of Object.entries(config)
  ) {
    if (
      typeof value === "string" &&
      value.trim()
    ) {
      if (
        key === "configMessage"
      ) {
        output[key] =
          decodeConfigMessage(value)
      } else {
        const decoded =
          decryptXorLayer(
            value,
            salt
          )

        output[key] =
          decoded !== null
            ? decoded
            : value
      }

    } else {
      output[key] = value
    }
  }

  return output
}

// ============================================================
// MAIN
// ============================================================

async function decryptEHI(
  file
) {
  const container =
    parseEhi(file)

  if (!container) {
    throw new Error(
      "EHI container invalid"
    )
  }

  const outer =
    decryptOuter(
      container.payload
    )

  let parsedFinal

  if (
    outer.mode === "bypass"
  ) {
    parsedFinal =
      outer.config
  } else {
    parsedFinal =
      await decryptLockedConfig(
        outer.config
      )
  }

  const salt =
    outer.config.configSalt ||
    "EVZJNI"

  const cleaned =
    decodeInnerFields(
      parsedFinal,
      salt
    )

  // Parse embedded JSON
  for (
    const field of [
      "v2rRawJson",
      "overwriteServerData"
    ]
  ) {
    if (
      typeof cleaned[field] === "string"
    ) {
      try {
        const text =
          cleaned[field]

        const start =
          text.indexOf("{")

        const end =
          text.lastIndexOf("}")

        if (
          start !== -1 &&
          end !== -1
        ) {
          cleaned[field] =
            JSON.parse(
              text.slice(
                start,
                end + 1
              )
            )
        }
      } catch {}
    }
  }

  const host =
    cleaned.host ||
    cleaned.sshHost ||
    null

  const port =
    cleaned.port ||
    cleaned.sshPort ||
    null

  const username =
    cleaned.username ||
    cleaned.user ||
    cleaned.sshUsername ||
    null

  const password =
    cleaned.password ||
    cleaned.pass ||
    cleaned.sshPassword ||
    null

  const sni =
    cleaned.sniHostname ||
    cleaned.sni ||
    null

  const proxy =
    cleaned.remoteProxy ||
    cleaned.proxy ||
    null

  const payload =
    cleaned.payload ||
    cleaned.httpPayload ||
    null

  return {
    success: true,

    type:
      container.type,

    appVersion:
      container.version,

    mode:
      outer.mode,

    matchedIv:
      outer.matchedIv,

    host,
    port,
    username,
    password,
    sni,
    proxy,
    payload,

    config:
      cleaned
  }
}

// ============================================================
// HTTP BODY
// ============================================================

function getBody(req) {
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
// VERCEL
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

  if (req.method === "GET") {
    return res.status(200).json({
      success: true,
      api: "HTTP Injector EHI",
      status: "online"
    })
  }

  if (req.method !== "POST") {
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
        error: "File EHI tidak ditemukan"
      })
    }

    const result =
      await decryptEHI(body)

    return res
      .status(200)
      .json(result)

  } catch (err) {
    console.error(
      "[EHI ERROR]",
      err
    )

    return res.status(400).json({
      success: false,
      error:
        err?.message ||
        "Decrypt gagal"
    })
  }
}
