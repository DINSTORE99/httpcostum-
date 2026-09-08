const crypto = require("crypto")

module.exports = async (req, res) => {
  // =========================
  // CORS
  // =========================
  res.setHeader("Access-Control-Allow-Origin", "*")
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS"
  )
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  )

  // =========================
  // OPTIONS
  // =========================
  if (req.method === "OPTIONS") {
    return res.status(200).end()
  }

  // =========================
  // GET = TEST API
  // =========================
  if (req.method === "GET") {
    return res.status(200).json({
      success: true,
      api: "EHI Decrypt API",
      status: "online",
      endpoint: "/api/ehi",
      method: "POST",
      version: "1.0.0"
    })
  }

  // =========================
  // ONLY POST
  // =========================
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method Not Allowed"
    })
  }

  try {

    // =========================
    // AMBIL BODY
    // =========================
    let buffer

    if (Buffer.isBuffer(req.body)) {
      buffer = req.body
    }

    else if (req.body instanceof Uint8Array) {
      buffer = Buffer.from(req.body)
    }

    else if (typeof req.body === "string") {
      buffer = Buffer.from(req.body, "base64")
    }

    else {
      return res.status(400).json({
        success: false,
        error: "Body harus berupa file EHI"
      })
    }

    // =========================
    // CEK FILE
    // =========================
    if (!buffer.length) {
      return res.status(400).json({
        success: false,
        error: "File EHI kosong"
      })
    }

    // =========================
    // BATAS FILE
    // =========================
    if (buffer.length > 4 * 1024 * 1024) {
      return res.status(413).json({
        success: false,
        error: "File terlalu besar"
      })
    }

    // =========================
    // INFO FILE
    // =========================
    const sha256 = crypto
      .createHash("sha256")
      .update(buffer)
      .digest("hex")

    // =========================
    // BACA HEADER EHI
    // =========================
    let offset = 0

    if (buffer.length < 2) {
      throw new Error("File EHI tidak valid")
    }

    const firstLength =
      buffer.readUInt16BE(offset)

    offset += 2

    if (
      firstLength < 0 ||
      offset + firstLength * 2 > buffer.length
    ) {
      throw new Error("Header EHI rusak")
    }

    const type =
      buffer
        .subarray(
          offset,
          offset + firstLength * 2
        )
        .toString("utf16be")

    offset += firstLength * 2

    // skip 8 byte
    offset += 8

    if (offset + 2 > buffer.length) {
      throw new Error("Header versi tidak ditemukan")
    }

    const secondLength =
      buffer.readUInt16BE(offset)

    offset += 2

    if (
      offset + secondLength * 2 > buffer.length
    ) {
      throw new Error("Versi EHI rusak")
    }

    const appVersion =
      buffer
        .subarray(
          offset,
          offset + secondLength * 2
        )
        .toString("utf16be")

    return res.status(200).json({
      success: true,

      api: "EHI Decrypt API",

      file: {
        size: buffer.length,
        sha256
      },

      ehi: {
        type,
        appVersion
      },

      message:
        "File EHI berhasil diterima. Decryptor belum dijalankan."
    })

  } catch (error) {

    console.error(
      "EHI API ERROR:",
      error
    )

    return res.status(500).json({
      success: false,
      error: error.message || "Internal Server Error"
    })
  }
}
