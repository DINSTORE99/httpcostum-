const crypto = require("crypto")

function response(res, status, data) {
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

module.exports = async function handler(req, res) {

  try {

    // =========================
    // CORS
    // =========================

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

    // =========================
    // OPTIONS
    // =========================

    if (req.method === "OPTIONS") {
      return res.status(200).end()
    }

    // =========================
    // GET
    // =========================

    if (req.method === "GET") {

      return response(res, 200, {
        success: true,
        status: "online",
        api: "HTTP Custom HC API",
        version: "1.0.0",
        endpoint: "/api/hc",
        methods: [
          "GET",
          "POST"
        ]
      })
    }

    // =========================
    // POST ONLY
    // =========================

    if (req.method !== "POST") {

      return response(res, 405, {
        success: false,
        error: "Method Not Allowed"
      })
    }

    // =========================
    // BODY
    // =========================

    let buffer = req.body

    if (!buffer) {

      return response(res, 400, {
        success: false,
        error: "Request body kosong"
      })
    }

    if (Buffer.isBuffer(buffer)) {

      // OK

    } else if (
      buffer instanceof Uint8Array
    ) {

      buffer = Buffer.from(buffer)

    } else if (
      typeof buffer === "string"
    ) {

      buffer = Buffer.from(
        buffer,
        "base64"
      )

    } else {

      return response(res, 400, {
        success: false,
        error:
          "Kirim file HC sebagai application/octet-stream"
      })
    }

    // =========================
    // SIZE
    // =========================

    if (buffer.length === 0) {

      return response(res, 400, {
        success: false,
        error: "File HC kosong"
      })
    }

    if (
      buffer.length >
      4 * 1024 * 1024
    ) {

      return response(res, 413, {
        success: false,
        error: "File HC terlalu besar"
      })
    }

    // =========================
    // HASH
    // =========================

    const sha256 =
      crypto
        .createHash("sha256")
        .update(buffer)
        .digest("hex")

    // =========================
    // HEADER INFO
    // =========================

    const header =
      buffer
        .subarray(
          0,
          Math.min(
            buffer.length,
            32
          )
        )
        .toString("hex")

    // =========================
    // RESPONSE
    // =========================

    return response(res, 200, {

      success: true,

      status: "received",

      api: "HTTP Custom HC API",

      file: {
        size: buffer.length,
        sha256,
        header
      },

      message:
        "File .hc berhasil diterima oleh API."

    })

  } catch (error) {

    console.error(
      "HC API ERROR:",
      error
    )

    return response(res, 500, {

      success: false,

      error:
        error?.message ||
        "Internal Server Error"

    })
  }
}
