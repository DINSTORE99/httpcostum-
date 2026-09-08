const crypto = require("crypto")

function json(res, status, data) {
  res.status(status)
  res.setHeader("Content-Type", "application/json")
  res.setHeader("Access-Control-Allow-Origin", "*")
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,OPTIONS"
  )
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  )

  return res.end(JSON.stringify(data))
}

module.exports = async (req, res) => {
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
      return json(res, 200, {
        success: true,
        status: "online",
        name: "EHI Decrypt API",
        version: "1.0.0",
        endpoint: "/api/ehi",
        methods: [
          "GET",
          "POST"
        ]
      })
    }

    // =========================
    // POST
    // =========================
    if (req.method !== "POST") {
      return json(res, 405, {
        success: false,
        error: "Method Not Allowed"
      })
    }

    // =========================
    // BODY
    // =========================
    let body = req.body

    if (!body) {
      return json(res, 400, {
        success: false,
        error: "Request body kosong"
      })
    }

    if (Buffer.isBuffer(body)) {
      // OK
    } else if (body instanceof Uint8Array) {
      body = Buffer.from(body)
    } else {
      return json(res, 400, {
        success: false,
        error: "Kirim file EHI sebagai application/octet-stream"
      })
    }

    // =========================
    // FILE SIZE
    // =========================
    if (body.length === 0) {
      return json(res, 400, {
        success: false,
        error: "File kosong"
      })
    }

    if (body.length > 4 * 1024 * 1024) {
      return json(res, 413, {
        success: false,
        error: "File terlalu besar"
      })
    }

    // =========================
    // HASH
    // =========================
    const sha256 = crypto
      .createHash("sha256")
      .update(body)
      .digest("hex")

    // =========================
    // RESPONSE
    // =========================
    return json(res, 200, {
      success: true,

      status: "received",

      file: {
        size: body.length,
        sha256
      },

      message:
        "File EHI berhasil diterima oleh API."
    })

  } catch (error) {

    console.error(
      "EHI API ERROR:",
      error
    )

    return json(res, 500, {
      success: false,
      error:
        error?.message ||
        "Internal Server Error"
    })
  }
}
