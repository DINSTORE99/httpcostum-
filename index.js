const express = require("express");
const multer = require("multer");
const path = require("path");

const hcDecrypt = require("./decryptors/hc");
const ehiDecrypt = require("./decryptors/ehi");

const app = express();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/decrypt", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "File tidak ditemukan"
      });
    }

    const filename = req.file.originalname.toLowerCase();

    let result;

    if (filename.endsWith(".hc")) {
      result = await hcDecrypt(req.file.buffer);
    } else if (filename.endsWith(".ehi")) {
      result = await ehiDecrypt(req.file.buffer);
    } else {
      return res.status(400).json({
        success: false,
        error: "Format file harus .hc atau .ehi"
      });
    }

    if (!result) {
      return res.status(500).json({
        success: false,
        error: "Decryptor tidak mengembalikan hasil"
      });
    }

    return res.json(result);

  } catch (error) {
    console.error("API DECRYPT ERROR:");
    console.error(error);

    return res.status(500).json({
      success: false,
      error: error.message || "Terjadi kesalahan saat decrypt",
      stack: process.env.NODE_ENV === "development"
        ? error.stack
        : undefined
    });
  }
});

// Error handler multer
app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err);

  if (res.headersSent) {
    return next(err);
  }

  return res.status(500).json({
    success: false,
    error: err.message || "Internal server error"
  });
});

module.exports = app;
