const express = require("express");
const multer = require("multer");

const hcDecrypt = require("../decryptors/hc");
const ehiDecrypt = require("../decryptors/ehi");

const app = express();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 20 * 1024 * 1024
  }
});

app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));

// ========================================
// HOME
// ========================================

app.get("/", (req, res) => {
  res.redirect("/index.html");
});

// ========================================
// API INFO
// ========================================

app.get("/api", (req, res) => {
  res.json({
    success: true,
    name: "BONGKAR CONFIG",
    formats: [".hc", ".ehi"]
  });
});

// ========================================
// DECRYPT
// ========================================

app.post(
  "/api/decrypt",
  upload.single("file"),
  async (req, res) => {

    try {

      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: "File tidak ditemukan"
        });
      }

      const filename = String(
        req.file.originalname || ""
      ).toLowerCase();

      let result;

      // HC
      if (filename.endsWith(".hc")) {

        result = hcDecrypt(
          req.file.buffer
        );

      }

      // EHI
      else if (filename.endsWith(".ehi")) {

        result = await ehiDecrypt.execute(
          req.file.buffer
        );

      }

      // FORMAT LAIN
      else {

        return res.status(400).json({
          success: false,
          error:
            "Format tidak didukung. Gunakan file .HC atau .EHI"
        });

      }

      if (!result) {

        return res.status(400).json({
          success: false,
          error: "Gagal membongkar config"
        });

      }

      if (result.success === false) {

        return res.status(400).json({
          success: false,
          error:
            result.error ||
            "Gagal membongkar config"
        });

      }

      return res.status(200).json(result);

    } catch (error) {

      console.error(
        "DECRYPT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Internal Server Error"
      });
    }
  }
);

module.exports = app;
