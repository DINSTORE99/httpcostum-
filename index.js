const express = require("express");
const multer = require("multer");
const path = require("path");

const hcDecrypt = require("./decryptors/hc");
const ehiDecrypt = require("./decryptors/ehi");

const upload = multer({
  storage: multer.memoryStorage()
});

const app = express();

app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

// ==========================================
// API DECRYPT HC / EHI
// ==========================================

app.post(
  "/api/decrypt",
  upload.single("file"),
  async (req, res) => {
    try {

      // --------------------------------------
      // CEK FILE
      // --------------------------------------

      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: "File tidak ditemukan"
        });
      }

      const filename =
        req.file.originalname.toLowerCase();

      let result;

      // --------------------------------------
      // HC
      // --------------------------------------

      if (filename.endsWith(".hc")) {

        result =
          await hcDecrypt(req.file.buffer);

      }

      // --------------------------------------
      // EHI
      // --------------------------------------

      else if (filename.endsWith(".ehi")) {

        result =
          await ehiDecrypt(req.file.buffer);

      }

      // --------------------------------------
      // FORMAT TIDAK DIDUKUNG
      // --------------------------------------

      else {

        return res.status(400).json({
          success: false,
          error:
            "Format tidak didukung. Upload file .hc atau .ehi"
        });

      }

      // --------------------------------------
      // HASIL DECRYPT
      // --------------------------------------

      if (!result || !result.success) {

        return res.status(400).json(
          result || {
            success: false,
            error: "Gagal decrypt file"
          }
        );

      }

      return res.json(result);

    } catch (e) {

      console.error(
        "DECRYPT ERROR:",
        e
      );

      return res.status(500).json({
        success: false,
        error:
          e.message ||
          "Internal server error"
      });

    }
  }
);

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/api", (req, res) => {

  res.json({
    success: true,
    name: "DINSTORE HC / EHI Decryptor",
    formats: [
      ".hc",
      ".ehi"
    ]
  });

});

// ==========================================
// EXPORT
// ==========================================

module.exports = app;

// ==========================================
// RUN LANGSUNG
// ==========================================

if (require.main === module) {

  const PORT =
    process.env.PORT || 3000;

  app.listen(PORT, () => {

    console.log(
      `DINSTORE HC / EHI Decryptor running on port ${PORT}`
    );

  });

}
