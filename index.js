const express = require("express");
const multer = require("multer");
const path = require("path");

const hcDecrypt = require("./decryptors/hc");

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

      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: "File tidak ditemukan"
        });
      }

      const filename =
        String(req.file.originalname || "")
          .toLowerCase();

      // ====================================
      // HC
      // ====================================

      if (filename.endsWith(".hc")) {

        const result =
          await hcDecrypt(req.file.buffer);

        if (!result || !result.success) {
          return res.status(400).json(
            result || {
              success: false,
              error: "Gagal decrypt file HC"
            }
          );
        }

        return res.json(result);
      }

      // ====================================
      // EHI
      // ====================================

      if (filename.endsWith(".ehi")) {

        let ehiDecrypt;

        try {

          ehiDecrypt =
            require("./decryptors/ehi");

        } catch (err) {

          console.error(
            "EHI MODULE ERROR:",
            err
          );

          return res.status(500).json({
            success: false,
            error:
              "Decryptor EHI gagal dimuat: " +
              err.message
          });
        }

        try {

          const result =
            await ehiDecrypt(req.file.buffer);

          if (!result || !result.success) {
            return res.status(400).json(
              result || {
                success: false,
                error: "Gagal decrypt file EHI"
              }
            );
          }

          return res.json(result);

        } catch (err) {

          console.error(
            "EHI DECRYPT ERROR:",
            err
          );

          return res.status(400).json({
            success: false,
            error:
              err.message ||
              "Gagal decrypt file EHI"
          });
        }
      }

      // ====================================
      // FORMAT LAIN
      // ====================================

      return res.status(400).json({
        success: false,
        error:
          "Format tidak didukung. Upload file .hc atau .ehi"
      });

    } catch (err) {

      console.error(
        "API ERROR:",
        err
      );

      return res.status(500).json({
        success: false,
        error:
          err.message ||
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
// EXPORT VERCEL
// ==========================================

module.exports = app;

// ==========================================
// LOCAL
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
