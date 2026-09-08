const express = require("express");
const multer = require("multer");
const path = require("path");

const hcDecrypt =
  require("./decryptors/hc");

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
// API DECRYPT HC
// ==========================================

app.post(
  "/api/decrypt",
  upload.single("file"),
  (req, res) => {
    try {

      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: "File tidak ditemukan"
        });
      }

      const filename =
        req.file.originalname.toLowerCase();

      // Hanya HC
      if (!filename.endsWith(".hc")) {
        return res.status(400).json({
          success: false,
          error:
            "Format tidak didukung. Upload file .hc"
        });
      }

      const result =
        hcDecrypt(req.file.buffer);

      if (!result.success) {
        return res.status(400).json(result);
      }

      return res.json(result);

    } catch (e) {

      console.error(e);

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
    name: "DINSTORE HC Decryptor",
    format: ".hc"
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
      `DINSTORE HC Decryptor running on port ${PORT}`
    );
  });
}
