const express = require("express");
const multer = require("multer");
const path = require("path");

const hcDecrypt = require("./decryptors/hc");
const ehiDecrypt = require("./decryptors/ehi");

const upload = multer({ storage: multer.memoryStorage() });
const app = express();

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

    if (!filename.endsWith(".hc") && !filename.endsWith(".ehi")) {
      return res.status(400).json({
        success: false,
        error: "Format tidak didukung. Upload file .HC atau .EHI"
      });
    }

    const result = filename.endsWith(".ehi")
      ? await ehiDecrypt(req.file.buffer)
      : hcDecrypt(req.file.buffer);

    if (!result.success) {
      return res.status(400).json(result);
    }

    return res.json(result);
  } catch (e) {
    console.error(e);
    return res.status(500).json({
      success: false,
      error: e.message || "Internal server error"
    });
  }
});

app.get("/api", (req, res) => {
  res.json({
    success: true,
    name: "DINSTORE Config Decryptor",
    formats: [".hc", ".ehi"]
  });
});

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`DINSTORE Config Decryptor running on port ${PORT}`);
  });
}
