const express = require("express");
const multer = require("multer");
const path = require("path");

const {
  hcParseModern
} = require("./decryptors/hc");

const {
  ehiDecrypt
} = require("./decryptors/ehi");

const app = express();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 20 * 1024 * 1024
  }
});

app.use(express.json());
app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

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

      const name =
        req.file.originalname
          .toLowerCase();

      if (name.endsWith(".hc")) {

        return res.json(
          hcParseModern(
            req.file.buffer
          )
        );

      }

      if (name.endsWith(".ehi")) {

        return res.json(
          await ehiDecrypt(
            req.file.buffer
          )
        );

      }

      return res.status(400).json({
        success: false,
        error:
          "Hanya mendukung .hc dan .ehi"
      });

    } catch (e) {

      console.error(e);

      res.status(500).json({
        success: false,
        error: e.message
      });

    }
  }
);

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      success: true,
      status: "online",
      supported: [
        ".hc",
        ".ehi"
      ]
    });
  }
);

const PORT =
  process.env.PORT || 3000;

app.listen(
  PORT,
  () => {
    console.log(
      `DINSTORE Decryptor running on ${PORT}`
    );
  }
);
