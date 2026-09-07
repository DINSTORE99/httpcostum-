const express = require("express");
const multer = require("multer");
const path = require("path");

const hcDecrypt = require("./decryptors/hc");
const ehiDecrypt = require("./decryptors/ehi");

const app = express();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 20 * 1024 * 1024
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));


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
        req.file.originalname.toLowerCase();

      let result;

      if (filename.endsWith(".hc")) {

        result =
          await hcDecrypt(
            req.file.buffer
          );

      } else if (
        filename.endsWith(".ehi")
      ) {

        result =
          await ehiDecrypt(
            req.file.buffer
          );

      } else {

        return res.status(400).json({
          success: false,
          error: "Format harus .hc atau .ehi"
        });

      }

      return res.json(result);

    } catch (error) {

      console.error(
        "DECRYPT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Decrypt gagal"
      });

    }
  }
);


app.get("/api/status", (req, res) => {

  res.json({
    success: true,
    service: "DINSTORE Decryptor",
    formats: [
      ".hc",
      ".ehi"
    ]
  });

});


const PORT =
  process.env.PORT || 3000;

app.listen(
  PORT,
  () => {
    console.log(
      `DINSTORE Decryptor running on port ${PORT}`
    );
  }
);
