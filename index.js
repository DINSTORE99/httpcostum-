//// =========================
//// IMPORT
//// =========================

const express = require("express");
const multer = require("multer");
const path = require("path");

//// =========================
//// CONFIG
//// =========================

const app = express();
const PORT = process.env.PORT || 3000;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 20 * 1024 * 1024
  }
});

//// =========================
//// MIDDLEWARE
//// =========================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

//// =========================
//// HOME
//// =========================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

//// =========================
//// HEALTH
//// =========================

app.get("/api/health", (req, res) => {
  res.json({
    status: true,
    message: "DINSTORE Decryptor API aktif"
  });
});

//// =========================
//// SUPPORTED FORMAT
//// =========================

app.get("/api/supported", (req, res) => {
  res.json({
    status: true,
    formats: [
      ".hc",
      ".dark",
      ".ehi",
      ".npv",
      ".scc"
    ]
  });
});

//// =========================
//// BUKA FILE
//// =========================

app.post(
  "/api/open",
  upload.single("file"),
  async (req, res) => {

    try {

      if (!req.file) {
        return res.status(400).json({
          status: false,
          message: "File belum dipilih"
        });
      }

      const fileName = req.file.originalname;
      const buffer = req.file.buffer;

      const ext = path
        .extname(fileName)
        .toLowerCase();

      //// =========================
      //// CEK FORMAT
      //// =========================

      const supported = [
        ".hc",
        ".dark",
        ".ehi",
        ".npv",
        ".scc"
      ];

      if (!supported.includes(ext)) {
        return res.status(400).json({
          status: false,
          message: "Format file tidak didukung"
        });
      }

      //// =========================
      //// BACA FILE
      //// =========================

      let content;

      try {

        content = buffer.toString("utf8");

      } catch (err) {

        content = "";

      }

      //// =========================
      //// HASIL
      //// =========================

      return res.json({
        status: true,
        filename: fileName,
        extension: ext,
        size: buffer.length,
        result: content,
        message: "File berhasil dibuka"
      });

    } catch (error) {

      console.error(error);

      return res.status(500).json({
        status: false,
        message: "Gagal membuka file"
      });

    }

  }
);

//// =========================
//// ERROR UPLOAD
//// =========================

app.use((err, req, res, next) => {

  if (err instanceof multer.MulterError) {

    if (err.code === "LIMIT_FILE_SIZE") {

      return res.status(400).json({
        status: false,
        message: "Ukuran file maksimal 20MB"
      });

    }

  }

  console.error(err);

  res.status(500).json({
    status: false,
    message: "Terjadi kesalahan server"
  });

});

//// =========================
//// START SERVER
//// =========================

app.listen(PORT, "0.0.0.0", () => {

  console.log("");
  console.log("================================");
  console.log(" DINSTORE DECRYPTOR");
  console.log("================================");
  console.log(`PORT : ${PORT}`);
  console.log(`URL  : http://localhost:${PORT}`);
  console.log("================================");
  console.log("");

});
