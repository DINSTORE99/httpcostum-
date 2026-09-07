//// ========================================================
//// IMPORT
//// ========================================================

const express = require("express");
const multer = require("multer");
const path = require("path");

//// ========================================================
//// APP
//// ========================================================

const app = express();

const PORT =
  process.env.PORT || 3000;

//// ========================================================
//// UPLOAD
//// ========================================================

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 20 * 1024 * 1024
  }
});

//// ========================================================
//// MIDDLEWARE
//// ========================================================

app.use(express.json());

app.use(
  express.urlencoded({
    extended: true
  })
);

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

//// ========================================================
//// HOME
//// ========================================================

app.get("/", (req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );

});

//// ========================================================
//// HEALTH
//// ========================================================

app.get(
  "/api/health",
  (req, res) => {

    res.json({
      success: true,
      status: "online",
      service: "DINSTORE Decryptor"
    });

  }
);

//// ========================================================
//// UPLOAD TEST
//// ========================================================

app.post(
  "/api/upload",
  upload.single("file"),
  (req, res) => {

    if (!req.file) {

      return res.status(400).json({
        success: false,
        error: "File tidak ditemukan"
      });

    }

    res.json({

      success: true,

      file: {
        name: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
      }

    });

  }
);

//// ========================================================
//// ERROR
//// ========================================================

app.use(
  (err, req, res, next) => {

    console.error(err);

    res.status(500).json({
      success: false,
      error:
        err.message ||
        "Internal Server Error"
    });

  }
);

//// ========================================================
//// START
//// ========================================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `DINSTORE Decryptor running on port ${PORT}`
    );

  }
);
