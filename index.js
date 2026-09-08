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

/* ========================================
DECRYPT
======================================== */

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
    req.file.originalname
      .toLowerCase();


  let result;


  /* ==============================
     HC
  ============================== */

  if (
    filename.endsWith(".hc")
  ) {

    result =
      hcDecrypt(
        req.file.buffer
      );

  }


  /* ==============================
     EHI
  ============================== */

  else if (
    filename.endsWith(".ehi")
  ) {

    result =
      await ehiDecrypt.execute(
        req.file.buffer
      );

  }


  /* ==============================
     UNSUPPORTED
  ============================== */

  else {

    return res.status(400).json({
      success: false,

      error:
        "Format tidak didukung. Gunakan file .HC atau .EHI"
    });
  }


  if (
    !result ||
    result.success === false
  ) {

    return res.status(400).json({
      success: false,

      error:
        result?.error ||
        "Gagal membongkar config"
    });
  }


  return res.json(
    result
  );


} catch (error) {

  console.error(
    "DECRYPT ERROR:",
    error
  );

  return res.status(500).json({

    success: false,

    error:
      error.message ||
      "Gagal membongkar config"
  });
}

}
);

/* ========================================
API INFO
======================================== */

app.get(
"/api",
(req, res) => {

res.json({

  success: true,

  name:
    "BONGKAR CONFIG",

  formats: [
    ".hc",
    ".ehi"
  ]
});

}
);

module.exports = app;

if (
require.main === module
) {

const PORT =
process.env.PORT || 3000;

app.listen(
PORT,
() => {

  console.log(
    `BONGKAR CONFIG running on port ${PORT}`
  );

}

);
}
