const express = require("express");
const multer = require("multer");
const path = require("path");

const ehiDecrypt =
  require("./decryptors/ehi");

const app = express();

const upload =
  multer({
    storage: multer.memoryStorage()
  });


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
          error: "File EHI tidak ditemukan"
        });

      }


      const filename =
        req.file.originalname.toLowerCase();


      if (!filename.endsWith(".ehi")) {

        return res.status(400).json({
          success: false,
          error: "Hanya file .EHI yang diperbolehkan"
        });

      }


      const result =
        await ehiDecrypt(
          req.file.buffer
        );


      return res.json(result);


    } catch (error) {

      console.error(
        "EHI ERROR:",
        error
      );


      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Gagal membongkar EHI"
      });

    }

  }
);


app.get("/api", (req, res) => {

  res.json({
    success: true,
    name: "BONGKAR CONFIG EHI",
    format: ".ehi"
  });

});


module.exports = app;


if (require.main === module) {

  const PORT =
    process.env.PORT || 3000;

  app.listen(
    PORT,
    () => {
      console.log(
        `BONGKAR CONFIG EHI running on ${PORT}`
      );
    }
  );

}
