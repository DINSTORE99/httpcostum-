module.exports = async function handler(req, res) {

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Gunakan method POST"
    });
  }

  try {

    const chunks = [];

    for await (const chunk of req) {
      chunks.push(chunk);
    }

    const body =
      Buffer.concat(chunks);

    if (!body.length) {
      return res.status(400).json({
        success: false,
        error: "File EHI tidak ditemukan"
      });
    }

    /*
     * EHI hanya diload ketika endpoint
     * /api/ehi benar-benar dipanggil.
     *
     * Ini mencegah dependency EHI
     * membuat endpoint HC ikut crash.
     */
    const ehiDecrypt =
      require("../decryptors/ehi");

    if (
      !ehiDecrypt ||
      typeof ehiDecrypt.execute !== "function"
    ) {
      throw new Error(
        "decryptors/ehi.js tidak memiliki fungsi execute()"
      );
    }

    const result =
      await ehiDecrypt.execute(body);

    if (!result) {
      return res.status(400).json({
        success: false,
        error: "Gagal membongkar file EHI"
      });
    }

    return res.status(200).json(result);

  } catch (error) {

    console.error(
      "EHI API ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        error.message ||
        "EHI decrypt error"
    });
  }
};
