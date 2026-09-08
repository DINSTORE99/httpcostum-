const hcDecrypt = require("../decryptors/hc");

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

    const body = Buffer.concat(chunks);

    if (!body.length) {
      return res.status(400).json({
        success: false,
        error: "File HC tidak ditemukan"
      });
    }

    const result = hcDecrypt(body);

    if (!result) {
      return res.status(400).json({
        success: false,
        error: "Gagal membongkar file HC"
      });
    }

    return res.status(200).json(result);

  } catch (error) {
    console.error("HC API ERROR:", error);

    return res.status(500).json({
      success: false,
      error: error.message || "HC decrypt error"
    });
  }
};
