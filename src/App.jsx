async function decrypt() {

  if (!file) {
    setError("Pilih file terlebih dahulu.");
    return;
  }

  setLoading(true);
  setError("");
  setResult(null);

  try {

    const name =
      file.name.toLowerCase();

    const endpoint =
      name.endsWith(".hc")
        ? "/api/hc"
        : "/api/ehi";

    const response =
      await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type":
            "application/octet-stream"
        },
        body: file
      });

    const text =
      await response.text();

    let data;

    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(
        text ||
        `Server error ${response.status}`
      );
    }

    if (!response.ok) {
      throw new Error(
        data.error ||
        "Gagal membongkar config."
      );
    }

    if (data.success === false) {
      throw new Error(
        data.error ||
        "Gagal membongkar config."
      );
    }

    setResult(data);

  } catch (err) {

    setError(
      err.message ||
      "Terjadi kesalahan."
    );

  } finally {

    setLoading(false);

  }
}
