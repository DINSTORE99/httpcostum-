async function decryptFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch("/api/decrypt", {
      method: "POST",
      body: formData
    });

    // Jangan langsung response.json()
    const text = await response.text();

    let data;

    try {
      data = text ? JSON.parse(text) : null;
    } catch (e) {
      throw new Error(
        `Server mengembalikan response bukan JSON.\n` +
        `HTTP ${response.status}\n` +
        `Response: ${text.slice(0, 500)}`
      );
    }

    if (!response.ok) {
      throw new Error(
        data?.error ||
        data?.message ||
        `HTTP ${response.status}`
      );
    }

    if (!data) {
      throw new Error("Server mengembalikan response kosong.");
    }

    return data;

  } catch (error) {
    console.error("Decrypt error:", error);
    throw error;
  }
}
