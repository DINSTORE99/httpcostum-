const uploadBox = document.getElementById("uploadBox");
const fileInput = document.getElementById("fileInput");
const fileName = document.getElementById("fileName");
const decryptBtn = document.getElementById("decryptBtn");
const statusBox = document.getElementById("status");
const resultBox = document.getElementById("result");

let selectedFile = null;


// =========================
// FILE SELECT
// =========================

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];

  if (!file) return;

  setFile(file);
});


// =========================
// DRAG & DROP
// =========================

uploadBox.addEventListener("dragover", (e) => {
  e.preventDefault();
  uploadBox.classList.add("dragover");
});

uploadBox.addEventListener("dragleave", () => {
  uploadBox.classList.remove("dragover");
});

uploadBox.addEventListener("drop", (e) => {
  e.preventDefault();

  uploadBox.classList.remove("dragover");

  const file = e.dataTransfer.files[0];

  if (file) {
    setFile(file);
  }
});


// =========================
// SET FILE
// =========================

function setFile(file) {

  if (!file.name.toLowerCase().endsWith(".hc")) {

    showStatus(
      "❌ Hanya file .HC yang diperbolehkan",
      "error"
    );

    selectedFile = null;
    decryptBtn.disabled = true;

    return;
  }

  selectedFile = file;

  fileName.textContent =
    "📄 " + file.name;

  fileName.style.display = "block";

  decryptBtn.disabled = false;

  showStatus(
    "✅ File siap dibongkar",
    "success"
  );
}


// =========================
// DECRYPT
// =========================

decryptBtn.addEventListener("click", async () => {

  if (!selectedFile) return;

  decryptBtn.disabled = true;

  decryptBtn.innerHTML =
    "⏳ MEMPROSES...";

  resultBox.innerHTML = "";

  showStatus(
    "🔄 Sedang membongkar config...",
    "loading"
  );

  try {

    const formData = new FormData();

    formData.append(
      "file",
      selectedFile
    );

    const response = await fetch(
      "/api/decrypt",
      {
        method: "POST",
        body: formData
      }
    );

    const text = await response.text();

    let data;

    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(
        text || "Server tidak mengembalikan JSON"
      );
    }

    if (!response.ok || !data.success) {
      throw new Error(
        data.error || "Gagal membongkar config"
      );
    }

    renderResult(data);

    showStatus(
      "✅ Config berhasil dibongkar",
      "success"
    );

  } catch (error) {

    console.error(error);

    showStatus(
      "❌ " + error.message,
      "error"
    );

  } finally {

    decryptBtn.disabled = false;

    decryptBtn.innerHTML =
      "🔓 BONGKAR CONFIG";
  }
});


// =========================
// STATUS
// =========================

function showStatus(message, type = "") {

  statusBox.textContent = message;

  statusBox.className =
    "status " + type;

  statusBox.style.display = "block";
}
