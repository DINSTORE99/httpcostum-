const fileInput = document.getElementById("fileInput");
const selectBtn = document.getElementById("selectBtn");
const decryptBtn = document.getElementById("decryptBtn");

const fileText = document.getElementById("fileText");
const statusBox = document.getElementById("status");

const resultBox = document.getElementById("resultBox");
const result = document.getElementById("result");
const copyBtn = document.getElementById("copyBtn");

const dropZone = document.getElementById("dropZone");

let selectedFile = null;


// ==============================
// PILIH FILE
// ==============================

selectBtn.addEventListener("click", function (e) {
  e.preventDefault();
  e.stopPropagation();

  fileInput.click();
});


// Klik area upload
dropZone.addEventListener("click", function (e) {

  if (e.target === selectBtn) return;

  fileInput.click();

});


// ==============================
// FILE DIPILIH
// ==============================

fileInput.addEventListener("change", function () {

  if (!fileInput.files || fileInput.files.length === 0) {
    return;
  }

  const file = fileInput.files[0];

  const name = file.name.toLowerCase();

  if (!name.endsWith(".hc") && !name.endsWith(".ehi")) {

    showStatus(
      "❌ File harus berformat .hc atau .ehi",
      "error"
    );

    fileInput.value = "";
    selectedFile = null;
    decryptBtn.disabled = true;

    return;
  }

  selectedFile = file;

  fileText.textContent =
    `${file.name} (${formatBytes(file.size)})`;

  decryptBtn.disabled = false;

  showStatus(
    "✅ File siap di-decrypt",
    "success"
  );

});


// ==============================
// DRAG & DROP
// ==============================

dropZone.addEventListener("dragover", function (e) {

  e.preventDefault();

  dropZone.classList.add("drag");

});


dropZone.addEventListener("dragleave", function () {

  dropZone.classList.remove("drag");

});


dropZone.addEventListener("drop", function (e) {

  e.preventDefault();

  dropZone.classList.remove("drag");

  const files = e.dataTransfer.files;

  if (!files || files.length === 0) {
    return;
  }

  const file = files[0];

  const name = file.name.toLowerCase();

  if (!name.endsWith(".hc") && !name.endsWith(".ehi")) {

    showStatus(
      "❌ File harus .hc atau .ehi",
      "error"
    );

    return;
  }

  selectedFile = file;

  fileText.textContent =
    `${file.name} (${formatBytes(file.size)})`;

  decryptBtn.disabled = false;

  showStatus(
    "✅ File siap di-decrypt",
    "success"
  );

});


// ==============================
// DECRYPT
// ==============================

decryptBtn.addEventListener("click", async function () {

  if (!selectedFile) {

    showStatus(
      "❌ Pilih file terlebih dahulu",
      "error"
    );

    return;
  }

  decryptBtn.disabled = true;

  decryptBtn.textContent = "⏳ Processing...";

  resultBox.hidden = true;

  showStatus(
    "🔐 Sedang melakukan decrypt...",
    "loading"
  );

  try {

    const formData = new FormData();

    formData.append(
      "file",
      selectedFile,
      selectedFile.name
    );


    const response = await fetch(
      "/api/decrypt",
      {
        method: "POST",
        body: formData
      }
    );


    const text = await response.text();

    let data = null;

    try {

      data = text
        ? JSON.parse(text)
        : null;

    } catch (err) {

      console.error(
        "Response bukan JSON:",
        text
      );

      throw new Error(
        `Server mengembalikan response tidak valid (HTTP ${response.status})`
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

      throw new Error(
        "Server mengembalikan response kosong"
      );

    }


    if (data.success === false) {

      throw new Error(
        data.error ||
        "Decrypt gagal"
      );

    }


    // ==========================
    // TAMPILKAN HASIL
    // ==========================

    let output;

    if (typeof data.result === "string") {

      output = data.result;

    } else if (typeof data.output === "string") {

      output = data.output;

    } else if (data.data) {

      output = JSON.stringify(
        data.data,
        null,
        2
      );

    } else {

      output = JSON.stringify(
        data,
        null,
        2
      );

    }


    result.textContent = output;

    resultBox.hidden = false;

    showStatus(
      "✅ Decrypt berhasil",
      "success"
    );


  } catch (error) {

    console.error(error);

    showStatus(
      "❌ " + error.message,
      "error"
    );

  } finally {

    decryptBtn.disabled = !selectedFile;

    decryptBtn.textContent = "🔓 Decrypt";

  }

});


// ==============================
// COPY
// ==============================

copyBtn.addEventListener("click", async function () {

  try {

    await navigator.clipboard.writeText(
      result.textContent
    );

    copyBtn.textContent = "Copied!";

    setTimeout(() => {

      copyBtn.textContent = "Copy";

    }, 1500);

  } catch (error) {

    showStatus(
      "❌ Gagal menyalin hasil",
      "error"
    );

  }

});


// ==============================
// STATUS
// ==============================

function showStatus(message, type) {

  statusBox.textContent = message;

  statusBox.className =
    "status " + type;

}


// ==============================
// FORMAT SIZE
// ==============================

function formatBytes(bytes) {

  if (bytes === 0) {
    return "0 Bytes";
  }

  const units = [
    "Bytes",
    "KB",
    "MB",
    "GB"
  ];

  const i = Math.floor(
    Math.log(bytes) / Math.log(1024)
  );

  return (
    parseFloat(
      (bytes / Math.pow(1024, i)).toFixed(2)
    ) +
    " " +
    units[i]
  );

}
