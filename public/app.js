//// =========================
//// ELEMENT
//// =========================

const fileInput = document.getElementById("fileInput");
const chooseBtn = document.getElementById("chooseBtn");
const dropArea = document.getElementById("dropArea");

const filePreview = document.getElementById("filePreview");
const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");

const removeBtn = document.getElementById("removeBtn");
const openBtn = document.getElementById("openBtn");

const message = document.getElementById("message");

const resultCard = document.getElementById("resultCard");
const result = document.getElementById("result");
const resultName = document.getElementById("resultName");

const copyBtn = document.getElementById("copyBtn");
const downloadBtn = document.getElementById("downloadBtn");

//// =========================
//// STATE
//// =========================

let selectedFile = null;

//// =========================
//// FORMAT SIZE
//// =========================

function formatSize(bytes) {

  if (bytes < 1024) {
    return bytes + " B";
  }

  if (bytes < 1024 * 1024) {
    return (bytes / 1024).toFixed(2) + " KB";
  }

  return (bytes / 1024 / 1024).toFixed(2) + " MB";
}

//// =========================
//// PILIH FILE
//// =========================

chooseBtn.addEventListener("click", () => {
  fileInput.click();
});

dropArea.addEventListener("click", (e) => {

  if (
    e.target !== chooseBtn
  ) {
    fileInput.click();
  }

});

fileInput.addEventListener("change", () => {

  if (fileInput.files.length) {
    setFile(fileInput.files[0]);
  }

});

//// =========================
//// DRAG DROP
//// =========================

dropArea.addEventListener("dragover", (e) => {

  e.preventDefault();

  dropArea.classList.add("dragging");

});

dropArea.addEventListener("dragleave", () => {

  dropArea.classList.remove("dragging");

});

dropArea.addEventListener("drop", (e) => {

  e.preventDefault();

  dropArea.classList.remove("dragging");

  const file = e.dataTransfer.files[0];

  if (file) {
    setFile(file);
  }

});

//// =========================
//// SET FILE
//// =========================

function setFile(file) {

  selectedFile = file;

  fileName.textContent = file.name;
  fileSize.textContent = formatSize(file.size);

  filePreview.style.display = "flex";

  openBtn.disabled = false;

  message.textContent = "";

  resultCard.style.display = "none";

}

//// =========================
//// REMOVE
//// =========================

removeBtn.addEventListener("click", () => {

  selectedFile = null;

  fileInput.value = "";

  filePreview.style.display = "none";

  openBtn.disabled = true;

  resultCard.style.display = "none";

  message.textContent = "";

});

//// =========================
//// BUKA FILE
//// =========================

openBtn.addEventListener("click", async () => {

  if (!selectedFile) {
    return;
  }

  openBtn.disabled = true;

  openBtn.textContent = "⏳ Membuka...";

  message.textContent = "Sedang memproses file...";

  try {

    const formData = new FormData();

    formData.append(
      "file",
      selectedFile
    );

    const response = await fetch(
      "/api/open",
      {
        method: "POST",
        body: formData
      }
    );

    const data = await response.json();

    if (!data.status) {
      throw new Error(
        data.message || "Gagal membuka file"
      );
    }

    resultCard.style.display = "block";

    resultName.textContent =
      data.filename;

    result.textContent =
      data.result || "(File kosong)";

    message.textContent =
      "✅ File berhasil dibuka";

    resultCard.scrollIntoView({
      behavior: "smooth"
    });

  } catch (error) {

    message.textContent =
      "❌ " + error.message;

  } finally {

    openBtn.disabled = false;

    openBtn.textContent =
      "🔓 Buka File";

  }

});

//// =========================
//// COPY
//// =========================

copyBtn.addEventListener("click", async () => {

  try {

    await navigator.clipboard.writeText(
      result.textContent
    );

    copyBtn.textContent =
      "✅ Tersalin";

    setTimeout(() => {

      copyBtn.textContent =
        "📋 Salin";

    }, 1500);

  } catch (error) {

    alert("Gagal menyalin");

  }

});

//// =========================
//// DOWNLOAD
//// =========================

downloadBtn.addEventListener("click", () => {

  const blob = new Blob(
    [result.textContent],
    {
      type: "text/plain"
    }
  );

  const url =
    URL.createObjectURL(blob);

  const a =
    document.createElement("a");

  a.href = url;

  a.download =
    selectedFile
      ? selectedFile.name + ".txt"
      : "hasil.txt";

  a.click();

  URL.revokeObjectURL(url);

});
