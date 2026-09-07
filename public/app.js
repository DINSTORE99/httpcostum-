//// =========================
//// ELEMENT
//// =========================

const fileInput = document.getElementById("fileInput");
const chooseBtn = document.getElementById("chooseBtn");

const dropArea = document.getElementById("dropArea");

const fileBox = document.getElementById("fileBox");
const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");

const removeBtn = document.getElementById("removeBtn");
const decryptBtn = document.getElementById("decryptBtn");

const status = document.getElementById("status");

const resultCard = document.getElementById("resultCard");
const configResult = document.getElementById("configResult");

const protections = document.getElementById("protections");
const raw = document.getElementById("raw");

const resultFormat = document.getElementById("resultFormat");
const copyBtn = document.getElementById("copyBtn");


//// =========================
//// STATE
//// =========================

let selectedFile = null;
let lastResult = null;


//// =========================
//// FORMAT SIZE
//// =========================

function formatSize(bytes) {

  if (bytes < 1024)
    return bytes + " B";

  if (bytes < 1024 * 1024)
    return (bytes / 1024).toFixed(2) + " KB";

  return (bytes / 1024 / 1024).toFixed(2) + " MB";
}


//// =========================
//// SELECT FILE
//// =========================

chooseBtn.onclick = () => {
  fileInput.click();
};


fileInput.onchange = () => {

  if (!fileInput.files.length)
    return;

  setFile(fileInput.files[0]);

};


//// =========================
//// DRAG DROP
//// =========================

dropArea.ondragover = e => {

  e.preventDefault();

  dropArea.classList.add("drag");

};


dropArea.ondragleave = () => {

  dropArea.classList.remove("drag");

};


dropArea.ondrop = e => {

  e.preventDefault();

  dropArea.classList.remove("drag");

  const file = e.dataTransfer.files[0];

  if (file)
    setFile(file);

};


//// =========================
//// SET FILE
//// =========================

function setFile(file) {

  selectedFile = file;

  fileName.textContent = file.name;

  fileSize.textContent =
    formatSize(file.size);

  fileBox.style.display = "flex";

  decryptBtn.disabled = false;

  status.textContent = "";

  resultCard.style.display = "none";

}


//// =========================
//// REMOVE
//// =========================

removeBtn.onclick = () => {

  selectedFile = null;

  fileInput.value = "";

  fileBox.style.display = "none";

  decryptBtn.disabled = true;

  resultCard.style.display = "none";

  status.textContent = "";

};


//// =========================
//// DECRYPT
//// =========================

decryptBtn.onclick = async () => {

  if (!selectedFile)
    return;


  decryptBtn.disabled = true;

  decryptBtn.textContent =
    "⏳ Memproses...";

  status.textContent =
    "Sedang decrypt file...";


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


    const data = await response.json();


    if (!data.success) {

      throw new Error(
        data.error ||
        "Decrypt gagal"
      );

    }


    lastResult = data;


    showResult(data);


    status.textContent =
      "✅ File berhasil didecrypt";


  } catch (error) {

    status.textContent =
      "❌ " + error.message;

  }


  decryptBtn.disabled = false;

  decryptBtn.textContent =
    "🔓 Buka File";

};


//// =========================
//// SHOW RESULT
//// =========================

function showResult(data) {

  resultCard.style.display = "block";


  resultFormat.textContent =
    "Format: " +
    (data.format || "HC");


  //// CONFIG

  configResult.innerHTML = "";


  if (
    data.config &&
    typeof data.config === "object"
  ) {

    Object.entries(data.config)
      .forEach(([key, value]) => {

        const item =
          document.createElement("div");

        item.className =
          "config-item";


        const title =
          document.createElement("div");

        title.className =
          "config-key";

        title.textContent =
          key;


        const valueBox =
          document.createElement("pre");

        valueBox.className =
          "config-value";

        valueBox.textContent =
          typeof value === "object"
            ? JSON.stringify(
                value,
                null,
                2
              )
            : String(value);


        item.appendChild(title);

        item.appendChild(valueBox);

        configResult.appendChild(item);

      });

  }


  //// PROTECTIONS

  protections.textContent =
    JSON.stringify(
      data.protections || {},
      null,
      2
    );


  //// RAW

  raw.textContent =
    data.raw || "";


  resultCard.scrollIntoView({
    behavior: "smooth"
  });

}


//// =========================
//// COPY
//// =========================

copyBtn.onclick = async () => {

  if (!lastResult)
    return;


  let text = "";


  if (lastResult.config) {

    text =
      JSON.stringify(
        lastResult.config,
        null,
        2
      );

  }


  await navigator.clipboard.writeText(
    text
  );


  copyBtn.textContent =
    "✅ Tersalin";


  setTimeout(() => {

    copyBtn.textContent =
      "📋 Salin";

  }, 1500);

};
