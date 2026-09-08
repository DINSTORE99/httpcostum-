const fileInput = document.getElementById("fileInput");
const uploadBox = document.getElementById("uploadBox");
const fileName = document.getElementById("fileName");
const decryptBtn = document.getElementById("decryptBtn");
const statusBox = document.getElementById("status");
const resultBox = document.getElementById("result");

let selectedFile = null;


/* ================================
   FILE SELECT
================================ */

fileInput.addEventListener("change", () => {

  const file = fileInput.files[0];

  if (!file) return;

  setFile(file);

});


/* ================================
   DRAG DROP
================================ */

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


/* ================================
   SET FILE
================================ */

function setFile(file) {

  if (!file.name.toLowerCase().endsWith(".ehi")) {

    selectedFile = null;

    decryptBtn.disabled = true;

    fileName.style.display = "none";

    showStatus(
      "❌ Hanya file .EHI yang diperbolehkan",
      "error"
    );

    return;
  }


  selectedFile = file;

  fileName.textContent =
    "📄 " + file.name;

  fileName.style.display = "block";

  decryptBtn.disabled = false;

  resultBox.innerHTML = "";

  showStatus(
    "✅ File EHI siap dibongkar",
    "success"
  );

}


/* ================================
   DECRYPT
================================ */

decryptBtn.addEventListener("click", async () => {

  if (!selectedFile) {

    showStatus(
      "❌ Pilih file EHI terlebih dahulu",
      "error"
    );

    return;
  }


  decryptBtn.disabled = true;

  decryptBtn.textContent =
    "⏳ MEMPROSES...";

  resultBox.innerHTML = "";


  showStatus(
    "🔄 Sedang membongkar config EHI...",
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


    const text =
      await response.text();


    let data;


    try {

      data = JSON.parse(text);

    } catch {

      throw new Error(
        text ||
        "Server tidak mengembalikan JSON"
      );

    }


    if (
      !response.ok ||
      !data.success
    ) {

      throw new Error(
        data.error ||
        "Gagal membongkar config EHI"
      );

    }


    renderResult(data);


    showStatus(
      "✅ Config EHI berhasil dibongkar",
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

    decryptBtn.textContent =
      "🔓 BONGKAR CONFIG";

  }

});


/* ================================
   RENDER
================================ */

function renderResult(data) {

  resultBox.innerHTML = "";


  const config =
    data.data ||
    data.config ||
    data.result;


  const title =
    document.createElement("div");

  title.className =
    "result-title";

  title.textContent =
    "📋 HASIL CONFIG EHI";


  resultBox.appendChild(title);


  if (
    !config ||
    typeof config !== "object"
  ) {

    const field =
      createField(
        "result",
        "📄 RESULT",
        String(config || data.result || "")
      );

    resultBox.appendChild(field);

    return;
  }


  let count = 0;


  Object.entries(config).forEach(
    ([key, value]) => {

      if (
        value === null ||
        value === undefined ||
        value === ""
      ) {
        return;
      }


      count++;


      const field =
        createField(
          key,
          prettyName(key),
          formatValue(value)
        );


      resultBox.appendChild(field);

    }
  );


  if (!count) {

    resultBox.innerHTML += `
      <div class="empty">
        ⚠️ Config berhasil dibuka,
        tetapi tidak ada field yang dapat ditampilkan.
      </div>
    `;

  }

}


/* ================================
   CREATE FIELD
================================ */

function createField(
  key,
  title,
  value
) {

  const box =
    document.createElement("div");

  box.className =
    "field";


  const header =
    document.createElement("div");

  header.className =
    "field-header";


  const fieldTitle =
    document.createElement("div");

  fieldTitle.className =
    "field-title";

  fieldTitle.textContent =
    title;


  const copyBtn =
    document.createElement("button");

  copyBtn.type =
    "button";

  copyBtn.className =
    "copy-btn";

  copyBtn.textContent =
    "COPY";


  copyBtn.addEventListener(
    "click",
    () => copyText(value, copyBtn)
  );


  header.appendChild(fieldTitle);

  header.appendChild(copyBtn);


  const valueBox =
    document.createElement("div");

  valueBox.className =
    "field-value";

  valueBox.textContent =
    value;


  box.appendChild(header);

  box.appendChild(valueBox);


  return box;
}


/* ================================
   COPY
================================ */

async function copyText(
  text,
  button
) {

  try {

    await navigator.clipboard.writeText(
      String(text)
    );


    const old =
      button.textContent;


    button.textContent =
      "COPIED ✓";

    button.classList.add(
      "copied"
    );


    setTimeout(() => {

      button.textContent =
        old;

      button.classList.remove(
        "copied"
      );

    }, 1500);


  } catch {

    const textarea =
      document.createElement(
        "textarea"
      );

    textarea.value =
      String(text);

    textarea.style.position =
      "fixed";

    textarea.style.left =
      "-9999px";


    document.body.appendChild(
      textarea
    );

    textarea.select();

    document.execCommand(
      "copy"
    );

    textarea.remove();


    button.textContent =
      "COPIED ✓";


    setTimeout(() => {

      button.textContent =
        "COPY";

    }, 1500);

  }

}


/* ================================
   PRETTY NAME
================================ */

function prettyName(key) {

  const names = {

    payload: "📡 PAYLOAD",

    proxy: "🌐 PROXY",

    sni: "🔗 SNI",

    host: "🌍 HOST",

    port: "🔌 PORT",

    username: "👤 USERNAME",

    password: "🔑 PASSWORD",

    ssh: "🔐 SSH",

    server: "🖥️ SERVER",

    configName: "🏷️ CONFIG NAME",

    remarks: "📝 REMARKS",

    note: "📝 NOTE",

    expiry: "⏰ EXPIRY",

    expiryTime: "⏰ EXPIRY TIME",

    v2rayConfig: "🚀 V2RAY CONFIG",

    v2rayEnabled: "🚀 V2RAY ENABLED",

    dnsResolver: "🌐 DNS RESOLVER",

    slowdnsServer: "🐌 SLOWDNS SERVER",

    slowdnsPublickey: "🔑 SLOWDNS PUBLIC KEY",

    connectionMode: "🔌 CONNECTION MODE"

  };


  return (
    names[key] ||
    key
      .replace(/([A-Z])/g, " $1")
      .replace(/^./, c => c.toUpperCase())
  );

}


/* ================================
   FORMAT
================================ */

function formatValue(value) {

  if (
    typeof value === "object" &&
    value !== null
  ) {

    try {

      return JSON.stringify(
        value,
        null,
        2
      );

    } catch {

      return String(value);

    }

  }


  return String(value);

}


/* ================================
   STATUS
================================ */

function showStatus(
  message,
  type = ""
) {

  statusBox.textContent =
    message;

  statusBox.className =
    "status " + type;

  statusBox.style.display =
    "block";

}
