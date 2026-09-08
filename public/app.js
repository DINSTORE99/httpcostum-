// ========================================
// BONGKAR CONFIG HC + EHI
// public/app.js
// ========================================

const fileInput = document.getElementById("fileInput");
const uploadBox = document.getElementById("uploadBox");
const fileName = document.getElementById("fileName");
const decryptBtn = document.getElementById("decryptBtn");
const statusBox = document.getElementById("status");
const resultBox = document.getElementById("result");

let selectedFile = null;


// ========================================
// FILE SELECT
// ========================================

fileInput.addEventListener("change", function () {
  if (!this.files || !this.files.length) {
    resetFile();
    return;
  }

  handleFile(this.files[0]);
});


// ========================================
// HANDLE FILE
// ========================================

function handleFile(file) {
  if (!file) return;

  const name = file.name.toLowerCase();

  if (!name.endsWith(".hc") && !name.endsWith(".ehi")) {
    selectedFile = null;
    decryptBtn.disabled = true;

    fileName.textContent = "";
    showStatus(
      "❌ Format tidak didukung. Pilih file .HC atau .EHI",
      "error"
    );

    return;
  }

  selectedFile = file;

  fileName.textContent =
    `📄 ${file.name} • ${formatBytes(file.size)}`;

  decryptBtn.disabled = false;

  clearStatus();
  resultBox.innerHTML = "";
}


// ========================================
// DRAG & DROP
// ========================================

uploadBox.addEventListener("dragover", function (e) {
  e.preventDefault();
  e.stopPropagation();

  uploadBox.classList.add("dragover");
});

uploadBox.addEventListener("dragleave", function (e) {
  e.preventDefault();
  e.stopPropagation();

  uploadBox.classList.remove("dragover");
});

uploadBox.addEventListener("drop", function (e) {
  e.preventDefault();
  e.stopPropagation();

  uploadBox.classList.remove("dragover");

  const files = e.dataTransfer.files;

  if (!files || !files.length) return;

  handleFile(files[0]);
});


// ========================================
// DECRYPT BUTTON
// ========================================

decryptBtn.addEventListener("click", async function () {
  if (!selectedFile) {
    showStatus("❌ Pilih file terlebih dahulu", "error");
    return;
  }

  decryptBtn.disabled = true;

  resultBox.innerHTML = "";

  showStatus(
    "⏳ Sedang membongkar config...",
    "loading"
  );

  try {
    const formData = new FormData();

    formData.append("file", selectedFile);

    const response = await fetch("/api/decrypt", {
      method: "POST",
      body: formData
    });

    // Jangan langsung response.json()
    // supaya error HTML dari server tidak menyebabkan
    // Unexpected end of JSON input
    const text = await response.text();

    let data;

    try {
      data = JSON.parse(text);
    } catch (err) {
      console.error("Response server:", text);

      throw new Error(
        "Server mengembalikan response yang tidak valid."
      );
    }

    if (!response.ok || !data.success) {
      throw new Error(
        data.error ||
        data.message ||
        "Gagal membongkar config."
      );
    }

    showStatus(
      `✅ Berhasil membongkar ${data.format || getFormat(selectedFile.name)}`,
      "success"
    );

    renderResult(data);

  } catch (error) {
    console.error(error);

    showStatus(
      `❌ ${error.message || "Terjadi kesalahan."}`,
      "error"
    );

  } finally {
    decryptBtn.disabled = false;
  }
});


// ========================================
// RENDER RESULT
// ========================================

function renderResult(data) {
  resultBox.innerHTML = "";

  if (!data) {
    resultBox.innerHTML = `
      <div class="empty">
        ❌ Tidak ada data hasil decrypt.
      </div>
    `;
    return;
  }

  const format = String(
    data.format ||
    getFormat(selectedFile?.name || "")
  ).toUpperCase();

  const config = data.config || {};
  const protections = data.protections || {};

  // ======================================
  // RESULT TITLE
  // ======================================

  const title = document.createElement("div");

  title.className = "result-title";

  title.innerHTML = `
    <span>📦</span>
    <div>
      <strong>HASIL CONFIG ${escapeHtml(format)}</strong>
      <small>Data berhasil dibongkar</small>
    </div>
  `;

  resultBox.appendChild(title);


  // ======================================
  // SSH FIELD
  // ======================================

  let sshValue = "";

  if (typeof config.sshField === "string") {
    sshValue = config.sshField;
  }

  if (!sshValue && typeof config.ssh === "string") {
    sshValue = config.ssh;
  }

  if (
    !sshValue &&
    config.ssh &&
    typeof config.ssh === "object"
  ) {
    sshValue = buildSSH(config.ssh);
  }

  if (sshValue) {
    const sshBox = createSSHBox(sshValue);

    resultBox.appendChild(sshBox);
  }


  // ======================================
  // CONFIG FIELDS
  // ======================================

  const configEntries = Object.entries(config);

  for (const [key, value] of configEntries) {

    // SSH sudah ditampilkan khusus
    if (
      key === "sshField" ||
      key === "ssh"
    ) {
      continue;
    }

    const field = createField(
      key,
      value
    );

    resultBox.appendChild(field);
  }


  // ======================================
  // PROTECTION FIELDS
  // ======================================

  const protectionEntries =
    Object.entries(protections);

  if (protectionEntries.length > 0) {

    const protectionTitle =
      document.createElement("div");

    protectionTitle.className =
      "protection-title";

    protectionTitle.innerHTML = `
      <span>🛡️</span>
      <strong>PROTECTION</strong>
    `;

    resultBox.appendChild(protectionTitle);

    for (const [key, value] of protectionEntries) {

      const field = createField(
        key,
        value
      );

      resultBox.appendChild(field);
    }
  }


  // ======================================
  // EMPTY RESULT
  // ======================================

  if (
    configEntries.length === 0 &&
    protectionEntries.length === 0 &&
    !sshValue
  ) {
    resultBox.innerHTML += `
      <div class="empty">
        ⚠️ Config berhasil diproses,
        tetapi tidak ada field yang dapat ditampilkan.
      </div>
    `;
  }
}


// ========================================
// CREATE NORMAL FIELD
// ========================================

function createField(key, value) {
  const field = document.createElement("div");

  field.className = "field";

  const header = document.createElement("div");

  header.className = "field-header";

  const title = document.createElement("div");

  title.className = "field-title";

  title.textContent = prettyName(key);

  const copyBtn = createCopyButton(
    "COPY",
    () => getCopyValue(value)
  );

  header.appendChild(title);
  header.appendChild(copyBtn);

  const valueBox = document.createElement("div");

  valueBox.className = "field-value";

  valueBox.textContent =
    formatValue(value);

  field.appendChild(header);
  field.appendChild(valueBox);

  return field;
}


// ========================================
// CREATE SSH BOX
// ========================================

function createSSHBox(value) {
  const box = document.createElement("div");

  box.className = "ssh-box";

  const header = document.createElement("div");

  header.className = "ssh-header";

  const title = document.createElement("div");

  title.className = "ssh-title";

  title.textContent = "SSH";

  const copyBtn = createCopyButton(
    "COPY",
    () => value
  );

  header.appendChild(title);
  header.appendChild(copyBtn);

  const valueBox = document.createElement("div");

  valueBox.className = "ssh-value";

  valueBox.textContent = value;

  box.appendChild(header);
  box.appendChild(valueBox);

  return box;
}


// ========================================
// COPY BUTTON
// ========================================

function createCopyButton(label, getValue) {
  const button = document.createElement("button");

  button.type = "button";

  button.className = "copy-btn";

  button.textContent = label;

  button.addEventListener("click", async function (e) {
    e.preventDefault();
    e.stopPropagation();

    let value = "";

    try {
      value = getValue();
    } catch (err) {
      console.error(err);
      value = "";
    }

    if (
      value === null ||
      value === undefined
    ) {
      value = "";
    }

    value = String(value);

    if (!value.trim()) {
      showStatus(
        "⚠️ Field kosong, tidak ada yang bisa di-copy.",
        "error"
      );
      return;
    }

    const success = await copyText(value);

    if (success) {
      const oldText = button.textContent;

      button.textContent = "✓ COPIED";

      button.classList.add("copied");

      setTimeout(() => {
        button.textContent = oldText;
        button.classList.remove("copied");
      }, 1500);
    } else {
      showStatus(
        "❌ Gagal menyalin ke clipboard.",
        "error"
      );
    }
  });

  return button;
}


// ========================================
// COPY TEXT
// ========================================

async function copyText(text) {

  // Modern Clipboard API
  try {
    if (
      navigator.clipboard &&
      window.isSecureContext
    ) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (err) {
    console.warn(
      "Clipboard API gagal:",
      err
    );
  }

  // Fallback untuk browser lama / HTTP
  try {
    const textarea =
      document.createElement("textarea");

    textarea.value = text;

    textarea.style.position = "fixed";
    textarea.style.left = "-999999px";
    textarea.style.top = "-999999px";

    textarea.setAttribute(
      "readonly",
      ""
    );

    document.body.appendChild(textarea);

    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(
      0,
      textarea.value.length
    );

    const success =
      document.execCommand("copy");

    textarea.remove();

    return success;

  } catch (err) {
    console.error(
      "Fallback copy gagal:",
      err
    );

    return false;
  }
}


// ========================================
// BUILD SSH
// ========================================

function buildSSH(ssh) {
  if (!ssh || typeof ssh !== "object") {
    return "";
  }

  const host =
    ssh.host ||
    ssh.server ||
    ssh.ip ||
    "";

  const port =
    ssh.port ||
    "";

  const username =
    ssh.username ||
    ssh.user ||
    "";

  const password =
    ssh.password ||
    ssh.pass ||
    "";

  if (
    host &&
    port &&
    username &&
    password
  ) {
    return `${host}:${port}@${username}:${password}`;
  }

  return [
    host,
    port,
    username,
    password
  ]
    .filter(Boolean)
    .join(":");
}


// ========================================
// FORMAT VALUE
// ========================================

function formatValue(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  if (typeof value === "string") {
    return value;
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  try {
    return JSON.stringify(
      value,
      null,
      2
    );
  } catch (err) {
    return String(value);
  }
}


// ========================================
// VALUE UNTUK COPY
// ========================================

function getCopyValue(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  if (typeof value === "string") {
    return value;
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  try {
    return JSON.stringify(
      value,
      null,
      2
    );
  } catch (err) {
    return String(value);
  }
}


// ========================================
// PRETTY FIELD NAME
// ========================================

function prettyName(key) {
  const names = {
    payload: "Payload",
    proxy: "Proxy",
    lockAllConfig: "Lock All Config",
    blockedByRoot: "Blocked By Root",
    expiryTime: "Expiry Time",
    noteEnabled: "Note Enabled",
    notes: "Notes",
    sshField: "SSH",
    mobileDataAndLockProvider:
      "Mobile Data & Lock Provider",
    unlockUserAndPass:
      "Unlock User & Password",
    ovpnConfig: "OVPN Config",
    ovpnUserAndPass:
      "OVPN User & Password",
    sni: "SNI",
    unlockUserAndPass2:
      "Unlock User & Password 2",
    unknown14: "Unknown 14",
    blockedByHwid: "Blocked By HWID",
    cloudconfig: "Cloud Config",
    psiphon: "Psiphon",
    name: "Name",
    blockArea: "Block Area",
    connectionMode: "Connection Mode",
    blockedByPassword:
      "Blocked By Password",
    unknown22: "Unknown 22",
    extraSniffer: "Extra Sniffer",
    psiphon2: "Psiphon 2",
    v2rayEnabled: "V2Ray Enabled",
    v2rayConfig: "V2Ray Config",
    version: "Version",
    slowdnsEnabled: "SlowDNS Enabled",
    slowdnsServer: "SlowDNS Server",
    slowdnsPublickey:
      "SlowDNS Public Key",
    dnsResolver: "DNS Resolver",

    // EHI
    configAesKey: "Config AES Key",
    configIdentifier: "Config Identifier",
    configSalt: "Config Salt",
    configTimestamp: "Config Timestamp",
    configExpiryTimestamp:
      "Config Expiry Timestamp",
    lockModes: "Lock Modes",
    lockModesHash: "Lock Modes Hash",
    configHwid: "Config HWID",
    configLockMobileOperatorId:
      "Config Mobile Operator ID",
    configData: "Config Data",
    configMessage: "Config Message",
    overwriteServerData:
      "Overwrite Server Data",
    v2rRawJson: "V2Ray Raw JSON"
  };

  if (names[key]) {
    return names[key];
  }

  return key
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, char =>
      char.toUpperCase()
    );
}


// ========================================
// FORMAT FILE SIZE
// ========================================

function formatBytes(bytes) {
  if (!bytes) {
    return "0 B";
  }

  const units = [
    "B",
    "KB",
    "MB",
    "GB"
  ];

  const index = Math.floor(
    Math.log(bytes) /
    Math.log(1024)
  );

  return (
    parseFloat(
      (bytes /
        Math.pow(1024, index)
      ).toFixed(2)
    ) +
    " " +
    units[
      Math.min(
        index,
        units.length - 1
      )
    ]
  );
}


// ========================================
// GET FORMAT
// ========================================

function getFormat(filename) {
  if (!filename) {
    return "CONFIG";
  }

  const name =
    filename.toLowerCase();

  if (name.endsWith(".hc")) {
    return "HC";
  }

  if (name.endsWith(".ehi")) {
    return "EHI";
  }

  return "CONFIG";
}


// ========================================
// STATUS
// ========================================

function showStatus(message, type) {
  statusBox.textContent = message;

  statusBox.className =
    `status ${type || ""}`;
}


function clearStatus() {
  statusBox.textContent = "";

  statusBox.className =
    "status";
}


// ========================================
// RESET FILE
// ========================================

function resetFile() {
  selectedFile = null;

  fileName.textContent = "";

  decryptBtn.disabled = true;

  resultBox.innerHTML = "";

  clearStatus();
}


// ========================================
// ESCAPE HTML
// ========================================

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


// ========================================
// INITIAL STATE
// ========================================

decryptBtn.disabled = true;

console.log(
  "BONGKAR CONFIG HC + EHI siap."
);
