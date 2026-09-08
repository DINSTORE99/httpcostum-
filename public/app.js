"use strict";

// ========================================
// ELEMENT
// ========================================
const fileInput = document.getElementById("fileInput");
const uploadBox = document.getElementById("uploadBox");
const fileName = document.getElementById("fileName");
const decryptBtn = document.getElementById("decryptBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");

let selectedFile = null;


// ========================================
// PILIH FILE
// ========================================
fileInput?.addEventListener("change", () => {
  const file = fileInput.files?.[0];

  if (!file) {
    resetFile();
    return;
  }

  handleFile(file);
});


// ========================================
// DRAG & DROP
// ========================================
if (uploadBox) {
  ["dragenter", "dragover"].forEach(eventName => {
    uploadBox.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();
      uploadBox.classList.add("dragging");
    });
  });

  ["dragleave", "drop"].forEach(eventName => {
    uploadBox.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();
      uploadBox.classList.remove("dragging");
    });
  });

  uploadBox.addEventListener("drop", e => {
    const file = e.dataTransfer?.files?.[0];

    if (!file) return;

    handleFile(file);
  });
}


// ========================================
// HANDLE FILE
// ========================================
function handleFile(file) {
  const name = file.name || "";

  if (!name.toLowerCase().endsWith(".hc")) {
    selectedFile = null;

    if (fileName) {
      fileName.textContent = "❌ File harus berformat .HC";
    }

    if (decryptBtn) {
      decryptBtn.disabled = true;
    }

    showStatus("❌ Format file tidak didukung", "error");
    return;
  }

  selectedFile = file;

  if (fileName) {
    fileName.textContent = `📄 ${file.name}`;
  }

  if (decryptBtn) {
    decryptBtn.disabled = false;
  }

  resultEl.innerHTML = "";

  showStatus(
    `✅ File siap: ${file.name}`,
    "success"
  );
}


// ========================================
// RESET FILE
// ========================================
function resetFile() {
  selectedFile = null;

  if (fileName) {
    fileName.textContent = "";
  }

  if (decryptBtn) {
    decryptBtn.disabled = true;
  }
}


// ========================================
// BONGKAR CONFIG
// ========================================
decryptBtn?.addEventListener("click", async () => {
  if (!selectedFile) {
    showStatus("❌ Pilih file HC terlebih dahulu", "error");
    return;
  }

  decryptBtn.disabled = true;

  resultEl.innerHTML = "";

  showStatus(
    "⏳ Sedang membongkar config...",
    "running"
  );

  try {
    const formData = new FormData();

    formData.append("file", selectedFile);

    const response = await fetch("/api/decrypt", {
      method: "POST",
      body: formData
    });

    let data;

    try {
      data = await response.json();
    } catch {
      throw new Error(
        `Server mengembalikan response tidak valid (${response.status})`
      );
    }

    if (!response.ok || data?.success === false) {
      throw new Error(
        data?.message ||
        data?.error ||
        "Gagal membongkar config"
      );
    }

    renderResult(data);

    // 🔔 SATU KALI "TING"
    successSound();

    showStatus(
      "✅ Config berhasil dibongkar",
      "success"
    );

    resultEl.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });

  } catch (error) {
    console.error(error);

    resultEl.innerHTML = "";

    showStatus(
      `❌ ${error.message || "Terjadi kesalahan"}`,
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
  let config = data;

  // Kalau API mengirim result sebagai JSON string
  if (typeof data?.result === "string") {
    try {
      config = JSON.parse(data.result);
    } catch {
      renderRawResult(data.result);
      return;
    }
  }

  // Kalau result berupa object
  if (
    data?.result &&
    typeof data.result === "object"
  ) {
    config = data.result;
  }

  // Kalau API punya config
  if (
    data?.config &&
    typeof data.config === "object"
  ) {
    config = data.config;
  }

  // Kalau masih string
  if (typeof config === "string") {
    renderRawResult(config);
    return;
  }

  if (!config || typeof config !== "object") {
    renderRawResult(String(config ?? ""));
    return;
  }

  resultEl.innerHTML = `
    <div class="result-card">
      <div class="result-title">
        📋 HASIL CONFIG
      </div>

      <div id="configFields"></div>
    </div>
  `;

  const fieldsEl = document.getElementById("configFields");

  if (!fieldsEl) return;

  // ========================================
  // SSH
  // ========================================
  const ssh = getSSH(config);

  if (ssh) {
    fieldsEl.appendChild(
      createField(
        "ssh",
        "🔐 SSH",
        ssh,
        true
      )
    );
  }

  // ========================================
  // FIELD PRIORITAS
  // ========================================
  const priority = [
    ["host", "🌐 Host"],
    ["server", "🖥️ Server"],
    ["port", "🔌 Port"],
    ["username", "👤 Username"],
    ["user", "👤 Username"],
    ["password", "🔑 Password"],
    ["sni", "🎯 SNI"],
    ["sniHost", "🎯 SNI Host"],
    ["remoteProxy", "🔀 Remote Proxy"],
    ["remote_proxy", "🔀 Remote Proxy"],
    ["proxy", "🔀 Proxy"],
    ["payload", "📦 Payload"],
    ["dns", "🌍 DNS"],
    ["dnsProfile", "🌍 DNS Profile"],
    ["localPort", "📍 Local Port"],
    ["defaultRoute", "🛣️ Default Route"],
    ["tunnel", "🚇 Tunnel"],
    ["method", "⚙️ Method"],
    ["userAgent", "🧭 User Agent"]
  ];

  const used = new Set();

  priority.forEach(([key, title]) => {
    const actualKey = findKey(config, key);

    if (!actualKey) return;

    const value = config[actualKey];

    if (isEmptyValue(value)) return;

    // Hindari username/password tampil dua kali
    if (
      actualKey.toLowerCase() === "user" &&
      findKey(config, "username")
    ) {
      return;
    }

    used.add(actualKey);

    fieldsEl.appendChild(
      createField(
        actualKey,
        title,
        value
      )
    );
  });

  // ========================================
  // FIELD LAIN
  // ========================================
  Object.entries(config).forEach(
    ([key, value]) => {
      if (used.has(key)) return;

      if (isInternalKey(key)) return;

      if (isEmptyValue(value)) return;

      fieldsEl.appendChild(
        createField(
          key,
          prettyName(key),
          value
        )
      );
    }
  );

  // ========================================
  // PROTECTIONS
  // ========================================
  renderProtection(config, fieldsEl);

  if (!fieldsEl.children.length) {
    renderRawResult(data);
  }
}


// ========================================
// CREATE FIELD CARD
// ========================================
function createField(
  key,
  title,
  value,
  isSSH = false
) {
  const item = document.createElement("div");

  item.className = "config-item";

  const formatted = formatValue(value);

  item.innerHTML = `
    <div class="config-header">
      <div class="config-name">
        ${escapeHTML(title)}
      </div>

      <button
        type="button"
        class="config-copy"
        data-copy-key="${escapeHTML(key)}"
      >
        COPY
      </button>
    </div>

    <div class="config-value ${isSSH || key.toLowerCase().includes("payload") ? "payload" : ""}">
      ${escapeHTML(formatted)}
    </div>
  `;

  const copyBtn =
    item.querySelector(".config-copy");

  copyBtn?.addEventListener("click", async () => {
    const ok = await copyText(formatted);

    if (ok) {
      copyBtn.textContent = "COPIED";

      setTimeout(() => {
        copyBtn.textContent = "COPY";
      }, 1200);
    }
  });

  return item;
}


// ========================================
// SSH FORMAT
// ========================================
function getSSH(config) {
  const host =
    getValue(config, [
      "host",
      "server",
      "sshHost",
      "ssh_server"
    ]);

  const port =
    getValue(config, [
      "port",
      "sshPort",
      "ssh_port"
    ]);

  const username =
    getValue(config, [
      "username",
      "user",
      "sshUsername",
      "ssh_username"
    ]);

  const password =
    getValue(config, [
      "password",
      "pass",
      "sshPassword",
      "ssh_password"
    ]);

  if (
    isEmptyValue(host) &&
    isEmptyValue(port) &&
    isEmptyValue(username) &&
    isEmptyValue(password)
  ) {
    return null;
  }

  const lines = [];

  if (!isEmptyValue(host)) {
    lines.push(`Host     : ${formatValue(host)}`);
  }

  if (!isEmptyValue(port)) {
    lines.push(`Port     : ${formatValue(port)}`);
  }

  if (!isEmptyValue(username)) {
    lines.push(`Username : ${formatValue(username)}`);
  }

  if (!isEmptyValue(password)) {
    lines.push(`Password : ${formatValue(password)}`);
  }

  return lines.join("\n");
}


// ========================================
// PROTECTION
// ========================================
function renderProtection(config, parent) {
  const lockModes =
    config.lockModes ||
    config.lock_modes;

  if (
    !Array.isArray(lockModes) ||
    !lockModes.length
  ) {
    return;
  }

  parent.appendChild(
    createField(
      "lockModes",
      "🔒 Protection",
      lockModes.join("\n")
    )
  );
}


// ========================================
// RAW RESULT
// ========================================
function renderRawResult(value) {
  resultEl.innerHTML = `
    <div class="result-card">
      <div class="result-title">
        📋 HASIL CONFIG
      </div>

      <div class="config-item">
        <div class="config-header">
          <div class="config-name">
            📄 Result
          </div>

          <button
            type="button"
            class="config-copy"
            id="copyRaw"
          >
            COPY
          </button>
        </div>

        <div class="config-value payload">
          ${escapeHTML(formatValue(value))}
        </div>
      </div>
    </div>
  `;

  document
    .getElementById("copyRaw")
    ?.addEventListener("click", async e => {
      const ok = await copyText(
        formatValue(value)
      );

      if (ok) {
        e.target.textContent = "COPIED";

        setTimeout(() => {
          e.target.textContent = "COPY";
        }, 1200);
      }
    });
}


// ========================================
// FIND KEY
// ========================================
function findKey(obj, wanted) {
  if (!obj || typeof obj !== "object") {
    return null;
  }

  const target = wanted.toLowerCase();

  const key = Object.keys(obj).find(
    k => k.toLowerCase() === target
  );

  return key || null;
}


// ========================================
// GET VALUE
// ========================================
function getValue(obj, keys) {
  for (const key of keys) {
    const actual = findKey(obj, key);

    if (actual) {
      const value = obj[actual];

      if (!isEmptyValue(value)) {
        return value;
      }
    }
  }

  return null;
}


// ========================================
// INTERNAL CRYPTO FIELD
// ========================================
function isInternalKey(key) {
  const k = key.toLowerCase();

  const blocked = [
    "configaeskey",
    "configidentifier",
    "configsalt",
    "configtimestamp",
    "configexpirytimestamp",
    "lockmodeshash",
    "confighwid",
    "configlockmobileoperatorid",
    "v2rrawjson",
    "overwriteserverdata",
    "ehi",
    "crypto",
    "cipher",
    "nonce",
    "argon",
    "masterkey",
    "aeskey"
  ];

  return blocked.some(
    item => k.includes(item)
  );
}


// ========================================
// EMPTY CHECK
// ========================================
function isEmptyValue(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return true;
  }

  if (typeof value === "string") {
    return value.trim() === "";
  }

  if (Array.isArray(value)) {
    return value.length === 0;
  }

  return false;
}


// ========================================
// FORMAT VALUE
// ========================================
function formatValue(value) {
  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (
    typeof value === "number" ||
    typeof value === "bigint"
  ) {
    return String(value);
  }

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


// ========================================
// PRETTY NAME
// ========================================
function prettyName(key) {
  return key
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, char =>
      char.toUpperCase()
    );
}


// ========================================
// ESCAPE HTML
// ========================================
function escapeHTML(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


// ========================================
// COPY
// ========================================
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(
      String(text)
    );

    return true;
  } catch {
    try {
      const textarea =
        document.createElement("textarea");

      textarea.value = String(text);

      textarea.style.position = "fixed";
      textarea.style.opacity = "0";

      document.body.appendChild(textarea);

      textarea.focus();
      textarea.select();

      const success =
        document.execCommand("copy");

      textarea.remove();

      return success;
    } catch {
      return false;
    }
  }
}


// ========================================
// STATUS
// ========================================
function showStatus(message, type = "") {
  if (!statusEl) return;

  statusEl.className =
    `status ${type}`;

  statusEl.textContent = message;
}


// ========================================
// SUCCESS SOUND
// "TING" SATU KALI
// ========================================
function successSound() {
  try {
    const AudioContext =
      window.AudioContext ||
      window.webkitAudioContext;

    if (!AudioContext) return;

    const audioCtx =
      new AudioContext();

    const osc =
      audioCtx.createOscillator();

    const gain =
      audioCtx.createGain();

    osc.type = "sine";
    osc.frequency.value = 900;

    gain.gain.setValueAtTime(
      0.001,
      audioCtx.currentTime
    );

    gain.gain.exponentialRampToValueAtTime(
      0.18,
      audioCtx.currentTime + 0.02
    );

    gain.gain.exponentialRampToValueAtTime(
      0.001,
      audioCtx.currentTime + 0.25
    );

    osc.connect(gain);
    gain.connect(audioCtx.destination);

    osc.start();

    osc.stop(
      audioCtx.currentTime + 0.25
    );

    setTimeout(() => {
      audioCtx.close().catch(() => {});
    }, 500);

  } catch (error) {
    console.warn(
      "Audio tidak tersedia:",
      error
    );
  }
}
