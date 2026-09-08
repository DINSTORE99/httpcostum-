"use strict";

/*
====================================================
 DINSTORE - BONGKAR CONFIG
 public/app.js
====================================================
*/


// ==================================================
// ELEMENT
// ==================================================

const fileInput  = document.getElementById("fileInput");
const uploadBox  = document.getElementById("uploadBox");
const fileName   = document.getElementById("fileName");
const decryptBtn = document.getElementById("decryptBtn");
const statusEl   = document.getElementById("status");
const resultEl   = document.getElementById("result");


// ==================================================
// STATE
// ==================================================

let selectedFile = null;
let isDecrypting = false;


// ==================================================
// FILE INPUT
// ==================================================

if (fileInput) {

  fileInput.addEventListener("change", () => {

    const file = fileInput.files?.[0];

    if (!file) {
      resetFile();
      return;
    }

    handleFile(file);

  });

}


// ==================================================
// DRAG & DROP
// ==================================================

if (uploadBox) {

  uploadBox.addEventListener("dragenter", dragEnter);
  uploadBox.addEventListener("dragover", dragEnter);

  uploadBox.addEventListener("dragleave", dragLeave);
  uploadBox.addEventListener("drop", dropFile);

}


function dragEnter(event) {

  event.preventDefault();
  event.stopPropagation();

  uploadBox.classList.add("dragging");

}


function dragLeave(event) {

  event.preventDefault();
  event.stopPropagation();

  uploadBox.classList.remove("dragging");

}


function dropFile(event) {

  event.preventDefault();
  event.stopPropagation();

  uploadBox.classList.remove("dragging");

  const files = event.dataTransfer?.files;

  if (!files || !files.length) {
    return;
  }

  handleFile(files[0]);

}


// ==================================================
// HANDLE FILE
// ==================================================

function handleFile(file) {

  if (!file) {
    return;
  }

  const filename = file.name || "";

  const extension =
    filename
      .split(".")
      .pop()
      .toLowerCase();

  // ------------------------------------------------
  // HC ONLY
  // ------------------------------------------------

  if (extension !== "hc") {

    selectedFile = null;

    if (fileInput) {
      fileInput.value = "";
    }

    if (fileName) {
      fileName.textContent =
        "❌ File harus berformat .HC";
    }

    if (decryptBtn) {
      decryptBtn.disabled = true;
    }

    showStatus(
      "❌ Format file tidak didukung",
      "error"
    );

    return;
  }


  // ------------------------------------------------
  // VALID
  // ------------------------------------------------

  selectedFile = file;


  if (fileName) {

    fileName.textContent =
      `📄 ${file.name}`;

  }


  if (decryptBtn) {

    decryptBtn.disabled = false;

  }


  if (resultEl) {

    resultEl.innerHTML = "";

  }


  showStatus(
    `✅ File siap: ${file.name}`,
    "success"
  );

}


// ==================================================
// RESET FILE
// ==================================================

function resetFile() {

  selectedFile = null;

  if (fileInput) {
    fileInput.value = "";
  }

  if (fileName) {
    fileName.textContent = "";
  }

  if (decryptBtn) {
    decryptBtn.disabled = true;
  }

}


// ==================================================
// DECRYPT BUTTON
// ==================================================

if (decryptBtn) {

  decryptBtn.addEventListener(
    "click",
    decryptConfig
  );

}


// ==================================================
// DECRYPT CONFIG
// ==================================================

async function decryptConfig() {

  if (isDecrypting) {
    return;
  }


  if (!selectedFile) {

    showStatus(
      "❌ Pilih file HC terlebih dahulu",
      "error"
    );

    return;
  }


  isDecrypting = true;


  decryptBtn.disabled = true;


  if (resultEl) {
    resultEl.innerHTML = "";
  }


  showStatus(
    "⏳ Sedang membongkar config...",
    "running"
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
        body: formData,
        headers: {
          "Accept": "application/json"
        }
      }
    );


    let data = null;


    try {

      data = await response.json();

    } catch (jsonError) {

      throw new Error(
        `Response server tidak valid (${response.status})`
      );

    }


    // ------------------------------------------------
    // SERVER ERROR
    // ------------------------------------------------

    if (!response.ok) {

      throw new Error(
        data?.message ||
        data?.error ||
        `Server error ${response.status}`
      );

    }


    // ------------------------------------------------
    // API SUCCESS FALSE
    // ------------------------------------------------

    if (
      data &&
      data.success === false
    ) {

      throw new Error(
        data.message ||
        data.error ||
        "Gagal membongkar config"
      );

    }


    // ------------------------------------------------
    // RENDER
    // ------------------------------------------------

    renderResult(data);


    // ------------------------------------------------
    // SOUND
    // ------------------------------------------------

    successSound();


    // ------------------------------------------------
    // STATUS
    // ------------------------------------------------

    showStatus(
      "✅ Config berhasil dibongkar",
      "success"
    );


    // ------------------------------------------------
    // SCROLL RESULT
    // ------------------------------------------------

    setTimeout(() => {

      resultEl?.scrollIntoView({
        behavior: "smooth",
        block: "start"
      });

    }, 100);


  } catch (error) {

    console.error(
      "Decrypt error:",
      error
    );


    if (resultEl) {
      resultEl.innerHTML = "";
    }


    showStatus(
      `❌ ${error?.message || "Terjadi kesalahan"}`,
      "error"
    );


  } finally {

    isDecrypting = false;

    if (decryptBtn) {
      decryptBtn.disabled = !selectedFile;
    }

  }

}


// ==================================================
// RENDER RESULT
// ==================================================

function renderResult(data) {

  let config = data;


  // ------------------------------------------------
  // result = JSON STRING
  // ------------------------------------------------

  if (
    data &&
    typeof data.result === "string"
  ) {

    try {

      config = JSON.parse(
        data.result
      );

    } catch {

      renderRawResult(
        data.result
      );

      return;

    }

  }


  // ------------------------------------------------
  // result = OBJECT
  // ------------------------------------------------

  if (
    data &&
    data.result &&
    typeof data.result === "object"
  ) {

    config = data.result;

  }


  // ------------------------------------------------
  // config = OBJECT
  // ------------------------------------------------

  if (
    data &&
    data.config &&
    typeof data.config === "object"
  ) {

    config = data.config;

  }


  // ------------------------------------------------
  // STRING
  // ------------------------------------------------

  if (
    typeof config === "string"
  ) {

    renderRawResult(config);

    return;

  }


  // ------------------------------------------------
  // INVALID
  // ------------------------------------------------

  if (
    !config ||
    typeof config !== "object"
  ) {

    renderRawResult(
      String(config ?? "")
    );

    return;

  }


  // ------------------------------------------------
  // CONTAINER
  // ------------------------------------------------

  resultEl.innerHTML = `
    <div class="result-card">

      <div class="result-title">
        📋 HASIL CONFIG
      </div>

      <div
        id="configFields"
        class="config-fields"
      ></div>

    </div>
  `;


  const fields =
    document.getElementById(
      "configFields"
    );


  if (!fields) {
    return;
  }


  const shown = new Set();


  // ==================================================
  // 1. SSH
  // PALING ATAS
  // ==================================================

  const ssh = getSSH(config);


  if (ssh) {

    fields.appendChild(
      createField(
        "ssh",
        "🔐 SSH",
        ssh,
        true
      )
    );

    shown.add("host");
    shown.add("server");
    shown.add("sshHost");
    shown.add("ssh_server");

    shown.add("port");
    shown.add("sshPort");
    shown.add("ssh_port");

    shown.add("username");
    shown.add("user");
    shown.add("sshUsername");
    shown.add("ssh_username");

    shown.add("password");
    shown.add("pass");
    shown.add("sshPassword");
    shown.add("ssh_password");

  }


  // ==================================================
  // 2. PAYLOAD
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "payload",
      "requestPayload",
      "httpPayload",
      "customPayload",
      "payloadData"
    ],
    "📦 Payload",
    true
  );


  // ==================================================
  // 3. PROXY
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "proxy",
      "remoteProxy",
      "remote_proxy",
      "proxyHost",
      "proxyServer"
    ],
    "🔀 Proxy"
  );


  // ==================================================
  // 4. SNI
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "sni",
      "sniHost",
      "sni_host",
      "serverName",
      "server_name"
    ],
    "🎯 SNI"
  );


  // ==================================================
  // 5. PORT
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "port",
      "sshPort",
      "ssh_port",
      "serverPort",
      "server_port"
    ],
    "🔌 Port"
  );


  // ==================================================
  // 6. DNS
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "dns",
      "dnsProfile",
      "dns_profile",
      "dnsResolver",
      "dns_resolver"
    ],
    "🌐 DNS"
  );


  // ==================================================
  // 7. LOCAL PORT
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "localPort",
      "local_port",
      "localListenPort",
      "listenPort"
    ],
    "📍 Local Port"
  );


  // ==================================================
  // 8. DEFAULT ROUTE
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "defaultRoute",
      "default_route"
    ],
    "🛣️ Default Route"
  );


  // ==================================================
  // 9. TUNNEL
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "tunnel",
      "tunnelType",
      "tunnel_type",
      "mode",
      "connectionMode"
    ],
    "🚇 Tunnel"
  );


  // ==================================================
  // 10. LOCK
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "lockAllConfig",
      "lockModes",
      "lock_modes",
      "configLock",
      "config_lock"
    ],
    "🔒 Lock All Config"
  );


  // ==================================================
  // 11. EXPIRY
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "expiryTime",
      "expiry",
      "expiryTimestamp",
      "configExpiryTimestamp",
      "config_expiry_timestamp"
    ],
    "⏰ Expiry Time"
  );


  // ==================================================
  // 12. NOTE
  // ==================================================

  addOrderedField(
    config,
    fields,
    shown,
    [
      "note",
      "configMessage",
      "message",
      "remark",
      "description"
    ],
    "📝 Note"
  );


  // ==================================================
  // 13. FIELD LAINNYA
  // ==================================================

  Object.entries(config)
    .forEach(([key, value]) => {

      if (shown.has(key)) {
        return;
      }


      if (isInternalKey(key)) {
        return;
      }


      if (isEmptyValue(value)) {
        return;
      }


      fields.appendChild(
        createField(
          key,
          prettyName(key),
          value,
          false
        )
      );


      shown.add(key);

    });


  // ==================================================
  // NO RESULT
  // ==================================================

  if (!fields.children.length) {

    renderRawResult(data);

  }

}


// ==================================================
// ADD ORDERED FIELD
// ==================================================

function addOrderedField(
  config,
  parent,
  shown,
  keys,
  title,
  payload = false
) {

  let actualKey = null;


  for (const key of keys) {

    const found =
      findKey(
        config,
        key
      );

    if (found) {

      actualKey = found;

      break;

    }

  }


  if (!actualKey) {
    return;
  }


  if (shown.has(actualKey)) {
    return;
  }


  const value =
    config[actualKey];


  if (isEmptyValue(value)) {
    return;
  }


  parent.appendChild(
    createField(
      actualKey,
      title,
      value,
      payload
    )
  );


  shown.add(actualKey);

}


// ==================================================
// CREATE FIELD
// ==================================================

function createField(
  key,
  title,
  value,
  forcePayload = false
) {

  const item =
    document.createElement("div");


  item.className =
    "config-item";


  const formatted =
    formatValue(value);


  const isPayload =
    forcePayload ||
    String(key)
      .toLowerCase()
      .includes("payload");


  item.innerHTML = `

    <div class="config-header">

      <div class="config-name">
        ${escapeHTML(title)}
      </div>

      <button
        type="button"
        class="config-copy"
      >
        COPY
      </button>

    </div>

    <div
      class="config-value ${
        isPayload ? "payload" : ""
      }"
    >
      ${escapeHTML(formatted)}
    </div>

  `;


  const copyButton =
    item.querySelector(
      ".config-copy"
    );


  if (copyButton) {

    copyButton.addEventListener(
      "click",
      async () => {

        const success =
          await copyText(formatted);


        if (!success) {

          copyButton.textContent =
            "FAILED";

          setTimeout(() => {

            copyButton.textContent =
              "COPY";

          }, 1200);

          return;
        }


        copyButton.textContent =
          "COPIED";


        setTimeout(() => {

          copyButton.textContent =
            "COPY";

        }, 1200);

      }
    );

  }


  return item;

}


// ==================================================
// GET SSH
// ==================================================

function getSSH(config) {

  const host =
    getValue(
      config,
      [
        "host",
        "server",
        "sshHost",
        "ssh_server"
      ]
    );


  const port =
    getValue(
      config,
      [
        "port",
        "sshPort",
        "ssh_port",
        "serverPort"
      ]
    );


  const username =
    getValue(
      config,
      [
        "username",
        "user",
        "sshUsername",
        "ssh_username"
      ]
    );


  const password =
    getValue(
      config,
      [
        "password",
        "pass",
        "sshPassword",
        "ssh_password"
      ]
    );


  // ------------------------------------------------
  // Tidak ada SSH
  // ------------------------------------------------

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

    lines.push(
      `Host     : ${formatValue(host)}`
    );

  }


  if (!isEmptyValue(port)) {

    lines.push(
      `Port     : ${formatValue(port)}`
    );

  }


  if (!isEmptyValue(username)) {

    lines.push(
      `Username : ${formatValue(username)}`
    );

  }


  if (!isEmptyValue(password)) {

    lines.push(
      `Password : ${formatValue(password)}`
    );

  }


  return lines.join("\n");

}


// ==================================================
// GET VALUE
// ==================================================

function getValue(
  object,
  keys
) {

  if (
    !object ||
    typeof object !== "object"
  ) {

    return null;

  }


  for (const key of keys) {

    const actual =
      findKey(
        object,
        key
      );


    if (!actual) {
      continue;
    }


    const value =
      object[actual];


    if (
      !isEmptyValue(value)
    ) {

      return value;

    }

  }


  return null;

}


// ==================================================
// FIND KEY
// ==================================================

function findKey(
  object,
  wanted
) {

  if (
    !object ||
    typeof object !== "object"
  ) {

    return null;

  }


  const target =
    String(wanted)
      .toLowerCase();


  const found =
    Object.keys(object)
      .find(key =>
        key.toLowerCase() === target
      );


  return found || null;

}


// ==================================================
// INTERNAL FIELD
// ==================================================

function isInternalKey(key) {

  const k =
    String(key)
      .toLowerCase();


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

    "masterkey",

    "aeskey",

    "cryptokey",

    "ciphertext",

    "cipher",

    "nonce",

    "argon",

    "argon2",

    "salt",

    "aad",

    "tag",

    "rawjson",

    "rawconfig"

  ];


  return blocked.some(
    word =>
      k === word ||
      k.includes(word)
  );

}


// ==================================================
// EMPTY VALUE
// ==================================================

function isEmptyValue(value) {

  if (
    value === null ||
    value === undefined
  ) {

    return true;

  }


  if (
    typeof value === "string"
  ) {

    return value.trim() === "";

  }


  if (
    Array.isArray(value)
  ) {

    return value.length === 0;

  }


  return false;

}


// ==================================================
// FORMAT VALUE
// ==================================================

function formatValue(value) {

  if (
    typeof value === "string"
  ) {

    return value;

  }


  if (
    typeof value === "boolean"
  ) {

    return value
      ? "true"
      : "false";

  }


  if (
    typeof value === "number" ||
    typeof value === "bigint"
  ) {

    return String(value);

  }


  if (
    Array.isArray(value)
  ) {

    return value
      .map(item =>
        typeof item === "object"
          ? JSON.stringify(
              item,
              null,
              2
            )
          : String(item)
      )
      .join("\n");

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


// ==================================================
// PRETTY NAME
// ==================================================

function prettyName(key) {

  return String(key)

    .replace(
      /([a-z])([A-Z])/g,
      "$1 $2"
    )

    .replace(
      /[_-]+/g,
      " "
    )

    .replace(
      /\b\w/g,
      char =>
        char.toUpperCase()
    );

}


// ==================================================
// RAW RESULT
// ==================================================

function renderRawResult(value) {

  const text =
    formatValue(value);


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
            id="copyRawResult"
          >
            COPY
          </button>

        </div>

        <div class="config-value payload">
          ${escapeHTML(text)}
        </div>

      </div>

    </div>

  `;


  const copy =
    document.getElementById(
      "copyRawResult"
    );


  if (copy) {

    copy.addEventListener(
      "click",
      async () => {

        const success =
          await copyText(text);


        if (success) {

          copy.textContent =
            "COPIED";


          setTimeout(() => {

            copy.textContent =
              "COPY";

          }, 1200);

        }

      }
    );

  }

}


// ==================================================
// ESCAPE HTML
// ==================================================

function escapeHTML(value) {

  return String(value)

    .replace(
      /&/g,
      "&amp;"
    )

    .replace(
      /</g,
      "&lt;"
    )

    .replace(
      />/g,
      "&gt;"
    )

    .replace(
      /"/g,
      "&quot;"
    )

    .replace(
      /'/g,
      "&#039;"
    );

}


// ==================================================
// COPY TEXT
// ==================================================

async function copyText(text) {

  const value =
    String(text);


  // ------------------------------------------------
  // MODERN CLIPBOARD
  // ------------------------------------------------

  try {

    if (
      navigator.clipboard &&
      window.isSecureContext
    ) {

      await navigator.clipboard.writeText(
        value
      );

      return true;

    }

  } catch (error) {

    console.warn(
      "Clipboard API gagal:",
      error
    );

  }


  // ------------------------------------------------
  // FALLBACK
  // ------------------------------------------------

  try {

    const textarea =
      document.createElement(
        "textarea"
      );


    textarea.value =
      value;


    textarea.style.position =
      "fixed";

    textarea.style.left =
      "-9999px";

    textarea.style.top =
      "0";

    textarea.style.opacity =
      "0";


    document.body.appendChild(
      textarea
    );


    textarea.focus();

    textarea.select();


    const success =
      document.execCommand(
        "copy"
      );


    textarea.remove();


    return success;

  } catch (error) {

    console.error(
      "Copy gagal:",
      error
    );

    return false;

  }

}


// ==================================================
// STATUS
// ==================================================

function showStatus(
  message,
  type = ""
) {

  if (!statusEl) {
    return;
  }


  statusEl.className =
    `status ${type}`;


  statusEl.textContent =
    message;

}


// ==================================================
// SUCCESS SOUND
// SATU KALI TING
// ==================================================

function successSound() {

  try {

    const AudioContext =
      window.AudioContext ||
      window.webkitAudioContext;


    if (!AudioContext) {
      return;
    }


    const audio =
      new AudioContext();


    const oscillator =
      audio.createOscillator();


    const gain =
      audio.createGain();


    oscillator.type =
      "sine";


    oscillator.frequency.setValueAtTime(
      900,
      audio.currentTime
    );


    gain.gain.setValueAtTime(
      0.001,
      audio.currentTime
    );


    gain.gain.exponentialRampToValueAtTime(
      0.18,
      audio.currentTime + 0.02
    );


    gain.gain.exponentialRampToValueAtTime(
      0.001,
      audio.currentTime + 0.25
    );


    oscillator.connect(
      gain
    );


    gain.connect(
      audio.destination
    );


    oscillator.start();


    oscillator.stop(
      audio.currentTime + 0.25
    );


    setTimeout(() => {

      audio.close()
        .catch(() => {});

    }, 500);


  } catch (error) {

    console.warn(
      "Success sound tidak tersedia:",
      error
    );

  }

}


// ==================================================
// INITIAL STATE
// ==================================================

if (decryptBtn) {

  decryptBtn.disabled = true;

}


console.log(
  "DINSTORE HC Decryptor loaded"
);
