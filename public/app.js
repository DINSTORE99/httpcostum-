const uploadBox = document.getElementById("uploadBox");
const fileInput = document.getElementById("fileInput");
const fileName = document.getElementById("fileName");
const decryptBtn = document.getElementById("decryptBtn");
const statusBox = document.getElementById("status");
const resultBox = document.getElementById("result");

let selectedFile = null;

/* ========================================
   FILE SELECT
======================================== */

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];

  if (!file) return;

  setFile(file);
});


/* ========================================
   DRAG & DROP
======================================== */

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


/* ========================================
   SET FILE
======================================== */

function setFile(file) {

  const name = file.name.toLowerCase();

  if (!name.endsWith(".hc")) {

    selectedFile = null;

    decryptBtn.disabled = true;

    fileName.textContent = "";
    fileName.style.display = "none";

    showStatus(
      "❌ Hanya file .HC yang diperbolehkan",
      "error"
    );

    return;
  }

  selectedFile = file;

  fileName.textContent = "📄 " + file.name;
  fileName.style.display = "block";

  decryptBtn.disabled = false;

  showStatus(
    "✅ File siap dibongkar",
    "success"
  );
}


/* ========================================
   DECRYPT
======================================== */

decryptBtn.addEventListener("click", async () => {

  if (!selectedFile) {

    showStatus(
      "❌ Pilih file HC terlebih dahulu",
      "error"
    );

    return;
  }

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

      console.error(
        "Response server:",
        text
      );

      throw new Error(
        "Server tidak mengembalikan JSON"
      );
    }

    if (!response.ok || !data.success) {

      throw new Error(
        data.error ||
        "Gagal membongkar config"
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


/* ========================================
   RENDER RESULT
======================================== */

function renderResult(data) {

  resultBox.innerHTML = "";

  /*
   * API biasanya mengirim:
   *
   * data.result = JSON STRING
   *
   * Contoh:
   * data.result = '{"ssh":"...","payload":"..."}'
   *
   * Jadi harus JSON.parse().
   */

  let config = data.result || data.config || data;

  if (typeof config === "string") {

    try {

      config = JSON.parse(config);

    } catch {

      /*
       * Kalau bukan JSON,
       * tampilkan sebagai raw result.
       */

      renderRawResult(config);

      return;
    }
  }

  if (
    !config ||
    typeof config !== "object"
  ) {

    renderRawResult(
      String(config || "")
    );

    return;
  }


  /* ======================================
     TITLE
  ====================================== */

  const title =
    document.createElement("h2");

  title.className =
    "result-title";

  title.textContent =
    "📋 HASIL CONFIG";

  resultBox.appendChild(title);


  let count = 0;


  /* ======================================
     SSH
  ====================================== */

  const sshText =
    getSSH(config);

  if (sshText) {

    resultBox.appendChild(
      createField(
        "ssh",
        "🔑 SSH",
        sshText,
        true
      )
    );

    count++;
  }


  /* ======================================
     FIELD PRIORITAS
  ====================================== */

  const priorityKeys = [

    "payload",

    "proxy",

    "sni",

    "expiryTime",

    "lockAllConfig",

    "notes",

    "note",

    "ovpnUserAndPass",

    "ovpnConfig",

    "unlockUserAndPass",

    "unlockUserAndPass2",

    "name",

    "protection",

    "version",

    "connectionMode",

    "dnsResolver",

    "slowdnsServer",

    "slowdnsPublickey",

    "v2rayConfig",

    "cloudconfig",

    "psiphon",

    "blockArea",

    "blockedByHwid",

    "blockedByPassword",

    "blockedByRoot",

    "mobileDataAndLockProvider",

    "extraSniffer",

    "slowdnsEnabled",

    "v2rayEnabled",

    "psiphon2"

  ];


  const rendered =
    new Set([
      "ssh",
      "sshField"
    ]);


  /* ======================================
     RENDER PRIORITAS
  ====================================== */

  for (
    const key of priorityKeys
  ) {

    if (!(key in config)) {
      continue;
    }

    if (rendered.has(key)) {
      continue;
    }

    const value =
      config[key];

    if (isEmptyValue(value)) {
      continue;
    }

    resultBox.appendChild(
      createField(
        key,
        prettyName(key),
        formatValue(value)
      )
    );

    rendered.add(key);

    count++;
  }


  /* ======================================
     RENDER FIELD LAINNYA
  ====================================== */

  Object.keys(config).forEach((key) => {

    if (rendered.has(key)) {
      return;
    }

    const value =
      config[key];

    if (isEmptyValue(value)) {
      return;
    }

    /*
     * Jangan tampilkan field internal
     * yang biasanya tidak berguna untuk user.
     */

    if (
      key === "configData" ||
      key === "configSalt" ||
      key === "configAesKey" ||
      key === "configIdentifier" ||
      key === "lockModesHash" ||
      key === "configHwid" ||
      key === "configTimestamp" ||
      key === "configExpiryTimestamp"
    ) {

      return;
    }

    resultBox.appendChild(
      createField(
        key,
        prettyName(key),
        formatValue(value)
      )
    );

    rendered.add(key);

    count++;
  });


  /* ======================================
     PROTECTIONS
  ====================================== */

  if (
    data.protections &&
    typeof data.protections === "object"
  ) {

    const protectionTitle =
      document.createElement("div");

    protectionTitle.className =
      "protection-title";

    protectionTitle.textContent =
      "🛡️ PROTECTION";

    resultBox.appendChild(
      protectionTitle
    );

    Object.keys(
      data.protections
    ).forEach((key) => {

      const value =
        data.protections[key];

      if (isEmptyValue(value)) {
        return;
      }

      resultBox.appendChild(
        createField(
          key,
          prettyName(key),
          formatValue(value)
        )
      );

      count++;
    });
  }


  /* ======================================
     EMPTY
  ====================================== */

  if (count === 0) {

    const empty =
      document.createElement("div");

    empty.className =
      "empty";

    empty.textContent =
      "⚠️ Tidak ada data config yang ditemukan.";

    resultBox.appendChild(
      empty
    );
  }


  /* ======================================
     SCROLL
  ====================================== */

  setTimeout(() => {

    resultBox.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });

  }, 100);
}


/* ========================================
   GET SSH
======================================== */

function getSSH(config) {

  let ssh =
    config.sshField ||
    config.ssh;

  if (!ssh) {
    return "";
  }


  /* STRING */

  if (
    typeof ssh === "string"
  ) {

    return ssh.trim();
  }


  /* OBJECT */

  if (
    typeof ssh === "object"
  ) {

    const host =
      ssh.host ||
      ssh.hostname ||
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
      !host &&
      !port &&
      !username &&
      !password
    ) {

      return "";
    }

    return (
      `${host}:${port}` +
      `@${username}:${password}`
    );
  }

  return "";
}


/* ========================================
   CREATE FIELD
======================================== */

function createField(
  key,
  title,
  value,
  isSSH = false
) {

  const box =
    document.createElement("div");

  box.className =
    "config-item";

  if (isSSH) {
    box.classList.add("ssh-item");
  }


  /* HEADER */

  const header =
    document.createElement("div");

  header.className =
    "config-header";


  /* TITLE */

  const fieldTitle =
    document.createElement("div");

  fieldTitle.className =
    "config-name";

  fieldTitle.textContent =
    title;


  /* COPY */

  const copyBtn =
    document.createElement("button");

  copyBtn.type =
    "button";

  copyBtn.className =
    "config-copy";

  copyBtn.textContent =
    "COPY";

  copyBtn.addEventListener(
    "click",
    async () => {

      await copyText(
        value,
        copyBtn
      );

    }
  );


  header.appendChild(
    fieldTitle
  );

  header.appendChild(
    copyBtn
  );


  /* VALUE */

  const valueBox =
    document.createElement("div");

  valueBox.className =
    "config-value";

  if (
    key === "payload" ||
    key === "v2rayConfig" ||
    key === "ovpnConfig"
  ) {

    valueBox.classList.add(
      "payload"
    );
  }

  valueBox.textContent =
    value;


  box.appendChild(
    header
  );

  box.appendChild(
    valueBox
  );

  return box;
}


/* ========================================
   RAW RESULT
======================================== */

function renderRawResult(value) {

  resultBox.innerHTML = "";

  const title =
    document.createElement("h2");

  title.className =
    "result-title";

  title.textContent =
    "📋 HASIL CONFIG";

  resultBox.appendChild(
    title
  );


  const box =
    document.createElement("div");

  box.className =
    "config-item";


  const header =
    document.createElement("div");

  header.className =
    "config-header";


  const name =
    document.createElement("div");

  name.className =
    "config-name";

  name.textContent =
    "📄 RESULT";


  const copy =
    document.createElement("button");

  copy.className =
    "config-copy";

  copy.type =
    "button";

  copy.textContent =
    "COPY";

  copy.onclick = () =>
    copyText(
      value,
      copy
    );


  header.appendChild(name);
  header.appendChild(copy);


  const content =
    document.createElement("div");

  content.className =
    "config-value payload";

  content.textContent =
    value;


  box.appendChild(header);
  box.appendChild(content);

  resultBox.appendChild(box);
}


/* ========================================
   EMPTY CHECK
======================================== */

function isEmptyValue(value) {

  if (
    value === null ||
    value === undefined
  ) {
    return true;
  }

  if (
    typeof value === "string" &&
    value.trim() === ""
  ) {
    return true;
  }

  return false;
}


/* ========================================
   COPY
======================================== */

async function copyText(
  text,
  button
) {

  try {

    const value =
      String(text);


    if (
      navigator.clipboard &&
      window.isSecureContext
    ) {

      await navigator.clipboard.writeText(
        value
      );

    } else {

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

      document.body.appendChild(
        textarea
      );

      textarea.focus();
      textarea.select();

      document.execCommand(
        "copy"
      );

      textarea.remove();
    }


    const oldText =
      button.textContent;

    button.textContent =
      "COPIED ✓";

    button.classList.add(
      "copied"
    );


    setTimeout(() => {

      button.textContent =
        oldText;

      button.classList.remove(
        "copied"
      );

    }, 1500);

  } catch (error) {

    console.error(
      "Copy error:",
      error
    );

    button.textContent =
      "FAILED";

    setTimeout(() => {

      button.textContent =
        "COPY";

    }, 1500);
  }
}


/* ========================================
   PRETTY NAME
======================================== */

function prettyName(key) {

  const names = {

    payload:
      "📡 PAYLOAD",

    proxy:
      "🌐 PROXY",

    sni:
      "🔗 SNI",

    notes:
      "📝 NOTES",

    note:
      "📝 NOTE",

    ovpnConfig:
      "📄 OVPN CONFIG",

    ovpnUserAndPass:
      "🔐 OVPN USER & PASSWORD",

    unlockUserAndPass:
      "🔓 UNLOCK USER & PASSWORD",

    unlockUserAndPass2:
      "🔓 UNLOCK USER & PASSWORD 2",

    name:
      "🏷️ NAME",

    expiryTime:
      "⏰ EXPIRY TIME",

    version:
      "📦 VERSION",

    connectionMode:
      "🔌 CONNECTION MODE",

    dnsResolver:
      "🌍 DNS RESOLVER",

    slowdnsServer:
      "🐌 SLOWDNS SERVER",

    slowdnsPublickey:
      "🔑 SLOWDNS PUBLIC KEY",

    v2rayConfig:
      "🚀 V2RAY CONFIG",

    cloudconfig:
      "☁️ CLOUD CONFIG",

    psiphon:
      "🛡️ PSIPHON",

    blockArea:
      "📍 BLOCK AREA",

    blockedByHwid:
      "🔒 BLOCKED BY HWID",

    blockedByPassword:
      "🔒 BLOCKED BY PASSWORD",

    blockedByRoot:
      "🔒 BLOCKED BY ROOT",

    lockAllConfig:
      "🔒 LOCK ALL CONFIG",

    mobileDataAndLockProvider:
      "📱 MOBILE DATA & LOCK PROVIDER",

    unknown14:
      "❓ UNKNOWN 14",

    unknown22:
      "❓ UNKNOWN 22",

    extraSniffer:
      "🔍 EXTRA SNIFFER",

    slowdnsEnabled:
      "🐌 SLOWDNS ENABLED",

    v2rayEnabled:
      "🚀 V2RAY ENABLED",

    psiphon2:
      "🛡️ PSIPHON 2",

    protection:
      "🛡️ PROTECTION"

  };


  if (names[key]) {
    return names[key];
  }


  return key
    .replace(
      /([A-Z])/g,
      " $1"
    )
    .replace(
      /^./,
      (char) =>
        char.toUpperCase()
    );
}


/* ========================================
   FORMAT VALUE
======================================== */

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


/* ========================================
   STATUS
======================================== */

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
