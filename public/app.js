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

if (!file.name.toLowerCase().endsWith(".hc")) {

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

fileName.textContent =
"📄 " + file.name;

fileName.style.display = "block";

decryptBtn.disabled = false;

showStatus(
"✅ File siap dibongkar",
"success"
);
}

/* ========================================
DECRYPT BUTTON
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

} catch (e) {

  console.error(
    "Response server:",
    text
  );

  throw new Error(
    text ||
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

const config =
data.config || data.result || data;

const title =
document.createElement("div");

title.className =
"result-title";

title.textContent =
"📋 HASIL CONFIG";

resultBox.appendChild(title);

/* ======================================
SSH
====================================== */

let sshText = "";

if (
config.sshField &&
typeof config.sshField === "object"
) {

const ssh =
  config.sshField;

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
  host ||
  port ||
  username ||
  password
) {

  sshText =
    `${host}:${port}@${username}:${password}`;
}

} else if (
typeof config.sshField === "string"
) {

sshText =
  config.sshField;

} else if (
typeof config.ssh === "string"
) {

sshText =
  config.ssh;

} else if (
config.ssh &&
typeof config.ssh === "object"
) {

const ssh =
  config.ssh;

sshText =
  `${ssh.host || ssh.hostname || ""}:` +
  `${ssh.port || ""}@` +
  `${ssh.username || ssh.user || ""}:` +
  `${ssh.password || ssh.pass || ""}`;

}

if (sshText) {

const sshBox =
  createField(
    "ssh",
    "🔑 SSH",
    sshText,
    true
  );

resultBox.appendChild(sshBox);

}

/* ======================================
CONFIG FIELDS
====================================== */

const skipKeys = [
"ssh",
"sshField"
];

let fieldCount = 0;

Object.keys(config).forEach((key) => {

if (skipKeys.includes(key)) {
  return;
}

const value =
  config[key];

/*
  Jangan tampilkan field kosong
  supaya hasil lebih bersih.
*/

if (
  value === null ||
  value === undefined ||
  value === ""
) {
  return;
}

fieldCount++;

const field =
  createField(
    key,
    prettyName(key),
    formatValue(value),
    false
  );

resultBox.appendChild(field);

});

/* ======================================
PROTECTION
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

  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return;
  }

  const field =
    createField(
      key,
      prettyName(key),
      formatValue(value),
      false
    );

  resultBox.appendChild(field);
});

}

/* ======================================
EMPTY
====================================== */

if (
!sshText &&
fieldCount === 0 &&
!data.protections
) {

const empty =
  document.createElement("div");

empty.className =
  "empty";

empty.textContent =
  "⚠️ Tidak ada data yang berhasil ditemukan.";

resultBox.appendChild(empty);

}
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
isSSH
? "ssh-box"
: "field";

const header =
document.createElement("div");

header.className =
isSSH
? "ssh-header"
: "field-header";

const fieldTitle =
document.createElement("div");

fieldTitle.className =
isSSH
? "ssh-title"
: "field-title";

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

const valueBox =
document.createElement("div");

valueBox.className =
isSSH
? "ssh-value"
: "field-value";

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
COPY
======================================== */

async function copyText(
text,
button
) {

try {

if (
  navigator.clipboard &&
  window.isSecureContext
) {

  await navigator.clipboard.writeText(
    text
  );

} else {

  const textarea =
    document.createElement(
      "textarea"
    );

  textarea.value =
    text;

  textarea.style.position =
    "fixed";

  textarea.style.left =
    "-9999px";

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

blockedByRoot:
  "🔒 BLOCKED BY ROOT",

blockedByHwid:
  "🔒 BLOCKED BY HWID",

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
  "🛡️ PSIPHON 2"

};

return (
names[key] ||
key
.replace(
/([A-Z])/g,
" $1"
)
.replace(
/^./,
(char) =>
char.toUpperCase()
)
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
