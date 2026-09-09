const crypto = require("crypto");
const HC = require("../config/hc.keys");

// ============================================================
// BASIC HELPERS
// ============================================================

function hcCleanHex(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  let clean = String(value)
    .replace(/[^0-9a-f]/gi, "");

  if (!clean) {
    return "";
  }

  if (clean.length % 2 !== 0) {
    clean = "0" + clean;
  }

  return clean;
}

function hcIsHex(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return false;
  }

  const s = String(value);

  return (
    s.length >= 16 &&
    s.length % 2 === 0 &&
    /^[0-9a-f]+$/i.test(s)
  );
}

// ============================================================
// PRINTABLE
// ============================================================

function hcPrintable(value, strict = false) {
  if (
    value === null ||
    value === undefined
  ) {
    return false;
  }

  const s = String(value);

  if (!s.length) {
    return false;
  }

  if (s.length < 4) {
    return true;
  }

  let printable = 0;

  for (const ch of s) {
    const code = ch.charCodeAt(0);

    if (
      (code >= 32 && code <= 126) ||
      code === 9 ||
      code === 10 ||
      code === 13
    ) {
      printable++;
    }
  }

  return (
    printable / s.length >
    (strict ? 0.90 : 0.80)
  );
}

// ============================================================
// CHACHA20
// ============================================================

function hcRotl32(x, n) {
  return (
    (x << n) |
    (x >>> (32 - n))
  ) >>> 0;
}

function hcQR(s, a, b, c, d) {
  s[a] =
    (s[a] + s[b]) >>> 0;

  s[d] ^= s[a];
  s[d] =
    hcRotl32(s[d], 16);

  s[c] =
    (s[c] + s[d]) >>> 0;

  s[b] ^= s[c];
  s[b] =
    hcRotl32(s[b], 12);

  s[a] =
    (s[a] + s[b]) >>> 0;

  s[d] ^= s[a];
  s[d] =
    hcRotl32(s[d], 8);

  s[c] =
    (s[c] + s[d]) >>> 0;

  s[b] ^= s[c];
  s[b] =
    hcRotl32(s[b], 7);
}

function hcChaCha20(
  data,
  key,
  nonce,
  counter = 0
) {
  if (!Buffer.isBuffer(data)) {
    data = Buffer.from(data || "");
  }

  if (!Buffer.isBuffer(key)) {
    key = Buffer.from(key || "");
  }

  if (!Buffer.isBuffer(nonce)) {
    nonce = Buffer.from(nonce || "");
  }

  if (key.length !== 32) {
    throw new Error(
      "ChaCha20 key harus 32 byte"
    );
  }

  if (nonce.length !== 8) {
    throw new Error(
      "ChaCha20 nonce harus 8 byte"
    );
  }

  const out =
    Buffer.alloc(data.length);

  for (
    let offset = 0,
      block = counter >>> 0;

    offset < data.length;

    offset += 64,
      block++
  ) {
    const state =
      new Uint32Array(16);

    // "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (let i = 0; i < 8; i++) {
      state[4 + i] =
        key.readUInt32LE(i * 4);
    }

    state[12] =
      block >>> 0;

    state[13] = 0;

    state[14] =
      nonce.readUInt32LE(0);

    state[15] =
      nonce.readUInt32LE(4);

    const working =
      new Uint32Array(state);

    // 20 rounds
    for (let i = 0; i < 10; i++) {
      // Column
      hcQR(
        working,
        0,
        4,
        8,
        12
      );

      hcQR(
        working,
        1,
        5,
        9,
        13
      );

      hcQR(
        working,
        2,
        6,
        10,
        14
      );

      hcQR(
        working,
        3,
        7,
        11,
        15
      );

      // Diagonal
      hcQR(
        working,
        0,
        5,
        10,
        15
      );

      hcQR(
        working,
        1,
        6,
        11,
        12
      );

      hcQR(
        working,
        2,
        7,
        8,
        13
      );

      hcQR(
        working,
        3,
        4,
        9,
        14
      );
    }

    const stream =
      Buffer.alloc(64);

    for (let i = 0; i < 16; i++) {
      stream.writeUInt32LE(
        (
          working[i] +
          state[i]
        ) >>> 0,
        i * 4
      );
    }

    const length =
      Math.min(
        64,
        data.length - offset
      );

    for (let i = 0; i < length; i++) {
      out[offset + i] =
        data[offset + i] ^
        stream[i];
    }
  }

  return out;
}

// ============================================================
// ABC
// ============================================================

function hcABC(
  raw,
  key,
  nonce = HC.nonce
) {
  try {
    if (!raw) {
      return "";
    }

    const hex =
      hcCleanHex(raw);

    if (!hex) {
      return "";
    }

    if (hex.length % 2 !== 0) {
      return "";
    }

    const data =
      Buffer.from(hex, "hex");

    // 16 byte trailing data
    if (data.length <= 16) {
      return "";
    }

    const ciphertext =
      data.subarray(0, -16);

    const decrypted =
      hcChaCha20(
        ciphertext,
        key,
        nonce,
        1
      );

    return decrypted.toString(
      "utf8"
    );

  } catch {
    return "";
  }
}

// ============================================================
// Z3A
// ============================================================

function hcZ3A(
  data,
  iv
) {
  if (
    data === null ||
    data === undefined
  ) {
    return "";
  }

  const source =
    String(data);

  const out = [];

  const regex =
    /(-?\d+)\.(-?\d+)/g;

  let match;

  const ivNumber =
    Number(iv);

  if (!Number.isFinite(ivNumber)) {
    return "";
  }

  while (
    (match = regex.exec(source))
  ) {
    try {
      const a =
        Number(match[1]) -
        ivNumber;

      const b =
        Number(match[2]) -
        ivNumber;

      if (
        !Number.isFinite(a) ||
        !Number.isFinite(b)
      ) {
        continue;
      }

      const divisor =
        2 ** b;

      if (
        divisor === 0 ||
        !Number.isFinite(divisor)
      ) {
        continue;
      }

      const value =
        Math.floor(
          a / divisor
        );

      out.push(
        (
          (value % 256) +
          256
        ) % 256
      );

    } catch {
      // ignore invalid pair
    }
  }

  if (!out.length) {
    return "";
  }

  return Buffer.from(out)
    .toString("utf8");
}

// ============================================================
// BRAILLE
// ============================================================

function hcBraille(value) {
  try {
    if (!value) {
      return value;
    }

    const source =
      String(value);

    const alphabet =
      String(HC.braille || "");

    if (!alphabet.length) {
      return value;
    }

    const out = [];

    for (
      let i = 0;
      i + 1 < source.length;
      i += 2
    ) {
      const a =
        alphabet.indexOf(
          source[i]
        );

      const b =
        alphabet.indexOf(
          source[i + 1]
        );

      if (
        a < 0 ||
        b < 0
      ) {
        return value;
      }

      out.push(
        (a * 16 + b) & 255
      );
    }

    return Buffer.from(out)
      .toString("utf8");

  } catch {
    return value;
  }
}

// ============================================================
// CREDENTIALS
// ============================================================

function hcCredentials(
  raw,
  isSSH = false
) {
  if (
    raw === null ||
    raw === undefined ||
    raw === ""
  ) {
    return raw;
  }

  let source =
    String(raw);

  // SSH braille
  if (
    isSSH &&
    source.length &&
    HC.braille &&
    HC.braille.includes(
      source[0]
    )
  ) {
    const decoded =
      hcBraille(source);

    if (decoded) {
      source = decoded;
    }
  }

  if (isSSH) {
    /*
     * host:port@username:password
     */
    const match =
      source.match(
        /^([^:@]+):(\d+)@(.+):(.+)$/
      );

    if (!match) {
      return source;
    }

    const host =
      match[1];

    const port =
      match[2];

    const username =
      match[3];

    const password =
      match[4];

    const usernameIv =
      (
        username.match(
          /-?\d+\.-?\d+/g
        ) || []
      ).length;

    const passwordIv =
      (
        password.match(
          /-?\d+\.-?\d+/g
        ) || []
      ).length;

    const decodedUser =
      hcZ3A(
        username,
        usernameIv
      ) || username;

    const decodedPass =
      hcZ3A(
        password,
        passwordIv
      ) || password;

    return (
      `${host}:${port}` +
      `@${decodedUser}` +
      `:${decodedPass}`
    );
  }

  // Normal username:password
  const match =
    source.match(
      /^([^:]+):(.+)$/
    );

  if (!match) {
    return source;
  }

  const username =
    match[1];

  const password =
    match[2];

  const usernameIv =
    (
      username.match(
        /-?\d+\.-?\d+/g
      ) || []
    ).length;

  const passwordIv =
    (
      password.match(
        /-?\d+\.-?\d+/g
      ) || []
    ).length;

  const decodedUser =
    hcZ3A(
      username,
      usernameIv
    ) || username;

  const decodedPass =
    hcZ3A(
      password,
      passwordIv
    ) || password;

  return (
    `${decodedUser}:${decodedPass}`
  );
}

// ============================================================
// BASE64
// ============================================================

function hcB64Decode(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return Buffer.alloc(0);
  }

  let source =
    String(value)
      .trim()
      .replace(/\s+/g, "");

  if (!source) {
    return Buffer.alloc(0);
  }

  const remainder =
    source.length % 4;

  if (remainder) {
    source +=
      "=".repeat(
        4 - remainder
      );
  }

  try {
    return Buffer.from(
      source,
      "base64"
    );
  } catch {
    return Buffer.alloc(0);
  }
}

// ============================================================
// JKL
// ============================================================

function hcJKL(
  input,
  isNew = false
) {
  if (
    input === null ||
    input === undefined ||
    input === ""
  ) {
    return input;
  }

  try {
    const key =
      isNew
        ? HC.jklNew
        : HC.jklOld;

    if (
      !key ||
      key.length < 20
    ) {
      return input;
    }

    const data =
      hcB64Decode(input);

    if (!data.length) {
      return input;
    }

    for (
      let i = 0;
      i < data.length;
      i++
    ) {
      const d =
        data[i];

      const k =
        key[i % 20];

      const left =
        (
          ((d ^ 0xff) & 0xca) |
          (d & 0x35)
        );

      const right =
        (
          ((k ^ 0xff) & 0xca) |
          (k & 0x35)
        );

      data[i] =
        (left ^ right) & 0xff;
    }

    const decoded =
      hcB64Decode(
        data.toString("utf8")
      );

    if (!decoded.length) {
      return input;
    }

    const result =
      decoded.toString("utf8");

    return result || input;

  } catch {
    return input;
  }
}

// ============================================================
// RST
// ============================================================

function hcRST(input) {
  try {
    if (!input) {
      return null;
    }

    const xorKey =
      HC.rstXor;

    if (
      !xorKey ||
      !xorKey.length
    ) {
      return null;
    }

    const source =
      Buffer.from(
        String(input),
        "utf8"
      );

    const x =
      Buffer.alloc(
        source.length
      );

    for (
      let i = 0;
      i < source.length;
      i++
    ) {
      x[i] =
        source[i] ^
        xorKey[
          i % xorKey.length
        ];
    }

    const encrypted =
      Buffer.from(
        x.toString("utf8"),
        "base64"
      );

    if (!encrypted.length) {
      return null;
    }

    const keys =
      Array.isArray(HC.rstKeys)
        ? HC.rstKeys
        : [];

    for (
      const key of keys
    ) {
      try {
        const keyBuffer =
          Buffer.isBuffer(key)
            ? key
            : Buffer.from(
                String(key),
                "utf8"
              );

        if (
          keyBuffer.length !== 16
        ) {
          continue;
        }

        const decipher =
          crypto.createDecipheriv(
            "aes-128-ecb",
            keyBuffer,
            null
          );

        decipher.setAutoPadding(
          true
        );

        const decrypted =
          Buffer.concat([
            decipher.update(
              encrypted
            ),
            decipher.final()
          ]);

        const result =
          decrypted.toString(
            "utf8"
          );

        if (
          result.includes(
            "[splitConfig]"
          )
        ) {
          return result;
        }

      } catch {
        // Try next key
      }
    }

  } catch {
    // ignore
  }

  return null;
}

// ============================================================
// FIELD DECRYPT
// ============================================================

function hcDecryptField(
  token,
  nonce
) {
  if (
    token === null ||
    token === undefined
  ) {
    return token;
  }

  const source =
    String(token);

  if (
    !source ||
    [
      "true",
      "false",
      "lifeTime",
      "[splitPsiphon][splitPsiphon]"
    ].includes(source) ||
    source.startsWith("<")
  ) {
    return token;
  }

  const candidates = [];

  // ----------------------------------------------------------
  // HEX
  // ----------------------------------------------------------

  const clean =
    hcCleanHex(source);

  if (
    hcIsHex(clean) &&
    clean.length >= 32
  ) {
    try {
      candidates.push(
        Buffer.from(
          clean,
          "hex"
        )
      );
    } catch {}
  }

  // ----------------------------------------------------------
  // LATIN1
  // ----------------------------------------------------------

  if (source.length > 16) {
    try {
      candidates.push(
        Buffer.from(
          source,
          "latin1"
        )
      );
    } catch {}
  }

  // ----------------------------------------------------------
  // UTF8
  // ----------------------------------------------------------

  if (source.length > 16) {
    try {
      candidates.push(
        Buffer.from(
          source,
          "utf8"
        )
      );
    } catch {}
  }

  const seen =
    new Set();

  for (
    const data of candidates
  ) {
    if (
      !Buffer.isBuffer(data) ||
      data.length <= 16
    ) {
      continue;
    }

    const identity =
      data.toString("hex");

    if (
      seen.has(identity)
    ) {
      continue;
    }

    seen.add(identity);

    const ciphertext =
      data.subarray(0, -16);

    for (
      const key of HC.keys || []
    ) {
      try {
        if (
          !Buffer.isBuffer(key) ||
          key.length !== 32
        ) {
          continue;
        }

        const decrypted =
          hcChaCha20(
            ciphertext,
            key,
            nonce,
            1
          );

        const text =
          decrypted.toString(
            "utf8"
          );

        if (!text) {
          continue;
        }

        // JKL new
        const newResult =
          hcJKL(
            text,
            true
          );

        if (
          newResult !== text &&
          hcPrintable(newResult)
        ) {
          return newResult;
        }

        // JKL old
        const oldResult =
          hcJKL(
            text,
            false
          );

        if (
          oldResult !== text &&
          hcPrintable(oldResult)
        ) {
          return oldResult;
        }

        // Plain decrypted result
        if (
          hcPrintable(
            text,
            true
          ) &&
          (
            text.includes("HTTP") ||
            text.includes("@") ||
            text.includes(":") ||
            text.includes("{")
          )
        ) {
          return text;
        }

      } catch {
        // Try next candidate/key
      }
    }
  }

  // ----------------------------------------------------------
  // DIRECT JKL FALLBACK
  // ----------------------------------------------------------

  for (
    const isNew of [
      true,
      false
    ]
  ) {
    try {
      const result =
        hcJKL(
          source,
          isNew
        );

      if (
        result !== source &&
        hcPrintable(result)
      ) {
        return result;
      }

    } catch {}
  }

  return token;
}

// ============================================================
// INITIAL XOR
// ============================================================

function hcInitial(
  fileBytes
) {
  if (
    !Buffer.isBuffer(fileBytes)
  ) {
    fileBytes =
      Buffer.from(
        fileBytes || ""
      );
  }

  const xorKey =
    HC.initialXor;

  if (
    !xorKey ||
    !xorKey.length
  ) {
    throw new Error(
      "HC initialXor tidak tersedia"
    );
  }

  /*
   * File HC dibaca sebagai byte.
   * Jangan mengubahnya menjadi UTF-8
   * sebelum XOR karena byte > 0x7f
   * bisa berubah.
   */

  const out =
    Buffer.alloc(
      fileBytes.length
    );

  for (
    let i = 0;
    i < fileBytes.length;
    i++
  ) {
    out[i] =
      fileBytes[i] ^
      xorKey[
        i % xorKey.length
      ];
  }

  return out;
}

// ============================================================
// SAFE JSON
// ============================================================

function hcTryJson(value) {
  if (
    typeof value !== "string"
  ) {
    return value;
  }

  const text =
    value.trim();

  if (
    !text.startsWith("{") &&
    !text.startsWith("[")
  ) {
    return value;
  }

  try {
    return JSON.parse(text);
  } catch {
    return value;
  }
}

// ============================================================
// MAIN HC PARSER
// ============================================================

function hcParseModern(
  buffer
) {
  try {
    if (
      !Buffer.isBuffer(buffer) ||
      !buffer.length
    ) {
      return {
        success: false,
        error: "File HC kosong"
      };
    }

    // ========================================================
    // 1. INITIAL
    // ========================================================

    const initial =
      hcInitial(buffer);

    // ========================================================
    // 2. OUTER ABC
    // ========================================================

    let outer = "";

    // Coba key yang sama dengan
    // implementasi sebelumnya.
    if (
      HC.keys &&
      HC.keys[5]
    ) {
      outer =
        hcABC(
          initial.toString("utf8"),
          HC.keys[5]
        );
    }

    if (
      !outer ||
      !outer.trim().startsWith("{")
    ) {
      return {
        success: false,
        error:
          "Outer HC gagal didekripsi"
      };
    }

    // ========================================================
    // 3. JSON
    // ========================================================

    let obj;

    try {
      obj =
        JSON.parse(
          outer
        );
    } catch (e) {
      return {
        success: false,
        error:
          "JSON HC tidak valid: " +
          e.message
      };
    }

    if (
      !obj ||
      typeof obj !== "object" ||
      Array.isArray(obj)
    ) {
      return {
        success: false,
        error:
          "Struktur JSON HC tidak valid"
      };
    }

    // ========================================================
    // 4. CFG
    // ========================================================

    const cfg =
      obj.cfg &&
      typeof obj.cfg === "object"
        ? obj.cfg
        : {};

    const isNew =
      Object.prototype.hasOwnProperty.call(
        cfg,
        "content"
      );

    const meta = {};
    const protections = {};

    let target;
    let delimiter;

    // ========================================================
    // NEW FORMAT
    // ========================================================

    if (isNew) {
      for (
        const [field, name] of [
          ["b", "hwid"],
          ["f", "area"]
        ]
      ) {
        const value =
          String(
            obj[field] ??
            cfg[field] ??
            ""
          );

        if (value) {
          meta[name] =
            value;

          protections[name] =
            value;
        }
      }

      target =
        cfg.content;

      delimiter =
        "[splitConfig]";
    }

    // ========================================================
    // OLD FORMAT
    // ========================================================

    else {
      const a =
        obj.a &&
        typeof obj.a === "object"
          ? obj.a
          : {};

      for (
        const [field, name] of [
          ["bb", "hwid"],
          ["e", "password"],
          ["fe", "area"],
          ["ed", "provider"]
        ]
      ) {
        const value =
          field === "e"
            ? obj[field]
            : a[field];

        if (
          value === null ||
          value === undefined
        ) {
          continue;
        }

        const decrypted =
          hcABC(
            String(value),
            HC.keys[7]
          );

        if (decrypted) {
          meta[name] =
            decrypted;

          protections[name] =
            decrypted;
        }
      }

      target =
        obj.xy ||
        a.xy;

      delimiter =
        obj.uv ||
        a.uv;
    }

    // ========================================================
    // 5. VALIDATE
    // ========================================================

    if (
      target === null ||
      target === undefined ||
      target === ""
    ) {
      return {
        success: false,
        error:
          "Payload konfigurasi tidak ditemukan"
      };
    }

    if (
      delimiter === null ||
      delimiter === undefined ||
      delimiter === ""
    ) {
      return {
        success: false,
        error:
          "Delimiter konfigurasi tidak ditemukan"
      };
    }

    delimiter =
      String(delimiter);

    // ========================================================
    // 6. DERIVED NONCE
    // ========================================================

    const toHex =
      value =>
        Buffer.from(
          String(value || ""),
          "utf8"
        ).toString("hex");

    const hwid =
      meta.hwid;

    const password =
      meta.password;

    const provider =
      meta.provider;

    const area =
      meta.area;

    let derived = "";

    if (
      hwid &&
      !password &&
      !provider &&
      !area
    ) {
      derived =
        toHex(hwid) +
        toHex(hwid);
    } else {
      derived =
        toHex(password) +
        toHex(hwid) +
        toHex(provider) +
        toHex(area);
    }

    let dynNonce =
      Buffer.from(
        HC.nonce
      );

    if (
      dynNonce.length !== 8
    ) {
      return {
        success: false,
        error:
          "HC.nonce harus 8 byte"
      };
    }

    if (derived) {
      try {
        const derivedBytes =
          Buffer.from(
            derived,
            "hex"
          );

        const first8 =
          derivedBytes.subarray(
            0,
            8
          );

        first8.copy(
          dynNonce,
          0,
          0,
          first8.length
        );

      } catch {}
    }

    // ========================================================
    // 7. DECRYPT CONTENT
    // ========================================================

    let decryptedContent =
      null;

    // --------------------------------------------------------
    // NEW
    // --------------------------------------------------------

    if (isNew) {
      decryptedContent =
        hcRST(
          String(target)
        );

      // Fallback ABC
      if (!decryptedContent) {
        for (
          const key of HC.keys || []
        ) {
          try {
            const candidate =
              hcABC(
                String(target),
                key
              );

            if (
              candidate &&
              candidate.includes(
                delimiter
              )
            ) {
              decryptedContent =
                candidate;

              break;
            }
          } catch {}
        }
      }
    }

    // --------------------------------------------------------
    // OLD
    // --------------------------------------------------------

    else {
      decryptedContent =
        hcABC(
          String(target),
          HC.keys[1]
        );
    }

    if (
      !decryptedContent
    ) {
      return {
        success: false,
        error:
          "Isi konfigurasi HC gagal didekripsi"
      };
    }

    // ========================================================
    // 8. SPLIT
    // ========================================================

    const tokens =
      decryptedContent.split(
        delimiter
      );

    if (!tokens.length) {
      return {
        success: false,
        error:
          "Token konfigurasi HC kosong"
      };
    }

    // ========================================================
    // 9. FIELD MAP
    // ========================================================

    const config = {};

    for (
      let index = 0;
      index < tokens.length;
      index++
    ) {
      /*
       * Field tertentu memang bukan field
       * konfigurasi yang perlu ditampilkan.
       */
      if (
        index === 22 ||
        index === 24
      ) {
        continue;
      }

      const label =
        HC.tokenMap &&
        HC.tokenMap[index]
          ? HC.tokenMap[index]
          : `field_${index}`;

      let value =
        tokens[index];

      // ======================================================
      // NEW FORMAT FIELD
      // ======================================================

      if (isNew) {
        value =
          hcDecryptField(
            value,
            dynNonce
          );
      }

      // ======================================================
      // OLD FORMAT FIELD
      // ======================================================

      else {
        if (
          typeof value === "string" &&
          hcIsHex(value)
        ) {
          const abc =
            hcABC(
              value,
              HC.keys[7],
              dynNonce
            );

          if (abc) {
            value = abc;
          }
        }

        value =
          hcJKL(
            value,
            false
          );
      }

      // ======================================================
      // CLEAN
      // ======================================================

      if (
        typeof value === "string"
      ) {
        value =
          value.replace(
            /88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d/g,
            ""
          );

        value =
          value.trim();

        value =
          hcTryJson(value);
      }

      // ======================================================
      // CREDENTIALS
      // ======================================================

      if (index === 7) {
        value =
          hcCredentials(
            value,
            true
          );
      }

      else if (index === 11) {
        value =
          hcCredentials(
            value,
            false
          );
      }

      // ======================================================
      // SAVE
      // ======================================================

      if (
        value !== null &&
        value !== undefined &&
        value !== ""
      ) {
        /*
         * Jangan menampilkan token hex
         * mentah sebagai hasil decrypt.
         */
        if (
          !(
            typeof value === "string" &&
            hcIsHex(value)
          )
        ) {
          config[label] =
            value;
        }
      }
    }

    // ========================================================
    // 10. SSH
    // ========================================================

    if (
      config.sshField !==
        null &&
      config.sshField !==
        undefined
    ) {
      const ssh =
        hcCredentials(
          config.sshField,
          true
        );

      const match =
        String(ssh).match(
          /^([^:]+):(\d+)@(.+):(.+)$/
        );

      if (match) {
        config.ssh = {
          host: match[1],
          port: match[2],
          username: match[3],
          password: match[4]
        };
      }
    }

    // ========================================================
    // 11. RETURN
    // ========================================================

    return {
      success: true,
      format: isNew
        ? "new"
        : "old",

      config,

      protections,

      raw: decryptedContent
    };

  } catch (error) {
    return {
      success: false,
      error:
        error?.message ||
        "HC decrypt error"
    };
  }
}

// ============================================================
// EXPORT
// ============================================================

module.exports = hcParseModern;
