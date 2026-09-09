"use strict";

const crypto = require("crypto");
const HC = require("../config/hc.keys");

// ============================================================
// HC HELPERS
// ============================================================

function hcCleanHex(value) {
  if (value === null || value === undefined) return "";

  return String(value)
    .replace(/^0x/i, "")
    .replace(/[^0-9a-f]/gi, "");
}

function hcIsHex(value) {
  if (!value || typeof value !== "string") return false;

  const clean = hcCleanHex(value);

  return (
    clean.length > 0 &&
    clean.length % 2 === 0 &&
    /^[0-9a-f]+$/i.test(clean)
  );
}

function hcPrintable(value) {
  if (value === null || value === undefined) return "";

  const text = Buffer.isBuffer(value)
    ? value.toString("utf8")
    : String(value);

  return text
    .replace(/\0/g, "")
    .replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "");
}

function hcTryJson(value) {
  if (value === null || value === undefined) {
    return null;
  }

  if (typeof value === "object") {
    return value;
  }

  if (typeof value !== "string") {
    return null;
  }

  const text = value.trim();

  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch {}

  return null;
}

// ============================================================
// CHACHA20
// ============================================================

function hcChaCha20(data, key, nonce, counter = 0) {
  try {
    const input = Buffer.isBuffer(data)
      ? Buffer.from(data)
      : Buffer.from(data);

    const k = Buffer.isBuffer(key)
      ? Buffer.from(key)
      : Buffer.from(key);

    const n = Buffer.isBuffer(nonce)
      ? Buffer.from(nonce)
      : Buffer.from(nonce);

    if (k.length !== 32) {
      return null;
    }

    if (n.length !== 8) {
      return null;
    }

    const cipher = crypto.createCipheriv(
      "chacha20",
      k,
      n
    );

    cipher.setAutoPadding(false);

    const counterBuf = Buffer.alloc(4);

    counterBuf.writeUInt32LE(
      counter >>> 0,
      0
    );

    /*
     * Node's chacha20 implementation expects
     * an 8-byte nonce where the first 4 bytes
     * contain the counter.
     */
    const iv = Buffer.concat([
      counterBuf,
      n
    ]);

    const c = crypto.createCipheriv(
      "chacha20",
      k,
      iv
    );

    c.setAutoPadding(false);

    return Buffer.concat([
      c.update(input),
      c.final()
    ]);
  } catch {
    return null;
  }
}

// ============================================================
// ABC
// ============================================================

function hcABC(data) {
  try {
    if (!Buffer.isBuffer(data)) {
      data = Buffer.from(data);
    }

    if (data.length <= 16) {
      return null;
    }

    const body = data.subarray(
      0,
      data.length - 16
    );

    const key = Buffer.isBuffer(HC.abcKey)
      ? HC.abcKey
      : Buffer.from(HC.abcKey);

    const nonce = Buffer.isBuffer(HC.abcNonce)
      ? HC.abcNonce
      : Buffer.from(HC.abcNonce);

    return hcChaCha20(
      body,
      key,
      nonce,
      1
    );
  } catch {
    return null;
  }
}

// ============================================================
// Z3A
// ============================================================

function hcZ3A(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const text = String(value).trim();

  /*
   * Z3A style:
   * number.number
   */
  const match = text.match(
    /^(-?\d+)\.(-?\d+)$/
  );

  if (!match) {
    return null;
  }

  const a = Number(match[1]);
  const b = Number(match[2]);

  if (!Number.isFinite(a) || !Number.isFinite(b)) {
    return null;
  }

  return {
    x: a,
    y: b
  };
}

// ============================================================
// BRAILLE
// ============================================================

function hcBraille(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const text = String(value);

  if (!HC.braille) {
    return null;
  }

  let result = "";

  for (let i = 0; i < text.length; i += 2) {
    const pair = text.slice(i, i + 2);

    if (
      Object.prototype.hasOwnProperty.call(
        HC.braille,
        pair
      )
    ) {
      result += HC.braille[pair];
    } else {
      result += pair;
    }
  }

  return result || null;
}

// ============================================================
// CREDENTIALS
// ============================================================

function hcCredentials(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const text = String(value).trim();

  if (!text) return null;

  /*
   * SSH:
   * host:port@username:password
   */

  const atIndex = text.indexOf("@");

  if (atIndex !== -1) {
    const server = text.slice(
      0,
      atIndex
    );

    const login = text.slice(
      atIndex + 1
    );

    const serverMatch =
      server.match(
        /^(.+):(\d+)$/
      );

    if (serverMatch) {
      const host = serverMatch[1];
      const port = Number(serverMatch[2]);

      const colon = login.indexOf(":");

      if (colon !== -1) {
        return {
          host,
          port,
          username: login.slice(0, colon),
          password: login.slice(colon + 1)
        };
      }
    }
  }

  /*
   * Normal:
   * username:password
   */

  const colon = text.indexOf(":");

  if (colon !== -1) {
    return {
      username: text.slice(0, colon),
      password: text.slice(colon + 1)
    };
  }

  return null;
}

// ============================================================
// JKL
// ============================================================

function hcJKL(value) {
  try {
    if (value === null || value === undefined) {
      return null;
    }

    let text = String(value).trim();

    if (!text) return null;

    /*
     * JKL bitwise transform
     */
    let transformed = "";

    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);

      const x =
        ((c ^ 0x5a) +
          ((i + 1) * 7)) &
        0xff;

      transformed += String.fromCharCode(x);
    }

    const candidates = [
      text,
      transformed
    ];

    for (const candidate of candidates) {
      try {
        const clean = candidate
          .replace(/\s+/g, "");

        if (!clean) continue;

        const decoded =
          Buffer.from(
            clean,
            "base64"
          );

        if (decoded.length > 0) {
          return decoded;
        }
      } catch {}
    }

    return null;
  } catch {
    return null;
  }
}

// ============================================================
// RST
// ============================================================

function hcRST(value) {
  try {
    if (value === null || value === undefined) {
      return null;
    }

    const text = String(value).trim();

    if (!text) return null;

    const xorKey =
      Buffer.isBuffer(HC.rstXor)
        ? HC.rstXor
        : Buffer.from(
            HC.rstXor || ""
          );

    if (!xorKey.length) {
      return null;
    }

    const raw = Buffer.from(
      text,
      "utf8"
    );

    const xored = Buffer.alloc(
      raw.length
    );

    for (let i = 0; i < raw.length; i++) {
      xored[i] =
        raw[i] ^
        xorKey[i % xorKey.length];
    }

    const candidates = [
      xored,
      raw
    ];

    for (const candidate of candidates) {
      try {
        const decoded =
          Buffer.from(
            candidate.toString("utf8")
              .replace(/\s+/g, ""),
            "base64"
          );

        if (!decoded.length) {
          continue;
        }

        if (
          HC.rstKeys &&
          Array.isArray(HC.rstKeys)
        ) {
          for (const keyValue of HC.rstKeys) {
            try {
              const key =
                Buffer.isBuffer(keyValue)
                  ? keyValue
                  : Buffer.from(
                      keyValue
                    );

              if (key.length !== 16) {
                continue;
              }

              const decipher =
                crypto.createDecipheriv(
                  "aes-128-ecb",
                  key,
                  null
                );

              decipher.setAutoPadding(true);

              const plain =
                Buffer.concat([
                  decipher.update(decoded),
                  decipher.final()
                ]);

              if (plain.length) {
                return plain;
              }
            } catch {}
          }
        }

        return decoded;
      } catch {}
    }

    return null;
  } catch {
    return null;
  }
}

// ============================================================
// FIELD DECRYPT
// ============================================================

function hcDecryptField(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return value;
  }

  if (typeof value !== "string") {
    return value;
  }

  const original = value.trim();

  if (!original) {
    return original;
  }

  const candidates = [];

  if (hcIsHex(original)) {
    try {
      candidates.push(
        Buffer.from(
          hcCleanHex(original),
          "hex"
        )
      );
    } catch {}
  }

  try {
    candidates.push(
      Buffer.from(
        original,
        "latin1"
      )
    );
  } catch {}

  try {
    candidates.push(
      Buffer.from(
        original,
        "utf8"
      )
    );
  } catch {}

  /*
   * Try ChaCha20 + JKL.
   */
  for (const raw of candidates) {
    if (!raw.length) continue;

    if (
      HC.keys &&
      Array.isArray(HC.keys)
    ) {
      for (const keyValue of HC.keys) {
        try {
          const key =
            Buffer.isBuffer(keyValue)
              ? keyValue
              : Buffer.from(
                  keyValue
                );

          if (key.length !== 32) {
            continue;
          }

          const nonce =
            Buffer.isBuffer(HC.nonce)
              ? HC.nonce
              : Buffer.from(
                  HC.nonce || Buffer.alloc(8)
                );

          if (nonce.length !== 8) {
            continue;
          }

          const decrypted =
            hcChaCha20(
              raw,
              key,
              nonce,
              0
            );

          if (
            decrypted &&
            decrypted.length
          ) {
            const utf8 =
              decrypted.toString("utf8");

            if (utf8.trim()) {
              return utf8;
            }
          }
        } catch {}
      }
    }

    /*
     * ABC
     */
    const abc = hcABC(raw);

    if (abc && abc.length) {
      const text =
        abc.toString("utf8");

      if (text.trim()) {
        return text;
      }
    }
  }

  /*
   * JKL fallback
   */
  const jkl = hcJKL(original);

  if (jkl && jkl.length) {
    const text =
      jkl.toString("utf8");

    if (text.trim()) {
      return text;
    }
  }

  /*
   * RST fallback
   */
  const rst = hcRST(original);

  if (rst && rst.length) {
    const text =
      rst.toString("utf8");

    if (text.trim()) {
      return text;
    }
  }

  return value;
}

// ============================================================
// NOTE FINDER
// ============================================================

function hcFindNote(source) {
  if (
    source === null ||
    source === undefined
  ) {
    return null;
  }

  if (
    typeof source !== "object"
  ) {
    return null;
  }

  const noteKeys = [
    "note",
    "configMessage",
    "message",
    "remark",
    "description",
    "configNote",
    "notes",
    "comment"
  ];

  /*
   * Check direct fields first.
   */
  for (const key of noteKeys) {
    if (
      Object.prototype.hasOwnProperty.call(
        source,
        key
      )
    ) {
      const value = source[key];

      if (
        typeof value === "string" &&
        value.trim()
      ) {
        return value.trim();
      }

      if (
        typeof value === "number" ||
        typeof value === "boolean"
      ) {
        return String(value);
      }
    }
  }

  /*
   * Search nested objects.
   */
  for (const [key, value] of Object.entries(source)) {
    if (
      value &&
      typeof value === "object"
    ) {
      const found =
        hcFindNote(value);

      if (found) {
        return found;
      }
    }
  }

  return null;
}

// ============================================================
// DECODE NOTE / CONFIG MESSAGE
// ============================================================

function hcDecodeNote(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return value;
  }

  if (
    typeof value !== "string"
  ) {
    return value;
  }

  const text = value.trim();

  if (!text) {
    return value;
  }

  /*
   * Already readable.
   */
  const printable =
    hcPrintable(text);

  if (
    printable.length >= 2 &&
    printable.length >=
      text.length * 0.85
  ) {
    return text;
  }

  /*
   * Base64 candidate.
   */
  try {
    let padded = text;

    while (
      padded.length % 4 !== 0
    ) {
      padded += "=";
    }

    const raw =
      Buffer.from(
        padded,
        "base64"
      );

    if (raw.length) {
      const utf8 =
        raw.toString("utf8");

      if (
        hcPrintable(utf8).length >=
        utf8.length * 0.85
      ) {
        return utf8;
      }
    }
  } catch {}

  return value;
}

// ============================================================
// RECURSIVE FIELD CLEANER
// ============================================================

function hcDecodeInnerFields(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(
      hcDecodeInnerFields
    );
  }

  if (
    typeof value !== "object"
  ) {
    return value;
  }

  const output = {};

  for (const [key, val] of Object.entries(value)) {
    let decoded = val;

    const lower =
      String(key).toLowerCase();

    /*
     * Fields that can contain Note.
     */
    if (
      lower === "note" ||
      lower === "configmessage" ||
      lower === "message" ||
      lower === "remark" ||
      lower === "description" ||
      lower === "confignote" ||
      lower === "notes" ||
      lower === "comment"
    ) {
      if (
        typeof val === "string"
      ) {
        decoded =
          hcDecodeNote(val);
      }
    }

    /*
     * Recursively process objects.
     */
    if (
      decoded &&
      typeof decoded === "object"
    ) {
      decoded =
        hcDecodeInnerFields(decoded);
    }

    output[key] = decoded;
  }

  /*
   * If configMessage exists,
   * expose it as note too.
   */
  if (
    !output.note &&
    typeof output.configMessage ===
      "string" &&
    output.configMessage.trim()
  ) {
    output.note =
      output.configMessage.trim();
  }

  return output;
}

// ============================================================
// TOKEN PARSER
// ============================================================

function hcParseToken(token) {
  if (
    token === null ||
    token === undefined
  ) {
    return null;
  }

  const text =
    String(token).trim();

  if (!text) {
    return null;
  }

  /*
   * Try JSON.
   */
  const json =
    hcTryJson(text);

  if (json) {
    return json;
  }

  /*
   * Z3A.
   */
  const z3a =
    hcZ3A(text);

  if (z3a) {
    return z3a;
  }

  /*
   * Braille.
   */
  const braille =
    hcBraille(text);

  if (
    braille &&
    braille !== text
  ) {
    return braille;
  }

  /*
   * Credential.
   */
  const credential =
    hcCredentials(text);

  if (credential) {
    return credential;
  }

  /*
   * Decrypt field.
   */
  const decrypted =
    hcDecryptField(text);

  if (
    decrypted !== text
  ) {
    const parsed =
      hcTryJson(decrypted);

    if (parsed) {
      return parsed;
    }

    return decrypted;
  }

  return text;
}

// ============================================================
// INITIAL XOR
// ============================================================

function hcInitial(data) {
  try {
    if (
      !Buffer.isBuffer(data)
    ) {
      data =
        Buffer.from(data);
    }

    const xorKey =
      Buffer.isBuffer(HC.initialXor)
        ? HC.initialXor
        : Buffer.from(
            HC.initialXor || ""
          );

    if (!xorKey.length) {
      return Buffer.from(data);
    }

    const output =
      Buffer.alloc(
        data.length
      );

    for (
      let i = 0;
      i < data.length;
      i++
    ) {
      output[i] =
        data[i] ^
        xorKey[i % xorKey.length];
    }

    return output;
  } catch {
    return null;
  }
}

// ============================================================
// MODERN PARSER
// ============================================================

function hcParseModern(input) {
  let protections = {};

  try {
    /*
     * Accept Buffer / string / object.
     */
    let source = input;

    if (
      Buffer.isBuffer(source)
    ) {
      const initial =
        hcInitial(source);

      if (initial) {
        source =
          initial.toString("utf8");
      }
    }

    if (
      typeof source === "string"
    ) {
      const parsed =
        hcTryJson(source);

      if (parsed) {
        source = parsed;
      } else {
        const abc =
          hcABC(
            Buffer.from(source)
          );

        if (abc) {
          const json =
            hcTryJson(
              abc.toString("utf8")
            );

          if (json) {
            source = json;
          }
        }
      }
    }

    if (
      !source ||
      typeof source !== "object"
    ) {
      throw new Error(
        "HC data bukan object/JSON"
      );
    }

    const isNew =
      !!source.content ||
      !!source.cfg ||
      !!source.config;

    /*
     * ========================================================
     * NEW FORMAT
     * ========================================================
     */

    let content =
      source.content ||
      source.cfg?.content ||
      source.config?.content ||
      "";

    if (
      typeof content !== "string"
    ) {
      content =
        JSON.stringify(content);
    }

    /*
     * [splitConfig]
     */
    let parts =
      content.split(
        "[splitConfig]"
      );

    /*
     * ========================================================
     * OLD FORMAT
     * ========================================================
     */

    if (
      parts.length <= 1 &&
      source.xy
    ) {
      content =
        source.xy;

      if (
        typeof content !==
        "string"
      ) {
        content =
          JSON.stringify(content);
      }

      parts =
        content.split(
          "[splitConfig]"
        );
    }

    /*
     * Some HC versions use uv.
     */
    if (
      parts.length <= 1 &&
      source.uv
    ) {
      content =
        source.uv;

      if (
        typeof content !==
        "string"
      ) {
        content =
          JSON.stringify(content);
      }

      parts =
        content.split(
          "[splitConfig]"
        );
    }

    /*
     * ========================================================
     * DECRYPT / PARSE TOKENS
     * ========================================================
     */

    const parsedParts = [];

    for (
      const part of parts
    ) {
      const token =
        hcParseToken(part);

      if (
        token !== null &&
        token !== undefined
      ) {
        parsedParts.push(token);
      }
    }

    /*
     * ========================================================
     * BUILD CONFIG
     * ========================================================
     */

    let config = {};

    if (
      parsedParts.length === 1 &&
      parsedParts[0] &&
      typeof parsedParts[0] ===
        "object" &&
      !Array.isArray(
        parsedParts[0]
      )
    ) {
      config =
        parsedParts[0];
    } else {
      config = {
        parts: parsedParts
      };
    }

    /*
     * Copy common HC metadata.
     */
    const metadataKeys = [
      "name",
      "version",
      "type",
      "remark",
      "description",
      "note",
      "configMessage"
    ];

    for (
      const key of metadataKeys
    ) {
      if (
        source[key] !==
        undefined &&
        config[key] ===
          undefined
      ) {
        config[key] =
          source[key];
      }
    }

    /*
     * SSH credentials.
     */
    const sshCandidates = [
      config.ssh,
      config.SSH,
      config.sshData,
      config.server,
      config.credentials
    ];

    for (
      const candidate of
      sshCandidates
    ) {
      if (
        typeof candidate ===
        "string"
      ) {
        const ssh =
          hcCredentials(
            candidate
          );

        if (
          ssh &&
          ssh.host
        ) {
          config.ssh = ssh;
          break;
        }
      }

      if (
        candidate &&
        typeof candidate ===
          "object"
      ) {
        if (
          candidate.host ||
          candidate.hostname
        ) {
          config.ssh = {
            ...candidate
          };

          if (
            !config.ssh.host &&
            config.ssh.hostname
          ) {
            config.ssh.host =
              config.ssh.hostname;
          }

          break;
        }
      }
    }

    /*
     * ========================================================
     * RECURSIVE DECODE
     * ========================================================
     */

    config =
      hcDecodeInnerFields(
        config
      );

    /*
     * ========================================================
     * NOTE
     * ========================================================
     */

    const note =
      hcFindNote(config);

    if (note) {
      config.note = note;
    }

    /*
     * ========================================================
     * PROTECTIONS
     * ========================================================
     */

    if (
      source.lock !== undefined
    ) {
      protections.lock =
        source.lock;
    }

    if (
      source.configLock !==
      undefined
    ) {
      protections.configLock =
        source.configLock;
    }

    if (
      source.protection !==
      undefined
    ) {
      protections.protection =
        source.protection;
    }

    /*
     * ========================================================
     * RESULT
     * ========================================================
     */

    return {
      success: true,

      format: isNew
        ? "new"
        : "old",

      config,

      /*
       * Note tersedia langsung
       * di root result.
       */
      note:
        note || null,

      protections,

      raw:
        typeof input === "string"
          ? input
          : Buffer.isBuffer(input)
          ? input.toString("utf8")
          : source
    };
  } catch (error) {
    return {
      success: false,
      error:
        error?.message ||
        "HC decrypt failed",
      config: null,
      note: null,
      protections
    };
  }
}

// ============================================================
// MAIN HC DECRYPT
// ============================================================

function decryptHC(input) {
  try {
    if (
      input === null ||
      input === undefined
    ) {
      return {
        success: false,
        error: "HC input kosong",
        config: null,
        note: null
      };
    }

    /*
     * Buffer
     */
    if (
      Buffer.isBuffer(input)
    ) {
      return hcParseModern(
        input
      );
    }

    /*
     * String
     */
    if (
      typeof input === "string"
    ) {
      const text =
        input.trim();

      if (!text) {
        return {
          success: false,
          error: "HC input kosong",
          config: null,
          note: null
        };
      }

      /*
       * Direct JSON.
       */
      const json =
        hcTryJson(text);

      if (json) {
        return hcParseModern(
          json
        );
      }

      /*
       * Base64.
       */
      try {
        const decoded =
          Buffer.from(
            text,
            "base64"
          );

        if (
          decoded.length > 0
        ) {
          const result =
            hcParseModern(
              decoded
            );

          if (
            result &&
            result.success
          ) {
            return result;
          }
        }
      } catch {}

      /*
       * Direct parser.
       */
      return hcParseModern(
        text
      );
    }

    /*
     * Object
     */
    if (
      typeof input === "object"
    ) {
      return hcParseModern(
        input
      );
    }

    return {
      success: false,
      error:
        "Format HC tidak didukung",
      config: null,
      note: null
    };
  } catch (error) {
    return {
      success: false,
      error:
        error?.message ||
        "HC decrypt error",
      config: null,
      note: null
    };
  }
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  decryptHC,
  hcParseModern,

  hcInitial,
  hcChaCha20,
  hcABC,
  hcZ3A,
  hcBraille,
  hcCredentials,
  hcJKL,
  hcRST,
  hcDecryptField,

  hcFindNote,
  hcDecodeNote,
  hcDecodeInnerFields,

  hcParseToken,
  hcTryJson,
  hcPrintable,
  hcCleanHex,
  hcIsHex
};
