"use strict";

const crypto = require("crypto");
const HC = require("../config/hc.keys");

// ============================================================
// BASIC HELPERS
// ============================================================

function hcCleanHex(value) {
  if (value === null || value === undefined) return "";

  return String(value)
    .replace(/^0x/i, "")
    .replace(/[^0-9a-f]/gi, "");
}

function hcIsHex(value) {
  if (typeof value !== "string") return false;

  const clean = hcCleanHex(value);

  return (
    clean.length > 0 &&
    clean.length % 2 === 0 &&
    /^[0-9a-f]+$/i.test(clean)
  );
}

function hcPrintable(value) {
  if (value === null || value === undefined) {
    return "";
  }

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

  try {
    return JSON.parse(value.trim());
  } catch {
    return null;
  }
}

// ============================================================
// INITIAL XOR
// ============================================================

function hcInitial(data) {
  try {
    const input = Buffer.isBuffer(data)
      ? Buffer.from(data)
      : Buffer.from(data);

    const keyValue =
      HC.initialXor ||
      HC.initialKey ||
      HC.xorKey ||
      "";

    const key = Buffer.isBuffer(keyValue)
      ? Buffer.from(keyValue)
      : Buffer.from(keyValue);

    if (!key.length) {
      return input;
    }

    const output = Buffer.alloc(input.length);

    for (let i = 0; i < input.length; i++) {
      output[i] =
        input[i] ^
        key[i % key.length];
    }

    return output;
  } catch {
    return null;
  }
}

// ============================================================
// CHACHA20
// ============================================================

function hcChaCha20(
  data,
  key,
  nonce,
  counter = 0
) {
  try {
    const input = Buffer.isBuffer(data)
      ? Buffer.from(data)
      : Buffer.from(data);

    const k = Buffer.isBuffer(key)
      ? Buffer.from(key)
      : Buffer.from(key);

    let n = Buffer.isBuffer(nonce)
      ? Buffer.from(nonce)
      : Buffer.from(nonce);

    if (k.length !== 32) {
      return null;
    }

    /*
     * Support 8-byte and 12-byte nonce.
     */
    if (
      n.length !== 8 &&
      n.length !== 12
    ) {
      return null;
    }

    let iv;

    if (n.length === 8) {
      const counterBuf =
        Buffer.alloc(4);

      counterBuf.writeUInt32LE(
        counter >>> 0,
        0
      );

      iv = Buffer.concat([
        counterBuf,
        n
      ]);
    } else {
      iv = Buffer.alloc(16);

      iv.writeUInt32LE(
        counter >>> 0,
        0
      );

      n.copy(iv, 4);
    }

    const cipher =
      crypto.createCipheriv(
        "chacha20",
        k,
        iv
      );

    cipher.setAutoPadding(false);

    return Buffer.concat([
      cipher.update(input),
      cipher.final()
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
    const input = Buffer.isBuffer(data)
      ? Buffer.from(data)
      : Buffer.from(data);

    if (input.length <= 16) {
      return null;
    }

    const body = input.subarray(
      0,
      input.length - 16
    );

    const keyValue =
      HC.abcKey ||
      HC.ABC_KEY ||
      HC.key;

    const nonceValue =
      HC.abcNonce ||
      HC.ABC_NONCE ||
      HC.nonce;

    if (!keyValue || !nonceValue) {
      return null;
    }

    const key = Buffer.isBuffer(keyValue)
      ? Buffer.from(keyValue)
      : Buffer.from(keyValue);

    const nonce =
      Buffer.isBuffer(nonceValue)
        ? Buffer.from(nonceValue)
        : Buffer.from(nonceValue);

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
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const text =
    String(value).trim();

  const match =
    text.match(
      /^(-?\d+)\.(-?\d+)$/
    );

  if (!match) {
    return null;
  }

  return {
    x: Number(match[1]),
    y: Number(match[2])
  };
}

// ============================================================
// BRAILLE
// ============================================================

function hcBraille(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  if (!HC.braille) {
    return null;
  }

  const text =
    String(value);

  let result = "";

  for (
    let i = 0;
    i < text.length;
    i += 2
  ) {
    const pair =
      text.slice(i, i + 2);

    if (
      Object.prototype.hasOwnProperty.call(
        HC.braille,
        pair
      )
    ) {
      result +=
        HC.braille[pair];
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
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const text =
    String(value).trim();

  if (!text) return null;

  /*
   * host:port@username:password
   */
  const at =
    text.indexOf("@");

  if (at !== -1) {
    const server =
      text.slice(0, at);

    const login =
      text.slice(at + 1);

    const serverMatch =
      server.match(
        /^(.+):(\d+)$/
      );

    if (serverMatch) {
      const host =
        serverMatch[1];

      const port =
        Number(serverMatch[2]);

      const colon =
        login.indexOf(":");

      if (colon !== -1) {
        return {
          host,
          port,
          username:
            login.slice(0, colon),
          password:
            login.slice(colon + 1)
        };
      }
    }
  }

  /*
   * username:password
   */
  const colon =
    text.indexOf(":");

  if (colon !== -1) {
    return {
      username:
        text.slice(0, colon),
      password:
        text.slice(colon + 1)
    };
  }

  return null;
}

// ============================================================
// JKL
// ============================================================

function hcJKL(value) {
  try {
    if (
      value === null ||
      value === undefined
    ) {
      return null;
    }

    const text =
      String(value).trim();

    if (!text) return null;

    /*
     * Original value first.
     */
    const candidates = [
      text
    ];

    /*
     * Bitwise transform.
     */
    let transformed = "";

    for (
      let i = 0;
      i < text.length;
      i++
    ) {
      const c =
        text.charCodeAt(i);

      const x =
        ((c ^ 0x5a) +
          ((i + 1) * 7)) &
        0xff;

      transformed +=
        String.fromCharCode(x);
    }

    candidates.push(
      transformed
    );

    for (
      const candidate of candidates
    ) {
      try {
        const clean =
          candidate.replace(
            /\s+/g,
            ""
          );

        if (!clean) continue;

        const decoded =
          Buffer.from(
            clean,
            "base64"
          );

        if (decoded.length) {
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
    if (
      value === null ||
      value === undefined
    ) {
      return null;
    }

    const text =
      String(value).trim();

    if (!text) return null;

    const xorValue =
      HC.rstXor ||
      HC.RST_XOR ||
      "";

    const xorKey =
      Buffer.isBuffer(xorValue)
        ? Buffer.from(xorValue)
        : Buffer.from(xorValue);

    if (!xorKey.length) {
      return null;
    }

    const raw =
      Buffer.from(text, "utf8");

    const xored =
      Buffer.alloc(raw.length);

    for (
      let i = 0;
      i < raw.length;
      i++
    ) {
      xored[i] =
        raw[i] ^
        xorKey[i % xorKey.length];
    }

    const candidates = [
      xored,
      raw
    ];

    for (
      const candidate of candidates
    ) {
      try {
        const decoded =
          Buffer.from(
            candidate
              .toString("utf8")
              .replace(/\s+/g, ""),
            "base64"
          );

        if (!decoded.length) {
          continue;
        }

        const keys =
          HC.rstKeys ||
          HC.RST_KEYS ||
          [];

        for (
          const keyValue of keys
        ) {
          try {
            const key =
              Buffer.isBuffer(keyValue)
                ? Buffer.from(keyValue)
                : Buffer.from(keyValue);

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

  if (
    typeof value !== "string"
  ) {
    return value;
  }

  const original =
    value.trim();

  if (!original) {
    return original;
  }

  const candidates = [];

  /*
   * HEX
   */
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

  /*
   * Latin1
   */
  try {
    candidates.push(
      Buffer.from(
        original,
        "latin1"
      )
    );
  } catch {}

  /*
   * UTF8
   */
  try {
    candidates.push(
      Buffer.from(
        original,
        "utf8"
      )
    );
  } catch {}

  /*
   * HC keys.
   */
  const keyValues =
    HC.keys ||
    HC.KEYS ||
    [];

  const nonceValue =
    HC.nonce ||
    HC.NONCE;

  if (nonceValue) {
    const nonce =
      Buffer.isBuffer(nonceValue)
        ? Buffer.from(nonceValue)
        : Buffer.from(nonceValue);

    if (
      nonce.length === 8 ||
      nonce.length === 12
    ) {
      for (
        const raw of candidates
      ) {
        if (!raw.length) {
          continue;
        }

        for (
          const keyValue of keyValues
        ) {
          try {
            const key =
              Buffer.isBuffer(keyValue)
                ? Buffer.from(keyValue)
                : Buffer.from(keyValue);

            if (key.length !== 32) {
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
              const text =
                decrypted.toString(
                  "utf8"
                );

              if (
                hcPrintable(text)
                  .trim()
              ) {
                return text;
              }
            }
          } catch {}
        }
      }
    }
  }

  /*
   * ABC
   */
  for (
    const raw of candidates
  ) {
    const abc =
      hcABC(raw);

    if (abc && abc.length) {
      const text =
        abc.toString("utf8");

      if (
        hcPrintable(text)
          .trim()
      ) {
        return text;
      }
    }
  }

  /*
   * JKL
   */
  const jkl =
    hcJKL(original);

  if (jkl && jkl.length) {
    const text =
      jkl.toString("utf8");

    if (
      hcPrintable(text)
        .trim()
    ) {
      return text;
    }
  }

  /*
   * RST
   */
  const rst =
    hcRST(original);

  if (rst && rst.length) {
    const text =
      rst.toString("utf8");

    if (
      hcPrintable(text)
        .trim()
    ) {
      return text;
    }
  }

  return value;
}

// ============================================================
// NOTE
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

  const text =
    value.trim();

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
   * Base64 Note.
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
      const decoded =
        raw.toString("utf8");

      const clean =
        hcPrintable(decoded);

      if (
        clean.length >= 2 &&
        clean.length >=
          decoded.length * 0.85
      ) {
        return decoded;
      }
    }
  } catch {}

  /*
   * Try normal HC field decrypt.
   */
  try {
    const decrypted =
      hcDecryptField(text);

    if (
      decrypted !== text &&
      typeof decrypted ===
        "string"
    ) {
      return decrypted;
    }
  } catch {}

  return value;
}

// ============================================================
// FIND NOTE
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
   * Direct fields.
   */
  for (
    const key of noteKeys
  ) {
    if (
      Object.prototype.hasOwnProperty.call(
        source,
        key
      )
    ) {
      const value =
        source[key];

      if (
        typeof value ===
          "string" &&
        value.trim()
      ) {
        return hcDecodeNote(
          value
        );
      }
    }
  }

  /*
   * Nested objects.
   */
  for (
    const value of
      Object.values(source)
  ) {
    if (
      value &&
      typeof value ===
        "object"
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
// RECURSIVE DECODE
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

  for (
    const [key, val] of
      Object.entries(value)
  ) {
    let decoded = val;

    const lower =
      key.toLowerCase();

    /*
     * Note fields.
     */
    if (
      [
        "note",
        "configmessage",
        "message",
        "remark",
        "description",
        "confignote",
        "notes",
        "comment"
      ].includes(lower)
    ) {
      if (
        typeof val === "string"
      ) {
        decoded =
          hcDecodeNote(val);
      }
    }

    /*
     * Recursion.
     */
    if (
      decoded &&
      typeof decoded ===
        "object"
    ) {
      decoded =
        hcDecodeInnerFields(
          decoded
        );
    }

    output[key] = decoded;
  }

  /*
   * configMessage -> note
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
// TOKEN
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
   * JSON.
   */
  const json =
    hcTryJson(text);

  if (json) {
    return hcDecodeInnerFields(
      json
    );
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
   * Credentials.
   */
  const credentials =
    hcCredentials(text);

  if (credentials) {
    return credentials;
  }

  /*
   * Encrypted field.
   */
  const decrypted =
    hcDecryptField(text);

  if (
    decrypted !== text
  ) {
    const parsed =
      hcTryJson(decrypted);

    if (parsed) {
      return hcDecodeInnerFields(
        parsed
      );
    }

    return decrypted;
  }

  return text;
}

// ============================================================
// MODERN / OLD PARSER
// ============================================================

function hcParseModern(input) {
  let protections = {};

  try {
    let source = input;

    /*
     * Buffer.
     */
    if (
      Buffer.isBuffer(source)
    ) {
      const initial =
        hcInitial(source);

      if (initial) {
        const decoded =
          initial.toString("utf8");

        const json =
          hcTryJson(decoded);

        source =
          json || decoded;
      }
    }

    /*
     * String.
     */
    if (
      typeof source === "string"
    ) {
      const json =
        hcTryJson(source);

      if (json) {
        source = json;
      } else {
        /*
         * Try Base64.
         */
        try {
          const decoded =
            Buffer.from(
              source.trim(),
              "base64"
            );

          if (
            decoded.length
          ) {
            const json2 =
              hcTryJson(
                decoded.toString(
                  "utf8"
                )
              );

            if (json2) {
              source = json2;
            }
          }
        } catch {}

        /*
         * Try ABC.
         */
        if (
          typeof source ===
            "string"
        ) {
          const abc =
            hcABC(
              Buffer.from(source)
            );

          if (abc) {
            const json3 =
              hcTryJson(
                abc.toString(
                  "utf8"
                )
              );

            if (json3) {
              source = json3;
            }
          }
        }
      }
    }

    if (
      !source ||
      typeof source !== "object"
    ) {
      throw new Error(
        "HC data bukan JSON/object"
      );
    }

    const isNew =
      !!source.content ||
      !!source.cfg ||
      !!source.config;

    /*
     * ========================================================
     * CONTENT
     * ========================================================
     */

    let content =
      source.content ||
      source.cfg?.content ||
      source.config?.content ||
      "";

    /*
     * Old HC.
     */
    if (
      !content &&
      source.xy
    ) {
      content =
        source.xy;
    }

    if (
      !content &&
      source.uv
    ) {
      content =
        source.uv;
    }

    /*
     * Object content.
     */
    if (
      typeof content ===
        "object"
    ) {
      content =
        JSON.stringify(content);
    }

    content =
      String(content || "");

    /*
     * ========================================================
     * SPLIT
     * ========================================================
     */

    let parts =
      content.split(
        "[splitConfig]"
      );

    /*
     * Jika delimiter tidak ada,
     * coba delimiter lain.
     */
    if (
      parts.length === 1
    ) {
      const delimiters = [
        "[split]",
        "|splitConfig|",
        "splitConfig",
        "\n---\n"
      ];

      for (
        const delimiter of delimiters
      ) {
        const test =
          content.split(
            delimiter
          );

        if (
          test.length > 1
        ) {
          parts = test;
          break;
        }
      }
    }

    /*
     * ========================================================
     * PARSE PARTS
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
     * CONFIG
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
        parts:
          parsedParts
      };
    }

    /*
     * Copy metadata.
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
     * ========================================================
     * SSH
     * ========================================================
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
     * DECODE EVERYTHING
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
     * RESULT
     * ========================================================
     */

    return {
      success: true,

      format:
        isNew
          ? "new"
          : "old",

      config,

      note:
        note || null,

      protections,

      raw:
        typeof input ===
          "string"
          ? input
          : Buffer.isBuffer(input)
          ? input.toString(
              "utf8"
            )
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
// MAIN FUNCTION
// ============================================================

function hcDecrypt(input) {
  try {
    if (
      input === null ||
      input === undefined
    ) {
      return {
        success: false,
        error:
          "HC input kosong",
        config: null,
        note: null
      };
    }

    /*
     * Buffer.
     */
    if (
      Buffer.isBuffer(input)
    ) {
      return hcParseModern(
        input
      );
    }

    /*
     * String.
     */
    if (
      typeof input === "string"
    ) {
      const text =
        input.trim();

      if (!text) {
        return {
          success: false,
          error:
            "HC input kosong",
          config: null,
          note: null
        };
      }

      /*
       * JSON.
       */
      const json =
        hcTryJson(text);

      if (json) {
        return hcParseModern(
          json
        );
      }

      /*
       * Direct parser.
       */
      const direct =
        hcParseModern(text);

      if (
        direct &&
        direct.success
      ) {
        return direct;
      }

      /*
       * Base64 fallback.
       */
      try {
        const decoded =
          Buffer.from(
            text,
            "base64"
          );

        if (
          decoded.length
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

      return direct;
    }

    /*
     * Object.
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
// ALIAS
// ============================================================

const decryptHC =
  hcDecrypt;

// ============================================================
// EXPORT
// ============================================================

module.exports = {
  hcDecrypt,
  decryptHC,

  hcParseModern,
  hcParseToken,

  hcInitial,
  hcChaCha20,
  hcABC,

  hcZ3A,
  hcBraille,
  hcCredentials,

  hcJKL,
  hcRST,
  hcDecryptField,

  hcDecodeNote,
  hcFindNote,
  hcDecodeInnerFields,

  hcTryJson,
  hcPrintable,
  hcCleanHex,
  hcIsHex
};
