const HC = require("../config/hc.keys");

// ==========================================
// HEX
// ==========================================

function hcCleanHex(s) {
  if (!s) return "";

  const clean = String(s).replace(/[^0-9a-f]/gi, "");

  return clean.length % 2
    ? "0" + clean
    : clean;
}

function hcIsHex(s) {
  return !!s &&
    String(s).length >= 16 &&
    /^[0-9a-f]+$/i.test(String(s));
}

// ==========================================
// PRINTABLE
// ==========================================

function hcPrintable(s, strict = false) {
  if (!s) return false;

  if (s.length < 4) return true;

  let n = 0;

  for (const c of s) {
    const x = c.charCodeAt(0);

    if (
      (x >= 32 && x <= 126) ||
      x === 9 ||
      x === 10 ||
      x === 13
    ) {
      n++;
    }
  }

  return n / s.length > (strict ? 0.90 : 0.80);
}

// ==========================================
// CHACHA20
// ==========================================

function hcRotl32(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function hcQR(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] ^= s[a];
  s[d] = hcRotl32(s[d], 16);

  s[c] = (s[c] + s[d]) >>> 0;
  s[b] ^= s[c];
  s[b] = hcRotl32(s[b], 12);

  s[a] = (s[a] + s[b]) >>> 0;
  s[d] ^= s[a];
  s[d] = hcRotl32(s[d], 8);

  s[c] = (s[c] + s[d]) >>> 0;
  s[b] ^= s[c];
  s[b] = hcRotl32(s[b], 7);
}

function hcChaCha20(data, key, nonce, counter = 0) {
  if (key.length !== 32 || nonce.length !== 8) {
    throw new Error("ChaCha20 key/nonce invalid");
  }

  const out = Buffer.alloc(data.length);

  for (
    let off = 0, block = counter >>> 0;
    off < data.length;
    off += 64, block++
  ) {
    const st = new Uint32Array(16);

    st[0] = 0x61707865;
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;

    for (let i = 0; i < 8; i++) {
      st[4 + i] = key.readUInt32LE(i * 4);
    }

    st[12] = block;
    st[13] = 0;
    st[14] = nonce.readUInt32LE(0);
    st[15] = nonce.readUInt32LE(4);

    const x = new Uint32Array(st);

    for (let i = 0; i < 10; i++) {
      hcQR(x, 0, 4, 8, 12);
      hcQR(x, 1, 5, 9, 13);
      hcQR(x, 2, 6, 10, 14);
      hcQR(x, 3, 7, 11, 15);

      hcQR(x, 0, 5, 10, 15);
      hcQR(x, 1, 6, 11, 12);
      hcQR(x, 2, 7, 8, 13);
      hcQR(x, 3, 4, 9, 14);
    }

    const stream = Buffer.alloc(64);

    for (let i = 0; i < 16; i++) {
      stream.writeUInt32LE(
        (x[i] + st[i]) >>> 0,
        i * 4
      );
    }

    const n = Math.min(
      64,
      data.length - off
    );

    for (let i = 0; i < n; i++) {
      out[off + i] =
        data[off + i] ^ stream[i];
    }
  }

  return out;
}

// ==========================================
// ABC
// ==========================================

function hcABC(raw, key, nonce = HC.nonce) {
  try {
    const hex = hcCleanHex(raw);

    if (!hex) return "";

    const data = Buffer.from(hex, "hex");

    if (data.length <= 16) return "";

    return hcChaCha20(
      data.subarray(0, -16),
      key,
      nonce,
      1
    ).toString("utf8");

  } catch {
    return "";
  }
}

// ==========================================
// Z3A
// ==========================================

function hcZ3A(data, iv) {
  if (!data) return "";

  const out = [];
  const re = /(-?\d+)\.(-?\d+)/g;

  let m;

  while ((m = re.exec(String(data)))) {
    try {
      const a = Number(m[1]) - iv;
      const b = Number(m[2]) - iv;

      const divisor = 2 ** b;

      if (
        divisor !== 0 &&
        Number.isFinite(divisor)
      ) {
        out.push(
          ((Math.floor(a / divisor) % 256) + 256) % 256
        );
      }
    } catch {}
  }

  return Buffer.from(out).toString("utf8");
}

// ==========================================
// BRAILLE
// ==========================================

function hcBraille(s) {
  try {
    const out = [];

    for (let i = 0; i < s.length - 1; i += 2) {
      const a = HC.braille.indexOf(s[i]);
      const b = HC.braille.indexOf(s[i + 1]);

      if (a < 0 || b < 0) {
        return s;
      }

      out.push((a * 16 + b) & 255);
    }

    return Buffer.from(out).toString("utf8");

  } catch {
    return s;
  }
}

// ==========================================
// CREDENTIALS
// ==========================================

function hcCredentials(raw, isSSH = false) {
  if (!raw) return raw;

  if (
    isSSH &&
    HC.braille.includes(raw[0])
  ) {
    raw = hcBraille(raw);
  }

  const re = isSSH
    ? /^([\w.-]+):([\d-]+)@(.+):(.+)$/
    : /^([^:]+):(.+)$/;

  const m = String(raw).match(re);

  if (!m) return raw;

  const u = m[m.length - 2];
  const p = m[m.length - 1];

  const uc =
    hcZ3A(
      u,
      (u.match(/-?\d+\.-?\d+/g) || []).length
    ) || u;

  const pc =
    hcZ3A(
      p,
      (p.match(/-?\d+\.-?\d+/g) || []).length
    ) || p;

  return isSSH
    ? `${m[1]}:${m[2]}@${uc}:${pc}`
    : `${uc}:${pc}`;
}

// ==========================================
// BASE64
// ==========================================

function hcB64Decode(s) {
  let x = String(s || "");

  const pad = x.length % 4;

  if (pad) {
    x += "=".repeat(4 - pad);
  }

  return Buffer.from(x, "base64");
}

// ==========================================
// JKL
// ==========================================

function hcJKL(input, isNew = false) {
  if (!input) return input;

  try {
    const key = isNew
      ? HC.jklNew
      : HC.jklOld;

    const data = hcB64Decode(input);

    for (let i = 0; i < data.length; i++) {
      const d = data[i];
      const k = key[i % 20];

      data[i] =
        (((d ^ 0xff) & 0xca) | (d & 0x35)) ^
        (((k ^ 0xff) & 0xca) | (k & 0x35));
    }

    return hcB64Decode(
      data.toString("utf8")
    ).toString("utf8");

  } catch {
    return input;
  }
}

// ==========================================
// RST
// ==========================================

function hcRST(input) {
  try {
    const src = Buffer.from(
      String(input),
      "utf8"
    );

    const x = Buffer.alloc(src.length);

    for (let i = 0; i < src.length; i++) {
      x[i] =
        src[i] ^
        HC.rstXor[i % 20];
    }

    const ct = Buffer.from(
      x.toString("utf8"),
      "base64"
    );

    for (const key of HC.rstKeys) {
      try {
        const crypto = require("crypto");

        const d = crypto.createDecipheriv(
          "aes-128-ecb",
          Buffer.from(key),
          null
        );

        d.setAutoPadding(true);

        const out = Buffer.concat([
          d.update(ct),
          d.final()
        ]).toString("utf8");

        if (
          out.includes("[splitConfig]")
        ) {
          return out;
        }

      } catch {}
    }

  } catch {}

  return null;
}

// ==========================================
// FIELD DECRYPT
// ==========================================

function hcDecryptField(token, nonce) {
  if (
    !token ||
    [
      "true",
      "false",
      "lifeTime",
      "[splitPsiphon][splitPsiphon]"
    ].includes(token) ||
    token.startsWith("<")
  ) {
    return token;
  }

  const candidates = [];

  const clean = hcCleanHex(token);

  if (
    hcIsHex(clean) &&
    clean.length >= 32
  ) {
    try {
      candidates.push(
        Buffer.from(clean, "hex")
      );
    } catch {}
  }

  if (String(token).length > 16) {
    try {
      candidates.push(
        Buffer.from(token, "latin1")
      );
    } catch {}

    try {
      candidates.push(
        Buffer.from(token, "utf8")
      );
    } catch {}
  }

  const seen = new Set();

  for (const data of candidates) {
    const id = data.toString("hex");

    if (seen.has(id)) continue;

    seen.add(id);

    if (data.length <= 16) continue;

    const ct = data.subarray(0, -16);

    for (const key of HC.keys) {
      try {
        const dec =
          hcChaCha20(
            ct,
            key,
            nonce,
            1
          ).toString("utf8");

        for (const isNew of [true, false]) {
          const out =
            hcJKL(dec, isNew);

          if (
            out !== dec &&
            hcPrintable(out)
          ) {
            return out;
          }
        }

        if (
          (
            hcPrintable(dec, true) &&
            /HTTP|@|:|\{/.test(dec)
          ) ||
          /^[A-Za-z0-9]+$/.test(dec)
        ) {
          return dec;
        }

      } catch {}
    }
  }

  for (const isNew of [true, false]) {
    const out =
      hcJKL(token, isNew);

    if (
      out !== token &&
      hcPrintable(out)
    ) {
      return out;
    }
  }

  return token;
}

// ==========================================
// INITIAL
// ==========================================

function hcInitial(fileBytes) {
  let latin;

  try {
    latin = Buffer.from(
      fileBytes.toString("utf8"),
      "latin1"
    );
  } catch {
    latin = fileBytes;
  }

  const out =
    Buffer.alloc(latin.length);

  for (
    let i = 0;
    i < latin.length;
    i++
  ) {
    out[i] =
      latin[i] ^
      HC.initialXor[
        i % HC.initialXor.length
      ];
  }

  return out.toString("utf8");
}

// ==========================================
// MAIN HC PARSER
// ==========================================

function hcParseModern(buffer) {
  try {
    if (
      !Buffer.isBuffer(buffer) ||
      !buffer.length
    ) {
      return {
        success: false,
        error: "File kosong"
      };
    }

    const hexPayload =
      hcInitial(buffer);

    const outer =
      hcABC(
        hexPayload,
        HC.keys[5]
      );

    if (
      !outer ||
      !outer.trim().startsWith("{")
    ) {
      return {
        success: false,
        error: "Outer decrypt gagal"
      };
    }

    const obj =
      JSON.parse(outer);

    if (
      !obj ||
      typeof obj !== "object"
    ) {
      return {
        success: false,
        error: "JSON HC tidak valid"
      };
    }

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
    let delim;

    // ======================================
    // NEW FORMAT
    // ======================================

    if (isNew) {
      for (
        const [k, name] of [
          ["b", "hwid"],
          ["f", "area"]
        ]
      ) {
        const val =
          String(
            obj[k] ??
            cfg[k] ??
            ""
          );

        if (val) {
          meta[name] = val;
          protections[name] = val;
        }
      }

      target = cfg.content;
      delim = "[splitConfig]";

    }

    // ======================================
    // OLD FORMAT
    // ======================================

    else {
      const a =
        obj.a &&
        typeof obj.a === "object"
          ? obj.a
          : {};

      for (
        const [k, name] of [
          ["bb", "hwid"],
          ["e", "password"],
          ["fe", "area"],
          ["ed", "provider"]
        ]
      ) {
        const val =
          k === "e"
            ? obj[k]
            : a[k];

        if (val) {
          const dec =
            hcABC(
              String(val),
              HC.keys[7]
            );

          if (dec) {
            meta[name] = dec;
            protections[name] = dec;
          }
        }
      }

      target =
        obj.xy ||
        a.xy;

      delim =
        obj.uv ||
        a.uv;
    }

    if (
      !target ||
      !delim
    ) {
      return {
        success: false,
        error:
          "Payload/delimiter tidak ditemukan"
      };
    }

    const toHex = s =>
      Buffer.from(
        String(s || ""),
        "utf8"
      ).toString("hex");

    const h = meta.hwid;
    const p = meta.password;
    const pr = meta.provider;
    const a = meta.area;

    const derived =
      h &&
      !p &&
      !pr &&
      !a
        ? toHex(h) + toHex(h)
        : toHex(p) +
          toHex(h) +
          toHex(pr) +
          toHex(a);

    const dyn =
      Buffer.from(HC.nonce);

    if (derived) {
      try {
        const b =
          Buffer.from(
            derived,
            "hex"
          ).subarray(0, 8);

        b.copy(
          dyn,
          0,
          0,
          b.length
        );

      } catch {}
    }

    let xyDec = null;

    // ======================================
    // NEW
    // ======================================

    if (isNew) {
      xyDec =
        hcRST(
          String(target)
        );

      if (!xyDec) {
        for (
          const key of HC.keys
        ) {
          const t =
            hcABC(
              String(target),
              key
            );

          if (
            t &&
            t.includes(delim)
          ) {
            xyDec = t;
            break;
          }
        }
      }

    }

    // ======================================
    // OLD
    // ======================================

    else {
      xyDec =
        hcABC(
          String(target),
          HC.keys[1]
        );
    }

    if (!xyDec) {
      return {
        success: false,
        error:
          "Isi konfigurasi gagal didekripsi"
      };
    }

    const config = {};
    const tokens =
      xyDec.split(
        String(delim)
      );

    for (
      let i = 0;
      i < tokens.length;
      i++
    ) {
      if (
        i === 22 ||
        i === 24
      ) {
        continue;
      }

      const label =
        HC.tokenMap[i] ||
        `field_${i}`;

      let out =
        tokens[i];

      if (isNew) {
        out =
          hcDecryptField(
            out,
            dyn
          );

      } else {
        if (hcIsHex(out)) {
          out =
            hcABC(
              out,
              HC.keys[7],
              dyn
            );
        }

        out =
          hcJKL(
            out,
            false
          );
      }

      if (i === 7) {
        out =
          hcCredentials(
            out,
            true
          );

      } else if (i === 11) {
        out =
          hcCredentials(
            out,
            false
          );
      }

      if (
        typeof out === "string"
      ) {
        out =
          out.replace(
            /88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d/g,
            ""
          );

        if (
          /^[\[{]/.test(out)
        ) {
          try {
            out =
              JSON.parse(out);
          } catch {}
        }
      }

      if (
        out &&
        !(
          typeof out === "string" &&
          hcIsHex(out)
        )
      ) {
        config[label] = out;
      }
    }

    // ======================================
    // SSH PARSER
    // ======================================

    if (config.sshField) {
      const sv =
        hcCredentials(
          config.sshField,
          true
        );

      const sm =
        String(sv).match(
          /^([^:]+):(\d+)@(.+):(.+)$/
        );

      config.ssh =
        sm
          ? {
              host: sm[1],
              port: sm[2],
              username: sm[3],
              password: sm[4]
            }
          : {};
    }

    return {
      success: true,
      config,
      protections,
      raw: xyDec,
      format: isNew
        ? "new"
        : "old"
    };

  } catch (e) {
    return {
      success: false,
      error:
        e.message ||
        "Decrypt error"
    };
  }
}

module.exports = hcParseModern;
