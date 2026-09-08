import { useRef, useState } from "react";
import "./style.css";

export default function App() {
  const inputRef = useRef(null);

  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);

  const chooseFile = (selected) => {
    if (!selected) return;

    const name = selected.name.toLowerCase();

    if (!name.endsWith(".hc") && !name.endsWith(".ehi")) {
      setError("File harus berformat .HC atau .EHI");
      setFile(null);
      return;
    }

    setFile(selected);
    setError("");
    setResult(null);
  };

  const handleFile = (e) => {
    chooseFile(e.target.files?.[0]);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    chooseFile(e.dataTransfer.files?.[0]);
  };

  const decrypt = async () => {
    if (!file) {
      setError("Pilih file terlebih dahulu.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const endpoint = file.name
        .toLowerCase()
        .endsWith(".hc")
        ? "/api/hc"
        : "/api/ehi";

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream"
        },
        body: file
      });

      const text = await response.text();

      let data;

      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(
          text || `Server error ${response.status}`
        );
      }

      if (!response.ok || data.success === false) {
        throw new Error(
          data.error || "Gagal membongkar config."
        );
      }

      setResult(data);
    } catch (err) {
      setError(err.message || "Terjadi kesalahan.");
    } finally {
      setLoading(false);
    }
  };

  const copy = async (value) => {
    if (value === null || value === undefined) return;

    const text =
      typeof value === "object"
        ? JSON.stringify(value, null, 2)
        : String(value);

    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
  };

  const formatValue = (value) => {
    if (value === null || value === undefined) {
      return "-";
    }

    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }

    if (typeof value === "object") {
      return JSON.stringify(value, null, 2);
    }

    return String(value);
  };

  const getConfig = () => {
    if (!result) return {};

    if (
      result.config &&
      typeof result.config === "object"
    ) {
      return result.config;
    }

    if (
      result.data &&
      typeof result.data === "object"
    ) {
      return result.data;
    }

    return result;
  };

  const config = getConfig();

  const fields = Object.entries(config).filter(
    ([key]) =>
      key !== "success" &&
      key !== "message" &&
      key !== "config"
  );

  return (
    <div className="app">

      <div className="background-grid" />

      <div className="orb orb-one" />
      <div className="orb orb-two" />

      <main className="container">

        {/* HEADER */}

        <header className="hero">

          <div className="brand-icon">
            <span>🔐</span>
          </div>

          <div className="badge">
            ● ONLINE
          </div>

          <h1>
            BONGKAR
            <span> CONFIG</span>
          </h1>

          <p>
            HC & EHI CONFIG DECRYPTOR
          </p>

        </header>


        {/* UPLOAD CARD */}

        <section className="panel">

          <div
            className={`dropzone ${
              dragging ? "dragging" : ""
            }`}
            onClick={() =>
              inputRef.current?.click()
            }
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() =>
              setDragging(false)
            }
            onDrop={handleDrop}
          >

            <input
              ref={inputRef}
              type="file"
              accept=".hc,.ehi"
              hidden
              onChange={handleFile}
            />

            <div className="upload-circle">
              {file ? "📄" : "↑"}
            </div>

            {file ? (
              <>
                <h2>{file.name}</h2>

                <p>
                  {(file.size / 1024).toFixed(1)} KB
                  {" • "}
                  {file.name
                    .toLowerCase()
                    .endsWith(".hc")
                    ? "HC CONFIG"
                    : "EHI CONFIG"}
                </p>
              </>
            ) : (
              <>
                <h2>
                  Upload Config
                </h2>

                <p>
                  Drag & drop file di sini
                  <br />
                  atau klik untuk memilih
                </p>
              </>
            )}

            <div className="format-list">
              <span>.HC</span>
              <span>.EHI</span>
            </div>

          </div>


          {file && (
            <button
              className="change-file"
              onClick={() => {
                setFile(null);
                setResult(null);
                inputRef.current.value = "";
              }}
            >
              Ganti File
            </button>
          )}


          <button
            className="decrypt-button"
            disabled={!file || loading}
            onClick={decrypt}
          >

            {loading ? (
              <>
                <span className="spinner" />
                MEMPROSES CONFIG...
              </>
            ) : (
              <>
                🔓 BONGKAR CONFIG
              </>
            )}

          </button>


          {error && (
            <div className="error-box">
              <strong>ERROR</strong>
              <span>{error}</span>
            </div>
          )}

        </section>


        {/* INFO */}

        <section className="features">

          <div>
            <b>01</b>
            <span>
              <strong>HC Support</strong>
              HTTP Custom config
            </span>
          </div>

          <div>
            <b>02</b>
            <span>
              <strong>EHI Support</strong>
              HTTP Injector config
            </span>
          </div>

          <div>
            <b>03</b>
            <span>
              <strong>Fast Process</strong>
              Serverless API
            </span>
          </div>

        </section>


        {/* RESULT */}

        {result && (

          <section className="result-panel">

            <div className="result-header">

              <div>
                <div className="success-badge">
                  ✓ SUCCESS
                </div>

                <h2>
                  Config Berhasil Dibongkar
                </h2>
              </div>

              <button
                className="copy-all"
                onClick={() =>
                  copy(config)
                }
              >
                COPY ALL
              </button>

            </div>


            <div className="result-grid">

              {fields.map(
                ([key, value]) => (

                  <div
                    className="result-field"
                    key={key}
                  >

                    <div className="field-title">

                      <span>
                        {key}
                      </span>

                      <button
                        onClick={() =>
                          copy(value)
                        }
                      >
                        COPY
                      </button>

                    </div>

                    <pre>
                      {formatValue(value)}
                    </pre>

                  </div>

                )
              )}

            </div>

          </section>

        )}


        <footer>

          <span>
            BONGKAR CONFIG
          </span>

          <i>•</i>

          HC + EHI

          <small>
            Secure Config Decoder
          </small>

        </footer>

      </main>
    </div>
  );
}
