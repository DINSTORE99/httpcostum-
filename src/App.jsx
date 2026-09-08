import React, {
  useRef,
  useState
} from "react";

export default function App() {

  const inputRef = useRef(null);

  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  function selectFile(selectedFile) {

    setError("");
    setResult(null);

    if (!selectedFile) {
      setFile(null);
      return;
    }

    const name =
      selectedFile.name.toLowerCase();

    if (
      !name.endsWith(".hc") &&
      !name.endsWith(".ehi")
    ) {
      setError(
        "File harus berformat .HC atau .EHI"
      );

      setFile(null);
      return;
    }

    setFile(selectedFile);
  }


  function handleInput(event) {
    selectFile(
      event.target.files?.[0]
    );
  }


  function handleDrop(event) {

    event.preventDefault();

    const droppedFile =
      event.dataTransfer.files?.[0];

    selectFile(droppedFile);
  }


  async function decrypt() {

    if (!file) {
      setError("Pilih file terlebih dahulu.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {

      const name =
        file.name.toLowerCase();

      const endpoint =
        name.endsWith(".hc")
          ? "/api/hc"
          : "/api/ehi";

      const formData =
        new FormData();

      formData.append(
        "file",
        file
      );

      const response =
        await fetch(
          endpoint,
          {
            method: "POST",
            body: formData
          }
        );

      const text =
        await response.text();

      let data;

      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(
          text ||
          `Server error ${response.status}`
        );
      }

      if (!response.ok) {
        throw new Error(
          data.error ||
          "Gagal membongkar config."
        );
      }

      if (
        data.success === false
      ) {
        throw new Error(
          data.error ||
          "Gagal membongkar config."
        );
      }

      setResult(data);

    } catch (err) {

      setError(
        err.message ||
        "Terjadi kesalahan."
      );

    } finally {

      setLoading(false);

    }
  }


  function copy(text) {

    if (!text) return;

    navigator.clipboard
      ?.writeText(String(text));

  }


  function renderValue(value) {

    if (
      value === null ||
      value === undefined
    ) {
      return "";
    }

    if (
      typeof value === "object"
    ) {
      return (
        <pre>
          {JSON.stringify(
            value,
            null,
            2
          )}
        </pre>
      );
    }

    return String(value);
  }


  function renderResult() {

    if (!result) return null;

    const config =
      result.config ||
      result.data ||
      result;

    const entries =
      Object.entries(config)
        .filter(
          ([key]) =>
            key !== "success" &&
            key !== "config"
        );

    return (
      <section className="result">

        <div className="result-title">
          <span>✓</span>
          CONFIG BERHASIL DIBONGKAR
        </div>

        <div className="fields">

          {entries.map(
            ([key, value]) => (

              <div
                className="field"
                key={key}
              >

                <div className="field-head">

                  <span>
                    {key}
                  </span>

                  <button
                    onClick={() =>
                      copy(
                        typeof value ===
                        "object"
                          ? JSON.stringify(
                              value,
                              null,
                              2
                            )
                          : value
                      )
                    }
                  >
                    COPY
                  </button>

                </div>

                <div className="field-value">
                  {renderValue(value)}
                </div>

              </div>

            )
          )}

        </div>

      </section>
    );
  }


  return (
    <div className="app">

      <div className="glow glow-one" />
      <div className="glow glow-two" />

      <main className="container">

        <header>

          <div className="logo">
            🔐
          </div>

          <h1>
            BONGKAR CONFIG
          </h1>

          <p>
            HC + EHI CONFIG DECRYPTOR
          </p>

        </header>


        <section className="card">

          <div
            className="dropzone"
            onDragOver={(e) =>
              e.preventDefault()
            }
            onDrop={handleDrop}
            onClick={() =>
              inputRef.current?.click()
            }
          >

            <div className="upload-icon">
              📁
            </div>

            <h2>
              Pilih Config
            </h2>

            <p>
              Drag & drop atau klik
              untuk memilih file
            </p>

            <div className="formats">
              .HC
              <span>+</span>
              .EHI
            </div>

            <input
              ref={inputRef}
              type="file"
              hidden
              accept=".hc,.ehi"
              onChange={handleInput}
            />

          </div>


          {file && (

            <div className="selected">

              <span>📄</span>

              <div>
                <strong>
                  {file.name}
                </strong>

                <small>
                  {(
                    file.size /
                    1024
                  ).toFixed(1)}
                  {" KB"}
                </small>
              </div>

            </div>

          )}


          <button
            className="decrypt"
            onClick={decrypt}
            disabled={
              !file ||
              loading
            }
          >

            {loading
              ? "⏳ MEMPROSES..."
              : "🔓 BONGKAR CONFIG"}

          </button>


          {error && (

            <div className="error">
              ❌ {error}
            </div>

          )}

        </section>


        {renderResult()}


        <footer>
          BONGKAR CONFIG
          <span>•</span>
          HC + EHI
        </footer>

      </main>

    </div>
  );
}
