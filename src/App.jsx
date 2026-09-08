import { useState } from "react";

export default function App() {
  const [file, setFile] = useState(null);

  return (
    <main className="app">
      <div className="container">

        <section className="hero">
          <div className="logo">🔓</div>

          <div className="badge">
            HC + EHI DECRYPTOR
          </div>

          <h1>
            BONGKAR <span>CONFIG</span>
          </h1>

          <p>
            DECRYPT • ANALYZE • EXTRACT
          </p>
        </section>

        <section className="card">

          <div
            className="upload"
            onClick={() =>
              document.getElementById("file").click()
            }
          >
            <div className="upload-icon">
              📁
            </div>

            <h2>
              {file
                ? file.name
                : "Pilih File Config"}
            </h2>

            <p>
              Upload file konfigurasi HC atau EHI
            </p>

            <div className="formats">
              <span>.HC</span>
              <span>.EHI</span>
            </div>
          </div>

          <input
            id="file"
            type="file"
            accept=".hc,.ehi"
            hidden
            onChange={(e) =>
              setFile(e.target.files?.[0] || null)
            }
          />

          <button
            className="button"
            disabled={!file}
          >
            🔓 BONGKAR CONFIG
          </button>

        </section>

        <section className="features">

          <div>
            <b>01</b>
            <span>
              <strong>HC SUPPORT</strong>
              HTTP Custom
            </span>
          </div>

          <div>
            <b>02</b>
            <span>
              <strong>EHI SUPPORT</strong>
              HTTP Injector
            </span>
          </div>

          <div>
            <b>03</b>
            <span>
              <strong>FAST</strong>
              Processing
            </span>
          </div>

        </section>

        <footer>
          BONGKAR CONFIG
          <br />
          <small>HC + EHI Decryptor</small>
        </footer>

      </div>
    </main>
  );
}
