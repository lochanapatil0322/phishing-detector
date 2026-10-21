import { useState } from "react";
import { api } from "../api";
import ResultCard from "../components/ResultCard";
import EmailDetails from "../components/EmailDetails";

export default function Scan() {
  const [mode, setMode] = useState("url");
  const [url, setUrl] = useState("");
  const [raw, setRaw] = useState("");
  const [fileName, setFileName] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function switchMode(m) {
    setMode(m);
    setResult(null);
    setError("");
  }

  function handleFile(e) {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 400000) {
      setError("File is too large (maximum 400 KB).");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setRaw(String(reader.result));
      setFileName(file.name);
      setError("");
    };
    reader.onerror = () => setError("Could not read the file.");
    reader.readAsText(file);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setResult(null);
    setBusy(true);
    try {
      setResult(mode === "url" ? await api.analyzeUrl(url) : await api.analyzeEmail(raw));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="card">
        <h1>{mode === "url" ? "Check a link" : "Check an email"}</h1>

        <div className="tabs">
          <button type="button" className={`tab ${mode === "url" ? "active" : ""}`}
                  onClick={() => switchMode("url")}>🔗 Link</button>
          <button type="button" className={`tab ${mode === "email" ? "active" : ""}`}
                  onClick={() => switchMode("email")}>✉️ Email</button>
        </div>

        {mode === "url" ? (
          <>
            <p className="muted">Paste a suspicious link below. It will not be opened.</p>
            <form onSubmit={handleSubmit} className="scan-form">
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="e.g. http://paypal-login.xyz/verify"
                maxLength={2000}
              />
              <button className="btn" disabled={busy || !url.trim()}>
                {busy ? "Scanning..." : "Scan"}
              </button>
            </form>
          </>
        ) : (
          <>
            <p className="muted">
              Paste the full email (with headers if possible) or upload a .eml file.
              Nothing inside it is opened or run.
            </p>
            <form onSubmit={handleSubmit}>
              <textarea
                value={raw}
                onChange={(e) => { setRaw(e.target.value); setFileName(""); }}
                placeholder="Paste the email here..."
                maxLength={500000}
              />
              <div className="file-row">
                <input type="file" accept=".eml,.txt" onChange={handleFile} />
                {fileName && <span className="muted">Loaded: {fileName}</span>}
              </div>
              <button className="btn" disabled={busy || !raw.trim()}>
                {busy ? "Scanning..." : "Scan email"}
              </button>
            </form>
          </>
        )}

        {error && <p className="error">{error}</p>}
      </div>

      {result && <ResultCard result={result} />}
      {result && mode === "email" && <EmailDetails result={result} />}
    </div>
  );
}