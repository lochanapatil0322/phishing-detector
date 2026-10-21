import { useState } from "react";
import { api } from "../api";
import ResultCard from "../components/ResultCard";

export default function Scan() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setResult(null);
    setBusy(true);
    try {
      setResult(await api.analyzeUrl(url));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="card">
        <h1>Check a link</h1>
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
        {error && <p className="error">{error}</p>}
      </div>

      {result && <ResultCard result={result} />}
    </div>
  );
}