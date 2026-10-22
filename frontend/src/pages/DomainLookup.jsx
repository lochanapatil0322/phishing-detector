import { useState } from "react";
import { api } from "../api";

function humanAge(days) {
  if (days < 1) return "registered today";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"} old`;
  if (days < 730) return `about ${Math.floor(days / 30)} months old`;
  return `about ${Math.floor(days / 365)} years old`;
}

const LEVELS = {
  high: { color: "red", title: "Very new domain", text: "Domains registered in the last 30 days are strongly linked to phishing campaigns, because attackers keep registering fresh ones." },
  medium: { color: "amber", title: "Fairly new domain", text: "Registered within the last 3 months. Worth a closer look, but not proof of anything." },
  low: { color: "green", title: "Established domain", text: "Registered more than 3 months ago. Age alone does not make a site safe, since attackers can also hijack old domains." },
  unknown: { color: "amber", title: "Registration date not available", text: "The registry did not return a date. Some domain endings do not publish this information." },
};

export default function DomainLookup() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setResult(null);
    setBusy(true);
    try {
      setResult(await api.domainLookup(domain));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const info = result ? LEVELS[result.level] : null;

  return (
    <div>
      <div className="card">
        <h1>Domain lookup</h1>
        <p className="muted">
          Finds when a website name was first registered. Only the name is sent to the public
          registration database. The site itself is never contacted.
        </p>
        <form onSubmit={handleSubmit} className="scan-form">
          <input value={domain} onChange={(e) => setDomain(e.target.value)}
                 placeholder="e.g. example.com" maxLength={300} />
          <button className="btn" disabled={busy || !domain.trim()}>{busy ? "Looking up..." : "Look up"}</button>
        </form>
        {error && <p className="error">{error}</p>}
      </div>

      {result && info && (
        <div className={`result result-${info.color}`}>
          <h2>{info.title}</h2>
          <p>{info.text}</p>
          <dl className="kv">
            <dt>Domain</dt><dd>{result.domain}</dd>
            <dt>Registered</dt>
            <dd>{result.created ? new Date(result.created).toLocaleDateString() : "Unknown"}</dd>
            <dt>Age</dt>
            <dd>{result.age_days !== null ? humanAge(result.age_days) : "Unknown"}</dd>
            <dt>Source</dt><dd>{result.cached ? "Saved result" : "Live lookup"}</dd>
          </dl>
        </div>
      )}
    </div>
  );
}