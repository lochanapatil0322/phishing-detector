import { useEffect, useState } from "react";
import { api } from "../api";

export default function ThreatFeed() {
  const [stats, setStats] = useState(null);
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.threatStats().then(setStats).catch((e) => setError(e.message));
  }, []);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setResult(null);
    setBusy(true);
    try {
      setResult(await api.threatCheck(url));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  let color = "green";
  let title = "Not found in the feed";
  let text = "This link is not in the database. That does not make it safe: the feed only lists pages that have already been reported.";
  if (result?.exact) {
    color = "red";
    title = "Listed: known phishing link";
    text = `This exact link is in the ${result.exact.source} database.`;
  } else if (result?.domain) {
    color = "amber";
    title = "Website has listed pages";
    text = `This website name appears in ${result.domain.count} ${result.domain.source} entr${result.domain.count === 1 ? "y" : "ies"}, but this exact link is not listed.`;
  }

  return (
    <div>
      <div className="stat-grid three">
        <div className="stat stat-red">
          <div className="stat-value">{stats ? stats.total.toLocaleString() : "..."}</div>
          <div className="stat-label">Known phishing links stored</div>
        </div>
        <div className="stat stat-blue">
          <div className="stat-value">{stats ? stats.sources.length : "..."}</div>
          <div className="stat-label">Sources</div>
        </div>
        <div className="stat stat-green">
          <div className="stat-value small">
            {stats?.sources[0]?.updated ? new Date(stats.sources[0].updated).toLocaleDateString() : "n/a"}
          </div>
          <div className="stat-label">Last updated</div>
        </div>
      </div>

      {stats && stats.sources.length > 0 && (
        <div className="chips left" style={{ marginBottom: 20 }}>
          {stats.sources.map((s) => (
            <span key={s.source} className="chip">{s.source}: {s.count.toLocaleString()} links</span>
          ))}
        </div>
      )}

      <div className="card">
        <h1>Look up a link</h1>
        <p className="muted">
          Checks a link against the stored phishing database only. It is never opened. To run the full
          analysis, use the Scan page.
        </p>
        <form onSubmit={handleSubmit} className="scan-form">
          <input value={url} onChange={(e) => setUrl(e.target.value)}
                 placeholder="e.g. http://example.com/login" maxLength={2000} />
          <button className="btn" disabled={busy || !url.trim()}>{busy ? "Checking..." : "Check"}</button>
        </form>
        {error && <p className="error">{error}</p>}
      </div>

      {result && (
        <div className={`result result-${color}`}>
          <h2>{title}</h2>
          <p>{text}</p>
          <dl className="kv">
            <dt>Link</dt><dd>{result.url}</dd>
            <dt>Website</dt><dd>{result.host}</dd>
            <dt>Exact match</dt><dd>{result.exact ? `Yes (${result.exact.source})` : "No"}</dd>
            <dt>Website entries</dt><dd>{result.domain ? result.domain.count : 0}</dd>
          </dl>
        </div>
      )}

      <div className="card">
        <h1>About this data</h1>
        <ul className="plain-list">
          <li>It is a snapshot of a public community database of verified phishing links.</li>
          <li>Phishing sites are taken down quickly, so old entries may no longer be live.</li>
          <li>New phishing pages are not listed yet, which is why the model and rules also run.</li>
        </ul>
      </div>
    </div>
  );
}