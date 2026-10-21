import { useEffect, useState } from "react";
import { api } from "../api";
import Badge from "../components/Badge";

export default function History() {
  const [scans, setScans] = useState([]);
  const [filter, setFilter] = useState("All");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .scans()
      .then(setScans)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const shown = filter === "All" ? scans : scans.filter((s) => s.verdict === filter);

  return (
    <div>
      <div className="card">
        <div className="row-between">
          <h1>Scan history</h1>
          <select value={filter} onChange={(e) => setFilter(e.target.value)} className="select">
            <option>All</option>
            <option>Safe</option>
            <option>Suspicious</option>
            <option>Phishing</option>
          </select>
        </div>
        <p className="muted">Your last 50 scans. Click one to see the reasons.</p>

        {loading && <p className="muted">Loading...</p>}
        {error && <p className="error">{error}</p>}
        {!loading && !error && shown.length === 0 && (
          <p className="muted">No scans to show yet.</p>
        )}

        {shown.map((scan) => (
          <details key={scan.id} className="scan-item">
            <summary>
              <Badge verdict={scan.verdict} />
              <span className="scan-score">{scan.score}/100</span>
              <span className="scan-url">{scan.url}</span>
              <span className="scan-time muted">
                {new Date(scan.created_at).toLocaleString()}
              </span>
            </summary>
            <ul className="scan-reasons">
              {scan.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </details>
        ))}
      </div>
    </div>
  );
}