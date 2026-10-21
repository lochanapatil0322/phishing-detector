import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import Badge from "../components/Badge";

function StatCard({ label, value, color }) {
  return (
    <div className={`stat stat-${color}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function Donut({ stats }) {
  const { total, safe, suspicious } = stats;
  const safeEnd = (safe / total) * 100;
  const susEnd = safeEnd + (suspicious / total) * 100;

  const gradient = `conic-gradient(
    #2e9e57 0 ${safeEnd}%,
    #e0a100 ${safeEnd}% ${susEnd}%,
    #d33a3a ${susEnd}% 100%
  )`;

  return (
    <div className="donut-wrap">
      <div className="donut" style={{ background: gradient }}>
        <div className="donut-hole">
          <strong>{total}</strong>
          <span>scans</span>
        </div>
      </div>
      <ul className="legend">
        <li><i className="dot dot-green" /> Safe</li>
        <li><i className="dot dot-amber" /> Suspicious</li>
        <li><i className="dot dot-red" /> Phishing</li>
      </ul>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.stats(), api.scans()])
      .then(([s, list]) => {
        setStats(s);
        setRecent(list.slice(0, 5));
      })
      .catch((err) => setError(err.message));
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!stats) return <p className="center muted">Loading...</p>;

  const rate = stats.total ? Math.round((stats.phishing / stats.total) * 100) : 0;

  return (
    <div>
      <div className="stat-grid">
        <StatCard label="Total scans" value={stats.total} color="blue" />
        <StatCard label="Safe" value={stats.safe} color="green" />
        <StatCard label="Suspicious" value={stats.suspicious} color="amber" />
        <StatCard label="Phishing" value={stats.phishing} color="red" />
      </div>

      <div className="card">
        <h1>Your results</h1>
        {stats.total === 0 ? (
          <p className="muted">
            No scans yet. <Link to="/">Scan your first link</Link>.
          </p>
        ) : (
          <>
            <Donut stats={stats} />
            <p className="muted">{rate}% of the links you scanned were flagged as phishing.</p>
          </>
        )}
      </div>

      <div className="card">
        <div className="row-between">
          <h1>Latest scans</h1>
          <Link to="/history">View all</Link>
        </div>
        {recent.length === 0 && <p className="muted">Nothing yet.</p>}
        {recent.map((s) => (
          <div key={s.id} className="recent-row">
            <Badge verdict={s.verdict} />
            <span>{s.type === "email" ? "✉️" : "🔗"}</span>
            <span className="scan-url">{s.url}</span>
            <span className="scan-score">{s.score}</span>
          </div>
        ))}
      </div>
    </div>
  );
}