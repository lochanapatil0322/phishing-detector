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

function TrendChart({ data }) {
  const totals = data.map((d) => d.Safe + d.Suspicious + d.Phishing);
  const max = Math.max(1, ...totals);

  if (totals.every((t) => t === 0)) {
    return <p className="muted">No scans in the last 7 days.</p>;
  }

  return (
    <>
      <div className="trend">
        {data.map((d, i) => {
          const total = totals[i];
          const height = total ? Math.max(10, (total / max) * 150) : 4;
          const day = new Date(d.date + "T00:00:00").toLocaleDateString(undefined, { weekday: "short" });
          return (
            <div key={d.date} className="trend-col">
              <span className="trend-total">{total || ""}</span>
              <div className={`trend-bar ${total ? "" : "empty"}`} style={{ height }}>
                {d.Safe > 0 && <div className="seg seg-green" style={{ flex: d.Safe }} />}
                {d.Suspicious > 0 && <div className="seg seg-amber" style={{ flex: d.Suspicious }} />}
                {d.Phishing > 0 && <div className="seg seg-red" style={{ flex: d.Phishing }} />}
              </div>
              <span className="trend-day">{day}</span>
            </div>
          );
        })}
      </div>
      <ul className="legend inline">
        <li><i className="dot dot-green" /> Safe</li>
        <li><i className="dot dot-amber" /> Suspicious</li>
        <li><i className="dot dot-red" /> Phishing</li>
      </ul>
    </>
  );
}

function TopFlags({ flags }) {
  if (flags.length === 0) {
    return <p className="muted">No flagged scans yet. Scan a suspicious link to see its red flags here.</p>;
  }
  const max = flags[0].count;
  return (
    <>
      {flags.map((f) => (
        <div key={f.label} className="flag-row">
          <span className="flag-name">{f.label}</span>
          <div className="imp-track">
            <div className="flag-fill" style={{ width: `${(f.count / max) * 100}%` }} />
          </div>
          <span className="imp-val">{f.count}</span>
        </div>
      ))}
    </>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [trend, setTrend] = useState([]);
  const [flags, setFlags] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const tz = -new Date().getTimezoneOffset();   // minutes ahead of UTC (India = 330)
    Promise.all([api.stats(), api.scans(), api.trend(tz), api.topReasons()])
      .then(([s, list, t, f]) => {
        setStats(s);
        setRecent(list.slice(0, 5));
        setTrend(t);
        setFlags(f);
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
            No scans yet. <Link to="/scan">Scan your first link</Link>.
          </p>
        ) : (
          <>
            <Donut stats={stats} />
            <p className="muted">{rate}% of your scans were flagged as phishing.</p>
          </>
        )}
      </div>

      <div className="card">
        <h1>Last 7 days</h1>
        <TrendChart data={trend} />
      </div>

      <div className="card">
        <h1>Most common red flags</h1>
        <p className="muted">What appears most often in your Suspicious and Phishing scans.</p>
        <TopFlags flags={flags} />
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