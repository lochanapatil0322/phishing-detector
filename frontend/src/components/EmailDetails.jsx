import Badge from "./Badge";

function authColor(value) {
  if (value === "pass") return "green";
  if (value === "fail" || value === "permerror") return "red";
  if (value) return "amber";
  return "gray";
}

export default function EmailDetails({ result }) {
  const auth = result.auth || {};
  const links = result.links || [];

  return (
    <div className="card">
      <h1>Email details</h1>
      <p><strong>Subject:</strong> {result.subject || "(none)"}</p>
      <p><strong>From:</strong> {result.sender}</p>

      <h3>Sender checks</h3>
      <div className="auth-row">
        {["spf", "dkim", "dmarc"].map((k) => (
          <span key={k} className={`auth auth-${authColor(auth[k])}`}>
            {k.toUpperCase()}: {auth[k] || "not found"}
          </span>
        ))}
      </div>

      <h3>Links found ({links.length})</h3>
      {links.length === 0 && <p className="muted">No links in this email.</p>}
      {links.map((l, i) => (
        <div key={i} className="recent-row">
          <Badge verdict={l.verdict} />
          {/* plain text on purpose: never make these links clickable */}
          <span className="scan-url">{l.url}</span>
          <span className="scan-score">{l.score}</span>
        </div>
      ))}
    </div>
  );
}