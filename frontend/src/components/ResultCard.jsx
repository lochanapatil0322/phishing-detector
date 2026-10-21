const COLORS = {
  Safe: "green",
  Suspicious: "amber",
  Phishing: "red",
};

export default function ResultCard({ result }) {
  const color = COLORS[result.verdict] || "amber";

  return (
    <div className={`result result-${color}`}>
      <div className="result-top">
        <h2>{result.verdict}</h2>
        <div className="score">{result.score}<span>/100</span></div>
      </div>

      <div className="bar">
        <div className={`bar-fill fill-${color}`} style={{ width: `${result.score}%` }} />
      </div>

      {/* Shown as plain text on purpose: never make a scanned link clickable */}
      <p className="scanned-url">{result.url}</p>

      <h3>Why?</h3>
      <ul>
        {result.reasons.map((reason, i) => (
          <li key={i}>{reason}</li>
        ))}
      </ul>
    </div>
  );
}