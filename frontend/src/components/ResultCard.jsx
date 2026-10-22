const COLORS = {
  Safe: "green",
  Suspicious: "amber",
  Phishing: "red",
};

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export default function ResultCard({ result }) {
  const color = COLORS[result.verdict] || "amber";
  const offset = CIRCUMFERENCE * (1 - result.score / 100);

  return (
    <div className={`result result-${color}`}>
      <div className="result-head">
        <svg className="gauge" viewBox="0 0 120 120" role="img"
             aria-label={`Risk score ${result.score} out of 100`}>
          <circle className="gauge-bg" cx="60" cy="60" r={RADIUS} />
          <circle
            className={`gauge-fill stroke-${color}`}
            cx="60" cy="60" r={RADIUS}
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={offset}
            transform="rotate(-90 60 60)"
          />
          <text x="60" y="64" className="gauge-num">{result.score}</text>
          <text x="60" y="82" className="gauge-sub">RISK SCORE</text>
        </svg>

        <div className="result-info">
          <h2>{result.verdict}</h2>
          {/* plain text on purpose: never make a scanned link clickable */}
          <p className="scanned-url">{result.url || result.subject}</p>
        </div>
      </div>

      <h3>Why?</h3>
      <ul>
        {result.reasons.map((reason, i) => (
          <li key={i}>{reason}</li>
        ))}
      </ul>

      {result.signals && result.signals.length > 0 && (
        <>
          <h3>Detection layers</h3>
          <div className="signals">
            {result.signals.map((s, i) => (
              <div key={i} className={`signal signal-${s.level}`}>
                <span className="signal-name">{s.name}</span>
                <span className="signal-status">{s.status}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}