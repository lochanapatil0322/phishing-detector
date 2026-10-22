import { useEffect, useState } from "react";
import { api } from "../api";

const pct = (v) => (v * 100).toFixed(1) + "%";
const pretty = (name) => name.replace(/_/g, " ");

function Metric({ label, value, color, hint }) {
  return (
    <div className={`stat stat-${color}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      <div className="stat-hint">{hint}</div>
    </div>
  );
}

export default function ModelPerformance() {
  const [m, setM] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.modelMetrics().then(setM).catch((e) => setError(e.message));
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!m) return <p className="center muted">Loading...</p>;

  const { tn, fp, fn, tp } = m.confusion;
  const top = m.importance.slice(0, 10);
  const maxImp = top[0]?.value || 1;

  return (
    <div>
      <div className="stat-grid">
        <Metric label="Accuracy" value={pct(m.accuracy)} color="blue" hint="Overall correct" />
        <Metric label="Precision" value={pct(m.precision)} color="green" hint="Flags that were right" />
        <Metric label="Recall" value={pct(m.recall)} color="amber" hint="Phishing caught" />
        <Metric label="F1 score" value={pct(m.f1)} color="red" hint="Balance of both" />
      </div>

      <div className="card">
        <h1>Confusion matrix</h1>
        <p className="muted">
          Results on {m.n_test.toLocaleString()} links the model never saw during training.
        </p>
        <div className="cm">
          <div />
          <div className="cm-head">Predicted safe</div>
          <div className="cm-head">Predicted phishing</div>

          <div className="cm-head">Actually safe</div>
          <div className="cm-cell cm-good"><strong>{tn}</strong><span>correct</span></div>
          <div className="cm-cell cm-warn"><strong>{fp}</strong><span>false alarms</span></div>

          <div className="cm-head">Actually phishing</div>
          <div className="cm-cell cm-bad"><strong>{fn}</strong><span>missed</span></div>
          <div className="cm-cell cm-good"><strong>{tp}</strong><span>caught</span></div>
        </div>
      </div>

      <div className="card">
        <h1>What the model relies on</h1>
        <p className="muted">The ten features with the most influence on its decisions.</p>
        {top.map((f) => (
          <div key={f.feature} className="imp-row">
            <span className="imp-name">{pretty(f.feature)}</span>
            <div className="imp-track">
              <div className="imp-fill" style={{ width: `${(f.value / maxImp) * 100}%` }} />
            </div>
            <span className="imp-val">{(f.value * 100).toFixed(1)}%</span>
          </div>
        ))}
      </div>

      <div className="card">
        <h1>About this evaluation</h1>
        <ul className="plain-list">
          <li><strong>Model:</strong> {m.model}, using {m.n_features} link features.</li>
          <li><strong>Data:</strong> trained on {m.n_train.toLocaleString()} links and tested on
              {" "}{m.n_test.toLocaleString()} sealed links, with phishing and safe links balanced 50/50.</li>
          <li><strong>Why recall matters most:</strong> a missed phishing link is more dangerous than a
              false alarm, so recall is the number to watch.</li>
          <li><strong>Honest limits:</strong> the model looks only at the website name, not the page
              content or domain age. These figures describe the model alone. The live tool also uses a
              trusted-site list and rule-based signals, so real results can differ from these numbers.</li>
        </ul>
        <p className="muted small">Generated {new Date(m.generated_at).toLocaleString()}</p>
      </div>
    </div>
  );
}