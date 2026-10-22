import { Link, Navigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import PublicNav from "../components/PublicNav";

const FEATURES = [
  { icon: "🔗", title: "Link analysis", text: "Checks the structure of a URL: shorteners, fake brand names, risky endings, free hosting, look-alike characters." },
  { icon: "✉️", title: "Email analysis", text: "Reads SPF, DKIM and DMARC results, reply-to mismatches, urgent wording, risky attachments and hidden link targets." },
  { icon: "🧠", title: "Explainable verdicts", text: "Every result comes with a 0-100 risk score and plain-English reasons, not just a label." },
  { icon: "🛡️", title: "Layered detection", text: "A trusted-site allowlist, a machine-learning model and rule-based signals work together." },
  { icon: "📊", title: "Dashboard and history", text: "Every scan is saved to your account, with stats on what you have checked." },
  { icon: "🔐", title: "Secure accounts", text: "Passwords are hashed with bcrypt, logins use signed tokens, and resets use one-time codes." },
];

const STACK = ["React", "FastAPI", "scikit-learn", "SQLAlchemy", "JWT", "bcrypt"];

export default function Landing() {
  const { user, loading } = useAuth();
  if (!loading && user) return <Navigate to="/dashboard" replace />;

  return (
    <div>
      <PublicNav />

      <header className="hero">
        <span className="hero-tag">AI-assisted phishing detection</span>
        <h1>Detect phishing links and emails <span className="grad">before you click</span></h1>
        <p className="hero-sub">
          Paste a link or an email and get a clear verdict, a risk score, and the exact reasons behind it.
          Nothing you scan is ever opened or run.
        </p>
        <div className="hero-cta">
          <Link to="/register" className="btn-pill big">Create free account</Link>
          <Link to="/login" className="btn-ghost">Log in</Link>
        </div>
        <div className="chips">
          {STACK.map((s) => <span key={s} className="chip">{s}</span>)}
        </div>
      </header>

      <section className="features">
        {FEATURES.map((f) => (
          <div key={f.title} className="feature">
            <div className="feature-icon">{f.icon}</div>
            <h3>{f.title}</h3>
            <p>{f.text}</p>
          </div>
        ))}
      </section>

      <footer className="footer">
        <span>🛡️ PhishGuard · Final year cybersecurity project</span>
        <a href="https://github.com/lochanapatil0322/phishing-detector" target="_blank" rel="noreferrer">GitHub</a>
      </footer>
    </div>
  );
}