import { Link, Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../AuthContext";

export default function AuthLayout() {
  const { user, loading } = useAuth();
  if (!loading && user) return <Navigate to="/dashboard" replace />;

  return (
    <div className="auth-split">
      <section className="auth-hero">
        <Link to="/" className="brand">🛡️ PhishGuard</Link>
        <div>
          <h2>Stop phishing before it reaches you.</h2>
          <ul className="hero-points">
            <li>🔗 Analyse suspicious links in seconds</li>
            <li>✉️ Inspect emails: headers, wording, attachments</li>
            <li>🧠 See exactly why something was flagged</li>
            <li>🔒 Your account, your history, protected</li>
          </ul>
        </div>
        <p className="muted small">Final year project · Cybersecurity</p>
      </section>

      <section className="auth-panel">
        <Outlet />
      </section>
    </div>
  );
}