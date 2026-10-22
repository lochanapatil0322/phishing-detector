import { Link } from "react-router-dom";

export default function PublicNav() {
  return (
    <nav className="pub-nav">
      <Link to="/" className="brand">🛡️ PhishGuard</Link>
      <div className="pub-nav-right">
        <Link to="/login">Log in</Link>
        <Link to="/register" className="btn-pill">Get started</Link>
      </div>
    </nav>
  );
}