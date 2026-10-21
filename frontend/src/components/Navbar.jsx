import { Link, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login");
  }

  return (
    <nav className="navbar">
      <Link to="/" className="brand">🛡️ PhishGuard</Link>

      {user && (
        <div className="nav-links">
          <NavLink to="/" end>Scan</NavLink>
          <NavLink to="/history">History</NavLink>
          <NavLink to="/dashboard">Dashboard</NavLink>
        </div>
      )}

      <div className="nav-right">
        {user ? (
          <>
            <span className="muted nav-name">Hi, {user.name}</span>
            <button className="btn-small" onClick={handleLogout}>Log out</button>
          </>
        ) : (
          <>
            <Link to="/login">Log in</Link>
            <Link to="/register">Register</Link>
          </>
        )}
      </div>
    </nav>
  );
}