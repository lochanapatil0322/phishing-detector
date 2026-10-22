import { useEffect, useState } from "react";
import { Outlet, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { api } from "../api";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: "📊" },
  { to: "/scan", label: "Scan", icon: "🔍" },
  { to: "/history", label: "History", icon: "🕘" },
];

const TITLES = {
  "/dashboard": "Dashboard",
  "/scan": "Scan a link or email",
  "/history": "Scan history",
};

export default function AppShell() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const [online, setOnline] = useState(null);

  useEffect(() => {
    api.health().then(() => setOnline(true)).catch(() => setOnline(false));
  }, []);

  function handleLogout() {
    logout();
    navigate("/login");
  }

  const initial = (user?.name || "?").charAt(0).toUpperCase();

  return (
    <div className="shell">
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="side-brand">🛡️ PhishGuard</div>

        <nav className="side-nav">
          {NAV.map((item) => (
            <NavLink key={item.to} to={item.to} className="side-link" onClick={() => setOpen(false)}>
              <span>{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="side-user">
          <div className="user-row">
            <div className="avatar">{initial}</div>
            <div className="user-meta">
              <div className="user-name">{user?.name}</div>
              <div className="user-email">{user?.email}</div>
            </div>
          </div>
          <button className="btn-small" onClick={handleLogout}>Log out</button>
        </div>
      </aside>

      {open && <div className="scrim" onClick={() => setOpen(false)} />}

      <div className="main">
        <header className="topbar">
          <button className="menu-btn" onClick={() => setOpen(true)} aria-label="Open menu">☰</button>
          <span className="topbar-title">{TITLES[location.pathname] || "PhishGuard"}</span>
          <span className="status">
            <i className={`status-dot ${online === true ? "online" : online === false ? "offline" : ""}`} />
            {online === null ? "Checking..." : online ? "Detection engine online" : "Engine offline"}
          </span>
        </header>

        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}