import { useEffect, useState } from "react";
import { Outlet, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { api } from "../api";

const NAV = [
  {
    section: "Main",
    items: [
      { to: "/dashboard", label: "Dashboard", icon: "📊", title: "Dashboard" },
      { to: "/scan", label: "Scan", icon: "🔍", title: "Scan a link or email" },
      { to: "/history", label: "History", icon: "🕘", title: "Scan history" },
    ],
  },
  {
    section: "Intelligence",
    items: [
      { to: "/threat-feed", label: "Threat Feed", icon: "🌐", title: "Threat feed" },
      { to: "/domain-lookup", label: "Domain Lookup", icon: "🔎", title: "Domain lookup" },
    ],
  },
  {
    section: "System",
    items: [
      { to: "/model", label: "Model Performance", icon: "🧠", title: "Model performance" },
      { to: "/how-it-works", label: "How It Works", icon: "📘", title: "How it works" },
    ],
  },
  {
    section: "Account",
    items: [{ to: "/settings", label: "Settings", icon: "⚙️", title: "Settings" }],
  },
];

const TITLES = Object.fromEntries(
  NAV.flatMap((g) => g.items).map((i) => [i.to, i.title])
);

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
          {NAV.map((group) => (
            <div key={group.section} className="side-group">
              <div className="side-section">{group.section}</div>
              {group.items.map((item) => (
                <NavLink key={item.to} to={item.to} className="side-link" onClick={() => setOpen(false)}>
                  <span>{item.icon}</span>
                  {item.label}
                </NavLink>
              ))}
            </div>
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