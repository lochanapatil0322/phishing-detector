import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { api } from "../api";

export default function Settings() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  // Change password
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pwMsg, setPwMsg] = useState({ type: "", text: "" });
  const [pwBusy, setPwBusy] = useState(false);

  // Clear history
  const [histMsg, setHistMsg] = useState({ type: "", text: "" });

  // Delete account
  const [delPassword, setDelPassword] = useState("");
  const [delError, setDelError] = useState("");
  const [delBusy, setDelBusy] = useState(false);

  async function changePassword(e) {
    e.preventDefault();
    setPwMsg({ type: "", text: "" });
    if (next !== confirm) {
      setPwMsg({ type: "error", text: "The new passwords do not match." });
      return;
    }
    setPwBusy(true);
    try {
      const data = await api.changePassword({ current_password: current, new_password: next });
      setPwMsg({ type: "ok", text: data.message });
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (err) {
      setPwMsg({ type: "error", text: err.message });
    } finally {
      setPwBusy(false);
    }
  }

  async function clearHistory() {
    if (!window.confirm("Delete ALL your scan history? This cannot be undone.")) return;
    setHistMsg({ type: "", text: "" });
    try {
      const data = await api.clearHistory();
      setHistMsg({ type: "ok", text: data.message });
    } catch (err) {
      setHistMsg({ type: "error", text: err.message });
    }
  }

  async function deleteAccount(e) {
    e.preventDefault();
    setDelError("");
    if (!window.confirm("Permanently delete your account and all your data? This cannot be undone.")) return;
    setDelBusy(true);
    try {
      await api.deleteAccount(delPassword);
      logout();
      navigate("/");
    } catch (err) {
      setDelError(err.message);
      setDelBusy(false);
    }
  }

  return (
    <div>
      <div className="card">
        <h1>Your account</h1>
        <p><span className="muted">Name:</span> {user?.name}</p>
        <p><span className="muted">Email:</span> {user?.email}</p>
      </div>

      <div className="card">
        <h1>Change password</h1>
        <form onSubmit={changePassword}>
          <label>Current password</label>
          <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)}
                 maxLength={64} required />

          <label>New password (8 to 64 characters)</label>
          <input type="password" value={next} onChange={(e) => setNext(e.target.value)}
                 minLength={8} maxLength={64} required />

          <label>Confirm new password</label>
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)}
                 minLength={8} maxLength={64} required />

          {pwMsg.text && <p className={pwMsg.type === "ok" ? "success" : "error"}>{pwMsg.text}</p>}
          <button className="btn" disabled={pwBusy}>{pwBusy ? "Saving..." : "Change password"}</button>
        </form>
      </div>

      <div className="card danger-zone">
        <h1>Danger zone</h1>

        <div className="danger-row">
          <div>
            <strong>Clear scan history</strong>
            <p className="muted">Deletes every scan saved to your account. Your account stays.</p>
          </div>
          <button className="btn-danger" onClick={clearHistory}>Clear history</button>
        </div>
        {histMsg.text && <p className={histMsg.type === "ok" ? "success" : "error"}>{histMsg.text}</p>}

        <hr className="divider" />

        <form onSubmit={deleteAccount}>
          <strong>Delete account</strong>
          <p className="muted">Permanently deletes your account and all your scans. Enter your password to confirm.</p>
          <input type="password" value={delPassword} onChange={(e) => setDelPassword(e.target.value)}
                 placeholder="Your password" maxLength={64} required />
          {delError && <p className="error">{delError}</p>}
          <button className="btn-danger solid" disabled={delBusy || !delPassword}>
            {delBusy ? "Deleting..." : "Delete my account"}
          </button>
        </form>
      </div>
    </div>
  );
}