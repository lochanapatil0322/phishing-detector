import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

export default function ForgotPassword() {
  const [step, setStep] = useState(1);        // 1 = email, 2 = code + new password, 3 = done
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [info, setInfo] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  // Countdown for the "resend" button
  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  async function sendCode(e) {
    if (e) e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const data = await api.forgotPassword(email);
      setInfo(data.message);
      setStep(2);
      setCooldown(60);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function resetPassword(e) {
    e.preventDefault();
    setError("");
    if (password !== confirm) {
      setError("The two passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await api.resetPassword({ email, code, new_password: password });
      setStep(3);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (step === 3) {
    return (
      <div className="card narrow center">
        <div className="big-icon">✅</div>
        <h1>Password updated</h1>
        <p className="muted">You can now log in with your new password.</p>
        <Link to="/login" className="btn-pill big">Go to login</Link>
      </div>
    );
  }

  return (
    <div className="card narrow">
      <h1>{step === 1 ? "Forgot password?" : "Enter your code"}</h1>

      {step === 1 && (
        <form onSubmit={sendCode}>
          <p className="muted">Enter your account email and we will send you a 6-digit code.</p>
          <label>Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          {error && <p className="error">{error}</p>}
          <button className="btn" disabled={busy || !email.trim()}>
            {busy ? "Sending..." : "Send code"}
          </button>
        </form>
      )}

      {step === 2 && (
        <form onSubmit={resetPassword}>
          <p className="muted">{info}</p>

          <label>6-digit code</label>
          <input
            className="otp"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            placeholder="······"
            required
          />

          <label>New password (8 to 64 characters)</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                 minLength={8} maxLength={64} required />

          <label>Confirm new password</label>
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)}
                 minLength={8} maxLength={64} required />

          {error && <p className="error">{error}</p>}
          <button className="btn" disabled={busy || code.length !== 6}>
            {busy ? "Updating..." : "Reset password"}
          </button>

          <p className="muted resend">
            {cooldown > 0 ? (
              <>You can request a new code in {cooldown}s</>
            ) : (
              <button type="button" className="link-btn" onClick={sendCode}>Send a new code</button>
            )}
          </p>
        </form>
      )}

      <p className="muted"><Link to="/login">← Back to login</Link></p>
    </div>
  );
}