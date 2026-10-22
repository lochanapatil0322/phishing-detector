const LINK_STEPS = [
  { n: "1", title: "Clean the input", text: "Adds a missing scheme and extracts the website name (hostname)." },
  { n: "2", title: "Known-phishing database (exact link)", text: "If this exact link is in the community phishing database, it is reported as Phishing straight away." },
  { n: "3", title: "Trusted-site list", text: "Well-known sites from the world's top 10,000 are marked Safe. Shorteners and free-hosting platforms are never trusted." },
  { n: "4", title: "Known-phishing database (website)", text: "If the website name already hosts listed phishing pages, the link is flagged. Shared platforms are skipped." },
  { n: "5", title: "Machine-learning model", text: "A Random Forest reads 15 features of the hostname and returns a probability of phishing." },
  { n: "6", title: "Rule boosts and domain age", text: "Fake brand names, '@' tricks, look-alike characters and risky endings add points. Domains registered in the last few weeks add more." },
  { n: "7", title: "Verdict and reasons", text: "The score becomes Safe (0-30), Suspicious (31-70) or Phishing (71-100), with plain-English reasons and a layer-by-layer breakdown." },
];

const EMAIL_CHECKS = [
  "SPF, DKIM and DMARC results from the headers",
  "Reply-To that differs from the sender",
  "Sender display name imitating a brand",
  "Urgent or threatening wording and generic greetings",
  "Risky attachment types (names only, never opened)",
  "Link text that shows one site but goes to another",
  "Every link inside the email, scored with the link pipeline",
];

const SECURITY = [
  "Passwords hashed with bcrypt (salted)",
  "Signed JWT login tokens that expire after 2 hours",
  "Password resets use one-time codes: hashed, 10-minute expiry, 5 attempts, single use",
  "Same response for existing and unknown emails, so accounts cannot be discovered",
  "Every query is filtered by the logged-in user",
  "Scanned links and emails are only read as text, never opened or executed",
  "Input length limits and validation on every endpoint",
];

const LIMITS = [
  "The model sees only the hostname, not the page content or domain age.",
  "Genuine sites on free-hosting platforms (github.io, vercel.app) can be flagged.",
  "The trusted-site list can include subdomains that attackers abuse.",
  "Email header results are read from pasted text and cannot be independently verified.",
  "Wording rules work for English only.",
  "A token issued before a password change stays valid until it expires.",
  "The threat database is a snapshot: it misses brand-new phishing pages and can list hacked legitimate sites.",
  "Domain age depends on public registration data, which is not available for every domain ending.",
];

export default function HowItWorks() {
  return (
    <div>
      <div className="card">
        <h1>How a link is analysed</h1>
        <p className="muted">Five layers work together, so no single weak signal decides the result.</p>
        <div className="steps">
          {LINK_STEPS.map((s) => (
            <div key={s.n} className="step">
              <div className="step-n">{s.n}</div>
              <div>
                <strong>{s.title}</strong>
                <p>{s.text}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="two-col">
        <div className="card">
          <h1>How an email is analysed</h1>
          <ul className="plain-list">
            {EMAIL_CHECKS.map((t) => <li key={t}>{t}</li>)}
          </ul>
        </div>
        <div className="card">
          <h1>Security of this app</h1>
          <ul className="plain-list">
            {SECURITY.map((t) => <li key={t}>{t}</li>)}
          </ul>
        </div>
      </div>

      <div className="card">
        <h1>Tech stack</h1>
        <div className="chips left">
          {["React + Vite", "FastAPI", "SQLAlchemy + SQLite", "scikit-learn", "pandas", "bcrypt", "PyJWT"].map((t) => (
            <span key={t} className="chip">{t}</span>
          ))}
        </div>
      </div>

      <div className="card">
        <h1>Known limitations</h1>
        <p className="muted">No detector is perfect. These are the weak points, stated openly.</p>
        <ul className="plain-list">
          {LIMITS.map((t) => <li key={t}>{t}</li>)}
        </ul>
      </div>
    </div>
  );
}