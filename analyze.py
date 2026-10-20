import joblib
import pandas as pd
from urllib.parse import urlparse
from url_features import extract_features, get_hostname, SHORTENERS, FREE_HOSTING

# --- Load the model (once) ---
_saved = joblib.load("model.pkl")
_model = _saved["model"]
_columns = _saved["columns"]

# --- Load the trusted-sites list (once) ---
with open("data/allowlist.txt") as f:
    _trusted = {line.strip().lower() for line in f if line.strip()}

# Never trust shorteners or free-hosting platforms, even if they are popular,
# because attackers use them to hide fake pages.
_trusted = {
    d for d in _trusted
    if d not in SHORTENERS
    and not any(d == h or d.endswith("." + h) for h in FREE_HOSTING)
}


def _is_trusted(host):
    """True only if the website's real domain is on the trusted list.
    'mail.google.com' -> checks 'google.com'  (trusted)
    'google.com.evil.xyz' -> checks 'evil.xyz' (not trusted)"""
    parts = host.split(".")
    for n in (2, 3):                      # 3 covers endings like .co.uk
        if len(parts) >= n and ".".join(parts[-n:]) in _trusted:
            return True
    return False


def _clean_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def _rule_boost(url, f):
    """Extra points for tricks the model has seen too rarely to judge."""
    boost = 0
    if f["fake_brand"]:
        boost += 30
    if f["has_at"]:
        boost += 30
    if f["has_punycode"]:
        boost += 25
    if f["is_ip"]:
        boost += 15
    if f["risky_tld"]:
        boost += 10
    if urlparse(url).scheme == "http":
        boost += 5
    return boost


def _get_reasons(url, f):
    reasons = []
    if urlparse(url).scheme == "http":
        reasons.append("The connection is not encrypted (http instead of https)")
    if f["is_shortener"]:
        reasons.append("Link shortener: it hides where the link really goes")
    if f["free_hosting"]:
        reasons.append("Hosted on a free website platform that attackers often use for fake pages")
    if f["risky_tld"]:
        reasons.append("Uses a domain ending that is common in scam websites")
    if f["fake_brand"]:
        reasons.append("Contains a famous brand name, but this is not that brand's real website")
    if f["is_ip"]:
        reasons.append("Uses a raw IP address instead of a website name")
    if f["has_at"]:
        reasons.append("Contains '@', a trick used to hide the real destination")
    if f["has_punycode"]:
        reasons.append("Uses look-alike foreign characters to imitate another website")
    if f["num_hyphens"] >= 2:
        reasons.append("The website name has many hyphens, common in fake sites")
    if f["num_subdomains"] >= 3:
        reasons.append("Has an unusually long chain of subdomains")
    if f["host_length"] > 30:
        reasons.append("The website name is unusually long")
    if f["digit_ratio"] > 0.2:
        reasons.append("The website name contains many digits")
    if f["entropy"] > 3.5:
        reasons.append("The website name looks random, like auto-generated text")
    return reasons


def analyze(url):
    url = _clean_url(url)
    host = get_hostname(url)

    # Layer 1: well-known website -> trusted
    if _is_trusted(host):
        return {"url": url, "verdict": "Safe", "score": 5,
                "reasons": ["Well-known website (ranked in the world's top 10,000 sites)"]}

    # Layer 2: the machine learning model
    features = extract_features(url)
    row = pd.DataFrame([features])[_columns]
    model_score = int(round(_model.predict_proba(row)[0][1] * 100))

    # Layer 3: rule boosts on top of the model
    score = min(100, model_score + _rule_boost(url, features))

    if score <= 30:
        verdict = "Safe"
    elif score <= 70:
        verdict = "Suspicious"
    else:
        verdict = "Phishing"

    reasons = _get_reasons(url, features)
    if not reasons:
        if verdict == "Safe":
            reasons = ["No suspicious signs found in the website name"]
        else:
            reasons = ["The overall pattern of this link resembles known phishing links"]

    return {"url": url, "verdict": verdict, "score": score, "reasons": reasons}


if __name__ == "__main__":
    tests = [
        "https://google.com",
        "https://paypal.com",
        "https://mail.wikipedia.org",
        "http://paypal-login.xyz/verify",
        "http://google.com.evil-login.xyz",
        "https://rb.gy/28wrls",
        "https://manuelabritto.github.io/azul-atual/",
        "http://192.168.1.1/login",
    ]
    for t in tests:
        r = analyze(t)
        print(f"\n{r['url']}")
        print(f"  Verdict: {r['verdict']}   Score: {r['score']}/100")
        for reason in r["reasons"]:
            print("   -", reason)