import joblib
import pandas as pd
from urllib.parse import urlparse

from url_features import extract_features, get_hostname, SHORTENERS, FREE_HOSTING
from threat_feed import lookup_exact, lookup_host
from domain_age import get_domain_age, age_points

# --- Load the model (once) ---
_saved = joblib.load("model.pkl")
_model = _saved["model"]
_columns = _saved["columns"]

# --- Load the trusted-sites list (once) ---
with open("data/allowlist.txt") as f:
    _trusted = {line.strip().lower() for line in f if line.strip()}

# Never trust shorteners or free-hosting platforms, even if they are popular
_trusted = {
    d for d in _trusted
    if d not in SHORTENERS
    and not any(d == h or d.endswith("." + h) for h in FREE_HOSTING)
}


def _is_trusted(host):
    parts = host.split(".")
    for n in (2, 3):
        if len(parts) >= n and ".".join(parts[-n:]) in _trusted:
            return True
    return False


def _is_shared_platform(host):
    """Shorteners and free-hosting sites are shared by millions of people,
    so their domain age and website-level feed matches say nothing about one page."""
    parts = host.split(".")
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else host
    return registered in SHORTENERS or any(
        host == h or host.endswith("." + h) for h in FREE_HOSTING
    )


def _clean_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def _sig(name, status, level):
    """One entry in the 'Detection layers' panel."""
    return {"name": name, "status": status, "level": level}


def _human_age(days):
    if days < 1:
        return "today"
    if days < 60:
        return f"{days} day{'s' if days != 1 else ''}"
    if days < 730:
        return f"{days // 30} months"
    return f"{days // 365} years"


def _rule_boost(url, f):
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


def analyze(url, check_age=True):
    url = _clean_url(url)
    host = get_hostname(url)
    signals = []

    # Layer 1: is this exact link in the threat feed?
    hit = lookup_exact(url)
    if hit:
        signals.append(_sig("Threat feed (exact link)", f"Match: {hit['source']}", "bad"))
        return {
            "url": url, "verdict": "Phishing", "score": 100,
            "reasons": [f"This exact link is listed in the {hit['source']} phishing database"],
            "signals": signals,
        }
    signals.append(_sig("Threat feed (exact link)", "No match", "ok"))

    # Layer 2: well-known website
    if _is_trusted(host):
        signals.append(_sig("Trusted-site list", "Top 10,000 website", "ok"))
        return {
            "url": url, "verdict": "Safe", "score": 5,
            "reasons": ["Well-known website (ranked in the world's top 10,000 sites)"],
            "signals": signals,
        }
    signals.append(_sig("Trusted-site list", "Not listed", "info"))

    shared = _is_shared_platform(host)

    # Layer 3: does the website name appear in the threat feed?
    if shared:
        signals.append(_sig("Threat feed (website)", "Skipped: shared platform", "skip"))
    else:
        dhit = lookup_host(host)
        if dhit:
            n = dhit["count"]
            signals.append(_sig("Threat feed (website)", f"{n} listed page{'s' if n != 1 else ''}", "bad"))
            return {
                "url": url, "verdict": "Phishing", "score": 90,
                "reasons": [f"This website has {n} page{'s' if n != 1 else ''} listed in the {dhit['source']} phishing database"],
                "signals": signals,
            }
        signals.append(_sig("Threat feed (website)", "No match", "ok"))

    # Layer 4: machine-learning model + rule signals
    features = extract_features(url)
    row = pd.DataFrame([features])[_columns]
    model_score = int(round(_model.predict_proba(row)[0][1] * 100))
    signals.append(_sig(
        "ML model", f"{model_score}/100 phishing probability",
        "bad" if model_score > 70 else "warn" if model_score > 30 else "ok",
    ))

    boost = _rule_boost(url, features)
    signals.append(_sig("Rule signals", f"+{boost} points" if boost else "None triggered",
                        "warn" if boost else "ok"))
    score = model_score + boost

    # Layer 5: how old is the domain?
    age_reason = None
    if not check_age:
        signals.append(_sig("Domain age", "Skipped", "skip"))
    elif shared or features["is_ip"]:
        signals.append(_sig("Domain age", "Skipped: not applicable", "skip"))
    else:
        info = get_domain_age(host)
        if info and info["age_days"] is not None:
            days = info["age_days"]
            points = age_points(days)
            score += points
            signals.append(_sig(
                "Domain age", f"Registered {_human_age(days)} ago" if days >= 1 else "Registered today",
                "bad" if days < 30 else "warn" if days < 90 else "ok",
            ))
            if points:
                age_reason = ("The domain was registered today" if days < 1
                              else f"The domain was registered only {_human_age(days)} ago")
        else:
            signals.append(_sig("Domain age", "Not available", "info"))

    score = min(100, score)
    if score <= 30:
        verdict = "Safe"
    elif score <= 70:
        verdict = "Suspicious"
    else:
        verdict = "Phishing"

    reasons = _get_reasons(url, features)
    if age_reason:
        reasons.insert(0, age_reason)
    if not reasons:
        if verdict == "Safe":
            reasons = ["No suspicious signs found in the website name"]
        else:
            reasons = ["The overall pattern of this link resembles known phishing links"]

    return {"url": url, "verdict": verdict, "score": score, "reasons": reasons, "signals": signals}


if __name__ == "__main__":
    tests = [
        "https://google.com",
        "http://paypal-login.xyz/verify",
        "http://google.com.evil-login.xyz",
        "https://rb.gy/28wrls",
        "https://manuelabritto.github.io/azul-atual/",
    ]
    for t in tests:
        r = analyze(t)
        print(f"\n{r['url']}")
        print(f"  Verdict: {r['verdict']}   Score: {r['score']}/100")
        for reason in r["reasons"]:
            print("   -", reason)
        print("  Layers:", " | ".join(f"{s['name']}: {s['status']}" for s in r["signals"]))