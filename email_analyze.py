import re
from email import message_from_string, policy
from email.utils import parseaddr
from html.parser import HTMLParser

from analyze import analyze
from url_features import get_hostname, BRANDS

MAX_LINKS = 15

URGENT_PHRASES = [
    "verify your account", "verify now", "account suspended", "has been suspended",
    "account will be closed", "urgent", "immediately", "action required",
    "confirm your identity", "unusual activity", "suspicious activity",
    "within 24 hours", "last warning", "password expires", "security alert",
    "update your payment", "limited access", "failure to",
]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear client",
                     "dear account holder", "dear member", "dear valued"]

RISKY_ATTACHMENTS = {"exe", "scr", "bat", "cmd", "js", "vbs", "jar", "iso",
                     "lnk", "hta", "html", "htm", "docm", "xlsm", "pptm"}

URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'()]+", re.I)
LOOKS_LIKE_URL = re.compile(r"^(https?://)?[\w-]+(\.[\w-]+)+(/\S*)?$", re.I)
HEADER_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s")


class _LinkParser(HTMLParser):
    """Collects (href, visible text) for every <a> tag. Never loads anything."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append((self._href.strip(), text))
            self._href = None


def _reg(host):
    """'mail.paypal.com' -> 'paypal.com'"""
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _domain_of(address):
    return address.rsplit("@", 1)[-1].lower().strip() if "@" in address else ""


def _parse(raw):
    raw = raw.strip()
    # If the text has no headers (just a pasted message), treat all of it as body
    if not HEADER_LINE.match(raw):
        raw = "\n" + raw
    return message_from_string(raw, policy=policy.default)


def _content(part):
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:
        pass
    try:
        data = part.get_payload(decode=True)
        return data.decode("utf-8", "replace") if data else ""
    except Exception:
        return ""


def _bodies(msg):
    plain, html = "", ""
    for part in msg.walk():
        if part.is_multipart() or part.get_filename():
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain += _content(part) + "\n"
        elif ctype == "text/html":
            html += _content(part) + "\n"
    return plain, html


def _auth_results(msg):
    text = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or [])).lower()
    out = {}
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{key}\s*=\s*(\w+)", text)
        out[key] = m.group(1) if m else None
    if out["spf"] is None:
        received = str(msg.get("Received-SPF") or "").strip().lower()
        if received:
            out["spf"] = received.split()[0]
    return out


def _extract_links(plain, html):
    parser = _LinkParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    anchors = parser.links[:100]
    candidates = [href for href, _ in anchors] + URL_IN_TEXT.findall(plain)

    urls, seen = [], set()
    for u in candidates:
        u = u.strip().rstrip(".,;:!?")
        if not u.lower().startswith(("http://", "https://")) or u in seen:
            continue
        seen.add(u)
        urls.append(u)
    return urls[:MAX_LINKS], anchors


def analyze_email(raw):
    msg = _parse(raw)
    subject = str(msg.get("Subject") or "").strip()
    display, addr = parseaddr(str(msg.get("From") or ""))
    from_domain = _domain_of(addr)

    plain, html = _bodies(msg)
    # A pasted HTML email without headers arrives as "plain" text; handle that too
    if not html and re.search(r"<a\s[^>]*href", plain, re.I):
        html = plain
    text_all = f"{subject}\n{plain}\n{re.sub(r'<[^>]+>', ' ', html)}".lower()

    points = 0
    warnings = []
    notes = []

    # --- Sender checks (need headers) ---
    has_headers = any(msg.get(h) for h in
                      ("From", "Reply-To", "Authentication-Results", "Received-SPF"))
    if not has_headers:
        notes.append("Note: only the message text was provided, so sender checks "
                     "(SPF, DKIM, DMARC, Reply-To) were skipped. Paste the full email "
                     "with headers for a deeper check.")

    auth = _auth_results(msg)
    if auth["spf"] in ("fail", "permerror"):
        points += 25
        warnings.append("SPF check failed: the sending server is not allowed to send for this domain")
    elif auth["spf"] == "softfail":
        points += 10
        warnings.append("SPF check softfailed: the sending server is probably not authorised")
    if auth["dkim"] in ("fail", "permerror"):
        points += 20
        warnings.append("DKIM check failed: the email's digital signature is invalid")
    if auth["dmarc"] in ("fail", "permerror"):
        points += 25
        warnings.append("DMARC check failed: the sender's own domain policy rejects this email")

    _, reply_addr = parseaddr(str(msg.get("Reply-To") or ""))
    reply_domain = _domain_of(reply_addr)
    if from_domain and reply_domain and _reg(from_domain) != _reg(reply_domain):
        points += 20
        warnings.append(f"Replies go to a different domain ({reply_domain}) than the sender ({from_domain})")

    if from_domain:
        labels = from_domain.split(".")
        for brand in BRANDS:
            if brand in display.lower() and brand not in labels:
                points += 25
                warnings.append(f"The sender name mentions '{brand}', but the address is from {from_domain}")
                break

    # --- Wording ---
    found = [p for p in URGENT_PHRASES if p in text_all]
    if found:
        points += min(20, 7 * len(found))
        examples = ", ".join(f"'{p}'" for p in found[:2])
        warnings.append(f"Uses urgent or threatening language (for example {examples})")
    if any(g in text_all for g in GENERIC_GREETINGS):
        points += 5
        warnings.append("Uses a generic greeting instead of your name")

    # --- Attachments (names only, never opened) ---
    for part in msg.walk():
        name = part.get_filename()
        if name and name.lower().rsplit(".", 1)[-1] in RISKY_ATTACHMENTS:
            points += 25
            warnings.append(f"Has a risky attachment type: {name[:60]}")
            break

    # --- Links ---
    urls, anchors = _extract_links(plain, html)

    for href, text in anchors:
        if LOOKS_LIKE_URL.match(text):
            shown = get_hostname(text if text.lower().startswith("http") else "http://" + text)
            real = get_hostname(href)
            if shown and real and _reg(shown) != _reg(real):
                points += 30
                warnings.append(f"A link claims to go to {shown} but really goes to {real}")
                break

    links = []
    for u in urls:
        try:
            r = analyze(u, check_age=False)
        except Exception:
            continue
        links.append({"url": r["url"][:300], "verdict": r["verdict"], "score": r["score"]})

    bad = sum(1 for l in links if l["score"] > 70)
    shaky = sum(1 for l in links if 30 < l["score"] <= 70)
    if bad:
        points += 35
        warnings.append(f"{bad} link{'s' if bad > 1 else ''} in this email look like phishing links")
    elif shaky:
        points += 15
        warnings.append(f"{shaky} link{'s' if shaky > 1 else ''} in this email look suspicious")

    # --- Verdict ---
    score = min(100, points)
    if score <= 30:
        verdict = "Safe"
    elif score <= 70:
        verdict = "Suspicious"
    else:
        verdict = "Phishing"

    if not warnings:
        warnings = ["No suspicious signs found in this email"]

    return {
        "verdict": verdict,
        "score": score,
        "reasons": warnings + notes,
        "subject": subject[:200],
        "sender": addr or "unknown sender",
        "auth": auth,
        "links": links,
    }


PHISH_SAMPLE = """From: "PayPal Support" <service@paypal-secure-login.xyz>
Reply-To: help@gmail.com
To: you@example.com
Subject: Urgent: Your account has been suspended
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypal-secure-login.xyz; dkim=none; dmarc=fail
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear customer,</p>
<p>We noticed unusual activity. Verify your account immediately within 24 hours or it will be closed.</p>
<a href="http://paypal-login.xyz/verify">www.paypal.com/verify</a>
</body></html>
"""

SAFE_SAMPLE = """From: "GitHub" <noreply@github.com>
Reply-To: noreply@github.com
Subject: Your pull request was merged
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

Hi, your pull request was merged.
See https://github.com/lochanapatil0322/phishing-detector for details.
"""

if __name__ == "__main__":
    for name, sample in [("PHISH", PHISH_SAMPLE), ("SAFE", SAFE_SAMPLE)]:
        r = analyze_email(sample)
        print(f"\n[{name}] {r['verdict']}  {r['score']}/100")
        for reason in r["reasons"]:
            print("  -", reason)