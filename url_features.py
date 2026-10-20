import re
import math
from collections import Counter
from urllib.parse import urlparse

RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link",
              "work", "support", "online", "site", "club", "buzz", "icu",
              "cyou", "rest", "monster"}

BRANDS = ["paypal", "amazon", "google", "apple", "microsoft", "facebook",
          "instagram", "netflix", "whatsapp", "linkedin", "hdfc", "icici",
          "paytm", "dhl", "fedex", "outlook", "dropbox", "binance", "coinbase"]

# Link shorteners hide where the link really goes
SHORTENERS = {"bit.ly", "rb.gy", "tinyurl.com", "t.co", "cutt.ly", "is.gd",
              "goo.gl", "ow.ly", "shorturl.at", "t.ly", "tiny.cc", "buff.ly"}

# Free website builders that attackers use to host fake pages
FREE_HOSTING = ["github.io", "vercel.app", "netlify.app", "web.app",
                "firebaseapp.com", "pages.dev", "workers.dev", "weebly.com",
                "wixsite.com", "blogspot.com", "herokuapp.com",
                "onrender.com", "glitch.me", "webflow.io", "framer.website"]

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def get_hostname(url):
    try:
        host = urlparse(url).hostname
    except ValueError:
        host = None
    return host or ""


def has_at_symbol(url):
    try:
        return int("@" in urlparse(url).netloc)
    except ValueError:
        return 0


def entropy(text):
    """How random does the text look? 'google' is low, 'xk9qz7vb' is high."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_features(url):
    host = get_hostname(url)
    parts = host.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    main = parts[-2] if len(parts) >= 2 else host
    is_ip = int(bool(IP_PATTERN.match(host)))
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else host

    fake_brand = int(any(b in host and b != main for b in BRANDS))

    return {
        "host_length": len(host),
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "num_subdomains": 0 if is_ip else max(len(parts) - 2, 0),
        "num_digits": sum(c.isdigit() for c in host),
        "digit_ratio": round(sum(c.isdigit() for c in host) / len(host), 3) if host else 0,
        "longest_label": max((len(p) for p in parts), default=0),
        "entropy": round(entropy(main), 3),
        "is_ip": is_ip,
        "risky_tld": int(tld in RISKY_TLDS),
        "has_at": has_at_symbol(url),
        "fake_brand": fake_brand,
        "has_punycode": int("xn--" in host),
        "is_shortener": int(registered in SHORTENERS),
        "free_hosting": int(any(host.endswith("." + d) for d in FREE_HOSTING)),
    }


if __name__ == "__main__":
    tests = [
        "https://google.com",
        "https://rb.gy/28wrls",
        "https://manuelabritto.github.io/azul-atual/",
        "http://paypal-login.xyz/verify",
    ]
    for t in tests:
        print(t)
        print("  ->", extract_features(t))