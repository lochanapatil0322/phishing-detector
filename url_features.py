import re
from urllib.parse import urlparse

# Endings often used in cheap or free domains that attackers like
RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link",
              "work", "support", "online", "site", "club", "buzz", "icu",
              "cyou", "rest", "monster"}

# Brands that attackers like to imitate
BRANDS = ["paypal", "amazon", "google", "apple", "microsoft", "facebook",
          "instagram", "netflix", "whatsapp", "linkedin", "hdfc", "icici",
          "paytm", "dhl", "fedex", "outlook", "dropbox", "binance", "coinbase"]

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def get_hostname(url):
    """'https://paypal-login.xyz/verify' -> 'paypal-login.xyz'"""
    try:
        host = urlparse(url).hostname
    except ValueError:
        host = None
    return host or ""


def has_at_symbol(url):
    """Checks for the '@' trick: http://google.com@evil.com goes to evil.com"""
    try:
        return int("@" in urlparse(url).netloc)
    except ValueError:
        return 0


def extract_features(url):
    host = get_hostname(url)
    parts = host.split(".")
    tld = parts[-1] if len(parts) > 1 else ""         # the ending, like 'com' or 'xyz'
    main = parts[-2] if len(parts) >= 2 else host     # the main name, like 'paypal'
    is_ip = int(bool(IP_PATTERN.match(host)))

    # fake_brand = 1 when a brand name appears, but the real site is NOT that brand
    # 'paypal.com' -> 0 (real), 'paypal-login.xyz' -> 1 (suspicious)
    fake_brand = int(any(b in host and b != main for b in BRANDS))

    return {
        "host_length": len(host),
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "num_subdomains": 0 if is_ip else max(len(parts) - 2, 0),
        "num_digits": sum(c.isdigit() for c in host),
        "is_ip": is_ip,
        "risky_tld": int(tld in RISKY_TLDS),
        "has_at": has_at_symbol(url),
        "fake_brand": fake_brand,
        "has_punycode": int("xn--" in host),   # trick to imitate foreign letters
    }


if __name__ == "__main__":
    tests = [
        "https://google.com",
        "http://paypal-login.xyz/verify",
        "http://192.168.1.1/login",
    ]
    for t in tests:
        print(t)
        print("  ->", extract_features(t))