from urllib.parse import urlparse


def get_hostname(url):
    """Return just the website name from a link. 
    Example: 'https://paypal-login.xyz/verify' -> 'paypal-login.xyz'"""
    try:
        host = urlparse(url).hostname
    except ValueError:
        host = None
    return host or ""


def extract_features(url):
    """Turn one link into a few numbers."""
    host = get_hostname(url)
    return {
        "host_length": len(host),          # how many characters in the website name
        "num_dots": host.count("."),       # how many dots
        "num_hyphens": host.count("-"),    # how many hyphens
    }


# This part only runs when you run this file directly, for testing
if __name__ == "__main__":
    tests = [
        "https://google.com",
        "http://paypal-login.xyz/verify",
        "http://secure-paypal-login.verify-account.example.tk/x",
    ]
    for t in tests:
        print(t)
        print("  ->", extract_features(t))