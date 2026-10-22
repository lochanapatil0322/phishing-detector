import re
from datetime import datetime, timedelta, timezone

import requests
import tldextract

from database import SessionLocal, engine, Base
import models

Base.metadata.create_all(bind=engine)

# Uses the list of domain endings bundled with the library, with no network call
_extract = tldextract.TLDExtract(suffix_list_urls=())

RDAP_URL = "https://rdap.org/domain/"
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$")


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def age_points(days):
    """Extra risk points for very new domains."""
    if days is None:
        return 0
    if days < 7:
        return 30
    if days < 30:
        return 20
    if days < 90:
        return 8
    return 0


def age_level(days):
    if days is None:
        return "unknown"
    if days < 30:
        return "high"
    if days < 90:
        return "medium"
    return "low"


def _fetch_created(domain):
    """Ask RDAP when the domain was registered. Returns a datetime or None."""
    try:
        r = requests.get(
            RDAP_URL + domain,
            timeout=4,
            headers={"Accept": "application/rdap+json"},
            allow_redirects=True,
        )
        if r.status_code != 200:
            return None
        data = r.json()
    except (requests.RequestException, ValueError):
        return None

    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            try:
                text = event["eventDate"].replace("Z", "+00:00")
                dt = datetime.fromisoformat(text)
                if dt.tzinfo:
                    dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt
            except (KeyError, ValueError):
                return None
    return None


def _result(domain, created, cached, now):
    age = max((now - created).days, 0) if created else None
    return {
        "domain": domain,
        "created": created.date().isoformat() if created else None,
        "age_days": age,
        "cached": cached,
    }


def get_domain_age(host):
    """Returns {'domain', 'created', 'age_days', 'cached'} or None if the host is not a valid domain."""
    host = (host or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(host):
        return None                      # IP addresses and junk are rejected here

    ext = _extract(host)
    if not ext.domain or not ext.suffix:
        return None
    domain = f"{ext.domain}.{ext.suffix}"

    now = _now()
    db = SessionLocal()
    try:
        row = db.query(models.DomainCache).filter(models.DomainCache.domain == domain).first()
        if row:
            fresh_for = timedelta(days=7) if row.created_date else timedelta(hours=24)
            if now - row.checked_at < fresh_for:
                return _result(domain, row.created_date, True, now)

        created = _fetch_created(domain)
        try:
            if row:
                row.created_date = created
                row.checked_at = now
            else:
                db.add(models.DomainCache(domain=domain, created_date=created, checked_at=now))
            db.commit()
        except Exception:
            db.rollback()
        return _result(domain, created, False, now)
    finally:
        db.close()