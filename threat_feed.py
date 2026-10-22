import hashlib
from urllib.parse import urlparse

from sqlalchemy import func

from database import SessionLocal, engine, Base
import models

Base.metadata.create_all(bind=engine)


def normalize_url(url):
    """'HTTPS://Evil.com/Login/?a=1#top' -> ('evil.com', 'evil.com/Login?a=1')
    Scheme, port and fragment are ignored, so http and https versions match."""
    url = (url or "").strip()
    if "://" not in url:
        url = "http://" + url
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return "", ""
    if not host:
        return "", ""
    key = host + p.path.rstrip("/") + ("?" + p.query if p.query else "")
    return host, key


def url_hash(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def lookup_exact(url):
    """Is this exact link in the feed?"""
    host, key = normalize_url(url)
    if not key:
        return None
    db = SessionLocal()
    try:
        row = (
            db.query(models.ThreatEntry)
            .filter(models.ThreatEntry.url_hash == url_hash(key))
            .first()
        )
        if row:
            return {"source": row.source, "added_at": row.added_at.isoformat() + "Z"}
        return None
    finally:
        db.close()


def lookup_host(host):
    """How many feed entries are on this website name?"""
    host = (host or "").lower()
    if not host:
        return None
    db = SessionLocal()
    try:
        rows = (
            db.query(models.ThreatEntry.source, func.count(models.ThreatEntry.id))
            .filter(models.ThreatEntry.host == host)
            .group_by(models.ThreatEntry.source)
            .all()
        )
        if not rows:
            return None
        return {"source": rows[0][0], "count": sum(c for _, c in rows)}
    finally:
        db.close()


def feed_stats():
    db = SessionLocal()
    try:
        rows = (
            db.query(
                models.ThreatEntry.source,
                func.count(models.ThreatEntry.id),
                func.max(models.ThreatEntry.added_at),
            )
            .group_by(models.ThreatEntry.source)
            .all()
        )
        return {
            "total": sum(r[1] for r in rows),
            "sources": [
                {"source": r[0], "count": r[1],
                 "updated": r[2].isoformat() + "Z" if r[2] else None}
                for r in rows
            ],
        }
    finally:
        db.close()