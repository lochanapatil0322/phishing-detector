import json
from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta, timezone, time as dt_time
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from analyze import analyze
from threat_feed import lookup_exact, lookup_host, feed_stats
from domain_age import get_domain_age, age_level
from ratelimit import check_rate
from url_features import get_hostname
from mailer import send_email
from otp import create_reset_code, reset_password_with_code
from email_analyze import analyze_email
from database import engine, Base, get_db
from auth import (hash_password, verify_password, DUMMY_HASH,
                  create_access_token, get_current_user)
import models

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Phishing Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Input shapes ----------
class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=64)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=64)

class ForgotRequest(BaseModel):
    email: EmailStr


class ResetRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^\d{6}$")
    new_password: str = Field(min_length=8, max_length=64)

class UrlRequest(BaseModel):
    url: str
class EmailRequest(BaseModel):
    raw: str = Field(min_length=1, max_length=500000)


# ---------- Helpers ----------
def user_to_dict(user):
    return {"id": user.id, "name": user.name, "email": user.email}


def scan_to_dict(scan):
    return {
        "id": scan.id,
        "type": scan.input_type,
        "url": scan.input_text,
        "verdict": scan.verdict,
        "score": scan.score,
        "reasons": [r.reason_text for r in scan.reasons],
        "created_at": scan.created_at.isoformat() + "Z",
    }


# ---------- Public routes ----------
@app.get("/")
def home():
    return {"message": "Phishing Detector API is running"}


@app.post("/auth/register", status_code=201)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    email = req.email.lower()
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    user = models.User(
        name=req.name.strip(),
        email=email,
        password_hash=hash_password(req.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"token": create_access_token(user.id), "user": user_to_dict(user)}


@app.post("/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    email = req.email.lower()
    user = db.query(models.User).filter(models.User.email == email).first()

    # Same error for "no such email" and "wrong password"
    bad_login = HTTPException(status_code=401, detail="Invalid email or password")
    if user is None:
        verify_password(req.password, DUMMY_HASH)
        raise bad_login
    if not verify_password(req.password, user.password_hash):
        raise bad_login

    return {"token": create_access_token(user.id), "user": user_to_dict(user)}

@app.post("/auth/forgot-password")
def forgot_password(
    req: ForgotRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
):
    email = req.email.lower()
    user = db.query(models.User).filter(models.User.email == email).first()

    if user:
        code = create_reset_code(db, user)
        if code:
            body = (
                f"Your PhishGuard password reset code is: {code}\n\n"
                "It expires in 10 minutes and works only once.\n"
                "If you did not ask for this, ignore this email. "
                "Your password has not been changed.\n"
            )
            background.add_task(send_email, user.email, "Your PhishGuard reset code", body)

    # Same answer whether or not the account exists
    return {"message": "If an account exists for that email, a 6-digit code has been sent."}


@app.post("/auth/reset-password")
def reset_password(req: ResetRequest, db: Session = Depends(get_db)):
    ok = reset_password_with_code(db, req.email.lower(), req.code, req.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    return {"message": "Password updated. You can log in now."}

# ---------- Protected routes (login required) ----------
@app.get("/auth/me")
def me(user: models.User = Depends(get_current_user)):
    return user_to_dict(user)


@app.post("/analyze/url")
def analyze_url(
    req: UrlRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_rate(f"scan:{user.id}", 30, 60)      # at most 30 scans per minute per user

    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Please enter a URL")
    if len(url) > 2000:
        raise HTTPException(status_code=400, detail="URL is too long")

    try:
        result = analyze(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Could not analyze this URL")

    scan = models.Scan(
        user_id=user.id,
        input_type="url",
        input_text=result["url"],
        verdict=result["verdict"],
        score=result["score"],
    )
    scan.reasons = [models.ScanReason(reason_text=r) for r in result["reasons"]]
    db.add(scan)
    db.commit()
    db.refresh(scan)

    saved = scan_to_dict(scan)
    saved["signals"] = result.get("signals", [])
    return saved

@app.post("/analyze/email")
def analyze_email_route(
    req: EmailRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    try:
        result = analyze_email(req.raw)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Could not read this email. Paste the full email text or upload a .eml file.",
        )

    # We store only the subject and sender, never the whole email
    label = f"{result['subject'] or '(no subject)'} (from {result['sender']})"[:300]

    scan = models.Scan(
        user_id=user.id,
        input_type="email",
        input_text=label,
        verdict=result["verdict"],
        score=result["score"],
    )
    scan.reasons = [models.ScanReason(reason_text=r) for r in result["reasons"]]
    db.add(scan)
    db.commit()
    db.refresh(scan)

    saved = scan_to_dict(scan)
    saved["subject"] = result["subject"]
    saved["sender"] = result["sender"]
    saved["auth"] = result["auth"]
    saved["links"] = result["links"]
    return saved

@app.get("/scans")
def list_scans(
    limit: int = 50,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    limit = max(1, min(limit, 200))
    scans = (
        db.query(models.Scan)
        .filter(models.Scan.user_id == user.id)      # only MY scans
        .order_by(models.Scan.id.desc())
        .limit(limit)
        .all()
    )
    return [scan_to_dict(s) for s in scans]


@app.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    rows = (
        db.query(models.Scan.verdict, func.count(models.Scan.id))
        .filter(models.Scan.user_id == user.id)      # only MY scans
        .group_by(models.Scan.verdict)
        .all()
    )
    counts = {verdict: count for verdict, count in rows}
    return {
        "total": sum(counts.values()),
        "safe": counts.get("Safe", 0),
        "suspicious": counts.get("Suspicious", 0),
        "phishing": counts.get("Phishing", 0),
    }
# ---------- Model info, account settings ----------
class ChangePasswordRequest(BaseModel):
    current_password: str = Field(max_length=64)
    new_password: str = Field(min_length=8, max_length=64)


class DeleteAccountRequest(BaseModel):
    password: str = Field(max_length=64)


@app.get("/model/metrics")
def model_metrics(user: models.User = Depends(get_current_user)):
    path = Path(__file__).parent / "model_metrics.json"
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail="Model metrics have not been generated yet. Run: python evaluate_model.py",
        )
    return json.loads(path.read_text())


@app.post("/auth/change-password")
def change_password(
    req: ChangePasswordRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if not verify_password(req.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if req.new_password == req.current_password:
        raise HTTPException(status_code=400, detail="New password must be different from the current one")

    user.password_hash = hash_password(req.new_password)
    db.commit()
    return {"message": "Password changed successfully"}


@app.delete("/scans")
def clear_history(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    scans = db.query(models.Scan).filter(models.Scan.user_id == user.id).all()
    for scan in scans:
        db.delete(scan)          # its reasons are deleted automatically
    db.commit()
    return {"message": f"Deleted {len(scans)} scans"}


@app.post("/auth/delete-account")
def delete_account(
    req: DeleteAccountRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect password")

    for scan in db.query(models.Scan).filter(models.Scan.user_id == user.id).all():
        db.delete(scan)
    db.flush()
    db.query(models.PasswordReset).filter(models.PasswordReset.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    return {"message": "Account deleted"}
# ---------- Threat feed and domain lookup ----------
class CheckUrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2000)


class DomainRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=300)


@app.get("/threat/stats")
def threat_stats(user: models.User = Depends(get_current_user)):
    return feed_stats()


@app.post("/threat/check")
def threat_check(req: CheckUrlRequest, user: models.User = Depends(get_current_user)):
    check_rate(f"lookup:{user.id}", 40, 60)
    url = req.url.strip()
    if "://" not in url:
        url = "http://" + url
    host = get_hostname(url)
    return {
        "url": url,
        "host": host,
        "exact": lookup_exact(url),
        "domain": lookup_host(host) if host else None,
    }


@app.post("/domain/lookup")
def domain_lookup(req: DomainRequest, user: models.User = Depends(get_current_user)):
    check_rate(f"lookup:{user.id}", 40, 60)
    raw = req.domain.strip()
    if "://" not in raw:
        raw = "http://" + raw
    host = get_hostname(raw)
    info = get_domain_age(host)
    if info is None:
        raise HTTPException(status_code=400, detail="Enter a valid website name, like example.com")
    info["host"] = host
    info["level"] = age_level(info["age_days"])
    return info
# ---------- Dashboard charts ----------
# Each reason sentence is grouped under a short label (first match wins)
FLAG_LABELS = [
    ("exact link is listed", "Listed in phishing database"),
    ("website has", "Website hosts listed phishing pages"),
    ("registered", "Newly registered domain"),
    ("not encrypted", "No encryption (http)"),
    ("link shortener", "Link shortener"),
    ("free website platform", "Free hosting platform"),
    ("domain ending", "Risky domain ending"),
    ("famous brand", "Fake brand name"),
    ("raw ip", "Raw IP address"),
    ("'@'", "'@' redirect trick"),
    ("look-alike", "Look-alike characters"),
    ("many hyphens", "Many hyphens"),
    ("chain of subdomains", "Long subdomain chain"),
    ("unusually long", "Very long website name"),
    ("many digits", "Many digits in name"),
    ("looks random", "Random-looking name"),
    ("overall pattern", "Matches known phishing patterns"),
    ("spf check", "SPF check failed"),
    ("dkim check", "DKIM check failed"),
    ("dmarc check", "DMARC check failed"),
    ("replies go to", "Reply-To mismatch"),
    ("sender name mentions", "Sender name impersonation"),
    ("urgent or threatening", "Urgent or threatening wording"),
    ("generic greeting", "Generic greeting"),
    ("risky attachment", "Risky attachment"),
    ("claims to go to", "Misleading link text"),
    ("look like phishing links", "Phishing links inside emails"),
    ("look suspicious", "Suspicious links inside emails"),
]


def _flag_label(text):
    t = text.lower()
    for key, label in FLAG_LABELS:
        if key in t:
            return label
    return text[:60]


@app.get("/stats/trend")
def stats_trend(
    days: int = 7,
    tz: int = 0,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """Scans per day, split by verdict. `tz` = the browser's offset from UTC in minutes."""
    days = max(1, min(days, 30))
    tz = max(-840, min(tz, 840))
    offset = timedelta(minutes=tz)

    now_local = datetime.now(timezone.utc).replace(tzinfo=None) + offset
    first_day = now_local.date() - timedelta(days=days - 1)
    start_utc = datetime.combine(first_day, dt_time.min) - offset

    rows = (
        db.query(models.Scan.created_at, models.Scan.verdict)
        .filter(models.Scan.user_id == user.id, models.Scan.created_at >= start_utc)
        .limit(20000)
        .all()
    )

    buckets = {
        first_day + timedelta(days=i): {"Safe": 0, "Suspicious": 0, "Phishing": 0}
        for i in range(days)
    }
    for created_at, verdict in rows:
        local_day = (created_at.replace(tzinfo=None) + offset).date()
        if local_day in buckets and verdict in buckets[local_day]:
            buckets[local_day][verdict] += 1

    return [{"date": d.isoformat(), **counts} for d, counts in buckets.items()]


@app.get("/stats/top-reasons")
def top_reasons(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """The most common red flags across this user's Suspicious and Phishing scans."""
    rows = (
        db.query(models.ScanReason.reason_text)
        .join(models.Scan, models.ScanReason.scan_id == models.Scan.id)
        .filter(models.Scan.user_id == user.id, models.Scan.verdict != "Safe")
        .limit(5000)
        .all()
    )
    counts = Counter(
        _flag_label(r[0]) for r in rows if not r[0].lower().startswith("note:")
    )
    return [{"label": label, "count": n} for label, n in counts.most_common(6)]