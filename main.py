from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from analyze import analyze
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
    return scan_to_dict(scan)

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