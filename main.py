from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from analyze import analyze
from database import engine, Base, get_db
import models

# Create the tables in phishing.db if they don't exist yet
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Phishing Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class UrlRequest(BaseModel):
    url: str


def scan_to_dict(scan):
    """Turn a database row into a dictionary the website can read."""
    return {
        "id": scan.id,
        "url": scan.input_text,
        "verdict": scan.verdict,
        "score": scan.score,
        "reasons": [r.reason_text for r in scan.reasons],
        "created_at": scan.created_at.isoformat() + "Z",
    }


@app.get("/")
def home():
    return {"message": "Phishing Detector API is running"}


@app.post("/analyze/url")
def analyze_url(req: UrlRequest, db: Session = Depends(get_db)):
    url = req.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="Please enter a URL")
    if len(url) > 2000:
        raise HTTPException(status_code=400, detail="URL is too long")

    try:
        result = analyze(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Could not analyze this URL")

    # Save the scan, then its reasons
    scan = models.Scan(
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


@app.get("/scans")
def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    """History: newest scans first."""
    limit = max(1, min(limit, 200))
    scans = db.query(models.Scan).order_by(models.Scan.id.desc()).limit(limit).all()
    return [scan_to_dict(s) for s in scans]


@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Numbers for the dashboard."""
    rows = (
        db.query(models.Scan.verdict, func.count(models.Scan.id))
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