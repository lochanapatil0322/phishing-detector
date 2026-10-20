from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from analyze import analyze

app = FastAPI(title="Phishing Detector API")

# Allow the React website (running on port 5173) to talk to this server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class UrlRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {"message": "Phishing Detector API is running"}


@app.post("/analyze/url")
def analyze_url(req: UrlRequest):
    url = req.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="Please enter a URL")
    if len(url) > 2000:
        raise HTTPException(status_code=400, detail="URL is too long")

    try:
        return analyze(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Could not analyze this URL")