import sys
from datetime import datetime, timezone

import pandas as pd

from database import SessionLocal, engine, Base
import models
from threat_feed import normalize_url, url_hash

Base.metadata.create_all(bind=engine)

if len(sys.argv) < 3:
    print("Usage: python load_feed.py <file> <SourceName>")
    print("Example: python load_feed.py data/online-valid.csv PhishTank")
    sys.exit(1)

path, source = sys.argv[1], sys.argv[2][:30]

# 1. Read the URLs
if path.lower().endswith((".csv", ".bz2")):
    df = pd.read_csv(path)
    column = "url" if "url" in df.columns else df.columns[0]
    urls = df[column].dropna().astype(str).tolist()
else:
    with open(path, encoding="utf-8", errors="ignore") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

# 2. Clean and remove duplicates
now = datetime.now(timezone.utc).replace(tzinfo=None)
rows, seen = [], set()
for u in urls:
    host, key = normalize_url(u)
    if not key or len(u) > 2000:
        continue
    h = url_hash(key)
    if h in seen:
        continue
    seen.add(h)
    rows.append({"url_hash": h, "url": u, "host": host[:255], "source": source, "added_at": now})

# 3. Replace this source's old entries with the new list
db = SessionLocal()
try:
    removed = db.query(models.ThreatEntry).filter(models.ThreatEntry.source == source).delete()
    for i in range(0, len(rows), 5000):
        db.bulk_insert_mappings(models.ThreatEntry, rows[i:i + 5000])
    db.commit()
    print(f"{source}: removed {removed} old entries, loaded {len(rows)} entries")
finally:
    db.close()