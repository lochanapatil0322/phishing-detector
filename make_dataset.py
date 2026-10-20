import pandas as pd

# 1. Load the phishing links
phish = pd.read_csv("data/verified_online.csv")
phish = phish[["url"]].drop_duplicates()          # keep only the url column, remove repeats

n = min(5000, len(phish))                          # use up to 5000 links
phish = phish.sample(n=n, random_state=42)         # pick random ones
phish["label"] = 1                                 # 1 = phishing

# 2. Load the safe links
safe = pd.read_csv("data/top-1m.csv", header=None, names=["rank", "domain"])
safe = safe.head(50000)                            # take from the top 50,000 sites
safe = safe.sample(n=n, random_state=42)           # same number as phishing
safe["url"] = "https://" + safe["domain"]          # turn "google.com" into "https://google.com"
safe["label"] = 0                                  # 0 = safe

# 3. Join and shuffle
df = pd.concat([phish[["url", "label"]], safe[["url", "label"]]])
df = df.sample(frac=1, random_state=42)

# 4. Save
df.to_csv("data/dataset.csv", index=False)
print("Done! Rows:", len(df))
print(df["label"].value_counts())