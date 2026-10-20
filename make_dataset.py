import pandas as pd

# 1. Load the phishing links
phish = pd.read_csv("data/verified_online.csv")
phish = phish[["url"]].drop_duplicates()          # keep only the url column, remove repeats

n = min(5000, len(phish))                          # use up to 5000 links
phish = phish.sample(n=n, random_state=42)         # pick random ones
phish["label"] = 1                                 # 1 = phishing

# 2. Load the safe links
safe = pd.read_csv("data/top-1m.csv", header=None, names=["rank", "domain"])

safe = safe.sample(n=n, random_state=42)           # same number as phishing
import random
rng = random.Random(42)
subs = ["www", "mail", "login", "accounts", "support", "blog", "shop", "app", "docs", "help"]

def add_subdomain(domain):
    # 40% of safe links get a common subdomain, like real websites do
    if rng.random() < 0.4:
        return "https://" + rng.choice(subs) + "." + domain
    return "https://" + domain

safe["url"] = safe["domain"].apply(add_subdomain)
safe["label"] = 0                                  # 0 = safe

# 3. Join and shuffle
df = pd.concat([phish[["url", "label"]], safe[["url", "label"]]])
df = df.sample(frac=1, random_state=42)

# 4. Save
df.to_csv("data/dataset.csv", index=False)
print("Done! Rows:", len(df))
print(df["label"].value_counts())