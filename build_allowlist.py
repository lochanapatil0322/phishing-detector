import pandas as pd

df = pd.read_csv("data/top-1m.csv", header=None, names=["rank", "domain"])
df.head(10000)["domain"].to_csv("data/allowlist.txt", index=False, header=False)
print("Saved top 10,000 trusted domains to data/allowlist.txt")