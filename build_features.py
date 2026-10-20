import pandas as pd
from url_features import extract_features

# 1. Load the dataset we made
df = pd.read_csv("data/dataset.csv")

# 2. Calculate the features for every link
features = df["url"].apply(extract_features).apply(pd.Series)

# 3. Put everything together: link + numbers + label
out = pd.concat([df[["url"]], features, df[["label"]]], axis=1)

# 4. Save
out.to_csv("data/features.csv", index=False)

# 5. Show a few rows, and the average numbers for each group
print(out.head())
print()
print("Average of each feature (0 = safe, 1 = phishing):")
print(out.groupby("label").mean(numeric_only=True))