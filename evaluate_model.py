import json
from datetime import datetime, timezone

import joblib
import pandas as pd
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split

saved = joblib.load("model.pkl")
model = saved["model"]
columns = saved["columns"]

df = pd.read_csv("data/features.csv")
X, y = df[columns], df["label"]

# The same split as train_model.py (same random_state), so this is the sealed test set
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

pred = model.predict(X_test)
tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()

importance = sorted(
    zip(columns, model.feature_importances_), key=lambda p: p[1], reverse=True
)

metrics = {
    "model": f"Random Forest ({model.n_estimators} trees)",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "n_train": int(len(X_train)),
    "n_test": int(len(X_test)),
    "n_features": len(columns),
    "accuracy": float(accuracy_score(y_test, pred)),
    "precision": float(precision_score(y_test, pred)),
    "recall": float(recall_score(y_test, pred)),
    "f1": float(f1_score(y_test, pred)),
    "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    "importance": [{"feature": f, "value": round(float(v), 4)} for f, v in importance],
}

with open("model_metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)

print("Saved model_metrics.json")
print(f"Accuracy {metrics['accuracy']:.4f} | Precision {metrics['precision']:.4f} | "
      f"Recall {metrics['recall']:.4f} | F1 {metrics['f1']:.4f}")