import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix)

# 1. Load the numbers
df = pd.read_csv("data/features.csv")
X = df.drop(columns=["url", "label"])   # the numbers the model looks at
y = df["label"]                         # the correct answers (0 or 1)

# 2. Split: 80% to learn from, 20% sealed for testing
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 3. Train the model
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# 4. Test it on the sealed 20%
pred = model.predict(X_test)
print("Accuracy :", round(accuracy_score(y_test, pred), 4))
print("Precision:", round(precision_score(y_test, pred), 4))
print("Recall   :", round(recall_score(y_test, pred), 4))
print("F1 score :", round(f1_score(y_test, pred), 4))
print()
print("Confusion matrix:")
print(confusion_matrix(y_test, pred))

# 5. Which features mattered most?
print()
print("Feature importance:")
importance = pd.Series(model.feature_importances_, index=X.columns)
print(importance.sort_values(ascending=False).round(3))

# 6. Save the model and the feature order
joblib.dump({"model": model, "columns": list(X.columns)}, "model.pkl")
print()
print("Saved model.pkl")