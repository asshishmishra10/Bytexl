
from pathlib import Path

import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = Path(__file__).resolve().parent

train_path = DATA_DIR / "train.csv"
if not train_path.exists():
    train_path = MODEL_DIR / "Instagram fake" / "train.csv"

test_path = DATA_DIR / "test.csv"
if not test_path.exists():
    test_path = MODEL_DIR / "Instagram fake" / "test.csv"

train_df = pd.read_csv(train_path)
test_df = pd.read_csv(test_path)


target = "fake"

X_train = train_df.drop(columns=[target])
y_train = train_df[target]

X_test = test_df.drop(columns=[target])
y_test = test_df[target]


model = XGBClassifier(
    n_estimators=200,
    max_depth=4,
    learning_rate=0.05,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
)


print("Training started...")
model.fit(X_train, y_train)


predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n===== MODEL RESULTS =====")
print(f"Accuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Genuine", "Fake"],
        zero_division=0,
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

model_path = MODEL_DIR / "social_xgb_model.json"
model.save_model(str(model_path))

print(f"\nModel saved successfully at:\n{model_path}")
