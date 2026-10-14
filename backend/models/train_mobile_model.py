
from pathlib import Path

import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.preprocessing import LabelEncoder


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = Path(__file__).resolve().parent

TRAIN_PATH = DATA_DIR / "mobile_apps" / "train" / "train.csv"
TEST_PATH = DATA_DIR / "mobile_apps" / "test" / "test.csv"


print("Loading mobile app training and testing data...")

if not TRAIN_PATH.exists() or not TEST_PATH.exists():
    print(f"[-] Training or testing dataset not found:\n    - {TRAIN_PATH}\n    - {TEST_PATH}")
    print("[!] Pre-trained mobile model artifacts (mobile_xgb.json) already exist in models/.")
    print("[!] To retrain from scratch, please place mobile_apps.csv per data/mobile_apps/README.md and run prepare_mobile_data.py first.")
    raise SystemExit(0)

train_df = pd.read_csv(TRAIN_PATH, low_memory=False)
test_df = pd.read_csv(TEST_PATH, low_memory=False)


target = "class"

X_train = train_df.drop(columns=[target])
y_train = train_df[target]

X_test = test_df.drop(columns=[target])
y_test = test_df[target]


X_train = X_train.apply(pd.to_numeric, errors="coerce")
X_test = X_test.apply(pd.to_numeric, errors="coerce")


medians = X_train.median().fillna(0)
X_train = X_train.fillna(medians)
X_test = X_test.fillna(medians)


encoder = LabelEncoder()
y_train = encoder.fit_transform(y_train)
y_test = encoder.transform(y_test)

print("Training rows:", len(X_train))
print("Testing rows:", len(X_test))
print("Labels:", list(encoder.classes_))

model = XGBClassifier(
    n_estimators=100,
    max_depth=5,
    learning_rate=0.1,
    objective="binary:logistic",
    eval_metric="logloss",
    tree_method="hist",
    random_state=42,
    n_jobs=2,
)


print("\nTraining started...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\n===== MOBILE APP MODEL RESULTS =====")
print(f"Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=list(encoder.classes_),
        zero_division=0,
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

model_path = MODEL_DIR / "mobile_xgb_model.json"
model.save_model(str(model_path))

mapping_path = MODEL_DIR / "mobile_label_mapping.txt"
mapping_path.write_text(
    "\n".join(
        f"{index} = {label}"
        for index, label in enumerate(encoder.classes_)
    ),
    encoding="utf-8",
)

print("\nModel saved:", model_path)
print("Label mapping saved:", mapping_path)
