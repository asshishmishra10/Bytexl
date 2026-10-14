from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = Path(__file__).resolve().parent

CSV_PATH = (
    DATA_DIR / "mobile_apps"
    / "Original" / "mobile_apps.csv"
)

TRAIN_DIR = DATA_DIR / "mobile_apps" / "train"
TEST_DIR = DATA_DIR / "mobile_apps" / "test"

print("Loading mobile app dataset...")

if not CSV_PATH.exists():
    print(f"ERROR: Original mobile apps CSV file not found at: {CSV_PATH}")
    print("Please place the source dataset at data/mobile_apps/Original/mobile_apps.csv")
    raise SystemExit(1)


df = pd.read_csv(CSV_PATH, low_memory=False)


if "class" not in df.columns:
    print("ERROR: Target 'class' label column not found in dataset.")
    raise SystemExit(1)


df = df.dropna(subset=["class"]).copy()


df = df[df["class"].isin(["B", "S"])].copy()

print("\nOriginal dataset loaded!")
print("Total apps:", len(df))
print("\nClass distribution:")
print(df["class"].value_counts())


train_df, test_df = train_test_split(
    df,
    test_size=0.20,
    random_state=42,
    stratify=df["class"]
)


TRAIN_DIR.mkdir(parents=True, exist_ok=True)
TEST_DIR.mkdir(parents=True, exist_ok=True)


train_df.to_csv(TRAIN_DIR / "train.csv", index=False)
test_df.to_csv(TEST_DIR / "test.csv", index=False)

print("\n===== SPLIT COMPLETE =====")
print("Training apps:", len(train_df))
print("Testing apps:", len(test_df))

print("\nTraining labels:")
print(train_df["class"].value_counts())

print("\nTesting labels:")
print(test_df["class"].value_counts())

print("\nFiles saved successfully!")
print("Training file:", TRAIN_DIR / "train.csv")
print("Testing file:", TEST_DIR / "test.csv")
