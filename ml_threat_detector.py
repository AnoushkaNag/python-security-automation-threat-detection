"""Machine-learning threat detector trained on the UCI Phishing Websites dataset.

Loads the dataset (downloading it first if needed), preprocesses it,
trains a supervised RandomForestClassifier to classify websites as
phishing or legitimate, and separately trains an unsupervised
IsolationForest to flag anomalies -- treating the minority class
(phishing) as the anomaly class -- for comparison. Uses only pandas and
scikit-learn.
"""

import os

import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from download_dataset import DATA_PATH, download_dataset

# In the UCI Phishing Websites dataset, `result` is the target column:
# -1 = phishing website, 1 = legitimate website (Mohammad et al., 2015).
TARGET_COLUMN = "result"
PHISHING_LABEL = -1
LEGITIMATE_LABEL = 1


def load_dataset():
    """Load the dataset with pandas, downloading it first if not cached."""
    if not os.path.exists(DATA_PATH):
        print(f"Dataset not found at {DATA_PATH}; downloading from UCI...")
        download_dataset()
    return pd.read_csv(DATA_PATH)


def preprocess(df):
    """Inspect, clean, and deduplicate the dataset. Returns the cleaned df
    plus the null-row and duplicate-row counts that were removed."""
    print("\n--- First 5 rows ---")
    print(df.head())

    print("\n--- Class distribution (raw) ---")
    print(df[TARGET_COLUMN].value_counts())

    null_row_count = int(df.isnull().any(axis=1).sum())
    df = df.dropna()
    print(f"\nRows dropped for containing null values: {null_row_count}")

    # Encode any non-numeric/categorical feature columns with LabelEncoder.
    # The UCI Phishing Websites dataset ships fully numeric (-1/0/1)
    # features, so this is a no-op here, but keeps the pipeline correct
    # for any dataset variant that does carry categorical columns.
    categorical_cols = df.select_dtypes(include="object").columns.tolist()
    for col in categorical_cols:
        df[col] = LabelEncoder().fit_transform(df[col])
    if categorical_cols:
        print(f"Encoded categorical columns: {categorical_cols}")
    else:
        print("No categorical feature columns found; no encoding needed.")

    duplicate_row_count = int(df.duplicated().sum())
    df = df.drop_duplicates()
    print(f"Duplicate rows detected and removed: {duplicate_row_count}")

    return df, null_row_count, duplicate_row_count


def split_data(df):
    """80/20 train/test split, stratified on the binary target for
    balanced class representation in both splits."""
    X = df.drop(columns=[TARGET_COLUMN])
    y = df[TARGET_COLUMN]
    return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)


def train_random_forest(X_train, y_train):
    # Default hyperparameters only, per assignment requirement -- the sole
    # non-default argument is random_state, set purely for reproducibility
    # and not as tuning.
    clf = RandomForestClassifier(random_state=42)
    clf.fit(X_train, y_train)
    return clf


def evaluate_random_forest(clf, X_test, y_test):
    y_pred = clf.predict(X_test)
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, pos_label=PHISHING_LABEL),
        "recall": recall_score(y_test, y_pred, pos_label=PHISHING_LABEL),
        "f1": f1_score(y_test, y_pred, pos_label=PHISHING_LABEL),
    }
    report = classification_report(
        y_test,
        y_pred,
        labels=[PHISHING_LABEL, LEGITIMATE_LABEL],
        target_names=["phishing(-1)", "legitimate(1)"],
    )
    return metrics, report


def train_isolation_forest(X_train):
    # IsolationForest is UNSUPERVISED: it is fit on the training features
    # only, with no access to y_train whatsoever. The labels are used
    # afterwards, in evaluate_isolation_forest, purely to score how well
    # the anomalies it finds line up with the real phishing/legitimate
    # split -- this does not make the model itself supervised.
    iso = IsolationForest(random_state=42)
    iso.fit(X_train)
    return iso


def _minority_and_majority_labels(y_train):
    counts = y_train.value_counts()
    return counts.idxmin(), counts.idxmax()


def evaluate_isolation_forest_accuracy(iso, X_test, y_test, y_train):
    """Map IsolationForest's inlier/anomaly output onto the real class
    labels and compute anomaly-detection accuracy against y_test."""
    raw_pred = iso.predict(X_test)  # IsolationForest output: 1 = inlier, -1 = anomaly

    # Explicit minority-class-as-anomaly mapping, derived from the actual
    # training label distribution rather than hardcoded: whichever class
    # is the minority in y_train is treated as the "anomaly" class, and
    # IsolationForest's -1/1 output is mapped onto it accordingly.
    minority_label, majority_label = _minority_and_majority_labels(y_train)
    mapping = {-1: minority_label, 1: majority_label}
    mapped_pred = pd.Series(raw_pred, index=X_test.index).map(mapping)
    accuracy = accuracy_score(y_test, mapped_pred)
    return accuracy, mapping


def main():
    df = load_dataset()
    df, null_row_count, duplicate_row_count = preprocess(df)

    X_train, X_test, y_train, y_test = split_data(df)

    rf = train_random_forest(X_train, y_train)
    rf_metrics, rf_report = evaluate_random_forest(rf, X_test, y_test)

    print("\n--- Random Forest results (test set) ---")
    print(f"Accuracy:  {rf_metrics['accuracy']:.4f}")
    print(f"Precision: {rf_metrics['precision']:.4f}")
    print(f"Recall:    {rf_metrics['recall']:.4f}")
    print(f"F1 score:  {rf_metrics['f1']:.4f}")
    print("\nFull classification report:")
    print(rf_report)

    iso = train_isolation_forest(X_train)
    iso_accuracy, mapping = evaluate_isolation_forest_accuracy(iso, X_test, y_test, y_train)

    print("\n--- Isolation Forest results (test set) ---")
    print(f"Anomaly-label mapping (IsolationForest output -> class label): {mapping}")
    print(f"Anomaly detection accuracy: {iso_accuracy:.4f}")


if __name__ == "__main__":
    main()
