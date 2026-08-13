"""Download script for the UCI 'Phishing Websites' dataset (id=327).

Fetches the dataset directly from the UCI Machine Learning Repository via
the official `ucimlrepo` client library and caches it locally as
`data/phishing_websites.csv`, so `ml_threat_detector.py` can load it with
pandas without re-downloading on every run. The dataset itself is not
committed to the repository -- this script is the reproducible way to
obtain it.

Source: https://archive.ics.uci.edu/dataset/327/phishing+websites
Citation: Mohammad, R., Thabtah, F., McCluskey, L. (2015).
Phishing Websites [Dataset]. UCI Machine Learning Repository.
https://doi.org/10.24432/C51W2X
"""

import os

import pandas as pd
from ucimlrepo import fetch_ucirepo

UCI_DATASET_ID = 327

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DATA_PATH = os.path.join(DATA_DIR, "phishing_websites.csv")


def download_dataset():
    """Fetch the dataset from UCI and cache it as a single CSV file."""
    os.makedirs(DATA_DIR, exist_ok=True)
    dataset = fetch_ucirepo(id=UCI_DATASET_ID)
    df = pd.concat([dataset.data.features, dataset.data.targets], axis=1)
    df.to_csv(DATA_PATH, index=False)
    print(f"Downloaded '{dataset.metadata.name}': {len(df)} rows x {df.shape[1]} columns")
    print(f"Saved to {DATA_PATH}")
    return DATA_PATH


if __name__ == "__main__":
    download_dataset()
