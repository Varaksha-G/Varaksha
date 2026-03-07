"""
services/local_engine/train_ensemble.py
────────────────────────────────────────
Layer 1: Local Fraud Engine — Training Script
Varaksha V2 | Hackathon requirement satisfier

Covers every "Bible" ML objective:
  ✔ Anomaly Detection   — IsolationForest
  ✔ Ensemble Methods    — RandomForest + XGBoost
  ✔ Imbalanced dataset  — SMOTE (imblearn)
  ✔ Saves model         — joblib

Usage:
    python services/local_engine/train_ensemble.py
    python services/local_engine/train_ensemble.py --data path/to/upi.csv
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import pathlib
import sys

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import IsolationForest, RandomForestClassifier, VotingClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("varaksha.train_ensemble")

# ── Paths ─────────────────────────────────────────────────────────────────────

ROOT        = pathlib.Path(__file__).resolve().parents[2]
MODEL_DIR   = ROOT / "data" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

RF_PATH     = MODEL_DIR / "random_forest.pkl"
XGB_PATH    = MODEL_DIR / "xgboost.pkl"
VOTING_PATH = MODEL_DIR / "voting_ensemble.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
ISO_PATH    = MODEL_DIR / "isolation_forest.pkl"

# ── Feature columns ──────────────────────────────────────────────────────────

CATEGORICAL = ["merchant_category", "transaction_type", "device_type"]
NUMERICAL   = [
    "amount",
    "hour_of_day",
    "day_of_week",
    "transactions_last_1h",
    "transactions_last_24h",
    "amount_zscore",
    "gps_delta_km",
    "is_new_device",
    "is_new_merchant",
]
TARGET      = "is_fraud"

# ── Synthetic dataset generator ───────────────────────────────────────────────

def _make_synthetic_dataset(n_rows: int = 10_000, fraud_rate: float = 0.025) -> pd.DataFrame:
    """
    Generate a realistic synthetic UPI dataset when no real CSV is supplied.
    Columns mirror the Kaggle UPI dataset described in the hackathon brief.
    Fraud rate is intentionally low (~2.5 %) to create a realistic imbalance.
    """
    rng = np.random.default_rng(42)
    n_fraud = int(n_rows * fraud_rate)
    n_legit = n_rows - n_fraud

    def _block(size: int, is_fraud: bool) -> dict:
        base_amount  = rng.exponential(800, size) if is_fraud else rng.exponential(400, size)
        return {
            "transaction_id"       : [hashlib.md5(str(i).encode()).hexdigest()[:12] for i in range(size)],
            "amount"               : np.clip(base_amount, 1, 200_000).round(2),
            "merchant_category"    : rng.choice(["FOOD", "TRAVEL", "ECOM", "UTILITY", "P2P", "GAMBLING"], size,
                                                  p=[0.20, 0.10, 0.25, 0.15, 0.25, 0.05] if not is_fraud
                                                  else [0.05, 0.10, 0.20, 0.05, 0.30, 0.30]),
            "transaction_type"     : rng.choice(["CREDIT", "DEBIT"], size),
            "device_type"          : rng.choice(["ANDROID", "IOS", "WEB"], size),
            "hour_of_day"          : rng.integers(0, 24, size) if not is_fraud
                                     else rng.choice(range(1, 6), size),   # fraud peaks at night
            "day_of_week"          : rng.integers(0, 7, size),
            "transactions_last_1h" : rng.integers(0, 5, size) if not is_fraud
                                     else rng.integers(5, 30, size),
            "transactions_last_24h": rng.integers(0, 15, size) if not is_fraud
                                     else rng.integers(15, 80, size),
            "amount_zscore"        : rng.normal(0, 1, size) if not is_fraud
                                     else rng.normal(3.5, 1.2, size),
            "gps_delta_km"         : rng.exponential(5, size) if not is_fraud
                                     else rng.exponential(500, size),
            "is_new_device"        : rng.integers(0, 2, size) if not is_fraud
                                     else rng.choice([0, 1], size, p=[0.3, 0.7]),
            "is_new_merchant"      : rng.integers(0, 2, size) if not is_fraud
                                     else rng.choice([0, 1], size, p=[0.2, 0.8]),
            TARGET                 : int(is_fraud),
        }

    legit_block = _block(n_legit, is_fraud=False)
    fraud_block = _block(n_fraud, is_fraud=True)

    df = pd.concat(
        [pd.DataFrame(legit_block), pd.DataFrame(fraud_block)],
        ignore_index=True,
    ).sample(frac=1, random_state=42).reset_index(drop=True)

    log.info("Synthetic dataset: %d rows | fraud=%.1f%%", len(df), 100 * df[TARGET].mean())
    return df


# ── Preprocessing ─────────────────────────────────────────────────────────────

def preprocess(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, StandardScaler]:
    """Encode categoricals, scale numericals, return (X, y, scaler)."""
    df = df.copy()

    # Encode categoricals
    le = LabelEncoder()
    for col in CATEGORICAL:
        if col in df.columns:
            df[col] = le.fit_transform(df[col].astype(str))

    feature_cols = [c for c in CATEGORICAL + NUMERICAL if c in df.columns]
    X_raw = df[feature_cols].values.astype(np.float32)
    y     = df[TARGET].values.astype(np.int32)

    scaler = StandardScaler()
    X      = scaler.fit_transform(X_raw)

    log.info(
        "Features: %d  |  Class balance: %d legit / %d fraud (%.2f%% fraud)",
        X.shape[1], int((y == 0).sum()), int((y == 1).sum()), 100 * y.mean(),
    )
    return X, y, scaler


# ── SMOTE ─────────────────────────────────────────────────────────────────────

def apply_smote(X_train: np.ndarray, y_train: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Apply SMOTE to the *training* split only.
    SMOTE (Synthetic Minority Over-sampling Technique) synthesises new minority-
    class samples in feature space, addressing the extreme class imbalance
    characteristic of UPI fraud datasets (~1-3 % fraud rate).
    """
    log.info("Applying SMOTE …")
    sm = SMOTE(random_state=42, k_neighbors=5)
    X_res, y_res = sm.fit_resample(X_train, y_train)
    log.info(
        "After SMOTE: %d legit / %d fraud (was %d / %d)",
        int((y_res == 0).sum()), int((y_res == 1).sum()),
        int((y_train == 0).sum()), int((y_train == 1).sum()),
    )
    return X_res, y_res


# ── IsolationForest (anomaly detection) ───────────────────────────────────────

def train_isolation_forest(X_train: np.ndarray) -> IsolationForest:
    """
    Unsupervised anomaly detection — captures distribution shift without labels.
    Used to generate 'anomaly_score' features for the ensemble and as a
    standalone first-pass detector in Agent 01.
    """
    log.info("Training IsolationForest …")
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.025,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train)
    joblib.dump(iso, ISO_PATH)
    log.info("IsolationForest saved → %s", ISO_PATH)
    return iso


# ── Random Forest ─────────────────────────────────────────────────────────────

def train_random_forest(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """
    Random Forest — primary ensemble classifier.
    Achieves ~90.75% accuracy on the UPI dataset per the JETIR2504567 study.
    """
    log.info("Training RandomForest …")
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=5,
        class_weight="balanced",   # extra guard beyond SMOTE
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    joblib.dump(rf, RF_PATH)
    log.info("RandomForest saved → %s", RF_PATH)
    return rf


# ── XGBoost ───────────────────────────────────────────────────────────────────

def train_xgboost(X_train: np.ndarray, y_train: np.ndarray) -> XGBClassifier:
    """
    XGBoost — secondary ensemble classifier.
    Gradient boosting captures complex interaction patterns that RF misses.
    """
    log.info("Training XGBoost …")
    fraud_ratio = float((y_train == 0).sum()) / float((y_train == 1).sum())
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        scale_pos_weight=fraud_ratio,   # built-in imbalance handling
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    xgb.fit(X_train, y_train)
    joblib.dump(xgb, XGB_PATH)
    log.info("XGBoost saved → %s", XGB_PATH)
    return xgb


# ── Voting Ensemble ───────────────────────────────────────────────────────────

def train_voting_ensemble(rf: RandomForestClassifier, xgb: XGBClassifier) -> VotingClassifier:
    """Soft-voting ensemble of RF + XGB for final risk score output."""
    log.info("Building soft-voting ensemble …")
    voting = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb)],
        voting="soft",
    )
    # VotingClassifier wraps already-fitted estimators — mark as fitted
    voting.estimators_ = [rf, xgb]
    voting.le_         = None
    voting.classes_    = np.array([0, 1])
    joblib.dump(voting, VOTING_PATH)
    log.info("VotingEnsemble saved → %s", VOTING_PATH)
    return voting


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(name: str, model, X_test: np.ndarray, y_test: np.ndarray) -> None:
    if hasattr(model, "predict_proba"):
        proba    = model.predict_proba(X_test)[:, 1]
        auc      = roc_auc_score(y_test, proba)
        y_pred   = (proba >= 0.5).astype(int)
    else:
        y_pred = model.predict(X_test)
        auc    = None

    print(f"\n{'═'*55}")
    print(f"  {name}")
    print(f"{'═'*55}")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Fraud"], digits=4))
    if auc is not None:
        print(f"  ROC-AUC: {auc:.4f}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main(data_path: str | None = None) -> None:
    # 1. Load data
    if data_path and pathlib.Path(data_path).exists():
        log.info("Loading dataset from %s", data_path)
        df = pd.read_csv(data_path)
        # Normalise common column name variants
        df.rename(columns={
            "isFraud": TARGET, "is_fraud": TARGET,
            "amount": "amount", "Amount": "amount",
        }, inplace=True, errors="ignore")
    else:
        log.warning("No CSV supplied — using 10 000-row synthetic dataset")
        df = _make_synthetic_dataset(n_rows=10_000)

    # 2. Preprocess
    X, y, scaler = preprocess(df)
    joblib.dump(scaler, SCALER_PATH)
    log.info("Scaler saved → %s", SCALER_PATH)

    # 3. Train/test split (BEFORE SMOTE — never oversample the test set)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 4. IsolationForest (unsupervised — trained on all data for better coverage)
    iso = train_isolation_forest(X_train)
    evaluate("IsolationForest (anomaly score > 0 = fraud)", iso, X_test, y_test)

    # 5. SMOTE on training split only
    X_sm, y_sm = apply_smote(X_train, y_train)

    # 6. Train classifiers on SMOTE-resampled data
    rf  = train_random_forest(X_sm, y_sm)
    xgb = train_xgboost(X_sm, y_sm)

    # 7. Evaluate on original (unaugmented) test set
    evaluate("RandomForest", rf,  X_test, y_test)
    evaluate("XGBoost",      xgb, X_test, y_test)

    # 8. Ensemble
    voting = train_voting_ensemble(rf, xgb)
    evaluate("Soft-Voting Ensemble (RF + XGB)", voting, X_test, y_test)

    print("\n✔  All models saved to", MODEL_DIR)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Varaksha V2 — train ensemble fraud models")
    parser.add_argument("--data", default=None, help="Path to UPI CSV dataset (optional)")
    args = parser.parse_args()
    main(args.data)
