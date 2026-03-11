"""
services/local_engine/train_ensemble.py
────────────────────────────────────────
Layer 1: Local Fraud Engine — Training Script
Varaksha V2 | Hackathon requirement satisfier

Covers every "Bible" ML objective:
  ✔ Anomaly Detection   — IsolationForest
  ✔ Ensemble Methods    — RandomForest (300 estimators, balanced weights, post-SMOTE)
  ✔ Imbalanced dataset  — SMOTE (imblearn)
  ✔ Saves model         — joblib + ONNX (varaksha_rf_model.onnx)

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
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ONNX export — optional at import time; hard-required at export step
try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    import onnxruntime as ort  # smoke-check the runtime is present
    _ONNX_AVAILABLE = True
except ImportError:
    _ONNX_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("varaksha.train_ensemble")

# ── Paths ─────────────────────────────────────────────────────────────────────

ROOT        = pathlib.Path(__file__).resolve().parents[2]
MODEL_DIR   = ROOT / "data" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

RF_PATH        = MODEL_DIR / "random_forest.pkl"
SCALER_PATH    = MODEL_DIR / "scaler.pkl"
ISO_PATH       = MODEL_DIR / "isolation_forest.pkl"

# ONNX export paths (server-side inference uses these — no sklearn at runtime)
RF_ONNX        = MODEL_DIR / "varaksha_rf_model.onnx"
ISO_ONNX       = MODEL_DIR / "isolation_forest.onnx"
SCALER_ONNX    = MODEL_DIR / "scaler.onnx"
FEATURE_META   = MODEL_DIR / "feature_meta.json"   # column order + names

# ── Dataset paths ─────────────────────────────────────────────────────────────

DATASET_DIR = ROOT / "data" / "datasets"

# Canonical filenames — each loader checks existence before loading
_DS_PAYSIM      = DATASET_DIR / "PS_20174392719_1491204439457_log.csv"
_DS_UPI         = DATASET_DIR / "Untitled spreadsheet - upi_transactions.csv"
_DS_MOMTSIM     = DATASET_DIR / "momtsim.csv"
_DS_DIGITAL_PAY = DATASET_DIR / "digital_payment_fraud.csv"
_DS_USA_BANKING = DATASET_DIR / "usa_banking_2023.csv"
# Newly dropped datasets (auto-detected if present)
_DS_CUSTOMER_DF  = DATASET_DIR / "Customer_DF (1).csv"
_DS_CUST_TXN     = DATASET_DIR / "cust_transaction_details (1).csv"
_DS_CDR          = DATASET_DIR / "realtime_cdr_fraud_dataset.csv"

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
    # ── Multi-dataset engineered features ─────────────────────────────────────
    "balance_drain_ratio",       # MoMTSim + PaySim: (old_bal-new_bal)/old_bal
    "account_age_days",          # UPI/Digital Payment: ATO risk proxy
    "previous_failed_attempts",  # Digital Payment: credential-stuffing signal
    "transfer_cashout_flag",     # PaySim: TRANSFER immediately followed by CASH_OUT
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
            "transaction_id"        : [hashlib.md5(str(i).encode()).hexdigest()[:12] for i in range(size)],
            "amount"                : np.clip(base_amount, 1, 200_000).round(2),
            "merchant_category"     : rng.choice(["FOOD", "TRAVEL", "ECOM", "UTILITY", "P2P", "GAMBLING"], size,
                                                   p=[0.20, 0.10, 0.25, 0.15, 0.25, 0.05] if not is_fraud
                                                   else [0.05, 0.10, 0.20, 0.05, 0.30, 0.30]),
            "transaction_type"      : rng.choice(["CREDIT", "DEBIT"], size),
            "device_type"           : rng.choice(["ANDROID", "IOS", "WEB"], size),
            "hour_of_day"           : rng.integers(0, 24, size) if not is_fraud
                                      else rng.choice(range(1, 6), size),
            "day_of_week"           : rng.integers(0, 7, size),
            "transactions_last_1h"  : rng.integers(0, 5, size) if not is_fraud
                                      else rng.integers(5, 30, size),
            "transactions_last_24h" : rng.integers(0, 15, size) if not is_fraud
                                      else rng.integers(15, 80, size),
            "amount_zscore"         : rng.normal(0, 1, size) if not is_fraud
                                      else rng.normal(3.5, 1.2, size),
            "gps_delta_km"          : rng.exponential(5, size) if not is_fraud
                                      else rng.exponential(500, size),
            "is_new_device"         : rng.integers(0, 2, size) if not is_fraud
                                      else rng.choice([0, 1], size, p=[0.3, 0.7]),
            "is_new_merchant"       : rng.integers(0, 2, size) if not is_fraud
                                      else rng.choice([0, 1], size, p=[0.2, 0.8]),
            # Multi-dataset engineered features (realistically distributed)
            "balance_drain_ratio"      : rng.uniform(0.0, 0.05, size) if not is_fraud
                                         else rng.uniform(0.7, 1.0, size),
            "account_age_days"         : rng.integers(180, 3650, size) if not is_fraud
                                         else rng.integers(0, 60, size),
            "previous_failed_attempts" : rng.integers(0, 2, size) if not is_fraud
                                         else rng.integers(3, 12, size),
            "transfer_cashout_flag"    : rng.choice([0, 1], size, p=[0.97, 0.03]) if not is_fraud
                                         else rng.choice([0, 1], size, p=[0.25, 0.75]),
            TARGET                     : int(is_fraud),
        }

    legit_block = _block(n_legit, is_fraud=False)
    fraud_block = _block(n_fraud, is_fraud=True)

    df = pd.concat(
        [pd.DataFrame(legit_block), pd.DataFrame(fraud_block)],
        ignore_index=True,
    ).sample(frac=1, random_state=42).reset_index(drop=True)

    log.info("Synthetic dataset: %d rows | fraud=%.1f%%", len(df), 100 * df[TARGET].mean())
    return df


# ── Multi-dataset loaders ─────────────────────────────────────────────────────
# Each loader returns a DataFrame normalised to the unified schema or None
# if the file is absent.  Missing feature columns are filled by load_and_merge_all.

def _load_paysim(path: pathlib.Path, max_rows: int = 50_000) -> pd.DataFrame | None:
    """
    Dataset 3 & 5 — PaySim + Rupak Roy (identical schema).
    File: PS_20174392719_1491204439457_log.csv (6.36 M rows)

    Extracts:
      transaction_type — CASH_IN/CASH_OUT/TRANSFER mapped → CREDIT/DEBIT
      amount           — transaction amount
      balance_drain_ratio        — (oldbalanceOrg - newbalanceOrig) / oldbalanceOrg
      transfer_cashout_flag      — 1 when TRANSFER row immediately precedes CASH_OUT
                                   by the same account (money-laundering sub-pattern)
      hour_of_day      — step mod 24
    """
    if not path.exists():
        log.info("PaySim dataset not found (%s) — skipping", path.name)
        return None
    log.info("Loading PaySim → %s (this may take a few seconds)", path.name)
    needed = ["step", "type", "amount", "nameOrig",
              "oldbalanceOrg", "newbalanceOrig", "isFraud"]
    df = pd.read_csv(path, usecols=needed)

    # Stratified sample: keep ALL fraud rows + random legit up to max_rows
    fraud_df = df[df["isFraud"] == 1]
    n_legit  = min(max_rows - len(fraud_df), (df["isFraud"] == 0).sum())
    legit_df = df[df["isFraud"] == 0].sample(n=n_legit, random_state=42)
    df = pd.concat([fraud_df, legit_df], ignore_index=True)
    log.info("  PaySim sample: %d rows | fraud=%.2f%%", len(df), 100 * df["isFraud"].mean())

    # ── TRANSFER → CASH_OUT laundering sequence flag ──────────────────────────
    # Sort by account + time; a TRANSFER row is flagged when the very next
    # transaction by the same account is a CASH_OUT (classic layering pattern).
    df_s = df.sort_values(["nameOrig", "step"])
    df_s["_next_type"] = df_s.groupby("nameOrig")["type"].shift(-1)
    df["transfer_cashout_flag"] = (
        (df_s["type"] == "TRANSFER") & (df_s["_next_type"] == "CASH_OUT")
    ).astype(np.float32).values

    # ── balance_drain_ratio ───────────────────────────────────────────────────
    df["balance_drain_ratio"] = (
        (df["oldbalanceOrg"] - df["newbalanceOrig"]) /
        df["oldbalanceOrg"].clip(lower=1)
    ).clip(-1, 1).astype(np.float32)

    # ── Unified column names ──────────────────────────────────────────────────
    df["hour_of_day"] = (df["step"] % 24).astype(np.float32)
    _type_map = {"CASH_IN": "CREDIT", "CASH_OUT": "DEBIT",
                 "TRANSFER": "DEBIT",  "PAYMENT": "DEBIT", "DEBIT": "DEBIT"}
    df["transaction_type"] = df["type"].map(_type_map).fillna("DEBIT")
    df.rename(columns={"isFraud": TARGET}, inplace=True)
    df.drop(columns=["step", "type", "nameOrig", "oldbalanceOrg", "newbalanceOrig"],
            inplace=True, errors="ignore")
    return df


def _load_upi_transactions(path: pathlib.Path) -> pd.DataFrame | None:
    """
    Dataset 2 & 4 & 5 — Varaksha UPI Transactions spreadsheet.
    Schema: Transaction_ID, Date, Time, Merchant_ID, Customer_ID, Device_ID,
            Transaction_Type, Payment_Gateway, Transaction_City, Transaction_State,
            IP_Address, Transaction_Status, Device_OS, Transaction_Frequency,
            Merchant_Category, Transaction_Channel, Transaction_Amount_Deviation,
            Days_Since_Last_Transaction, amount, fraud

    Covers:
      device_type              ← Device_OS
      merchant_category        ← Merchant_Category
      account_age_days         ← Days_Since_Last_Transaction (proxy)
      transactions_last_24h    ← Transaction_Frequency
      amount_zscore            ← Transaction_Amount_Deviation
      hour_of_day              ← Time (HH:MM:SS)
    """
    if not path.exists():
        log.info("UPI transactions dataset not found (%s) — skipping", path.name)
        return None
    log.info("Loading UPI Transactions → %s", path.name)
    df = pd.read_csv(path)

    df.rename(columns={
        "fraud":                          TARGET,
        "Transaction_Type":               "transaction_type",
        "Merchant_Category":              "merchant_category",
        "Device_OS":                      "device_type",
        "Transaction_Frequency":          "transactions_last_24h",
        "Transaction_Amount_Deviation":   "amount_zscore",
        "Days_Since_Last_Transaction":    "account_age_days",
    }, inplace=True)

    # Parse hour from Time column ("HH:MM:SS" format)
    if "Time" in df.columns:
        try:
            df["hour_of_day"] = pd.to_datetime(
                df["Time"], format="%H:%M:%S", errors="coerce"
            ).dt.hour.fillna(12).astype(np.float32)
        except Exception:
            df["hour_of_day"] = 12.0

    # Normalise free-text device type to the three canonical values
    if "device_type" in df.columns:
        dev_map = {"android": "ANDROID", "ios": "IOS",
                   "iphone": "IOS", "web": "WEB", "desktop": "WEB"}
        df["device_type"] = (
            df["device_type"].str.lower().map(dev_map).fillna("ANDROID")
        )

    # Normalise merchant_category to uppercase
    if "merchant_category" in df.columns:
        df["merchant_category"] = df["merchant_category"].str.upper()

    log.info("  UPI Transactions: %d rows | fraud=%.2f%%",
             len(df), 100 * df[TARGET].mean())
    return df


def _load_momtsim(path: pathlib.Path) -> pd.DataFrame | None:
    """
    Dataset 1 — MoMTSim (Synthetic Mobile Money Simulator).
    Expected columns: step, amount, oldBalInitiator, newBalInitiator,
                      oldBalRecipient, isFraud.
    Engineers: balance_drain_ratio (mathematical account-draining signal)
    """
    if not path.exists():
        log.info("MoMTSim dataset not found (%s) — skipping", path.name)
        return None
    log.info("Loading MoMTSim → %s", path.name)
    df = pd.read_csv(path)
    # Flexible column detection (different naming conventions)
    col_map: dict[str, str] = {}
    for c in df.columns:
        cl = c.lower().replace(" ", "")
        if "isfraud" in cl or "is_fraud" in cl:              col_map[c] = TARGET
        elif "oldbalinitiator" in cl or "oldbal_init" in cl: col_map[c] = "_old_bal"
        elif "newbalinitiator" in cl or "newbal_init" in cl: col_map[c] = "_new_bal"
        elif cl == "amount":                                  col_map[c] = "amount"
        elif cl == "step":                                    col_map[c] = "step"
    df.rename(columns=col_map, inplace=True)
    if TARGET not in df.columns:
        log.warning("MoMTSim: fraud column not found — skipping")
        return None
    if "_old_bal" in df.columns and "_new_bal" in df.columns:
        df["balance_drain_ratio"] = (
            (df["_old_bal"] - df["_new_bal"]) / df["_old_bal"].clip(lower=1)
        ).clip(-1, 1).astype(np.float32)
    if "step" in df.columns:
        df["hour_of_day"] = (df["step"] % 24).astype(np.float32)
    df[TARGET] = df[TARGET].astype(int)
    df.drop(columns=["step", "_old_bal", "_new_bal"], inplace=True, errors="ignore")
    log.info("  MoMTSim: %d rows | fraud=%.2f%%", len(df), 100 * df[TARGET].mean())
    return df


def _load_digital_payment(path: pathlib.Path) -> pd.DataFrame | None:
    """
    Dataset 2 — Digital Payment Fraud Detection.
    Expected columns: device_type, account_age_days, transaction_hour,
                      previous_failed_attempts, (fraud label).
    """
    if not path.exists():
        log.info("Digital Payment dataset not found (%s) — skipping", path.name)
        return None
    log.info("Loading Digital Payment Fraud → %s", path.name)
    df = pd.read_csv(path)
    col_map: dict[str, str] = {}
    for c in df.columns:
        cl = c.lower().replace(" ", "_")
        if "isfraud" in cl or "is_fraud" in cl or cl == "fraud": col_map[c] = TARGET
        elif "device_type" in cl:                    col_map[c] = "device_type"
        elif "account_age" in cl:                    col_map[c] = "account_age_days"
        elif "transaction_hour" in cl or "trans_hour" in cl: col_map[c] = "hour_of_day"
        elif "failed_attempt" in cl or "prev_failed" in cl:  col_map[c] = "previous_failed_attempts"
        elif cl in ("amount", "trans_amount", "amt"): col_map[c] = "amount"
    df.rename(columns=col_map, inplace=True)
    if TARGET not in df.columns:
        log.warning("Digital Payment: fraud column not found — skipping")
        return None
    df[TARGET] = df[TARGET].astype(int)
    log.info("  Digital Payment: %d rows | fraud=%.2f%%", len(df), 100 * df[TARGET].mean())
    return df


def _load_usa_banking(path: pathlib.Path) -> pd.DataFrame | None:
    """
    Dataset 4 — USA Banking Transactions 2023-2024.
    Expected columns: Merchant_Name, Category, City, amt, is_fraud,
                      trans_date_trans_time.
    """
    if not path.exists():
        log.info("USA Banking dataset not found (%s) — skipping", path.name)
        return None
    log.info("Loading USA Banking → %s", path.name)
    df = pd.read_csv(path)
    col_map: dict[str, str] = {}
    for c in df.columns:
        cl = c.lower().replace(" ", "_")
        if cl in ("is_fraud", "isfraud", "fraud"):        col_map[c] = TARGET
        elif cl in ("category",):                         col_map[c] = "merchant_category"
        elif cl in ("amt", "amount", "trans_amount"):    col_map[c] = "amount"
        elif "trans_date" in cl or "datetime" in cl:     col_map[c] = "_datetime"
    df.rename(columns=col_map, inplace=True)
    if TARGET not in df.columns:
        log.warning("USA Banking: fraud column not found — skipping")
        return None
    if "_datetime" in df.columns:
        try:
            df["hour_of_day"] = pd.to_datetime(
                df["_datetime"], errors="coerce"
            ).dt.hour.fillna(12).astype(np.float32)
        except Exception:
            pass
        df.drop(columns=["_datetime"], inplace=True, errors="ignore")
    if "merchant_category" in df.columns:
        df["merchant_category"] = df["merchant_category"].str.upper().str.replace(" ", "_")
    df[TARGET] = df[TARGET].astype(int)
    log.info("  USA Banking: %d rows | fraud=%.2f%%", len(df), 100 * df[TARGET].mean())
    return df


def _load_customer_transactions(
    cdf_path: pathlib.Path, ctd_path: pathlib.Path
) -> pd.DataFrame | None:
    """
    Customer_DF (1).csv + cust_transaction_details (1).csv
    ───────────────────────────────────────────────────────────────────
    Customer_DF holds the fraud label and per-customer aggregates:
      Fraud             → is_fraud
      No_Payments       → previous_failed_attempts (proxy: high payment count = ATO)
      No_Transactions   → transactions_last_24h
      customerDevice    → device_type (hash encoded, mapped to ANDROID/IOS/WEB)

    cust_transaction_details holds per-transaction rows joined on customerEmail:
      transactionAmount        → amount
      transactionFailed        → is_new_device (1 if any txn failed = suspicious)
      paymentMethodType        → transaction_type (card=DEBIT, bitcoin=DEBIT, ...)
    """
    if not cdf_path.exists():
        log.info("Customer_DF not found (%s) — skipping", cdf_path.name)
        return None
    log.info("Loading Customer_DF + cust_transaction_details")

    cdf = pd.read_csv(cdf_path)
    # Fraud column may be bool string 'True'/'False' or actual bool
    cdf["Fraud"] = cdf["Fraud"].map(
        lambda x: 1 if str(x).strip().lower() in ("true", "1", "yes") else 0
    ).astype(int)
    cdf.rename(columns={
        "Fraud":           TARGET,
        "No_Transactions": "transactions_last_24h",
        "No_Payments":     "previous_failed_attempts",
        "customerDevice":  "_raw_device",
    }, inplace=True)

    # Device type: the column is a hash token, not a real device name —
    # use length-mod to get a deterministic pseudo-category
    if "_raw_device" in cdf.columns:
        dev_choices = ["ANDROID", "IOS", "WEB"]
        cdf["device_type"] = cdf["_raw_device"].apply(
            lambda h: dev_choices[len(str(h)) % 3]
        )

    if ctd_path.exists():
        ctd = pd.read_csv(ctd_path)
        # Per-customer aggregates: total amount, any failed transaction
        ctd_agg = ctd.groupby("customerEmail").agg(
            amount=("transactionAmount", "mean"),
            is_new_device=("transactionFailed", "max"),   # 1 = at least 1 failure
        ).reset_index()
        cdf = cdf.merge(ctd_agg, on="customerEmail", how="left")
    else:
        log.info("  cust_transaction_details not found — using Customer_DF alone")

    log.info("  Customer_DF merged: %d rows | fraud=%.2f%%",
             len(cdf), 100 * cdf[TARGET].mean())
    return cdf


def _load_cdr_fraud(path: pathlib.Path) -> pd.DataFrame | None:
    """
    Realtime CDR (Call Detail Records) Fraud Dataset
    ────────────────────────────────────────────────────────────────
    24,543 rows of telecom transactions covering sim_box_fraud,
    subscription_fraud, random_fraud, call_masking.

    Column mapping:
      fraud_type != 'none'   → is_fraud=1
      duration_sec           → amount (transaction magnitude proxy)
      is_night_call          → hour_of_day (1→2, 0→14)
      device_id (hash)       → is_new_device (change detection: 1 if unique modulo)
      fraud_type values      → merchant_category (maps telecom fraud type)
    """
    if not path.exists():
        log.info("CDR fraud dataset not found (%s) — skipping", path.name)
        return None
    log.info("Loading CDR Fraud → %s", path.name)
    df = pd.read_csv(path)

    # Binary fraud label
    df[TARGET] = (df["fraud_type"] != "none").astype(int)
    log.info("  CDR: %d rows | fraud=%.2f%%", len(df), 100 * df[TARGET].mean())

    # amount proxy: call duration in seconds
    df.rename(columns={"duration_sec": "amount"}, inplace=True)

    # hour_of_day: night calls are 1-5h, day calls are 9-17h
    df["hour_of_day"] = df["is_night_call"].map({1: 2, 0: 14}).fillna(12).astype(np.float32)

    # is_new_device: device_id hash token changes — flag last-seen novelty
    seen: set[str] = set()
    new_dev_flags: list[int] = []
    for did in df["device_id"].astype(str):
        new_dev_flags.append(0 if did in seen else 1)
        seen.add(did)
    df["is_new_device"] = new_dev_flags

    # merchant_category: telecom fraud type as category signal
    _ft_map = {
        "none":                "P2P",
        "sim_box_fraud":       "GAMBLING",
        "subscription_fraud":  "UTILITY",
        "random_fraud":        "ECOM",
        "call_masking":        "TRAVEL",
    }
    df["merchant_category"] = df["fraud_type"].map(_ft_map).fillna("P2P")
    df["transaction_type"] = "DEBIT"

    df.drop(columns=["caller_id", "receiver_id", "start_time", "sim_id",
                     "device_id", "location_origin", "country_origin",
                     "location_dest", "country_dest", "is_night_call",
                     "transaction_status", "fraud_type"],
            inplace=True, errors="ignore")
    return df


def load_and_merge_all(datasets_dir: pathlib.Path | None = None) -> pd.DataFrame | None:
    """
    Orchestrate loading of all 5 source datasets, unify their schemas, and
    merge into a single feature matrix ready for preprocessing.

    Unified sender_id naming:
        nameOrig / Customer_ID / caller_id → stripped (hash already done by gateway)

    Returns None only if every loader returns None (all files absent).
    In that case the caller falls back to the synthetic dataset.
    """
    d = datasets_dir or DATASET_DIR
    frames: list[pd.DataFrame] = []

    # Dataset 3 + 5: PaySim (covers Rupak Roy — same schema)
    f = _load_paysim(_DS_PAYSIM)
    if f is not None:
        frames.append(f)

    # Dataset 2 + 4 + 5 partial: Varaksha UPI Transactions (rich multi-purpose file)
    f = _load_upi_transactions(_DS_UPI)
    if f is not None:
        frames.append(f)

    # Dataset 1: MoMTSim (graceful skip if absent)
    f = _load_momtsim(_DS_MOMTSIM)
    if f is not None:
        frames.append(f)

    # Dataset 2: standalone Digital Payment Fraud Detection
    f = _load_digital_payment(_DS_DIGITAL_PAY)
    if f is not None:
        frames.append(f)

    # Dataset 4: USA Banking 2023-2024
    f = _load_usa_banking(_DS_USA_BANKING)
    if f is not None:
        frames.append(f)

    # Customer_DF + cust_transaction_details (joined on email)
    f = _load_customer_transactions(_DS_CUSTOMER_DF, _DS_CUST_TXN)
    if f is not None:
        frames.append(f)

    # CDR Realtime Fraud Dataset
    f = _load_cdr_fraud(_DS_CDR)
    if f is not None:
        frames.append(f)

    if not frames:
        return None

    log.info("Merging %d dataset(s) into unified feature matrix …", len(frames))
    merged = pd.concat(frames, ignore_index=True, sort=False)
    log.info("Merged: %d rows | fraud=%.2f%%", len(merged), 100 * merged[TARGET].mean())

    # ── Post-merge: compute amount_zscore globally (cross-dataset normalisation)
    if "amount" in merged.columns and "amount_zscore" not in merged.columns:
        mu  = merged["amount"].mean()
        sig = merged["amount"].std() + 1e-9
        merged["amount_zscore"] = ((merged["amount"] - mu) / sig).clip(-5, 5)

    # ── Impute: fill NaN numericals with median, categorical with mode ────────
    for col in NUMERICAL:
        if col in merged.columns:
            merged[col] = merged[col].fillna(merged[col].median())
        else:
            merged[col] = 0.0   # feature absent in all loaded datasets
    for col in CATEGORICAL:
        if col in merged.columns:
            mode_val = merged[col].mode()
            merged[col] = merged[col].fillna(mode_val.iloc[0] if len(mode_val) else "UNKNOWN")
        else:
            merged[col] = "UNKNOWN"

    return merged


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



# ── ONNX Export ──────────────────────────────────────────────────────────────

def export_onnx(rf: RandomForestClassifier,
               iso: IsolationForest, scaler: StandardScaler,
               n_features: int, feature_names: list[str]) -> None:
    """
    Export trained models to ONNX so the server only needs onnxruntime (~30 MB)
    instead of sklearn (~200 MB).  512 MB deployment-safe.

    Outputs:
        data/models/varaksha_rf_model.onnx  — RandomForest, outputs proba
        data/models/isolation_forest.onnx   — anomaly scorer
        data/models/scaler.onnx             — StandardScaler pre-processing step
        data/models/feature_meta.json       — column order for the inference server
    """
    if not _ONNX_AVAILABLE:
        log.warning(
            "skl2onnx / onnxruntime not installed — skipping ONNX export.\n"
            "Install with: pip install skl2onnx onnxruntime"
        )
        return

    import json
    from skl2onnx import convert_sklearn  # type: ignore[import]
    from skl2onnx.common.data_types import FloatTensorType  # type: ignore[import]

    input_type = [("X", FloatTensorType([None, n_features]))]

    # 1. Scaler
    log.info("Exporting scaler → %s", SCALER_ONNX)
    scaler_onnx = convert_sklearn(scaler, "scaler", input_type)
    SCALER_ONNX.write_bytes(scaler_onnx.SerializeToString())

    # 2. RandomForest — primary (and only) classifier
    log.info("Exporting RandomForest → %s", RF_ONNX)
    rf_onnx = convert_sklearn(
        rf, "rf",
        [("X", FloatTensorType([None, n_features]))],
        options={type(rf): {"zipmap": False}},
    )
    RF_ONNX.write_bytes(rf_onnx.SerializeToString())

    # 3. IsolationForest
    log.info("Exporting IsolationForest → %s", ISO_ONNX)
    iso_onnx = convert_sklearn(iso, "iso", input_type,
                               target_opset={"": 17, "ai.onnx.ml": 3})
    ISO_ONNX.write_bytes(iso_onnx.SerializeToString())

    # 6. Feature metadata — tells the inference server the exact column order
    import json
    meta = {"feature_names": feature_names, "n_features": n_features}
    FEATURE_META.write_text(json.dumps(meta, indent=2))
    log.info("Feature metadata saved → %s", FEATURE_META)

    log.info("✔  ONNX export complete — inference server needs only onnxruntime")


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(name: str, model, X_test: np.ndarray, y_test: np.ndarray) -> None:
    if hasattr(model, "predict_proba"):
        proba    = model.predict_proba(X_test)[:, 1]
        auc      = roc_auc_score(y_test, proba)
        y_pred   = (proba >= 0.5).astype(int)
    else:
        raw    = model.predict(X_test)
        # IsolationForest returns 1 (inlier) / -1 (outlier); remap to 0/1
        y_pred = np.where(raw == -1, 1, 0).astype(int)
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
    # Priority: --data single CSV > multi-dataset merge > synthetic fallback
    if data_path and pathlib.Path(data_path).exists():
        log.info("Loading single dataset from %s", data_path)
        df = pd.read_csv(data_path)
        df.rename(columns={"isFraud": TARGET, "fraud": TARGET,
                            "Amount": "amount"}, inplace=True, errors="ignore")
        # Fill any multi-dataset features absent in single-file mode
        for col in NUMERICAL:
            if col not in df.columns:
                df[col] = 0.0
    else:
        # Try loading all real datasets first
        df = load_and_merge_all()
        if df is None:
            log.warning("No real dataset files found — using 10 000-row synthetic dataset")
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

    # 6. Train RandomForest on SMOTE-resampled data
    rf = train_random_forest(X_sm, y_sm)

    # 7. Evaluate on original (unaugmented) test set
    evaluate("RandomForest", rf, X_test, y_test)

    # 8. ONNX export (for lightweight server-side inference)
    feature_cols = [c for c in CATEGORICAL + NUMERICAL if c in df.columns]
    export_onnx(rf, iso, scaler, len(feature_cols), feature_cols)

    print("\n✔  All models saved to", MODEL_DIR)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Varaksha V2 — train ensemble fraud models")
    parser.add_argument("--data", default=None, help="Path to UPI CSV dataset (optional)")
    args = parser.parse_args()
    main(args.data)
