"""
services/local_engine/infer.py
────────────────────────────────────────────────────────────────────────────────
Lightweight inference module — server runtime dependency: onnxruntime only.

Does NOT import sklearn, xgboost, lightgbm, or pandas.
Loads pre-exported .onnx files from data/models/ and runs predictions
with numpy arrays only.

Usage (from code):
    from services.local_engine.infer import VarakshaScoringEngine
    engine = VarakshaScoringEngine()
    result = engine.score(tx_dict)

Usage (standalone smoke-test):
    python services/local_engine/infer.py
"""

from __future__ import annotations

import json
import logging
import pathlib
from dataclasses import dataclass

import numpy as np
import onnxruntime as ort

log = logging.getLogger("varaksha.infer")

ROOT       = pathlib.Path(__file__).resolve().parents[2]
MODEL_DIR  = ROOT / "data" / "models"

# ── ONNX model paths ──────────────────────────────────────────────────────────
_RF_ONNX   = MODEL_DIR / "varaksha_rf_model.onnx"
_ISO_ONNX  = MODEL_DIR / "isolation_forest.onnx"
_META      = MODEL_DIR / "feature_meta.json"

# ── Fallback: feature column definitions (mirrors train_ensemble.py) ─────────
_CATEGORICAL = ["merchant_category", "transaction_type", "device_type"]
_NUMERICAL   = [
    "amount", "hour_of_day", "day_of_week",
    "transactions_last_1h", "transactions_last_24h",
    "amount_zscore", "gps_delta_km", "is_new_device", "is_new_merchant",
    # Multi-dataset engineered features (default 0.0 when not present at inference)
    "balance_drain_ratio", "account_age_days",
    "previous_failed_attempts", "transfer_cashout_flag",
]

# Categorical label maps (must match LabelEncoder order from training)
# These are exact maps from the synthetic dataset generation in train_ensemble.py
_CAT_MAPS: dict[str, dict[str, int]] = {
    "merchant_category": {"ECOM": 0, "FOOD": 1, "GAMBLING": 2, "P2P": 3, "TRAVEL": 4, "UTILITY": 5},
    "transaction_type":  {"CREDIT": 0, "DEBIT": 1},
    "device_type":       {"ANDROID": 0, "IOS": 1, "WEB": 2},
}


@dataclass
class ScoreResult:
    fraud_proba: float      # 0.0 – 1.0 probability the transaction is fraudulent
    anomaly_score: float    # IsolationForest score; < 0 = anomalous
    verdict: str            # "ALLOW" | "FLAG" | "BLOCK"
    reason: str             # human-readable reason string


class VarakshaScoringEngine:
    """
    Load ONNX models once at startup, score transactions at runtime.

    Memory profile (onnxruntime only):
        RF model session:          ~10–25 MB
        IsolationForest session:   ~5–10 MB
        numpy + ort runtime:       ~25 MB
        Total:                     ~40–60 MB  (well within 512 MB limit)
    """

    def __init__(self) -> None:
        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 2
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        if not _RF_ONNX.exists():
            raise FileNotFoundError(
                f"ONNX model not found: {_RF_ONNX}\n"
                "Run: python services/local_engine/train_ensemble.py"
            )

        self._rf_sess  = ort.InferenceSession(str(_RF_ONNX),  sess_options=opts)
        self._iso_sess = ort.InferenceSession(str(_ISO_ONNX), sess_options=opts) if _ISO_ONNX.exists() else None

        # Feature names from metadata (saved during training)
        if _META.exists():
            meta = json.loads(_META.read_text())
            self._feature_names: list[str] = meta["feature_names"]
        else:
            self._feature_names = [c for c in _CATEGORICAL + _NUMERICAL]

        log.info(
            "VarakshaScoringEngine ready | features=%d | iso=%s",
            len(self._feature_names),
            "yes" if self._iso_sess else "no",
        )

    # ── Feature extraction ────────────────────────────────────────────────────

    def _extract(self, tx: dict) -> np.ndarray:
        """
        Convert a raw transaction dict to a float32 feature vector.
        Missing keys fall back to 0.0 — caller should validate upstream.
        """
        row: list[float] = []
        for col in self._feature_names:
            val = tx.get(col, 0)
            if col in _CAT_MAPS:
                val = _CAT_MAPS[col].get(str(val).upper(), 0)
            row.append(float(val))
        return np.array([row], dtype=np.float32)   # shape (1, n_features)

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self, tx: dict) -> ScoreResult:
        """
        Score a single transaction dict.

        Expected keys (all optional, fall back to 0):
            amount, merchant_category, transaction_type, device_type,
            hour_of_day, day_of_week, transactions_last_1h,
            transactions_last_24h, amount_zscore, gps_delta_km,
            is_new_device, is_new_merchant
        """
        X = self._extract(tx)

        # RF probability — sole classifier
        rf_out       = self._rf_sess.run(None, {"X": X})
        fraud_proba  = float(rf_out[1][0][1])   # [1]=probabilities, [0]=first sample, [1]=fraud class

        # IsolationForest anomaly score
        if self._iso_sess is not None:
            iso_out      = self._iso_sess.run(None, {"X": X})
            anomaly_score = float(iso_out[1].flat[0])   # decision_function output
        else:
            anomaly_score = 0.0

        # Blend: if IF scores very anomalous, bump fraud_proba floor
        if anomaly_score < -0.15:
            fraud_proba = max(fraud_proba, 0.45)

        verdict, reason = self._verdict(fraud_proba, anomaly_score, tx)
        return ScoreResult(
            fraud_proba=round(fraud_proba, 4),
            anomaly_score=round(anomaly_score, 4),
            verdict=verdict,
            reason=reason,
        )

    @staticmethod
    def _verdict(proba: float, anomaly: float, tx: dict) -> tuple[str, str]:
        reasons: list[str] = []

        if tx.get("is_new_device"):
            reasons.append("new device")
        if tx.get("is_new_merchant"):
            reasons.append("new merchant")
        if tx.get("gps_delta_km", 0) > 200:
            reasons.append(f"location jump {tx['gps_delta_km']:.0f} km")
        if tx.get("transactions_last_1h", 0) > 8:
            reasons.append("velocity spike")
        if anomaly < -0.15:
            reasons.append("behavioural anomaly")

        reason_str = "; ".join(reasons) if reasons else "normal pattern"

        if proba >= 0.75:
            return "BLOCK", reason_str
        elif proba >= 0.40:
            return "FLAG", reason_str
        else:
            return "ALLOW", reason_str


# ── Smoke test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    engine = VarakshaScoringEngine()

    tests = [
        {
            "label": "Normal daytime P2P",
            "amount": 250.0, "merchant_category": "P2P", "transaction_type": "DEBIT",
            "device_type": "ANDROID", "hour_of_day": 14, "day_of_week": 2,
            "transactions_last_1h": 1, "transactions_last_24h": 3,
            "amount_zscore": 0.3, "gps_delta_km": 2.0,
            "is_new_device": 0, "is_new_merchant": 0,
        },
        {
            "label": "Suspicious: high velocity + new device + night",
            "amount": 49999.0, "merchant_category": "GAMBLING", "transaction_type": "DEBIT",
            "device_type": "WEB", "hour_of_day": 3, "day_of_week": 6,
            "transactions_last_1h": 15, "transactions_last_24h": 60,
            "amount_zscore": 4.2, "gps_delta_km": 850.0,
            "is_new_device": 1, "is_new_merchant": 1,
        },
    ]

    for t in tests:
        label = t.pop("label")
        result = engine.score(t)
        print(f"\n[{label}]")
        print(f"  verdict={result.verdict}  proba={result.fraud_proba:.3f}  "
              f"anomaly={result.anomaly_score:.3f}  reason='{result.reason}'")
