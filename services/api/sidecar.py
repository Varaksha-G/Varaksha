from __future__ import annotations

from fastapi import FastAPI, HTTPException
import numpy as np
from pydantic import BaseModel

from services.local_engine.infer import VarakshaScoringEngine


app = FastAPI(title="Varaksha Sidecar", version="1.0.0")
engine = VarakshaScoringEngine()


class ScoreRequest(BaseModel):
    merchant_category: int
    transaction_type: int
    device_type: int
    amount: float
    hour_of_day: int
    day_of_week: int
    transactions_last_1h: int
    transactions_last_24h: int
    amount_zscore: float
    gps_delta_km: float
    is_new_device: int
    is_new_merchant: int
    balance_drain_ratio: float
    account_age_days: int
    previous_failed_attempts: int
    transfer_cashout_flag: int


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/score")
def score(body: ScoreRequest) -> dict[str, object]:
    try:
        x = np.array([[
            float(body.merchant_category),
            float(body.transaction_type),
            float(body.device_type),
            float(body.amount),
            float(body.hour_of_day),
            float(body.day_of_week),
            float(body.transactions_last_1h),
            float(body.transactions_last_24h),
            float(body.amount_zscore),
            float(body.gps_delta_km),
            float(body.is_new_device),
            float(body.is_new_merchant),
            float(body.balance_drain_ratio),
            float(body.account_age_days),
            float(body.previous_failed_attempts),
            float(body.transfer_cashout_flag),
        ]], dtype=np.float32)

        # Use the real ONNX sessions from infer.py.
        rf_out = engine._rf_sess.run(None, {"X": x})  # pylint: disable=protected-access
        rf_prob = float(rf_out[1][0][1])

        iso_score = 0.0
        if engine._iso_sess is not None:  # pylint: disable=protected-access
            iso_out = engine._iso_sess.run(None, {"X": x})  # pylint: disable=protected-access
            iso_score = float(iso_out[1].flat[0])

        iso_norm = max(0.0, min(1.0, (iso_score + 1.0) / 2.0))
        risk_score = max(0.0, min(1.0, (rf_prob * 0.7) + (iso_norm * 0.3)))

        return {
            "risk_score": round(risk_score, 4),
            "reason": "rf+if composite",
        }
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"sidecar inference failed: {exc}") from exc
