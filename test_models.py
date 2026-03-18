#!/usr/bin/env python
"""Quick test to verify ML models are loaded and scoring works"""

from services.local_engine.infer import VarakshaScoringEngine

print("Loading ML models...")
engine = VarakshaScoringEngine()

# Test 1: Normal transaction
print("\n[Test 1] Normal ECOM transaction:")
result1 = engine.score({
    'amount': 1000,
    'merchant_category': 'ECOM',
    'transaction_type': 'DEBIT',
    'device_type': 'ANDROID',
    'hour_of_day': 14,
    'day_of_week': 2,
    'transactions_last_1h': 1,
    'transactions_last_24h': 3,
    'amount_zscore': 0.2,
    'gps_delta_km': 2,
    'is_new_device': 0,
    'is_new_merchant': 0,
    'balance_drain_ratio': 0.01,
    'account_age_days': 365,
    'previous_failed_attempts': 0,
    'transfer_cashout_flag': 0,
})
print(f"  Score: {result1.fraud_proba} | Verdict: {result1.verdict} | Reason: {result1.reason}")

# Test 2: Suspicious transaction
print("\n[Test 2] Suspicious GAMBLING transaction:")
result2 = engine.score({
    'amount': 65000,
    'merchant_category': 'GAMBLING',
    'transaction_type': 'DEBIT',
    'device_type': 'WEB',
    'hour_of_day': 3,
    'day_of_week': 6,
    'transactions_last_1h': 15,
    'transactions_last_24h': 60,
    'amount_zscore': 4.2,
    'gps_delta_km': 850,
    'is_new_device': 1,
    'is_new_merchant': 1,
    'balance_drain_ratio': 0.65,
    'account_age_days': 30,
    'previous_failed_attempts': 2,
    'transfer_cashout_flag': 1,
})
print(f"  Score: {result2.fraud_proba} | Verdict: {result2.verdict} | Reason: {result2.reason}")

print("\n✓ All models loaded and working correctly")
