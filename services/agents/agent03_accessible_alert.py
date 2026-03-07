"""
services/agents/agent03_accessible_alert.py
────────────────────────────────────────────
Layer 4: Contextual AI Agent & Mock-Bhashini Accessible Alert
Varaksha V2

For a blocked/flagged transaction this agent:
  1. Calls a mock LLM to generate an English legal warning citing Indian laws.
  2. Translates it to Hindi via a mock NMT (real Bhashini NMT endpoint stubbed).
  3. Generates an MP3 audio alert using edge-tts (Microsoft Neural TTS).
  4. Returns a structured AlertResult for the Streamlit dashboard to render.

Indian laws cited:
  - BNS §318(4)   : Cheating (≥ ₹1 L → 7 yr imprisonment)
  - IT Act §66D   : Cheating by personation using computer resource
  - PMLA §3       : Money-laundering offence

Usage:
    python services/agents/agent03_accessible_alert.py
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import pathlib
import re
from dataclasses import dataclass, field

log = logging.getLogger("varaksha.agent03")

AUDIO_DIR = pathlib.Path(__file__).resolve().parents[2] / "data" / "audio_alerts"
AUDIO_DIR.mkdir(parents=True, exist_ok=True)

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class FlaggedTransaction:
    transaction_id:   str
    vpa_hash:         str               # SHA-256 hex — never the raw VPA
    amount_inr:       float
    merchant_category: str
    risk_score:       float             # 0.0 – 1.0
    graph_flags:      list[str] = field(default_factory=list)   # e.g. ["FAN_OUT", "CYCLE"]


@dataclass
class AlertResult:
    transaction_id:  str
    english_warning: str
    hindi_warning:   str
    laws_cited:      list[str]
    audio_path:      pathlib.Path | None
    risk_level:      str                 # "HIGH" | "CRITICAL"


# ── Law citation builder ──────────────────────────────────────────────────────

def _build_law_citations(tx: FlaggedTransaction) -> list[str]:
    """Return the applicable Indian law citations for a flagged transaction."""
    laws = ["IT Act §66D — Cheating by personation using computer resource"]

    if tx.amount_inr >= 100_000:
        laws.append("BNS §318(4) — Cheating: value > ₹1,00,000 (up to 7 years imprisonment)")

    if "CYCLE" in tx.graph_flags or "FAN_IN" in tx.graph_flags:
        laws.append("PMLA §3 — Money-laundering offence (proceeds of a scheduled offence)")

    if tx.risk_score >= 0.90:
        laws.append("PMLA §4 — Punishment for money-laundering (rigorous imprisonment 3–7 yrs)")

    return laws


# ── Mock LLM (replace with real GPT-4o-mini / Groq call) ─────────────────────

def _mock_llm_english_warning(tx: FlaggedTransaction, laws: list[str]) -> str:
    """
    Mock LLM call — generates a court-ready English warning.

    Replace this function body with a real API call, e.g.:
        from openai import OpenAI
        client = OpenAI()
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    """
    amount_str = f"₹{tx.amount_inr:,.2f}"
    graph_str  = ", ".join(tx.graph_flags) if tx.graph_flags else "none"
    laws_str   = "; ".join(laws)

    warning = (
        f"FRAUD ALERT — Transaction {tx.transaction_id} has been BLOCKED. "
        f"A payment of {amount_str} to merchant category '{tx.merchant_category}' "
        f"has been flagged with a risk score of {tx.risk_score:.0%}. "
        f"Network analysis flags: [{graph_str}]. "
        f"This activity may constitute offences under Indian law: {laws_str}. "
        f"If you did not initiate this payment, immediately contact your bank's "
        f"24-hour helpline and file a complaint at cybercrime.gov.in "
        f"(National Cyber Crime Reporting Portal — Helpline: 1930)."
    )
    return warning


# ── Mock Bhashini NMT (Hindi translation) ────────────────────────────────────

def _mock_bhashini_nmt_translate(english_text: str, target_language: str = "hi") -> str:
    """
    Mock Bhashini NMT translation (Hindi).

    In production, replace with an actual Bhashini API call:
        POST https://dhruva-api.bhashini.gov.in/services/inference/pipeline
        Headers: Authorization: <BHASHINI_API_KEY>
        Body: {
            "pipelineTasks": [{"taskType": "translation",
                               "config": {"language": {"sourceLanguage": "en",
                                                       "targetLanguage": "hi"}}}],
            "inputData": {"input": [{"source": english_text}]}
        }

    The mock returns a templated Hindi warning so the demo is not API-dependent.
    """
    # Extract amount from English text for templating
    amount_match = re.search(r"₹[\d,]+\.?\d*", english_text)
    amount_str   = amount_match.group(0) if amount_match else "अज्ञात राशि"

    hindi_warning = (
        f"धोखाधड़ी की चेतावनी — यह लेन-देन रोक दिया गया है। "
        f"{amount_str} की राशि का भुगतान संदिग्ध पाया गया है। "
        f"यदि आपने यह भुगतान शुरू नहीं किया, तो तुरंत अपने बैंक से संपर्क करें "
        f"और cybercrime.gov.in पर शिकायत दर्ज करें। "
        f"साइबर अपराध हेल्पलाइन: 1930।"
    )
    return hindi_warning


# ── edge-tts Neural TTS ───────────────────────────────────────────────────────

async def _generate_audio(text: str, transaction_id: str, language: str = "hi") -> pathlib.Path:
    """
    Generate an MP3 audio alert using Microsoft edge-tts (Neural TTS).
    No API key required — uses the free Edge browser TTS endpoint.

    Voice mapping:
        Hindi   → hi-IN-SwaraNeural   (female, natural Hindi)
        English → en-IN-NeerjaNeural  (female, Indian English)
    """
    try:
        import edge_tts  # type: ignore
    except ImportError:
        log.warning("edge-tts not installed. Run: pip install edge-tts")
        return None  # type: ignore

    voice_map = {
        "hi": "hi-IN-SwaraNeural",
        "en": "en-IN-NeerjaNeural",
    }
    voice     = voice_map.get(language, "hi-IN-SwaraNeural")
    safe_id   = hashlib.md5(transaction_id.encode()).hexdigest()[:10]
    out_path  = AUDIO_DIR / f"alert_{safe_id}_{language}.mp3"

    communicate = edge_tts.Communicate(text=text, voice=voice)
    await communicate.save(str(out_path))
    log.info("Audio alert generated: %s", out_path)
    return out_path


# ── Main alert function ───────────────────────────────────────────────────────

async def generate_alert(tx: FlaggedTransaction) -> AlertResult:
    """
    Full pipeline: law citation → LLM warning → NMT translation → TTS audio.
    Returns an AlertResult ready for the Streamlit dashboard.
    """
    log.info("Generating alert for transaction %s (score=%.2f)", tx.transaction_id, tx.risk_score)

    laws            = _build_law_citations(tx)
    english_warning = _mock_llm_english_warning(tx, laws)
    hindi_warning   = _mock_bhashini_nmt_translate(english_warning, target_language="hi")
    audio_path      = await _generate_audio(hindi_warning, tx.transaction_id, language="hi")
    risk_level      = "CRITICAL" if tx.risk_score >= 0.85 else "HIGH"

    return AlertResult(
        transaction_id  = tx.transaction_id,
        english_warning = english_warning,
        hindi_warning   = hindi_warning,
        laws_cited      = laws,
        audio_path      = audio_path,
        risk_level      = risk_level,
    )


# ── CLI demo ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    demo_tx = FlaggedTransaction(
        transaction_id    = "TXN-DEMO-20260307-001",
        vpa_hash          = hashlib.sha256(b"victim@okaxis").hexdigest(),
        amount_inr        = 175_000.00,
        merchant_category = "P2P",
        risk_score        = 0.92,
        graph_flags       = ["FAN_OUT", "CYCLE"],
    )

    result = asyncio.run(generate_alert(demo_tx))

    print("\n" + "═" * 60)
    print("ENGLISH WARNING:")
    print(result.english_warning)
    print("\nHINDI WARNING:")
    print(result.hindi_warning)
    print("\nLAWS CITED:")
    for law in result.laws_cited:
        print(f"  • {law}")
    print(f"\nRISK LEVEL : {result.risk_level}")
    print(f"AUDIO FILE : {result.audio_path}")
    print("═" * 60)
