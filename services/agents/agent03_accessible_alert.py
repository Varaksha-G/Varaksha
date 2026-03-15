"""
services/agents/agent03_accessible_alert.py
────────────────────────────────────────────
Layer 4: Contextual AI Agent — Multilingual Accessible Alert
Varaksha V2

For a blocked/flagged transaction this agent:
  1. Calls a mock LLM to generate an English legal warning citing Indian laws.
  2. Translates it to the preferred language via multilingual NMT templates
     (8 Indian languages supported; swap _translate_warning() for a real
     NMT API — e.g. IndicTrans2, Google Translate, or any ULCA-compliant
     service — in production).
  3. Generates an MP3 audio alert using edge-tts (Microsoft Neural TTS,
     language-matched voice, no API key required).
  4. Returns a structured AlertResult for the Streamlit / Next.js dashboard.

Supported languages (ISO 639-1):
  en · hi · ta · te · bn · mr · gu · kn · ml

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
from dataclasses import dataclass, field

log = logging.getLogger("varaksha.agent03")

AUDIO_DIR = pathlib.Path(__file__).resolve().parents[2] / "data" / "audio_alerts"
AUDIO_DIR.mkdir(parents=True, exist_ok=True)

# ── Supported languages ───────────────────────────────────────────────────────
# (lang_code) → (display_name, edge-tts Neural voice)
SUPPORTED_LANGUAGES: dict[str, tuple[str, str]] = {
    "en": ("English",   "en-IN-NeerjaNeural"),
    "hi": ("Hindi",     "hi-IN-SwaraNeural"),
    "ta": ("Tamil",     "ta-IN-PallaviNeural"),
    "te": ("Telugu",    "te-IN-ShrutiNeural"),
    "bn": ("Bengali",   "bn-IN-TanishaaNeural"),
    "mr": ("Marathi",   "mr-IN-AarohiNeural"),
    "gu": ("Gujarati",  "gu-IN-DhwaniNeural"),
    "kn": ("Kannada",   "kn-IN-SapnaNeural"),
    "ml": ("Malayalam", "ml-IN-SobhanaNeural"),
}

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
    transaction_id:     str
    english_warning:    str
    translated_warning: str               # Warning in preferred_language
    language:           str               # ISO 639-1 e.g. "hi", "ta"
    laws_cited:         list[str]
    audio_path:         pathlib.Path | None
    risk_level:         str               # "HIGH" | "CRITICAL"


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


# ── Multilingual NMT translation ─────────────────────────────────────────────

def _translate_warning(english_text: str, target_language: str, tx: FlaggedTransaction) -> str:
    """
    Produce a personalised alert in the requested language using templated NMT.

    In production, replace with a real NMT API, e.g.:
      • IndicTrans2  (open-source, 22 Indic languages)
      • Google Cloud Translation API
      • Any ULCA-compliant service (ulcaapi.ai4bharat.org)

    Templates are personalised — they include the transaction ID, amount, and
    risk score so each alert feels specific to the flagged event.
    """
    if target_language == "en" or target_language not in SUPPORTED_LANGUAGES:
        return english_text  # No translation needed

    amount_str = f"₹{tx.amount_inr:,.0f}"
    score_pct  = f"{tx.risk_score:.0%}"
    txn_id     = tx.transaction_id

    _TEMPLATES: dict[str, str] = {
        "hi": (
            f"धोखाधड़ी की चेतावनी — लेन-देन {txn_id} रोक दिया गया है। "
            f"{amount_str} की राशि का भुगतान संदिग्ध पाया गया है "
            f"(जोखिम स्कोर: {score_pct})। "
            f"यदि आपने यह भुगतान शुरू नहीं किया, तो तुरंत अपने बैंक से संपर्क करें "
            f"और cybercrime.gov.in पर शिकायत दर्ज करें। "
            f"साइबर अपराध हेल्पलाइन: 1930।"
        ),
        "ta": (
            f"மோசடி எச்சரிக்கை — பரிவர்த்தனை {txn_id} தடுக்கப்பட்டது। "
            f"{amount_str} தொகை சந்தேகக்கூடியதாகக் கண்டறியப்பட்டது "
            f"(ஆபத்து மதிப்பெண்: {score_pct})। "
            f"நீங்கள் இந்தப் பரிவர்த்தனையை தொடங்கவில்லை என்றால் உடனடியாக "
            f"உங்கள் வங்கியை தொடர்பு கொள்ளுங்கள், "
            f"cybercrime.gov.in இல் புகார் அளியுங்கள். "
            f"சைபர் கிரைம் உதவி எண்: 1930."
        ),
        "te": (
            f"మోసపూరిత హెచ్చరిక — లావాదేవీ {txn_id} నిరోధించబడింది। "
            f"{amount_str} చెల్లింపు అనుమానాస్పదంగా గుర్తించబడింది "
            f"(ప్రమాద స్కోర్: {score_pct})। "
            f"మీరు ఈ చెల్లింపు ప్రారంభించలేదు అంటే వెంటనే మీ బ్యాంకుని "
            f"సంప్రదించండి, cybercrime.gov.in లో ఫిర్యాదు నమోదు చేయండి. "
            f"సైబర్ క్రైమ్ హెల్ప్‌లైన్: 1930."
        ),
        "bn": (
            f"জালিয়াতির সতর্কতা — লেনদেন {txn_id} আটকানো হয়েছে। "
            f"{amount_str} পরিমাণের পেমেন্ট সন্দেহজনক পাওয়া গেছে "
            f"(ঝুঁকি স্কোর: {score_pct})। "
            f"আপনি এই পেমেন্ট শুরু না করলে অবিলম্বে আপনার ব্যাংকে যোগাযোগ করুন "
            f"এবং cybercrime.gov.in-এ অভিযোগ দায়ের করুন। "
            f"সাইবার ক্রাইম হেল্পলাইন: 1930।"
        ),
        "mr": (
            f"फसवणूकीची सूचना — व्यवहार {txn_id} थांबवण्यात आला आहे। "
            f"{amount_str} ची रक्कम संशयास्पद आढळली आहे "
            f"(जोखीम स्कोर: {score_pct})। "
            f"जर तुम्ही हा व्यवहार सुरू केला नसेल, तर लगेच तुमच्या बँकेशी संपर्क साधा "
            f"आणि cybercrime.gov.in वर तक्रार नोंदवा. "
            f"सायबर क्राइम हेल्पलाइन: 1930."
        ),
        "gu": (
            f"છેતરપિંડીની ચેતવણી — વ્યવહાર {txn_id} અટકાવ્યો છે। "
            f"{amount_str} ની ચૂકવણી શંકાસ્પદ પ્રવૃત્તિ તરીકે ઓળખવામાં આવી "
            f"(જોખમ સ્કોર: {score_pct})। "
            f"જો તમે આ ચૂકવણી શરૂ ન કરી હોય, તો તરત જ તમારી બેંકનો સંપર્ક કરો "
            f"અને cybercrime.gov.in પર ફરિયાદ નોંધાવો. "
            f"સાઇબર ક્રાઇમ હેલ્પલાઇન: 1930."
        ),
        "kn": (
            f"ವಂಚನೆ ಎಚ್ಚರಿಕೆ — ವ್ಯವಹಾರ {txn_id} ತಡೆದಿದೆ। "
            f"{amount_str} ಮೊತ್ತದ ಪಾವತಿ ಅನುಮಾನಾಸ್ಪದವೆಂದು ಪತ್ತೆಯಾಗಿದೆ "
            f"(ಅಪಾಯ ಸ್ಕೋರ್: {score_pct})। "
            f"ನೀವು ಈ ಪಾವತಿ ಪ್ರಾರಂಭಿಸಿಲ್ಲ ಎಂದಾದರೆ ತಕ್ಷಣ ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಅನ್ನು "
            f"ಸಂಪರ್ಕಿಸಿ, cybercrime.gov.in ನಲ್ಲಿ ದೂರು ದಾಖಲಿಸಿ. "
            f"ಸೈಬರ್ ಕ್ರೈಮ್ ಹೆಲ್ಪ್‌ಲೈನ್: 1930."
        ),
        "ml": (
            f"തട്ടിപ്പ് മുന്നറിയിപ്പ് — ഇടപാട് {txn_id} തടഞ്ഞു. "
            f"{amount_str} തുകയുടെ പേയ്‌മെന്റ് സംശയകരമായി കണ്ടെത്തി "
            f"(അപകടസ്‌കോർ: {score_pct})। "
            f"ഈ പേയ്‌മെന്റ് നിങ്ങൾ ആരംഭിക്കാതിരുന്നാൽ ഉടൻ "
            f"ബാങ്കുമായി ബന്ധപ്പെടുക, cybercrime.gov.in-ൽ പരാതി നൽകുക. "
            f"സൈബർ ക്രൈം ഹെൽപ്പ്‌ലൈൻ: 1930."
        ),
    }
    return _TEMPLATES.get(target_language, english_text)


# ── edge-tts Neural TTS ───────────────────────────────────────────────────────

async def _generate_audio(text: str, transaction_id: str, language: str = "hi") -> pathlib.Path:
    """
    Generate an MP3 audio alert using Microsoft edge-tts (Neural TTS).
    No API key required — uses the free Edge browser TTS endpoint.

    Voice is selected from SUPPORTED_LANGUAGES for the requested language code.
    Falls back to hi-IN-SwaraNeural for unsupported codes.
    """
    try:
        import edge_tts  # type: ignore
    except ImportError:
        log.warning("edge-tts not installed. Run: pip install edge-tts")
        return None  # type: ignore

    _, voice = SUPPORTED_LANGUAGES.get(language, SUPPORTED_LANGUAGES["hi"])
    safe_id   = hashlib.md5(transaction_id.encode()).hexdigest()[:10]
    out_path  = AUDIO_DIR / f"alert_{safe_id}_{language}.mp3"

    communicate = edge_tts.Communicate(text=text, voice=voice)
    await communicate.save(str(out_path))
    log.info("Audio alert generated: %s", out_path)
    return out_path


# ── Main alert function ───────────────────────────────────────────────────────

async def generate_alert(
    tx: FlaggedTransaction,
    preferred_language: str = "hi",
) -> AlertResult:
    """
    Full pipeline: law citation → LLM warning → multilingual NMT → TTS audio.

    Args:
        tx:                 The flagged transaction.
        preferred_language: ISO 639-1 code of the user's preferred language
                            (default "hi"). Falls back to "hi" if unsupported.

    Returns an AlertResult ready for the Streamlit / Next.js dashboard.
    """
    lang = preferred_language if preferred_language in SUPPORTED_LANGUAGES else "hi"
    log.info(
        "Generating %s alert for transaction %s (score=%.2f)",
        lang, tx.transaction_id, tx.risk_score,
    )

    laws               = _build_law_citations(tx)
    english_warning    = _mock_llm_english_warning(tx, laws)
    translated_warning = _translate_warning(english_warning, lang, tx)
    audio_text         = translated_warning  # TTS speaks in the preferred language
    audio_path         = await _generate_audio(audio_text, tx.transaction_id, language=lang)
    risk_level         = "CRITICAL" if tx.risk_score >= 0.85 else "HIGH"

    return AlertResult(
        transaction_id     = tx.transaction_id,
        english_warning    = english_warning,
        translated_warning = translated_warning,
        language           = lang,
        laws_cited         = laws,
        audio_path         = audio_path,
        risk_level         = risk_level,
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
    lang_name = SUPPORTED_LANGUAGES.get(result.language, ("Unknown",))[0]
    print(f"\n{lang_name.upper()} WARNING ({result.language}):")
    print(result.translated_warning)
    print("\nLAWS CITED:")
    for law in result.laws_cited:
        print(f"  • {law}")
    print(f"\nRISK LEVEL : {result.risk_level}")
    print(f"AUDIO FILE : {result.audio_path}")
    print("═" * 60)
