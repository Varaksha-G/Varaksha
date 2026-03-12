"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

// (audio constants removed — duration driven by real <audio> element)

// Waveform bar heights — fixed array, no Math.random() in render
const WAVEFORM_HEIGHTS = [4, 9, 6, 13, 8, 15, 5, 12, 7, 14, 4, 11, 6, 10, 5, 13, 8, 9, 4, 12];

// ── Supported languages ────────────────────────────────────────────────────
const LANGUAGES = [
  { code: "en", name: "English",   voiceLabel: "en-IN" },
  { code: "hi", name: "हिंदी",     voiceLabel: "hi-IN" },
  { code: "ta", name: "தமிழ்",    voiceLabel: "ta-IN" },
  { code: "te", name: "తెలుగు",   voiceLabel: "te-IN" },
  { code: "bn", name: "বাংলা",    voiceLabel: "bn-IN" },
  { code: "mr", name: "मराठी",    voiceLabel: "mr-IN" },
  { code: "gu", name: "ગુજરાતી",  voiceLabel: "gu-IN" },
  { code: "kn", name: "ಕನ್ನಡ",   voiceLabel: "kn-IN" },
] as const;

type LangCode = typeof LANGUAGES[number]["code"];

// ── Per-language personalised alert text ──────────────────────────────────
const ALERT_TEXT: Record<LangCode, { primary: string; secondary: string }> = {
  en: {
    primary:   "This transaction is suspicious. Your money is secure.",
    secondary: "₹99,999 suspicious payment blocked. High-value transfer at 3 AM from new device detected. Please contact your bank immediately and file a complaint at cybercrime.gov.in — Helpline: 1930.",
  },
  hi: {
    primary:   "यह लेनदेन संदिग्ध है। आपके पैसे सुरक्षित हैं।",
    secondary: "₹99,999 का संदिग्ध लेन-देन TXN20260310-00842 रोका गया। रात के 3 बजे नए डिवाइस से उच्च राशि का लेनदेन। कृपया अपने बैंक से संपर्क करें — साइबर अपराध हेल्पलाइन: 1930।",
  },
  ta: {
    primary:   "இந்த பரிவர்த்தனை சந்தேகக்கூடியது. உங்கள் பணம் பாதுகாப்பாக உள்ளது.",
    secondary: "₹99,999 சந்தேகக்கூடிய பரிவர்த்தனை TXN20260310-00842 தடுக்கப்பட்டது. இரவு 3 மணிக்கு புதிய சாதனத்தில் அதிக தொகை பரிமாற்றம். cybercrime.gov.in — உதவி எண்: 1930.",
  },
  te: {
    primary:   "ఈ లావాదేవీ అనుమానాస్పదంగా ఉంది. మీ డబ్బు సురక్షితంగా ఉంది.",
    secondary: "₹99,999 అనుమానాస్పద లావాదేవీ TXN20260310-00842 నిరోధించబడింది. రాత్రి 3 గంటలకు కొత్త పరికరం నుండి అధిక మొత్తం బదిలీ. cybercrime.gov.in — హెల్ప్‌లైన్: 1930.",
  },
  bn: {
    primary:   "এই লেনদেন সন্দেহজনক। আপনার টাকা নিরাপদ।",
    secondary: "₹99,999 সন্দেহজনক লেনদেন TXN20260310-00842 আটকানো হয়েছে। রাত ৩টায় নতুন ডিভাইস থেকে উচ্চ পরিমাণ স্থানান্তর। cybercrime.gov.in — হেল্পলাইন: 1930।",
  },
  mr: {
    primary:   "हे व्यवहार संशयास्पद आहे। तुमचे पैसे सुरक्षित आहेत.",
    secondary: "₹99,999 चा संशयास्पद व्यवहार TXN20260310-00842 थांबवला. रात्री 3 वाजता नवीन उपकरणावरून उच्च रक्कम हस्तांतरण. cybercrime.gov.in — हेल्पलाइन: 1930.",
  },
  gu: {
    primary:   "આ વ્યવહાર શંકાસ્પદ છે. તમારા પૈસા સુરક્ષિત છે.",
    secondary: "₹99,999 ની શંકાસ્પદ ચૂકવણી TXN20260310-00842 અટકાવ્યો. રાત્રે 3 વાગ્યે નવા ઉપકરણ પર ઊંચી રકમ ટ્રાન્સફર. cybercrime.gov.in — હેલ્પલાઇન: 1930.",
  },
  kn: {
    primary:   "ಈ ವ್ಯವಹಾರ ಅನುಮಾನಾಸ್ಪದವಾಗಿದೆ. ನಿಮ್ಮ ಹಣ ಸುರಕ್ಷಿತವಾಗಿದೆ.",
    secondary: "₹99,999 ಅನುಮಾನಾಸ್ಪದ ವ್ಯವಹಾರ TXN20260310-00842 ತಡೆದಿದೆ. ರಾತ್ರಿ 3 ಗಂಟೆಗೆ ಹೊಸ ಸಾಧನದಿಂದ ಹೆಚ್ಚಿನ ಮೊತ್ತ ವರ್ಗಾವಣೆ. cybercrime.gov.in — ಹೆಲ್ಪ್‌ಲೈನ್: 1930.",
  },
};

// ── Personalised downloadable report (language-aware) ─────────────────────
function buildReport(lang: LangCode): string {
  const langObj     = LANGUAGES.find((l) => l.code === lang)!;
  const alertT      = ALERT_TEXT[lang];
  const langSection = lang === "en"
    ? ""
    : `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ALERT NOTIFICATION  —  ${langObj.name}  (${langObj.voiceLabel} Neural MT)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${alertT.primary}

${alertT.secondary}
`;

  return `
VARAKSHA FRAUD INTELLIGENCE NETWORK
Legal Evidence Report  —  Auto-Generated
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Case Reference : TXN20260310-BLOCK-00842
Generated      : 2026-03-10T03:14:07Z  (IST)
Alert Language : ${langObj.name}  (${langObj.voiceLabel})
Classification : BLOCKED — HIGH RISK
System Version : Varaksha V2  ·  NPCI Hackathon 2026  ·  Blue Team
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TRANSACTION DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Transaction ID  : TXN20260310-00842
Sender VPA      : suraj.thakur@okicici
Receiver VPA    : cash.agent.77@paytm
Amount          : ₹99,999.00
Timestamp       : 2026-03-10  03:14:07  IST
Merchant Cat.   : Finance  (High-Risk Category)
Device Status   : FIRST-SEEN  (new device fingerprint)

VERDICT        : BLOCK
Risk Score     : 0.90 / 1.00  (RF: 0.89  ·  IsolationForest: 0.91)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FRAUD SIGNALS DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 1.  Off-hours transaction: 03:14 IST  (HOUR_SIN = -0.99 — deep anomaly)
 2.  High-value transfer exceeding ₹50,000 threshold  (AMOUNT_LOG = 11.51)
 3.  First-seen device fingerprint  (new device flag: TRUE)
 4.  Receiver VPA pattern "cash.agent.77" — synthetic mule indicator
 5.  ML composite score: 0.90  (Random Forest 0.89 · IsolationForest 0.91)
 6.  Merchant category "Finance" — elevated risk category
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
APPLICABLE LEGAL PROVISIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Bharatiya Nyaya Sanhita (BNS) §318(4)
    Cheating by impersonation — Punishment: Imprisonment up to 7 years + fine

  Information Technology Act §66C
    Identity theft (SIM-swap / credential hijack)
    Punishment: Imprisonment up to 3 years + fine up to ₹1,00,000

  Information Technology Act §66D
    Cheating by personation using computer resource
    Punishment: Imprisonment up to 3 years + fine up to ₹1,00,000

  Prevention of Money Laundering Act (PMLA) §3
    Projecting proceeds of crime as untainted property

  DPDP Act 2023 §7(g)  [processing legal basis]
    Legitimate use — ensuring safety and security / detecting unlawful activity
    No explicit consent required when a PSP invokes this security exception

  NPCI OC-215/2025-26  [operational compliance]
    Per-VPA daily scoring cap enforced by Varaksha gateway (100 req / 24 h)
    Architecture is physically incapable of exceeding NPCI rate limits

  RBI Master Directions — Digital Payment Security Controls
    Risk-based transaction monitoring (RBI 2026 mandate)
    Varaksha fulfils the PSP obligation for dynamic risk-scoring layer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SYSTEM EVIDENCE CHAIN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SHA-256(suraj.thakur@okicici) : 7f3a9c12e803b5d1902871ea6cd048f3...
Consortium Cache               : HIT — Risk delta: 0.90 written to DashMap
Graph Analysis                 : Off-path async — pending corroboration
Alert Delivery                 : Neural MT (${langObj.voiceLabel}) + edge-tts MP3${langSection}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CERTIFYING SYSTEM : Varaksha V2 Fraud Intelligence Network
                    NPCI Hackathon 2026  ·  Blue Team  ·  DEMONSTRATION ONLY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`.trimStart();
}

// ── Formatting helper: mm:ss (takes seconds) ────────────────────────────────
function fmtTime(sec: number): string {
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${m}:${String(s).padStart(2, "0")}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

type DlState = "idle" | "generating" | "done";

export function LegalReport() {
  const [isPlaying,     setIsPlaying    ] = useState(false);
  const [progress,      setProgress     ] = useState(0);
  const [dlState,       setDlState      ] = useState<DlState>("idle");
  const [language,      setLanguage     ] = useState<LangCode>("hi");
  const [audioDuration, setAudioDuration] = useState(0);
  const [currentTimeSec,setCurrentTimeSec] = useState(0);
  const audioRef = useRef<HTMLAudioElement>(null);

  const langObj = LANGUAGES.find((l) => l.code === language)!;
  const alertT  = ALERT_TEXT[language];

  // ── Reset audio whenever language changes ───────────────────────────────
  useEffect(() => {
    const audio = audioRef.current;
    if (audio) {
      audio.pause();
      audio.load();
    }
    setIsPlaying(false);
    setProgress(0);
    setCurrentTimeSec(0);
  }, [language]);

  // ── Play / pause ───────────────────────────────────────────────────────────
  const handlePlayPause = useCallback(() => {
    const audio = audioRef.current;
    if (!audio) return;
    if (isPlaying) {
      audio.pause();
      setIsPlaying(false);
    } else {
      if (progress >= 100) {
        audio.currentTime = 0;
        setProgress(0);
        setCurrentTimeSec(0);
      }
      audio.play().catch(() => {});
      setIsPlaying(true);
    }
  }, [isPlaying, progress]);

  // ── PDF / evidence-file download ─────────────────────────────────────────
  const handleDownload = useCallback(() => {
    if (dlState === "generating") return;
    setDlState("generating");
    setTimeout(() => {
      const blob = new Blob([buildReport(language)], { type: "text/plain;charset=utf-8" });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = "varaksha-evidence-TXN20260310-00842.txt";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setDlState("done");
      setTimeout(() => setDlState("idle"), 3500);
    }, 1600);
  }, [dlState, language]);

  const durationStr = audioDuration > 0 ? fmtTime(audioDuration) : "0:08";

  return (
    <section className="border border-cream/[0.08] overflow-hidden">

      {/* ── Module header ── */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-cream/[0.07] bg-cream/[0.025]">
        <div className="flex items-center gap-2.5">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-block" />
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/60 font-semibold">
            Module E — Legal Report & Accessible Alert
          </span>
        </div>
          <span className="font-courier text-[0.52rem] text-cream/18">
            BNS §318(4) &middot; IT Act §66C/D &middot; DPDP §7(g) &middot; NPCI OC-215
          </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-0 divide-y lg:divide-y-0 lg:divide-x divide-cream/[0.07]">

        {/* ── Left: victim alert card ─────────────────────────────────────── */}
        <div className="p-6 lg:p-8">

          {/* BLOCKED header */}
          <div className="flex items-center gap-3 mb-6">
            <motion.div
              className="w-10 h-10 border-2 border-block flex items-center justify-center shrink-0"
              animate={{ borderColor: ["#C0392B", "#8b1a1a", "#C0392B"] }}
              transition={{ duration: 2.5, repeat: Infinity }}
            >
              <span className="font-courier text-block font-bold text-xs">✕</span>
            </motion.div>
            <div>
              <p className="font-barlow text-[0.52rem] tracking-[0.28em] uppercase text-block/55 mb-0.5">
                Varaksha Verdict
              </p>
              <p className="font-courier font-bold text-block leading-none" style={{ fontSize: "1.8rem" }}>
                BLOCKED
              </p>
            </div>
          </div>

          {/* Transaction details rows */}
          <div className="border border-block/10 bg-block/[0.03] mb-6">
            {[
              { label: "TRANSACTION",  value: "TXN20260310-00842" },
          { label: "FROM",         value: "suraj.thakur@okicici" },
              { label: "TO",           value: "cash.agent.77@paytm" },
              { label: "AMOUNT",       value: "₹99,999.00" },
              { label: "TIME",         value: "03:14:07 IST  (off-hours)" },
              { label: "RISK SCORE",   value: "0.90 / 1.00" },
            ].map((r) => (
              <div
                key={r.label}
                className="flex gap-4 px-4 py-2.5 border-b border-block/[0.06] last:border-0"
              >
                <span className="font-courier text-[0.56rem] tracking-wider uppercase text-cream/22 w-24 shrink-0 pt-px">
                  {r.label}
                </span>
                <span className={`font-courier text-[0.72rem] ${
                  r.label === "RISK SCORE" ? "text-block" :
                  r.label === "AMOUNT"     ? "text-saffron" :
                                             "text-cream/60"
                }`}>
                  {r.value}
                </span>
              </div>
            ))}
          </div>

          {/* ── Language selector ── */}
          <div className="border border-cream/[0.06] bg-cream/[0.015] p-3 mb-5">
            <div className="flex items-center justify-between mb-2.5">
              <span className="font-barlow text-[0.48rem] tracking-widest uppercase text-cream/25">
                Alert language
              </span>
              <AnimatePresence mode="wait">
                <motion.span
                  key={language}
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 4 }}
                  className="font-courier text-[0.52rem] text-saffron/60"
                >
                  {langObj.voiceLabel} Neural MT + edge-tts
                </motion.span>
              </AnimatePresence>
            </div>
            <div className="flex gap-1 flex-wrap">
              {LANGUAGES.map((l) => (
                <button
                  key={l.code}
                  onClick={() => setLanguage(l.code)}
                  className={`px-2.5 py-1 font-barlow text-[0.62rem] tracking-wide transition-all duration-200 ${
                    language === l.code
                      ? "bg-saffron/15 border border-saffron/40 text-saffron shadow-[0_0_8px_rgba(217,119,6,0.15)]"
                      : "border border-cream/[0.08] text-cream/35 hover:border-cream/20 hover:text-cream/55"
                  }`}
                >
                  {l.name}
                </button>
              ))}
            </div>
          </div>

          {/* ── Alert card ── */}
          <div className="border border-saffron/15 bg-saffron/[0.033] p-5 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <span className="font-barlow text-[0.52rem] tracking-[0.28em] uppercase text-saffron/45">
                Neural MT &middot; {langObj.voiceLabel} Translation
              </span>
              <div className="flex-1 h-px bg-saffron/10" />
              <span className="font-barlow text-[0.48rem] tracking-widest uppercase text-saffron/25">
                edge-tts
              </span>
            </div>

            {/* Primary — translated alert */}
            <p
              className="text-cream leading-[1.9] mb-2"
              style={{ fontSize: "clamp(1rem, 2vw, 1.2rem)", fontFamily: "sans-serif" }}
            >
              {alertT.primary}
            </p>

            {/* Secondary — extended personalised alert */}
            <p className="font-barlow text-[0.78rem] text-cream/60 font-semibold leading-relaxed mb-5">
              {alertT.secondary}
            </p>

            {/* ── Audio player ── */}
            <div className="border border-cream/[0.08] bg-ink/30 p-4">
              <div className="flex items-center gap-4">

                {/* Play/pause button */}
                <motion.button
                  onClick={handlePlayPause}
                  whileTap={{ scale: 0.93 }}
                  className="w-9 h-9 flex items-center justify-center border border-saffron/30 bg-saffron/[0.07] hover:bg-saffron/15 transition-colors shrink-0"
                >
                  {isPlaying ? (
                    /* Pause icon */
                    <svg viewBox="0 0 12 12" className="w-3 h-3 fill-saffron">
                      <rect x="2" y="1.5" width="3" height="9" />
                      <rect x="7" y="1.5" width="3" height="9" />
                    </svg>
                  ) : (
                    /* Play icon */
                    <svg viewBox="0 0 12 12" className="w-3 h-3 fill-saffron">
                      <polygon points="2,1 11,6 2,11" />
                    </svg>
                  )}
                </motion.button>

                {/* Waveform + scrubber */}
                <div className="flex-1 min-w-0">
                  {/* Animated waveform bars */}
                  <div className="flex items-end gap-[2px] mb-2 h-5">
                    {WAVEFORM_HEIGHTS.map((h, i) => (
                      <motion.div
                        key={i}
                        className="w-[3px] rounded-sm bg-saffron/40"
                        style={{ height: h }}
                        animate={
                          isPlaying
                            ? { height: [`${h}px`, `${Math.max(2, Math.round(h * 0.3))}px`, `${h}px`] }
                            : { height: `${h}px` }
                        }
                        transition={{
                          duration:   0.68,
                          repeat:     isPlaying ? Infinity : 0,
                          delay:      i * 0.045,
                          ease:       "easeInOut",
                        }}
                      />
                    ))}
                  </div>

                  {/* Progress bar */}
                  <div className="h-1 bg-cream/[0.07] overflow-hidden relative">
                    <motion.div
                      className="h-full bg-saffron/60"
                      animate={{ width: `${progress}%` }}
                      transition={{ duration: 0.1, ease: "linear" }}
                    />
                  </div>
                </div>

                {/* Time display */}
                <div className="text-right shrink-0">
                  <p className="font-courier text-[0.64rem] text-saffron/60 tabular-nums">
                    {fmtTime(currentTimeSec)}
                  </p>
                  <p className="font-courier text-[0.52rem] text-cream/18 tabular-nums">
                    {durationStr}
                  </p>
                </div>
              </div>

              <div className="flex items-center justify-between mt-3">
                <p className="font-barlow text-[0.48rem] tracking-widest uppercase text-cream/16">
                  Microsoft Neural TTS &middot; edge-tts
                </p>
                <AnimatePresence mode="wait">
                  <motion.p
                    key={language}
                    initial={{ opacity: 0, x: 6 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0 }}
                    className="font-courier text-[0.5rem] text-saffron/35"
                  >
                    {langObj.voiceLabel} Neural
                  </motion.p>
                </AnimatePresence>
              </div>
            </div>
          </div>

          {/* ── Download button ── */}
          <motion.button
            onClick={handleDownload}
            disabled={dlState === "generating"}
            whileHover={dlState === "idle" ? { scale: 1.01 } : {}}
            whileTap={dlState === "idle"   ? { scale: 0.98 } : {}}
            className={`w-full flex items-center justify-center gap-3 py-4 font-barlow font-semibold text-[0.76rem] tracking-[0.14em] uppercase transition-all duration-300 ${
              dlState === "done"
                ? "bg-allow/15 border border-allow/25 text-allow cursor-default"
                : dlState === "generating"
                  ? "bg-cream/[0.06] border border-cream/20 text-cream/40 font-semibold cursor-not-allowed"
                  : "bg-block text-cream border border-block hover:bg-block/85 cursor-pointer shadow-[0_3px_24px_rgba(192,57,43,0.18)]"
            }`}
          >
            <AnimatePresence mode="wait">
              {dlState === "idle" && (
                <motion.span
                  key="idle"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-2.5"
                >
                  {/* Download icon */}
                  <svg viewBox="0 0 16 16" className="w-4 h-4 fill-current shrink-0">
                    <path d="M8 11L3 6h3V1h4v5h3L8 11z" />
                    <rect x="2" y="13" width="12" height="2" />
                  </svg>
                  Download Court-Ready PDF (BNS §318(4) &amp; IT Act §66C/D &amp; DPDP §7(g))
                </motion.span>
              )}

              {dlState === "generating" && (
                <motion.span
                  key="gen"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-2.5"
                >
                  <motion.span
                    className="inline-block w-2 h-2 rounded-full bg-cream/30"
                    animate={{ opacity: [1, 0.2, 1] }}
                    transition={{ duration: 0.6, repeat: Infinity }}
                  />
                  Generating evidence report…
                </motion.span>
              )}

              {dlState === "done" && (
                <motion.span
                  key="done"
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-2.5"
                >
                  <svg viewBox="0 0 14 14" fill="none" className="w-4 h-4 shrink-0">
                    <polyline
                      points="2,7 5.5,10.5 12,3"
                      stroke="currentColor"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  Report downloaded — varaksha-evidence-TXN20260310-00842.txt
                </motion.span>
              )}
            </AnimatePresence>
          </motion.button>

        </div>

        {/* ── Right: legal framework sidebar ──────────────────────────────── */}
        <div className="p-6 bg-cream/[0.018] flex flex-col gap-6">

          <div>
            <p className="font-barlow text-[0.52rem] tracking-[0.28em] uppercase text-saffron/45 mb-3">
              Legal Framework
            </p>
            {[
              {
                code:  "BNS §318(4)",
                title: "Cheating by Impersonation",
                desc:  "Imprisonment up to 7 years and fine.",
                color: "text-block",
              },
              {
                code:  "IT Act §66C",
                title: "Identity Theft",
                desc:  "SIM-swap / credential hijack. Up to 3 years + ₹1L fine.",
                color: "text-block",
              },
              {
                code:  "IT Act §66D",
                title: "Cheating by Personation",
                desc:  "Via computer resource. Up to 3 years + ₹1L fine.",
                color: "text-saffron",
              },
              {
                code:  "PMLA §3",
                title: "Money Laundering",
                desc:  "Projecting proceeds of crime as untainted.",
                color: "text-saffron",
              },
              {
                code:  "DPDP §7(g)",
                title: "Legitimate Use — Security",
                desc:  "Lawful basis for fraud detection without explicit consent.",
                color: "text-allow",
              },
              {
                code:  "NPCI OC-215",
                title: "Rate Cap — 2025-26",
                desc:  "Per-VPA daily scoring limit enforced at gateway layer.",
                color: "text-allow",
              },
              {
                code:  "RBI 2FA 2026",
                title: "Risk-Based Monitoring",
                desc:  "Varaksha is the mandated dynamic risk-scoring layer.",
                color: "text-cream/60 font-semibold",
              },
            ].map((law) => (
              <div key={law.code} className="border-b border-cream/[0.05] py-3.5 last:border-0">
                <p className={`font-courier text-[0.72rem] font-bold mb-0.5 ${law.color}`}>
                  {law.code}
                </p>
                <p className="font-barlow text-[0.72rem] text-cream/55 font-medium mb-0.5">
                  {law.title}
                </p>
                <p className="font-barlow text-[0.65rem] text-cream/28 leading-relaxed">
                  {law.desc}
                </p>
              </div>
            ))}
          </div>

          {/* Evidence chain */}
          <div>
            <p className="font-barlow text-[0.52rem] tracking-[0.28em] uppercase text-cream/25 mb-3">
              Evidence Chain
            </p>
            {[
              { step: "01", label: "SHA-256 VPA Hash",     detail: "Privacy-preserving · no raw PII" },
              { step: "02", label: "ML Ensemble Score",    detail: "RF=0.89  ·  XGB=0.91  →  0.90" },
              { step: "03", label: "Gateway Verdict Log",  detail: "Timestamped  ·  immutable" },
              { step: "04", label: "Alert Delivery",      detail: `${langObj.voiceLabel} Neural MT  ·  edge-tts MP3` },
            ].map((e) => (
              <div key={e.step} className="flex gap-3 mb-3.5 last:mb-0">
                <span className="font-courier text-[0.58rem] text-saffron/35 shrink-0 pt-px">
                  {e.step}
                </span>
                <div>
                  <p className="font-barlow text-[0.68rem] text-cream/55 font-medium">
                    {e.label}
                  </p>
                  <p className="font-barlow text-[0.58rem] text-cream/22 leading-relaxed">
                    {e.detail}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* Disclaimer */}
          <p className="font-barlow text-[0.5rem] text-cream/14 leading-relaxed mt-auto">
            This interface is a demonstration for NPCI Hackathon 2026. No real
            transaction data is stored or transmitted. All VPAs and amounts are
            synthetic test fixtures.
          </p>

        </div>
      </div>

      {/* Hidden audio element — pre-generated Neural TTS MP3s */}
      {/* eslint-disable-next-line jsx-a11y/media-has-caption */}
      <audio
        ref={audioRef}
        src={`/alert-${language}.mp3`}
        preload="auto"
        onLoadedMetadata={() => {
          const audio = audioRef.current;
          if (audio) setAudioDuration(audio.duration);
        }}
        onTimeUpdate={() => {
          const audio = audioRef.current;
          if (!audio || !audio.duration) return;
          setCurrentTimeSec(audio.currentTime);
          setProgress((audio.currentTime / audio.duration) * 100);
        }}
        onEnded={() => {
          setIsPlaying(false);
          setProgress(100);
        }}
      />
    </section>
  );
}
