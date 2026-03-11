"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

// 8-second simulated audio clip (100ms ticks, advance by 1.25% each tick)
const AUDIO_DURATION_MS   = 8000;
const AUDIO_TICK_MS       = 100;
const AUDIO_STEP_PCT      = 100 / (AUDIO_DURATION_MS / AUDIO_TICK_MS);

// Waveform bar heights — fixed array, no Math.random() in render
const WAVEFORM_HEIGHTS = [4, 9, 6, 13, 8, 15, 5, 12, 7, 14, 4, 11, 6, 10, 5, 13, 8, 9, 4, 12];

// ── Legal report text blob ────────────────────────────────────────────────────
// This is downloaded as a .txt evidence file when the button is clicked.

const REPORT_TEXT = `
VARAKSHA FRAUD INTELLIGENCE NETWORK
Legal Evidence Report  —  Auto-Generated
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Case Reference : TXN20260310-BLOCK-00842
Generated      : 2026-03-10T03:14:07Z  (IST)
Classification : BLOCKED — HIGH RISK
System Version : Varaksha V2  ·  NPCI Hackathon 2026  ·  Blue Team

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TRANSACTION DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Transaction ID  : TXN20260310-00842
Sender VPA      : suraj.thakur@okicici
Receiver VPA    : cash.agent.77@paytm
Amount          : ₹99,999.00
Timestamp       : 2026-03-10  03:14:07  IST
Merchant Cat.   : Finance  (High-Risk Category)
Device Status   : FIRST-SEEN  (new device fingerprint)

VERDICT        : BLOCK
Risk Score     : 0.90 / 1.00  (RF: 0.89  ·  IsolationForest: 0.91)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FRAUD SIGNALS DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 1.  Off-hours transaction: 03:14 IST  (HOUR_SIN = -0.99 — deep anomaly)
 2.  High-value transfer exceeding ₹50,000 threshold  (AMOUNT_LOG = 11.51)
 3.  First-seen device fingerprint  (new device flag: TRUE)
 4.  Receiver VPA pattern "cash.agent.77" — synthetic mule indicator
 5.  ML composite score: 0.90  (Random Forest 0.89 · IsolationForest 0.91)
 6.  Merchant category "Finance" — elevated risk category

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
APPLICABLE LEGAL PROVISIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Bharatiya Nyaya Sanhita (BNS) §318(4)
    Cheating by impersonation — Punishment: Imprisonment up to 7 years + fine

  Information Technology Act §66D
    Cheating by personation using computer resource
    Punishment: Imprisonment up to 3 years + fine up to ₹1,00,000

  Prevention of Money Laundering Act (PMLA) §3
    Projecting proceeds of crime as untainted property

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SYSTEM EVIDENCE CHAIN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SHA-256(suraj.thakur@okicici) : 7f3a9c12e803b5d1902871ea6cd048f3...
Consortium Cache               : HIT — Risk delta: 0.90 written to DashMap
Graph Analysis                 : Off-path async — pending corroboration
Alert Delivery                 : Bhashini NMT (hi-IN) + edge-tts MP3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CERTIFYING SYSTEM : Varaksha V2 Fraud Intelligence Network
                    NPCI Hackathon 2026  ·  Blue Team  ·  DEMONSTRATION ONLY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`.trimStart();

// ── Formatting helper: mm:ss ──────────────────────────────────────────────────
function fmtTime(pct: number): string {
  const totalSec = Math.round((pct / 100) * (AUDIO_DURATION_MS / 1000));
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

type DlState = "idle" | "generating" | "done";

export function LegalReport() {
  const [isPlaying, setIsPlaying] = useState(false);
  const [progress,  setProgress ] = useState(0);
  const [dlState,   setDlState  ] = useState<DlState>("idle");

  // ── Audio player logic ──────────────────────────────────────────────────────
  useEffect(() => {
    if (!isPlaying) return;
    const interval = setInterval(() => {
      setProgress((p) => {
        const next = p + AUDIO_STEP_PCT;
        if (next >= 100) {
          setIsPlaying(false);
          return 100;
        }
        return next;
      });
    }, AUDIO_TICK_MS);
    return () => clearInterval(interval);
  }, [isPlaying]);

  const handlePlayPause = useCallback(() => {
    if (progress >= 100) {
      setProgress(0);
      setIsPlaying(true);
    } else {
      setIsPlaying((p) => !p);
    }
  }, [progress]);

  // ── PDF / evidence-file download ─────────────────────────────────────────
  const handleDownload = useCallback(() => {
    if (dlState === "generating") return;
    setDlState("generating");
    setTimeout(() => {
      const blob = new Blob([REPORT_TEXT], { type: "text/plain;charset=utf-8" });
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
  }, [dlState]);

  const durationStr = `0:${String(Math.round(AUDIO_DURATION_MS / 1000)).padStart(2, "0")}`;

  return (
    <section className="border border-cream/[0.08] overflow-hidden">

      {/* ── Module header ── */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-cream/[0.07] bg-cream/[0.025]">
        <div className="flex items-center gap-2.5">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-block" />
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/40">
            Module E — Legal Report & Accessible Alert
          </span>
        </div>
        <span className="font-courier text-[0.52rem] text-cream/18">
          BNS §318(4) &middot; IT Act §66D
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

          {/* ── Bhashini Hindi alert ── */}
          <div className="border border-saffron/15 bg-saffron/[0.033] p-5 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <span className="font-barlow text-[0.52rem] tracking-[0.28em] uppercase text-saffron/45">
                Bhashini NMT &middot; hi-IN Translation
              </span>
              <div className="flex-1 h-px bg-saffron/10" />
              <span className="font-barlow text-[0.48rem] tracking-widest uppercase text-saffron/25">
                edge-tts
              </span>
            </div>

            {/* Primary — Hindi */}
            <p
              className="text-cream leading-[1.9] mb-2"
              style={{ fontSize: "clamp(1rem, 2vw, 1.2rem)", fontFamily: "sans-serif" }}
            >
              यह लेनदेन संदिग्ध है। आपके पैसे सुरक्षित हैं।
            </p>

            {/* Secondary — extended translated alert */}
            <p className="font-barlow text-[0.78rem] text-cream/40 leading-relaxed mb-5">
              ₹99,999 का संदिग्ध लेन-देन रोका गया।
              रात के 3 बजे नए डिवाइस से उच्च राशि का लेनदेन।
              कृपया अपने बैंक से संपर्क करें।
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
                    {fmtTime(progress)}
                  </p>
                  <p className="font-courier text-[0.52rem] text-cream/18 tabular-nums">
                    {durationStr}
                  </p>
                </div>
              </div>

              <p className="font-barlow text-[0.48rem] tracking-widest uppercase text-cream/16 mt-3">
                Simulated audio &middot; edge-tts &middot; hi-IN &middot; Bhashini NMT
              </p>
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
                  ? "bg-cream/[0.06] border border-cream/10 text-cream/30 cursor-not-allowed"
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
                  Download Court-Ready PDF (BNS §318(4) &amp; IT Act §66D)
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
              { step: "04", label: "Bhashini Alert",       detail: "hi-IN delivery receipt  ·  MP3" },
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
    </section>
  );
}
