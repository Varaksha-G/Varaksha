"use client";

import { useState, useCallback } from "react";
import { motion, AnimatePresence, type Variants } from "framer-motion";

// ── Constants ─────────────────────────────────────────────────────────────────

const STEP_H  = 108;   // px height per step slot in the left timeline track

// ── Types ─────────────────────────────────────────────────────────────────────

type Phase        = "idle" | "running" | "done";
type VerdictColor = "saffron" | "allow" | "block";

interface DataRow    { label: string; value: string }
interface FeatureBar { label: string; pct: number }
interface Callout    {
  label:        string;
  text:         string;
  accentClass?: string;   // border + bg for the box
  labelClass?:  string;   // colour for the label text
  waveform?:    boolean;  // show audio waveform indicator
}

interface StepDef {
  layer:     string;
  title:     string;
  kicker:    string;
  isAsync?:  boolean;
  rows:      DataRow[];
  bars?:     FeatureBar[];
  callout?:  Callout;
  verdict:   { label: string; color: VerdictColor };
}

// ── Step Definitions ──────────────────────────────────────────────────────────
// Every detail here maps to real system behaviour documented in README.md.

const STEPS: StepDef[] = [
  {
    layer:  "UPI Client",
    title:  "Payment Initiated",
    kicker: "A payment leaves the user’s phone — signed, timestamped, and handed directly to Varaksha.",
    rows: [
      { label: "FROM",       value: "user@axisbank" },
      { label: "TO",         value: "merchant@kirana" },
      { label: "AMOUNT",     value: "₹4,750.00" },
      { label: "TIMESTAMP",  value: "2026-03-10T09:14:32Z" },
      { label: "REF",        value: "TXN20260310-00842" },
      { label: "DEVICE",     value: "Android 14 · 16-feature vector extracted" },
      { label: "STATUS",     value: "Handed to Varaksha gateway" },
    ],
    verdict: { label: "DISPATCHED", color: "saffron" },
  },
  {
    layer:  "L1 — ML Engine",
    title:  "Anomaly Evaluated",
    kicker: "Our model scores 16 transaction features across 300 decision trees — and delivers a risk score in milliseconds.",
    rows: [
      { label: "FEATURES",       value: "16  (13 numerical + 3 categorical)" },
      { label: "MODEL",          value: "Random Forest · 300 estimators (RF-only, no XGBoost)" },
      { label: "INFERENCE",      value: "300 trees → single RF decision (no ensemble voting)" },
      { label: "RISK SCORE",     value: "0.23 / 1.00" },
      { label: "THRESHOLD",      value: "≥ 0.50 → HIGH RISK  (current: LOW)" },
      { label: "CLASSIFICATION", value: "LOW RISK — forwarding score to gateway" },
    ],
    bars: [
      { label: "AMOUNT_LOG",         pct: 84 },
      { label: "HOUR_SIN",           pct: 48 },
      { label: "MERCHANT_RISK_FREQ", pct: 35 },
      { label: "VELOCITY_1H",        pct: 61 },
    ],
    verdict: { label: "LOW RISK · 0.23", color: "allow" },
  },
  {
    layer:  "L2 — Rust Gateway",
    title:  "Anonymise, Hash & Decide",
    kicker: "Your account ID is SHA-256 hashed before anything touches the cache. What gets stored is a score and a flag — never your name, number, or balance.",
    rows: [
      { label: "RAW INPUT",    value: "user@axisbank  (seen once — never written to disk)" },
      { label: "SHA-256 HASH", value: "a3f8c2d9e1b04f72\u20264e190b7a  (one-way \u00b7 irreversible)" },
      { label: "CACHE KEY",    value: "a3f8c2d9  (first 8 bytes \u00b7 cannot recover original VPA)" },
      { label: "CACHE HIT",    value: "YES  \u2192  { risk: 0.23, consortium: CLEAN }" },
      { label: "PII STORED",   value: "NONE \u2014 no name \u00b7 no phone \u00b7 no account number" },
      { label: "VERDICT",      value: "ALLOW  (risk 0.23 < threshold 0.50)" },
      { label: "LATENCY",      value: "< 10 ms  (P99 \u00b7 Criterion.rs benchmark)" },
    ],
    callout: {
      label: "Data anonymisation pipeline",
      accentClass: "border-allow/25 bg-allow/[0.04]",
      labelClass:  "text-allow/65",
      text:
        "user@axisbank\n" +
        "     \u2193  SHA-256  (one-way \u2014 cannot be reversed)\n" +
        "a3f8c2d9e1b04f72\u20264e190b7a\n" +
        "\n" +
        "What enters the cache:   { risk: 0.23 \u00b7 consortium: CLEAN }\n" +
        "What never gets stored:  name \u00b7 phone \u00b7 balance \u00b7 transaction history",
    },
    verdict: { label: "ALLOW", color: "allow" },
  },
  {
    layer:   "L3 — Graph Agent",
    title:   "Topology Analysis",
    kicker:  "While the payment clears, our graph engine maps money-flow patterns in the background — protecting future transactions without blocking this one.",
    isAsync: true,
    rows: [
      { label: "GRAPH NODES",   value: "142  (VPA partition · Axis Bank segment)" },
      { label: "GRAPH EDGES",   value: "398" },
      { label: "FAN-OUT",       value: "CLEAR  —  4 unique payees  (threshold: 10)" },
      { label: "FAN-IN",        value: "CLEAR  —  2 sources routing to merchant" },
      { label: "CYCLE DETECT",  value: "CLEAR  —  no circular money flows found" },
      { label: "ACTION",        value: "Cache enriched with graph risk delta: 0.00" },
      { label: "NOTE",          value: "Verdict already issued — this enriches future lookups" },
    ],
    verdict: { label: "ASYNC · CLEAR", color: "allow" },
  },
  {
    layer:  "L4 — Alert Agent",
    title:  "Contextual Alert Generated",
    kicker: "If the transaction looks suspicious, an LLM drafts a plain-language alert in Hindi — then read aloud using edge-tts, Microsoft's neural text-to-speech engine.",
    rows: [
      { label: "INPUT RISK",  value: "0.23  (LOW — no alert for this transaction)" },
      { label: "ALERT SENT",  value: "NO  (score below 0.50 threshold)" },
      { label: "CHANNEL",     value: "SMS · Push Notification · Audio" },
    ],
    callout: {
      label: "HYPOTHETICAL HIGH-RISK OUTPUT — Hindi alert · edge-tts · hi-IN voice",
      waveform: true,
      text:
        "सावधान! ₹12,400 का संदिग्ध लेन-देन।\n" +
        "6 अलग खातों में धन भेजा जा रहा है।\n" +
        "अपना UPI पिन किसी के साथ साझा न करें।",
    },
    verdict: { label: "PIPELINE COMPLETE", color: "saffron" },
  },
];

// ── Animation variants ────────────────────────────────────────────────────────

const slideIn: Variants = {
  hidden:  { opacity: 0, x: 32 },
  visible: { opacity: 1, x: 0,   transition: { duration: 0.42, ease: "easeOut" } },
  exit:    { opacity: 0, x: -24, transition: { duration: 0.24 } },
};

// ── Helper: center-y of a step node in the timeline ──────────────────────────
// The node circle for step i sits at the top of its row (plus a small offset),
// so its vertical center is: i × STEP_H + 12
const nodeY = (i: number) => i * STEP_H + 12;

// ── Sub-component: left timeline sidebar ─────────────────────────────────────

function TimelinePanel({
  currentStep,
  phase,
}: {
  currentStep: number;
  phase: Phase;
}) {
  const trackTop    = nodeY(0);
  const trackBottom = nodeY(STEPS.length - 1);
  const trackHeight = trackBottom - trackTop;

  const fillH =
    phase === "done"         ? trackHeight :
    currentStep > 0          ? nodeY(currentStep) - trackTop :
                               0;

  // Packet dot is 24 × 24; its center should align with nodeY(currentStep)
  const packetTop = nodeY(Math.max(0, currentStep)) - 12;

  return (
    <div
      className="relative select-none"
      style={{ height: STEPS.length * STEP_H + 24 }}
    >
      {/* ── Background track line ── */}
      <div
        className="absolute w-px bg-ink/10"
        style={{ left: 11, top: trackTop, height: trackHeight }}
      />

      {/* ── Animated saffron fill line ── */}
      <motion.div
        className="absolute w-px bg-saffron origin-top"
        style={{ left: 11, top: trackTop }}
        animate={{ height: fillH }}
        transition={{ duration: 0.55, ease: "easeInOut" }}
      />

      {/* ── Traveling data-packet dot ── */}
      {phase !== "idle" && (
        <motion.div
          className="absolute z-20"
          style={{ left: 0, width: 24, height: 24 }}
          animate={{ top: packetTop }}
          transition={{ type: "spring", stiffness: 270, damping: 28 }}
        >
          {/* Outer pulse ring */}
          <motion.span
            className="absolute inset-0 rounded-full border-2 border-saffron"
            animate={{ scale: [1, 1.9, 1], opacity: [0.65, 0, 0.65] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: "easeOut" }}
          />
          {/* Inner dot */}
          <span className="absolute inset-[5px] rounded-full bg-saffron shadow-[0_0_6px_rgba(37,99,235,0.55)]" />
        </motion.div>
      )}

      {/* ── Step nodes ── */}
      {STEPS.map((step, i) => {
        const isDone    = (i < currentStep && phase === "running") || phase === "done";
        const isActive  = i === currentStep && phase === "running";
        const nodeClass = isDone   ? "bg-allow border-allow"
                        : isActive ? "bg-saffron border-saffron"
                        :            "bg-cream border-ink/20";

        return (
          <div
            key={i}
            className="absolute flex items-start gap-3 pr-2"
            style={{ top: i * STEP_H, left: 0, right: 0 }}
          >
            {/* Circle */}
            <div
              className={`relative z-10 w-6 h-6 rounded-full border-2 flex items-center justify-center shrink-0 transition-colors duration-500 ${nodeClass}`}
            >
              {isDone && (
                <svg className="w-3 h-3" viewBox="0 0 12 12" fill="none">
                  <polyline
                    points="2,6 5,9 10,3"
                    stroke="white"
                    strokeWidth="1.7"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              )}
              {!isDone && !isActive && (
                <span className="font-courier text-[0.5rem] font-bold text-ink/25">
                  {i + 1}
                </span>
              )}
            </div>

            {/* Labels */}
            <div className="pt-0.5 min-w-0">
              <p
                className={`font-barlow text-[0.55rem] tracking-[0.24em] uppercase truncate mb-0.5 transition-colors duration-300 ${
                  isActive ? "text-saffron" : isDone ? "text-allow" : "text-ink/22"
                }`}
              >
                {step.layer}
              </p>
              <p
                className={`font-barlow text-[0.75rem] font-medium leading-snug truncate transition-colors duration-300 ${
                  isActive ? "text-ink" : isDone ? "text-ink/55" : "text-ink/22"
                }`}
              >
                {step.title}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Sub-component: mobile step progress bar ───────────────────────────────────

function MobileStepBar({
  currentStep,
  phase,
}: {
  currentStep: number;
  phase: Phase;
}) {
  return (
    <div className="lg:hidden flex items-stretch gap-1 mb-7">
      {STEPS.map((s, i) => {
        const done   = (i < currentStep && phase === "running") || phase === "done";
        const active = i === currentStep && phase === "running";
        return (
          <div key={i} className="flex-1 flex flex-col items-center gap-1">
            <div
              className={`h-1 w-full rounded-full transition-colors duration-500 ${
                done ? "bg-allow" : active ? "bg-saffron" : "bg-ink/10"
              }`}
            />
            <span
              className={`font-barlow text-[0.46rem] tracking-wider uppercase transition-colors ${
                done ? "text-allow" : active ? "text-saffron" : "text-ink/18"
              }`}
            >
              {s.layer.split(" ")[0]}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── Sub-component: step detail card ──────────────────────────────────────────

function StepDetail({ step, idx }: { step: StepDef; idx: number }) {
  const verdictClass =
    step.verdict.color === "allow" ? "text-allow  border-allow/30  bg-allow/[0.06]"  :
    step.verdict.color === "block" ? "text-block  border-block/30  bg-block/[0.06]"  :
                                     "text-saffron border-saffron/30 bg-saffron/[0.06]";

  return (
    <motion.article
      variants={slideIn}
      initial="hidden"
      animate="visible"
      exit="exit"
      className="surface-card border border-ink/10 bg-white/48 overflow-hidden"
    >
      {/* ── Card header ── */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-ink/[0.07] bg-ink/[0.025]">
        <div className="flex items-center gap-2.5">
          <motion.span
            className="inline-block w-2 h-2 rounded-full bg-saffron"
            animate={{ opacity: [1, 0.25, 1] }}
            transition={{ duration: 0.95, repeat: Infinity }}
          />
          <span className="font-barlow text-[0.58rem] tracking-[0.26em] uppercase text-ink/60 font-semibold">
            {step.layer}
          </span>
          {step.isAsync && (
            <span className="font-barlow text-[0.5rem] tracking-widest uppercase text-saffron/60 border border-saffron/22 px-1.5 py-0.5 leading-none">
              ASYNC
            </span>
          )}
        </div>
        <span className="font-courier text-[0.55rem] tracking-wider text-ink/18">
          PROCESSING&thinsp;·&thinsp;STEP {idx + 1}&thinsp;/&thinsp;{STEPS.length}
        </span>
      </div>

      {/* ── Card body ── */}
      <div className="p-5 lg:p-7">
        {/* Title */}
        <h2
          className="font-playfair font-bold text-ink leading-tight mb-1.5"
          style={{ fontSize: "clamp(1.5rem, 3.2vw, 2.4rem)" }}
        >
          {step.title}
        </h2>
        <p className="font-barlow text-[0.74rem] text-ink/58 leading-relaxed mb-6 max-w-2xl">
          {step.kicker}
        </p>

        {/* ── Data rows ── */}
        <div className="mb-6 border border-ink/[0.07]">
          {step.rows.map((row, ri) => (
            <motion.div
              key={ri}
              className="flex gap-4 px-4 py-2.5 border-b border-ink/[0.05] last:border-0"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: ri * 0.07, duration: 0.35 }}
            >
              <span className="font-courier text-[0.59rem] tracking-wider text-ink/28 w-28 lg:w-36 shrink-0 uppercase pt-px">
                {row.label}
              </span>
              <span className="font-courier text-[0.72rem] text-ink/72 break-all leading-relaxed">
                {row.value}
              </span>
            </motion.div>
          ))}
        </div>

        {/* ── Feature importance bars (L1 only) ── */}
        {step.bars && (
          <div className="mb-6 border border-ink/[0.07] p-4 lg:p-5">
            <p className="font-barlow text-[0.55rem] tracking-[0.30em] uppercase text-ink/25 mb-4">
              Top Feature Importances
            </p>
            <div className="space-y-3.5">
              {step.bars.map((bar, bi) => (
                <div key={bi}>
                  <div className="flex justify-between mb-1">
                    <span className="font-courier text-[0.59rem] uppercase tracking-wider text-ink/35">
                      {bar.label}
                    </span>
                    <span className="font-courier text-[0.58rem] text-ink/35">
                      {bar.pct}%
                    </span>
                  </div>
                  <div className="h-1.5 bg-ink/[0.07] overflow-hidden">
                    <motion.div
                      className="h-full bg-saffron"
                      initial={{ width: "0%" }}
                      animate={{ width: `${bar.pct}%` }}
                      transition={{ duration: 0.9, ease: "easeOut", delay: bi * 0.12 }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Generic callout box (L2 anonymisation · L4 Hindi alert) ── */}
        {step.callout && (
          <div className={`mb-5 border p-4 lg:p-5 ${step.callout.accentClass ?? "border-block/15 bg-block/[0.03]"}`}>
            <p className={`font-barlow text-[0.53rem] tracking-[0.28em] uppercase mb-3 ${step.callout.labelClass ?? "text-block/45"}`}>
              {step.callout.label}
            </p>
            <p className="font-barlow text-[0.95rem] text-ink leading-[1.85] whitespace-pre-line mb-4">
              {step.callout.text}
            </p>
            {/* Audio waveform — only for the L4 TTS callout */}
            {step.callout.waveform && <div className="flex items-center gap-2">
              <span className="font-barlow text-[0.52rem] tracking-widest uppercase text-ink/25">
                edge-tts&thinsp;·&thinsp;hi-IN&thinsp;·&thinsp;MP3
              </span>
              {/* Fixed 16px tall container — bars scale inside, never push layout */}
              <div className="flex items-end gap-0.5" style={{ height: 16, overflow: "hidden" }}>
                {[5, 11, 7, 14, 9, 13, 6, 15, 8, 12, 5, 10].map((h, i) => (
                  <motion.div
                    key={i}
                    className="w-0.5 bg-saffron/50 rounded-sm self-end"
                    style={{ height: h, transformOrigin: "bottom" }}
                    animate={{ scaleY: [1, 0.38, 1] }}
                    transition={{
                      duration: 0.75,
                      repeat: Infinity,
                      delay: i * 0.068,
                      ease: "easeInOut",
                    }}
                  />
                ))}
              </div>
            </div>}
          </div>
        )}

        {/* ── Verdict badge ── */}
        <div className="flex items-center gap-3 mt-5">
          <div className="flex-1 h-px bg-ink/8" />
          <span
            className={`font-courier text-[0.67rem] tracking-[0.22em] uppercase px-3 py-1.5 border ${verdictClass}`}
          >
            {step.verdict.label}
          </span>
          <div className="flex-1 h-px bg-ink/8" />
        </div>
      </div>
    </motion.article>
  );
}

// ── Sub-component: final verdict banner ──────────────────────────────────────

function VerdictBanner() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 36 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.62, ease: [0.22, 1, 0.36, 1] }}
      className="border-2 border-allow overflow-hidden"
    >
      {/* Top label strip */}
      <div className="bg-allow/[0.08] border-b border-allow/12 px-6 py-3">
        <span className="font-barlow text-[0.56rem] tracking-[0.34em] uppercase text-allow/55">
          Final Verdict &mdash; Simulation Complete &mdash; TXN20260310-00842
        </span>
      </div>

      <div className="p-8 lg:p-12 text-center bg-allow/[0.025]">
        {/* Giant verdict word */}
        <motion.p
          className="font-courier font-bold text-allow leading-none mb-4"
          style={{ fontSize: "clamp(4rem, 10vw, 7rem)" }}
          initial={{ scale: 0.65, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.18, duration: 0.52, ease: [0.22, 1, 0.36, 1] }}
        >
          ALLOW
        </motion.p>

        <p className="font-barlow text-[0.8rem] text-ink/58 mb-8">
          ₹4,750 cleared to merchant@kirana &mdash; all five layers passed, every signal clean.
        </p>

        {/* Layer pass-badges */}
        <div className="flex flex-wrap justify-center gap-2.5">
          {STEPS.map((s, i) => (
            <motion.div
              key={i}
              className="flex items-center gap-1.5 border border-allow/20 bg-allow/[0.05] px-3 py-1.5"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 + i * 0.08 }}
            >
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-allow" />
              <span className="font-barlow text-[0.55rem] tracking-wider uppercase text-allow/65">
                {s.layer}
              </span>
            </motion.div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function FlowPage() {
  const [phase, setPhase]      = useState<Phase>("idle");
  const [currentStep, setStep] = useState(-1);

  // ── Manual navigation ────────────────────────────────────────────────────
  const handleNext = useCallback(() => {
    if (currentStep === STEPS.length - 1) {
      setPhase("done");
    } else {
      setStep((s) => s + 1);
    }
  }, [currentStep]);

  const handlePrev = useCallback(() => {
    if (currentStep > 0) setStep((s) => s - 1);
  }, [currentStep]);

  const handleStart = useCallback(() => {
    setStep(0);
    setPhase("running");
  }, []);

  const handleReplay = useCallback(() => {
    setPhase("idle");
    setStep(-1);
    // Allow one frame for AnimatePresence exits, then restart
    setTimeout(() => {
      setStep(0);
      setPhase("running");
    }, 80);
  }, []);

  const progressPct =
    phase === "idle" ? 0 :
    phase === "done" ? 100 :
    ((currentStep + 1) / STEPS.length) * 100;

  return (
    <main className="min-h-screen bg-cream text-ink">

      {/* ── Fixed top progress rail ─────────────────────────────────────── */}
      <div className="fixed top-0 inset-x-0 z-50 h-[2px] bg-ink/8">
        <motion.div
          className="h-full bg-saffron"
          animate={{ width: `${progressPct}%` }}
          transition={{ duration: 0.50, ease: "easeInOut" }}
        />
      </div>

      {/* ── Nav header ─────────────────────────────────────────────────── */}
      <header className="border-b border-ink/10 px-6 lg:px-12 py-2.5">
        <div className="max-w-7xl mx-auto flex items-center justify-between">

          <div className="flex items-center gap-3">
            <a
              href="/"
              className="font-barlow text-[0.6rem] tracking-[0.24em] uppercase text-ink/32 hover:text-saffron transition-colors"
            >
              &larr;&thinsp;Varaksha
            </a>
            <span className="text-ink/15 select-none">|</span>
            <span className="font-barlow text-[0.6rem] tracking-[0.24em] uppercase text-ink/32">
              Architectural Flow
            </span>
          </div>

          {/* Replay button — visible once simulation has started */}
          <AnimatePresence>
            {phase !== "idle" && (
              <motion.button
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                onClick={handleReplay}
                className="font-barlow text-[0.58rem] tracking-[0.22em] uppercase text-saffron hover:text-ink transition-colors"
              >
                &#8635;&thinsp;Replay
              </motion.button>
            )}
          </AnimatePresence>

        </div>
      </header>

      {/* ── Hero ───────────────────────────────────────────────────────── */}
      <section className="px-6 lg:px-12 pt-14 pb-10 max-w-7xl mx-auto">

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="font-barlow text-[0.68rem] tracking-[0.36em] uppercase text-saffron mb-4"
        >
          System Architecture &middot; Walkthrough
        </motion.p>

        <motion.h1
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.07, duration: 0.5, ease: "easeOut" }}
          className="font-playfair font-bold text-ink leading-[0.92] mb-4"
          style={{ fontSize: "clamp(2.4rem, 5.5vw, 4.4rem)" }}
        >
          Follow a ₹4,750 Payment
          <br className="hidden md:block" />
          Through Every Layer of Defence
        </motion.h1>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.18 }}
          className="font-barlow text-[0.86rem] text-ink/58 max-w-xl mb-10 leading-relaxed"
        >
          Click through each layer at your own pace. See exactly what Varaksha
          does with a real payment &mdash; from the moment it leaves the phone
          to the final fraud verdict.
        </motion.p>

        {/* ── Start Simulation button ── */}
        <AnimatePresence>
          {phase === "idle" && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ delay: 0.25 }}
            >
              <motion.button
                onClick={handleStart}
                whileHover={{ scale: 1.02, backgroundColor: "#0F1E2E" }}
                whileTap={{ scale: 0.97 }}
                className="inline-flex items-center gap-3 bg-saffron text-cream font-barlow font-semibold text-[0.8rem] tracking-[0.16em] uppercase px-8 py-4 transition-colors duration-200 shadow-[0_4px_28px_rgba(37,99,235,0.25)]"
              >
                <motion.span
                  className="inline-block w-2 h-2 rounded-full bg-cream/70"
                  animate={{ opacity: [1, 0.3, 1] }}
                  transition={{ duration: 0.95, repeat: Infinity }}
                />
                Start Simulation
              </motion.button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── Pre-simulation hint ── */}
        <AnimatePresence>
          {phase === "idle" && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1, transition: { delay: 0.45 } }}
              exit={{ opacity: 0 }}
              className="mt-10 border border-dashed border-ink/12 p-10 text-center"
            >
              <p className="font-barlow text-[0.72rem] text-ink/22 tracking-wide">
                Hit &ldquo;Start Simulation&rdquo; to begin &mdash; then step
                through each layer using the Next and Back buttons below.
              </p>
            </motion.div>
          )}
        </AnimatePresence>

      </section>

      {/* ── Main flow area ─────────────────────────────────────────────── */}
      <AnimatePresence>
        {phase !== "idle" && (
          <motion.section
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="px-6 lg:px-12 pb-28 max-w-7xl mx-auto"
          >
            {/* Mobile step bar */}
            <MobileStepBar currentStep={currentStep} phase={phase} />

            <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-8 lg:gap-14">

              {/* ── Left: sticky timeline ──────────────────────────────── */}
              <div className="hidden lg:block">
                <div className="sticky top-10 pt-2">
                  <p className="font-barlow text-[0.54rem] tracking-[0.30em] uppercase text-ink/20 mb-6 pl-8">
                    Transaction Path
                  </p>
                  <TimelinePanel currentStep={currentStep} phase={phase} />
                </div>
              </div>

              {/* ── Right: step detail + verdict ──────────────────────── */}
              <div>
                <AnimatePresence mode="wait">
                  {phase === "running" && currentStep >= 0 && (
                    <StepDetail
                      key={currentStep}
                      step={STEPS[currentStep]}
                      idx={currentStep}
                    />
                  )}
                </AnimatePresence>

                {/* ── Step nav buttons ── */}
                {phase === "running" && currentStep >= 0 && (
                  <div className="flex items-center justify-between mt-5">
                    <button
                      onClick={handlePrev}
                      disabled={currentStep === 0}
                      className="inline-flex items-center gap-2 font-barlow text-[0.72rem] tracking-[0.18em] uppercase px-5 py-2.5 border border-ink/30 text-ink/70 hover:border-ink/60 hover:text-ink transition-colors disabled:opacity-25 disabled:pointer-events-none font-semibold"
                    >
                      &larr; Back
                    </button>
                    <span className="font-courier text-[0.62rem] tracking-widest text-ink/60 font-semibold">
                      {currentStep + 1} / {STEPS.length}
                    </span>
                    <button
                      onClick={handleNext}
                      className="inline-flex items-center gap-2 font-barlow text-[0.72rem] tracking-[0.18em] uppercase px-5 py-2.5 bg-saffron text-cream hover:bg-ink transition-colors"
                    >
                      {currentStep === STEPS.length - 1 ? "See Verdict" : "Next"} &rarr;
                    </button>
                  </div>
                )}

                <AnimatePresence>
                  {phase === "done" && <VerdictBanner />}
                </AnimatePresence>
              </div>

            </div>
          </motion.section>
        )}
      </AnimatePresence>

      {/* ── Footer ─────────────────────────────────────────────────────── */}
      <footer className="border-t border-ink/10 px-6 lg:px-12 py-4">
        <div className="max-w-7xl mx-auto flex justify-between items-center gap-2">
          <span className="font-barlow text-[0.56rem] tracking-[0.26em] uppercase text-ink/20">
            Varaksha V2 &middot; NPCI Hackathon 2026
          </span>
          <span className="font-courier text-[0.56rem] tracking-wider text-ink/16">
            Rust &middot; Python &middot; Next.js
          </span>
        </div>
      </footer>

    </main>
  );
}
