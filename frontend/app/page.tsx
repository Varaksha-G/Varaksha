"use client";

import { motion, type Variants } from "framer-motion";

// ── Animation Variants ────────────────────────────────────────────────────────

/** Container: staggers children as they enter the viewport. */
const stagger: Variants = {
  hidden: {},
  visible: {
    transition: { staggerChildren: 0.10, delayChildren: 0.12 },
  },
};

/** Individual item: fades up with a smooth ease. */
const fadeUp: Variants = {
  hidden: { opacity: 0, y: 26 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.65, ease: "easeOut" },
  },
};

/** Simple fade — used for decorative separators. */
const fadeIn: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 1.1 } },
};

// ── Metric Data ───────────────────────────────────────────────────────────────
// Every stat here is sourced from a public benchmark or regulatory report.

const metrics = [
  {
    kicker: "The Problem",
    value: "₹1,750Cr",
    label: "Lost to UPI fraud last year",
    sub: "FY 2024",
    source: "RBI Annual Report 2024",
    accent: "bg-block",          // red top-bar
    valueColor: "text-block",
    // 3-up row on md+
    colSpan: "col-span-12 md:col-span-4",
  },
  {
    kicker: "The Scale",
    value: "640M",
    label: "UPI transactions every single day",
    sub: "Real payments, real people",
    source: "NPCI",
    accent: "bg-saffron",
    valueColor: "text-saffron",
    colSpan: "col-span-12 md:col-span-4",
  },
  {
    kicker: "Model Performance",
    value: "85.24%",
    label: "Random Forest Accuracy",
    sub: "111K rows · 7 real datasets · ROC-AUC 0.9546",
    source: "Varaksha · trained Mar 2026",
    accent: "bg-allow",           // green top-bar
    valueColor: "text-allow",
    colSpan: "col-span-12 md:col-span-4",
  },
  {
    kicker: "Our Speed",
    value: "<10ms",
    label: "To deliver a fraud verdict",
    sub: "Faster than a human blink",
    source: "Varaksha Gateway · Criterion.rs",
    accent: "bg-saffron",
    valueColor: "text-saffron",
    // 2-up row on md+
    colSpan: "col-span-12 md:col-span-6",
  },
  {
    kicker: "Who We Protect",
    value: "44%",
    label: "Indians can’t read an English fraud alert",
    sub: "Varaksha alerts in your language",
    source: "India BRICS Language Survey",
    accent: "bg-ink",
    valueColor: "text-ink",
    colSpan: "col-span-12 md:col-span-6",
  },
] as const;

// ── Architecture Layers ───────────────────────────────────────────────────────

const layers = [
  { id: "L1", name: "ML Engine",      tech: "RF-300 · IsolationForest · SMOTE" },
  { id: "L2", name: "Rust Gateway",   tech: "DashMap · SHA-256 · <10ms" },
  { id: "L3", name: "Graph Agent",    tech: "NetworkX · Fan-out · Cycles" },
  { id: "L4", name: "Alert Agent",    tech: "LLM · Hindi alert · edge-tts" },
  { id: "L5", name: "Dashboard",      tech: "Real-time Verdict Stream" },
] as const;

// ── Component ─────────────────────────────────────────────────────────────────

export default function PitchPage() {
  return (
    <main className="min-h-screen bg-cream text-ink">

      {/* ── Masthead ──────────────────────────────────────────────────────── */}
      <header className="border-b border-ink/10 px-6 lg:px-12 py-2.5">
        <div className="max-w-7xl mx-auto flex justify-between items-center">

          <span className="font-barlow text-[0.62rem] tracking-[0.22em] uppercase text-ink/35">
            Vol.&thinsp;II &middot; NPCI Hackathon 2026
          </span>

          {/* Live status dots — hidden on small screens */}
          <div className="hidden md:flex items-center gap-6">
            {["Gateway: LIVE", "ML: READY", "Graph: ACTIVE"].map((s) => (
              <div key={s} className="flex items-center gap-1.5">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-allow animate-pulse" />
                <span className="font-barlow text-[0.58rem] tracking-widest uppercase text-ink/35">
                  {s}
                </span>
              </div>
            ))}
          </div>

          <span className="font-barlow text-[0.62rem] tracking-[0.22em] uppercase text-ink/35">
            Blue Team &middot; UPI Fraud Detection
          </span>
        </div>
      </header>

      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <motion.section
        className="px-6 lg:px-12 pt-16 lg:pt-24 pb-12 max-w-7xl mx-auto"
        variants={stagger}
        initial="hidden"
        animate="visible"
      >
        {/* Overline kicker */}
        <motion.p
          variants={fadeUp}
          className="font-barlow text-[0.7rem] tracking-[0.34em] uppercase text-saffron mb-5"
        >
          Real-time fraud protection for India&rsquo;s 640M+ daily UPI transactions
        </motion.p>

        {/* Display headline */}
        <motion.h1
          variants={fadeUp}
          className="font-playfair font-bold leading-[0.88] tracking-tight text-ink mb-4"
          style={{ fontSize: "clamp(3.5rem, 10vw, 8rem)" }}
        >
          Varaksha
          <span className="text-saffron">.</span>
        </motion.h1>

        {/* Subheadline */}
        <motion.p
          variants={fadeUp}
          className="font-playfair italic text-ink/80 mb-10"
          style={{ fontSize: "clamp(1.1rem, 2.4vw, 1.9rem)" }}
        >
          UPI Fraud Defense Network
        </motion.p>

        {/* Decorative rule */}
        <motion.div variants={fadeIn} className="flex items-center gap-4">
          <div className="w-14 h-[2px] bg-saffron" />
          <span className="font-barlow text-[0.62rem] tracking-[0.28em] uppercase text-ink/60 font-semibold">
            Rust &middot; Random Forest &middot; IsolationForest &middot; NetworkX &middot; edge-tts
          </span>
          <div className="flex-1 h-px bg-ink/10" />
        </motion.div>
      </motion.section>

      {/* ── Metrics Grid ──────────────────────────────────────────────────── */}
      <section className="px-6 lg:px-12 pb-20 max-w-7xl mx-auto">

        {/* Section label */}
        <div className="flex items-center gap-3 mb-5">
          <span className="font-barlow text-[0.62rem] tracking-[0.30em] uppercase text-ink/30">
            Why This Matters
          </span>
          <div className="flex-1 h-px bg-ink/10" />
        </div>

        {/* 12-column grid; row 1 = 3 cards (col-span-4), row 2 = 2 cards (col-span-6) */}
        <motion.div
          className="grid grid-cols-12 gap-3 lg:gap-4"
          variants={stagger}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-60px" }}
        >
          {metrics.map((m) => (
            <motion.div
              key={m.value}
              variants={fadeUp}
              whileHover={{ y: -4, transition: { duration: 0.18, ease: "easeOut" } }}
              className={`${m.colSpan} surface-card relative overflow-hidden border border-ink/[0.09] bg-white/55 hover:bg-white/80 transition-colors duration-300`}
            >
              {/* Coloured top accent bar */}
              <div className={`absolute inset-x-0 top-0 h-[3px] ${m.accent}`} />

              <div className="p-5 pt-7 flex flex-col h-full">
                {/* Kicker / category label */}
                <p className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-ink/32 mb-3">
                  {m.kicker}
                </p>

                {/* Headline number */}
                <p
                  className={`font-courier font-bold leading-none ${m.valueColor} mb-2`}
                  style={{ fontSize: "clamp(2.4rem, 4.5vw, 3.8rem)" }}
                >
                  {m.value.startsWith("₹")
                    ? <><span style={{ fontSize: "0.72em" }}>₹</span>{m.value.slice(1)}</>
                    : m.value}
                </p>

                {/* Label */}
                <p className="font-barlow text-[0.88rem] font-semibold text-ink leading-snug mb-1">
                  {m.label}
                </p>

                {/* Sub-label — pushed to the bottom by mb-auto */}
                <p className="font-barlow text-[0.78rem] text-ink/55 mb-auto pb-4">
                  {m.sub}
                </p>

                {/* Citation */}
                <div className="border-t border-ink/[0.08] pt-2.5 mt-1">
                  <p className="font-barlow text-[0.56rem] tracking-[0.16em] uppercase text-ink/24">
                    &mdash;&thinsp;{m.source}
                  </p>
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      </section>

      {/* ── Ornamental Divider ────────────────────────────────────────────── */}
      <div className="px-6 lg:px-12 max-w-7xl mx-auto mb-16">
        <div className="flex items-center gap-4">
          <div className="flex-1 h-px bg-ink/10" />
          <span className="font-courier text-[0.55rem] tracking-[0.5em] text-ink/18">&#9670;</span>
          <div className="flex-1 h-px bg-ink/10" />
        </div>
      </div>

      {/* ── Mission Statement ─────────────────────────────────────────────── */}
      <motion.section
        className="px-6 lg:px-12 pb-24 max-w-7xl mx-auto"
        variants={stagger}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, margin: "-80px" }}
      >
        {/* Overline kicker */}
        <motion.p
          variants={fadeUp}
          className="font-barlow text-[0.7rem] tracking-[0.34em] uppercase text-saffron mb-4"
        >
          How We Designed This
        </motion.p>

        {/* Display heading */}
        <motion.h2
          variants={fadeUp}
          className="font-playfair font-bold text-ink leading-[1.05] mb-12 max-w-3xl"
          style={{ fontSize: "clamp(2rem, 5vw, 4rem)" }}
        >
          Instant payments.
          <br className="hidden md:block" /> Intelligent fraud defence.
        </motion.h2>

        {/* Two-column prose */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-10 lg:gap-16 max-w-5xl mb-14">

          {/* The Constraint */}
          <motion.div variants={fadeUp} className="flex gap-3">
            <div className="w-0.5 shrink-0 bg-block/50 mt-1" />
            <div>
              <p className="font-barlow text-[0.6rem] tracking-[0.30em] uppercase text-ink/32 mb-2">
                The Challenge
              </p>
              <p className="font-barlow text-[0.92rem] text-ink/68 leading-[1.75]">
                Every UPI transaction settles in under <strong className="font-semibold text-ink">15 seconds</strong>.
                If your fraud model sits on that critical path &mdash; between the
                user and their bank &mdash; one slow inference call can stall payments
                for millions of people. That&rsquo;s the tradeoff every legacy
                system forces you to accept.
              </p>
            </div>
          </motion.div>

          {/* The Verdict */}
          <motion.div variants={fadeUp} className="flex gap-3">
            <div className="w-0.5 shrink-0 bg-allow/50 mt-1" />
            <div>
              <p className="font-barlow text-[0.6rem] tracking-[0.30em] uppercase text-ink/32 mb-2">
                How We Solve It
              </p>
              <p className="font-barlow text-[0.92rem] text-ink/68 leading-[1.75]">
                Our Rust gateway reads from a shared risk cache and returns{" "}
                <code className="font-courier text-[0.82rem] text-saffron bg-ink/[0.05] px-1 py-0.5">
                  ALLOW&thinsp;/&thinsp;FLAG&thinsp;/&thinsp;BLOCK
                </code>{" "}
                in{" "}
                <strong className="font-semibold text-ink">under 10&thinsp;ms</strong>
                {" "}&mdash; without ever calling the ML model in real time. The Random
                Forest and graph agent run{" "}
                <em>entirely in the background</em>, writing better signals into
                the cache after every transaction.
              </p>
            </div>
          </motion.div>
        </div>

        {/* ── Five-Layer Architecture Callout ───────────────────────────── */}
        <motion.div
          variants={fadeUp}
          className="border border-ink/12 bg-ink text-cream overflow-hidden"
          style={{
            backgroundImage:
              "linear-gradient(rgba(37,99,235,0.055) 1px, transparent 1px), linear-gradient(90deg, rgba(37,99,235,0.055) 1px, transparent 1px)",
            backgroundSize: "36px 36px",
          }}
        >
          {/* Callout header bar */}
          <div className="border-b border-cream/[0.08] px-8 py-3.5 flex justify-between items-center">
            <span className="font-barlow text-[0.6rem] tracking-[0.32em] uppercase text-cream/32">
              Five Layers &mdash; One Verdict in Under 10ms
            </span>
            <span className="font-courier text-[0.58rem] tracking-wider text-cream/18">
              async &middot; off-path &middot; consortium
            </span>
          </div>

          {/* Layer columns */}
          <div className="grid grid-cols-1 md:grid-cols-5 divide-y md:divide-y-0 md:divide-x divide-cream/[0.08]">
            {layers.map((l) => (
              <div key={l.id} className="px-6 py-6">
                {/* Layer ID */}
                <p className="font-courier text-2xl font-bold text-saffron mb-2">
                  {l.id}
                </p>
                {/* Layer name */}
                <p className="font-barlow text-[0.84rem] font-semibold text-cream leading-snug mb-1.5">
                  {l.name}
                </p>
                {/* Tech stack note */}
                <p className="font-barlow text-[0.72rem] text-cream/35 leading-relaxed mb-3">
                  {l.tech}
                </p>
                {/* Status indicator */}
                <div className="flex items-center gap-1.5">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-allow animate-pulse" />
                  <span className="font-barlow text-[0.54rem] tracking-widest uppercase text-cream/22">
                    Active
                  </span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </motion.section>

      {/* ── Footer ────────────────────────────────────────────────────────── */}
      <footer className="border-t border-ink/10 px-6 lg:px-12 py-4">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row justify-between items-center gap-2">
          <span className="font-barlow text-[0.58rem] tracking-[0.26em] uppercase text-ink/22">
            Varaksha V2 &middot; NPCI Hackathon 2026 &middot; Blue Team
          </span>
          <span className="font-courier text-[0.58rem] tracking-wider text-ink/18">
            Rust + Python + Next.js
          </span>
        </div>
      </footer>

    </main>
  );
}
