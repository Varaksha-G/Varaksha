"use client";

import { useRef } from "react";
import {
  motion,
  useScroll,
  useTransform,
  useInView,
} from "framer-motion";
import {
  Lightbulb,
  ShieldCheck,
  BrainCircuit,
  GitBranch,
  MessageCircle,
  BarChart2,
  RefreshCw,
  Globe,
  SearchCode,
  Zap,
  Rocket,
  Smartphone,
  Languages,
  Network,
  Scale,
  Cpu,
  Bot,
  PackageOpen,
  ShieldPlus,
  type LucideIcon,
} from "lucide-react";

// ── Palette ───────────────────────────────────────────────────────────────────
const PINK = "#EC4899";
const BLUE = "#2563EB";

type Owner = "sec" | "ml" | "both";

const LABEL: Record<Owner, string> = {
  sec:  "Security",
  ml:   "ML",
  both: "Together",
};

function ownerColor(o: Owner) {
  return o === "sec" ? PINK : BLUE;
}

// ── Milestone data ────────────────────────────────────────────────────────────
interface Milestone {
  date:  string;
  title: string;
  quote: string;
  body:  string;
  tags:  string[];
  owner: Owner;
  Icon:  LucideIcon;
}

const MILESTONES: Milestone[] = [
  {
    date:  "Feb 28",
    title: "Defining the Architecture",
    quote: "Demonstrability is a first-class design constraint.",
    body:  "Five-layer architecture scoped: Rust privacy gateway, ML classifier, graph topology analyser, multilingual alert agent, and ops dashboard. System designed to be comprehensible in under a minute, evaluated under pressure.",
    tags:  ["5-Layer Design", "Architecture", "Core Pipeline"],
    owner: "both",
    Icon:  Lightbulb,
  },
  {
    date:  "Mar 1",
    title: "Privacy Gateway in Rust",
    quote: "Sensitive identifiers must not persist beyond the perimeter. Everything downstream operates on hashes.",
    body:  "The Actix-Web 4 gateway is the sole component that handles raw Virtual Payment Addresses — SHA-256 hashing is applied at ingress so all downstream services receive only derived identifiers. DashMap provides a lock-free concurrent risk cache across the Actix worker pool; score_to_verdict() threshold logic determines ALLOW, FLAG, and BLOCK classifications.",
    tags:  ["Rust", "SHA-256", "DashMap", "Actix-Web 4"],
    owner: "sec",
    Icon:  ShieldCheck,
  },
  {
    date:  "Mar 1",
    title: "ML Baseline Established",
    quote: "A working baseline yields insights that an unimplemented optimal architecture cannot.",
    body:  "Random Forest + XGBoost soft-vote ensemble on transaction velocity, round-amount flag, network out-degree, and time-of-day encoding. Stratified 50K PaySim sample with SMOTE rebalancing. Reference point established for subsequent iterations.",
    tags:  ["RF + XGBoost", "SMOTE", "PaySim"],
    owner: "ml",
    Icon:  BrainCircuit,
  },
  {
    date:  "Mar 2",
    title: "Graph-Based Mule Detection",
    quote: "Network fan-out is a consistent topological signature across all known money-mule architectures.",
    body:  "A NetworkX graph agent runs asynchronously outside the payment critical path, detecting all four BIS Project Hertha mule typologies: fan-out, fan-in, directed cycles, and scatter patterns. Score aggregation uses the maximum across detected patterns to prevent false positives on legitimate high-volume merchants; results push to the Rust risk cache via HMAC-SHA256-signed webhooks.",
    tags:  ["NetworkX", "Fan-out", "Directed Cycles", "Async", "HMAC-SHA256"],
    owner: "sec",
    Icon:  GitBranch,
  },
  {
    date:  "Mar 2–3",
    title: "Multilingual Alert Delivery",
    quote: "A fraud alert has no utility if the recipient cannot read the language in which it is issued.",
    body:  "Alerts synthesised in 8 Indian languages via Microsoft Neural TTS (edge-tts) embed the transaction ID, blocked amount, and risk score in the recipient\u2019s preferred language. BLOCK verdicts cite IT Act 2000 \u00a766D and BNS \u00a7318(4) verbatim; the template engine is swappable for IndicTrans2 at production time.",
    tags:  ["8 languages", "Neural TTS", "IT Act 2000 §66D", "edge-tts"],
    owner: "sec",
    Icon:  MessageCircle,
  },
  {
    date:  "Mar 3",
    title: "Integration Proof-of-Concept",
    quote: "End-to-end verdicts validated — from Rust ingress to multilingual alert.",
    body:  "A live operations dashboard confirmed verdicts flowing through all five layers: transaction ingress, hashing, ML scoring, graph analysis, and multilingual alert dispatch. Force-directed network visualization, Hindi alert panel, and 50-event audit log. All data is synthetic—no real PII processed.",
    tags:  ["5-Layer Pipeline", "Live Dashboard", "Audit Log", "Synthetic"],
    owner: "both",
    Icon:  BarChart2,
  },
  {
    date:  "Mar 5–7",
    title: "Model Architecture Overhaul",
    quote: "At 450 MB combined, the ensemble consumed nearly the entire memory budget for a sub-0.005 accuracy gain.",
    body:  "XGBoost was removed from the serving stack: RF-300 achieves ROC-AUC 0.9869 in isolation and the marginal ensemble gain was insufficient to justify 450 MB combined weight. Feature engineering expanded from 8 to 16 variables, incorporating balance_drain_ratio, account_age_days, previous_failed_attempts, and transfer_cashout_flag; the output artefact became varaksha_rf_model.onnx.",
    tags:  ["RF-300 only", "16 features", "75K rows", "ONNX", "ROC-AUC 0.9869"],
    owner: "ml",
    Icon:  RefreshCw,
  },
  {
    date:  "Mar 9–10",
    title: "Production Deployment",
    quote: "Static export to a global edge network eliminates cold starts and infrastructure overhead from the demonstration path entirely.",
    body:  "Next.js 15 configured with static export and deployed to Cloudflare Pages eliminates cold starts and Node.js server overhead from the demonstration path. The frontend ships three routes: a live stats landing page, an animated architecture walkthrough, and a real-time transaction feed with Security Arena and Cache Visualizer panels.",
    tags:  ["Next.js 15", "Cloudflare Pages", "Static Export", "framer-motion"],
    owner: "both",
    Icon:  Globe,
  },
  {
    date:  "Mar 11 AM",
    title: "Dataset Coverage Audit",
    quote: "Model timestamps revealed the training pipeline had never ingested the complete dataset.",
    body:  "Three missing dataset files discovered: supervised_dataset.csv, remaining_behavior_ext.csv, and ton-iot.csv. All loaders written, validated against schema, and integrated into the merge pipeline. 54,142 rows recovered.",
    tags:  ["Dataset Audit", "54K Rows", "3 Loaders"],
    owner: "ml",
    Icon:  SearchCode,
  },
  {
    date:  "Mar 11 PM",
    title: "85.24%",
    quote: "Retraining on the complete leakage-corrected dataset: 85.24% accuracy, ROC-AUC 0.9546.",
    body:  "The expanded 111,499-row dataset rebalanced by SMOTE to 51,735/51,735 yielded: RF Accuracy 85.24%, ROC-AUC 0.9546, Precision 0.7709, Recall 0.9229, F1 0.8401. Stale artefacts — lightgbm, xgboost, voting ensemble — were removed from the repository.",
    tags:  ["111K rows", "85.24% accuracy", "ROC-AUC 0.9546", "Artefact cleanup"],
    owner: "ml",
    Icon:  Zap,
  },
  {
    date:  "Mar 11",
    title: "Finalisation and Deployment",
    quote: "A deployable system is defined by finishing details—texture, colour, and interactive feedback.",
    body:  "Frontend polish: dot-grid body texture, surface-gradient card utility, amber token separated from saffron for distinct FLAG verdict rendering. Next.js static export deployed to Cloudflare Pages. Core pipeline hardened and ready for production integration.",
    tags:  ["Next.js 15", "Static Export", "Polish", "Production-Ready"],
    owner: "both",
    Icon:  Rocket,
  },
];

// ── Storyboard data ──────────────────────────────────────────────────────────
const STORYBOARD = [
  {
    num:   "01",
    label: "The Problem",
    body:  "India's Unified Payments Interface processes over 500 million transactions daily. Legacy fraud detection operates on batch cycles, introducing delays that allow mule networks to execute and disperse before a single alert is raised. Real-time classification at the transaction layer is a structural necessity, not an optimisation.",
  },
  {
    num:   "02",
    label: "The Architecture",
    body:  "Varaksha is a five-layer detection pipeline: a Rust privacy gateway that hashes identifiers at ingress, a Random Forest ML engine trained on 111K real transactions, a graph topology analyser for network-pattern fraud, a multilingual alert agent covering 22 Indian languages, and a real-time operations dashboard.",
  },
  {
    num:   "03",
    label: "The Outcome",
    body:  "85.24% detection accuracy. ROC-AUC 0.9546. Sub-5ms P99 gateway latency. Four BIS money-mule typologies detected autonomously. Fraud alerts in 8 Indian languages, with legal citations embedded. Recall 0.9229 — catches 92 in every 100 fraud transactions. Built, trained, and deployed to global edge in 12 days.",
  },
];

// ── Future scope data ────────────────────────────────────────────────────
interface FutureItem {
  Icon:     LucideIcon;
  title:    string;
  blurb:    string;
  tag:      string;
  colorIdx: number;   // 0 = pink, 1 = blue, 2 = purple
}

const FUTURE: FutureItem[] = [
  {
    Icon:     Languages,
    title:    "All 22 Scheduled Languages",
    blurb:    "Expand from 8 to all constitutionally scheduled Indian languages via IndicTrans2 — swap a single function call in agent03.",
    tag:      "Accessibility",
    colorIdx: 0,
  },
  {
    Icon:     Smartphone,
    title:    "Mobile SDK Packaging",
    blurb:    "Package the ONNX inference layer as an Android / iOS SDK so PSPs can embed sub-1ms on-device scoring without a network call.",
    tag:      "Distribution",
    colorIdx: 1,
  },
  {
    Icon:     Cpu,
    title:    "On-Device Edge Inference",
    blurb:    "Ship varaksha_rf_model.onnx to handsets via ONNX Runtime Mobile. Scores computed locally — zero round-trip latency, works offline.",
    tag:      "Performance",
    colorIdx: 1,
  },
  {
    Icon:     Network,
    title:    "Streaming Graph Analytics",
    blurb:    "Replace batch NetworkX with Apache Flink or Kafka Streams so fan-out and cycle detection updates continuously as edges arrive.",
    tag:      "Architecture",
    colorIdx: 2,
  },
  {
    Icon:     Bot,
    title:    "Live LLM Legal Summaries",
    blurb:    "Replace the mock LLM in agent03 with GPT-4o-mini or Groq to generate dynamic, context-aware legal citations per transaction.",
    tag:      "AI",
    colorIdx: 0,
  },
  {
    Icon:     ShieldPlus,
    title:    "NPCI Consortium Risk Sharing",
    blurb:    "Federate anonymised risk scores across participating PSP banks via a shared NPCI registry — consortium intelligence without PII exposure.",
    tag:      "Ecosystem",
    colorIdx: 2,
  },
  {
    Icon:     Scale,
    title:    "Automated Regulatory Reporting",
    blurb:    "Auto-generate FIU-IND Suspicious Transaction Reports for PMLA §3 triggers and maintain a DPDP Act 2023 audit trail per blocked VPA.",
    tag:      "Compliance",
    colorIdx: 0,
  },
  {
    Icon:     PackageOpen,
    title:    "Open-Source Release",
    blurb:    "Publish the five-layer pipeline as an open library — plug in your own dataset, retrain in one command, deploy to any cloud with azd.",
    tag:      "Community",
    colorIdx: 1,
  },
];

const FUTURE_COLORS = [
  { text: PINK,      bg: `${PINK}10`,      border: `${PINK}22`      },
  { text: BLUE,      bg: `${BLUE}10`,      border: `${BLUE}22`      },
  { text: "#9333ea", bg: "#9333ea10",      border: "#9333ea22"      },
];

// ── Chip (owner label) ────────────────────────────────────────────────────────
function Chip({ owner }: { owner: Owner }) {
  if (owner === "both") {
    return (
      <div className="flex items-center gap-1.5">
        <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: PINK }} />
        <span
          className="font-barlow text-[0.63rem] tracking-[0.2em] uppercase"
          style={{
            backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})`,
            WebkitBackgroundClip: "text",
            color: "transparent",
          }}
        >
          Together
        </span>
        <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: BLUE }} />
      </div>
    );
  }
  const color = ownerColor(owner);
  return (
    <div className="flex items-center gap-1.5">
      <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
      <span className="font-barlow text-[0.63rem] tracking-[0.2em] uppercase" style={{ color }}>
        {LABEL[owner]}
      </span>
    </div>
  );
}

// ── Spine node ────────────────────────────────────────────────────────────────
function SpineNode({ ms }: { ms: Milestone }) {
  const color = ms.owner === "both" ? PINK : ownerColor(ms.owner);
  return (
    <div className="relative flex items-center justify-center w-10 h-10 shrink-0">
      <motion.span
        className="absolute inset-0 rounded-full"
        style={{ border: `1px solid ${color}`, opacity: 0.3 }}
        animate={{ scale: [1, 1.75, 1], opacity: [0.3, 0, 0.3] }}
        transition={{ duration: 3, repeat: Infinity, ease: "easeOut" }}
      />
      <div
        className="relative z-10 w-8 h-8 rounded-full flex items-center justify-center"
        style={{ backgroundColor: `${color}12`, border: `1px solid ${color}30` }}
      >
        <ms.Icon size={14} style={{ color }} />
      </div>
    </div>
  );
}

// ── Milestone card ────────────────────────────────────────────────────────────
function Card({ ms, side }: { ms: Milestone; side: "left" | "right" | "center" }) {
  const ref    = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-80px 0px 0px 0px" });
  const color  = ms.owner === "sec" ? PINK : BLUE;
  const isBoth = ms.owner === "both";
  const initX  = side === "left" ? -28 : side === "right" ? 28 : 0;

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, x: initX, y: 10 }}
      animate={inView ? { opacity: 1, x: 0, y: 0 } : {}}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      className="group"
    >
      <div
        className="h-[2px] mb-0 rounded-full"
        style={
          isBoth
            ? { backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})` }
            : { backgroundColor: color, opacity: 0.65 }
        }
      />
      <div className="bg-white/60 backdrop-blur-sm px-6 py-7 lg:px-8 lg:py-8 transition-shadow duration-300 group-hover:shadow-[0_8px_32px_rgba(15,30,46,0.12)]">
        <div className="flex items-start justify-between gap-4 mb-4">
          <Chip owner={ms.owner} />
          <span className="font-courier text-[0.65rem] tracking-[0.14em] text-ink/70 font-semibold whitespace-nowrap pt-px">
            {ms.date}
          </span>
        </div>
        <h3
          className="font-playfair font-bold text-ink leading-tight mb-4"
          style={{ fontSize: "clamp(1.15rem, 2.2vw, 1.35rem)" }}
        >
          {ms.title}
        </h3>
        <p
          className="font-playfair italic leading-snug mb-4"
              style={{ fontSize: "0.95rem", color: isBoth ? PINK : color, opacity: 0.95 }}
        >
          &ldquo;{ms.quote}&rdquo;
        </p>
        <p className="font-barlow text-[0.88rem] text-ink/70 leading-relaxed mb-5">
          {ms.body}
        </p>
        <div className="flex flex-wrap gap-2">
          {ms.tags.map((t, i) => (
            <span
              key={i}
              className="font-courier text-[0.62rem] tracking-wide uppercase px-2.5 py-1 rounded-full font-semibold"
              style={{
                color:           isBoth ? "#4b5563" : color,
                backgroundColor: isBoth ? "rgba(0,0,0,0.05)" : `${color}0f`,
                border:          `1px solid ${isBoth ? "rgba(0,0,0,0.1)" : `${color}25`}`,
              }}
            >
              {t}
            </span>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

// ── Thin connector (spine node to card) ──────────────────────────────────────
function Connector({ ms }: { ms: Milestone }) {
  const color = ms.owner === "sec" ? PINK : BLUE;
  return (
    <div
      className="hidden lg:block self-center h-px shrink-0 w-8"
      style={{ backgroundColor: color, opacity: 0.18 }}
    />
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function TimelinePage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target:  containerRef,
    offset:  ["start 15%", "end 85%"],
  });
  const lineScaleY = useTransform(scrollYProgress, [0, 1], [0, 1]);

  return (
    <main className="min-h-screen bg-cream text-ink pb-32">

      {/* breadcrumb */}
      <header className="border-b border-ink/10 px-6 lg:px-12 py-2.5">
        <div className="max-w-7xl mx-auto flex items-center gap-3">
          <a
            href="/"
            className="font-barlow text-[0.58rem] tracking-[0.24em] uppercase text-ink/60 font-semibold hover:text-saffron transition-colors"
          >
            &larr;&thinsp;Varaksha
          </a>
          <span className="text-ink/15 select-none">|</span>
          <span className="font-barlow text-[0.58rem] tracking-[0.24em] uppercase text-ink/60 font-semibold">
            Build Timeline
          </span>
        </div>
      </header>

      {/* Hero */}
      <section className="px-6 lg:px-12 pt-14 pb-12 max-w-6xl mx-auto">
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
          className="font-barlow text-[0.65rem] tracking-[0.36em] uppercase mb-5"
          style={{
            backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})`,
            WebkitBackgroundClip: "text",
            color: "transparent",
            display: "inline-block",
          }}
        >
          Feb 28 &ndash; Mar 11, 2026 &middot; 11 days
        </motion.p>

        <motion.h1
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.08, duration: 0.6, ease: "easeOut" }}
          className="font-playfair font-bold text-ink leading-[0.9] mb-5"
          style={{ fontSize: "clamp(2.4rem, 5.5vw, 4.2rem)" }}
        >
          How We Built<br />Varaksha in a Sprint
        </motion.h1>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="font-barlow text-[0.82rem] text-ink/60 leading-relaxed max-w-md mb-9"
        >
          Two workstreams converging on a single system. Security in pink, ML in blue, shared decisions in gradient.
        </motion.p>

        {/* Legend */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="flex flex-wrap items-center gap-6"
        >
          {[
            { label: "Security Expert", color: PINK },
            { label: "ML Expert",       color: BLUE },
          ].map(({ label, color }) => (
            <div key={label} className="flex items-center gap-2.5">
              <div className="w-7 h-[2px] rounded-full" style={{ backgroundColor: color }} />
              <span className="font-barlow text-[0.65rem] tracking-[0.2em] uppercase text-ink/60 font-semibold">
                {label}
              </span>
            </div>
          ))}
          <div className="flex items-center gap-2.5">
            <div
              className="w-7 h-[2px] rounded-full"
              style={{ backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})` }}
            />
            <span className="font-barlow text-[0.65rem] tracking-[0.2em] uppercase text-ink/60 font-semibold">
              Together
            </span>
          </div>
        </motion.div>
      </section>

      {/* Storyboard */}
      <section className="px-6 lg:px-12 pb-16 max-w-6xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-ink/8">
          {STORYBOARD.map((s, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-30px" }}
              transition={{ delay: i * 0.1, duration: 0.55, ease: "easeOut" }}
              className="px-0 md:px-8 py-8 first:pl-0 last:pr-0"
            >
              <p
                className="font-playfair font-bold leading-none mb-5 select-none"
                style={{
                  fontSize: "3.2rem",
                  backgroundImage: `linear-gradient(135deg, ${PINK}30, ${BLUE}30)`,
                  WebkitBackgroundClip: "text",
                  color: "transparent",
                }}
              >
                {s.num}
              </p>
              <h3 className="font-playfair font-bold text-ink text-[1.15rem] mb-3 leading-snug">
                {s.label}
              </h3>
              <p className="font-barlow text-[0.85rem] text-ink/70 leading-relaxed">
                {s.body}
              </p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Timeline */}
      <section ref={containerRef} className="px-3 sm:px-6 lg:px-10 max-w-6xl mx-auto relative">

        {/* Animated spine — desktop */}
        <div
          className="absolute top-0 bottom-0 hidden lg:block overflow-hidden"
          style={{ left: "50%", width: 1, transform: "translateX(-0.5px)" }}
        >
          <div className="absolute inset-0 bg-ink/8" />
          <motion.div
            className="absolute inset-x-0 top-0 origin-top"
            style={{
              scaleY: lineScaleY,
              backgroundImage: `linear-gradient(to bottom, ${PINK}, #9333ea 45%, ${BLUE})`,
              height: "100%",
            }}
          />
        </div>

        {/* Left spine — mobile */}
        <div
          className="absolute top-0 bottom-0 lg:hidden"
          style={{ left: 18, width: 1, backgroundColor: "rgba(15,30,46,0.08)" }}
        />

        <div className="space-y-0">
          {MILESTONES.map((ms, i) => {
            const isBoth = ms.owner === "both";
            const isSec  = ms.owner === "sec";
            return (
              <div key={i} className="relative">

                {/* Mobile layout */}
                <div className="lg:hidden flex items-start gap-4 pl-8 pb-8">
                  <div className="absolute left-[3px] top-0">
                    <SpineNode ms={ms} />
                  </div>
                  <Card ms={ms} side="center" />
                </div>

                {/* Desktop alternating */}
                {isBoth ? (
                  <div className="hidden lg:flex items-center justify-center py-8">
                    <div className="w-[min(460px,46%)] flex flex-col items-center gap-2">
                      <SpineNode ms={ms} />
                      <Card ms={ms} side="center" />
                    </div>
                  </div>
                ) : isSec ? (
                  <div className="hidden lg:flex items-center py-8">
                    <div className="flex-1 flex justify-end pr-1">
                      <div className="w-[92%]"><Card ms={ms} side="left" /></div>
                    </div>
                    <Connector ms={ms} />
                    <SpineNode ms={ms} />
                    <Connector ms={ms} />
                    <div className="flex-1" />
                  </div>
                ) : (
                  <div className="hidden lg:flex items-center py-8">
                    <div className="flex-1" />
                    <Connector ms={ms} />
                    <SpineNode ms={ms} />
                    <Connector ms={ms} />
                    <div className="flex-1 flex justify-start pl-1">
                      <div className="w-[92%]"><Card ms={ms} side="right" /></div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Future Scope */}
      <section className="px-6 lg:px-12 max-w-6xl mx-auto mt-28">

        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.55 }}
          className="mb-12 text-center"
        >
          <p
            className="font-barlow text-[0.6rem] tracking-[0.38em] uppercase mb-4 inline-block"
            style={{
              backgroundImage: `linear-gradient(90deg, #9333ea, ${BLUE})`,
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            On the Horizon
          </p>
          <h2
            className="font-playfair font-bold text-ink leading-tight mb-4"
            style={{ fontSize: "clamp(1.7rem, 4vw, 2.8rem)" }}
          >
            What We Build Next
          </h2>
          <p className="font-barlow text-[0.78rem] text-ink/50 max-w-md mx-auto leading-relaxed">
            Next steps: features we consciously set down to meet the deadline.
          </p>
        </motion.div>

        {/* Cards grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {FUTURE.map((item, i) => {
            const c = FUTURE_COLORS[item.colorIdx];
            return (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-30px" }}
                transition={{ delay: (i % 4) * 0.07, duration: 0.5, ease: "easeOut" }}
                className="group relative p-5 bg-white/35 backdrop-blur-sm"
                style={{ border: `1px dashed ${c.border}` }}
              >
                {/* Top accent line */}
                <div
                  className="absolute top-0 left-0 right-0 h-[1.5px] opacity-50"
                  style={{ backgroundColor: c.text }}
                />

                {/* Icon */}
                <div
                  className="w-8 h-8 flex items-center justify-center mb-4"
                  style={{ backgroundColor: c.bg, border: `1px solid ${c.border}` }}
                >
                  <item.Icon size={14} style={{ color: c.text }} />
                </div>

                {/* Title */}
                <h4
                  className="font-playfair font-bold text-ink text-[0.88rem] leading-snug mb-2"
                >
                  {item.title}
                </h4>

                {/* Blurb */}
                <p className="font-barlow text-[0.72rem] text-ink/55 leading-relaxed mb-4">
                  {item.blurb}
                </p>

                {/* Tag */}
                <span
                  className="font-courier text-[0.43rem] tracking-widest uppercase px-2 py-0.5"
                  style={{
                    color:           c.text,
                    backgroundColor: c.bg,
                    border:          `1px solid ${c.border}`,
                  }}
                >
                  {item.tag}
                </span>
              </motion.div>
            );
          })}
        </div>

      </section>

      {/* Footer */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.55 }}
        className="mt-24 flex flex-col items-center gap-4 px-6"
      >
        <div
          className="w-px h-16"
          style={{ backgroundImage: `linear-gradient(to bottom, ${BLUE}, ${PINK})` }}
        />
        <p
          className="font-playfair italic text-[0.9rem] text-center"
          style={{
            backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})`,
            WebkitBackgroundClip: "text",
            color: "transparent",
          }}
        >
          11 days &middot; 2 people &middot; shipped.
        </p>
      </motion.div>

    </main>
  );
}
