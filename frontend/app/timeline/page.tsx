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
    quote: "A system that cannot be demonstrated in under a minute cannot be evaluated under pressure.",
    body:  "An initial audit identified a fundamental tension between technical depth and operational legibility. The architecture carried PyO3 bindings, a kernel monitor, multi-agent orchestration, and a twelve-step setup sequence — all fully functional, none presentable within a constrained demonstration window. The decision was taken to rebuild on a focused five-layer pipeline with plain JSON interfaces between components, with demonstrability treated as a first-class design constraint.",
    tags:  ["Architecture", "5-Layer Design", "Design Decision"],
    owner: "both",
    Icon:  Lightbulb,
  },
  {
    date:  "Mar 1",
    title: "Privacy Gateway in Rust",
    quote: "Sensitive identifiers must not persist beyond the perimeter. Everything downstream operates on hashes.",
    body:  "The Actix-Web 4 gateway was designed as the sole component that handles raw Virtual Payment Addresses. SHA-256 hashing is applied at ingress — all downstream services receive only derived identifiers. DashMap provides a lock-free concurrent risk cache across the Actix worker pool. Three endpoints manage transaction scoring, health enquiries, and cache updates; score_to_verdict() threshold logic determines ALLOW, FLAG, and BLOCK classifications.",
    tags:  ["Rust", "SHA-256", "DashMap", "Actix-Web 4"],
    owner: "sec",
    Icon:  ShieldCheck,
  },
  {
    date:  "Mar 1",
    title: "ML Baseline Established",
    quote: "A working baseline yields more actionable information than an unimplemented optimal architecture.",
    body:  "The initial model comprised a RandomForest and XGBoost soft-vote ensemble operating on eight engineered features: transaction velocity, round-amount flag, network out-degree, and hour-of-day sinusoidal encoding. SMOTE rebalancing was applied prior to every train-test split. Trained on a stratified 50K PaySim sample, the baseline established an evaluation framework and an accuracy reference point for subsequent iterations.",
    tags:  ["RF + XGBoost", "SMOTE", "8 features", "PaySim"],
    owner: "ml",
    Icon:  BrainCircuit,
  },
  {
    date:  "Mar 2",
    title: "Graph-Based Mule Detection",
    quote: "Network fan-out is a consistent topological signature across all known money-mule architectures.",
    body:  "The NetworkX graph agent operates asynchronously and entirely outside the critical payment path — graph traversal must never introduce latency into /v1/tx response times. Four BIS Project Hertha typologies are detected: fan-out, fan-in, directed cycles, and scatter patterns. Score aggregation uses the maximum across detected patterns rather than summation, preventing false positives on legitimate high-volume merchants. Results are pushed to the Rust risk cache via HMAC-SHA256-signed webhooks.",
    tags:  ["NetworkX", "Fan-out", "Directed Cycles", "Async", "HMAC-SHA256"],
    owner: "sec",
    Icon:  GitBranch,
  },
  {
    date:  "Mar 2–3",
    title: "Multilingual Alert Delivery",
    quote: "A fraud alert has no utility if the recipient cannot read the language in which it is issued.",
    body:  "The alert agent was designed with zero hard runtime dependencies. All Hindi narration uses deterministic templates, requiring neither a language model nor an external API. Googletrans provides coverage for all 22 Indian scheduled languages; edge-tts delivers Microsoft neural TTS output at no cost. BLOCK-verdict alerts explicitly cite IT Act 2000 §66C and BNSS §318, grounding each notification in the applicable legal framework. The agent degrades gracefully to plain text on base Python environments.",
    tags:  ["Hindi TTS", "22 languages", "IT Act 2000 §66C", "edge-tts"],
    owner: "sec",
    Icon:  MessageCircle,
  },
  {
    date:  "Mar 3",
    title: "Integration Proof-of-Concept",
    quote: "A live feed of synthetic fraud, rendered with correctly classified verdicts, validated the end-to-end pipeline.",
    body:  "The Streamlit dashboard was constructed as an integration test made visible: an auto-refreshing ALLOW/FLAG/BLOCK verdict feed with colour-coded classifications, a Plotly Scattergl force-directed transaction network, a Hindi alert panel surfacing the most recent flagged transaction, and an audit log of the last 50 scored events. All Virtual Payment Addresses are synthetically generated from a seeded RNG — no real payment data is processed at any stage.",
    tags:  ["Streamlit", "Plotly Scattergl", "Synthetic PII", "Audit Log"],
    owner: "both",
    Icon:  BarChart2,
  },
  {
    date:  "Mar 5–7",
    title: "Model Architecture Overhaul",
    quote: "At 450 MB combined, the ensemble consumed nearly the entire memory budget for a sub-0.005 accuracy gain.",
    body:  "XGBoost was removed from the serving stack. RF-300 achieves ROC-AUC 0.9869 in isolation; the marginal improvement from the ensemble was below 0.005 on this dataset family — insufficient to justify the memory overhead. Feature engineering was expanded from 8 to 16 variables, incorporating balance_drain_ratio, account_age_days, previous_failed_attempts, and transfer_cashout_flag. Seven dataset loaders merged 75,358 real-world rows into a single training set. The output artefact, varaksha_rf_model.onnx, replaced the ensemble entirely.",
    tags:  ["RF-300 only", "16 features", "75K rows", "ONNX", "ROC-AUC 0.9869"],
    owner: "ml",
    Icon:  RefreshCw,
  },
  {
    date:  "Mar 9–10",
    title: "Production Deployment",
    quote: "Static export to a global edge network eliminates cold starts and infrastructure overhead from the demonstration path entirely.",
    body:  "Next.js 15 was configured with static export, removing the Node.js server from the serving path and enabling zero-latency global delivery via Cloudflare Pages. The frontend comprises three routes: a landing page with live metric cards, an animated architectural walkthrough, and a synthetic real-time transaction feed incorporating a Security Arena panel and a Cache Visualizer. Initial deployment was live and stable.",
    tags:  ["Next.js 15", "Cloudflare Pages", "Static Export", "framer-motion"],
    owner: "both",
    Icon:  Globe,
  },
  {
    date:  "Mar 11 AM",
    title: "Dataset Coverage Audit",
    quote: "Model artefact timestamps confirmed the training pipeline had never ingested the complete dataset.",
    body:  "A systematic audit of the dataset directory revealed that three files had no registered loaders in the training pipeline: supervised_dataset.csv (API behaviour anomaly patterns, 1,699 rows), remaining_behavior_ext.csv (bot, attack, and outlier behaviours, 34,423 rows), and ton-iot.csv (IoT network intrusion data). Filesystem modification timestamps on the ONNX model artefacts confirmed they predated the addition of these files. Three loaders were written, validated against schema, and integrated into the merge pipeline.",
    tags:  ["Dataset Audit", "34K rows recovered", "3 loaders added", "Timestamp analysis"],
    owner: "ml",
    Icon:  SearchCode,
  },
  {
    date:  "Mar 11 PM",
    title: "96.52%",
    quote: "Retraining on the complete dataset produced a consistent 96.52% accuracy — a 2.1-point gain over the partial-data baseline.",
    body:  "The expanded dataset of 111,499 merged rows was rebalanced via SMOTE to a 51,735/51,735 class distribution. Final evaluation: RF Accuracy 96.52%, ROC-AUC 0.9952, Fraud Precision 0.9745, Recall 0.9419, F1 0.9579. Stale model artefacts from discarded experiments — lightgbm.pkl, xgboost.pkl, xgboost.onnx, voting_ensemble.pkl, voting_ensemble.onnx — were removed from the repository. None were referenced by the active inference pipeline.",
    tags:  ["111K rows", "96.52% accuracy", "ROC-AUC 0.9952", "Artefact cleanup"],
    owner: "ml",
    Icon:  Zap,
  },
  {
    date:  "Mar 11",
    title: "Finalisation and Deployment",
    quote: "The margin between a functional system and a deployable one is defined by the quality of its finishing details.",
    body:  "A dot-grid body texture and surface-gradient card utility were applied across the frontend. The amber token (#D97706) was separated from the saffron accent to provide a visually distinct classification colour for FLAG-severity verdicts. The repository was migrated to the Varaksha-G organisation, the Cloudflare Pages project was recreated under the new identity, all documentation was updated, and the build timeline page was published.",
    tags:  ["dot-grid texture", "Amber FLAG", "Organisation transfer", "Cloudflare"],
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
    body:  "96.52% detection accuracy. ROC-AUC 0.9952. Sub-5ms P99 gateway latency. Four BIS money-mule typologies detected autonomously. Fraud alerts in 22 Indian languages, with legal citations embedded. Built, trained, and deployed to global edge in 11 days.",
  },
];

// ── Chip (owner label) ────────────────────────────────────────────────────────
function Chip({ owner }: { owner: Owner }) {
  if (owner === "both") {
    return (
      <div className="flex items-center gap-1.5">
        <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: PINK }} />
        <span
          className="font-barlow text-[0.5rem] tracking-[0.22em] uppercase"
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
      <span className="font-barlow text-[0.5rem] tracking-[0.22em] uppercase" style={{ color }}>
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
      <div className="bg-white/55 backdrop-blur-sm px-5 py-5 lg:px-6 lg:py-6 transition-shadow duration-300 group-hover:shadow-[0_4px_24px_rgba(15,30,46,0.07)]">
        <div className="flex items-start justify-between gap-4 mb-3">
          <Chip owner={ms.owner} />
          <span className="font-courier text-[0.48rem] tracking-[0.18em] text-ink/25 whitespace-nowrap pt-px">
            {ms.date}
          </span>
        </div>
        <h3
          className="font-playfair font-bold text-ink leading-tight mb-3"
          style={{ fontSize: "clamp(1.05rem, 2vw, 1.25rem)" }}
        >
          {ms.title}
        </h3>
        <p
          className="font-playfair italic leading-snug mb-3"
          style={{ fontSize: "0.8rem", color: isBoth ? PINK : color, opacity: 0.85 }}
        >
          &ldquo;{ms.quote}&rdquo;
        </p>
        <p className="font-barlow text-[0.71rem] text-ink/48 leading-relaxed mb-4">
          {ms.body}
        </p>
        <div className="flex flex-wrap gap-1.5">
          {ms.tags.map((t, i) => (
            <span
              key={i}
              className="font-courier text-[0.45rem] tracking-widest uppercase px-2 py-0.5 rounded-full"
              style={{
                color:           isBoth ? "#6b7280" : color,
                backgroundColor: isBoth ? "rgba(0,0,0,0.03)" : `${color}0c`,
                border:          `1px solid ${isBoth ? "rgba(0,0,0,0.07)" : `${color}1f`}`,
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
            className="font-barlow text-[0.58rem] tracking-[0.24em] uppercase text-ink/30 hover:text-saffron transition-colors"
          >
            &larr;&thinsp;Varaksha
          </a>
          <span className="text-ink/15 select-none">|</span>
          <span className="font-barlow text-[0.58rem] tracking-[0.24em] uppercase text-ink/30">
            Build Timeline
          </span>
        </div>
      </header>

      {/* Hero */}
      <section className="px-6 lg:px-12 pt-14 pb-12 max-w-5xl mx-auto">
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
          className="font-barlow text-[0.78rem] text-ink/42 leading-relaxed max-w-md mb-9"
        >
          A detailed account of two parallel workstreams converging on a single system.
          Security architecture in pink. Machine learning in blue.
          Shared decisions in gradient.
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
              <span className="font-barlow text-[0.6rem] tracking-[0.2em] uppercase text-ink/42">
                {label}
              </span>
            </div>
          ))}
          <div className="flex items-center gap-2.5">
            <div
              className="w-7 h-[2px] rounded-full"
              style={{ backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})` }}
            />
            <span className="font-barlow text-[0.6rem] tracking-[0.2em] uppercase text-ink/42">
              Together
            </span>
          </div>
        </motion.div>
      </section>

      {/* Storyboard */}
      <section className="px-6 lg:px-12 pb-16 max-w-5xl mx-auto">
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
                className="font-playfair font-bold leading-none mb-4 select-none"
                style={{
                  fontSize: "3rem",
                  backgroundImage: `linear-gradient(135deg, ${PINK}25, ${BLUE}25)`,
                  WebkitBackgroundClip: "text",
                  color: "transparent",
                }}
              >
                {s.num}
              </p>
              <h3 className="font-playfair font-bold text-ink text-[1rem] mb-2">
                {s.label}
              </h3>
              <p className="font-barlow text-[0.72rem] text-ink/48 leading-relaxed">
                {s.body}
              </p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Timeline */}
      <section ref={containerRef} className="px-4 lg:px-12 max-w-5xl mx-auto relative">

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
                <div className="lg:hidden flex items-start gap-4 pl-10 pb-10">
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

      {/* Footer */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.55 }}
        className="mt-16 flex flex-col items-center gap-4 px-6"
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
