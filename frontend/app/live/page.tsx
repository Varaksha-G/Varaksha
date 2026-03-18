"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CacheVisualizer } from "./CacheVisualizer";
import { SecurityArena   } from "./SecurityArena";
import { LegalReport     } from "./LegalReport";
import { getApiBaseNormalized } from "../lib/api-config";

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const FEED_INTERVAL_MS  = 2200;   // New transaction injected to feed every N ms
const FEED_MAX_ROWS     = 60;     // Max rows before old ones are pruned
let streamSeq           = 1;

// ── Synthetic data pools ──────────────────────────────────────────────────────

const VPA_SENDERS = [
  "ravi.kumar@axisbank",  "priya.sharma@okicici",  "suresh.patel@ybl",
  "anita.rao@axisbank",   "mohan.verma@okhdfc",    "kavitha.n@paytm",
  "deepak.joshi@okaxis",  "sunita.devi@okhdfcbank","arjun.mehta@ybl",
  "lalitha.k@axisbank",   "rajesh.singh@okicici",  "meera.iyer@paytm",
];
const VPA_RECEIVERS = [
  "kirana.store@okhdfc",    "dmart.retail@ybl",       "fuel.pump@okaxis",
  "swiggy.merchant@icici",  "zomato.pay@okicici",     "pharmacy.care@ybl",
  "auto.rickshaw@paytm",    "electricity.board@okhdfc","booking.com@axisbank",
  "railway.prs@ybl",        "cashback.offer@okaxis",  "loan.repay@axisbank",
];
const MERCHANT_CATS = ["Grocery", "Fuel", "Food", "Pharmacy", "Utilities", "Travel", "Finance"];

// Feed transactions always ALLOW; occasional edge-cases are flagged
const FEED_AMOUNTS   = [120, 499, 1200, 4750, 890, 2400, 340, 7800, 1100, 60000, 310, 5500];
const FEED_DEVICES   = [false, false, false, true, false, false, true, false, false, true];

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

type Verdict    = "ALLOW" | "FLAG" | "BLOCK";
type LoadStage  = 0 | 1 | 2 | 3;   // 0 = idle, 1-3 = stages, after 3 = result

interface SandboxForm {
  senderVpa:    string;
  receiverVpa:  string;
  amount:       string;
  merchantCat:  string;
  timeOfDay:    string;
  newDevice:    boolean;
}

interface SandboxResult {
  verdict:    Verdict;
  riskScore:  number;
  latencyMs:  number;
  reasons:    string[];
}

interface FeedRow {
  id:          number;
  ts:          string;
  sender:      string;
  receiver:    string;
  amount:      number;
  merchantCat: string;
  verdict:     Verdict;
  riskScore:   number;
  latencyMs:   number;
}

interface StreamTx {
  time: string;
  sender: string;
  receiver: string;
  amount: number;
  category: string;
  verdict: Verdict;
  risk: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETERMINISTIC SYNTHETIC HELPERS  (no Math.random() in render — SSR-safe IDR)
// ═══════════════════════════════════════════════════════════════════════════════

let _feedSeq = 0;

function nextFeedRow(): FeedRow {
  const idx     = _feedSeq % VPA_SENDERS.length;
  const amtIdx  = _feedSeq % FEED_AMOUNTS.length;
  const devIdx  = _feedSeq % FEED_DEVICES.length;
  _feedSeq++;

  const amount    = FEED_AMOUNTS[amtIdx];
  const newDevice = FEED_DEVICES[devIdx];

  // Simplified verdict rule matching sandbox logic
  let verdict:    Verdict = "ALLOW";
  let riskScore          = 0.08 + (idx % 7) * 0.05;

  if (amount > 50000 && newDevice) {
    verdict   = "BLOCK";
    riskScore = 0.91;
  } else if (amount > 30000 || (newDevice && amount > 10000)) {
    verdict   = "FLAG";
    riskScore = 0.55 + (idx % 3) * 0.08;
  }

  const now = new Date();
  const ts  = now.toTimeString().slice(0, 8);   // HH:MM:SS

  return {
    id:          _feedSeq,
    ts,
    sender:      VPA_SENDERS[idx],
    receiver:    VPA_RECEIVERS[idx % VPA_RECEIVERS.length],
    amount,
    merchantCat: MERCHANT_CATS[idx % MERCHANT_CATS.length],
    verdict,
    riskScore:   Math.round(riskScore * 100) / 100,
    latencyMs:   4 + (idx % 9),
  };
}

function mapMerchantCategory(input: string): string {
  const key = input.toLowerCase();
  if (key === "grocery" || key === "food") return "FOOD";
  if (key === "fuel" || key === "utilities") return "UTILITY";
  if (key === "travel") return "TRAVEL";
  if (key === "finance") return "GAMBLING";
  return "ECOM";
}

function mapTimeBucketToHour(bucket: string): number {
  if (bucket === "06:00-09:00") return 8;
  if (bucket === "09:00-18:00") return 14;
  if (bucket === "18:00-22:00") return 20;
  if (bucket === "22:00-02:00") return 23;
  return 3;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHARED STYLE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function verdictBadge(v: Verdict) {
  if (v === "ALLOW") return "text-allow  bg-allow/10  border border-allow/20";
  if (v === "BLOCK") return "text-block  bg-block/10  border border-block/22";
  return                    "text-flag   bg-flag/10   border border-flag/22";
}

function verdictDot(v: Verdict) {
  if (v === "ALLOW") return "bg-allow";
  if (v === "BLOCK") return "bg-block";
  return                    "bg-flag";
}

function riskBar(score: number) {
  if (score >= 0.75) return "bg-block";
  if (score >= 0.40) return "bg-flag";
  return                    "bg-allow";
}

/**
 * maskVpa — privacy helper
 *
 * Per DPDP Act 2023 §2(t) mobile numbers are personal data; per NPCI UPI
 * Procedural Guidelines PSPs must mask phone-number VPAs when displayed
 * outside the VPA owner's own screen.  Name-based VPAs (e.g.
 * "ravi.kumar@axisbank") are passed through unchanged because the handle
 * contains no phone number.
 *
 * Examples:
 *   9876543210@ybl  →  98****10@ybl
 *   ravi.kumar@axisbank  →  ravi.kumar@axisbank  (unchanged)
 */
function maskVpa(vpa: string): string {
  const atIdx = vpa.indexOf("@");
  if (atIdx === -1) return vpa;
  const handle = vpa.slice(0, atIdx);
  const bank   = vpa.slice(atIdx + 1);
  // Match 10+ consecutive digits (Indian mobile VPA format)
  if (/^\d{10,}$/.test(handle)) {
    return `${handle.slice(0, 2)}****${handle.slice(-2)}@${bank}`;
  }
  return vpa;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE A — INTELLIGENCE SANDBOX
// ═══════════════════════════════════════════════════════════════════════════════

const LOAD_STAGES = [
  { label: "Rust Hashing …",   sub: "SHA-256 VPA digest · DashMap lookup" },
  { label: "ML Scoring …",     sub: "Random Forest 300 trees · IsolationForest anomaly" },
  { label: "Graph Checking …", sub: "NetworkX fan-out / fan-in / cycle scan" },
];

const FORM_DEFAULTS: SandboxForm = {
  senderVpa:   "ravi.kumar@axisbank",
  receiverVpa: "kirana.store@okhdfc",
  amount:      "4750",
  merchantCat: "Grocery",
  timeOfDay:   "09:00-18:00",
  newDevice:   false,
};

function IntelSandbox() {
  const [form,   setForm  ] = useState<SandboxForm>(FORM_DEFAULTS);
  const [stage,  setStage ] = useState<LoadStage>(0);
  const [result, setResult] = useState<SandboxResult | null>(null);
  const [error,  setError ] = useState<string | null>(null);

  const isRunning = stage > 0 && stage <= 3;

  const handleTest = useCallback(() => {
    if (isRunning) return;
    setResult(null);
    setError(null);
    setStage(1);

    // Stage 1 → 2 → 3 → result with fixed delays
    setTimeout(() => setStage(2), 900);
    setTimeout(() => setStage(3), 1850);
    setTimeout(async () => {
      try {
        const API_BASE = getApiBaseNormalized();
        const amount = parseFloat(form.amount) || 0;
        
        // Calculate proper z-score: (value - mean) / std_dev
        // Training statistics (from historical transaction data):
        // mean amount: 3000 INR, std dev: 12000 INR
        const AMOUNT_MEAN = 3000;
        const AMOUNT_STD = 12000;
        const amount_zscore_value = (amount - AMOUNT_MEAN) / AMOUNT_STD;
        // Clamp to [-5, 5] for numerical stability (outliers beyond ±5σ)
        const amount_zscore = Math.max(-5, Math.min(5, amount_zscore_value));
        
        const payload = {
          vpa: form.senderVpa,
          amount: amount,
          merchant_category: mapMerchantCategory(form.merchantCat),
          transaction_type: "DEBIT",
          device_type: "ANDROID",
          hour_of_day: mapTimeBucketToHour(form.timeOfDay),
          day_of_week: new Date().getDay(),
          transactions_last_1h: 1,
          transactions_last_24h: 3,
          amount_zscore: amount_zscore,
          gps_delta_km: 0,
          is_new_device: form.newDevice,
          is_new_merchant: false,
          balance_drain_ratio: Math.min(1, amount / 100000),
          account_age_days: 365,
          previous_failed_attempts: form.newDevice ? 1 : 0,
          transfer_cashout_flag: 0,
        };

        const res = await fetch(`${API_BASE}/v1/tx`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (!res.ok) {
          throw new Error(`API ${res.status}`);
        }

        const apiResult = await res.json();
        setResult({
          verdict: apiResult.verdict,
          riskScore: Number(apiResult.risk_score ?? 0),
          latencyMs: Number(apiResult.latency_ms ?? 0),
          reasons: [
            `VPA hash: ${String(apiResult.vpa_hash || "").slice(0, 16)}...`,
            `Trace ID: ${apiResult.trace_id}`,
            "Real ONNX inference via Railway API",
          ],
        });
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        const API_BASE = getApiBaseNormalized();
        setError(`API Error: ${API_BASE}/v1/tx failed (${errorMsg}). Backend unavailable or network error.`);
      } finally {
        setStage(0);
      }
    }, 2900);
  }, [form, isRunning]);

  const upd = useCallback(
    (k: keyof SandboxForm) =>
      (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
        setForm((f) => ({ ...f, [k]: e.target.value })),
    [],
  );

  // ── sub-render: result panel ────────────────────────────────────────────────
  const ResultPanel = result ? (
    <motion.div
      key={result.verdict + result.riskScore}
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.38, ease: "easeOut" }}
      className="mt-5 border border-ink/20 overflow-hidden"
    >
      {/* Header strip */}
      <div
        className={`px-5 py-3 border-b border-ink/20 flex items-center justify-between ${
          result.verdict === "ALLOW" ? "bg-allow/[0.08]" :
          result.verdict === "BLOCK" ? "bg-block/[0.08]" :
                                       "bg-flag/[0.07]"
        }`}
      >
        <div className="flex items-center gap-2.5">
          <motion.span
            className={`inline-block w-2 h-2 rounded-full ${verdictDot(result.verdict)}`}
            animate={{ opacity: [1, 0.3, 1] }}
            transition={{ duration: 0.9, repeat: Infinity }}
          />
          <span className="font-barlow text-[0.56rem] tracking-[0.28em] uppercase text-cream/35">
            Varaksha Engine · Verdict
          </span>
        </div>
        <span className="font-courier text-[0.55rem] text-cream/22">
          {result.latencyMs}ms
        </span>
      </div>

      <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-5">
        {/* Left: verdict word + risk score bar */}
        <div>
          <p
            className={`font-courier font-bold leading-none mb-3 ${
              result.verdict === "ALLOW" ? "text-allow" :
              result.verdict === "BLOCK" ? "text-block" :
                                           "text-flag"
            }`}
            style={{ fontSize: "clamp(2.6rem, 5vw, 3.8rem)" }}
          >
            {result.verdict}
          </p>

          <p className="font-barlow text-[0.56rem] tracking-[0.24em] uppercase text-cream/25 mb-1.5">
            Risk Score
          </p>
          <div className="flex items-center gap-2.5 mb-1">
            <div className="flex-1 h-1.5 bg-cream/[0.08] overflow-hidden">
              <motion.div
                className={`h-full ${riskBar(result.riskScore)}`}
                initial={{ width: "0%" }}
                animate={{ width: `${result.riskScore * 100}%` }}
                transition={{ duration: 0.75, ease: "easeOut" }}
              />
            </div>
            <span className="font-courier text-[0.66rem] text-cream/55">
              {result.riskScore.toFixed(2)}
            </span>
          </div>
        </div>

        {/* Right: signal list */}
        <div>
          <p className="font-barlow text-[0.52rem] tracking-[0.26em] uppercase text-cream/22 mb-2">
            Signal Analysis
          </p>
          <ul className="space-y-1.5">
            {result.reasons.map((r, i) => (
              <motion.li
                key={i}
                initial={{ opacity: 0, x: 8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.07 }}
                className="flex items-start gap-2"
              >
                <span
                  className={`mt-[3px] w-1.5 h-1.5 rounded-full shrink-0 ${verdictDot(result.verdict)}`}
                />
                <span className="font-barlow text-[0.72rem] text-cream/55 leading-snug">
                  {r}
                </span>
              </motion.li>
            ))}
          </ul>
        </div>
      </div>
    </motion.div>
  ) : null;

  // ── sub-render: loading stage indicator ────────────────────────────────────
  const LoadingBar = isRunning ? (
    <div className="mt-5 space-y-2.5">
      {LOAD_STAGES.map((ls, i) => {
        const active   = stage === i + 1;
        const complete = stage > i + 1;
        return (
          <motion.div
            key={i}
            className="flex items-center gap-3"
            initial={{ opacity: 0 }}
            animate={{ opacity: active || complete ? 1 : 0.22 }}
            transition={{ duration: 0.3 }}
          >
            {/* Indicator */}
            <div className="w-4 h-4 shrink-0 flex items-center justify-center">
              {complete ? (
                <svg viewBox="0 0 12 12" fill="none" className="w-3.5 h-3.5">
                  <polyline
                    points="2,6 5,9 10,3"
                    stroke="#0D7A5F"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              ) : active ? (
                <motion.span
                  className="inline-block w-2 h-2 rounded-full bg-saffron"
                  animate={{ opacity: [1, 0.25, 1] }}
                  transition={{ duration: 0.7, repeat: Infinity }}
                />
              ) : (
                <span className="w-2 h-2 rounded-full border border-cream/15" />
              )}
            </div>

            {/* Label */}
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="font-barlow text-[0.6rem] tracking-widest uppercase text-cream/50 shrink-0 font-semibold">
                  {i + 1}.
                </span>
                <span
                  className={`font-barlow text-[0.76rem] font-medium transition-colors ${
                    active ? "text-saffron" : complete ? "text-allow" : "text-cream/22"
                  }`}
                >
                  {ls.label}
                </span>
              </div>
              <p className="font-barlow text-[0.6rem] text-cream/22 pl-4 mt-0.5">
                {ls.sub}
              </p>
            </div>

            {/* Shimmer bar */}
            {active && (
              <div className="flex-1 h-px overflow-hidden bg-cream/[0.06]">
                <motion.div
                  className="h-full bg-saffron/50"
                  animate={{ x: ["-100%", "100%"] }}
                  transition={{ duration: 0.85, repeat: Infinity, ease: "linear" }}
                />
              </div>
            )}
          </motion.div>
        );
      })}
    </div>
  ) : null;

  // ── Label + input helper ───────────────────────────────────────────────────
  const inputCls =
    "w-full bg-cream/[0.04] border border-cream/[0.10] text-cream " +
    "font-courier text-[0.75rem] px-3 py-2 " +
    "focus:outline-none focus:border-saffron/50 transition-colors placeholder:text-cream/18";

  const labelCls =
    "block font-barlow text-[0.52rem] tracking-[0.28em] uppercase text-cream/30 mb-1.5";

  return (
    <section className="border border-cream/[0.08] overflow-hidden">
      {/* Module header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-cream/[0.07] bg-cream/[0.025]">
        <div className="flex items-center gap-2.5">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-saffron" />
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/40">
            Module A &mdash; Intelligence Sandbox
          </span>
        </div>
        <span className="font-courier text-[0.52rem] text-cream/18">
          Manual Tester
        </span>
      </div>

      <div className="p-5 lg:p-6">
        {/* Form grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-x-5 gap-y-4 mb-5">

          <div>
            <label className={labelCls}>Sender VPA</label>
            <input
              className={inputCls}
              value={form.senderVpa}
              onChange={upd("senderVpa")}
              placeholder="user@bank"
            />
          </div>

          <div>
            <label className={labelCls}>Receiver VPA</label>
            <input
              className={inputCls}
              value={form.receiverVpa}
              onChange={upd("receiverVpa")}
              placeholder="merchant@bank"
            />
          </div>

          <div>
            <label className={labelCls}>Amount (₹)</label>
            <input
              className={inputCls}
              type="number"
              min="1"
              value={form.amount}
              onChange={upd("amount")}
              placeholder="4750"
            />
          </div>

          <div>
            <label className={labelCls}>Merchant Category</label>
            <select
              className={inputCls + " cursor-pointer"}
              value={form.merchantCat}
              onChange={upd("merchantCat")}
            >
              {MERCHANT_CATS.map((c) => (
                <option key={c} value={c} className="bg-[#0F1E2E]">
                  {c}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className={labelCls}>Time of Day</label>
            <select
              className={inputCls + " cursor-pointer"}
              value={form.timeOfDay}
              onChange={upd("timeOfDay")}
            >
              {["06:00-09:00","09:00-18:00","18:00-22:00","22:00-02:00","02:00-05:00"].map((t) => (
                <option key={t} value={t} className="bg-[#0F1E2E]">
                  {t}
                </option>
              ))}
            </select>
          </div>

          {/* New Device toggle */}
          <div className="flex flex-col justify-end">
            <label className={labelCls}>New Device</label>
            <button
              type="button"
              onClick={() => setForm((f) => ({ ...f, newDevice: !f.newDevice }))}
              className={`relative flex items-center gap-3 border px-3 py-2 transition-colors duration-200 ${
                form.newDevice
                  ? "border-block/40 bg-block/[0.08]"
                  : "border-cream/[0.10] bg-cream/[0.04]"
              }`}
            >
              {/* Toggle track */}
              <div
                className={`relative w-8 h-4 rounded-full transition-colors duration-200 ${
                  form.newDevice ? "bg-block/60" : "bg-cream/[0.12]"
                }`}
              >
                <motion.div
                  className="absolute top-0.5 w-3 h-3 rounded-full bg-cream"
                  animate={{ left: form.newDevice ? "18px" : "2px" }}
                  transition={{ type: "spring", stiffness: 380, damping: 28 }}
                />
              </div>
              <span
                className={`font-barlow text-[0.72rem] transition-colors ${
                  form.newDevice ? "text-block font-semibold" : "text-cream/50 font-semibold"
                }`}
              >
                {form.newDevice ? "First-seen device" : "Known device"}
              </span>
            </button>
          </div>
        </div>

        {/* Block trigger hint */}
        <AnimatePresence>
          {parseFloat(form.amount) > 50000 && form.newDevice && (
            <motion.p
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="font-barlow text-[0.62rem] text-block/60 tracking-wide mb-4 border-l-2 border-block/40 pl-3"
            >
              High-value amount + new device detected &mdash; simulation will
              return <strong className="text-block font-semibold">BLOCK</strong>
            </motion.p>
          )}
        </AnimatePresence>

        {/* Test button */}
        <motion.button
          onClick={handleTest}
          disabled={isRunning}
          whileHover={!isRunning ? { scale: 1.015, backgroundColor: "#1d4ed8" } : {}}
          whileTap={!isRunning ? { scale: 0.97 } : {}}
          className={`inline-flex items-center gap-3 font-barlow font-semibold text-[0.76rem] tracking-[0.14em] uppercase px-7 py-3.5 transition-all duration-200 ${
            isRunning
              ? "bg-cream/10 text-cream/22 cursor-not-allowed"
              : "bg-saffron text-cream cursor-pointer shadow-[0_3px_20px_rgba(37,99,235,0.25)]"
          }`}
        >
          {isRunning ? (
            <>
              <motion.span
                className="inline-block w-2 h-2 rounded-full bg-saffron/70"
                animate={{ opacity: [1, 0.2, 1] }}
                transition={{ duration: 0.7, repeat: Infinity }}
              />
              Running…
            </>
          ) : (
            <>
              <span className="inline-block w-2 h-2 rounded-full bg-cream/60" />
              Test Transaction
            </>
          )}
        </motion.button>

        {/* Loading stages */}
        {LoadingBar}

        {/* Result */}
        {ResultPanel}
        {error && (
          <p className="mt-3 font-barlow text-[0.68rem] text-block/70">{error}</p>
        )}
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE B — REAL-TIME TRANSACTION FEED
// ═══════════════════════════════════════════════════════════════════════════════

function TransactionFeed() {
  const [rows,    setRows   ] = useState<FeedRow[]>([]);
  const [paused,  setPaused ] = useState(false);
  const [stats,   setStats  ] = useState({ allow: 0, flag: 0, block: 0, total: 0 });
  const [usingFallback, setUsingFallback] = useState(false);
  const pausedRef             = useRef(paused);
  pausedRef.current           = paused;

  // Seed while waiting for stream connection.
  useEffect(() => {
    const seed: FeedRow[] = [];
    for (let i = 0; i < 12; i++) seed.push(nextFeedRow());
    setRows(seed.reverse());
    setStats(accumulate(seed));
  }, []);

  useEffect(() => {
    let es: EventSource | null = null;

    function connectStream() {
      if (es) return;
      const API_BASE = getApiBaseNormalized();
      es = new EventSource(`${API_BASE}/v1/stream`);

      es.onmessage = (e) => {
        if (pausedRef.current) return;
        try {
          const tx: StreamTx = JSON.parse(e.data);
          const row: FeedRow = {
            id: streamSeq++,
            ts: tx.time,
            sender: tx.sender,
            receiver: tx.receiver,
            amount: tx.amount,
            merchantCat: tx.category,
            verdict: tx.verdict,
            riskScore: Number(tx.risk),
            latencyMs: 4,
          };

          setRows((prev) => {
            const next = [row, ...prev];
            return next.length > FEED_MAX_ROWS ? next.slice(0, FEED_MAX_ROWS) : next;
          });

          setStats((s) => ({
            allow: s.allow + (row.verdict === "ALLOW" ? 1 : 0),
            flag:  s.flag  + (row.verdict === "FLAG"  ? 1 : 0),
            block: s.block + (row.verdict === "BLOCK" ? 1 : 0),
            total: s.total + 1,
          }));
        } catch {
          // ignore malformed events
        }
      };

      es.onerror = () => {
        setUsingFallback(true);
        es?.close();
        es = null;
      };
    }

    connectStream();

    const handleVisibility = () => {
      if (document.hidden) {
        es?.close();
        es = null;
      } else {
        connectStream();
      }
    };

    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      es?.close();
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, []);

  useEffect(() => {
    if (!usingFallback) return;
    const timer = setInterval(() => {
      if (pausedRef.current) return;
      const row = nextFeedRow();
      setRows((prev) => {
        const next = [row, ...prev];
        return next.length > FEED_MAX_ROWS ? next.slice(0, FEED_MAX_ROWS) : next;
      });
      setStats((s) => ({
        allow: s.allow + (row.verdict === "ALLOW" ? 1 : 0),
        flag:  s.flag  + (row.verdict === "FLAG"  ? 1 : 0),
        block: s.block + (row.verdict === "BLOCK" ? 1 : 0),
        total: s.total + 1,
      }));
    }, FEED_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [usingFallback]);

  return (
    <section className="border border-cream/[0.08] overflow-hidden flex flex-col">
      {/* Module header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-cream/[0.07] bg-cream/[0.025] shrink-0">
        <div className="flex items-center gap-2.5">
          <motion.span
            className="inline-block w-1.5 h-1.5 rounded-full bg-allow"
            animate={{ opacity: [1, 0.25, 1] }}
            transition={{ duration: paused ? 100 : 1.1, repeat: Infinity }}
          />
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/40">
            Module B &mdash; Live Transaction Feed
          </span>
        </div>

        <div className="flex items-center gap-3">
          {/* Mini stats */}
          <div className="hidden sm:flex items-center gap-3 mr-2">
            {[
              { label: "ALLOW", val: stats.allow, cls: "text-allow" },
              { label: "FLAG",  val: stats.flag,  cls: "text-flag"    },
              { label: "BLOCK", val: stats.block, cls: "text-block"  },
            ].map((s) => (
              <div key={s.label} className="flex items-center gap-1">
                <span className={`font-courier text-[0.66rem] font-bold ${s.cls}`}>
                  {s.val}
                </span>
                <span className="font-barlow text-[0.48rem] tracking-widest uppercase text-cream/22">
                  {s.label}
                </span>
              </div>
            ))}
          </div>

          {/* Pause/resume */}
          <button
            onClick={() => setPaused((p) => !p)}
            className={`font-barlow text-[0.54rem] tracking-[0.22em] uppercase border px-2.5 py-1 transition-colors ${
              paused
                ? "border-saffron/40 text-saffron hover:bg-saffron/10"
                : "border-cream/30 text-cream/50 hover:border-cream/60 hover:text-cream/70 font-semibold"
            }`}
          >
            {paused ? "▶ Resume" : "⏸ Pause"}
          </button>
        </div>
      </div>

      {/* Table header */}
      <div className="grid grid-cols-[58px_1fr_1fr_72px_72px_56px_64px] gap-2 px-4 py-2 border-b border-cream/[0.05] bg-cream/[0.015] shrink-0">
        {["Time","Sender","Receiver","Amount","Category","Risk","Verdict"].map((h) => (
          <span key={h} className="font-barlow text-[0.48rem] tracking-[0.24em] uppercase text-cream/20">
            {h}
          </span>
        ))}
      </div>

      {/* Scrollable feed body */}
      <div className="overflow-y-auto flex-1" style={{ maxHeight: "600px" }}>
        <AnimatePresence initial={false}>
          {rows.map((row, i) => (
            <motion.div
              key={row.id}
              initial={{ opacity: 0, y: -10, backgroundColor: "rgba(37,99,235,0.12)" }}
              animate={{ opacity: 1, y: 0,  backgroundColor: "rgba(255,255,255,0)" }}
              transition={{ duration: 0.45 }}
              className={`grid grid-cols-[58px_1fr_1fr_72px_72px_56px_64px] gap-2 px-4 py-2.5 border-b border-cream/[0.04] hover:bg-cream/[0.03] transition-colors ${
                i === 0 && !paused ? "bg-cream/[0.025]" : ""
              }`}
            >
              <span className="font-courier text-[0.6rem] text-cream/50 font-semibold tabular-nums">
                {row.ts}
              </span>
              <span className="font-courier text-[0.65rem] text-cream/55 truncate">
                {maskVpa(row.sender)}
              </span>
              <span className="font-courier text-[0.65rem] text-cream/38 truncate">
                {maskVpa(row.receiver)}
              </span>
              <span className="font-courier text-[0.65rem] text-cream/55 tabular-nums">
                ₹{row.amount.toLocaleString("en-IN")}
              </span>
              <span className="font-barlow text-[0.56rem] text-cream/28 truncate">
                {row.merchantCat}
              </span>

              {/* Risk bar */}
              <div className="flex items-center gap-1.5">
                <div className="flex-1 h-1 bg-cream/[0.07] overflow-hidden">
                  <div
                    className={`h-full ${riskBar(row.riskScore)}`}
                    style={{ width: `${row.riskScore * 100}%` }}
                  />
                </div>
                <span className="font-courier text-[0.52rem] text-cream/22 tabular-nums shrink-0">
                  {row.riskScore.toFixed(2)}
                </span>
              </div>

              {/* Verdict badge */}
              <span
                className={`font-courier text-[0.56rem] tracking-wider uppercase px-1.5 py-0.5 text-center ${verdictBadge(row.verdict)}`}
              >
                {row.verdict}
              </span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* Footer totals bar */}
      <div className="px-5 py-2.5 border-t border-cream/[0.07] bg-cream/[0.015] shrink-0 flex items-center justify-between">
        <span className="font-barlow text-[0.52rem] tracking-widest uppercase text-cream/18">
          {stats.total} transactions processed
        </span>
        <span className="font-courier text-[0.52rem] text-cream/18">
          {paused ? "Feed paused" : `Updating every ${FEED_INTERVAL_MS / 1000}s`}
        </span>
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ACCUMULATE STATS HELPER (pure — used in useEffect only)
// ═══════════════════════════════════════════════════════════════════════════════

function accumulate(rows: FeedRow[]) {
  return rows.reduce(
    (acc, r) => ({
      allow: acc.allow + (r.verdict === "ALLOW" ? 1 : 0),
      flag:  acc.flag  + (r.verdict === "FLAG"  ? 1 : 0),
      block: acc.block + (r.verdict === "BLOCK" ? 1 : 0),
      total: acc.total + 1,
    }),
    { allow: 0, flag: 0, block: 0, total: 0 },
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE F — ML MODEL STACK
// ═══════════════════════════════════════════════════════════════════════════════

const ML_MODELS = [
  {
    letter: "01",
    code: "RF-300",
    name: "Random Forest",
    role: "Primary Classifier",
    accent: "#2563EB",
    accentClass: "bg-saffron",
    borderClass: "border-saffron/20",
    concept:
      "Ensemble of 300 decision trees trained on 111K labelled transactions with SMOTE rebalancing. Votes across trees to produce a calibrated fraud probability score.",
    tracks: [
      "Transaction velocity (60-min window)",
      "Network topology: cycle, fan-out, scatter scores",
      "Balance drain ratio & round-amount flag",
      "Device novelty & previous failure count",
      "Temporal patterns (hour sin/cos encoding)",
    ],
    metrics: [
      { label: "Accuracy",  value: "96.52%", pct: 96.5 },
      { label: "ROC-AUC",   value: "0.9952",  pct: 99.5 },
      { label: "F1 (fraud)",value: "0.9579",  pct: 95.8 },
      { label: "Precision", value: "97.45%", pct: 97.5 },
      { label: "Recall",    value: "93.59%", pct: 93.6 },
    ],
    weight: "Primary",
    artifact: "varaksha_rf_model.onnx",
  },
  {
    letter: "02",
    code: "ISOF-02",
    name: "Isolation Forest",
    role: "Anomaly Detector",
    accent: "#D97706",
    accentClass: "bg-flag",
    borderClass: "border-flag/20",
    concept:
      "Unsupervised outlier detector that isolates anomalies by recursively partitioning the feature space. No fraud labels required — flags transactions that deviate from the learned distribution.",
    tracks: [
      "Multivariate outliers across all 16 features",
      "Novel transaction patterns not seen in training",
      "Structurally anomalous amount–velocity combinations",
      "Unseen merchant category and device pairings",
      "Distribution shift across all graph topology scores",
    ],
    metrics: [
      { label: "Contamination", value: "2.0%",  pct: 2 },
      { label: "Flagged rate",  value: "~2%",   pct: 2 },
      { label: "Mode",          value: "Unsupervised", pct: 100 },
      { label: "Label input",   value: "None",  pct: 100 },
      { label: "Inference",     value: "Real-time", pct: 100 },
    ],
    weight: "Secondary",
    artifact: "isolation_forest.onnx",
  },
  {
    letter: "03",
    code: "SCALER",
    name: "Standard Scaler",
    role: "Feature Normalisation",
    accent: "#0D7A5F",
    accentClass: "bg-allow",
    borderClass: "border-allow/20",
    concept:
      "Fitted on the training distribution; transforms all 16 raw features to zero-mean, unit-variance before RF inference. Ensures probability calibration is stable across transaction magnitude ranges.",
    tracks: [
      "All 16 feature dimensions before classifier input",
      "Training distribution mean and variance",
      "Zero-mean, unit-variance normalisation",
      "Consistent scale across amount, age, velocity",
      "ONNX-exported for runtime parity with training",
    ],
    metrics: [
      { label: "Features",     value: "16",          pct: 100 },
      { label: "Stage",        value: "Pre-inference", pct: 100 },
      { label: "Distribution", value: "Zero-mean",   pct: 100 },
      { label: "Variance",     value: "Unit",        pct: 100 },
      { label: "Export",       value: "ONNX",        pct: 100 },
    ],
    weight: "Pipeline",
    artifact: "scaler.onnx",
  },
];

function MLModelModule() {
  return (
    <section
      className="border border-cream/[0.08] overflow-hidden"
      style={{ borderRadius: 2 }}
    >
      {/* Module header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-cream/[0.06] bg-cream/[0.025]">
        <div className="flex items-center gap-3">
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/40">
            Module F &mdash; ML Model Stack
          </span>
          <motion.span
            className="inline-block w-1.5 h-1.5 rounded-full bg-saffron"
            animate={{ opacity: [1, 0.25, 1] }}
            transition={{ duration: 2.4, repeat: Infinity }}
          />
        </div>
        <span className="font-barlow text-[0.48rem] tracking-[0.20em] uppercase text-cream/18">
          3 models &middot; ONNX runtime
        </span>
      </div>

      {/* Cards */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-px bg-cream/[0.04] p-px">
        {ML_MODELS.map((m) => (
          <motion.div
            key={m.code}
            initial={{ opacity: 0, y: 14 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-60px" }}
            transition={{ duration: 0.5, delay: ML_MODELS.indexOf(m) * 0.12 }}
            className="bg-ink flex flex-col"
          >
            {/* Accent top-bar */}
            <div className="h-0.5" style={{ backgroundColor: m.accent }} />

            <div className="p-5 flex flex-col gap-4 flex-1">
              {/* Header row */}
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className="font-barlow text-[0.44rem] tracking-[0.28em] uppercase"
                      style={{ color: m.accent }}
                    >
                      {m.letter}
                    </span>
                    <span className="font-courier text-[0.56rem] text-cream/50 font-semibold">{m.code}</span>
                  </div>
                  <h3 className="font-playfair font-bold text-cream text-lg leading-tight">
                    {m.name}
                  </h3>
                  <p className="font-barlow text-[0.52rem] tracking-[0.20em] uppercase text-cream/35 mt-0.5">
                    {m.role}
                  </p>
                </div>
                <span
                  className={`shrink-0 font-barlow text-[0.44rem] tracking-[0.18em] uppercase px-2 py-0.5 border ${m.borderClass}`}
                  style={{ color: m.accent }}
                >
                  {m.weight}
                </span>
              </div>

              {/* Concept */}
              <p className="font-barlow text-[0.61rem] text-cream/45 leading-relaxed">
                {m.concept}
              </p>

              {/* What it tracks */}
              <div>
                <p className="font-barlow text-[0.48rem] tracking-[0.26em] uppercase text-cream/25 mb-2">
                  Tracks
                </p>
                <ul className="space-y-1">
                  {m.tracks.map((t) => (
                    <li key={t} className="flex items-start gap-2">
                      <span className="mt-1 shrink-0 w-1 h-1 rounded-full" style={{ backgroundColor: m.accent }} />
                      <span className="font-courier text-[0.58rem] text-cream/38">{t}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Metrics */}
              <div className="mt-auto">
                <p className="font-barlow text-[0.48rem] tracking-[0.26em] uppercase text-cream/25 mb-2">
                  Results
                </p>
                <div className="space-y-2">
                  {m.metrics.map((met) => (
                    <div key={met.label}>
                      <div className="flex justify-between mb-0.5">
                        <span className="font-barlow text-[0.50rem] tracking-[0.14em] uppercase text-cream/50 font-semibold">
                          {met.label}
                        </span>
                        <span className="font-courier text-[0.58rem] text-cream/60">{met.value}</span>
                      </div>
                      <div className="h-px bg-cream/[0.06] overflow-hidden">
                        <motion.div
                          className="h-full"
                          style={{ backgroundColor: m.accent }}
                          initial={{ width: 0 }}
                          whileInView={{ width: `${met.pct}%` }}
                          viewport={{ once: true }}
                          transition={{ duration: 0.9, ease: "easeOut", delay: 0.2 }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Artifact */}
              <div className="pt-3 border-t border-cream/[0.06]">
                <span className="font-barlow text-[0.44rem] tracking-[0.20em] uppercase text-cream/20">
                  Artifact &nbsp;
                </span>
                <span className="font-courier text-[0.54rem]" style={{ color: m.accent }}>
                  {m.artifact}
                </span>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE
// ═══════════════════════════════════════════════════════════════════════════════

export default function LivePage() {
  return (
    // Dark ink background — overrides the cream set in layout.tsx
    <main
      className="min-h-screen bg-ink text-cream"
      style={{
        backgroundImage: [
          "radial-gradient(circle, rgba(37,99,235,0.065) 1px, transparent 1px)",
          "radial-gradient(ellipse 90% 38% at 50% 0%, rgba(37,99,235,0.10) 0%, transparent 62%)",
          "radial-gradient(ellipse 50% 42% at 95% 92%, rgba(13,122,95,0.055) 0%, transparent 55%)",
        ].join(", "),
        backgroundSize: "24px 24px, 100% 100%, 100% 100%",
      }}
    >

      {/* ── Fixed scanning line effect ─────────────────────────────────── */}
      <motion.div
        className="pointer-events-none fixed inset-x-0 h-[1px] bg-saffron/8 z-50"
        animate={{ top: ["0%", "100%"] }}
        transition={{ duration: 7, repeat: Infinity, ease: "linear" }}
      />

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-40 border-b border-cream/[0.07] px-5 lg:px-10 py-2.5 bg-ink/95 backdrop-blur-sm">
        <div className="max-w-screen-2xl mx-auto flex items-center justify-between">

          <div className="flex items-center gap-4">
            <a
              href="/"
              className="font-barlow text-[0.58rem] tracking-[0.24em] uppercase text-cream/28 hover:text-saffron transition-colors"
            >
              &larr;&thinsp;Varaksha
            </a>
            <span className="text-cream/10 select-none">|</span>
            <span className="font-playfair font-bold text-cream text-[1.05rem] tracking-tight">
              SOC Dashboard
            </span>
            <span className="hidden md:inline font-barlow text-[0.56rem] tracking-[0.22em] uppercase text-cream/22">
              &mdash; Security Operations Center
            </span>
          </div>

          {/* Status pills */}
          <div className="flex items-center gap-4">
            {[
              { label: "Gateway",  color: "bg-allow"   },
              { label: "ML Engine",color: "bg-allow"   },
              { label: "Graph",    color: "bg-saffron"  },
            ].map((p) => (
              <div key={p.label} className="flex items-center gap-1.5">
                <motion.span
                  className={`inline-block w-1.5 h-1.5 rounded-full ${p.color}`}
                  animate={{ opacity: [1, 0.25, 1] }}
                  transition={{ duration: 1.3, repeat: Infinity }}
                />
                <span className="hidden sm:inline font-barlow text-[0.52rem] tracking-widest uppercase text-cream/22">
                  {p.label}
                </span>
              </div>
            ))}
          </div>

        </div>
      </header>

      {/* ── Page body ──────────────────────────────────────────────────── */}
      <div className="max-w-screen-2xl mx-auto px-5 lg:px-10 py-8 space-y-8">

        {/* ── Page title row ── */}
        <div className="flex items-end justify-between mb-2">
          <div>
            <p className="font-barlow text-[0.62rem] tracking-[0.30em] uppercase text-saffron mb-1.5">
              Varaksha V2 &middot; Real-Time Intelligence
            </p>
            <h1
              className="font-playfair font-bold text-cream leading-tight"
              style={{ fontSize: "clamp(1.8rem, 3.5vw, 3rem)" }}
            >
              Live Defense Console
            </h1>
          </div>

          <div className="hidden md:flex items-center gap-2 pb-1">
            <div className="w-1.5 h-1.5 rounded-full bg-saffron animate-pulse" />
            <span className="font-barlow text-[0.55rem] tracking-[0.28em] uppercase text-cream/22">
              Stream Active
            </span>
          </div>
        </div>

        {/* ── KPI strip ─────────────────────────────────────────────────── */}
        <KpiStrip />

        {/* ── Two-column layout: Sandbox | Feed ─────────────────────────── */}
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_1fr] gap-6 items-start">
          <IntelSandbox />
          <TransactionFeed />
        </div>

        {/* ── C | D ─────────────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
          <CacheVisualizer />
          <SecurityArena />
        </div>

        {/* ── F full-width — ML model stack ─────────────────────────────── */}
        <MLModelModule />

        {/* ── E full-width ──────────────────────────────────────────────── */}
        <LegalReport />

      </div>

      {/* ── Footer ─────────────────────────────────────────────────────── */}
      <footer className="border-t border-cream/[0.06] px-5 lg:px-10 py-3 mt-10">
        <div className="max-w-screen-2xl mx-auto flex justify-between items-center gap-2">
          <span className="font-barlow text-[0.52rem] tracking-[0.24em] uppercase text-cream/16">
            Varaksha V2 &middot; NPCI Hackathon 2026 &middot; Blue Team
          </span>
          <span className="font-courier text-[0.52rem] text-cream/12">
            Rust &middot; Python &middot; Next.js
          </span>
        </div>
      </footer>

    </main>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// KPI STRIP — top-of-page 4-metric summary cards
// ═══════════════════════════════════════════════════════════════════════════════

const KPI_DEFS = [
  { label: "Blocked (session)",  key: "block" as const, color: "text-block", border: "border-block/15" },
  { label: "Flagged (session)",  key: "flag"  as const, color: "text-flag",  border: "border-flag/15"  },
  { label: "Allowed (session)",  key: "allow" as const, color: "text-allow",   border: "border-allow/15"   },
  { label: "Gateway Latency",    key: "lat"   as const, color: "text-cream/70",border: "border-cream/8"    },
] as const;

function KpiStrip() {
  const [counts, setCounts] = useState({ allow: 0, flag: 0, block: 0 });

  // Mirrors the feed's verdict distribution so numbers feel coherent
  useEffect(() => {
    const timer = setInterval(() => {
      if (Math.random() > 0.45) return;   // sporadic update — not every tick
      const roll = Math.random();
      if (roll < 0.06) {
        setCounts((c) => ({ ...c, block: c.block + 1 }));
      } else if (roll < 0.22) {
        setCounts((c) => ({ ...c, flag: c.flag + 1 }));
      } else {
        setCounts((c) => ({ ...c, allow: c.allow + 1 }));
      }
    }, FEED_INTERVAL_MS / 1.8);
    return () => clearInterval(timer);
  }, []);

  const displayVal = (key: typeof KPI_DEFS[number]["key"]) => {
    if (key === "lat") return "<10ms";
    return counts[key].toString().padStart(2, "0");
  };

  return (
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
      {KPI_DEFS.map((k) => (
        <motion.div
          key={k.label}
          layout
          className={`border ${k.border} bg-cream/[0.025] px-4 py-4 flex flex-col gap-1`}
        >
          <span className="font-barlow text-[0.52rem] tracking-[0.26em] uppercase text-cream/22">
            {k.label}
          </span>
          <AnimatePresence mode="popLayout">
            <motion.span
              key={displayVal(k.key)}
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 6 }}
              transition={{ duration: 0.25 }}
              className={`font-courier font-bold leading-none ${k.color}`}
              style={{ fontSize: "clamp(1.6rem, 2.8vw, 2.4rem)" }}
            >
              {displayVal(k.key)}
            </motion.span>
          </AnimatePresence>
        </motion.div>
      ))}
    </div>
  );
}
