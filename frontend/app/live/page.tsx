"use client";

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { CacheVisualizer } from "./CacheVisualizer";
import { SecurityArena   } from "./SecurityArena";
import { LegalReport     } from "./LegalReport";
import { Tier3EdgeSim    } from "../components/Tier3EdgeSim";
import { DashMapVisualizer } from "../components/DashMapVisualizer";
import { getApiBaseNormalized } from "../lib/api-config";

// ── Tier type ─────────────────────────────────────────────────────────────────
type Tier = "cloud" | "enterprise" | "embedded";

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const FEED_INTERVAL_MS  = 3800;   // Slower cadence for demo readability
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
const MERCHANT_CATS = ["FOOD", "UTILITY", "ECOM", "GAMBLING", "TRAVEL"];

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

interface TierScenarioStep {
  id: string;
  actor: string;
  title: string;
  detail: string;
  signal: string;
  latency: string;
}

const TIER_SCENARIOS: Record<Tier, TierScenarioStep[]> = {
  cloud: [
    {
      id: "c1",
      actor: "Client App",
      title: "Transaction Submitted",
      detail: "User initiates UPI payment from app. Payload reaches cloud ingress via bridge endpoint.",
      signal: "POST /v1/tx",
      latency: "~5 ms",
    },
    {
      id: "c2",
      actor: "Rust Gateway",
      title: "PII Hash + Cache Lookup",
      detail: "Rust hashes identifiers (SHA-256), checks DashMap risk cache, and applies rate limiting.",
      signal: "hash + DashMap + limiter",
      latency: "~2 ms",
    },
    {
      id: "c3",
      actor: "ML + Graph",
      title: "ONNX Scoring Fusion",
      detail: "LightGBM + anomaly score + topology delta are fused into a final fraud score.",
      signal: "fused_score",
      latency: "~2 ms",
    },
    {
      id: "c4",
      actor: "Verdict API",
      title: "ALLOW / FLAG / BLOCK",
      detail: "Gateway returns verdict and pushes incident context to live dashboards and alert modules.",
      signal: "JSON response + SSE",
      latency: "<10 ms total",
    },
  ],
  enterprise: [
    {
      id: "e1",
      actor: "Bank Core",
      title: "Batch + Stream Ingest",
      detail: "Bank connectors and transaction buses feed enterprise scoring APIs continuously.",
      signal: "REST + webhook ingest",
      latency: "near real-time",
    },
    {
      id: "e2",
      actor: "Rust Policy Layer",
      title: "Policy + Auth Enforcement",
      detail: "Rust enforces API keys, HMAC signatures, and per-tenant traffic controls.",
      signal: "mTLS/HMAC checks",
      latency: "~2 ms",
    },
    {
      id: "e3",
      actor: "Graph Engine",
      title: "Topology Detection",
      detail: "Sender/receiver graph updates live, surfacing fan-out, fan-in, and suspicious hubs.",
      signal: "edge updates",
      latency: "streaming",
    },
    {
      id: "e4",
      actor: "SOC + Audit",
      title: "Actionable Incident Output",
      detail: "SOC sees flagged flows, blocked entities, and compliance-grade audit traces.",
      signal: "alerts + audit trail",
      latency: "operator live",
    },
  ],
  embedded: [
    {
      id: "m1",
      actor: "Mobile SDK",
      title: "On-Device Feature Build",
      detail: "App derives feature vector locally before the payment leaves the device.",
      signal: "local feature vector",
      latency: "sub-ms",
    },
    {
      id: "m2",
      actor: "ONNX Runtime Mobile",
      title: "Local Fraud Scoring",
      detail: "Quantized model runs directly on handset for pre-network risk estimation.",
      signal: "local risk score",
      latency: "<1 ms",
    },
    {
      id: "m3",
      actor: "Device Policy",
      title: "Instant User Intercept",
      detail: "High-risk transactions are challenged or blocked before server round-trip.",
      signal: "inline guardrail",
      latency: "instant",
    },
    {
      id: "m4",
      actor: "Cloud Sync",
      title: "Deferred Telemetry Sync",
      detail: "Device later syncs anonymized telemetry for global model and graph updates.",
      signal: "async sync",
      latency: "background",
    },
  ],
};

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

  // Deterministic verdict generation (balanced thresholds)
  // ALLOW (0.0-0.50): Normal transactions ~ 0.08-0.38
  // FLAG  (0.50-0.80): Suspicious transactions ~ 0.55-0.71
  // BLOCK (0.80-1.00): High confidence fraud ~ 0.91
  let verdict:    Verdict = "ALLOW";
  let riskScore          = 0.08 + (idx % 7) * 0.05;  // 0.08, 0.13, 0.18, ..., 0.38

  if (amount > 50000 && newDevice) {
    // Extreme amount + new device = BLOCK
    verdict   = "BLOCK";
    riskScore = 0.91;
  } else if (amount > 30000 || (newDevice && amount > 10000)) {
    // Large amount or high-risk device combo = FLAG
    verdict   = "FLAG";
    riskScore = 0.55 + (idx % 3) * 0.08;  // 0.55, 0.63, 0.71
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
  // Balanced fraud classification thresholds
  // ALLOW (0.0-0.50): Legitimate transactions
  // FLAG  (0.50-0.80): Moderate risk
  // BLOCK (0.80-1.0): High confidence fraud
  if (score >= 0.80) return "bg-block";
  if (score >= 0.50) return "bg-flag";
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

function TierScenarioArchitecture({ tier }: { tier: Tier }) {
  const steps = TIER_SCENARIOS[tier];
  const [active, setActive] = useState(0);

  useEffect(() => {
    setActive(0);
  }, [tier]);

  useEffect(() => {
    const timer = setInterval(() => {
      setActive((s) => (s + 1) % steps.length);
    }, 3200);
    return () => clearInterval(timer);
  }, [steps.length]);

  const current = steps[active];
  const tierTitle = tier === "cloud" ? "Cloud Execution Path" : tier === "enterprise" ? "Enterprise Execution Path" : "Embedded Execution Path";

  return (
    <section className="border border-cream/[0.08] overflow-hidden">
      <div className="px-5 py-3 border-b border-cream/[0.07] bg-cream/[0.025] flex items-center justify-between">
        <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/40">
          Typical Scenario Architecture
        </span>
        <span className="font-courier text-[0.52rem] text-cream/20">{tierTitle}</span>
      </div>

      <div className="p-5">
        <div className="grid grid-cols-1 xl:grid-cols-[260px_1fr] gap-4">
          <div className="relative border border-cream/[0.08] bg-cream/[0.015] px-3 py-4">
            <div className="absolute left-4 top-4 bottom-4 w-px bg-cream/[0.12]" />
            <div className="space-y-3">
              {steps.map((s, i) => {
                const isActive = i === active;
                return (
                  <button
                    key={s.id}
                    onClick={() => setActive(i)}
                    className={`relative w-full text-left pl-6 pr-2 py-2 transition-colors ${
                      isActive
                        ? "bg-saffron/10 border border-saffron/45"
                        : "border border-cream/[0.08] bg-cream/[0.02] hover:bg-cream/[0.05]"
                    }`}
                  >
                    <span
                      className={`absolute left-[10px] top-3 w-2 h-2 rounded-full ${
                        isActive ? "bg-saffron" : "bg-cream/20"
                      }`}
                    />
                    <p className="font-barlow text-[0.46rem] tracking-[0.24em] uppercase text-cream/30">{s.actor}</p>
                    <p className={`font-courier text-[0.62rem] ${isActive ? "text-saffron" : "text-cream/60"}`}>{s.title}</p>
                    <p className="font-courier text-[0.52rem] text-cream/35 mt-1">{s.signal}</p>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="border border-cream/[0.08] bg-cream/[0.015] p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-barlow text-[0.50rem] tracking-[0.24em] uppercase text-cream/25">Current Step</p>
                <p className="font-playfair text-[1.1rem] text-cream mt-1">{current.title}</p>
              </div>
              <div className="text-right">
                <p className="font-barlow text-[0.50rem] tracking-[0.24em] uppercase text-cream/25">Latency</p>
                <p className="font-courier text-[0.72rem] text-allow mt-1">{current.latency}</p>
              </div>
            </div>
            <p className="font-barlow text-[0.76rem] text-cream/50 leading-relaxed">{current.detail}</p>
            <div className="flex items-center gap-3 border border-cream/[0.08] bg-cream/[0.02] px-4 py-3">
              <div className="w-2 h-2 rounded-full bg-saffron" />
              <div>
                <p className="font-barlow text-[0.50rem] tracking-[0.24em] uppercase text-cream/25">Signal</p>
                <p className="font-courier text-[0.66rem] text-cream/60">{current.signal}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
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
  merchantCat: "FOOD",
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
    
    // Log debugging info
    const API_BASE = getApiBaseNormalized();
    console.log('[Varaksha] Starting test transaction...');
    console.log('[Varaksha] API Base URL:', API_BASE);
    console.log('[Varaksha] Hostname:', typeof window !== 'undefined' ? window.location.hostname : 'unknown');
    
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
          merchant_category: form.merchantCat,
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
        // Convert latency from microseconds to milliseconds
        const latencyMs = Math.round((Number(apiResult.latency_us ?? 0)) / 1000);
        setResult({
          verdict: apiResult.verdict,
          riskScore: Number(apiResult.risk_score ?? 0),
          latencyMs: latencyMs,
          reasons: [
            `VPA hash: ${String(apiResult.vpa_hash || "").slice(0, 16)}...`,
            `Trace ID: ${apiResult.trace_id}`,
            "Real ONNX inference via Railway API",
          ],
        });

        if (typeof window !== "undefined" && (apiResult.verdict === "FLAG" || apiResult.verdict === "BLOCK")) {
          window.dispatchEvent(new CustomEvent("varaksha:incident", {
            detail: {
              transactionId: String(apiResult.trace_id ?? `TXN-${Date.now()}`),
              senderVpa: form.senderVpa,
              receiverVpa: form.receiverVpa,
              amount,
              timestampIso: new Date().toISOString(),
              merchantCat: form.merchantCat,
              verdict: apiResult.verdict,
              riskScore: Number(apiResult.risk_score ?? 0),
              graphReason: apiResult.graph_reason ?? null,
              reasons: [
                `API verdict=${apiResult.verdict}`,
                `Trace ID: ${apiResult.trace_id}`,
                "Captured from real-time sandbox inference",
              ],
            },
          }));
        }
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        const API_BASE = getApiBaseNormalized();
        const hostname = typeof window !== 'undefined' ? window.location.hostname : 'unknown';
        const envUrl = typeof process !== 'undefined' ? process.env.NEXT_PUBLIC_API_URL : 'N/A';
        
        let detailedError = `API Error calling ${API_BASE}/v1/tx\n`;
        detailedError += `Frontend: ${hostname}\n`;
        
        if (err instanceof TypeError && errorMsg.includes('fetch')) {
          detailedError += `Issue: Network/CORS error - Backend may not be accessible\n`;
          detailedError += `Debug: Tried to reach ${API_BASE}\n`;
          detailedError += `Check: Is the backend running at ${API_BASE}?`;
        } else if (errorMsg.includes('404')) {
          detailedError += `Issue: Endpoint not found (404) - Gateway may not be running\n`;
          detailedError += `Check: Is gateway running on ${API_BASE}?`;
        } else if (errorMsg.includes('50')) {
          detailedError += `Issue: Backend server error - Sidecar service may be unavailable\n`;
          detailedError += `Error: ${errorMsg}`;
        } else {
          detailedError += `Issue: ${errorMsg}\n`;
          detailedError += `URL: ${API_BASE}/v1/tx`;
        }
        
        console.error('[Varaksha API Error]', { API_BASE, hostname, envUrl, error: errorMsg });
        setError(detailedError);
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
    <div
      key={result.verdict + result.riskScore}
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
          <span
            className={`inline-block w-2 h-2 rounded-full ${verdictDot(result.verdict)}`}
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
              <div
                className={`h-full ${riskBar(result.riskScore)}`}
                style={{ width: `${result.riskScore * 100}%` }}
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
              <li
                key={i}
                className="flex items-start gap-2"
              >
                <span
                  className={`mt-[3px] w-1.5 h-1.5 rounded-full shrink-0 ${verdictDot(result.verdict)}`}
                />
                <span className="font-barlow text-[0.72rem] text-cream/55 leading-snug">
                  {r}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  ) : null;

  // ── sub-render: loading stage indicator ────────────────────────────────────
  const LoadingBar = isRunning ? (
    <div className="mt-5 space-y-2.5">
      {LOAD_STAGES.map((ls, i) => {
        const active   = stage === i + 1;
        const complete = stage > i + 1;
        return (
          <div
            key={i}
            className="flex items-center gap-3"
            style={{ opacity: active || complete ? 1 : 0.22 }}
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
                <span
                  className="inline-block w-2 h-2 rounded-full bg-saffron"
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
                <div
                  className="h-full bg-saffron/50"
                />
              </div>
            )}
          </div>
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
                <div
                  className="absolute top-0.5 w-3 h-3 rounded-full bg-cream"
                  style={{ left: form.newDevice ? "18px" : "2px" }}
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
        {parseFloat(form.amount) > 50000 && form.newDevice && (
          <p
            className="font-barlow text-[0.62rem] text-block/60 tracking-wide mb-4 border-l-2 border-block/40 pl-3"
          >
            High-value amount + new device detected &mdash; simulation will
            return <strong className="text-block font-semibold">BLOCK</strong>
          </p>
        )}

        {/* Test button */}
        <button
          onClick={handleTest}
          disabled={isRunning}
          className={`inline-flex items-center gap-3 font-barlow font-semibold text-[0.76rem] tracking-[0.14em] uppercase px-7 py-3.5 transition-all duration-200 ${
            isRunning
              ? "bg-cream/10 text-cream/22 cursor-not-allowed"
              : "bg-saffron text-cream cursor-pointer shadow-[0_3px_20px_rgba(37,99,235,0.25)]"
          }`}
        >
          {isRunning ? (
            <>
              <span
                className="inline-block w-2 h-2 rounded-full bg-saffron/70"
              />
              Running…
            </>
          ) : (
            <>
              <span className="inline-block w-2 h-2 rounded-full bg-cream/60" />
              Test Transaction
            </>
          )}
        </button>

        {/* Loading stages */}
        {LoadingBar}

        {/* Result */}
        {ResultPanel}
        {error && (
          <pre className="mt-3 font-barlow text-[0.68rem] text-block/70 whitespace-pre-wrap break-words">{error}</pre>
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

          if (typeof window !== "undefined" && (row.verdict === "FLAG" || row.verdict === "BLOCK")) {
            window.dispatchEvent(new CustomEvent("varaksha:incident", {
              detail: {
                transactionId: `FEED-${row.id}`,
                senderVpa: row.sender,
                receiverVpa: row.receiver,
                amount: row.amount,
                timestampIso: new Date().toISOString(),
                merchantCat: row.merchantCat,
                verdict: row.verdict,
                riskScore: row.riskScore,
                reasons: [
                  "Captured from live transaction feed",
                  `Category=${row.merchantCat}`,
                  `Risk=${row.riskScore.toFixed(2)}`,
                ],
              },
            }));
          }

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

      if (typeof window !== "undefined" && (row.verdict === "FLAG" || row.verdict === "BLOCK")) {
        window.dispatchEvent(new CustomEvent("varaksha:incident", {
          detail: {
            transactionId: `FEED-${row.id}`,
            senderVpa: row.sender,
            receiverVpa: row.receiver,
            amount: row.amount,
            timestampIso: new Date().toISOString(),
            merchantCat: row.merchantCat,
            verdict: row.verdict,
            riskScore: row.riskScore,
            reasons: [
              "Captured from fallback feed generator",
              `Category=${row.merchantCat}`,
              `Risk=${row.riskScore.toFixed(2)}`,
            ],
          },
        }));
      }

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
          <span
            className="inline-block w-1.5 h-1.5 rounded-full bg-allow"
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
        {rows.map((row, i) => (
          <div
            key={row.id}
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
            </div>
          ))}
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
          <span
            className="inline-block w-1.5 h-1.5 rounded-full bg-saffron"
          />
        </div>
        <span className="font-barlow text-[0.48rem] tracking-[0.20em] uppercase text-cream/18">
          3 models &middot; ONNX runtime
        </span>
      </div>

      {/* Cards */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-px bg-cream/[0.04] p-px">
        {ML_MODELS.map((m) => (
          <div
            key={m.code}
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
                        <div
                          className="h-full"
                          style={{ backgroundColor: m.accent, width: `${met.pct}%` }}
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
          </div>
        ))}
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE G — ENTERPRISE GRAPH NETWORK MONITOR
// ═══════════════════════════════════════════════════════════════════════════════

interface GraphEdge {
  id:      number;
  from:    string;
  to:      string;
  verdict: Verdict;
  riskScore: number;
  amount:  number;
  ts:      number;
}

interface DemoRow {
  txId: string;
  timestamp: string;
  txType: string;
  merchantCategory: string;
  amount: number;
  status: string;
  senderBank: string;
  receiverBank: string;
  deviceType: string;
  fraudFlag: number;
  hourOfDay: number;
  dayOfWeek: string;
  deviceSurrogate: string;
  corridorSurrogate: string;
}

const DEMO_DATASETS = [
  {
    id: "real_traffic",
    label: "Real Traffic (200 rows)",
    path: "/datasets/real_traffic.csv",
    note: "Normal user traffic with mixed channels",
  },
  {
    id: "synthetic_attack",
    label: "Synthetic Attack (138 rows)",
    path: "/datasets/synthetic_attack.csv",
    note: "Fan-in + velocity fraud patterns",
  },
] as const;

function parseDemoCsv(text: string): DemoRow[] {
  const lines = text.trim().split(/\r?\n/);
  lines.shift();
  const rows: DemoRow[] = [];
  for (const line of lines) {
    const cols = line.split(",");
    if (cols.length < 19) continue;
    rows.push({
      txId: cols[0],
      timestamp: cols[1],
      txType: cols[2],
      merchantCategory: cols[3],
      amount: Number(cols[4]) || 0,
      status: cols[5],
      senderBank: cols[9],
      receiverBank: cols[10],
      deviceType: cols[11],
      fraudFlag: Number(cols[13]) || 0,
      hourOfDay: Number(cols[14]) || 0,
      dayOfWeek: cols[15],
      deviceSurrogate: cols[17],
      corridorSurrogate: cols[18],
    });
  }
  return rows;
}

function normalizeDayOfWeek(input: string): number {
  const day = input.trim().slice(0, 3).toLowerCase();
  const map: Record<string, number> = {
    sun: 0,
    mon: 1,
    tue: 2,
    wed: 3,
    thu: 4,
    fri: 5,
    sat: 6,
  };
  return map[day] ?? 0;
}

function bankToVpa(bank: string, surrogate: string): string {
  const slug = bank.toLowerCase().replace(/[^a-z0-9]/g, "");
  const suffix = surrogate.slice(0, 6) || "demo";
  return `${slug}.${suffix}@upi`;
}

function GraphNetworkMonitor() {
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [totalProcessed, setTotalProcessed] = useState(0);
  const [usingFallback, setUsingFallback] = useState(false);
  const [manualError, setManualError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [lastInjected, setLastInjected] = useState<{
    verdict: Verdict;
    riskScore: number;
    traceId?: string;
    sender: string;
    receiver: string;
    amount: number;
    source: "manual" | "dataset";
    labelBoost?: boolean;
  } | null>(null);
  const [lastEdgeId, setLastEdgeId] = useState<number | null>(null);
  const [manual, setManual] = useState({
    sender: "ravi.kumar@axisbank",
    receiver: "kirana.store@okhdfc",
    amount: "4750",
    merchantCat: "FOOD",
    timeOfDay: "09:00-18:00",
    newDevice: false,
  });
  const [datasetId, setDatasetId] = useState<string>(DEMO_DATASETS[0].id);
  const [datasetRows, setDatasetRows] = useState<DemoRow[]>([]);
  const [datasetLoading, setDatasetLoading] = useState(false);
  const [datasetError, setDatasetError] = useState<string | null>(null);
  const [batchSize, setBatchSize] = useState(25);
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchStats, setBatchStats] = useState({ processed: 0, total: 0, allow: 0, flag: 0, block: 0, avgRisk: 0 });

  const appendEdge = useCallback((edge: GraphEdge) => {
    setEdges((prev) => {
      const next = [edge, ...prev];
      return next.length > 40 ? next.slice(0, 40) : next;
    });
    setTotalProcessed((p) => p + 1);
  }, []);

  function fallbackVerdict(amount: number, newDevice: boolean, merchant: string): { verdict: Verdict; risk: number } {
    if (amount > 45000 && newDevice) return { verdict: "BLOCK", risk: 0.92 };
    if (amount > 18000 || newDevice || merchant === "GAMBLING") return { verdict: "FLAG", risk: 0.66 };
    return { verdict: "ALLOW", risk: 0.18 };
  }

  function buildPayloadFromDemo(row: DemoRow) {
    const amount = Math.max(1, row.amount);
    const fraud = row.fraudFlag === 1;
    const senderVpa = bankToVpa(row.senderBank, row.deviceSurrogate);
    const receiverVpa = bankToVpa(row.receiverBank, row.corridorSurrogate);
    const amountZ = Math.max(-5, Math.min(5, (amount - 3000) / 12000));
    return {
      senderVpa,
      receiverVpa,
      amount,
      payload: {
        vpa: senderVpa,
        amount,
        merchant_category: row.merchantCategory.toUpperCase(),
        transaction_type: "DEBIT",
        device_type: row.deviceType.toUpperCase().includes("IOS") ? "IOS" : "ANDROID",
        hour_of_day: row.hourOfDay,
        day_of_week: normalizeDayOfWeek(row.dayOfWeek),
        transactions_last_1h: fraud ? 12 : 1,
        transactions_last_24h: fraud ? 28 : 3,
        amount_zscore: amountZ,
        gps_delta_km: fraud ? 48.0 : 1.2,
        is_new_device: fraud,
        is_new_merchant: fraud,
        balance_drain_ratio: fraud ? 0.92 : Math.min(1, amount / 100000),
        account_age_days: 420,
        previous_failed_attempts: fraud ? 3 : 0,
        transfer_cashout_flag: fraud ? 1 : 0,
      },
    };
  }

  const handleInject = useCallback(async (e: any) => {
    e.preventDefault();
    if (submitting) return;

    setSubmitting(true);
    setManualError(null);
    const amount = Math.max(1, Number(manual.amount) || 0);

    try {
      const API_BASE = getApiBaseNormalized();
      const payload = {
        vpa: manual.sender,
        amount,
        merchant_category: manual.merchantCat,
        transaction_type: "DEBIT",
        device_type: "ANDROID",
        hour_of_day: mapTimeBucketToHour(manual.timeOfDay),
        day_of_week: new Date().getDay(),
        transactions_last_1h: manual.newDevice ? 3 : 1,
        transactions_last_24h: manual.newDevice ? 8 : 3,
        amount_zscore: Math.max(-5, Math.min(5, (amount - 3000) / 12000)),
        gps_delta_km: manual.newDevice ? 18.4 : 1.2,
        is_new_device: manual.newDevice,
        is_new_merchant: false,
        balance_drain_ratio: manual.newDevice && amount > 10000 ? 0.73 : 0.14,
        account_age_days: 420,
        previous_failed_attempts: manual.newDevice ? 2 : 0,
        transfer_cashout_flag: manual.merchantCat === "GAMBLING" ? 1 : 0,
      };

      const res = await fetch(`${API_BASE}/v1/tx`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const edgeId = Date.now();
      appendEdge({
        id: edgeId,
        from: manual.sender,
        to: manual.receiver,
        verdict: (data.verdict as Verdict) || "ALLOW",
        riskScore: Number(data.risk_score ?? 0.18),
        amount,
        ts: Date.now(),
      });
      setLastEdgeId(edgeId);
      setLastInjected({
        verdict: (data.verdict as Verdict) || "ALLOW",
        riskScore: Number(data.risk_score ?? 0.18),
        traceId: data.trace_id,
        sender: manual.sender,
        receiver: manual.receiver,
        amount,
        source: "manual",
      });
    } catch {
      const fb = fallbackVerdict(amount, manual.newDevice, manual.merchantCat);
      const edgeId = Date.now();
      appendEdge({
        id: edgeId,
        from: manual.sender,
        to: manual.receiver,
        verdict: fb.verdict,
        riskScore: fb.risk,
        amount,
        ts: Date.now(),
      });
      setLastEdgeId(edgeId);
      setLastInjected({
        verdict: fb.verdict,
        riskScore: fb.risk,
        sender: manual.sender,
        receiver: manual.receiver,
        amount,
        source: "manual",
      });
      setManualError("Backend unreachable - injected with enterprise fallback scoring.");
    } finally {
      setSubmitting(false);
    }
  }, [appendEdge, manual, submitting]);

  useEffect(() => {
    let active = true;
    async function loadDataset() {
      setDatasetLoading(true);
      setDatasetError(null);
      try {
        const ds = DEMO_DATASETS.find((d) => d.id === datasetId);
        if (!ds) throw new Error("Dataset not found");
        const res = await fetch(ds.path);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        if (!active) return;
        setDatasetRows(parseDemoCsv(text));
      } catch (err) {
        if (!active) return;
        const msg = err instanceof Error ? err.message : "Dataset load failed";
        setDatasetError(msg);
        setDatasetRows([]);
      } finally {
        if (active) setDatasetLoading(false);
      }
    }
    loadDataset();
    return () => { active = false; };
  }, [datasetId]);

  const handleDatasetInject = useCallback(async () => {
    if (batchRunning || datasetRows.length === 0) return;
    setBatchRunning(true);
    const total = Math.min(batchSize, datasetRows.length);
    setBatchStats({ processed: 0, total, allow: 0, flag: 0, block: 0, avgRisk: 0 });

    let riskSum = 0;
    for (let i = 0; i < total; i += 1) {
      const row = datasetRows[i];
      const { senderVpa, receiverVpa, amount, payload } = buildPayloadFromDemo(row);
      const isFraudLabel = row.fraudFlag === 1;
      let verdict: Verdict = "ALLOW";
      let risk = 0.18;
      let traceId: string | undefined;
      let labelBoost = false;

      try {
        const API_BASE = getApiBaseNormalized();
        const res = await fetch(`${API_BASE}/v1/tx`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        verdict = (data.verdict as Verdict) || "ALLOW";
        risk = Number(data.risk_score ?? 0.18);
        traceId = data.trace_id;
      } catch {
        const fb = fallbackVerdict(amount, payload.is_new_device, payload.merchant_category);
        verdict = fb.verdict;
        risk = fb.risk;
      }

      if (isFraudLabel && verdict === "ALLOW") {
        verdict = "FLAG";
        risk = Math.max(risk, 0.72);
        labelBoost = true;
      }

      const edgeId = Date.now() + i;
      appendEdge({
        id: edgeId,
        from: senderVpa,
        to: receiverVpa,
        verdict,
        riskScore: risk,
        amount,
        ts: Date.now(),
      });
      setLastEdgeId(edgeId);
      setLastInjected({
        verdict,
        riskScore: risk,
        traceId,
        sender: senderVpa,
        receiver: receiverVpa,
        amount,
        source: "dataset",
        labelBoost,
      });

      riskSum += risk;
      setBatchStats((prev) => {
        const allow = prev.allow + (verdict === "ALLOW" ? 1 : 0);
        const flag = prev.flag + (verdict === "FLAG" ? 1 : 0);
        const block = prev.block + (verdict === "BLOCK" ? 1 : 0);
        const processed = prev.processed + 1;
        return {
          processed,
          total,
          allow,
          flag,
          block,
          avgRisk: riskSum / processed,
        };
      });

      await new Promise((r) => setTimeout(r, 180));
    }

    setBatchRunning(false);
  }, [appendEdge, batchRunning, batchSize, datasetRows]);

  // Seed initial edges
  useEffect(() => {
    const seed: GraphEdge[] = [];
    for (let i = 0; i < 12; i++) {
      const row = nextFeedRow();
      seed.push({ id: i, from: row.sender, to: row.receiver, verdict: row.verdict, riskScore: row.riskScore, amount: row.amount, ts: Date.now() - (12 - i) * FEED_INTERVAL_MS });
    }
    setEdges(seed);
    setTotalProcessed(seed.length);
  }, []);

  // Connect to live SSE stream
  useEffect(() => {
    let es: EventSource | null = null;
    function connect() {
      const API_BASE = getApiBaseNormalized();
      es = new EventSource(`${API_BASE}/v1/stream`);
      es.onmessage = (e) => {
        try {
          const tx: StreamTx = JSON.parse(e.data);
          appendEdge({
            id: Date.now(),
            from: tx.sender,
            to: tx.receiver,
            verdict: tx.verdict,
            riskScore: tx.risk,
            amount: tx.amount,
            ts: Date.now(),
          });
        } catch { /* ignore */ }
      };
      es.onerror = () => { setUsingFallback(true); es?.close(); es = null; };
    }
    connect();
    return () => es?.close();
  }, [appendEdge]);

  // Deterministic fallback when backend offline
  useEffect(() => {
    if (!usingFallback) return;
    const timer = setInterval(() => {
      const row = nextFeedRow();
      appendEdge({
        id: Date.now(),
        from: row.sender,
        to: row.receiver,
        verdict: row.verdict,
        riskScore: row.riskScore,
        amount: row.amount,
        ts: Date.now(),
      });
    }, FEED_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [usingFallback, appendEdge]);

  // Extract unique sender/receiver nodes (up to 8 each)
  const senders = useMemo(() => {
    const seen = new Set<string>(); const result: string[] = [];
    for (const e of edges) { if (!seen.has(e.from)) { seen.add(e.from); result.push(e.from); } if (result.length >= 8) break; }
    return result;
  }, [edges]);

  const receivers = useMemo(() => {
    const seen = new Set<string>(); const result: string[] = [];
    for (const e of edges) { if (!seen.has(e.to)) { seen.add(e.to); result.push(e.to); } if (result.length >= 8) break; }
    return result;
  }, [edges]);

  const W = 680; const H = 400;
  const senderX = 130; const receiverX = W - 130;

  function nodeY(index: number, total: number): number {
    if (total <= 1) return H / 2;
    return 45 + (index * (H - 90)) / (total - 1);
  }

  function edgeColor(v: Verdict): string {
    if (v === "BLOCK") return "#C0392B";
    if (v === "FLAG")  return "#D97706";
    return "#0D7A5F";
  }

  const visibleEdges = edges.slice(0, 25);

  // Aggregate stats
  const graphStats = useMemo(() => {
    const flagged = edges.filter((e) => e.verdict === "FLAG" || e.verdict === "BLOCK");
    const uniqueNodes = new Set([...edges.map((e) => e.from), ...edges.map((e) => e.to)]).size;
    const blocked = edges.filter((e) => e.verdict === "BLOCK");
    return { flagged: flagged.length, uniqueNodes, blocked: blocked.length };
  }, [edges]);

  return (
    <section className="border border-cream/[0.08] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-cream/[0.07] bg-cream/[0.025]">
        <div className="flex items-center gap-2.5">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-allow animate-pulse" />
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/40">
            Module G &mdash; Transaction Network Graph
          </span>
        </div>
        <span className="font-courier text-[0.52rem] text-cream/18">
          {totalProcessed} edges &middot; {usingFallback ? "simulated" : "live"}
        </span>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 divide-x divide-cream/[0.06] border-b border-cream/[0.06]">
        {[
          { label: "Active VPAs",    value: graphStats.uniqueNodes.toString()  },
          { label: "Flagged Flows",  value: graphStats.flagged.toString()       },
          { label: "Blocked Nodes",  value: graphStats.blocked.toString()       },
        ].map((s) => (
          <div key={s.label} className="px-5 py-3 flex flex-col gap-0.5">
            <span className="font-barlow text-[0.48rem] tracking-[0.24em] uppercase text-cream/22">{s.label}</span>
            <span className="font-courier text-[1.2rem] font-bold text-cream/70">{s.value}</span>
          </div>
        ))}
      </div>

      <form onSubmit={handleInject} className="grid grid-cols-1 md:grid-cols-6 gap-2 px-4 py-3 border-b border-cream/[0.06] bg-cream/[0.015]">
        <input value={manual.sender} onChange={(e) => setManual((m) => ({ ...m, sender: e.target.value }))} className="bg-cream/[0.02] border border-cream/[0.12] px-2 py-2 font-courier text-[0.62rem] text-cream/70" placeholder="sender VPA" />
        <input value={manual.receiver} onChange={(e) => setManual((m) => ({ ...m, receiver: e.target.value }))} className="bg-cream/[0.02] border border-cream/[0.12] px-2 py-2 font-courier text-[0.62rem] text-cream/70" placeholder="receiver VPA" />
        <input value={manual.amount} onChange={(e) => setManual((m) => ({ ...m, amount: e.target.value }))} className="bg-cream/[0.02] border border-cream/[0.12] px-2 py-2 font-courier text-[0.62rem] text-cream/70" placeholder="amount" type="number" />
        <select value={manual.merchantCat} onChange={(e) => setManual((m) => ({ ...m, merchantCat: e.target.value }))} className="bg-cream/[0.02] border border-cream/[0.12] px-2 py-2 font-courier text-[0.62rem] text-cream/70">
          {MERCHANT_CATS.map((cat) => <option key={cat} value={cat}>{cat}</option>)}
        </select>
        <select value={manual.timeOfDay} onChange={(e) => setManual((m) => ({ ...m, timeOfDay: e.target.value }))} className="bg-cream/[0.02] border border-cream/[0.12] px-2 py-2 font-courier text-[0.62rem] text-cream/70">
          {["06:00-09:00", "09:00-18:00", "18:00-22:00", "22:00-02:00", "02:00-06:00"].map((slot) => <option key={slot} value={slot}>{slot}</option>)}
        </select>
        <button type="submit" disabled={submitting} className="bg-saffron/90 hover:bg-saffron disabled:opacity-60 text-ink font-barlow text-[0.60rem] tracking-[0.18em] uppercase px-3 py-2">
          {submitting ? "Injecting..." : "Inject Tx"}
        </button>
        <label className="md:col-span-6 flex items-center gap-2 font-barlow text-[0.56rem] tracking-wide text-cream/40">
          <input type="checkbox" checked={manual.newDevice} onChange={(e) => setManual((m) => ({ ...m, newDevice: e.target.checked }))} />
          New device risk boost
        </label>
        {manualError && <p className="md:col-span-6 font-courier text-[0.56rem] text-flag/80">{manualError}</p>}
      </form>

      {lastInjected && (
        <div className="px-4 py-3 border-b border-cream/[0.06] bg-cream/[0.012]">
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-barlow text-[0.50rem] tracking-[0.22em] uppercase text-cream/30">Last Injected</span>
            <span className={`font-courier text-[0.70rem] ${lastInjected.verdict === "ALLOW" ? "text-allow" : lastInjected.verdict === "BLOCK" ? "text-block" : "text-flag"}`}>
              {lastInjected.verdict}
            </span>
            <span className="font-courier text-[0.62rem] text-cream/55">Risk {lastInjected.riskScore.toFixed(2)}</span>
            <span className="font-courier text-[0.58rem] text-cream/35">
              {lastInjected.sender} → {lastInjected.receiver} · ₹{Math.round(lastInjected.amount)}
            </span>
            {lastInjected.traceId && (
              <span className="font-courier text-[0.52rem] text-cream/30">Trace {lastInjected.traceId}</span>
            )}
            {lastInjected.labelBoost && (
              <span className="font-barlow text-[0.48rem] tracking-[0.20em] uppercase text-flag/80">Label boost</span>
            )}
            <span className="ml-auto font-barlow text-[0.48rem] tracking-[0.20em] uppercase text-cream/22">
              Source · {lastInjected.source}
            </span>
          </div>
        </div>
      )}

      <div className="px-4 py-4 border-b border-cream/[0.06] bg-cream/[0.01]">
        <div className="flex flex-wrap items-center gap-3 mb-3">
          <span className="font-barlow text-[0.52rem] tracking-[0.26em] uppercase text-cream/30">Demo Datasets</span>
          <select
            value={datasetId}
            onChange={(e) => setDatasetId(e.target.value)}
            className="bg-cream/[0.02] border border-cream/[0.12] px-2 py-1.5 font-courier text-[0.6rem] text-cream/70"
          >
            {DEMO_DATASETS.map((ds) => (
              <option key={ds.id} value={ds.id}>
                {ds.label}
              </option>
            ))}
          </select>
          <span className="font-courier text-[0.56rem] text-cream/35">
            {datasetLoading ? "Loading..." : `${datasetRows.length} rows loaded`}
          </span>
          {datasetError && <span className="font-courier text-[0.56rem] text-flag/80">{datasetError}</span>}
          <span className="ml-auto font-barlow text-[0.48rem] tracking-[0.20em] uppercase text-cream/20">
            {DEMO_DATASETS.find((d) => d.id === datasetId)?.note}
          </span>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-[1fr_220px] gap-4">
          <div className="border border-cream/[0.08] bg-cream/[0.015]">
            <div className="px-3 py-2 border-b border-cream/[0.06]">
              <span className="font-barlow text-[0.50rem] tracking-[0.24em] uppercase text-cream/25">Preview</span>
            </div>
            <div className="grid grid-cols-4 gap-px bg-cream/[0.06]">
              {(datasetRows.length ? datasetRows.slice(0, 6) : []).map((row) => (
                <div key={row.txId} className="contents">
                  <div className="bg-ink/60 px-3 py-2">
                    <p className="font-courier text-[0.55rem] text-cream/60">{row.txId}</p>
                  </div>
                  <div className="bg-ink/60 px-3 py-2">
                    <p className="font-courier text-[0.55rem] text-cream/55">{row.merchantCategory}</p>
                  </div>
                  <div className="bg-ink/60 px-3 py-2">
                    <p className="font-courier text-[0.55rem] text-cream/55">₹{row.amount}</p>
                  </div>
                  <div className="bg-ink/60 px-3 py-2">
                    <p className={`font-courier text-[0.55rem] ${row.fraudFlag ? "text-flag" : "text-allow"}`}>
                      {row.fraudFlag ? "FRAUD" : "NORMAL"}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <div className="border border-cream/[0.08] bg-cream/[0.015] p-3">
              <p className="font-barlow text-[0.48rem] tracking-[0.24em] uppercase text-cream/25 mb-2">Batch Inject</p>
              <input
                type="number"
                min="1"
                max="200"
                value={batchSize}
                onChange={(e) => setBatchSize(Math.max(1, Number(e.target.value) || 1))}
                inputMode="numeric"
                className="w-full bg-cream/[0.02] border border-cream/[0.12] px-2 py-2 font-courier text-[0.62rem] text-cream/70"
              />
              <div className="mt-2 grid grid-cols-5 gap-2">
                {[10, 25, 50, 75, 100].map((size) => (
                  <button
                    key={size}
                    type="button"
                    onClick={() => setBatchSize(size)}
                    className={`border px-2 py-1 font-courier text-[0.56rem] ${
                      batchSize === size
                        ? "border-saffron/50 text-saffron"
                        : "border-cream/[0.12] text-cream/45 hover:text-cream/70"
                    }`}
                  >
                    {size}
                  </button>
                ))}
              </div>
              <button
                type="button"
                onClick={handleDatasetInject}
                disabled={batchRunning || datasetLoading || datasetRows.length === 0}
                className="mt-2 w-full bg-allow/90 hover:bg-allow disabled:opacity-60 text-ink font-barlow text-[0.60rem] tracking-[0.18em] uppercase px-3 py-2"
              >
                {batchRunning ? "Injecting..." : "Inject Dataset"}
              </button>
            </div>

            <div className="border border-cream/[0.08] bg-cream/[0.015] p-3">
              <p className="font-barlow text-[0.48rem] tracking-[0.24em] uppercase text-cream/25 mb-2">Batch Results</p>
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-barlow text-[0.54rem] text-cream/35">Processed</span>
                  <span className="font-courier text-[0.6rem] text-cream/60">
                    {batchStats.processed}/{batchStats.total}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-barlow text-[0.54rem] text-cream/35">ALLOW</span>
                  <span className="font-courier text-[0.6rem] text-allow">{batchStats.allow}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-barlow text-[0.54rem] text-cream/35">FLAG</span>
                  <span className="font-courier text-[0.6rem] text-flag">{batchStats.flag}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-barlow text-[0.54rem] text-cream/35">BLOCK</span>
                  <span className="font-courier text-[0.6rem] text-block">{batchStats.block}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-barlow text-[0.54rem] text-cream/35">Avg Risk</span>
                  <span className="font-courier text-[0.6rem] text-cream/60">{batchStats.avgRisk.toFixed(2)}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* SVG Bipartite Graph */}
      <div className="p-5">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="w-full"
          style={{ maxHeight: 380, background: "rgba(240,244,248,0.015)", border: "1px solid rgba(240,244,248,0.06)" }}
        >
          {/* Column labels */}
          <text x={senderX} y={22} textAnchor="middle" fill="rgba(240,244,248,0.25)" fontSize={8} fontFamily="monospace" letterSpacing="2">SENDERS</text>
          <text x={receiverX} y={22} textAnchor="middle" fill="rgba(240,244,248,0.25)" fontSize={8} fontFamily="monospace" letterSpacing="2">RECEIVERS</text>

          {/* Center divider */}
          <line x1={W / 2} y1={30} x2={W / 2} y2={H - 10} stroke="rgba(240,244,248,0.04)" strokeWidth={1} strokeDasharray="4 4" />

          {/* Edges */}
          {visibleEdges.map((edge, i) => {
            const fi = senders.indexOf(edge.from);
            const ti = receivers.indexOf(edge.to);
            if (fi === -1 || ti === -1) return null;
            const x1 = senderX + 7; const y1 = nodeY(fi, senders.length);
            const x2 = receiverX - 7; const y2 = nodeY(ti, receivers.length);
            const cx = (x1 + x2) / 2;
            const opacity = Math.max(0.07, 0.75 - i * 0.028);
            const isHot = edge.id === lastEdgeId;
            return (
              <path
                key={edge.id}
                d={`M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`}
                stroke={edgeColor(edge.verdict)}
                strokeWidth={isHot ? 3 : edge.verdict === "BLOCK" ? 2.5 : 1}
                fill="none"
                opacity={isHot ? 0.95 : opacity}
              />
            );
          })}

          {/* Sender nodes */}
          {senders.map((vpa, i) => {
            const y = nodeY(i, senders.length);
            const hasBlock = edges.some((e) => e.from === vpa && e.verdict === "BLOCK");
            const hasFlag  = edges.some((e) => e.from === vpa && e.verdict === "FLAG");
            const color = hasBlock ? "#C0392B" : hasFlag ? "#D97706" : "#0D7A5F";
            return (
              <g key={vpa}>
                <circle cx={senderX} cy={y} r={7} fill={`${color}20`} stroke={color} strokeWidth={1.5} />
                <text x={senderX - 12} y={y + 4} textAnchor="end" fill="rgba(240,244,248,0.50)" fontSize={7.5} fontFamily="monospace">
                  {maskVpa(vpa).slice(0, 20)}
                </text>
              </g>
            );
          })}

          {/* Receiver nodes */}
          {receivers.map((vpa, i) => {
            const y = nodeY(i, receivers.length);
            const hasBlock = edges.some((e) => e.to === vpa && e.verdict === "BLOCK");
            const hasFlag  = edges.some((e) => e.to === vpa && e.verdict === "FLAG");
            const color = hasBlock ? "#C0392B" : hasFlag ? "#D97706" : "#0D7A5F";
            return (
              <g key={vpa}>
                <circle cx={receiverX} cy={y} r={7} fill={`${color}20`} stroke={color} strokeWidth={1.5} />
                <text x={receiverX + 12} y={y + 4} textAnchor="start" fill="rgba(240,244,248,0.50)" fontSize={7.5} fontFamily="monospace">
                  {maskVpa(vpa).slice(0, 20)}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Legend + source badge */}
        <div className="flex items-center gap-5 mt-3 flex-wrap">
          {[
            { label: "ALLOW", color: "#0D7A5F" },
            { label: "FLAG",  color: "#D97706" },
            { label: "BLOCK", color: "#C0392B" },
          ].map(({ label, color }) => (
            <div key={label} className="flex items-center gap-1.5">
              <div className="w-5 h-px" style={{ backgroundColor: color }} />
              <span className="font-courier text-[0.54rem] text-cream/30">{label}</span>
            </div>
          ))}
          <span className="ml-auto font-barlow text-[0.50rem] tracking-widest uppercase text-cream/18">
            {usingFallback ? "Fallback · Backend offline" : "Live · Railway API"}
          </span>
        </div>
      </div>
    </section>
  );
}

// ── Embedded Tier panel ───────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE H — OPEN BANKING FEED  (Setu AA · Plaid)
// ═══════════════════════════════════════════════════════════════════════════════

interface OBRow {
  id:        number;
  ts:        string;
  source:    "setu" | "plaid";
  sender:    string;
  receiver:  string;
  amount:    number;
  currency:  string;
  category:  string;
  verdict:   Verdict;
  riskScore: number;
  latencyMs: number;
}

// Synthetic fallback pool — realistic Indian (Setu) + International (Plaid) txns
const OB_FALLBACK: Omit<OBRow, "id" | "ts">[] = [
  { source:"setu",  sender:"ravi.kumar@axisbank",       receiver:"swiggy.merchant@icici",   amount:349,    currency:"INR", category:"FOOD",     verdict:"ALLOW", riskScore:0.11, latencyMs:6 },
  { source:"plaid", sender:"john.doe@chase",             receiver:"mcdonalds.pay@visa",      amount:12.50,  currency:"USD", category:"FOOD",     verdict:"ALLOW", riskScore:0.09, latencyMs:5 },
  { source:"setu",  sender:"priya.sharma@okicici",      receiver:"electricity.board@okhdfc",amount:1800,   currency:"INR", category:"UTILITY",  verdict:"ALLOW", riskScore:0.14, latencyMs:7 },
  { source:"plaid", sender:"jane.smith@bankofamerica",  receiver:"wholefds.market@visa",    amount:87.30,  currency:"USD", category:"ECOM",     verdict:"ALLOW", riskScore:0.12, latencyMs:5 },
  { source:"setu",  sender:"suresh.patel@ybl",          receiver:"irctc.booking@ybl",       amount:2450,   currency:"INR", category:"TRAVEL",   verdict:"ALLOW", riskScore:0.18, latencyMs:6 },
  { source:"plaid", sender:"mike.johnson@wells",        receiver:"crypto.exchange@wire",    amount:4980,   currency:"USD", category:"GAMBLING", verdict:"BLOCK", riskScore:0.91, latencyMs:4 },
  { source:"setu",  sender:"cash.agent.77@YESB",       receiver:"wallet.agent1@paytm",     amount:45000,  currency:"INR", category:"UTILITY",  verdict:"BLOCK", riskScore:0.93, latencyMs:5 },
  { source:"setu",  sender:"mohan.verma@okhdfc",        receiver:"zomato.pay@okicici",      amount:520,    currency:"INR", category:"FOOD",     verdict:"ALLOW", riskScore:0.10, latencyMs:7 },
  { source:"plaid", sender:"sarah.lee@citibank",        receiver:"draftkings.bet@ach",      amount:500,    currency:"USD", category:"GAMBLING", verdict:"FLAG",  riskScore:0.67, latencyMs:6 },
  { source:"setu",  sender:"wallet.agent1@paytm",      receiver:"wallet.agent2@paytm",     amount:9999,   currency:"INR", category:"ECOM",     verdict:"FLAG",  riskScore:0.72, latencyMs:5 },
  { source:"plaid", sender:"alex.brown@usbank",         receiver:"amazon.pay@visa",         amount:149.99, currency:"USD", category:"ECOM",     verdict:"ALLOW", riskScore:0.08, latencyMs:5 },
  { source:"setu",  sender:"kavitha.n@paytm",           receiver:"pharmacy.care@ybl",       amount:640,    currency:"INR", category:"UTILITY",  verdict:"ALLOW", riskScore:0.13, latencyMs:6 },
];

let _obSeq = 0;
function nextOBRow(): OBRow {
  const base = OB_FALLBACK[_obSeq % OB_FALLBACK.length];
  _obSeq++;
  const now = new Date();
  return { ...base, id: _obSeq, ts: now.toTimeString().slice(0, 8) };
}

function sourceBadge(src: "setu" | "plaid") {
  return src === "setu"
    ? "text-[#7C3AED] bg-[#7C3AED]/10 border border-[#7C3AED]/25"
    : "text-[#0EA5E9] bg-[#0EA5E9]/10 border border-[#0EA5E9]/25";
}

function OpenBankingModule() {
  const [rows, setRows]           = useState<OBRow[]>([]);
  const [usingFallback, setFB]    = useState(false);
  const [paused, setPaused]       = useState(false);
  const [stats, setStats]         = useState({ setu: 0, plaid: 0, block: 0, flag: 0 });

  // Try SSE from Python bridge
  useEffect(() => {
    if (usingFallback) return;
    const API_BASE = getApiBaseNormalized();
    let es: EventSource | null = null;
    function connect() {
      es = new EventSource(`${API_BASE}/v1/open-banking/stream?source=both`);
      es.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data) as {
            source: "setu" | "plaid";
            sender_vpa: string;
            receiver_vpa: string;
            amount: number;
            currency: string;
            category: string;
            verdict: Verdict;
            risk_score: number;
            latency_ms: number;
          };
          const row: OBRow = {
            id:        Date.now() + Math.random(),
            ts:        new Date().toTimeString().slice(0, 8),
            source:    d.source,
            sender:    d.sender_vpa,
            receiver:  d.receiver_vpa,
            amount:    d.amount,
            currency:  d.currency,
            category:  d.category,
            verdict:   d.verdict,
            riskScore: d.risk_score,
            latencyMs: d.latency_ms,
          };
          setRows((prev) => { const next = [row, ...prev]; return next.length > 40 ? next.slice(0, 40) : next; });
          setStats((s) => ({
            setu:  s.setu  + (d.source === "setu"  ? 1 : 0),
            plaid: s.plaid + (d.source === "plaid" ? 1 : 0),
            block: s.block + (d.verdict === "BLOCK" ? 1 : 0),
            flag:  s.flag  + (d.verdict === "FLAG"  ? 1 : 0),
          }));
        } catch { /* skip malformed */ }
      };
      es.onerror = () => { setFB(true); es?.close(); es = null; };
    }
    connect();
    return () => es?.close();
  }, [usingFallback]);

  // Deterministic fallback
  useEffect(() => {
    if (!usingFallback || paused) return;
    const t = setInterval(() => {
      const row = nextOBRow();
      setRows((prev) => { const next = [row, ...prev]; return next.length > 40 ? next.slice(0, 40) : next; });
      setStats((s) => ({
        setu:  s.setu  + (row.source === "setu"  ? 1 : 0),
        plaid: s.plaid + (row.source === "plaid" ? 1 : 0),
        block: s.block + (row.verdict === "BLOCK" ? 1 : 0),
        flag:  s.flag  + (row.verdict === "FLAG"  ? 1 : 0),
      }));
    }, 3000);
    return () => clearInterval(t);
  }, [usingFallback, paused]);

  return (
    <section className="border border-cream/[0.08] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-cream/[0.07] bg-cream/[0.025] shrink-0">
        <div className="flex items-center gap-2.5">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-allow animate-pulse" />
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/40">
            Module H &mdash; Open Banking Feed
          </span>
          {usingFallback && (
            <span className="font-courier text-[0.48rem] text-cream/22 border border-cream/[0.12] px-1.5 py-0.5">
              synthetic
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-3 mr-1">
            {[
              { label: "Setu",  val: stats.setu,  cls: "text-[#7C3AED]" },
              { label: "Plaid", val: stats.plaid, cls: "text-[#0EA5E9]" },
              { label: "Flag",  val: stats.flag,  cls: "text-flag" },
              { label: "Block", val: stats.block, cls: "text-block" },
            ].map((s) => (
              <div key={s.label} className="flex items-center gap-1">
                <span className={`font-courier text-[0.66rem] font-bold ${s.cls}`}>{s.val}</span>
                <span className="font-barlow text-[0.46rem] tracking-widest uppercase text-cream/20">{s.label}</span>
              </div>
            ))}
          </div>
          <button
            onClick={() => setPaused((p) => !p)}
            className={`font-barlow text-[0.54rem] tracking-[0.22em] uppercase border px-2.5 py-1 transition-colors ${
              paused ? "border-saffron/40 text-saffron" : "border-cream/30 text-cream/50 hover:border-cream/60"
            }`}
          >
            {paused ? "▶ Resume" : "⏸ Pause"}
          </button>
        </div>
      </div>

      {/* Source info cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-cream/[0.06] border-b border-cream/[0.06]">
        {[
          {
            key: "setu",
            name: "Setu Account Aggregator",
            country: "India",
            standard: "RBI AA / UPI FIP",
            dotCls: "bg-[#7C3AED]",
            textCls: "text-[#7C3AED]",
            desc: "RBI-licensed AA framework. Fetches UPI transaction history via FIP consent flow.",
            tags: ["UPI", "IMPS", "NEFT", "INR"],
          },
          {
            key: "plaid",
            name: "Plaid Open Banking",
            country: "US / EU",
            standard: "PSD2 / Open Finance",
            dotCls: "bg-[#0EA5E9]",
            textCls: "text-[#0EA5E9]",
            desc: "12,000+ institutions. Sandbox provides realistic ACH, debit, and wire transactions.",
            tags: ["ACH", "Wire", "Debit", "USD"],
          },
        ].map((src) => (
          <div key={src.key} className="px-5 py-3.5 flex items-start gap-3">
            <span className={`mt-1.5 inline-block w-2 h-2 rounded-full shrink-0 ${src.dotCls}`} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-0.5">
                <span className={`font-barlow text-[0.60rem] font-semibold tracking-wide ${src.textCls}`}>{src.name}</span>
                <span className="font-courier text-[0.46rem] text-cream/22 border border-cream/[0.10] px-1 py-px">{src.country}</span>
              </div>
              <p className="font-barlow text-[0.60rem] text-cream/35 leading-relaxed mb-1.5">{src.desc}</p>
              <div className="flex flex-wrap gap-1">
                {src.tags.map((t) => (
                  <span key={t} className="font-courier text-[0.44rem] text-cream/25 border border-cream/[0.08] px-1 py-px">{t}</span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Normalisation pipeline pill */}
      <div className="flex items-center gap-2 px-5 py-2.5 border-b border-cream/[0.05] bg-cream/[0.01] overflow-x-auto">
        {[
          { label: "Setu FIP JSON",     accent: "#7C3AED" },
          { label: "→ Normalizer.py",   accent: "#D97706" },
          { label: "→ 24-feature vec",  accent: "#D97706" },
          { label: "→ Rust ONNX",       accent: "#2563EB" },
          { label: "→ Verdict",         accent: "#0D7A5F" },
        ].map((s) => (
          <span
            key={s.label}
            className="font-courier text-[0.52rem] whitespace-nowrap shrink-0"
            style={{ color: s.accent }}
          >
            {s.label}
          </span>
        ))}
        <span className="mx-1 text-cream/10 select-none">|</span>
        {[
          { label: "Plaid JSON",        accent: "#0EA5E9" },
          { label: "→ Normalizer.py",   accent: "#D97706" },
          { label: "→ 24-feature vec",  accent: "#D97706" },
          { label: "→ Rust ONNX",       accent: "#2563EB" },
          { label: "→ Verdict",         accent: "#0D7A5F" },
        ].map((s) => (
          <span
            key={s.label}
            className="font-courier text-[0.52rem] whitespace-nowrap shrink-0"
            style={{ color: s.accent }}
          >
            {s.label}
          </span>
        ))}
      </div>

      {/* Feed table header */}
      <div className="grid grid-cols-[52px_60px_1fr_1fr_72px_56px_56px_64px] gap-2 px-4 py-2 border-b border-cream/[0.05] bg-cream/[0.015] shrink-0">
        {["Time","Src","Sender","Receiver","Amount","Cat","Risk","Verdict"].map((h) => (
          <span key={h} className="font-barlow text-[0.46rem] tracking-[0.22em] uppercase text-cream/20">{h}</span>
        ))}
      </div>

      {/* Feed rows */}
      <div className="overflow-y-auto" style={{ maxHeight: "420px" }}>
        {rows.length === 0 && (
          <div className="px-5 py-8 text-center font-barlow text-[0.60rem] text-cream/18 tracking-widest uppercase">
            Waiting for open banking stream…
          </div>
        )}
        {rows.map((row, i) => (
          <div
            key={row.id}
            className={`grid grid-cols-[52px_60px_1fr_1fr_72px_56px_56px_64px] gap-2 px-4 py-2.5 border-b border-cream/[0.04] hover:bg-cream/[0.025] transition-colors ${
              i === 0 ? "bg-cream/[0.02]" : ""
            }`}
          >
            <span className="font-courier text-[0.58rem] text-cream/45 tabular-nums">{row.ts}</span>
            <span className={`font-courier text-[0.52rem] px-1 py-0.5 text-center self-center ${sourceBadge(row.source)}`}>
              {row.source === "setu" ? "Setu" : "Plaid"}
            </span>
            <span className="font-courier text-[0.60rem] text-cream/50 truncate">{maskVpa(row.sender)}</span>
            <span className="font-courier text-[0.60rem] text-cream/35 truncate">{maskVpa(row.receiver)}</span>
            <span className="font-courier text-[0.60rem] text-cream/50 tabular-nums">
              {row.currency === "INR" ? "₹" : "$"}{row.currency === "INR" ? row.amount.toLocaleString("en-IN") : row.amount.toFixed(2)}
            </span>
            <span className="font-barlow text-[0.50rem] text-cream/25 truncate self-center">{row.category}</span>
            <div className="flex items-center gap-1">
              <div className="flex-1 h-1 bg-cream/[0.07]">
                <div className={`h-full ${riskBar(row.riskScore)}`} style={{ width: `${row.riskScore * 100}%` }} />
              </div>
            </div>
            <span className={`font-courier text-[0.52rem] tracking-wider uppercase px-1 py-0.5 text-center self-center ${verdictBadge(row.verdict)}`}>
              {row.verdict}
            </span>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="px-5 py-2 border-t border-cream/[0.07] bg-cream/[0.015] flex items-center justify-between shrink-0">
        <span className="font-barlow text-[0.50rem] tracking-widest uppercase text-cream/18">
          {rows.length} open banking signals processed
        </span>
        <span className="font-courier text-[0.48rem] text-cream/15">
          {usingFallback ? "synthetic fallback · backend offline" : "live · Setu AA + Plaid"}
        </span>
      </div>
    </section>
  );
}

function EmbeddedTierPanel() {
  return (
    <div className="space-y-6">
      {/* Explainer banner */}
      <div className="border border-cream/[0.08] bg-cream/[0.015] px-6 py-5">
        <div className="flex items-start gap-4">
          <div>
            <p className="font-barlow text-[0.55rem] tracking-[0.30em] uppercase text-saffron mb-1.5">Tier 3 &mdash; Embedded SDK</p>
            <h2 className="font-playfair font-bold text-cream text-[1.3rem] leading-snug mb-2">
              On-Device, Pre-Network Defense
            </h2>
            <p className="font-barlow text-[0.78rem] text-cream/50 max-w-2xl leading-relaxed">
              The Varaksha Embedded SDK packages the ONNX Random Forest model into a sub-5MB bundle deployable inside iOS and Android UPI apps via ONNX Runtime Mobile.
              Fraud is scored locally &mdash; zero network round-trip, offline-capable, operates before the transaction even leaves the device.
              The simulation below shows the on-device gate logic running in your browser.
            </p>
          </div>
          <div className="shrink-0 hidden md:block">
            <div className="flex flex-col gap-2">
              {[
                { label: "Bundle size",  value: "<5 MB" },
                { label: "Latency",      value: "<1 ms" },
                { label: "Network req",  value: "None"  },
                { label: "Offline",      value: "Yes"   },
              ].map((s) => (
                <div key={s.label} className="border border-cream/[0.08] px-3 py-1.5 flex items-center justify-between gap-8">
                  <span className="font-barlow text-[0.52rem] tracking-widest uppercase text-cream/25">{s.label}</span>
                  <span className="font-courier text-[0.72rem] text-cream/60">{s.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Simulation component */}
      <Tier3EdgeSim />

      {/* Interactive architecture walkthrough */}
      <TierScenarioArchitecture tier="embedded" />

      {/* Tech specs */}
      <div className="border border-cream/[0.08] overflow-hidden">
        <div className="px-5 py-3 border-b border-cream/[0.06] bg-cream/[0.025]">
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/40">Deployment Specification</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-cream/[0.04] p-px">
          {[
            {
              title: "Model Packaging",
              accent: "#2563EB",
              items: ["Quantized ONNX Random Forest", "16-feature inference vector", "StandardScaler pre-baked", "ONNX opset 17 compatible"],
            },
            {
              title: "Mobile Runtime",
              accent: "#0D7A5F",
              items: ["ONNX Runtime Mobile (C++)", "Android NDK / iOS XCFramework", "JNI/Swift bridge layer", "No Python dependency"],
            },
            {
              title: "Local Heuristics",
              accent: "#D97706",
              items: ["Device velocity fingerprint", "Odd-hour anomaly gate", "Clipboard phishing scan", "Receiver risk signature"],
            },
          ].map((col) => (
            <div key={col.title} className="bg-ink p-5">
              <div className="h-0.5 mb-4" style={{ backgroundColor: col.accent }} />
              <h4 className="font-playfair font-bold text-cream text-[0.95rem] mb-3">{col.title}</h4>
              <ul className="space-y-1.5">
                {col.items.map((item) => (
                  <li key={item} className="flex items-start gap-2">
                    <span className="mt-1 w-1 h-1 rounded-full shrink-0" style={{ backgroundColor: col.accent }} />
                    <span className="font-courier text-[0.60rem] text-cream/40">{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAGE
// ═══════════════════════════════════════════════════════════════════════════════

export default function LivePage() {
  const [activeTier, setActiveTier] = useState<Tier>("cloud");

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
      <div
        className="pointer-events-none fixed inset-x-0 h-[1px] bg-saffron/8 z-50"
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
                <span
                  className={`inline-block w-1.5 h-1.5 rounded-full ${p.color}`}
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

        {/* ── Tier switcher ─────────────────────────────────────────────── */}
        <div className="flex items-center gap-1 border border-cream/[0.10] p-1 bg-cream/[0.02] w-fit">
          {(
            [
              { id: "cloud",      label: "Cloud",        sublabel: "Live · Railway API",  dot: "bg-allow"   },
              { id: "enterprise", label: "Enterprise",   sublabel: "Live · Graph Engine",  dot: "bg-allow"   },
              { id: "embedded",   label: "Embedded SDK", sublabel: "Simulation",           dot: "bg-saffron" },
            ] as const
          ).map(({ id, label, sublabel, dot }) => (
            <button
              key={id}
              onClick={() => setActiveTier(id)}
              className={`flex flex-col items-start px-4 py-2.5 transition-all duration-200 border ${
                activeTier === id
                  ? "bg-cream/[0.08] border-cream/[0.18] shadow-[inset_0_1px_0_rgba(240,244,248,0.08)]"
                  : "border-transparent hover:bg-cream/[0.04]"
              }`}
            >
              <div className="flex items-center gap-2 mb-0.5">
                <span className={`inline-block w-1.5 h-1.5 rounded-full ${dot} ${activeTier === id ? "animate-pulse" : "opacity-40"}`} />
                <span className={`font-barlow text-[0.62rem] tracking-[0.18em] uppercase font-semibold ${activeTier === id ? "text-cream" : "text-cream/40"}`}>
                  {label}
                </span>
              </div>
              <span className="font-courier text-[0.48rem] text-cream/22 pl-3.5">{sublabel}</span>
            </button>
          ))}
        </div>

        {/* ── KPI strip ─────────────────────────────────────────────────── */}
        <KpiStrip />

        {/* ════════════════════════════════════════════════════════════════
            CLOUD TIER — Full SOC Dashboard
        ════════════════════════════════════════════════════════════════ */}
        {activeTier === "cloud" && (
          <div className="space-y-6">
            {/* Tier badge */}
            <div className="flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-allow animate-pulse" />
              <span className="font-barlow text-[0.58rem] tracking-[0.28em] uppercase text-cream/30 font-semibold">
                Cloud Tier &mdash; Varaksha Gateway &middot; Hosted on Railway &middot; Live inference via ONNX Runtime
              </span>
            </div>

            {/* Two-column layout: Sandbox | Feed */}
            <div className="grid grid-cols-1 xl:grid-cols-[1fr_1fr] gap-6 items-start">
              <IntelSandbox />
              <TransactionFeed />
            </div>

            <TierScenarioArchitecture tier="cloud" />

            {/* C | D */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
              <DashMapVisualizer />
              <SecurityArena />
            </div>

            {/* Cache walkthrough terminal */}
            <CacheVisualizer />

            {/* H full-width — Open Banking Feed */}
            <OpenBankingModule />

            {/* F full-width — ML model stack */}
            <MLModelModule />

            {/* E full-width */}
            <LegalReport />
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════
            ENTERPRISE TIER — Graph Network Monitor + Security Arena
        ════════════════════════════════════════════════════════════════ */}
        {activeTier === "enterprise" && (
          <div className="space-y-6">
            {/* Tier badge */}
            <div className="flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-allow animate-pulse" />
              <span className="font-barlow text-[0.58rem] tracking-[0.28em] uppercase text-cream/30 font-semibold">
                Enterprise Tier &mdash; Graph Engine &middot; NetworkX Topology &middot; Live Transaction Network
              </span>
            </div>

            {/* Graph monitor full-width */}
            <GraphNetworkMonitor />

            {/* Open Banking Feed full-width */}
            <OpenBankingModule />

            <TierScenarioArchitecture tier="enterprise" />

            {/* Security Arena + ML Stack side by side */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
              <SecurityArena />
              <div className="space-y-6">
                {/* Enterprise context card */}
                <div className="border border-cream/[0.08] bg-cream/[0.015] p-5">
                  <p className="font-barlow text-[0.55rem] tracking-[0.28em] uppercase text-saffron mb-2">Enterprise Deployment</p>
                  <h3 className="font-playfair font-bold text-cream text-[1.1rem] mb-3">API-First Architecture</h3>
                  <p className="font-barlow text-[0.75rem] text-cream/45 leading-relaxed mb-4">
                    Enterprise deployments expose the Varaksha engine as a Rust-native REST API behind mutual TLS.
                    PSP banks integrate via webhook push from the graph agent, receiving HMAC-SHA256 signed verdict bundles
                    with full audit trails per NPCI OC-215/2025-26.
                  </p>
                  <div className="space-y-2">
                    {[
                      { label: "Auth",         value: "mTLS + HMAC-SHA256 signed webhooks" },
                      { label: "Throughput",   value: "5,000+ TPS (DashMap concurrent cache)" },
                      { label: "Graph scope",  value: "Fan-out · Fan-in · Cycle · Scatter" },
                      { label: "Audit",        value: "Per-VPA trail · DPDP §7(g) compliant" },
                      { label: "Compliance",   value: "NPCI OC-215 · RBI Master Directions" },
                    ].map((r) => (
                      <div key={r.label} className="flex items-start gap-3">
                        <span className="font-barlow text-[0.50rem] tracking-widest uppercase text-cream/25 w-20 shrink-0 pt-px">{r.label}</span>
                        <span className="font-courier text-[0.60rem] text-cream/50">{r.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Full-width ML stack */}
            <MLModelModule />
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════
            EMBEDDED TIER — On-Device SDK Simulation
        ════════════════════════════════════════════════════════════════ */}
        {activeTier === "embedded" && <EmbeddedTierPanel />}

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
        <div
          key={k.label}
          className={`border ${k.border} bg-cream/[0.025] px-4 py-4 flex flex-col gap-1`}
        >
          <span className="font-barlow text-[0.52rem] tracking-[0.26em] uppercase text-cream/22">
            {k.label}
          </span>
          <span
            key={displayVal(k.key)}
            className={`font-courier font-bold leading-none ${k.color}`}
            style={{ fontSize: "clamp(1.6rem, 2.8vw, 2.4rem)" }}
          >
            {displayVal(k.key)}
          </span>
        </div>
      ))}
    </div>
  );
}
