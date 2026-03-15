"use client";

import { useState, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

type LogColor = "info" | "ok" | "warn" | "error" | "gateway" | "layer" | "hindi";

interface LogEntry {
  text:  string;
  color: LogColor;
  delay: number;   // cumulative ms from attack start
}

type AttackId = "ddos" | "mule" | "ring";

interface AttackDef {
  id:         AttackId;
  label:      string;
  sublabel:   string;
  accentCls:  string;      // Tailwind border/text accent
  logs:       LogEntry[];
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK SCRIPTS
// ═══════════════════════════════════════════════════════════════════════════════

const ATTACKS: AttackDef[] = [
  // ── Attack 1: DDoS ────────────────────────────────────────────────────────
  {
    id:        "ddos",
    label:     "DDoS Flood",
    sublabel:  "150-request burst · rate-limiter · HTTP 429",
    accentCls: "border-block/40 text-block",
    logs: [
      { text: "[GATEWAY] DDoS simulation — injecting 150-request burst on /upi/verify",       color: "gateway", delay: 0    },
      { text: "[REQ-001] POST /upi/verify  192.168.42.7    →  3ms  ·  200 OK",                color: "ok",      delay: 280  },
      { text: "[REQ-002] POST /upi/verify  192.168.42.8    →  4ms  ·  200 OK",                color: "ok",      delay: 420  },
      { text: "[REQ-003] POST /upi/verify  10.0.0.14       →  3ms  ·  200 OK",                color: "ok",      delay: 540  },
      { text: "[REQ-004] POST /upi/verify  172.31.5.22     →  5ms  ·  200 OK",                color: "ok",      delay: 640  },
      { text: "[GATEWAY] Rate limiter: 10/150 requests processed — threshold: 100 (NPCI OC-215/2025-26)",   color: "gateway", delay: 820  },
      { text: "[REQ-050] POST /upi/verify  172.16.0.99     →  4ms  ·  200 OK",                color: "ok",      delay: 1100 },
      { text: "[GATEWAY] Velocity: 50 req/s — elevated — monitoring burst pattern",           color: "warn",    delay: 1320 },
      { text: "[REQ-100] POST /upi/verify  192.168.42.7    →  4ms  ·  200 OK  ← LIMIT",      color: "ok",      delay: 1600 },
      { text: "[GATEWAY] Burst ceiling reached — DashMap rate limiter ACTIVATED",             color: "warn",    delay: 1820 },
      { text: "[HTTP 429] Too Many Requests — NPCI OC-215/2025-26 cap — 50 subsequent requests rejected", color: "error",   delay: 2080 },
      { text: "[HTTP 429] Too Many Requests — 51 ...",                                        color: "error",   delay: 2200 },
      { text: "[HTTP 429] Too Many Requests — 52 ...",                                        color: "error",   delay: 2300 },
      { text: "[SHIELD ] DashMap read/write integrity: INTACT — 0 fraudulent writes",        color: "ok",      delay: 2620 },
      { text: "[GATEWAY] Attack absorbed. Cache consistent. Resuming normal operations.",     color: "gateway", delay: 2950 },
    ],
  },

  // ── Attack 2: Sneaky Mule ─────────────────────────────────────────────────
  {
    id:        "mule",
    label:     "Sneaky Mule",
    sublabel:  "₹99,999 @ 03:14 · ML ensemble intercept",
    accentCls: "border-flag/40 text-flag",
    logs: [
      { text: "[SIMULATION] Mule transaction — off-hours high-value transfer",                             color: "info",    delay: 0    },
      { text: "[TXN     ] suraj.thakur@okicici → cash.agent.77@paytm — ₹99,999 — 03:14:07 IST",          color: "warn",    delay: 380  },
      { text: "[L2-CACHE] SHA-256(suraj.thakur@okicici) → 7f3a9c12… — CLEAN (first occurrence)",         color: "layer",   delay: 820  },
      { text: "[L1-ML  ] Extracting 16 features: AMOUNT_LOG=11.51 | HOUR_SIN=-0.99 | VELOCITY_1H=1.00",  color: "layer",   delay: 1250 },
      { text: "[L1-ML  ] Random Forest (300 trees) — FRAUD vote: 0.89",                                  color: "warn",    delay: 1680 },
      { text: "[L1-ML  ] IsolationForest anomaly score — outlier confidence: 0.91",                       color: "warn",    delay: 2050 },
      { text: "[L1-ML  ] Ensemble composite: BLOCK — risk score 0.90  ■■■■■■■■■■ 90%",                  color: "error",   delay: 2420 },
      { text: "[L2-CACHE] Writing risk delta → DashMap[7f3a9c12]: { risk: 0.90, flag: MULE }",           color: "layer",   delay: 2750 },
      { text: "[GATEWAY] BLOCK issued — transaction halted before NPCI settlement window",                color: "error",   delay: 3080 },
      { text: "[ALERT  ] Neural TTS (hi-IN): \"रात के 3 बजे ₹99,999 — संदिग्ध लेन-देन रोका गया।\"",  color: "hindi",   delay: 3500 },
    ],
  },

  // ── Attack 3: Graph Ring ──────────────────────────────────────────────────
  {
    id:        "ring",
    label:     "Graph Ring",
    sublabel:  "A→B→C→D→A money cycle · 4th hop BLOCKED",
    accentCls: "border-allow/35 text-allow",
    logs: [
      { text: "[L3-GRAPH] Ring detection scan initiated — partition: ybl",                            color: "info",  delay: 0    },
      { text: "[HOP 1/4] wallet.alpha@ybl → wallet.beta@ybl — ₹45,000 — ALLOW — 6ms",               color: "ok",    delay: 400  },
      { text: "[GRAPH  ] wallet.beta@ybl: out-degree=1, in-degree=1 — no anomaly",                   color: "info",  delay: 680  },
      { text: "[HOP 2/4] wallet.beta@ybl → wallet.gamma@paytm — ₹44,500 — ALLOW — 7ms",             color: "ok",    delay: 1050 },
      { text: "[GRAPH  ] wallet.gamma@paytm: out-degree=1, in-degree=1 — no anomaly",                color: "info",  delay: 1320 },
      { text: "[HOP 3/4] wallet.gamma@paytm → wallet.delta@okicici — ₹44,000 — ALLOW — 8ms",        color: "ok",    delay: 1700 },
      { text: "[GRAPH  ] wallet.delta@okicici: out-degree=1, in-degree=1 — no anomaly",              color: "info",  delay: 1980 },
      { text: "[HOP 4/4] wallet.delta@okicici → wallet.alpha@ybl — ⚠  CYCLE DETECTED  ⚠",          color: "error", delay: 2380 },
      { text: "[L3-GRAPH] Confirmed: alpha→beta→gamma→delta→alpha. Depth: 4. Fee-skim: ₹500",       color: "error", delay: 2800 },
      { text: "[GATEWAY] BLOCK issued — all 4 wallets flagged in consortium DashMap",                 color: "error", delay: 3150 },
      { text: "[NETWORK] Cross-bank ring pattern shared to 8 member consortium banks",                color: "ok",    delay: 3550 },
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// STYLE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function logLineClass(c: LogColor): string {
  if (c === "ok")      return "text-allow";
  if (c === "error")   return "text-block";
  if (c === "warn")    return "text-saffron";
  if (c === "hindi")   return "text-saffron/90 font-medium";
  if (c === "gateway") return "text-cream/70";
  if (c === "layer")   return "text-cream/45";
  return "text-cream/50 font-semibold";   // info + fallback
}

function timestampBadge(c: LogColor): string {
  if (c === "ok")      return "text-allow/35";
  if (c === "error")   return "text-block/45";
  if (c === "warn")    return "text-flag/35";
  return "text-cream/15";
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

export function SecurityArena() {
  const [activeId,  setActiveId ] = useState<AttackId | null>(null);
  const [visible,   setVisible  ] = useState<LogEntry[]>([]);
  const [running,   setRunning  ] = useState(false);
  const timerRefs = useRef<ReturnType<typeof setTimeout>[]>([]);

  const clearTimers = useCallback(() => {
    timerRefs.current.forEach(clearTimeout);
    timerRefs.current = [];
  }, []);

  const runAttack = useCallback((attack: AttackDef) => {
    clearTimers();
    setActiveId(attack.id);
    setVisible([]);
    setRunning(true);

    attack.logs.forEach((entry, i) => {
      const t = setTimeout(() => {
        setVisible((v) => [...v, entry]);
        if (i === attack.logs.length - 1) {
          setRunning(false);
        }
      }, entry.delay);
      timerRefs.current.push(t);
    });
  }, [clearTimers]);

  const handleReset = useCallback(() => {
    clearTimers();
    setVisible([]);
    setRunning(false);
    setActiveId(null);
  }, [clearTimers]);

  // Derive a start-time string once per run for log timestamps
  const startTs = useRef("00:00:00");
  const handleAttack = useCallback((attack: AttackDef) => {
    if (running) return;
    startTs.current = new Date().toTimeString().slice(0, 8);
    runAttack(attack);
  }, [running, runAttack]);

  return (
    <section className="border border-cream/[0.08] overflow-hidden flex flex-col">

      {/* ── Module header ── */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-cream/[0.07] bg-cream/[0.025] shrink-0">
        <div className="flex items-center gap-2.5">
          <motion.span
            className={`inline-block w-1.5 h-1.5 rounded-full ${running ? "bg-block" : "bg-cream/22"}`}
            animate={running ? { opacity: [1, 0.2, 1] } : { opacity: 1 }}
            transition={running ? { duration: 0.55, repeat: Infinity } : {}}
          />
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/60 font-semibold">
            Module D — Security Arena
          </span>
        </div>
        <AnimatePresence>
          {(visible.length > 0 || activeId) && (
            <motion.button
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={handleReset}
              className="font-barlow text-[0.54rem] tracking-[0.22em] uppercase text-cream/28 hover:text-saffron transition-colors"
            >
              ✕&thinsp;Clear
            </motion.button>
          )}
        </AnimatePresence>
      </div>

      {/* ── Attack trigger buttons ── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-0 border-b border-cream/[0.07] shrink-0">
        {ATTACKS.map((atk) => {
          const isActive = activeId === atk.id;
          return (
            <button
              key={atk.id}
              onClick={() => handleAttack(atk)}
              disabled={running}
              className={`group relative px-5 py-4 text-left border-r last:border-r-0 border-cream/[0.06] transition-all duration-200 ${
                running
                  ? "cursor-not-allowed opacity-40"
                  : "cursor-pointer hover:bg-cream/[0.03]"
              } ${isActive ? `bg-cream/[0.04] ${atk.accentCls.split(" ")[0]}/10` : ""}`}
            >
              {/* Active indicator */}
              <AnimatePresence>
                {isActive && (
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: "100%" }}
                    transition={{ duration: (ATTACKS.find(a => a.id === atk.id)?.logs.at(-1)?.delay ?? 3000) / 1000, ease: "linear" }}
                    className={`absolute bottom-0 left-0 h-[2px] ${
                      atk.id === "ddos" ? "bg-block" :
                      atk.id === "mule" ? "bg-flag" :
                                          "bg-allow"
                    }`}
                  />
                )}
              </AnimatePresence>

              <p className={`font-courier text-[0.78rem] font-bold mb-1 transition-colors ${
                isActive ? atk.accentCls.split(" ")[1] : "text-cream/55 group-hover:text-cream/80"
              }`}>
                {atk.label}
              </p>
              <p className="font-barlow text-[0.55rem] text-cream/22 leading-relaxed">
                {atk.sublabel}
              </p>
            </button>
          );
        })}
      </div>

      {/* ── Log console ── */}
      <div className="flex-1 bg-[#060f1c] overflow-y-auto" style={{ maxHeight: "320px" }}>
        {visible.length === 0 ? (
          <div className="flex items-center justify-center h-32">
            <p className="font-barlow text-[0.62rem] tracking-widest uppercase text-cream/14">
              Select an attack simulation above to begin streaming
            </p>
          </div>
        ) : (
          <div className="p-4 space-y-1.5">
            <AnimatePresence initial={false}>
              {visible.map((log, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1,  x: 0   }}
                  transition={{ duration: 0.22 }}
                  className="flex items-start gap-3"
                >
                  {/* Sequence number */}
                  <span className={`font-courier text-[0.55rem] tabular-nums shrink-0 pt-px ${timestampBadge(log.color)}`}>
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  {/* Log line */}
                  <p className={`font-courier text-[0.72rem] leading-relaxed break-words min-w-0 ${logLineClass(log.color)}`}>
                    {log.text}
                  </p>
                </motion.div>
              ))}
            </AnimatePresence>

            {/* Blinking cursor while running */}
            {running && (
              <div className="flex items-center gap-3 pt-0.5">
                <span className="font-courier text-[0.55rem] text-cream/12 shrink-0">
                  {String(visible.length + 1).padStart(2, "0")}
                </span>
                <motion.span
                  className="inline-block w-[7px] h-[13px] bg-saffron/50"
                  animate={{ opacity: [1, 0, 1] }}
                  transition={{ duration: 0.5, repeat: Infinity }}
                />
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Status footer ── */}
      <div className="px-5 py-2.5 border-t border-cream/[0.06] shrink-0 flex items-center justify-between">
        <span className="font-barlow text-[0.48rem] tracking-widest uppercase text-cream/16">
          {running
            ? `Streaming ${activeId ?? ""} attack…`
            : activeId
              ? `Simulation complete — ${visible.length} log entries`
              : "Ready"}
        </span>
        <span className="font-courier text-[0.48rem] text-cream/12">
          {startTs.current}
        </span>
      </div>

    </section>
  );
}
