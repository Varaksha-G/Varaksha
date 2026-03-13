"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";

// ═══════════════════════════════════════════════════════════════════════════════
// DATA
// ═══════════════════════════════════════════════════════════════════════════════

type Verdict   = "ALLOW" | "FLAG" | "BLOCK";
type LineColor = "dim" | "normal" | "allow" | "block" | "flag" | "saffron";

interface CacheEntry {
  vpa:        string;
  hash:       string;   // full 64-char hex
  risk:       number;
  verdict:    Verdict;
  hitType:    "HIT" | "MISS";
  consortium: string;
}

// Pre-computed fake-but-plausible SHA-256 digests — no runtime hashing needed
const CACHE_POOL: CacheEntry[] = [
  {
    vpa: "ravi.kumar@axisbank",
    hash: "a3f8c2d9e1b04f724c7d1b83e95720f1a46b8c3d2e9f0175e3084b6c91a7f28e",
    risk: 0.08, verdict: "ALLOW", hitType: "HIT",  consortium: "CLEAN",
  },
  {
    vpa: "suspicious.x@paytm",
    hash: "f7e2910ac583d1b4902871ea6cd048f37b259182acf7e30d1c94b782659a07e1c",
    risk: 0.91, verdict: "BLOCK", hitType: "HIT",  consortium: "TAINTED",
  },
  {
    vpa: "priya.sharma@okicici",
    hash: "2d0f741e853cb6900c284b1a79c31e6d5f70e9243b48ad1c7a0f2e8b4591735dc",
    risk: 0.15, verdict: "ALLOW", hitType: "HIT",  consortium: "CLEAN",
  },
  {
    vpa: "transfer.agent@ybl",
    hash: "8c195b60d2fae07431a7b2e9546f801c3d92170bea4c68257f0139476b328690a",
    risk: 0.78, verdict: "FLAG",  hitType: "HIT",  consortium: "SUSPECT",
  },
  {
    vpa: "meera.iyer@paytm",
    hash: "5b48c1a9f2e360d74a02c758b1e93674f0218a3c4d9e870b6c1f52d3849b01e5f",
    risk: 0.12, verdict: "ALLOW", hitType: "MISS", consortium: "UNKNOWN",
  },
  {
    vpa: "crypto.convert@okaxis",
    hash: "e920a478f13c6b52d047f305a98c172e4b86d95c1a7e30f24db781659704fe21b",
    risk: 0.87, verdict: "BLOCK", hitType: "HIT",  consortium: "TAINTED",
  },
];

const AUTO_ADVANCE_MS = 5000;
const CHAR_DELAY_MS   = 22;    // ms per typed character
const API_BASE        = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

type Phase = "idle" | "query" | "hashing" | "lookup" | "verdict";

interface TermLine { key: string; text: string; color: LineColor; }

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function verdictLineColor(v: Verdict): LineColor {
  if (v === "ALLOW") return "allow";
  if (v === "BLOCK") return "block";
  return "flag";
}

function consortiumColor(c: string): LineColor {
  if (c === "TAINTED") return "block";
  if (c === "SUSPECT") return "flag";
  if (c === "UNKNOWN") return "dim";
  return "allow";
}

function lineClass(c: LineColor): string {
  if (c === "allow")   return "text-allow";
  if (c === "block")   return "text-block";
  if (c === "flag")    return "text-flag";
  if (c === "saffron") return "text-saffron/60";
  if (c === "dim")     return "text-cream/25";
  return "text-cream/58";
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

export function CacheVisualizer() {
  const [pool,      setPool     ] = useState<CacheEntry[]>(CACHE_POOL);
  const [entryIdx,  setEntryIdx ] = useState(0);
  const [phase,     setPhase    ] = useState<Phase>("idle");
  const [typedHash, setTypedHash] = useState("");
  const [lines,     setLines    ] = useState<TermLine[]>([]);
  const [running,   setRunning  ] = useState(false);

  // Track internal timers so we can cancel on re-run or unmount
  const typeIntervalRef = useRef<ReturnType<typeof setInterval>  | null>(null);
  const autoTimerRef    = useRef<ReturnType<typeof setTimeout>   | null>(null);
  const stageTimersRef  = useRef<ReturnType<typeof setTimeout>[] >([]);

  const clearAllTimers = useCallback(() => {
    if (typeIntervalRef.current) clearInterval(typeIntervalRef.current);
    if (autoTimerRef.current)    clearTimeout(autoTimerRef.current);
    stageTimersRef.current.forEach(clearTimeout);
    stageTimersRef.current = [];
  }, []);

  const runLookup = useCallback((idx: number) => {
    clearAllTimers();
    if (pool.length === 0) return;
    const e = pool[idx % pool.length];
    setRunning(true);
    setTypedHash("");
    setPhase("query");
    setLines([{ key: "q", text: `> QUERY    ${e.vpa}`, color: "normal" }]);

    // Stage 1: show HASHING label
    const t1 = setTimeout(() => {
      setPhase("hashing");
      setLines((l) => [
        ...l,
        { key: "h", text: "> HASHING  SHA-256 …", color: "saffron" },
      ]);

      // Stage 2: type hash character by character
      let charIdx = 0;
      typeIntervalRef.current = setInterval(() => {
        charIdx++;
        setTypedHash(e.hash.slice(0, charIdx));
        if (charIdx >= e.hash.length) {
          clearInterval(typeIntervalRef.current!);
          typeIntervalRef.current = null;

          // Stage 3: show abbreviated digest
          const t3 = setTimeout(() => {
            setLines((l) => [
              ...l,
              {
                key:   "d",
                text:  `> DIGEST   ${e.hash.slice(0, 16)}…${e.hash.slice(-8)}`,
                color: "dim",
              },
            ]);

            // Stage 4: cache hit/miss line
            const t4 = setTimeout(() => {
              setPhase("lookup");
              setLines((l) => [
                ...l,
                {
                  key:   "l",
                  text:  `> CACHE    ${e.hitType}  { risk: ${e.risk.toFixed(2)}, consortium: ${e.consortium} }`,
                  color: consortiumColor(e.consortium),
                },
              ]);

              // Stage 5: verdict
              const t5 = setTimeout(() => {
                setPhase("verdict");
                setLines((l) => [
                  ...l,
                  {
                    key:   "v",
                    text:  `> VERDICT  ${e.verdict}`,
                    color: verdictLineColor(e.verdict),
                  },
                ]);
                setRunning(false);
              }, 420);
              stageTimersRef.current.push(t5);
            }, 480);
            stageTimersRef.current.push(t4);
          }, 220);
          stageTimersRef.current.push(t3);
        }
      }, CHAR_DELAY_MS);
    }, 380);
    stageTimersRef.current.push(t1);
  }, [clearAllTimers, pool]);

  useEffect(() => {
    let cancelled = false;

    const loadCache = async () => {
      try {
        const res = await fetch(`${API_BASE}/v1/cache`);
        if (!res.ok) return;
        const data = await res.json();
        if (cancelled || !Array.isArray(data)) return;

        const mapped: CacheEntry[] = data.slice(0, 6).map((e: any, i: number) => {
          const hash = String(e.key || "");
          const risk = Number(e.risk_score || 0);
          const verdict: Verdict = risk >= 0.75 ? "BLOCK" : risk >= 0.4 ? "FLAG" : "ALLOW";
          return {
            vpa: `hash_${i + 1}`,
            hash,
            risk,
            verdict,
            hitType: "HIT" as const,
            consortium: String(verdict === "BLOCK" ? "TAINTED" : verdict === "FLAG" ? "SUSPECT" : "CLEAN"),
          };
        }).filter((e: CacheEntry) => e.hash.length > 0);

        if (mapped.length > 0) {
          setPool(mapped);
          setEntryIdx(0);
        }
      } catch {
        // keep local fallback cache pool
      }
    };

    loadCache();
    const timer = setInterval(loadCache, 4000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  // Run on mount
  useEffect(() => {
    runLookup(0);
    return clearAllTimers;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-advance after each run completes
  useEffect(() => {
    if (pool.length === 0) return;
    if (running) return;
    if (phase === "idle") return;
    autoTimerRef.current = setTimeout(() => {
      const nextIdx = (entryIdx + 1) % pool.length;
      setEntryIdx(nextIdx);
      runLookup(nextIdx);
    }, AUTO_ADVANCE_MS);
    return () => {
      if (autoTimerRef.current) clearTimeout(autoTimerRef.current);
    };
  }, [running, phase, entryIdx, runLookup, pool.length]);

  const handleQueryNext = useCallback(() => {
    if (running) return;
    if (pool.length === 0) return;
    const nextIdx = (entryIdx + 1) % pool.length;
    setEntryIdx(nextIdx);
    runLookup(nextIdx);
  }, [running, entryIdx, runLookup, pool.length]);

  const entry = pool[entryIdx] || CACHE_POOL[0];

  return (
    <section className="border border-cream/[0.08] overflow-hidden flex flex-col">

      {/* ── Module header ── */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-cream/[0.07] bg-cream/[0.025] shrink-0">
        <div className="flex items-center gap-2.5">
          <motion.span
            className="inline-block w-1.5 h-1.5 rounded-full bg-saffron"
            animate={{ opacity: running ? [1, 0.15, 1] : 1 }}
            transition={running ? { duration: 0.55, repeat: Infinity } : {}}
          />
          <span className="font-barlow text-[0.57rem] tracking-[0.30em] uppercase text-cream/60 font-semibold">
            Module C — Rust DashMap Cache
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="font-courier text-[0.52rem] text-cream/18">
            {entryIdx + 1}&thinsp;/&thinsp;{pool.length}
          </span>
          <button
            onClick={handleQueryNext}
            disabled={running}
            className={`font-barlow text-[0.54rem] tracking-[0.22em] uppercase border px-2.5 py-1 transition-colors ${
              running
                ? "border-cream/8 text-cream/16 cursor-not-allowed"
                : "border-saffron/35 text-saffron/70 hover:border-saffron/60 hover:text-saffron cursor-pointer"
            }`}
          >
            Query Next
          </button>
        </div>
      </div>

      {/* ── Terminal body ── */}
      <div className="p-5 bg-[#071628] flex-1 min-h-[240px]">
        {/* CLI meta header */}
        <p className="font-courier text-[0.52rem] tracking-widest text-cream/15 mb-5">
          varaksha-gateway-v2&thinsp;·&thinsp;dashmap-cache-cli&thinsp;·&thinsp;rust 1.82&thinsp;·&thinsp;sha2 crate
        </p>

        {/* Settled lines */}
        <div className="space-y-2.5">
          {lines.map((line) => (
            <motion.p
              key={line.key}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.18 }}
              className={`font-courier text-[0.74rem] leading-relaxed ${lineClass(line.color)}`}
            >
              {line.text}
            </motion.p>
          ))}
        </div>

        {/* Live typing: hash characters */}
        <AnimatePresence>
          {phase === "hashing" &&
            typedHash.length > 0 &&
            typedHash.length < entry.hash.length && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="mt-3"
              >
                <p className="font-courier text-[0.67rem] text-cream/20 break-all leading-loose">
                  <span className="text-cream/10">  computing: </span>
                  <span className="text-cream/35">{typedHash}</span>
                  <motion.span
                    className="inline-block w-[7px] h-[12px] bg-saffron/60 ml-0.5 align-middle"
                    animate={{ opacity: [1, 0, 1] }}
                    transition={{ duration: 0.45, repeat: Infinity }}
                  />
                </p>
              </motion.div>
            )}
        </AnimatePresence>

        {/* Idle cursor after verdict */}
        {!running && phase === "verdict" && (
          <p className="mt-3 font-courier text-[0.74rem] text-cream/25 flex items-center gap-1.5">
            <span>$</span>
            <motion.span
              className="inline-block w-[7px] h-[14px] bg-cream/35"
              animate={{ opacity: [1, 0, 1] }}
              transition={{ duration: 0.85, repeat: Infinity }}
            />
          </p>
        )}
      </div>

      {/* ── Entry dots footer ── */}
      <div className="px-5 py-2.5 border-t border-cream/[0.05] flex items-center gap-1.5">
        {pool.map((e, i) => (
          <motion.div
            key={i}
            className={`w-1.5 h-1.5 rounded-full transition-colors duration-400 ${
              i === entryIdx
                ? e.verdict === "BLOCK"  ? "bg-block"
                : e.verdict === "FLAG"   ? "bg-flag"
                :                          "bg-allow"
                : "bg-cream/10"
            }`}
            animate={i === entryIdx ? { scale: [1, 1.5, 1] } : { scale: 1 }}
            transition={{ duration: 0.6 }}
          />
        ))}
        <span className="font-barlow text-[0.46rem] tracking-widest uppercase text-cream/14 ml-auto">
          Auto-cycling&thinsp;·&thinsp;{AUTO_ADVANCE_MS / 1000}s
        </span>
      </div>

    </section>
  );
}
