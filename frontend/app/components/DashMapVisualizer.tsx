"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type EventKind = "HIT" | "MISS" | "EVICT";

interface StreamEvent {
  idx: number;
  kind: EventKind;
  key: string;
  message: string;
}

function shortKey(seed: number): string {
  const x = (seed * 2654435761) >>> 0;
  return x.toString(16).padStart(8, "0");
}

function eventMessage(kind: EventKind, key: string, seq: number) {
  const amount = [499, 1200, 4750, 9800, 25000, 65000][seq % 6];
  const category = ["FOOD", "UTILITY", "ECOM", "TRAVEL", "GAMBLING", "P2P"][seq % 6];
  const risk = kind === "HIT" ? (0.08 + (seq % 5) * 0.07).toFixed(2) : kind === "MISS" ? (0.52 + (seq % 3) * 0.11).toFixed(2) : "0.91";

  if (kind === "HIT") {
    return `> CACHE_HIT key=${key} risk=${risk} verdict=ALLOW amount=Rs.${amount} cat=${category} reason=known_behavior`;
  }
  if (kind === "MISS") {
    return `> CACHE_MISS key=${key} risk=${risk} verdict=FLAG amount=Rs.${amount} cat=${category} action=route_to_ml_graph`;
  }
  return `> INTERCEPT key=${key} risk=${risk} verdict=BLOCK amount=Rs.${amount} cat=${category} reason=velocity_spike_plus_new_device`;
}

export function useMockCacheStream(tps = 320, cells = 72 * 26) {
  const queueRef = useRef<StreamEvent[]>([]);
  const statsRef = useRef({ hit: 0, miss: 0, evict: 0, total: 0 });
  const seqRef = useRef(1);

  useEffect(() => {
    const eventsPerTick = Math.max(1, Math.floor(tps / 16));
    const timer = setInterval(() => {
      const batch: StreamEvent[] = [];
      for (let i = 0; i < eventsPerTick; i += 1) {
        const s = seqRef.current++;
        const r = (s * 1103515245 + 12345) & 1023;
        const kind: EventKind = r < 790 ? "HIT" : r < 970 ? "MISS" : "EVICT";
        const idx = (s * 48271) % cells;
        const key = shortKey(s);
        batch.push({ idx, kind, key, message: eventMessage(kind, key, s) });
      }

      queueRef.current.push(...batch);
      if (queueRef.current.length > 2400) {
        queueRef.current.splice(0, queueRef.current.length - 2400);
      }
    }, 60);

    return () => clearInterval(timer);
  }, [cells, tps]);

  return { queueRef, statsRef };
}

export function DashMapVisualizer() {
  const cols = 72;
  const rows = 26;
  const totalCells = cols * rows;
  const { queueRef, statsRef } = useMockCacheStream(320, totalCells);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const stateRef = useRef<Uint8Array>(new Uint8Array(totalCells));
  const kindRef = useRef<Uint8Array>(new Uint8Array(totalCells));
  const logsRef = useRef<string[]>([]);
  const [stats, setStats] = useState({ hit: 0, miss: 0, evict: 0, total: 0 });
  const [ticker, setTicker] = useState<string[]>([]);

  const palette = useMemo(
    () => ({
      bg: "#0f1e2e",
      hit: "#0D7A5F",
      miss: "#D97706",
      evict: "#C0392B",
      dim: "#163149",
    }),
    [],
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) return;

    const dpr = Math.max(1, window.devicePixelRatio || 1);
    const rect = canvas.getBoundingClientRect();
    canvas.width = Math.floor(rect.width * dpr);
    canvas.height = Math.floor(rect.height * dpr);
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;
    const gap = 1;
    const cellW = (w - (cols - 1) * gap) / cols;
    const cellH = (h - (rows - 1) * gap) / rows;

    let raf = 0;

    const draw = () => {
      const batch = queueRef.current.splice(0, Math.min(queueRef.current.length, 40));

      for (const ev of batch) {
        stateRef.current[ev.idx] = 8;
        kindRef.current[ev.idx] = ev.kind === "HIT" ? 1 : ev.kind === "MISS" ? 2 : 3;

        statsRef.current.total += 1;
        if (ev.kind === "HIT") statsRef.current.hit += 1;
        if (ev.kind === "MISS") statsRef.current.miss += 1;
        if (ev.kind === "EVICT") statsRef.current.evict += 1;

        logsRef.current.push(ev.message);
      }

      if (logsRef.current.length > 140) {
        logsRef.current.splice(0, logsRef.current.length - 140);
      }

      ctx.fillStyle = palette.bg;
      ctx.fillRect(0, 0, w, h);

      for (let r = 0; r < rows; r += 1) {
        for (let c = 0; c < cols; c += 1) {
          const idx = r * cols + c;
          const life = stateRef.current[idx];
          const kind = kindRef.current[idx];

          const x = c * (cellW + gap);
          const y = r * (cellH + gap);

          if (life === 0) {
            ctx.fillStyle = palette.dim;
            ctx.fillRect(x, y, cellW, cellH);
            continue;
          }

          const alpha = 0.22 + (life / 8) * 0.78;
          const color = kind === 1 ? palette.hit : kind === 2 ? palette.miss : palette.evict;
          ctx.fillStyle = `${color}${Math.round(alpha * 255)
            .toString(16)
            .padStart(2, "0")}`;
          ctx.fillRect(x, y, cellW, cellH);
          stateRef.current[idx] = Math.max(0, life - 1);
        }
      }

      raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [cols, palette, queueRef, rows, statsRef]);

  useEffect(() => {
    const timer = setInterval(() => {
      setStats({ ...statsRef.current });
      setTicker(logsRef.current.slice(-24));
    }, 280);
    return () => clearInterval(timer);
  }, [statsRef]);

  return (
    <section className="border border-cream/[0.08] bg-ink/95 overflow-hidden">
      <div className="px-4 py-3 border-b border-cream/[0.08] flex items-center justify-between">
        <span className="font-barlow text-[0.56rem] tracking-[0.28em] uppercase text-cream/45">
          Rust DashMap Live Cam
        </span>
        <span className="font-courier text-[0.55rem] text-cream/30">~320 TPS simulated · presentation mode</span>
      </div>

      <div className="px-4 pt-4 pb-3">
        <div className="relative border border-cream/[0.08] bg-[#081522]">
          <canvas ref={canvasRef} className="block w-full h-[220px]" />
          <div
            className="pointer-events-none absolute inset-0"
            style={{
              backgroundImage:
                "repeating-linear-gradient(0deg, rgba(255,255,255,0.00), rgba(255,255,255,0.00) 2px, rgba(255,255,255,0.03) 3px)",
            }}
          />
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-3">
          <div className="border border-allow/20 bg-allow/10 px-2 py-1">
            <p className="font-barlow text-[0.5rem] tracking-widest uppercase text-allow/70">Hit</p>
            <p className="font-courier text-[0.78rem] text-allow">{stats.hit.toLocaleString("en-IN")}</p>
          </div>
          <div className="border border-flag/20 bg-flag/10 px-2 py-1">
            <p className="font-barlow text-[0.5rem] tracking-widest uppercase text-flag/70">Miss</p>
            <p className="font-courier text-[0.78rem] text-flag">{stats.miss.toLocaleString("en-IN")}</p>
          </div>
          <div className="border border-block/20 bg-block/10 px-2 py-1">
            <p className="font-barlow text-[0.5rem] tracking-widest uppercase text-block/70">Intercept</p>
            <p className="font-courier text-[0.78rem] text-block">{stats.evict.toLocaleString("en-IN")}</p>
          </div>
          <div className="border border-cream/20 bg-cream/[0.04] px-2 py-1">
            <p className="font-barlow text-[0.5rem] tracking-widest uppercase text-cream/35">Total</p>
            <p className="font-courier text-[0.78rem] text-cream/70">{stats.total.toLocaleString("en-IN")}</p>
          </div>
        </div>
      </div>

      <div className="border-t border-cream/[0.08] bg-[#07111d] px-3 py-2">
        <div className="h-32 overflow-hidden relative border border-cream/[0.08] bg-black/25">
          <div className="absolute inset-0 p-2 font-courier text-[0.62rem] leading-[1.35] text-cream/60">
            {ticker.map((line, i) => (
              <div key={`${line}-${i}`}>{line}</div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
