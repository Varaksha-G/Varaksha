import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

// ── Font Definitions ──────────────────────────────────────────────────────────
// Fonts are self-hosted from public/fonts/ via @font-face in globals.css.
// The CSS custom properties are applied to the html element below.
// Tailwind fontFamily config references these custom properties as fallbacks.

// ── Metadata ──────────────────────────────────────────────────────────────────
export const metadata: Metadata = {
  title: "Varaksha — UPI Fraud Defense Network",
  description:
    "Privacy-preserving collaborative UPI fraud intelligence. " +
    "Rust gateway delivers ALLOW / FLAG / BLOCK verdicts in <10ms, " +
    "decoupled from the heavy ML ensemble and graph traversal off the critical path.",
};

// ── Root Layout ───────────────────────────────────────────────────────────────
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
    >
      {/*
       * font-barlow  → body copy (self-hosted from public/fonts/)
       * bg-cream     → #F0F4F8 cold off-white base
       * text-ink     → #0F1E2E deep navy
       * antialiased  → subpixel rendering
       */}
      <body className="bg-cream text-ink font-barlow antialiased">
        {/* ── Site-wide navigation ── */}
        <nav className="sticky top-0 z-50 border-b border-white/40 bg-white/25 backdrop-blur-xl shadow-[0_2px_32px_rgba(15,30,46,0.10),inset_0_1px_0_rgba(255,255,255,0.6)]">
          <div className="max-w-7xl mx-auto px-6 lg:px-12 flex items-center justify-between h-11">
            <Link
              href="/"
              className="font-playfair font-bold text-[1.05rem] text-ink tracking-tight hover:text-saffron transition-colors"
            >
              Varaksha<span className="text-saffron">.</span>
            </Link>
            <div className="flex items-center gap-1">
              {(
                [
                  { href: "/",        label: "Overview"     },
                  { href: "/flow",    label: "How It Works" },
                  { href: "/timeline",label: "Timeline"     },
                ] as const
              ).map(({ href, label }) => (
                <Link
                  key={href}
                  href={href}
                  className="group relative font-barlow text-[0.65rem] tracking-[0.22em] uppercase text-ink/70 hover:text-ink px-3 py-1.5 rounded-sm cursor-pointer transition-all duration-200 hover:bg-ink/[0.06] active:scale-95 font-semibold"
                >
                  {label}
                  {/* animated underline */}
                  <span className="absolute bottom-0.5 left-3 right-3 h-px bg-ink/30 scale-x-0 group-hover:scale-x-100 transition-transform duration-200 origin-left" />
                </Link>
              ))}

              {/* Live Demo — blinking green */}
              <Link
                href="/live"
                className="ml-3 flex items-center gap-2 font-barlow text-[0.65rem] tracking-[0.22em] uppercase bg-ink text-cream px-3 py-1.5 rounded-sm cursor-pointer hover:bg-ink/80 active:scale-95 transition-all duration-200 shadow-[0_2px_12px_rgba(15,30,46,0.25)] hover:shadow-[0_4px_20px_rgba(15,30,46,0.35)]"
              >
                {/* pulse dot */}
                <span className="relative flex h-2 w-2 shrink-0">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-80" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
                </span>
                Live Demo
              </Link>
            </div>
          </div>
        </nav>
        {children}

        {/*
         * ── DPDP Act 2023 Notice ──────────────────────────────────────────────
         * §5 and DPDP Rules 2025 Rule 3 require a notice to be provided to the
         * Data Principal before or at the time data is collected.
         *
         * This site is a demonstration and research prototype.  No personal data
         * is collected, stored, or transmitted to any server by this website.
         * All transaction flows shown on the /live page use synthetic VPAs
         * generated from hardcoded seed data.  The sandbox form processes inputs
         * entirely inside your browser — nothing leaves your device.
         *
         * If you deploy the Varaksha backend gateway in production, you must:
         *   1. Obtain free, specific, informed and unambiguous consent per §6
         *      before passing any real VPA to POST /v1/tx.
         *   2. Provide a privacy notice in the Data Principal's preferred language
         *      per DPDP Rules 2025 Rule 3.
         *   3. Register as a Data Fiduciary if processing personal data at scale
         *      per §10 (Significant Data Fiduciary criteria).
         *   4. Implement Data Principal rights (access, correction, erasure,
         *      nomination, grievance) per §§12–13.
         *
         * For grievances contact: privacy@varaksha.dev (placeholder)
         * ────────────────────────────────────────────────────────────────────────
         */}
        <footer className="border-t border-ink/[0.07] mt-0 py-4 px-6 lg:px-12">
          <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <p className="font-barlow text-[0.6rem] text-ink/35 leading-relaxed max-w-2xl">
              <span className="font-semibold text-ink/70">Demo prototype.</span>{" "}
              No personal data is collected or transmitted. All transactions on this site use synthetic data.
              {" "}Varaksha backend deployments must obtain user consent per{" "}
              <span className="text-ink/70 font-semibold">DPDP Act 2023 §4(1)</span>{" "}or invoke the{" "}
              <span className="text-ink/70 font-semibold">§7(g) Legitimate Use for Security</span>{" "}exemption before processing real VPAs.
            </p>
            <p className="font-barlow text-[0.58rem] text-ink/25 shrink-0">
              Grievances:{" "}
              <span className="text-ink/60 font-semibold">privacy@varaksha.dev</span>
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
