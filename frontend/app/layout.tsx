import type { Metadata } from "next";
import { Playfair_Display, Barlow, Courier_Prime } from "next/font/google";
import Link from "next/link";
import "./globals.css";

// ── Font Definitions ──────────────────────────────────────────────────────────
// Each font is assigned a CSS custom property (variable) that Tailwind picks
// up via fontFamily in tailwind.config.ts.

const playfairDisplay = Playfair_Display({
  subsets: ["latin"],
  weight: ["400", "700", "900"],
  style: ["normal", "italic"],
  variable: "--font-playfair",
  display: "swap",
});

const barlow = Barlow({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  style: ["normal"],
  variable: "--font-barlow",
  display: "swap",
});

const courierPrime = Courier_Prime({
  subsets: ["latin"],
  weight: ["400", "700"],
  style: ["normal"],
  variable: "--font-courier",
  display: "swap",
});

// ── Metadata ──────────────────────────────────────────────────────────────────
export const metadata: Metadata = {
  title: "Varaksha V2 — UPI Fraud Defense Network",
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
      className={`
        ${playfairDisplay.variable}
        ${barlow.variable}
        ${courierPrime.variable}
      `}
    >
      {/*
       * font-barlow  → body copy
       * bg-cream     → #F7F2E8 parchment base
       * text-ink     → #1C1610 near-black
       * antialiased  → subpixel rendering
       */}
      <body className="bg-cream text-ink font-barlow antialiased">
        {/* ── Site-wide navigation ── */}
        <nav className="sticky top-0 z-50 border-b border-ink/10 bg-cream/90 backdrop-blur-sm">
          <div className="max-w-7xl mx-auto px-6 lg:px-12 flex items-center justify-between h-11">
            <Link
              href="/"
              className="font-playfair font-bold text-[1.05rem] text-ink tracking-tight hover:text-saffron transition-colors"
            >
              Varaksha<span className="text-saffron">.</span>
            </Link>
            <div className="flex items-center gap-6">
              <Link
                href="/"
                className="font-barlow text-[0.65rem] tracking-[0.22em] uppercase text-ink/50 hover:text-ink transition-colors"
              >
                Overview
              </Link>
              <Link
                href="/flow"
                className="font-barlow text-[0.65rem] tracking-[0.22em] uppercase text-ink/50 hover:text-ink transition-colors"
              >
                How It Works
              </Link>
              <Link
                href="/live"
                className="font-barlow text-[0.65rem] tracking-[0.22em] uppercase bg-ink text-cream px-3 py-1.5 hover:bg-saffron hover:text-ink transition-colors"
              >
                Live Demo
              </Link>
            </div>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
