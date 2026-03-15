import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      // ── Brand Colors ──────────────────────────────────────
      // Cream (#F0F4F8): cold off-white page background
      // Ink  (#0F1E2E): deep navy primary text & dark surfaces
      // Saffron (#2563EB): denim blue accent / primary action
      // Allow (#0D7A5F): teal-green verdict
      // Block (#C0392B): verdict red (universal danger)
      colors: {
        cream: "#F0F4F8",
        ink: "#0F1E2E",
        saffron: "#2563EB",
        allow: "#0D7A5F",
        block: "#C0392B",
        flag: "#D97706",   // amber — FLAG verdict only
      },

      // ── Brand Typefaces ───────────────────────────────────
      // Injected as CSS custom properties by next/font in layout.tsx
      fontFamily: {
        playfair: ["var(--font-playfair)", "Georgia", "serif"],
        barlow: ["var(--font-barlow)", "system-ui", "sans-serif"],
        courier: ["var(--font-courier)", "Courier New", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
