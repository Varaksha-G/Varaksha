import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Static export for Cloudflare Pages (no Node.js runtime needed)
  output: "export",
  // Disable image optimisation — CF Pages serves images from its CDN directly
  images: { unoptimized: true },
};

export default nextConfig;
