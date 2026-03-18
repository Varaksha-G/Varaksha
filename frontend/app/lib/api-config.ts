/**
 * Determine the API base URL at runtime based on the current environment.
 * 
 * DESIGN RATIONALE:
 * - Uses runtime detection (window.location.hostname) instead of build-time env vars
 * - Build-time env vars (NEXT_PUBLIC_*) are baked into Next.js static exports
 * - Cloudflare Pages serves static exports, so env vars set at build time are immutable
 * - Runtime detection allows frontend to work without Cloudflare Pages build configuration
 * 
 * ENVIRONMENT DETECTION PRIORITY:
 * 1. window.location.hostname (runtime detection) - PREFERRED for production
 * 2. process.env.NEXT_PUBLIC_API_URL (if set in Cloudflare) - fallback
 * 3. Default Railway production URL - safe fallback
 * 
 * CLOUDFLARE PAGES SETUP (OPTIONAL but recommended):
 * - Go to Settings > Environment Variables
 * - Add NEXT_PUBLIC_API_URL = https://varaksha-production.up.railway.app
 * - This provides a backup if runtime detection fails
 */
export function getApiBase(): string {
  // Only in browser context (not during build/SSR)
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    const protocol = window.location.protocol; // http: or https:
    
    // Production: Cloudflare Pages serving from varaksha.pages.dev
    if (hostname === 'varaksha.pages.dev') {
      return 'https://varaksha-production.up.railway.app';
    }
    
    // Staging or custom domain on Cloudflare Pages
    if (hostname.endsWith('.pages.dev')) {
      return 'https://varaksha-production.up.railway.app';
    }
    
    // Local development (any localhost variant)
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
      // Preserve protocol if running on https://localhost (e.g., with local HTTPS proxy)
      const port = window.location.port ? `:${window.location.port}` : '';
      return `${protocol}//localhost${port === ':3000' ? ':8000' : port}`;
    }
  }

  // Build-time or server-side fallback: check env var (must be set in Cloudflare)
  const envUrl = process.env.NEXT_PUBLIC_API_URL;
  if (envUrl && envUrl.trim()) {
    const normalized = envUrl.endsWith('/') ? envUrl.slice(0, -1) : envUrl;
    if (normalized && normalized.startsWith('http')) {
      return normalized;
    }
  }

  // Final fallback: Railway production URL
  // This ensures frontend never breaks even if everything else fails
  return 'https://varaksha-production.up.railway.app';
}

/**
 * Get normalized API base URL (no trailing slash)
 */
export function getApiBaseNormalized(): string {
  const base = getApiBase();
  return base.endsWith('/') ? base.slice(0, -1) : base;
}
