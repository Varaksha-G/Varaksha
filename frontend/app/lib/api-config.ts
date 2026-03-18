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
 * 1. process.env.NEXT_PUBLIC_API_URL (if set in Cloudflare) - PREFERRED for production
 * 2. window.location.hostname (runtime detection) - fallback
 * 3. Detection for .pages.dev domains (Cloudflare production)
 * 4. Local development on localhost/127.0.0.1
 * 
 * CLOUDFLARE PAGES SETUP (REQUIRED for production):
 * - Go to Settings > Environment Variables
 * - Add NEXT_PUBLIC_API_URL = https://your-railway-backend.up.railway.app
 * - This is the PRIMARY method - should be set in production
 */
export function getApiBase(): string {
  // FIRST: Check environment variable (build-time override from Cloudflare)
  // This should be explicitly set in Cloudflare Pages environment variables
  const envUrl = process.env.NEXT_PUBLIC_API_URL;
  if (envUrl && envUrl.trim()) {
    const normalized = envUrl.endsWith('/') ? envUrl.slice(0, -1) : envUrl;
    if (normalized && normalized.startsWith('http')) {
      return normalized;
    }
  }

  // FALLBACK: Runtime detection based on hostname
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    const protocol = window.location.protocol; // http: or https:
    
    // Production: Cloudflare Pages serving from varaksha.pages.dev or similar
    if (hostname.endsWith('.pages.dev')) {
      // IMPORTANT: This requires NEXT_PUBLIC_API_URL to be set in Cloudflare
      // If not set, requests to Railway may fail due to dynamic routing
      // Default to Railway production but this may not work
      return 'https://varaksha-production.up.railway.app';
    }
    
    // Local development (any localhost variant)
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
      // For local dev, use the port from the frontend (3000 → gateway :8000)
      // If gateway is on a different port, override with API_URL env var
      const port = window.location.port ? `:${window.location.port}` : '';
      // Local frontend on :3000 or :3001 → backend on :8000
      // Local frontend on other port → use that port for backend too
      const backendPort = port === ':3000' || port === ':3001' ? ':8000' : port;
      return `${protocol}//localhost${backendPort}`;
    }
  }

  // FINAL FALLBACK: Railway production URL
  // This ensures frontend loads but may not connect to correct backend
  // User should set NEXT_PUBLIC_API_URL in Cloudflare Pages
  return 'https://varaksha-production.up.railway.app';
}

/**
 * Get normalized API base URL (no trailing slash)
 */
export function getApiBaseNormalized(): string {
  const base = getApiBase();
  return base.endsWith('/') ? base.slice(0, -1) : base;
}

/**
 * Get API URL with detailed debug information
 * Useful for troubleshooting connection issues
 */
export function getApiDebugInfo(): string {
  const apiBase = getApiBase();
  const envUrl = process.env.NEXT_PUBLIC_API_URL;
  const hostname = typeof window !== 'undefined' ? window.location.hostname : 'unknown';
  
  return [
    `API Base: ${apiBase}`,
    `Hostname: ${hostname}`,
    `NEXT_PUBLIC_API_URL: ${envUrl || 'NOT SET (using defaults)'}`,
  ].join(' | ');
}
