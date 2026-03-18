# Frontend Build & Deployment Guide

## Problem
When deploying to Cloudflare Pages with Next.js static export (`output: "export"`), environment variables prefixed with `NEXT_PUBLIC_*` are baked into the JavaScript bundle at **build time**, not runtime. If `NEXT_PUBLIC_API_URL` is not set during the Cloudflare Pages build, the frontend cannot find the backend.

## Solution: Runtime Detection

The frontend (`frontend/app/lib/api-config.ts`) uses **runtime detection** to bypass this limitation:

```typescript
// Detects hostname at runtime:
// - varaksha.pages.dev → https://varaksha-production.up.railway.app
// - localhost → http://localhost:8000
// - .pages.dev (any staging) → Production railway
```

This works without requiring `NEXT_PUBLIC_API_URL` in Cloudflare Pages environment variables.

## Setup: Cloudflare Pages (Recommended but Optional)

As a **backup fallback**, we recommend setting the environment variable in Cloudflare Pages:

### Step 1: Access Cloudflare Pages Settings
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Select your Pages project (`varaksha`)
3. Go to **Settings** → **Environment Variables**

### Step 2: Add Production Variable
Click **Add variable**:
- **Variable name:** `NEXT_PUBLIC_API_URL`
- **Value (Production):** `https://varaksha-production.up.railway.app`
- **Encryption:** Optional (not sensitive)

### Step 3: (Optional) Add Preview Variable
For staging branches:
- **Variable name:** `NEXT_PUBLIC_API_URL`
- **Value (Preview):** `https://varaksha-production.up.railway.app`

### Step 4: Trigger Redeploy
After saving, trigger a rebuild:
- **Option A:** Push a new commit to your branch
- **Option B:** Manually redeploy from Cloudflare Pages dashboard

The build must re-run with the env var present for it to be baked into the static output.

## Setup: Railway Backend

### CORS Configuration
The Rust gateway (`gateway/src/main.rs`) has automatic CORS configuration:

**Development Mode** (`cargo run`):
```rust
Cors::permissive()  // Allow any origin
```

**Production Mode** (Railway deployment):
```rust
Cors::default()
    .allowed_origin("https://varaksha.pages.dev")
    .allowed_origin("https://varaksha-production.up.railway.app")
    .allow_any_method()
    .allow_any_header()
    .supports_credentials()
```

No manual CORS configuration needed — it's handled automatically.

## Setup: Local Development

### Frontend
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:3000
# Auto-detects backend at http://localhost:8000
```

### Backend (Sidecar + Gateway)
```bash
# Terminal 1: Python sidecar (ML inference)
cd services/api
python -m uvicorn sidecar:app --host 127.0.0.1 --port 8001

# Terminal 2: Rust gateway (API routing)
cd gateway
RUST_LOG=info cargo run
# Runs on http://localhost:8000
```

Frontend will automatically detect `localhost` and connect to `http://localhost:8000`.

## Troubleshooting

### "API Error: ... Backend unavailable"
1. **Check frontend URL detection:**
   - Open browser DevTools Console
   - Inspect network requests to `/v1/tx`
   - Confirm the target API URL (should be Railway for production)

2. **Check backend connectivity:**
   - Verify Railway deployment is running
   - Check gateway pod logs: `railway logs gateway`
   - Verify sidecar pod is running: `railway logs sidecar`

3. **Check CORS:**
   - Look for CORS errors in browser console
   - Verify `varaksha.pages.dev` is in Railway gateway's allowed origins
   - For development: `localhost` requests should work automatically

4. **Check network:**
   - Verify `varaksha-production.up.railway.app` is accessible from browser
   - Test with curl: `curl https://varaksha-production.up.railway.app/health`

### Forced Cache Clear (Cloudflare Pages)
If you see old errors after deployment:
1. Cloudflare Pages → Your project → Deployments
2. Click "Clear everything" or trigger a new deploy
3. Wait 3-5 minutes for CDN cache to refresh

## Deployment Checklist

- [ ] Code pushed to `test` branch
- [ ] Railway backend deployed and healthy (`/health` endpoint returns `200 OK`)
- [ ] Cloudflare Pages build succeeded (check Deployments tab)
- [ ] Frontend can access API (no CORS errors in console)
- [ ] Test transaction loads and shows verdict
- [ ] Score values vary (not constant 0.68)

## Architecture

```
User Browser (varaksha.pages.dev)
    ↓ HTTPS (Cloudflare CDN)
Cloudflare Pages (static Next.js export)
    ├─ frontend/app/lib/api-config.ts (runtime detection)
    └─ Detects: hostname = "varaksha.pages.dev"
       → Routes to: https://varaksha-production.up.railway.app
            ↓ HTTPS (public Railway URL)
Railway Rust Gateway (:8002 internal, varaksha-production.up.railway.app public)
    ├─ CORS: allows varaksha.pages.dev
    ├─ POST /v1/tx → Calls sidecar
    ├─ GET /v1/stream → Streams transactions
    └─ GET /v1/cache → Returns cache
            ↓ HTTP (internal Docker network)
Railway Python Sidecar (:8001 internal)
    ├─ POST /score → ONNX ML inference
    ├─ Loads: scaler.onnx, RF model, IF model
    └─ Returns: risk_score, reason
            ↓ Internal file access
Data Models (data/models/*.onnx)
```
