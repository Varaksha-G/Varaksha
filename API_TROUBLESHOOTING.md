## VARAKSHA API TROUBLESHOOTING GUIDE

### Problem: "API Error" when submitting transactions

The API detection has been improved with better error messages. Here's how to fix it:

---

## ✓ VERIFICATION COMPLETED

I've verified that **ALL fraud detection is using real ML models** (not hardcoded values):

- ✓ Random Forest model (11.1 MB ONNX)  
- ✓ Isolation Forest model (1.25 MB ONNX)  
- ✓ Feature scaler (StandardScaler via ONNX)  
- ✓ Test: ₹65,000 GAMBLING → Score 0.6051 (FLAG) ✓  

---

## API Configuration Solutions

### Option 1: Local Development (Testing)

**If running locally** (localhost:3000):

```bash
# Make sure gateway is running on port 8000
cd gateway
cargo run --release
# Should show: "Server running on 127.0.0.1:8000"

# In another terminal, start the Python sidecar
cd services/api
python -m fastapi dev sidecar.py --host 127.0.0.1 --port 8001

# Frontend will auto-detect localhost and try localhost:8000
# If gateway is on different port, add NEXT_PUBLIC_API_URL=http://localhost:YOUR_PORT
```

### Option 2: Production (Cloudflare Pages + Railway)

**REQUIRED: Set environment variable in Cloudflare Pages:**

1. Go to your Cloudflare Pages project
2. Settings > Environment Variables  
3. Add **NEXT_PUBLIC_API_URL**:
   ```
   Value: https://your-railway-backend.up.railway.app
   ```
4. **Redeploy** the frontend

This is the PRIMARY method for production.

### Option 3: Custom Domain

If you have a custom domain:

1. Set **NEXT_PUBLIC_API_URL** to your Railway URL (same as Option 2)
2. Ensure Railway backend has CORS enabled (it does - using Cors::permissive())

---

## Common Issues & Fixes

### Issue: "Network/CORS error"
- **Cause**: Frontend can't reach backend
- **Fix**: 
  - Verify backend is running: `curl https://your-railway-backend.up.railway.app/health`
  - Set NEXT_PUBLIC_API_URL in Cloudflare
  - Check firewall/proxy settings

### Issue: "Endpoint not found (404)"
- **Cause**: Gateway isn't running
- **Fix**:
  - Locally: Run `cargo run --release` in gateway/
  - Railway: Check Railway deployment logs

### Issue: "Backend server error (50x)"
- **Cause**: Sidecar service unavailable  
- **Fix**:
  - Verify sidecar is running: `curl http://localhost:8001/health`
  - Check sidecar logs for errors
  - Verify ONNX models exist in data/models/

---

## API Architecture

```
Frontend (React/Next.js)
    ↓ (HTTP POST)
    ├→ Local: http://localhost:8000/v1/tx
    └→ Production: ${NEXT_PUBLIC_API_URL}/v1/tx
         ↓ (HTTP)
Gateway (Rust on Railway)
    ├→ Route: POST /v1/tx
    ├→ Call Python sidecar
    └→ Return TxResponse
         ↓ (HTTP POST to http://sidecar:8001/score)
Sidecar (FastAPI Python)
    ├→ Load ONNX models (RF + IF + Scaler)
    ├→ Scale features
    ├→ Run Random Forest  
    ├→ Run Isolation Forest
    ├→ Composite score: 0.7*RF + 0.3*IF
    └→ Return SidecarResponse
         ↓ (ONNX inference)
ML Models (ONNX format)
    ├→ varaksha_rf_model.onnx (Random Forest)
    ├→ isolation_forest.onnx (Anomaly detection)
    └→ scaler.onnx (Feature scaling)
```

---

## Quick Debug Checklist

- [ ] Can you curl the gateway health endpoint?
  ```bash
  curl https://varaksha-production.up.railway.app/health
  ```

- [ ] Is NEXT_PUBLIC_API_URL set in Cloudflare (if using .pages.dev)?
  - Go to Cloudflare Pages > Settings > Environment Variables
  - Should show NEXT_PUBLIC_API_URL value

- [ ] Check browser console (F12 → Console) for actual error details

- [ ] Try the /health endpoint first:
  ```bash
  curl ${API_BASE}/health  # Replace ${API_BASE} with your URL
  ```

- [ ] Is the sidecar running?
  ```bash
  python -m fastapi dev services/api/sidecar.py
  ```

- [ ] Do ML models exist?
  ```bash
  ls -lh data/models/*.onnx
  ```

---

## Recent Changes

✓ **Improved API config**: Now checks NEXT_PUBLIC_API_URL first (build-time priority)  
✓ **Better error messages**: Shows exactly which URL failed and why  
✓ **Local dev support**: Auto-detects localhost and tries port 8000  
✓ **Debug helper**: Added `getApiDebugInfo()` function for troubleshooting  

---

## Still Having Issues?

Run this to check all components:

```bash
# Test ML models
python test_models.py

# Test gateway health
curl https://varaksha-production.up.railway.app/health

# Test sidecar
curl -X POST http://localhost:8001/health

# Check models exist
ls data/models/
```
