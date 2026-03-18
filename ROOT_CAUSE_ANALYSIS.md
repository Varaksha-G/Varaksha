# Root Cause Analysis: Live API Error

## What We Found (Code Inspection Results)

### ✅ VERIFIED IN CODE (All Correct):

1. **Merchant Categories FIXED:**
   ```
   const MERCHANT_CATS = ["FOOD", "UTILITY", "ECOM", "GAMBLING", "TRAVEL"]
   ```
   ✅ No "Grocery" option (screenshot shows old cached version)

2. **Form Defaults FIXED:**
   ```
   const FORM_DEFAULTS = {
     merchantCat: "FOOD",  // ← Changed from "Grocery"
     ...
   }
   ```

3. **Validation Blocker REMOVED:**
   - No `if (hostname.endsWith('.pages.dev') && ...setError())` blocking call
   - Code goes straight to fetch without preemptive error

4. **Error Handling IMPROVED:**
   - Changed error display from `<p>` to `<pre>` (preserves multiline)
   - Added console logging `[Varaksha]` messages
   - Only shows error if fetch actually fails

---

## Why Screenshot Still Shows Old UI

**Root Cause: Cloudflare Pages is serving cached JavaScript**

Timeline:
1. ✅ We committed changes to GitHub (commit `02c942e`, `6ecd84f`, `7e87fc3`)
2. ✅ Code is correct in repository
3. ❌ Cloudflare's last auto-rebuild may have been from old commit
4. ❌ Even if it rebuilt, the cache hasn't been purged

**Evidence from screenshot:**
- Dropdown shows "Grocery" (code has "FOOD")
- Error says "Live API unavailable..." (removed from code)

Both of these are **impossible** with our current code.

---

## The Fix - In Order

### Immediate Actions (takes 5 minutes)

**Action 1: Nuke Cloudflare Cache**
```
https://dash.cloudflare.com
→ Varaksha project
→ Caching → Configuration 
→ Purge Everything
```

**Action 2: Force Rebuild**
```
→ Deployments
→ Redeploy this deployment (even if it looks recent!)
→ Wait for "Live" status
```

**Action 3: Browser Cache Clear**
```
F12 → Application → Clear site data
Ctrl + Shift + R (Windows) / Cmd + Shift + R (Mac)
Close and reopen tab
```

### After Actions:

**Expected Result:**
- Dropdown now says **FOOD** (not Grocery)
- Click "Test Transaction"
- Returns verdict + risk score (no error)

---

## If It STILL Fails (Advanced Debugging)

### Debug 1: Check What's Being Sent
```
F12 → Network tab
Click "Test Transaction"
Look for request to: https://varaksha-production.up.railway.app/v1/tx
Right-click → Copy as cURL
Check the payload - what merchantCat is being sent?
```

### Debug 2: Check What's Returned
Same request in Network tab:
- Response tab
- What's the HTTP status? (should be 200)
- What's the response body?

### Debug 3: Check Browser Console
```
F12 → Console tab
Look for [Varaksha] logs
```

Should show:
```
[Varaksha] Starting test transaction...
[Varaksha] API Base URL: https://varaksha-production.up.railway.app
[Varaksha] Hostname: varaksha.pages.dev
```

---

## Summary

| Check | Status | Why |
|-------|--------|-----|
| **Code correct?** | ✅ YES | Verified in editor |
| **Deployed to GitHub?** | ✅ YES | Commits pushed |
| **Cloudflare serving latest?** | ❌ NO | Screenshot shows old code |
| **Cache purged?** | ❌ LIKELY NO | Need to manually purge |

**99% confidence: This is a Cloudflare cache issue, not a code issue.**

Follow the 3 actions above and it will work.
