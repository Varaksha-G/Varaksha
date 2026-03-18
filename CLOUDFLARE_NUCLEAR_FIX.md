# Cloudflare Cache Nuclear Option - Follow EXACTLY

## Go to: https://dash.cloudflare.com

### Step 1: Purge entire cache
1. Click **Varaksha** project (top)
2. Left sidebar → Click **Caching**
3. Click **Configuration** tab
4. Scroll down → Click **Purge Everything**
5. Confirm "Purge Everything"
6. ⏳ Wait 10 seconds for completion

### Step 2: Force rebuild (even if deploy looks recent)
1. Click **Deployments** tab
2. Click **View build details** on the top deployment
3. Look for **"Redeploy"** button in top right
4. Click **Redeploy this deployment**
5. ⏳ Wait for "Live" status (60-90 seconds)

### Step 3: Browser - HARD CLEAR EVERYTHING
Go to: https://varaksha.pages.dev/live

**Do all 3 (don't skip any):**
- **Empty Chrome Cache:**
  1. `F12` → Settings → Application tab
  2. Left dropdown: Select "Cookies and other site data"
  3. Click **Clear site data**

- **Hard Refresh:**
  - Windows: `Ctrl + Shift + R`
  - Mac: `Cmd + Shift + R`

- **Close and reopen browser tab**

### Step 4: Verify in DevTools
1. Open `F12` → **Console** tab
2. Look for messages starting with `[Varaksha]`
3. Should show: `API Base URL: https://varaksha-production.up.railway.app`

### Step 5: TEST
- Merchant category dropdown should now say: **FOOD** (not Grocery)
- Click "Test Transaction"
- Should work without the "Live API unavailable" error

---

## If Still Failing:

1. Check Network tab (F12 → Network)
2. Look at the fetch call to `/v1/tx`
3. What HTTP status? (should be 200)
4. What's the response body?

Copy-paste that here if still broken.
