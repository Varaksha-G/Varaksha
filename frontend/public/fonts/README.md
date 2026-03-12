# Self-Hosted Fonts for Production Indian Deployment

This directory should contain self-hosted font files for Varaksha's production deployment. Self-hosting eliminates the external CDN dependency on Google Fonts, improving:

- **Latency**: Fonts served from CDN or local cache instead of googleapis.com
- **Compliance**: No third-party tracking cookies (DPDP Act 2023 §7(g) compliance)
- **Reliability**: Fonts remain available even if Google's service is throttled in certain regions
- **Privacy**: No font request logs sent to Google Fonts analytics

## Required Font Files

Place the following `.woff2` or `.woff` files in this directory:

### Playfair Display (serif headings)
- `PlayfairDisplay-Regular.woff2` (weight 400, normal)
- `PlayfairDisplay-Bold.woff2` (weight 700, normal)
- `PlayfairDisplay-Black.woff2` (weight 900, normal)
- `PlayfairDisplay-Italic.woff2` (weight 400, italic)

### Barlow (sans-serif body text)
- `Barlow-Regular.woff2` (weight 400, normal)
- `Barlow-Medium.woff2` (weight 500, normal)
- `Barlow-SemiBold.woff2` (weight 600, normal)
- `Barlow-Bold.woff2` (weight 700, normal)

### Courier Prime (monospace code)
- `CourierPrime-Regular.woff2` (weight 400, normal)
- `CourierPrime-Bold.woff2` (weight 700, normal)

## Download Instructions

All fonts are available under the SIL Open Font License (OFL) from Google Fonts:

1. Go to https://fonts.google.com
2. Search for each font above
3. Download the `.woff2` files (preferred for modern browsers; `.woff` as fallback for IE11)
4. Place files in this directory

## Font loading in globals.css

The `@font-face` declarations in `frontend/app/globals.css` reference these files using `url("/fonts/...")`.

Development: If fonts are missing, CSS falls back to system serif/sans-serif/monospace.
Production: Fonts must be present in this directory and served by the CDN or static host.

## WOFF2 Compression

WOFF2 files are ~30% smaller than WOFF or TTF. For production deployments in India with varying network conditions, WOFF2 is recommended. All modern browsers (except IE11) support WOFF2.

## Nginx/CDN Caching

Add this header to your webserver config for fonts:

```nginx
location ~* ^/fonts/.*\.woff2?$ {
  expires 30d;
  add_header Cache-Control "public, immutable";
}
```

This ensures fonts are cached for 30 days, reducing repeated downloads.

---

**Last updated**: Phase 18 (Section 7.2)
