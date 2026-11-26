# ATH License Bot integration

The iOS app verifies licenses through the Cloudflare Worker endpoint `/api/license/mobile-verify`. The app sends the license key and a Keychain-persisted installation device ID. The Worker performs key status, expiry, and device-limit checks against D1.

## Configure the Worker URL

After deploying `ath-license-bot`, replace `https://YOUR_WORKER.workers.dev` in `ThreeOneOSFive/Info.plist` with the actual Worker URL. Do not add Telegram credentials or `API_HMAC_SECRET` to the iOS target.

## Secrets

Keep these only in Cloudflare Worker secrets:

- `TELEGRAM_BOT_TOKEN`
- `OWNER_TELEGRAM_ID`
- `API_HMAC_SECRET`
- `TELEGRAM_WEBHOOK_SECRET`

The hardened `/api/license/verify` endpoint remains available for trusted server-to-server callers and requires HMAC headers. The mobile endpoint intentionally does not receive the HMAC secret because a mobile app cannot keep a shared secret private; HTTPS, D1 validation, device binding, and Worker rate limiting protect the mobile flow.

## Container grant backends

The iOS 26/27 container resolver keeps both native backends. It tries the
App-Group-backed `worse_query` path first and falls back to the original
`bad_query` implementation when the newer query is unavailable. The target
must be signed with the `group.com.ath.external.sandbox` App Group entitlement.
The advertised support range is limited to iOS 26.0–26.7.2 and iOS 27.0–27.2
for these two PoCs; later builds are intentionally rejected until validated.
