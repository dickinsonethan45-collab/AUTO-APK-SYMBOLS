# AMB Symbols — Meta GraphQL Failure Runbook

If the bot logs `OAuthException` / `code:100` / `error_subcode:1891224` (or the
Discord logger channel posts a 🔴 outage alert), work through these in order.
**Don't skip ahead** — each stage looks identical to the others in the error
message, and jumping straight to the "cool" fix has cost hours before.

## 0. Check the alert's "Likely cause" field first
As of the latest version, the outage embed includes a 🔍 diagnosis based on
the actual response body. Start there — it'll usually point at one of the
three stages below directly.

## 1. Is it just token expiry? (~5 min to rule out)
Run `/refreshtoken` in Discord.
- **"✅ Token refreshed"** → problem solved, was just an expired `META_TOKEN`.
- **"❌ Refresh failed"** → `OC_RT` itself is dead, go to step 1a.
- Still failing with a *fresh* token → not a token problem, skip to step 2.

### 1a. OC_RT is dead
1. Log into meta.com / oculus.com in a normal browser (or capture via
   Reqable proxy on the same device).
2. Grab the `oc_rt` cookie value (DevTools → Application → Cookies, or
   Reqable → any request to `secure.oculus.com` → Headers → `cookie`).
3. Update `OC_RT` in Railway → redeploy → `/refreshtoken`.
4. If it STILL fails with a fresh `oc_rt`, the problem was never the token —
   go to step 2, because this usually means fingerprinting (step 3) is
   actually what's blocking things, not auth.

## 2. Has the doc_id / query shape rotated?
Meta's GraphQL uses persisted queries (`doc_id`) instead of raw query text.
These occasionally get deprecated/rotated.

1. Open Reqable, proxy your phone/browser through it.
2. Log into meta.com and browse to the Animal Company store page (this
   triggers the real client's version-check query).
3. Filter traffic for `graph.oculus.com/graphql`, find a POST (not OPTIONS)
   request that succeeded (status 200).
4. Check its Body tab — compare `doc_id` and `variables` shape against
   `VERSION_DOC_ID` / `VERSION_VARIABLES_KEY` currently set in Railway.
5. If they differ, update those Railway vars to match, redeploy.
6. Check the response Body shape too — if `_parse_latest_version()` can't
   find `release_channels`/`liveChannel`, the response schema itself may
   have changed and the parser needs a code update, not just a var change.

## 3. Is Meta fingerprinting the request as non-browser traffic?
This is the sneaky one — an **identical, valid** token + doc_id + variables
can succeed from a browser and fail from the bot, both with the exact same
generic `OAuthException`. Meta doesn't reveal it's blocking on request shape;
it just returns the same auth-shaped error either way.

1. In Reqable, grab the FULL request headers from a working browser POST to
   `graph.oculus.com/graphql` (Headers tab, Request side — Raw view is
   easiest to copy wholesale).
2. Compare against the `headers = {...}` dict in `_post_app_meta()` in
   `main.py`. Look especially at: `sec-ch-ua`, `sec-ch-ua-platform`,
   `sec-fetch-site`, `sec-fetch-mode`, `sec-fetch-dest`, `Accept-Language`,
   `Accept-Encoding`, `priority`, and the Chrome version in `User-Agent`.
3. Update the header dict to match, redeploy.
4. Watch for **`Accept-Encoding`** including a codec `aiohttp` can't decode
   (`zstd` needs `backports.zstd`, `br` needs the `Brotli` package — neither
   is installed). If you see `Can not decode content-encoding: ...` in logs,
   just strip that codec out of the header rather than installing the
   package — simpler and one less dependency.
5. If matching headers exactly still doesn't work, the fingerprinting is
   likely happening at the **TLS layer** (JA3/JA4 hash), which `aiohttp`
   cannot replicate no matter what headers you send. The real fix at that
   point is swapping `aiohttp` for `curl_cffi` (TLS-impersonating HTTP
   client) for just this one call — a bigger change, only worth doing if
   steps 1–4 are confirmed insufficient.

## Known root cause history (most recent first)
- **2026-07-08**: Full chain failure — `oc_rt` genuinely needed refreshing,
  AND once refreshed the GraphQL call still 400'd with a byte-identical
  token/doc_id/variables that worked fine from a real Chrome browser. Root
  cause was header fingerprinting — `_post_app_meta()`'s header set was too
  thin (missing `sec-ch-ua`/`sec-fetch-*`/etc.) and Meta was silently
  rejecting it while returning a generic OAuth-shaped error. Fixed by
  matching the full browser header set. Also hit codec issues twice in a
  row afterward (`zstd`, then `br`) from over-matching `Accept-Encoding` —
  settled on `gzip, deflate` only.
