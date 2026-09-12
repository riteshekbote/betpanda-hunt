## REPOSCAN 2026-09-03 16:29:12 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-03 19:25:26 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-03 21:52:41 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-03 23:44:21 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-04 02:17:40 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-04 07:17:12 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-04 12:10:30 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-04 16:25:04 UTC
[HYP] S3 bucket reference in PWA manifest
class: MISCONFIG
asset: betpandacasino.io/rest/properties/manifest → nano-public.s3.eu-west-1.amazonaws.com
confidence: 70
reasoning: Cross-origin S3 bucket for static assets. Bucket listing returns 403 (no public listing). Bucket name follows predictable naming pattern. No source code to confirm whether credentials or write permissions are exposed.
impact: Low (bucket listing blocked, no evidence of public write)
verify_steps: Confirm whether nano-public bucket allows unauthenticated PUT/DELETE; check if any pre-signed URLs or credentials are leaked in client-side JS bundles.
[HYP] Wildcard CORS with credentials on affiliates backend
class: MISCONFIG
asset: affiliates.betpanda.io
confidence: 85
reasoning: Spring Boot backend reflects any Origin + Access-Control-Allow-Credentials: true. 10+ authenticated REST endpoints discovered from JS bundle (/rest/user, /rest/player/uid/{id}, /rest/transaction/list, etc.). An attacker-controlled origin can make credentialed cross-origin requests to read user data.
impact: Medium-High (session tokens/cookies can be exfiltrated from authenticated users via attacker-controlled page)
verify_steps: Confirm CORS header reflects attacker origin (e.g., Origin: https://evil.com); verify cookies are SameSite=None or Lax; test whether authenticated endpoints return sensitive data when called cross-origin.
[HYP] Unauthenticated event ingestion endpoint
class: MISCONFIG
asset: cable.betpanda.io/cable/user-event
confidence: 75
reasoning: POST to /cable/user-event accepts arbitrary JSON body with Access-Control-Allow-Origin: *, returns 200 "processed and saved". No authentication required. Could be abused for event injection, log poisoning, or SSRF if backend processes the payload.
impact: Medium (depends on how events are processed/stored; potential for event injection or resource exhaustion)
verify_steps: Send crafted JSON payloads to /cable/user-event; check if events are stored in database or forwarded to other services; test for SSRF via URL fields in event payload.
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-04 19:07:14 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-04 21:32:16 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-04 23:16:34 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-05 00:59:58 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-05 05:28:32 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-05 09:18:43 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-05 12:47:40 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-05 15:43:52 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-05 17:50:43 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-05 19:46:19 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-05 21:49:24 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-05 23:29:00 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-06 01:18:38 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-06 06:02:31 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-06 11:03:10 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-06 14:12:48 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-06 17:06:33 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-06 19:15:27 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-06 21:24:08 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-06 23:07:46 UTC
class: OTHER
asset: `.github/workflows/hunt.yml`
confidence: 90
reasoning: `hunt.yml` declares `contents: write` and `actions: write` (line 9-10). The workflow reads files, runs analysis, and pushes commits — `actions: write` is unused and unnecessary, violating least-privilege. `reposcan.yml` also declares `contents: write` (line 9) but the script only reads public repos via unauthenticated API.
impact: Low — expanded blast radius if workflow is compromised; not directly exploitable.
verify_steps: Inspect `permissions:` blocks in `.github/workflows/hunt.yml:8-10` and `.github/workflows/reposcan.yml:8-9`.
class: OTHER
asset: `.github/workflows/hunt.yml:46`, `.github/workflows/reposcan.yml:35`
confidence: 85
reasoning: Both workflows install opencode via `curl -fsSL https://opencode.ai/install | bash` (with retry logic). This pipes a remote script directly into bash without checksum verification, a known supply-chain risk pattern. In a GitHub Actions context the risk is mitigated by the runner being ephemeral.
impact: Low — supply-chain risk if opencode.ai is compromised; runner is ephemeral.
verify_steps: Confirm lines `hunt.yml:46` and `reposcan.yml:35` execute `curl ... | bash`.
class: OTHER
asset: `.github/workflows/reposcan.yml:50-52`
confidence: 70
reasoning: `$TARGET_ORG` is expanded unquoted in `for ORG in $TARGET_ORG` and interpolated into a curl URL (`https://api.github.com/orgs/$ORG/repos`). Currently `TARGET_ORG=""` (line 13), so this code path is dead. If someone sets `TARGET_ORG` to a value containing shell metacharacters (e.g., `foo; curl evil.com`), it could lead to command injection via the unquoted variable in the `for` loop and the curl URL.
impact: Low — `TARGET_ORG` is hardcoded empty in the repo; only exploitable if a contributor modifies it unsafely.
verify_steps: Check `reposcan.yml:13` (`TARGET_ORG: ""`) and `reposcan.yml:50-52` (unquoted expansion).
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-07 01:03:31 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-07 06:09:29 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-07 12:39:06 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-07 17:54:53 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-07 20:57:53 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-07 23:17:11 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-08 01:14:39 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-08 05:59:45 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-08 10:57:12 UTC
[HYP] (none)
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-08 14:53:05 UTC
[HYP] (none — no repos to scan)
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-08 18:13:42 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-08 21:12:26 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-08 23:25:34 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-09 01:30:23 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-09 06:38:39 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-09 11:49:36 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-09 15:42:01 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-09 18:59:39 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-09 21:35:52 UTC
[HYP] Phishing credential stealer (log.php)
class: OTHER
asset: betpanda/referral (deleted — commit b2cb01e0)
confidence: 95
reasoning: >
impact: N/A — file deleted, repo empty, no live deployment
verify_steps: >
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-09 23:30:19 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-10 01:25:44 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-10 06:37:11 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-10 11:47:04 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-10 15:36:46 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-10 18:41:14 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-10 21:12:39 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-10 23:12:49 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-11 01:08:48 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-11 06:03:50 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-11 11:26:46 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-11 15:10:47 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-11 18:36:45 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-11 21:15:43 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-11 23:18:09 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-12 01:12:23 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
## REPOSCAN 2026-09-12 05:50:34 UTC
TARGET_ORG not configured for betpanda; skipping public-org deep scan.
