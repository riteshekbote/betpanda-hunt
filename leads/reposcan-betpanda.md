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
