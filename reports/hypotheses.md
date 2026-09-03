# Hypotheses (ranked)

## RANKED HYPOTHESES 2026-09-02 21:55:06 UTC

## RANKED HYPOTHESES 2026-09-02 23:53:19 UTC

## RANKED HYPOTHESES 2026-09-03 03:14:41 UTC

## RANKED HYPOTHESES 2026-09-03 08:09:50 UTC

## RANKED HYPOTHESES 2026-09-03 12:57:32 UTC

## RANKED HYPOTHESES 2026-09-03 17:03:51 UTC
- [65] dashboard.betpanda.io: k8s Dashboard Exposure via AWS ALB (from art/lead_nemotron3.txt)
- [55] https://betpandacasino.io/rest/user/*: IDOR/BOLA on authenticated Player REST money-flow endpoints (from art/lead_bigpickle.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://dashboard.betpanda.io/ (passive, read-only, confirm k8s dashboard exposure)
- LEARN: No prior hypotheses to evaluate — first analysis cycle.

## RANKED HYPOTHESES 2026-09-03 19:50:16 UTC
- [85] affiliates.betpanda.io/rest/*: Wildcard CORS + credentials on Affiliates REST API enables cross-origin data exfiltration of player PII, transactions, and account settings (from art/lead_bigpickle.txt)
- [70] betpandacasino.io/rest/user/*: BOLA/IDOR on Player Wallet & Balance Endpoints (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: Confirm cookie-based auth + data exfiltration on affiliates REST API. `POST https://affiliates.betpanda.io/rest/user/players -H "Origin: https://evil.com
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://betpanda.io/api/auth/authorize?redirect_uri=https://httpbin.org/get&response_type=code&client_id=test&scope=openid&state=test123 (passive, re
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated endpoints discovered from JS bundle
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin atta
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials; OPTIONS from evil.com does NOT reflect origin. Not a finding.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML (catch-all route). Spring Boot actuator is NOT exposed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks all passive probes. Cannot assess without solving challenge.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB (all probes timeout) — ALB likely internal or auth-gated
- LEARN: ACCEPTED OAUTH @ betpanda.io: /api/auth/authorize accepts arbitrary redirect_uri (200 response) — high-confidence passive signal
- LEARN: ACCEPTED IDOR @ betpandacasino.io: Money-flow REST endpoints confirmed (403/405 responses) — Spring Boot + Cognito JWT, critical business value
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
