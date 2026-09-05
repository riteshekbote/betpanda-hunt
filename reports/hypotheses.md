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

## RANKED HYPOTHESES 2026-09-03 22:26:28 UTC
- [75] betpandacasino.io/rest/user/*: BOLA/IDOR on Player Wallet & Balance Endpoints (from art/lead_nemotron3.txt)
- [72] betpanda.io/api/auth/authorize: OAuth redirect_uri validation bypass on betpanda.io authorisation endpoint enables auth code theft via open redirect (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: GET `https://betpanda.io/api/auth/authorize?response_type=code&client_id=test&scope=openid&state=test123&redirect_uri=https://httpbin.org/get` — passive,
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://betpanda.io/api/auth/authorize?redirect_uri=https://httpbin.org/get&response_type=code&client_id=test&scope=openid&state=test123 (passive, re
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated endpoints discovered from JS bundle
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin atta
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials; OPTIONS from evil.com does NOT reflect origin. Not a finding.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML (catch-all route). Spring Boot actuator is NOT exposed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks all passive probes. Cannot assess without solving challenge.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB (all probes timeout). ALB likely internal or auth-gated.
- LEARN: ACCEPTED OAUTH @ betpanda.io: /api/auth/authorize accepts arbitrary redirect_uri (200 response). High-confidence passive signal for redirect_uri bypass.
- LEARN: ACCEPTED IDOR @ betpandacasino.io: Money-flow REST endpoints confirmed (403/405 responses). Spring Boot + Cognito JWT, critical business value.
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed. Injection surface validated.
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials; OPTIONS from evil.com does NOT reflect origin. Not a finding.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML (catch-all route). Spring Boot actuator is NOT exposed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks all passive probes. Cannot assess without solving challenge.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB (all probes timeout) — ALB likely internal or auth-gated
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated endpoints discovered from JS bundle
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin atta
- LEARN: ACCEPTED OAUTH @ betpanda.io: /api/auth/authorize accepts arbitrary redirect_uri (200 response) — high-confidence passive signal
- LEARN: ACCEPTED IDOR @ betpandacasino.io: Money-flow REST endpoints confirmed (403/405 responses) — Spring Boot + Cognito JWT, critical business value
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated

## RANKED HYPOTHESES 2026-09-04 00:18:06 UTC
- [85] affiliates.betpanda.io/rest/*: Wildcard CORS + credentials on affiliates REST API enables credentialed cross-origin exfiltration/ATO of player PII, transactions, payout config (from art/lead_bigpickle.txt)
- [80] betpanda.io/api/auth/authorize: OAuth Redirect_URI Validation Bypass on Main Platform (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://betpanda.io/api/auth/authorize?redirect_uri=https://httpbin.org/get&response_type=code&client_id=test&scope=openid&state=test123 (passive, re
- NEXT(hypotheses-bigpickle.txt): PROBE: Confirm credential model + per-origin reflection on affiliates: `OPTIONS https://affiliates.betpanda.io/rest/user/players -H "Origin: https://evil.com" -
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials; OPTIONS from evil.com does NOT reflect origin. Not a finding.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML (catch-all route). Spring Boot actuator is NOT exposed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks all passive probes. Cannot assess without solving challenge.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB (all probes timeout) — ALB likely internal or auth-gated
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated endpoints discovered from JS bundle
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin atta
- LEARN: ACCEPTED OAUTH @ betpanda.io: /api/auth/authorize accepts arbitrary redirect_uri (200 response) — high-confidence passive signal
- LEARN: ACCEPTED IDOR @ betpandacasino.io: Money-flow REST endpoints confirmed (403/405 responses) — Spring Boot + Cognito JWT, critical business value
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated

## RANKED HYPOTHESES 2026-09-04 04:49:30 UTC
- [85] affiliates.betpanda.io/rest/*: Wildcard CORS + credentials on affiliates REST API enables credentialed cross-origin exfiltration/ATO of player PII, transactions, payout config (from art/lead_bigpickle.txt)
- [80] betpandacasino.io/rest/user/*: BOLA/IDOR on Player Wallet & Balance Endpoints (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://betpanda.io/api/auth/authorize?redirect_uri=https://httpbin.org/get&response_type=code&client_id=test&scope=openid&state=test123 (passive, re
- NEXT(hypotheses-bigpickle.txt): PROBE: Investigate the Cognito hosted UI domain. Search for Cognito domain references in the SPA bundle or network requests. GET https://betpandacasino.io/rest/
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials; OPTIONS from evil.com does NOT reflect origin. Not a finding.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML (catch-all route). Spring Boot actuator is NOT exposed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks all passive probes. Cannot assess without solving challenge.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB (all probes timeout) — ALB likely internal or auth-gated
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated endpoints discovered from JS bundle
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin atta
- LEARN: ACCEPTED OAUTH @ betpanda.io: /api/auth/authorize accepts arbitrary redirect_uri (200 response) — high-confidence passive signal
- LEARN: ACCEPTED IDOR @ betpandacasino.io: Money-flow REST endpoints confirmed (403/405 responses) — Spring Boot + Cognito JWT, critical business value
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials; OPTIONS from evil.com does NOT reflect origin. Not a finding.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML (catch-all route). Spring Boot actuator is NOT exposed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks all passive probes. Cannot assess without solving challenge.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB (all probes timeout) — ALB likely internal or auth-gated
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated endpoints discovered from JS bundle
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin atta
- LEARN: ACCEPTED OAUTH @ betpanda.io: /api/auth/authorize accepts arbitrary redirect_uri (200 response) — high-confidence passive signal
- LEARN: ACCEPTED IDOR @ betpandacasino.io: Money-flow REST endpoints confirmed (403/405 responses) — Spring Boot + Cognito JWT, critical business value
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io/api/auth/authorize which returns SPA HTML (200). All /api/* paths on betpand
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated REST endpoints. Strongest finding, 
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin atta
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML.
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks probes.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.

## RANKED HYPOTHESES 2026-09-04 09:29:07 UTC
- [85] affiliates.betpanda.io/rest/*: Wildcard CORS + credentials on affiliates REST API enables credentialed cross-origin exfiltration/ATO of player PII, transactions, payout config (from art/lead_bigpickle.txt)
- [85] affiliates.betpanda.io/rest/*: Wildcard CORS + Credentials Enables Cross-Origin Account Takeover (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://nano-public.s3.eu-west-1.amazonaws.com/?list-type=2 (passive, read-only, check if S3 bucket listing is enabled for cross-tenant asset enumera
- NEXT(hypotheses-bigpickle.txt): PROBE: Test S3 bucket enumeration at `nano-public.s3.eu-west-1.amazonaws.com`. GET https://nano-public.s3.eu-west-1.amazonaws.com/?list-type=2 (check if bucket 
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io/api/auth/authorize which returns SPA HTML (200). All /api/* paths on betpand
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials; OPTIONS from evil.com does NOT reflect origin. Not a finding.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML (catch-all route). Spring Boot actuator is NOT exposed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks all passive probes. Cannot assess without solving challenge.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB (all probes timeout) — ALB likely internal or auth-gated.
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated endpoints discovered from JS bundle
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin atta
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated.
- LEARN: NEW ASSET @ betpandacasino.io/rest/properties/manifest: Real PWA manifest endpoint (JSON, 200). Cross-origin assets from nano-public.s3.eu-west-1.amazonaws.com.
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML.
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks probes.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated REST endpoints. Strongest finding, 
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin atta
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: SPA catch-all, not a real OAuth endpoint.

## RANKED HYPOTHESES 2026-09-04 13:57:16 UTC
- [90] affiliates.betpanda.io/rest/*: Wildcard CORS + Credentials Enables Cross-Origin Account Takeover (from art/lead_nemotron3.txt)
- [85] affiliates.betpanda.io/rest/*: Wildcard CORS + credentials on affiliates REST API enables credentialed cross-origin exfiltration/ATO of player PII, transactions, payout config (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Login to affiliates.betpanda.io and capture session cookies + Set-Cookie headers. This is the only way to complete the CORS+credentials POC for the top f
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://affiliates.betpanda.io/rest/user/players -H "Origin: https://evil.com" -H "Cookie: <valid_affiliate_session>" (auth-helped, credentialed cros
- LEARN: REJECTED S3 BUCKET LISTING @ nano-public.s3.eu-west-1.amazonaws.com: Bucket listing disabled (AccessDenied on ?list-type=2 and ?prefix=operators/). Individual o
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 20+ authenticated REST endpoints. Strongest finding, 
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed; CORS properly pinned reduces cross-origin attack vector.
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML.
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks probes.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists

## RANKED HYPOTHESES 2026-09-04 17:28:09 UTC
- [90] affiliates.betpanda.io/rest/*: Wildcard CORS + Credentials Enables Cross-Origin Account Takeover (from art/lead_nemotron3.txt)
- [85] affiliates.betpanda.io/rest/*: Wildcard CORS + credentials on affiliates REST API enables credentialed cross-origin exfiltration/ATO of player PII, transactions, payout config (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Login to affiliates.betpanda.io and capture session cookies + Set-Cookie headers. This is the only way to complete the CORS+credentials POC for the top f
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://affiliates.betpanda.io/rest/user/players -H "Origin: https://evil.com" -H "Cookie: <valid_affiliate_session>" (auth-helped, credentialed cros
- LEARN: REJECTED S3 BUCKET LISTING @ nano-public.s3.eu-west-1.amazonaws.com: Bucket listing disabled (AccessDenied on ?list-type=2 and ?prefix=operators/). Individual o
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 20+ authenticated REST endpoints. Strongest finding, 
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed; CORS properly pinned reduces cross-origin attack vector.
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML.
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks probes.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists

## RANKED HYPOTHESES 2026-09-04 20:00:07 UTC
- [90] affiliates.betpanda.io/rest/*: Wildcard CORS + Credentials Enables Cross-Origin Account Takeover (from art/lead_nemotron3.txt)
- [55] https://betpandacasino.io/rest/user/*: IDOR/BOLA on authenticated Player REST money-flow endpoints (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: GET https://affiliates.betpanda.io/rest/user/players -H "Origin: https://evil.com" -H "Cookie: <valid_affiliate_session>" (auth-helped, credentialed cros
- NEXT(hypotheses-nemotron3.txt): HUMAN: Login to affiliates.betpanda.io and capture session cookies + Set-Cookie headers. This is the only way to complete the CORS+credentials POC for the top f
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists
- LEARN: REJECTED S3 BUCKET LISTING @ nano-public.s3.eu-west-1.amazonaws.com: Bucket listing disabled (AccessDenied on ?list-type=2 and ?prefix=operators/). Individual o
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 20+ authenticated REST endpoints. Strongest finding, 
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed; CORS properly pinned reduces cross-origin attack vector.
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML.
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks probes.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.
- LEARN: REJECTED S3 BUCKET LISTING @ nano-public.s3.eu-west-1.amazonaws.com: Bucket listing disabled (AccessDenied on ?list-type=2 and ?prefix=operators/). Individual o
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 20+ authenticated REST endpoints. Strongest finding, 
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed; CORS properly pinned reduces cross-origin attack vector.
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML.
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks probes.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/user/password/reset: password-reset + 2FA endpoints confirmed under wildcard CORS + credentials.
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists

## RANKED HYPOTHESES 2026-09-04 22:13:28 UTC
- [95] affiliates.betpanda.io/rest/*: Wildcard CORS + Credentials Enables Cross-Origin Account Takeover + Password Reset/2FA Bypass (from art/lead_nemotron3.txt)
- [87] affiliates.betpanda.io/rest/*: Wildcard CORS + credentials enables cross-origin exfil/ATO incl. password-reset + 2FA + deposit-limit tampering on affiliates API (from art/lead_bigpickle.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Login to affiliates.betpanda.io and capture session cookies + Set-Cookie headers. This is the only way to complete the CORS+credentials POC for the top f
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true; 20
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).

## RANKED HYPOTHESES 2026-09-05 00:15:52 UTC
- [95] affiliates.betpanda.io/rest/*: Wildcard CORS + Credentials Enables Cross-Origin Account Takeover + Password Reset/2FA Bypass (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Login to affiliates.betpanda.io and capture session cookies + Set-Cookie headers. This is the only way to complete the CORS+credentials POC for the top f
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true; 20
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).

## RANKED HYPOTHESES 2026-09-05 04:42:30 UTC
- [95] affiliates.betpanda.io/rest/*: Wildcard CORS + Credentials Enables Cross-Origin Account Takeover + Password Reset/2FA Bypass (from art/lead_nemotron3.txt)
- [87] affiliates.betpanda.io/rest/*: Wildcard CORS + credentials on affiliates REST API enables cross-origin exfiltration/ATO incl. password-reset + 2FA + deposit-limit tampering (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Login to affiliates.betpanda.io and capture session cookies + Set-Cookie headers. This is the only way to complete the CORS+credentials POC for the top f
- NEXT(hypotheses-nemotron3.txt): HUMAN: Login to affiliates.betpanda.io and capture session cookies + Set-Cookie headers. This is the only way to complete the CORS+credentials POC for the top f
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.
- LEARN: REJECTED S3 BUCKET LISTING @ nano-public.s3.eu-west-1.amazonaws.com: Bucket listing disabled (AccessDenied on ?list-type=2 and ?prefix=operators/). Individual o
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 20+ authenticated REST endpoints. Strongest finding, 
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed; CORS properly pinned reduces cross-origin attack vector.
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML.
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks probes.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/user/password/reset: password-reset + 2FA endpoints confirmed under wildcard CORS + credentials.
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true; 20
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.
- LEARN: REJECTED S3 BUCKET LISTING @ nano-public.s3.eu-west-1.amazonaws.com: Bucket listing disabled (AccessDenied on ?list-type=2 and ?prefix=operators/). Individual o
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 20+ authenticated REST endpoints. Strongest finding, 
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed; CORS properly pinned reduces cross-origin attack vector.
- LEARN: REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials.
- LEARN: REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML.
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed.
- LEARN: REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks probes.
- LEARN: REJECTED MISCONFIG @ dashboard.betpanda.io: k8s dashboard not exposed on ALB.
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/user/password/reset: password-reset + 2FA endpoints confirmed under wildcard CORS + credentials.
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true; 20
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true; 20
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).

## RANKED HYPOTHESES 2026-09-05 08:40:59 UTC
- [95] affiliates.betpanda.io/rest/*: Wildcard CORS + Credentials Enables Cross-Origin Account Takeover + Password Reset/2FA Bypass (from art/lead_nemotron3.txt)
- [68] betpandacasino.io/rest/user/*: IDOR/BOLA on betpandacasino.io money-flow REST endpoints via Cognito JWT (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Login to affiliates.betpanda.io and capture session cookies + Set-Cookie headers. This is the only way to complete the CORS+credentials POC for the top f
- NEXT(hypotheses-nemotron3.txt): HUMAN: Login to affiliates.betpanda.io and capture session cookies + Set-Cookie headers. This is the only way to complete the CORS+credentials POC for the top f
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true; 20
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/public/*: Wildcard CORS + credentials (ACAO:<any Origin> + ACAC:true) confirmed on the unauthenticated public l
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io/rest/public: /rest/public/config (200 GET JSON), /rest/public/login (405 POST-only), /rest/public/register (405 POST-only
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 20+ authenticated + public REST endpoints.
- LEARN: ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials confirmed via live OPTIONS probe reflecting arbitrary Origin with ACAC: true; 20
- LEARN: ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances 405, settings 401); CORS pinned but server-side authZ unverifi
- LEARN: ACCEPTED BUSLOGIC @ cable.betpanda.io: Unauthenticated event ingestion with CORS * confirmed — injection surface validated
- LEARN: REJECTED OAUTH @ betpanda.io/api/auth/authorize: 301 redirects to betpandacasino.io SPA catch-all; no server-side OAuth endpoint exists
- LEARN: REJECTED MISCONFIG @ nano-public.s3.eu-west-1.amazonaws.com: S3 bucket listing returns 403 Forbidden; no enumeration possible
- LEARN: REJECTED SSRF @ betpandacasino.io/rest/properties/manifest: Manifest is static JSON with hardcoded S3 URLs; no user-controllable parameters for URL manipulation
- LEARN: NEW ENDPOINT @ betpandacasino.io/rest/user/authenticate: Real Spring Boot endpoint (403 JSON, not SPA catch-all). Returns 403 with dummy creds. Likely requires 
- LEARN: AUTH MODEL @ betpandacasino.io: REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout. SameSite=Lax limits cross-o
- LEARN: NEW ENDPOINTS @ affiliates.betpanda.io: JS reveals /agent/set-deposit-withdraw-limit (POST, financial), /payouts/single-currency-list, /reports/commission, /rep
- LEARN: REJECTED MISCONFIG @ affiliates.betpanda.io/actuator + api-docs: Spring Boot actuator/OpenAPI not publicly exposed (SPA catch-all).
- LEARN: NEW ASSET @ betpanda.partners: Dedicated in-scope host, "Betpanda" casino brand SPA fronting SAME Spring Boot /rest backend as betpandacasino.io
- LEARN: NEW ENDPOINT @ affiliates.betpanda.io/rest/public/config: Unauth Spring Boot route (200 JSON) leaks operatorId=1, strapiApiUrl=/cms, CloudFront d3ec3n7kizfkuy.c
