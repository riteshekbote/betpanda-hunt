## 2026-09-03 17:01:51 UTC [target] (model bigpickle)
[HYP] IDOR/BOLA on authenticated Player REST money-flow endpoints
class: IDOR
asset: https://betpandacasino.io/rest/user/* (esp. account-balances-and-bonuses, wallet/withdraw/bet)
confidence: 55
reasoning: Core casino API is Spring Boot + Cognito JWT; it exposes per-user balance/bonus/wallet/bet endpoints (authenticate 403, balances 405=exists, zendesk 401=auth-gated). Gambling money flows are classic BOLA/IDOR targets. CORS pinned but that does not prevent server-side IDOR.
evidence_needed: 2 user accounts; cross-tenant object access via enumerated id/uid while changing nothing (read-only)
verify_steps: PASSIVE-first: create 2 scoped test accounts → GET/POST balances/wallet/withdraw with user A JWT against user B's id → diff responses. Also check `/rest/settings`-style anonymous config for other object endpoints.
impact: cross-tenant wallet/balance/bonus disclosure or tampering on a real-money gambling platform; severity High/Critical
testability: AUTH_HELPED
[HYP] Unauth/cross-origin analytics injection & pollute via cable user-event
class: BUSLOGIC
asset: cable.betpanda.io/cable/user-event
confidence: 45
reasoning: Returns `access-control-allow-origin: *`, POST with arbitrary JSON accepted and confirmed `200 "processed and saved"`; no auth, no CSRF/Origin restriction, GET→405. Only `userId` alphanumeric-validated; other fields (referrer/registeredOn/firstVisitOn) unvalidated/injection-prone.
evidence_needed: show persisted server-side effect (e.g. malformed/oversized field causing 5xx or stored-XSS in a reporting dashboard) — needs HUMAN/account to observe aggregation
verify_steps: PASSIVE: try oversized/unusual `referrer`/`registeredOn` payloads and observe response; check for other `/cable/*` endpoints (GET)
impact: analytics-data poisoning / potential stored-XSS in internal dashboard; low-medium unless chained
testability: PASSIVE
[HYP] Flipt feature-flag admin / unauth evaluation abuse
class: AUTH
asset: flags.betpanda.io
confidence: 25
reasoning: Frontend declares `GLOBAL_FLIPT_URL=https://flags.betpanda.io` / `GLOBAL_FLIPT_ENVIRONMENT=betpanda`. Flipt exposes a gRPC/REST evaluation API; if unauthenticated it could reveal flag values used for client-side gating.
evidence_needed: bypass CF challenge then test `/api/v1/flags`, `/auth/v1/...` for unauth access or default creds
verify_steps: PASSIVE/AUTH_HELPED (needs JS-challenge pass or scoped access): GET `/api/v1/flags`, `/api/v1/namespaces`, `/auth/v1/authentication/methods`
impact: flag disclosure → client-side feature gating bypass; low-medium
testability: AUTH_HELPED
## 2026-09-03 19:45:43 UTC [target] (model bigpickle)
[NEW] `affiliates.betpanda.io/rest/*` — separate Spring Boot backend, CORS reflects **any origin + credentials**, endpoints discovered from JS bundle
[NEW] Affiliates JS endpoints: `/rest/user`, `/rest/user/players`, `/rest/player/uid/{id}?currency=`, `/rest/transaction/list`, `/rest/user/account-settings`, `/rest/user/set-profile`, `/rest/user/change-password`, `/rest/user/selectable-payout-currencies`, `/rest/user/selectable-payout-networks`
[NEW] Strapi CMS integration with `localStorage.getItem("strapiApiUrlOverride")` — overridable content API base URL
[NEW] `/actuator/*` paths on betpandacasino.io redirect 301→trailing-slash but serve SPA HTML (not real actuator — catch-all route, NOT a finding)
[CHANGED] `betpandacasino.io/rest/user/account-balances-and-bonuses` confirmed POST-only (405 GET); `/rest/user/settings` 401; CORS properly pinned to own origin + credentials
[CHANGED] `cable.betpanda.io/cable/user-event` confirmed POST-only, root returns "Cable Service - Ready!"; no new endpoints
[CHANGED] `fp.betpanda.io`, `custom-lp.betpanda.io`, `flags.betpanda.io`, `www.betpanda.io` all Cloudflare JS-challenged (403 cf-mitigated) — cannot probe passively
[PRIO] affiliates.betpanda.io/rest/*,7.95 — wildcard CORS+credentials, full API surface, Spring Boot, player/transaction data
[PRIO] betpandacasino.io/rest/user/*,7.40 — money-flow endpoints, Cognito JWT, POST-only balances
[PRIO] cable.betpanda.io/cable/user-event,4.80 — open CORS *, unauthenticated POST, analytics
[HYP] Wildcard CORS + credentials on Affiliates REST API enables cross-origin data exfiltration of player PII, transactions, and account settings
class: MISCONFIG
asset: affiliates.betpanda.io/rest/*
confidence: 85
reasoning: OPTIONS preflight returns 200 with `access-control-allow-origin: https://evil.com` + `access-control-allow-credentials: true`. GET /rest/user returns 401 (auth required, cookies/session-based). JS bundle reveals 10+ authenticated endpoints: /rest/user, /rest/user/players (POST, list with pagination), /rest/player/uid/{id} (GET, player by UID), /rest/transaction/list (POST), /rest/user/account-settings (GET/POST), /rest/user/set-profile (POST), /rest/user/change-password (POST), /rest/user/selectable-payout-currencies (GET), /rest/user/selectable-payout-networks (GET). A malicious page can make credentialed cross-origin requests; browser attaches affiliate session cookies; response exfiltrated to attacker.
evidence_needed: (1) Confirm auth is cookie/session-based (not only Bearer token) — check Set-Cookie on login; (2) Two affiliate accounts to confirm cross-account access isn't blocked server-side; (3) POC page that triggers /rest/user/players and reads response
verify_steps: PASSIVE-first: (1) `curl -sS -D- https://affiliates.betpanda.io/rest/user -H "Origin: https://evil.com"` — confirm ACAO reflected + credentials; (2) Login to affiliate panel, capture cookies, then `curl -sS -D- -b cookies.txt https://affiliates.betpanda.io/rest/user/players -X POST -H "Content-Type: application/json" -d '{"limit":10,"offset":0}' -H "Origin: https://evil.com"` — confirm data returns with CORS headers; (3) Check Set-Cookie flags on login response for SameSite
impact: Full cross-origin read of affiliate player lists, individual player data (UID-based), transaction history, account settings, payout currencies. Attacker can create arbitrary affiliate links, change profile, change password. On a gambling affiliate platform this exposes PII + financial data of referred players. Severity: Critical (CVSS ~9.1)
testability: AUTH_HELPED
[HYP] Strapi CMS baseURL override via localStorage enables API redirection and data exfiltration
class: OTHER
asset: affiliates.betpanda.io (Strapi CMS integration)
confidence: 60
reasoning: JS bundle contains `localStorage.getItem("strapiApiUrlOverride")` which overrides the Strapi API base URL. If an attacker can set this value (requires prior XSS or subdomain compromise), all CMS content requests (affiliate pages, banners, terms) go to attacker-controlled server. CMS content could include admin-configured promotional material, terms, or banners — data leakage or content injection.
evidence_needed: (1) Confirm Strapi instance exists and responds; (2) Verify content contains sensitive/privileged data beyond public pages; (3) Chain from XSS or other subdomain write
verify_steps: PASSIVE: (1) Search JS for Strapi base URL pattern; (2) Check if Strapi has /api/content/xxx endpoints accessible; (3) Verify localStorage persistence across page reloads
impact: Content injection (modified terms/banners/promotions) or data exfiltration of CMS content. Medium severity if no sensitive data in CMS, potentially higher if admin/privileged content stored.
testability: AUTH_HELPED
[HYP] IDOR/BOLA on authenticated Player REST money-flow endpoints on main casino API
class: IDOR
asset: https://betpandacasino.io/rest/user/*
confidence: 55
reasoning: Core casino API is Spring Boot + Cognito JWT; `/rest/user/account-balances-and-bonuses` is POST-only (confirmed 405 GET), `/rest/user/settings` returns 401. CORS properly pinned to `https://betpandacasino.io` (does NOT reflect evil.com). Gambling money flows are classic BOLA targets. However, proper CORS reduces cross-origin attack surface; IDOR requires same-origin JWT manipulation or ID parameter tampering.
evidence_needed: 2 user accounts; cross-tenant object access via enumerated id/uid while changing nothing (read-only)
verify_steps: PASSIVE-first: create 2 scoped test accounts → POST account-balances-and-bonuses with user A JWT including user B's id/uid → diff responses. Also probe `/rest/user/settings` with JWT.
impact: cross-tenant wallet/balance/bonus disclosure or tampering on a real-money gambling platform; severity High/Critical
testability: AUTH_HELPED
[PARKED] Strapi CMS baseURL override via localStorage: requires prior XSS to set localStorage value; standalone impact is content injection on affiliate pages, not player data. Severity medium at best. **Parked for chaining with XSS.**
[FINAL] Survivors ranked:
[NEXT] PROBE: Confirm cookie-based auth + data exfiltration on affiliates REST API. `POST https://affiliates.betpanda.io/rest/user/players -H "Origin: https://evil.com" -H "Content-Type: application/json" -d '{"limit":1,"offset":0}'` (requires authenticated session — HUMAN to login first and provide cookies). Also check Set-Cookie flags on login to confirm cookie-based auth model.
[LEARN] ACCEPTED MISCONFIG @ affiliates.betpanda.io/rest/*: Wildcard CORS + credentials reflected from any origin; 10+ authenticated endpoints discovered from JS bundle including player PII, transactions, account settings, and payout config. Verified via live OPTIONS+GET probes.
[LEARN] ACCEPTED IDOR @ betpandacasino.io/rest/user/*: Money-flow endpoints confirmed (POST-only balances, 401 settings); CORS properly pinned reduces cross-origin attack vector but does not prevent same-origin IDOR.
[LEARN] REJECTED MISCONFIG @ betpandacasino.io CORS: CORS correctly restricts to own origin + credentials; OPTIONS from evil.com does NOT reflect origin. Not a finding.
[LEARN] REJECTED ACTUATOR @ betpandacasino.io/actuator/*: All actuator paths serve SPA HTML (catch-all route). Spring Boot actuator is NOT exposed.
[LEARN] REJECTED AUTH @ flags.betpanda.io: Cloudflare JS challenge blocks all passive probes. Cannot assess without solving challenge.
[RISK] BetPanda: 35 — Scoped assets are behind Cloudflare; main casino API has proper CORS + Cognito JWT (server-side auth enforcement likely strong). The affiliates CORS misconfiguration is the highest-probability finding but requires authenticated affiliate session. No evidence of SSRF-to-metadata or admin panel exposure. Moderate cloud surface (AWS ELB for k8s dashboard, Cloudflare everywhere).
