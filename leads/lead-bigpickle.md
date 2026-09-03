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
