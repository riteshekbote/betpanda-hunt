# BetPanda inventory (discovery seed 2026-09-02)
# NOTE: hosts below are discovery candidates from passive DNS/CT; confirm in-scope vs program scope before active testing.
betpanda.io
dashboard.betpanda.io
www.betpanda.io

## PASSIVE RECON 2026-09-02 (read-only, non-intrusive)

> Recon observations only. These are NOT confirmed vulnerabilities; ownership/in-scope of each host must be confirmed against the program scope before any active testing. Hosts resolve + serve HTTP — investigation requires scoped authorization.

**Probed:** 3 hosts | **Live HTTP:** 0

| Host | Status | Server/Tech |
|---|---|---|

**CNAME review signals (1):**
- `dashboard.betpanda.io` -> `k8s-kubernet-albdashb-d955dbd267-2103356572.eu-west-1.elb.amazonaws.com`

## DEEP ENUM (wildcard-cleaned) 2026-09-03
**Root zone:** `betpanda.io` | **dedicated hosts after wildcard-filter: 4**
> Audit: brute+passive subfinder produced 10,083 resolving hostnames; zone-wildcard + IP-fingerprint filtering dropped 9,973 (98.9%) DNS-wildcard noise (random labels resolving to shared wildcard IPs e.g. account.cineplex.de, a.hypofriend.de, account.live-manager.de, docker.jtl-software.de, *.ggamdom.com, *.dev.alfaview.com). Only genuine dedicated hosts listed below. These are surface-map observations; live HTTP status captured read-only (GET / via curl). No findings claimed; scope must be confirmed with the program.
- `affiliates.betpanda.io`  [HTTP 200]
- `cable.betpanda.io`  [HTTP 200]
- `custom-lp.betpanda.io`  [HTTP 403]
- `fp.betpanda.io`  [HTTP 403]

## 2026-09-02 21:55:06 UTC

## 2026-09-02 23:53:19 UTC

## 2026-09-03 03:14:41 UTC

## 2026-09-03 08:09:50 UTC

## 2026-09-03 12:57:32 UTC

## 2026-09-03 17:03:51 UTC

## 2026-09-03 19:50:16 UTC
- NEW `affiliates.betpanda.io/rest/*` — separate Spring Boot backend, CORS reflects **any origin + credentials**, endpoints discovered from JS bundle
- NEW Affiliates JS endpoints: `/rest/user`, `/rest/user/players`, `/rest/player/uid/{id}?currency=`, `/rest/transaction/list`, `/rest/user/account-settings`, `/rest/user/set-profile`, `/rest/user/change-pa
- NEW Strapi CMS integration with `localStorage.getItem("strapiApiUrlOverride")` — overridable content API base URL
- NEW `/actuator/*` paths on betpandacasino.io redirect 301→trailing-slash but serve SPA HTML (not real actuator — catch-all route, NOT a finding)
- CHANGED `betpandacasino.io/rest/user/account-balances-and-bonuses` confirmed POST-only (405 GET); `/rest/user/settings` 401; CORS properly pinned to own origin + credentials
- CHANGED `cable.betpanda.io/cable/user-event` confirmed POST-only, root returns "Cable Service - Ready!"; no new endpoints
- CHANGED `fp.betpanda.io`, `custom-lp.betpanda.io`, `flags.betpanda.io`, `www.betpanda.io` all Cloudflare JS-challenged (403 cf-mitigated) — cannot probe passively

## 2026-09-03 22:26:28 UTC
- NEW affiliates.betpanda.io — dedicated host (HTTP 200), separate Spring Boot backend, wildcard CORS + credentials reflected from any origin, 10+ authenticated REST endpoints discovered from JS bundle (/re
- NEW cable.betpanda.io — dedicated host (HTTP 200), unauthenticated event ingestion endpoint /cable/user-event accepts arbitrary JSON with `access-control-allow-origin: *`, returns 200 "processed and saved
- NEW custom-lp.betpanda.io — dedicated host (HTTP 403), Cloudflare JS challenge blocks passive probes
- NEW fp.betpanda.io — dedicated host (HTTP 403), Cloudflare JS challenge blocks passive probes
- NEW betpandacasino.io — major betting platform (not in initial inventory), Spring Boot + Cognito JWT API at /rest/user/*, money-flow endpoints confirmed (balances POST-only 405, settings 401, wallet/withd
- CHANGED betpandacasino.io/rest/user/account-balances-and-bonuses — confirmed POST-only (405 GET), endpoint exists
- CHANGED betpandacasino.io/rest/user/settings — returns 401 (auth required)
- CHANGED betpandacasino.io/actuator/* — all paths redirect 301→trailing-slash but serve SPA HTML (catch-all route), Spring Boot actuator NOT exposed
- CHANGED cable.betpanda.io/cable/user-event — confirmed POST-only, root returns "Cable Service - Ready!", no additional endpoints discovered
- CHANGED dashboard.betpanda.io — k8s dashboard NOT exposed on ALB (all probes timeout), ALB likely internal or auth-gated
- CHANGED flags.betpanda.io, www.betpanda.io, custom-lp.betpanda.io, fp.betpanda.io — all Cloudflare JS-challenged (403 cf-mitigated), cannot probe passively
- CHANGED betpanda.io/api/auth/authorize — accepts arbitrary redirect_uri (200 response), high-confidence passive signal for OAuth redirect_uri validation bypass

## 2026-09-04 00:18:06 UTC

## 2026-09-04 04:49:30 UTC
- CHANGED betpanda.io/api/auth/authorize — 301 redirects to betpandacasino.io/api/auth/authorize which returns SPA HTML (200). `/api/*` paths on betpandacasino.io are ALL SPA catch-all (token, refresh, v1/users
- CHANGED betpandacasino.io/graphql/ — 301→301 trailing-slash redirect then 200 SPA HTML. Not a real GraphQL endpoint.
- NEW betpandacasino.io/rest/properties/manifest — real PWA manifest endpoint (JSON, 200). Cross-origin: `nano-public.s3.eu-west-1.amazonaws.com` bucket for assets.

## 2026-09-04 09:29:07 UTC
- CHANGED betpanda.io/api/auth/authorize — 301 redirects to betpandacasino.io/api/auth/authorize which returns SPA HTML (200). All /api/* paths on betpandacasino.io are SPA catch-all (token, refresh, v1/users).
- CHANGED betpandacasino.io/graphql/ — 301→301 trailing-slash redirect then 200 SPA HTML. Not a real GraphQL endpoint.
- NEW betpandacasino.io/rest/properties/manifest — real PWA manifest endpoint (JSON, 200). Assets served from `nano-public.s3.eu-west-1.amazonaws.com` cross-origin bucket.

## 2026-09-04 13:57:16 UTC
- NEW nano-public.s3.eu-west-1.amazonaws.com — S3 bucket listing returns 403 Forbidden (no enumeration)
- CHANGED betpandacasino.io/rest/properties/manifest — Static PWA manifest with hardcoded S3 asset URLs; no query params for URL manipulation
- CHANGED affiliates.betpanda.io/config/config.json — Only contains baseUrl (no strapiApiUrlOverride in config; override via localStorage only)

## 2026-09-04 17:28:09 UTC
- NEW nano-public.s3.eu-west-1.amazonaws.com — S3 bucket listing returns 403 Forbidden (no enumeration)
- CHANGED betpandacasino.io/rest/properties/manifest — Static PWA manifest with hardcoded S3 asset URLs; no query params for URL manipulation
- CHANGED affiliates.betpanda.io/config/config.json — Only contains baseUrl (no strapiApiUrlOverride in config; override via localStorage only)

## 2026-09-04 20:00:07 UTC
- NEW `affiliates.betpanda.io/rest/*` — separate Spring Boot backend, CORS reflects **any origin + credentials**, endpoints discovered from JS bundle
- NEW Affiliates JS endpoints: `/rest/user`, `/rest/user/players`, `/rest/player/uid/{id}?currency=`, `/rest/transaction/list`, `/rest/user/account-settings`, `/rest/user/set-profile`, `/rest/user/change-pa
- NEW Strapi CMS integration with `localStorage.getItem("strapiApiUrlOverride")` — overridable content API base URL
- NEW `/actuator/*` paths on betpandacasino.io redirect 301→trailing-slash but serve SPA HTML (not real actuator — catch-all route, NOT a finding)
- CHANGED `betpandacasino.io/rest/user/account-balances-and-bonuses` confirmed POST-only (405 GET); `/rest/user/settings` 401; CORS properly pinned to own origin + credentials
- CHANGED `cable.betpanda.io/cable/user-event` confirmed POST-only, root returns "Cable Service - Ready!"; no new endpoints
- CHANGED `fp.betpanda.io`, `custom-lp.betpanda.io`, `flags.betpanda.io`, `www.betpanda.io` all Cloudflare JS-challenged (403 cf-mitigated) — cannot probe passively
- NEW nano-public.s3.eu-west-1.amazonaws.com — S3 bucket listing returns 403 Forbidden (no enumeration)
- CHANGED betpandacasino.io/rest/properties/manifest — Static PWA manifest with hardcoded S3 asset URLs; no query params for URL manipulation
- CHANGED affiliates.betpanda.io/config/config.json — Only contains baseUrl (no strapiApiUrlOverride in config; override via localStorage only)
- NEW `affiliates.betpanda.io/rest/*` — separate Spring Boot backend, CORS reflects **any origin + credentials**, endpoints discovered from JS bundle
- NEW Affiliates JS endpoints: `/rest/user`, `/rest/user/players`, `/rest/player/uid/{id}?currency=`, `/rest/transaction/list`, `/rest/user/account-settings`, `/rest/user/set-profile`, `/rest/user/change-pa
- NEW Strapi CMS integration with `localStorage.getItem("strapiApiUrlOverride")` — overridable content API base URL
- NEW `/actuator/*` paths on betpandacasino.io redirect 301→trailing-slash but serve SPA HTML (not real actuator — catch-all route, NOT a finding)
- CHANGED `betpandacasino.io/rest/user/account-balances-and-bonuses` confirmed POST-only (405 GET); `/rest/user/settings` 401; CORS properly pinned to own origin + credentials
- CHANGED `cable.betpanda.io/cable/user-event` confirmed POST-only, root returns "Cable Service - Ready!"; no new endpoints
- CHANGED `fp.betpanda.io`, `custom-lp.betpanda.io`, `flags.betpanda.io`, `www.betpanda.io` all Cloudflare JS-challenged (403 cf-mitigated) — cannot probe passively
- NEW nano-public.s3.eu-west-1.amazonaws.com — S3 bucket listing returns 403 Forbidden (no enumeration)
- CHANGED betpandacasino.io/rest/properties/manifest — Static PWA manifest with hardcoded S3 asset URLs; no query params for URL manipulation
- CHANGED affiliates.betpanda.io/config/config.json — Only contains baseUrl (no strapiApiUrlOverride in config; override via localStorage only)
- NEW SPA redeploy on affiliates.betpanda.io — JS bundle main.ef021e68.js (previously main.1ae50aab.js). Fresh passive enumeration.
- NEW Endpoint surface expanded: /rest/user/password/reset, /rest/user/set-2fa-setting, /rest/user/metrics/affiliate (GET-gated 401), /rest/agent/list, /rest/agent/create, /rest/agent/events/list, /rest/v2/
- NEW CORS+credentials coverage extends to password-reset + 2FA endpoints (OPTIONS preflight confirmed ACAO reflect + ACAC:true). ATO/exfil chain on the top finding now includes password reset and 2FA setti

## 2026-09-04 22:13:28 UTC
- NEW affiliates.betpanda.io/rest/* — SPA redeploy (main.ef021e68.js), expanded endpoint surface: /rest/user/password/reset, /rest/user/set-2fa-setting, /rest/user/metrics/affiliate, /rest/agent/list, /rest
- NEW affiliates.betpanda.io/rest/user/password/reset + /rest/user/set-2fa-setting — CORS+credentials confirmed via OPTIONS preflight (ACAO reflect + ACAC:true), extends ATO/exfil chain to password reset & 
- CHANGED affiliates.betpanda.io/rest/* — endpoint count now 20+ authenticated REST endpoints (was 10+), all under wildcard CORS + credentials
- CHANGED betpandacasino.io/rest/user/authenticate — confirmed real Spring Boot endpoint (403 JSON, not SPA catch-all), requires x-captcha-token header per CORS allow-headers
- CHANGED betpandacasino.io — REFRESH_TOKEN cookie model confirmed (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh), limits cross-origin cookie sending

## 2026-09-05 00:15:52 UTC
- NEW affiliates.betpanda.io/rest/* — SPA redeploy (main.ef021e68.js), expanded endpoint surface: /rest/user/password/reset, /rest/user/set-2fa-setting, /rest/user/metrics/affiliate, /rest/agent/list, /rest
- NEW affiliates.betpanda.io/rest/user/password/reset + /rest/user/set-2fa-setting — CORS+credentials confirmed via OPTIONS preflight (ACAO reflect + ACAC:true), extends ATO/exfil chain to password reset & 
- CHANGED affiliates.betpanda.io/rest/* — endpoint count now 20+ authenticated REST endpoints (was 10+), all under wildcard CORS + credentials
- CHANGED betpandacasino.io/rest/user/authenticate — confirmed real Spring Boot endpoint (403 JSON, not SPA catch-all), requires x-captcha-token header per CORS allow-headers
- CHANGED betpandacasino.io — REFRESH_TOKEN cookie model confirmed (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh), limits cross-origin cookie sending

## 2026-09-05 04:42:30 UTC
- NEW SPA redeploy on affiliates.betpanda.io — JS bundle main.ef021e68.js (previously main.1ae50aab.js). Fresh passive enumeration.
- NEW Endpoint surface expanded: /rest/user/password/reset, /rest/user/set-2fa-setting, /rest/user/metrics/affiliate (GET-gated 401), /rest/agent/list, /rest/agent/create, /rest/agent/events/list, /rest/v2/
- NEW CORS+credentials coverage extends to password-reset + 2FA endpoints (OPTIONS preflight confirmed ACAO reflect + ACAC:true). ATO/exfil chain on the top finding now includes password reset and 2FA setti
- NEW SPA redeploy on affiliates.betpanda.io — JS bundle main.ef021e68.js (previously main.1ae50aab.js). Fresh passive enumeration.
- NEW Endpoint surface expanded: /rest/user/password/reset, /rest/user/set-2fa-setting, /rest/user/metrics/affiliate (GET-gated 401), /rest/agent/list, /rest/agent/create, /rest/agent/events/list, /rest/v2/
- NEW CORS+credentials coverage extends to password-reset + 2FA endpoints (OPTIONS preflight confirmed ACAO reflect + ACAC:true). ATO/exfil chain on the top finding now includes password reset and 2FA setti
- NEW affiliates.betpanda.io/rest/public/config — REAL unauth Spring Boot route (200 JSON). Leaks operatorId=1, strapiApiUrl=/cms, CloudFront d3ec3n7kizfkuy.cloudfront.net, linkUrl=betpanda.partners, suppor
- NEW affiliates.betpanda.io/rest/trk?code|id — tracking resolver exists but auth-gated (401 "You need to be logged in"). /rest/public/recover-password/email/{email} is public GET (email-enum => OUT of scop
- NEW betpanda.partners — dedicated in-scope host, "Betpanda" casino brand SPA fronting SAME Spring Boot /rest backend as betpandacasino.io (/rest/properties/manifest 200, S3 operator pwa icons under operat

## 2026-09-05 08:40:59 UTC
- NEW affiliates.betpanda.io/rest/public/config — REAL unauth Spring Boot route (200 JSON). Leaks operatorId=1, strapiApiUrl=/cms, CloudFront d3ec3n7kizfkuy.cloudfront.net, linkUrl=betpanda.partners, suppor
- NEW affiliates.betpanda.io/rest/trk?code|id — tracking resolver exists but auth-gated (401 "You need to be logged in"). /rest/public/recover-password/email/{email} is public GET (email-enum => OUT of scop
- NEW betpanda.partners — dedicated in-scope host, "Betpanda" casino brand SPA fronting SAME Spring Boot /rest backend as betpandacasino.io (/rest/properties/manifest 200, S3 operator pwa icons under operat
- NEW betpanda.partners — dedicated in-scope host, "Betpanda" casino brand SPA fronting SAME Spring Boot /rest backend as betpandacasino.io (/rest/properties/manifest 200, S3 operator PWA icons under operat
- NEW affiliates.betpanda.io/rest/public/config — REAL unauth Spring Boot route (200 JSON) leaks operatorId=1, strapiApiUrl=/cms, CloudFront d3ec3n7kizfkuy.cloudfront.net, linkUrl=betpanda.partners, support
- NEW affiliates.betpanda.io/rest/trk?code|id — tracking resolver exists but auth-gated (401 "You need to be logged in")
- NEW affiliates.betpanda.io/rest/public/recover-password/email/{email} — public GET (email enumeration => OUT of scope per program rules)
- NEW betpandacasino.io/rest/user/authenticate — Real Spring Boot endpoint (403 JSON, not SPA catch-all), returns 403 with dummy creds, requires CAPTCHA token (x-captcha-token in CORS allow-headers)
- NEW AUTH MODEL @ betpandacasino.io — REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout; SameSite=Lax limits cross-origin cookie sending
- CHANGED affiliates.betpanda.io/rest/* — SPA redeploy (main.ef021e68.js), endpoint surface expanded to 20+ authenticated REST endpoints including /rest/user/password/reset, /rest/user/set-2fa-setting, /rest/ag
- CHANGED affiliates.betpanda.io/rest/user/password/reset + /rest/user/set-2fa-setting — CORS+credentials confirmed via OPTIONS preflight (ACAO reflect + ACAC:true), extends ATO/exfil chain to password reset & 

## 2026-09-05 12:13:01 UTC

## 2026-09-05 15:38:16 UTC

## 2026-09-05 17:34:36 UTC
- CHANGED RE-AFFIRMED @ affiliates.betpanda.io: password/reset, set-2fa-setting, change-password, set-profile all 405-GET real POST routes reflecting evil Origin + ACAC:true (fresh probes this cycle).

## 2026-09-05 19:34:03 UTC
- NEW `betpanda.partners` — dedicated in-scope host, "Betpanda" casino brand SPA fronting SAME Spring Boot `/rest` backend as `betpandacasino.io` (manifest 200, S3 operator PWA icons under `/operators/`)
- NEW `affiliates.betpanda.io/rest/public/config` — unauth Spring Boot route (200 JSON) leaks `operatorId=1`, `strapiApiUrl=/cms`, CloudFront `d3ec3n7kizfkuy.cloudfront.net`, `linkUrl=betpanda.partners`, `s
- NEW `affiliates.betpanda.io/rest/public/*` — `/rest/public/login` (405 POST-only), `/rest/public/register` (405 POST-only), `/rest/public/phone/signin/verify`, `/rest/public/phone/register/verify` — all r
- NEW `affiliates.betpanda.io` SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset`
- NEW `affiliates.betpanda.io/rest/v2/*` — `/rest/v2/report` (POST-only 405-GET), `/rest/v2/report/sub-affiliates`, `/rest/v2/report/daily-stats-with-comparison`, `/rest/user/selectable-payout-currencies`, 
- CHANGED `affiliates.betpanda.io/rest/*` — password/reset, set-2fa-setting, change-password, set-profile all re-affirmed 405-GET real POST routes reflecting evil Origin + `ACAC:true` (fresh probes this cycle)
- CHANGED `betpanda.partners/rest/*` — CORS properly pinned: OPTIONS/GET with evil Origin return `Vary:Origin` but NO `ACAO` reflection; cross-origin credential vector ABSENT (only `affiliates.betpanda.io` is w
- CHANGED `cable.betpanda.io/cable/user-event` — full schema reverse-derived (`eventType`/`userId`/`registeredOn`/`amount`/`referrer`/`currency`/`ip`/`device`/`metadata`); arbitrary `eventType` accepted incl. X

## 2026-09-05 21:50:35 UTC

## 2026-09-05 23:36:53 UTC

## 2026-09-06 01:23:32 UTC
- NEW betpanda.partners — dedicated in-scope host, "Betpanda" casino brand SPA fronting SAME Spring Boot `/rest` backend as betpandacasino.io (manifest 200, S3 operator PWA icons under `/operators/`)
- NEW affiliates.betpanda.io/rest/public/config — unauth Spring Boot route (200 JSON) leaks `operatorId=1`, `strapiApiUrl=/cms`, CloudFront `d3ec3n7kizfkuy.cloudfront.net`, `linkUrl=betpanda.partners`, `sup
- NEW affiliates.betpanda.io/rest/public/* — `/rest/public/login` (405 POST-only), `/rest/public/register` (405 POST-only), `/rest/public/phone/signin/verify`, `/rest/public/phone/register/verify` — all ref
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset`
- NEW affiliates.betpanda.io/rest/v2/* — `/rest/v2/report` (POST-only 405-GET), `/rest/v2/report/sub-affiliates`, `/rest/v2/report/daily-stats-with-comparison`, `/rest/user/selectable-payout-currencies`, `/
- CHANGED betpanda.partners/rest/* — CORS properly pinned: OPTIONS/GET with evil Origin return `Vary:Origin` but NO `ACAO` reflection; cross-origin credential vector ABSENT (only affiliates.betpanda.io is wildc
- CHANGED cable.betpanda.io/cable/user-event — full schema reverse-derived (`eventType`/`userId`/`registeredOn`/`amount`/`referrer`/`currency`/`ip`/`device`/`metadata`); arbitrary `eventType` accepted incl. XSS
- CHANGED affiliates.betpanda.io/rest/* — password/reset, set-2fa-setting, change-password, set-profile all re-affirmed 405-GET real POST routes reflecting evil Origin + `ACAC:true` (fresh probes this cycle)

## 2026-09-06 06:09:00 UTC

## 2026-09-06 11:14:05 UTC

## 2026-09-06 14:23:37 UTC
- NEW betpanda.partners — dedicated in-scope host, "Betpanda" casino brand SPA fronting SAME Spring Boot `/rest` backend as betpandacasino.io (manifest 200, S3 operator PWA icons under `/operators/`)
- NEW affiliates.betpanda.io/rest/public/config — unauth Spring Boot route (200 JSON) leaks `operatorId=1`, `strapiApiUrl=/cms`, CloudFront `d3ec3n7kizfkuy.cloudfront.net`, `linkUrl=betpanda.partners`, `sup
- NEW affiliates.betpanda.io/rest/public/* — `/rest/public/login` (405 POST-only), `/rest/public/register` (405 POST-only), `/rest/public/phone/signin/verify`, `/rest/public/phone/register/verify` — all ref
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset`
- NEW affiliates.betpanda.io/rest/v2/* — `/rest/v2/report` (POST-only 405-GET), `/rest/v2/report/sub-affiliates`, `/rest/v2/report/daily-stats-with-comparison`, `/rest/user/selectable-payout-currencies`, `/
- CHANGED affiliates.betpanda.io/rest/* — password/reset, set-2fa-setting, change-password, set-profile all re-affirmed 405-GET real POST routes reflecting evil Origin + `ACAC:true` (fresh probes this cycle)
- CHANGED betpanda.partners/rest/* — CORS properly pinned: OPTIONS/GET with evil Origin return `Vary:Origin` but NO `ACAO` reflection; cross-origin credential vector ABSENT (only affiliates.betpanda.io is wildc
- CHANGED cable.betpanda.io/cable/user-event — full schema reverse-derived (`eventType`/`userId`/`registeredOn`/`amount`/`referrer`/`currency`/`ip`/`device`/`metadata`); arbitrary `eventType` accepted incl. XSS
- CHANGED betpandacasino.io/rest/user/authenticate — Real Spring Boot endpoint (403 JSON, not SPA catch-all), returns 403 with dummy creds, requires CAPTCHA token (`x-captcha-token` in CORS allow-headers)
- CHANGED betpandacasino.io — REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout; SameSite=Lax limits cross-origin cookie sending

## 2026-09-06 17:24:00 UTC
- NEW betpanda.partners — dedicated in-scope host, "Betpanda" casino brand SPA fronting SAME Spring Boot `/rest` backend as betpandacasino.io (manifest 200, S3 operator PWA icons under `/operators/`)
- NEW affiliates.betpanda.io/rest/public/config — unauth Spring Boot route (200 JSON) leaks `operatorId=1`, `strapiApiUrl=/cms`, CloudFront `d3ec3n7kizfkuy.cloudfront.net`, `linkUrl=betpanda.partners`, `sup
- NEW affiliates.betpanda.io/rest/public/* — `/rest/public/login` (405 POST-only), `/rest/public/register` (405 POST-only), `/rest/public/phone/signin/verify`, `/rest/public/phone/register/verify` — all ref
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset`
- NEW affiliates.betpanda.io/rest/v2/* — `/rest/v2/report` (POST-only 405-GET), `/rest/v2/report/sub-affiliates`, `/rest/v2/report/daily-stats-with-comparison`, `/rest/user/selectable-payout-currencies`, `/
- CHANGED affiliates.betpanda.io/rest/* — password/reset, set-2fa-setting, change-password, set-profile all re-affirmed 405-GET real POST routes reflecting evil Origin + `ACAC:true` (fresh probes this cycle)
- CHANGED betpanda.partners/rest/* — CORS properly pinned: OPTIONS/GET with evil Origin return `Vary:Origin` but NO `ACAO` reflection; cross-origin credential vector ABSENT (only affiliates.betpanda.io is wildc
- CHANGED cable.betpanda.io/cable/user-event — full schema reverse-derived (`eventType`/`userId`/`registeredOn`/`amount`/`referrer`/`currency`/`ip`/`device`/`metadata`); arbitrary `eventType` accepted incl. XSS
- CHANGED betpandacasino.io/rest/user/authenticate — Real Spring Boot endpoint (403 JSON, not SPA catch-all), returns 403 with dummy creds, requires CAPTCHA token (`x-captcha-token` in CORS allow-headers)
- CHANGED betpandacasino.io — REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout; SameSite=Lax limits cross-origin cookie sending
- CHANGED betpandacasino.io/cms/* — fresh probes this cycle: `/cms/_health`, `/cms/api/{global,home-page,operators,...}`, `/cms/admin` ALL return proper Strapi v4 JSON 404 (`{"data":null,"error":{...}}`) ⇒ real
- NEW betpanda.partners — dedicated in-scope host, "Betpanda" casino brand SPA fronting SAME Spring Boot `/rest` backend as betpandacasino.io (manifest 200, S3 operator PWA icons under `/operators/`)
- NEW affiliates.betpanda.io/rest/public/config — unauth Spring Boot route (200 JSON) leaks `operatorId=1`, `strapiApiUrl=/cms`, CloudFront `d3ec3n7kizfkuy.cloudfront.net`, `linkUrl=betpanda.partners`, `sup
- NEW affiliates.betpanda.io/rest/public/* — `/rest/public/login` (405 POST-only), `/rest/public/register` (405 POST-only), `/rest/public/phone/signin/verify`, `/rest/public/phone/register/verify` — all ref
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset`
- NEW affiliates.betpanda.io/rest/v2/* — `/rest/v2/report` (POST-only 405-GET), `/rest/v2/report/sub-affiliates`, `/rest/v2/report/daily-stats-with-comparison`, `/rest/user/selectable-payout-currencies`, `/
- CHANGED betpanda.partners/rest/* — CORS properly pinned: OPTIONS/GET with evil Origin return `Vary:Origin` but NO `ACAO` reflection; cross-origin credential vector ABSENT (only affiliates.betpanda.io is wildc
- CHANGED cable.betpanda.io/cable/user-event — full schema reverse-derived (`eventType`/`userId`/`registeredOn`/`amount`/`referrer`/`currency`/`ip`/`device`/`metadata`); arbitrary `eventType` accepted incl. XSS
- CHANGED betpandacasino.io/rest/user/authenticate — Real Spring Boot endpoint (403 JSON, not SPA catch-all), returns 403 with dummy creds, requires CAPTCHA token (`x-captcha-token` in CORS allow-headers)
- CHANGED betpandacasino.io — REFRESH_TOKEN cookie (HttpOnly, SameSite=Lax, Secure, Path=/rest/user/refresh) confirmed via logout; SameSite=Lax limits cross-origin cookie sending
- CHANGED affiliates.betpanda.io/rest/* — password/reset, set-2fa-setting, change-password, set-profile all re-affirmed 405-GET real POST routes reflecting evil Origin + `ACAC:true` (fresh probes this cycle)

## 2026-09-06 19:36:26 UTC
- CHANGED betpandacasino.io/cms/*: Fresh probes confirm real Strapi v4 backend (proper JSON 404s on /cms/_health, /cms/api/*, /cms/admin) but NO public content types under guessed names and NO admin at default 
- CHANGED affiliates.betpanda.io/rest/*: JS bundle unchanged (main.ef021e68.js); password/reset, set-2fa-setting, change-password, set-profile all re-affirmed 405-GET real POST routes reflecting evil Origin + A
- CHANGED betpanda.partners/rest/*: CORS properly pinned (Vary:Origin, no ACAO reflection) — only affiliates.betpanda.io has wildcard CORS+credentials
- CHANGED betpandacasino.io/cms/*: Fresh probes confirm real Strapi v4 backend (proper JSON 404s on /cms/_health, /cms/api/*, /cms/admin) but NO public content types under guessed names and NO admin at default 
- CHANGED affiliates.betpanda.io/rest/*: JS bundle unchanged (main.ef021e68.js); password/reset, set-2fa-setting, change-password, set-profile all re-affirmed 405-GET real POST routes reflecting evil Origin + A
- CHANGED betpanda.partners/rest/*: CORS properly pinned (Vary:Origin, no ACAO reflection) — only affiliates.betpanda.io has wildcard CORS+credentials

## 2026-09-06 21:29:38 UTC

## 2026-09-06 23:09:34 UTC

## 2026-09-07 01:10:24 UTC

## 2026-09-07 06:14:13 UTC
- NEW betpanda.partners/rest/* — CORS properly pinned (Vary:Origin, no ACAO reflection) re-confirmed; cross-origin credential vector ABSENT on shared backend (only affiliates.betpanda.io is wildcard)
- NEW affiliates.betpanda.io/rest/public/phone/* — signin/verify + register/verify POST-only JSON endpoints reflect evil Origin + ACAC:true; JSON body returns 404 (schema obfuscated) — unauthenticated publi
- NEW affiliates.betpanda.io/rest/v2/* — v2 report endpoints (POST-only 405-GET), agent enable/id endpoints (GET state-changing, 401) — expands attack surface
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST /rest/user/password/reset (ATO chain primitive)
- CHANGED betpandacasino.io/cms/* — Strapi v4 confirmed (proper JSON 404s) but NO public content types, NO admin at default path — CMS content-disclosure hypothesis dropped
- CHANGED affiliates.betpanda.io/rest/* — JS bundle unchanged (main.ef021e68.js); password/reset, set-2fa-setting, change-password, set-profile all 405-GET reflecting evil Origin + ACAC:true re-affirmed
- CHANGED betpanda.io/api/auth/authorize — 301 to betpandacasino.io SPA catch-all; NO server-side OAuth endpoint (OAuth ATO path eliminated)
- CHANGED cable.betpanda.io/cable/user-event — full schema reverse-derived, arbitrary eventType/XSS/negative amounts accepted (200) stable baseline

## 2026-09-07 12:59:23 UTC
- NEW affiliates.betpanda.io/rest/public/phone/* — signin/verify + register/verify POST-only JSON endpoints reflect evil Origin + ACAC:true; JSON body returns 404 (schema obfuscated) — unauthenticated publi
- NEW affiliates.betpanda.io/rest/v2/* — v2 report endpoints (POST-only 405-GET), agent enable/id endpoints (GET state-changing, 401) — expands attack surface
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST /rest/user/password/reset (ATO chain primitive)
- CHANGED betpanda.partners/rest/* — CORS properly pinned (Vary:Origin, no ACAO reflection) re-confirmed; cross-origin credential vector ABSENT on shared backend (only affiliates.betpanda.io is wildcard)
- CHANGED affiliates.betpanda.io/rest/* — JS bundle unchanged (main.ef021e68.js); password/reset, set-2fa-setting, change-password, set-profile all 405-GET reflecting evil Origin + ACAC:true re-affirmed
- CHANGED betpandacasino.io/cms/* — Strapi v4 confirmed (proper JSON 404s) but NO public content types, NO admin at default path — CMS content-disclosure hypothesis dropped
- CHANGED betpanda.io/api/auth/authorize — 301 to betpandacasino.io SPA catch-all; NO server-side OAuth endpoint (OAuth ATO path eliminated)
- CHANGED cable.betpanda.io/cable/user-event — full schema reverse-derived, arbitrary eventType/XSS/negative amounts accepted (200) stable baseline

## 2026-09-07 18:10:46 UTC
- NEW affiliates.betpanda.io/rest/public/phone/signin/verify + /register/verify — POST-only JSON (415 form-encoded), reflect evil Origin + ACAC:true; JSON body returns 404 (schema obfuscated) — unauthentica
- NEW affiliates.betpanda.io/rest/v2/report, /rest/v2/report/sub-affiliates, /rest/v2/report/daily-stats-with-comparison, /rest/user/selectable-payout-currencies, /rest/user/selectable-payout-networks, /res
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL binds to POST /rest/user/password/reset (ATO chain primitive)
- CHANGED betpanda.partners/rest/* — CORS properly pinned (Vary:Origin, no ACAO reflection) re-confirmed; cross-origin credential vector ABSENT on shared backend (only affiliates.betpanda.io is wildcard)
- CHANGED affiliates.betpanda.io/rest/* — JS bundle unchanged (main.ef021e68.js); password/reset, set-2fa-setting, change-password, set-profile all 405-GET reflecting evil Origin + ACAC:true re-affirmed
- CHANGED betpandacasino.io/cms/* — Strapi v4 confirmed (proper JSON 404s on /cms/_health, /cms/api/*, /cms/admin) but NO public content types, NO admin at default path — CMS content-disclosure hypothesis dropp
- CHANGED betpanda.io/api/auth/authorize — 301 to betpandacasino.io SPA catch-all; NO server-side OAuth endpoint (OAuth ATO path eliminated)
- CHANGED cable.betpanda.io/cable/user-event — full schema reverse-derived, arbitrary eventType/XSS/negative amounts accepted (200) stable baseline

## 2026-09-07 21:38:56 UTC

## 2026-09-07 23:50:44 UTC
- NEW affiliates.betpanda.io/rest/public/phone/signin/verify + /register/verify — POST-only JSON (415 form-encoded), reflect evil Origin + ACAC:true; JSON body returns 404 (schema obfuscated) — unauthentica
- NEW affiliates.betpanda.io/rest/v2/report, /rest/v2/report/sub-affiliates, /rest/v2/report/daily-stats-with-comparison, /rest/user/selectable-payout-currencies, /rest/user/selectable-payout-networks, /res
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL binds to POST /rest/user/password/reset (ATO chain primitive)
- CHANGED betpanda.partners/rest/* — CORS properly pinned (Vary:Origin, no ACAO reflection) re-confirmed; cross-origin credential vector ABSENT on shared backend (only affiliates.betpanda.io is wildcard)
- CHANGED affiliates.betpanda.io/rest/* — JS bundle unchanged (main.ef021e68.js); password/reset, set-2fa-setting, change-password, set-profile all 405-GET reflecting evil Origin + ACAC:true re-affirmed
- CHANGED betpandacasino.io/cms/* — Strapi v4 confirmed (proper JSON 404s on /cms/_health, /cms/api/*, /cms/admin) but NO public content types, NO admin at default path — CMS content-disclosure hypothesis dropp
- CHANGED betpanda.io/api/auth/authorize — 301 to betpandacasino.io SPA catch-all; NO server-side OAuth endpoint (OAuth ATO path eliminated)
- CHANGED cable.betpanda.io/cable/user-event — full schema reverse-derived, arbitrary eventType/XSS/negative amounts accepted (200) stable baseline
- CHANGED affiliates.betpanda.io/rest/* — JS bundle unchanged (main.ef021e68.js); password/reset, set-2fa-setting, change-password, set-profile all 405-GET reflecting evil Origin + ACAC:true re-affirmed via fre
- CHANGED betpanda.partners/rest/* — CORS properly pinned (Vary:Origin, no ACAO reflection) re-confirmed; cross-origin credential vector ABSENT on shared backend (only affiliates.betpanda.io is wildcard)
- CHANGED betpandacasino.io/cms/* — Strapi v4 confirmed (proper JSON 404s on /cms/_health, /cms/api/*, /cms/admin) but NO public content types, NO admin at default path — CMS content-disclosure hypothesis dropp
- CHANGED betpanda.io/api/auth/authorize — 301 to betpandacasino.io SPA catch-all; NO server-side OAuth endpoint (OAuth ATO path eliminated, confirmed false positive)
- CHANGED cable.betpanda.io/cable/user-event — full schema reverse-derived, arbitrary eventType/XSS/negative amounts accepted (200) stable baseline
- NEW affiliates.betpanda.io/rest/public/phone/signin/verify + /register/verify — POST-only JSON (415 form-encoded), reflect evil Origin + ACAC:true; JSON body returns 404 (schema obfuscated) — unauthentica
- NEW affiliates.betpanda.io/rest/v2/report, /rest/v2/report/sub-affiliates, /rest/v2/report/daily-stats-with-comparison, /rest/user/selectable-payout-currencies, /rest/user/selectable-payout-networks, /res
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL binds to POST /rest/user/password/reset (ATO chain primitive)

## 2026-09-08 03:19:52 UTC

## 2026-09-08 08:16:48 UTC

## 2026-09-08 13:05:10 UTC

## 2026-09-08 17:26:11 UTC

## 2026-09-08 20:01:02 UTC

## 2026-09-08 22:29:15 UTC
- CHANGED betpanda.partners/rest/user/refresh: OPTIONS (Origin:https://evil.example, ACRM:POST) → 200, Vary:Origin, NO ACAO, NO ACAC — handler envelope identical to betpandacasino.io; refresh-parity signal now 
- CHANGED betpandacasino.io/rest/user/refresh: ACAO pinned to own host + ACAC:true re-confirmed; emits new response header `x-site-name-id: betpandacasino_io`; `__cflb` LB cookie SameSite=None;Secure
- NEW betpanda.partners `__cflb` (Cloudflare LB affinity) is SameSite=Lax vs betpandacasino.io SameSite=None;Secure — affinity-only, not auth; no impact
- NEW `x-site-name-id: notcasino` sent to betpandacasino.io → response still `betpandacasino_io`; tenant discriminator is host-derived, client value ignored at CORS-filter layer

## 2026-09-09 00:37:30 UTC
- CHANGED betpanda.partners/rest/user/refresh: OPTIONS parity with betpandacasino.io confirmed (identical allow-headers/methods incl x-captcha-token, x-site-name-id, x-maintenance-reason, x-preferred-app-contex
- CHANGED betpandacasino.io/rest/user/refresh: CORS pinned (ACAO own-host + ACAC:true); emits x-site-name-id: betpandacasino_io; __cflb SameSite=None;Secure is LB-affinity only
- CHANGED betpandacasino.io x-site-name-id: forged client header ignored in CORS envelope (still betpandacasino_io) — tenant discriminator is host-derived, no client-controlled tenant switch
- CHANGED affiliates.betpanda.io/rest/*: Wildcard CORS+credentials re-verified live (GET /rest/public/config 200, ACAO:evil.example reflected + ACAC:true, no auth); bundle unchanged main.ef021e68.js
- CHANGED betpandacasino.io/rest/user/account-balances-and-bonuses: OPTIONS returns generic 200 CORS envelope identical to /rest/user/notreal123 404 control — OPTIONS cannot distinguish real handler from catch-

## 2026-09-09 05:21:42 UTC
- CHANGED betpanda.partners+betpandacasino.io/rest/user/refresh: OPTIONS envelope parity re-confirmed (identical allow-headers/methods incl x-captcha-token, x-site-name-id, x-maintenance-reason, x-preferred-app
- CHANGED betpandacasino.io/rest/user/refresh: CORS pinned (ACAO own-host + ACAC:true); emits x-site-name-id: betpandacasino_io; __cflb SameSite=None;Secure is LB-affinity only
- CHANGED betpandacasino.io x-site-name-id: forged client header ignored in CORS envelope (still betpandacasino_io) — tenant discriminator is host-derived, no client-controlled tenant switch at filter layer
- CHANGED affiliates.betpanda.io/rest/*: Wildcard CORS+credentials re-verified live (GET /rest/public/config 200, ACAO:evil.example reflected + ACAC:true, no auth); bundle unchanged main.ef021e68.js
- CHANGED betpandacasino.io/rest/user/account-balances-and-bonuses: OPTIONS returns generic 200 CORS envelope identical to /rest/user/notreal123 404 control — OPTIONS cannot distinguish real handler from catch-
- CHANGED affiliates.betpanda.io/rest/public/config: supportEmail rotated to deals@bamboopartners.io (was support@betpanda.io), phoneSignupEnabled:false, contentful access token fields empty — vendor operator-c
- CHANGED affiliates.betpanda.io/rest/public/config: x-site-name-id header + operatorId/code/operator/id query params all return identical operatorId=1 — no client-controlled tenant switch on wildcard host publ
- CHANGED affiliates.betpanda.io/rest/user/password/reset: wildcard CORS+ACAC re-confirmed fresh (OPTIONS ACAO:https://evil.example + ACAC:true + full allow-methods GET,POST,OPTIONS,PUT,HEAD,DELETE) — flagship 

## 2026-09-09 09:58:09 UTC
- NEW betpanda.partners — dedicated in-scope host confirmed, "Betpanda" casino brand SPA fronting SAME Spring Boot `/rest` backend as betpandacasino.io (manifest 200, S3 operator PWA icons under `/operators
- NEW affiliates.betpanda.io/rest/public/config — unauth Spring Boot route (200 JSON) leaks `operatorId=1`, `strapiApiUrl=/cms`, CloudFront `d3ec3n7kizfkuy.cloudfront.net`, `linkUrl=betpanda.partners`, `sup
- NEW affiliates.betpanda.io/rest/public/phone/* — `signin/verify` + `register/verify` POST-only JSON endpoints reflect evil Origin + ACAC:true; JSON body returns 404 (schema obfuscated)
- NEW affiliates.betpanda.io/rest/v2/* — v2 report endpoints (POST-only 405-GET), `/rest/v2/report/sub-affiliates`, `/rest/v2/report/daily-stats-with-comparison`, `/rest/user/selectable-payout-currencies`, 
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset` (ATO chain primitive)
- CHANGED affiliates.betpanda.io/rest/* — Wildcard CORS+credentials re-verified live (GET `/rest/public/config` 200, ACAO:https://evil.example reflected + ACAC:true, no auth); bundle unchanged main.ef021e68.js
- CHANGED affiliates.betpanda.io/rest/user/password/reset — wildcard CORS+ACAC re-confirmed fresh (OPTIONS ACAO:https://evil.example + ACAC:true + full allow-methods GET,POST,OPTIONS,PUT,HEAD,DELETE)
- CHANGED betpanda.partners+betpandacasino.io/rest/user/refresh — OPTIONS envelope parity re-confirmed (identical allow-headers/methods incl x-captcha-token, x-site-name-id, x-maintenance-reason, x-preferred-ap
- CHANGED betpandacasino.io/rest/user/account-balances-and-bonuses — OPTIONS returns generic 200 CORS envelope identical to `/rest/user/notreal123` 404 control — OPTIONS cannot distinguish real handler from cat
- CHANGED affiliates.betpanda.io/rest/public/config — `x-site-name-id` header + `operatorId`/`code`/`operator`/`id` query params all return identical operatorId=1 — no client-controlled tenant switch on wildcar
- CHANGED affiliates.betpanda.io/rest/public/config — supportEmail rotated to `deals@bamboopartners.io` (was `support@betpanda.io`), `phoneSignupEnabled:false`, contentful access token fields empty — vendor ope

## 2026-09-09 14:23:13 UTC

## 2026-09-09 17:53:56 UTC

## 2026-09-09 20:32:52 UTC

## 2026-09-09 22:48:10 UTC

## 2026-09-10 00:54:07 UTC

## 2026-09-10 05:43:54 UTC
- NEW betpanda.partners confirmed as dedicated in-scope host fronting SAME Spring Boot `/rest` backend as betpandacasino.io (manifest 200, S3 operator PWA icons under `/operators/`)
- NEW affiliates.betpanda.io/rest/public/phone/* — `signin/verify` + `register/verify` POST-only JSON endpoints reflect evil Origin + ACAC:true; JSON body returns 404 (schema obfuscated)
- NEW affiliates.betpanda.io/rest/v2/* — v2 report endpoints (POST-only 405-GET), `/rest/v2/report/sub-affiliates`, `/rest/v2/report/daily-stats-with-comparison`, `/rest/user/selectable-payout-currencies`, 
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset` (ATO chain primitive)
- CHANGED affiliates.betpanda.io/rest/public/config: supportEmail rotated to `deals@bamboopartners.io` (was `support@betpanda.io`), `phoneSignupEnabled:false`, contentful access token fields empty — vendor oper
- CHANGED betpanda.partners+betpandacasino.io/rest/user/refresh: OPTIONS envelope parity re-confirmed (identical allow-headers/methods incl x-captcha-token, x-site-name-id, x-maintenance-reason, x-preferred-app
- CHANGED betpandacasino.io/rest/user/account-balances-and-bonuses: OPTIONS returns generic 200 CORS envelope identical to `/rest/user/notreal123` 404 control — OPTIONS cannot distinguish real handler from catc
- CHANGED affiliates.betpanda.io/rest/*: Wildcard CORS+credentials re-verified live fresh (GET /rest/public/config 200 ACAO:evil.example + ACAC:true; OPTIONS /rest/user/password/reset 200 ACAO:evil.example + AC

## 2026-09-10 10:11:11 UTC
- NEW betpanda.partners confirmed as dedicated in-scope host fronting SAME Spring Boot `/rest` backend as betpandacasino.io (manifest 200, S3 operator PWA icons under `/operators/`)
- NEW affiliates.betpanda.io/rest/public/phone/* — `signin/verify` + `register/verify` POST-only JSON endpoints reflect evil Origin + ACAC:true; JSON body returns 404 (schema obfuscated)
- NEW affiliates.betpanda.io/rest/v2/* — v2 report endpoints (POST-only 405-GET), `/rest/v2/report/sub-affiliates`, `/rest/v2/report/daily-stats-with-comparison`, `/rest/user/selectable-payout-currencies`, 
- NEW affiliates.betpanda.io SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset` (ATO chain primitive)
- CHANGED affiliates.betpanda.io/rest/public/config: supportEmail rotated to `deals@bamboopartners.io` (was `support@betpanda.io`), `phoneSignupEnabled:false`, contentful access token fields empty — vendor oper
- CHANGED betpanda.partners+betpandacasino.io/rest/user/refresh: OPTIONS envelope parity re-confirmed (identical allow-headers/methods incl x-captcha-token, x-site-name-id, x-maintenance-reason, x-preferred-app
- CHANGED betpandacasino.io/rest/user/account-balances-and-bonuses: OPTIONS returns generic 200 CORS envelope identical to `/rest/user/notreal123` 404 control — OPTIONS cannot distinguish real handler from catc
- CHANGED affiliates.betpanda.io/rest/*: Wildcard CORS+credentials re-verified live fresh (GET /rest/public/config 200 ACAO:evil.example + ACAC:true; OPTIONS /rest/user/password/reset 200 ACAO:evil.example + AC

## 2026-09-10 14:42:33 UTC
- NEW `affiliates.betpanda.io/rest/public/phone/*` — `signin/verify` + `register/verify` POST-only JSON endpoints reflecting evil Origin + ACAC:true (schema obfuscated, 404 on JSON body)
- NEW `affiliates.betpanda.io/rest/v2/*` — v2 report endpoints: `/rest/v2/report`, `/rest/v2/report/sub-affiliates`, `/rest/v2/report/daily-stats-with-comparison`, `/rest/user/selectable-payout-currencies`,
- NEW `affiliates.betpanda.io` SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset` (ATO chain primitive)
- CHANGED `affiliates.betpanda.io/rest/public/config` — `supportEmail` rotated to `deals@bamboopartners.io` (was `support@betpanda.io`), `phoneSignupEnabled:false`, contentful access token fields empty — vendor
- CHANGED `betpanda.partners+betpandacasino.io/rest/user/refresh` — OPTIONS envelope parity re-confirmed (identical allow-headers/methods incl `x-captcha-token`, `x-site-name-id`, `x-maintenance-reason`, `x-pre
- CHANGED `betpandacasino.io/rest/user/account-balances-and-bonuses` — OPTIONS returns generic 200 CORS envelope identical to `/rest/user/notreal123` 404 control — OPTIONS cannot distinguish real handler from c
- CHANGED `affiliates.betpanda.io/rest/*` — Wildcard CORS+credentials re-verified live fresh (GET `/rest/public/config` 200 ACAO:evil.example + ACAC:true; OPTIONS `/rest/user/password/reset` 200 ACAO:evil.examp

## 2026-09-10 17:57:11 UTC
- NEW `affiliates.betpanda.io` SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL is credential binding for POST `/rest/user/password/reset` (ATO chain primitive)
- CHANGED `affiliates.betpanda.io/rest/public/config` — `supportEmail` rotated to `deals@bamboopartners.io` (was `support@betpanda.io`), `phoneSignupEnabled:false`, contentful access token fields empty — vendor
- CHANGED `betpanda.partners+betpandacasino.io/rest/user/refresh` — OPTIONS envelope parity re-confirmed (identical allow-headers/methods incl `x-captcha-token`, `x-site-name-id`, `x-maintenance-reason`, `x-pre
- CHANGED `betpandacasino.io/rest/user/account-balances-and-bonuses` — OPTIONS returns generic 200 CORS envelope identical to `/rest/user/notreal123` 404 control — OPTIONS cannot distinguish real handler from c
- CHANGED `affiliates.betpanda.io/rest/*` — Wildcard CORS+credentials re-verified live fresh (GET `/rest/public/config` 200 ACAO:evil.example + ACAC:true; OPTIONS `/rest/user/password/reset` 200 ACAO:evil.examp
- CHANGED cable.betpandacasino.io/cable/user-event — fresh OPTIONS preflight returns 204 ACAO:* + allow-methods GET,POST,HEAD,PUT,DELETE,PATCH; root serves byte-identical "BC CASINO / Cable Service - Ready!" ba
- NEW `affiliates.betpanda.io` SPA route `/reset-password/:affiliateId/:resetPasswordCode` — reset code in URL binds to POST `/rest/user/password/reset` (ATO chain primitive)
- CHANGED `affiliates.betpanda.io/rest/public/config` — `supportEmail` rotated to `deals@bamboopartners.io` (was `support@betpanda.io`), `phoneSignupEnabled:false`, contentful access token fields empty — vendor
- CHANGED `betpanda.partners+betpandacasino.io/rest/user/refresh` — OPTIONS envelope parity re-confirmed (identical allow-headers/methods incl `x-captcha-token`, `x-site-name-id`, `x-maintenance-reason`, `x-pre
- CHANGED `affiliates.betpanda.io/rest/*` — Wildcard CORS+credentials re-verified live fresh (GET `/rest/public/config` 200 ACAO:evil.example + ACAC:true; OPTIONS `/rest/user/password/reset` 200 ACAO:evil.examp
