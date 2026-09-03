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
