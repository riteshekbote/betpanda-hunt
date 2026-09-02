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
