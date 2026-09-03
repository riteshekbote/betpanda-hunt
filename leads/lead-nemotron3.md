## 2026-09-03 17:03:40 UTC [target] (model nemotron3)
[PRIO] dashboard.betpanda.io,7.3,attack_surface=8,business_value=9,tech_exposure=8,gate_ease=3,cloud_surface=9,freshness=5
[PRIO] affiliates.betpanda.io,7.0,attack_surface=7,business_value=8,tech_exposure=5,gate_ease=8,cloud_surface=6,freshness=7
[PRIO] betpanda.io,6.3,attack_surface=6,business_value=8,tech_exposure=5,gate_ease=7,cloud_surface=6,freshness=4
[PRIO] cable.betpanda.io,6.15,attack_surface=6,business_value=6,tech_exposure=5,gate_ease=8,cloud_surface=5,freshness=7
[PRIO] fp.betpanda.io,4.8,attack_surface=5,business_value=4,tech_exposure=6,gate_ease=3,cloud_surface=5,freshness=7
[PRIO] custom-lp.betpanda.io,4.5,attack_surface=4,business_value=5,tech_exposure=4,gate_ease=3,cloud_surface=5,freshness=7
[HYP] k8s Dashboard Exposure via AWS ALB
class: MISCONFIG
asset: dashboard.betpanda.io
confidence: 65
reasoning: CNAME resolves to AWS ALB with k8s naming pattern (k8s-kubernet-albdashb-). Kubernetes dashboards frequently exposed via ALB with weak/default auth or misconfigured RBAC.
evidence_needed: HTTP response showing k8s dashboard UI or unauthenticated API endpoints (/api/v1/namespaces/kubernetes-dashboard)
verify_steps: GET https://dashboard.betpanda.io/; GET https://dashboard.betpanda.io/api/; GET https://dashboard.betpanda.io/api/v1/namespaces/kubernetes-dashboard
impact: Full cluster access, secrets, all workloads - CRITICAL
testability: PASSIVE
[HYP] Affiliate Portal IDOR on Commission/Referral Endpoints
class: IDOR
asset: affiliates.betpanda.io
confidence: 60
reasoning: Vite SPA affiliate portal handling money flows (commissions/referrals). SPA bundles often hide API endpoints with user_id/account_id params. Affiliate systems classic IDOR targets.
evidence_needed: Hidden API endpoints in JS bundles, IDOR on /api/affiliates/{id}/commissions or /api/referrals/{code}
verify_steps: GET https://affiliates.betpanda.io/ (analyze main.1ae50aab.js for API paths); GET https://affiliates.betpanda.io/api/; check for /api/v1/affiliates/{id} patterns
impact: Cross-affiliate commission theft, PII access - HIGH
testability: PASSIVE
[HYP] OAuth Redirect_URI Validation Flaw on Main Platform
class: OAUTH
asset: betpanda.io
confidence: 55
reasoning: Main betting platform likely implements OAuth/OIDC for login. Gambling platforms with multiple subdomains often have loose redirect_uri validation allowing code theft via open redirect.
evidence_needed: OAuth authorize endpoint, redirect_uri parameter acceptance of external domains, missing state validation
verify_steps: GET https://betpanda.io/ (locate login/OAuth); GET https://betpanda.io/api/auth/authorize?redirect_uri=https://evil.com&state=test&client_id=test (passive probe)
impact: Account takeover via authorization code theft - CRITICAL
testability: PASSIVE
[FINAL] 1. k8s Dashboard Exposure via AWS ALB (dashboard.betpanda.io, 65)
[FINAL] 2. Affiliate Portal IDOR on Commission/Referral Endpoints (affiliates.betpanda.io, 60)
[FINAL] 3. OAuth Redirect_URI Validation Flaw on Main Platform (betpanda.io, 55)
[NEXT] PROBE: GET https://dashboard.betpanda.io/ (passive, read-only, confirm k8s dashboard exposure)
[LEARN] No prior hypotheses to evaluate — first analysis cycle.
[RISK] betpanda: 75 — New dedicated attack surface (4 hosts), k8s dashboard on AWS ALB, affiliate money-flow SPA, main betting platform OAuth surface. High-value target classes present (MISCONFIG, IDOR, OAUTH).
