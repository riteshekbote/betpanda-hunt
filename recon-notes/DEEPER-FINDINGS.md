# Deeper findings — session 2026-09-03

_Generated 2026-09-03 | read-only passive enumeration | no active testing_

## 1. alfaview — OpenAPI spec exposed (HIGH VALUE)

**Location:** `https://apis.alfaview.com/v2/docs/openapi.yaml` (159KB)
**Discovery:** Stoplight Elements UI at `https://apis.alfaview.com/docs` loads the spec via `apiDescriptionUrl="/v2/docs/openapi.yaml"`.

### Endpoints (35+)

**Authentication:**
- `/v2/auth/api-key` — API key auth (companyId + clientId + key)
- `/v2/auth/password` — Password auth
- `/v2/auth/group-link` — Guest auth via group link (accessKey)
- `/v2/auth/guest-link` — Guest auth via guest link
- `/v2/auth/token-info` — Token introspection

**Rooms & Meetings:**
- `/v2/rooms` — List rooms
- `/v2/rooms/{id}` — Get room
- `/v2/rooms/{roomId}/participants` — List participants
- `/v2/rooms/{roomId}/permissions` — Room permissions
- `/v2/rooms/{roomId}/permissions/{userId}` — Per-user permissions (IDOR potential)
- `/v2/rooms/{roomId}/passcode` — Room passcode
- `/v2/rooms/{roomId}/features` — Room features
- `/v2/rooms/{roomId}/group-links` / `guest-links` — Guest access management
- `/v2/rooms/{roomId}/file-share-settings` / `file-share-limits`
- `/v2/rooms/{roomId}/subrooms` — Subroom management
- `/v2/meetings` — List/Create meetings
- `/v2/meetings/{id}` — Get/Update meeting
- `/v2/meetings/{id}/cancellation` — Cancel meeting

**Users & Admin:**
- `/v2/users` — List users
- `/v2/users/{id}` — Get user
- `/v2/users/me` — Current user
- `/v2/users/invitation` — Invite user
- `/v2/permission-groups` — Permission groups
- `/v2/room-types` — Room types
- `/v2/stats` — Statistics
- `/v2/languages` — Available languages

### Auth model
- API keys: `companyId` + `clientId` + `key` (in request body)
- Bearer tokens: base64-encoded `accessToken` in `Authorization` header
- Guest access: `accessKey` from group-link or guest-link

### Attack-relevant observations
- `/v2/rooms/{roomId}/permissions/{userId}` — classic IDOR pattern (room ID + user ID in path)
- Guest auth via `accessKey` — if keys are predictable/brute-forceable, guest impersonation possible
- `/v2/users/invitation` — user invitation endpoint (potential user enumeration or abuse)
- `/v2/stats` — statistics endpoint (potential info disclosure)
- `/v2/rooms/{roomId}/passcode` — passcode management (potential bypass)

### Additional alfaview observations
- All hosts behind `edge-proxy` (reverse proxy fingerprint)
- CSP on `app.alfaview.com` allows `omega-lectures.com` as frame-ancestor (third-party integration)
- No X-Frame-Options on ANY alfaview host (potential clickjacking, mitigated by CSP frame-ancestors on app)
- `internal.alfaview.com` and `beta-app.alfaview.com` use HTTP Basic auth

---

## 2. BASF — Azure Function Apps exposed (MEDIUM VALUE)

**Hosts:** `ap-digitalconnect.api.basf.com`, `ap-eupf.api.basf.com`
**Fingerprint:** Azure Function Apps (default page: "Your Azure Function App is up and running")

### Exposed admin endpoints
- `/admin/functions` → 401 (Bearer auth required)
- `/admin/host/status` → 401 (Bearer auth required)
- `/admin/host/keys` → 401 (Bearer auth required)
- `/.env` → 403 (exists, blocked)

### Attack surface
- Azure Functions admin API requires function master key or system key
- If key is weak/default/leaked, full admin access to Function App
- Common Azure Functions key patterns: `<hex>-<hex>`, default keys in `host.json`
- Dev endpoints (`dev-clientcert-sap`, `dev-ext001`) require client certificates (400)

---

## 3. daimlertruck — Lockdown confirmed (NO UNAUTH FINDING)

- APIM gateways: all paths return `OperationNotFound` (no unauth surface)
- Developer portals: Next.js, login-gated (307 → callbackUrl)
- Authz services: empty 404 at root
- Management/capacitor hosts: unreachable (NAT64/IPv6 only)

**Honest assessment: surface is properly locked down against unauthenticated attackers.**

---

## 4. betpanda — Vite SPA with affiliate portal

- `affiliates.betpanda.io` — Vite-built SPA (main.1ae50aab.js)
- Cloudflare-fronted
- No API routes found in JS bundle
- Standard affiliate portal structure

---

## 5. elringklinger — Third-party integrations

- `go.events.elringklinger.com` — 302 redirect (event management platform)
- `ir.elringklinger.com` — Apache, investor relations page

---

## 6. avatarux — Atlassian + cPanel

- `help.desk.avatarux.com` — Atlassian Edge (Jira/Confluence help desk)
- `autoconfig.avatarux.com` — Apache autoconfig
- `cpanel.avatarux.com` — cPanel (if accessible)

---

_Honest framing: all observations from read-only passive enumeration. No vulnerability claimed. Scope must be confirmed before active testing on any of these live production assets._
