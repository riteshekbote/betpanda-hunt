# Validated findings (running count 0)

- 5 lead(s) marked VALID at 2026-09-04 14:04:02 UTC
  - **Verdict: VALID**
  - | Q2 Reachable | **Yes** — requires valid user JWT (low-priv authenticated) |
  - **Verdict: VALID**
  - | 1 | Wildcard CORS + credentials | `affiliates.betpanda.io/rest/*` | **VALID** | 9.1 Critical |
  - | 2 | BOLA/IDOR money-flow | `betpandacasino.io/rest/user/*` | **VALID** | 8.1 High |
