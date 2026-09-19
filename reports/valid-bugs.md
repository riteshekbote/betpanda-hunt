# Validated findings (running count 0)

- 5 lead(s) marked VALID at 2026-09-04 14:04:02 UTC
  - **Verdict: VALID**
  - | Q2 Reachable | **Yes** — requires valid user JWT (low-priv authenticated) |
  - **Verdict: VALID**
  - | 1 | Wildcard CORS + credentials | `affiliates.betpanda.io/rest/*` | **VALID** | 9.1 Critical |
  - | 2 | BOLA/IDOR money-flow | `betpandacasino.io/rest/user/*` | **VALID** | 8.1 High |

- 2 lead(s) marked VALID at 2026-09-05 00:13:34 UTC
  - **VERDICT: VALID**
  - | CORS+credentials | MISCONFIG | affiliates.betpanda.io | **VALID** | 9.1 |

- 2 lead(s) marked VALID at 2026-09-05 04:39:08 UTC
  - **VERDICT: VALID**
  - | 1 | CORS+credentials ATO chain | affiliates.betpanda.io | **VALID** | 9.1 |

- 3 lead(s) marked VALID at 2026-09-06 06:07:25 UTC
  - | Q5 | Novel/unreported? | **Yes** — independently discovered by bigpickle and nemotron3; no prior reports in valid-bugs.md prior to 2026-09-04 |
  - **Verdict: VALID**
  - | 1 | Wildcard CORS+creds (`affiliates.betpanda.io`) | **VALID** | 9.1 | Report to bugs.olivermaicher.eu |

- 2 lead(s) marked VALID at 2026-09-07 21:36:23 UTC
  - **VERDICT: VALID**
  - | 1 | Affiliates CORS+credentials | **VALID** | 9.1 | YES — bugs.olivermaicher.eu |

- 2 lead(s) marked VALID at 2026-09-15 11:18:16 UTC
  - **Verdict: VALID**
  - | 1 | Wildcard CORS + credentials on affiliates.betpanda.io REST API | **VALID** | 9.1 Critical | Yes |

- 1 lead(s) marked VALID at 2026-09-15 15:37:25 UTC
  - | 1 | Wildcard CORS + credentials on `affiliates.betpanda.io/rest/*` | **VALID** | 9.1 Critical |

- 2 lead(s) marked VALID at 2026-09-16 15:02:40 UTC
  - **VERDICT: VALID**
  - | CORS+credentials affiliates.betpanda.io | **VALID** | 8.1 |

- 6 lead(s) marked VALID at 2026-09-19 16:50:18 UTC
  - | Q5 Novel/unreported? | **Likely yes** | No prior report found in `reports/valid-bugs.md` or triage history; bot self-consistently confirms this across 10+ cycles since Sep 3. |
  - **Verdict: VALID**
  - | Q2 Attacker reachable? | **Partial** | Endpoints are real Spring Boot (403/401/405 responses confirm handlers exist). Requires valid Cognito JWT to reach authenticated handlers. |
  - | Q5 Novel/unreported? | **Likely yes** | Not in prior valid bugs list. |
  - | Q6 Not always-rejected? | **Yes** | Unauthenticated data ingestion with injection surface is a valid bounty class. |
  - | Wildcard CORS + Credentials (affiliates) | **VALID** | 9.1 Critical | Report to bugs.olivermaicher.eu |
