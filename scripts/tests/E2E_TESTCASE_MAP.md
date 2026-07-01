# E2E Test-Case Map

Structured mapping of **feature → scenario class → expected result**, so coverage
is deliberate (not just happy-path) and nothing is missed. Scenario classes:

- **HP** happy path · **VAL** validation/negative input · **NF** not-found ·
  **AZ** authn/authz (401/403/CSRF) · **IDOR** cross-tenant isolation ·
  **SM** state machine (valid + rejected transitions) · **BND** boundary
  (pagination/limits) · **IDMP** idempotency/dedup · **SEC** security guard.

Implemented by (single-auth, rate-limit-safe): `test_e2e_ctem_lifecycle.sh` (HP
across all areas), `test_e2e_regression_bugfixes.sh` (#228–242), and
`test_e2e_testcases.sh` (VAL/NF/AZ/IDOR/SM/BND/IDMP below).

Legend: ✅ implemented+passing · 🟡 implemented, see notes · ⬜ planned

## Auth & session
| TC | Scenario | Request | Expected | Status |
|---|---|---|---|---|
| AUTH-HP-1 | register→login→create-team | POST /auth/* | 201/200/201 | ✅ |
| AUTH-AZ-1 | no bearer token | GET /users/me (no auth) | 401 | ✅ |
| AUTH-AZ-2 | garbage token | GET /users/me (bad token) | 401 | ✅ |
| AUTH-AZ-3 | CSRF missing on mutation | POST /assets (no X-CSRF-Token) | 403 | ✅ |
| AUTH-VAL-1 | weak / missing password | POST /auth/register | 400/422 | ✅ |
| AUTH-SEC-1 | register rate limit | 4× POST /auth/register fast | 429 | ✅ |

## Assets
| TC | Scenario | Request | Expected | Status |
|---|---|---|---|---|
| ASSET-HP-1 | create/get/list/update | /assets | 201/200 | ✅ |
| ASSET-VAL-1 | missing criticality | POST /assets {name,type} | 422 | ✅ |
| ASSET-VAL-2 | invalid type enum | POST /assets type=bogus | 422 | ✅ |
| ASSET-VAL-3 | empty name | POST /assets name="" | 422 | ✅ |
| ASSET-NF-1 | get missing | GET /assets/{uuid} | 404 | ✅ |
| ASSET-NF-2 | get malformed id | GET /assets/not-a-uuid | 400 | ✅ |
| ASSET-IDOR-1 | tenant B reads A's asset | GET /assets/{A} as B | 404 | ✅ |

## Findings
| TC | Scenario | Request | Expected | Status |
|---|---|---|---|---|
| FIND-HP-1 | create/get/list/stats/groups | /findings | 200/201 | ✅ |
| FIND-VAL-1 | missing asset_id | POST /findings | 422 | ✅ |
| FIND-VAL-2 | invalid severity | POST /findings severity=x | 400/422 | ✅ |
| FIND-VAL-3 | nonexistent asset_id | POST /findings asset_id=uuid | 4xx | 🟡 |
| FIND-NF-1 | get missing | GET /findings/{uuid} | 404 | ✅ |
| FIND-NF-2 | patch missing status | PATCH /findings/{uuid}/status | 404 | ✅ |
| FIND-SM-1 | new→confirmed (valid) | PATCH status=confirmed | 200 | ✅ |
| FIND-SM-2 | new→resolved (invalid skip) | PATCH status=resolved | 4xx | ✅ |
| FIND-SM-3 | confirmed→in_progress (valid) | PATCH status=in_progress | 200 | ✅ |
| FIND-SM-4 | confirmed→fix_applied (invalid skip) | PATCH status=fix_applied | 4xx | ✅ |
| FIND-SM-5 | in_progress→fix_applied (valid, note) | PATCH status=fix_applied | 200 | ✅ |
| FIND-IDOR-1 | tenant B reads A's finding | GET /findings/{A} as B | 404 | ✅ |
| FIND-IDOR-2 | tenant B patches A's finding | PATCH /findings/{A}/status as B | 404/403 | ✅ |
| FIND-BND-1 | groups page 1 non-empty (#234) | GET /findings/groups | data≥1 | ✅ |
| FIND-BND-2 | per_page=0 | GET /findings?per_page=0 | no 500 | ✅ |
| FIND-IDMP-1 | ingest same finding twice | POST /findings ×2 | dedup, no dup | 🟡 |

## Exposures
| TC | Scenario | Request | Expected | Status |
|---|---|---|---|---|
| EXP-HP-1 | list/stats | /exposures | 200 | ✅ |
| EXP-VAL-1 | invalid severity filter (#238) | GET ?severity=criticl | 400 | ✅ |
| EXP-VAL-2 | invalid state filter | GET ?state=bogus | 400 | ✅ |

## Compliance
| TC | Scenario | Request | Expected | Status |
|---|---|---|---|---|
| CMP-HP-1 | list frameworks / stats | /compliance/* | 200 | ✅ |
| CMP-BND-1 | score in [0,100] (#230) | GET framework stats | 0≤s≤100 | ✅ |

## Remediation
| TC | Scenario | Request | Expected | Status |
|---|---|---|---|---|
| REM-HP-1 | create/get campaign | /remediation/campaigns | 201/200 | ✅ |
| REM-BND-1 | progress ≤100 (#242) | GET campaign | ≤100 | ✅ |

## Audit / Components / Threat-intel (regression-critical)
| TC | Scenario | Request | Expected | Status |
|---|---|---|---|---|
| AUD-BND-1 | per_page=0 no panic (#234) | GET /audit-logs/resource/../..?per_page=0 | no 500 | ✅ |
| CMPN-NF-1 | missing component (#233) | GET /components/{uuid} | 404 | ✅ |
| TI-VAL-1 | delete malformed actor id (#236) | DELETE /threat-actors/not-a-uuid | 400 | ✅ |
| TI-NF-1 | delete missing actor | DELETE /threat-actors/{uuid} | 404 | 🟡 |

## Dashboard / Workflows / Scans / Tools
| TC | Scenario | Request | Expected | Status |
|---|---|---|---|---|
| DASH-HP-1 | dashboard stats | /dashboard/stats | 200, no 500 | ✅ |
| WF-HP-1 | list workflows | /workflows | 200 | ✅ |
| WF-AZ-1 | member without perm creates workflow-scan action | (see api #225 unit) | blocked | ✅ (unit) |
| SCAN-HP-1 | list profiles/tools | /scan-profiles, /tools | 200 | ✅ |
