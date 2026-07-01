# E2E Feature-Flow Test Status

Persistent checklist + status for **every feature flow** in the OpenCTEM API, so
nothing is missed across context boundaries. Run against a live API + DB.

## How to run

```bash
# one flow
bash scripts/tests/test_e2e_findings.sh http://localhost:8080

# all flows, record status to .e2e_results.tsv (respects 3/min auth rate limit)
bash scripts/tests/run_status.sh http://localhost:8080 25

# regression guards for the 2026-07 bug-hunt fixes (api #228-242)
bash scripts/tests/test_e2e_regression_bugfixes.sh
```

Shared helpers live in `_e2e_common.sh` (`e2e_bootstrap_auth`, `do_request`
auto-injects the `X-CSRF-Token` double-submit header, `assert_status/assert_json`).

## ⚠️ Environment finding (FIXED 2026-07-01)

The running API was on code that expects migration **000183** (`users.federated_issuer`)
but the DB was at **179** — migrations **180–183 (scim_groups, scim_group_role_mappings,
saml_providers, user_federated_identity) were never applied**. Effect: **every auth
call (register/login) returned HTTP 500** (`column "federated_issuer" does not exist`),
and SCIM/SAML tables were missing. Applied 180–183 + set `schema_migrations.version=183`.
**Action item:** ensure the deploy pipeline runs `migrate up` after image rollout.

## Regression guards — 2026-07 bug-hunt fixes (api #228–242)

`test_e2e_regression_bugfixes.sh` — **15/15 PASS** ✅ (validated live). Covers:
component 404 (#233), audit `?per_page=0` no-panic (#234), findings/groups page-1
non-empty (#234), invalid exposure filter→400 (#238), threat-actor malformed-id→400
(#236), BulkFixApplied `failed` field (#241), compliance score ∈[0,100] (#230).

## Feature-flow checklist

Legend: ✅ PASS · ❌ FAIL · ⚠️ partial/needs-triage · ⏳ running · ⬜ not yet run

| # | Flow (script) | Feature area | Status | Notes |
|---|---|---|---|---|
| 1 | test_e2e_auth_lifecycle | Auth / session | ⏳ | register→login→refresh→logout |
| 2 | test_e2e_sso | Auth / SSO | ⏳ | SSO provider config |
| 3 | test_e2e_tenant_management | Tenant | ⏳ | create/list/members |
| 4 | test_e2e_permissions | RBAC | ⏳ | permission checks |
| 5 | test_e2e_team_rbac | RBAC | ⏳ | roles / membership |
| 6 | test_e2e_assets | Assets | ⏳ | CRUD asset |
| 7 | test_e2e_asset_services | Assets | ⏳ | ports/services |
| 8 | test_e2e_state_history | Assets | ⏳ | state history |
| 9 | test_e2e_tools_registry | Tools | ⏳ | tool registry |
| 10 | test_e2e_findings | Findings | ⏳ | finding lifecycle |
| 11 | test_e2e_finding_activities | Findings | ⏳ | activity log |
| 12 | test_e2e_finding_approvals | Findings | ⏳ | approval workflow |
| 13 | test_e2e_fix_lifecycle | Findings | ⏳ | fix-applied→verify→resolve |
| 14 | test_e2e_bulk_status | Findings | ⏳ | bulk status ops |
| 15 | test_e2e_ingest | Ingest | ⏳ | CTIS ingest |
| 16 | test_e2e_scans | Scanning | ⏳ | scan CRUD/trigger |
| 17 | test_e2e_advanced_scanning | Scanning | ⏳ | advanced scan |
| 18 | test_e2e_scan_phase1_2 | Scanning | ⏳ | scan phases |
| 19 | test_e2e_scan_export_import | Scanning | ⏳ | export/import config |
| 20 | test_e2e_scanner_templates | Scanning | ⏳ | scanner templates |
| 21 | test_e2e_exposures | Exposures | ⏳ | exposure CRUD/filter |
| 22 | test_e2e_compliance | Compliance | ⏳ | frameworks/assessments/score |
| 23 | test_e2e_policies | Policy | ⏳ | policy engine |
| 24 | test_e2e_dashboard | Dashboard | ⏳ | stats/trends |
| 25 | test_e2e_platform_stats | Dashboard | ⏳ | platform stats |
| 26 | test_e2e_integrations | Integrations | ⏳ | connectors |
| 27 | test_e2e_notifications | Notifications | ⏳ | notification channels |
| 28 | test_e2e_threat_intel | Threat intel | ⏳ | EPSS/KEV/actors |
| 29 | test_e2e_scope | Data scope | ⏳ | scoping |
| 30 | test_e2e_scope_hardening | Data scope | ⏳ | scope isolation |
| 31 | test_e2e_group_sync | Groups | ⏳ | group sync |
| 32 | test_e2e_pentest_rbac | Pentest | ⏳ | pentest RBAC |
| 33 | test_e2e_workflows | Workflows | ⏳ | workflow engine |
| 34 | test_e2e_attachments | Attachments | ⏳ | file attachments |
| 35 | test_e2e_security_fixes | Security | ⏳ | security controls |
| 36 | test_e2e_edge_cases | Robustness | ⏳ | edge/error cases |
| 37 | test_full_flow | Smoke | ⏳ | register→scan smoke |
| R | test_e2e_regression_bugfixes | Regression | ✅ | 15/15 (see above) |

_Status column is populated by `run_status.sh` → `.e2e_results.tsv`; this table is
updated after each full run._
