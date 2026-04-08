# Test Suite

Comprehensive test scripts for the OpenCTEM API. Covers E2E flows, security, edge cases, and integrations.

## Prerequisites

```bash
# Required tools
curl --version    # HTTP client
jq --version      # JSON processor
python3 --version # For test_oss_api.py only

# API must be running
curl http://localhost:8080/health
# {"status":"healthy"}

# Registration must be enabled (for test user creation)
# AUTH_ALLOW_REGISTRATION=true
```

## Quick Start

### Run all E2E tests

```bash
# Run entire suite (auto-waits 62s between scripts for rate limiting)
./run_all_e2e.sh http://localhost:8080

# Run with custom API URL
./run_all_e2e.sh https://api.staging.yourcompany.com
```

### Run a single test

```bash
# Run specific test
./test_e2e_assets.sh http://localhost:8080

# Default URL is http://localhost:8080 if not specified
./test_e2e_security_fixes.sh
```

### Run security tests

```bash
./run_security_tests.sh http://localhost:8080
```

## Test Scripts

### E2E Tests (33 scripts)

Each script: registers a test user → creates a team → runs tests → cleans up.

| Script | Tests | What it covers |
|--------|-------|----------------|
| `test_e2e_assets.sh` | ~23 | Asset CRUD, groups, relationships, components, stats |
| `test_e2e_findings.sh` | ~23 | Finding CRUD, severity, status, comments |
| `test_e2e_finding_activities.sh` | ~16 | Finding activity timeline, comments |
| `test_e2e_finding_approvals.sh` | ~30 | Approval workflows, verify, reject |
| `test_e2e_fix_lifecycle.sh` | ~14 | Fix Applied → Verify → Resolve lifecycle |
| `test_e2e_auth_lifecycle.sh` | ~18 | Register, login, token refresh, password reset |
| `test_e2e_team_rbac.sh` | ~23 | Roles, permissions, member management |
| `test_e2e_permissions.sh` | ~21 | RBAC owner vs member, permission boundaries |
| `test_e2e_tenant_management.sh` | ~20 | Tenant CRUD, settings, invitations |
| `test_e2e_scans.sh` | ~22 | Scan creation, status, results |
| `test_e2e_advanced_scanning.sh` | ~24 | Scan profiles, pipelines, tools |
| `test_e2e_scan_export_import.sh` | ~22 | Scan result export/import |
| `test_e2e_scanner_templates.sh` | ~23 | Scanner template CRUD |
| `test_e2e_ingest.sh` | ~16 | CTIS/SARIF ingestion, batch processing |
| `test_e2e_integrations.sh` | ~22 | Integration CRUD, SSRF protection |
| `test_e2e_notifications.sh` | ~18 | Webhook/Slack integrations, notification rules |
| `test_e2e_scope.sh` | ~21 | Scope targets, exclusions |
| `test_e2e_scope_hardening.sh` | ~63 | Scope edge cases, validation |
| `test_e2e_exposures.sh` | ~20 | Exposure event tracking |
| `test_e2e_asset_services.sh` | ~16 | Asset service extensions |
| `test_e2e_state_history.sh` | ~18 | Asset state change history |
| `test_e2e_bulk_status.sh` | ~19 | Bulk asset status updates |
| `test_e2e_policies.sh` | ~22 | SLA policies |
| `test_e2e_tools_registry.sh` | ~21 | Tool registry CRUD |
| `test_e2e_threat_intel.sh` | ~20 | Threat intelligence |
| `test_e2e_workflows.sh` | ~20 | Workflow engine |
| `test_e2e_group_sync.sh` | ~12 | Group synchronization |
| `test_e2e_platform_stats.sh` | ~15 | Platform statistics |
| `test_e2e_compliance.sh` | ~15 | Compliance frameworks, controls |
| `test_e2e_dashboard.sh` | ~10 | Dashboard summary stats |
| `test_e2e_sso.sh` | ~28 | SSO provider CRUD, authorize flow |
| `test_e2e_security_fixes.sh` | ~31 | SSRF, IDOR, header injection, auth bypass |
| `test_e2e_edge_cases.sh` | ~75 | Input validation, overflow, injection |

### Security Tests

| Script | What it covers |
|--------|----------------|
| `run_security_tests.sh` | Orchestrates all security test scripts |
| `test_security_controls.go` | Go-based security control verification |
| `test_e2e_security_fixes.sh` | SSRF (8 vectors), IDOR, JWT forgery, auth bypass |
| `test_e2e_edge_cases.sh` | SQLi, XSS, null bytes, overflow, CRLF injection |

### Other Tests

| Script | What it covers |
|--------|----------------|
| `test_full_flow.sh` | Full user flow: register → scan → findings → remediate |
| `test_oss_api.py` | Python API test suite (comprehensive) |
| `test_workflow_executor.go` | Workflow engine unit tests |
| `test_agent_analytics.sh` | Agent statistics and analytics |
| `test-assignment-rules.sh` | Auto-assignment rule testing |
| `test_data_scope.sh` | Data scope isolation verification |
| `test_data_scope_ux.sh` | Data scope UX flows |
| `test_notification_outbox.sh` | Notification outbox pattern |
| `test_notification_outbox_e2e.sh` | Notification delivery E2E |
| `test_notification_history.sh` | Notification history queries |
| `test_suppression_api.sh` | Finding suppression rules |

## Output Format

All bash test scripts output in this format:

```
=== Section Name ===

>>> Test: Description
  PASSED: What passed
  FAILED: What failed — Error details

==============================================================================
Test Summary
==============================================================================

  Passed:  42
  Failed:  0
  Skipped: 1
  Total Tests: 43

  All tests passed!
```

Exit codes:
- `0` — all tests passed
- `1` — one or more tests failed

## Running Unit Tests

Separate from E2E scripts — these are Go tests:

```bash
# All unit tests
cd api
make test

# Or directly
GOWORK=off go test ./tests/unit/... -v

# Specific test
GOWORK=off go test ./tests/unit/ -run TestAssetService -v

# With coverage
GOWORK=off go test ./tests/unit/... -cover
```

Unit test files are in `api/tests/unit/` (103 files).

### Security unit tests

```bash
# SSRF validation
GOWORK=off go test ./pkg/validator/ -run TestValidateWebhookURL -v

# Header injection
GOWORK=off go test ./internal/infra/http/handler/ -run TestIsValidHostHeader -v

# OAuth redirect validation
GOWORK=off go test ./internal/infra/http/handler/ -run TestOAuthRedirect -v

# ExtraArgs command injection (agent)
cd agent
go test ./internal/executor/ -run TestValidateExtraArgs -v
```

## Rate Limiting

E2E tests register new users. Auth endpoints are rate limited:
- Registration: 3/min per IP
- Login: 5/min per IP

The `run_all_e2e.sh` script automatically waits 62 seconds between test scripts to avoid rate limiting.

If running individual scripts back-to-back, wait at least 60 seconds:

```bash
./test_e2e_assets.sh && sleep 62 && ./test_e2e_findings.sh
```

## Writing New Tests

Follow the existing pattern:

```bash
#!/bin/bash
# test_e2e_myfeature.sh

API_URL="${1:-http://localhost:8080}"
PASS=0; FAIL=0

# Setup: register + login + create team
# ... (copy from any existing test)

# Test
print_test "My test description"
do_request POST "/api/v1/my-endpoint" '{"key":"value"}' "$(auth_header)"
if [ "$HTTP_CODE" = "200" ]; then
  print_success "It worked"
else
  print_failure "Expected 200, got $HTTP_CODE"
fi

# Summary
echo "Passed: $PASS, Failed: $FAIL"
exit $FAIL
```

## CI/CD Integration

Add to GitHub Actions:

```yaml
- name: Run E2E tests
  run: |
    cd api/scripts/tests
    ./run_all_e2e.sh ${{ env.API_URL }}
```

Or run individual critical tests:

```yaml
- name: Security tests
  run: ./api/scripts/tests/test_e2e_security_fixes.sh $API_URL

- name: Asset tests
  run: ./api/scripts/tests/test_e2e_assets.sh $API_URL
```
