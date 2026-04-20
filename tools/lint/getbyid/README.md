# getbyidtenant analyzer (F-310)

Flags repository methods named `GetByID`, `UpdateByID`, or `DeleteByID`
that lack a `tenantID` parameter. Prevents the IDOR class that F-4 and
F-5 hardened from re-appearing through a new repository.

## Run locally

```bash
cd api
GOWORK=off go run ./tools/lint/getbyid/cmd ./internal/infra/postgres/...
```

Exit code is non-zero when any flagged method is missing a tenant
parameter — suitable for CI.

## Opt-out

Any repository method that is **intentionally** tenant-less (shared
catalogues, platform-agent auth lookup, operator-only reads) can
suppress the diagnostic by adding this comment directly above the
declaration:

```go
//getbyid:unsafe - Foo is a shared catalogue table; safe to lookup by ID alone.
func (r *FooRepository) GetByID(ctx context.Context, id shared.ID) (*foo.Foo, error) {
```

The directive is grep-able so an auditor can enumerate every exception
at once.

## Wire into CI

Add to `.github/workflows/ci.yml` (Go tests job):

```yaml
      - name: Tenant-scope lint
        working-directory: api
        run: |
          GOWORK=off go run ./tools/lint/getbyid/cmd ./internal/infra/postgres/...
```

## Baseline

**Current ceiling:** 40 diagnostics (Q1/WS-F progress — down from 56 at
baseline). Enforced as a regression test in
`baseline_test.go:TestGetByIDLinter_BaselineNotRegressed` — adding a new
unscoped `GetByID` will fail CI.

Category breakdown (per `docs/audits/2026-04-unscoped-getbyid-audit.md`):

- **Category A (annotated, `//getbyid:unsafe`):** user, tenant, session,
  refresh_token, vulnerability, asset_type, tool, toolcategory,
  target_mapping, compliance_control, rule, rule_bundle, rule_source,
  asset_source, finding_source, finding_source_category, admin.
  These are global catalogs or primary-key-is-identity tables — safe
  by construction. 17 opt-outs landed.
- **Category B (already in docs):** agent / tool_execution — documented
  in F-4/F-5 fixes.
- **Category C (remaining, ~39 diagnostics):** tenant-scoped tables
  where the method needs a `GetByTenantAndID` sibling or a parameter
  change. This is the Q1/WS-F blocking item still to grind through
  — each one is a mechanical change plus caller migration.

## Flip to blocking

To make the linter a hard CI gate:

1. Lower `baselineCeiling` in `baseline_test.go` to 0.
2. Add this step to `.github/workflows/security.yml` under
   `ctem-gates`:

   ```yaml
   - name: F-310 tenant-scope lint
     working-directory: api
     run: GOWORK=off go run ./tools/lint/getbyid/cmd ./internal/infra/postgres/...
   ```

3. Only do this AFTER Category C is fully migrated.
