# RFC-095: CI gate settings per repository

| | |
|---|---|
| Status | Proposed (2026-10-15). Implemented: per-field layering with locks, reasons and expiry; the gate baseline settings; the effective-settings API; the `has_policy_override` pipelines filter and per-field override counts. Designed: the console Settings tab of a pipeline and bulk apply by name pattern |
| Scope | api, web |
| Related | RFC-051 (CI runner identity and the gate; §6.2 gate baseline), RFC-077 (enforced gate, `.openctem.yml`), RFC-091 (code scanning baseline) |

## 1. Summary

The gate policy already has three layers: organization, business unit and repository. Until now a lower layer
replaced the whole policy. A repository that only needed a stricter severity copied every other value, and those
copies stopped following later organization changes. Nothing stopped a lower layer from loosening what the
organization wanted fixed, and a loosening repository policy had no reason and no end.

This RFC makes the policy **per field**:

```
built-in default
  └─ organization            sets every field, may lock fields
      └─ business unit(s)    sets some fields, may lock fields; several units: strictest per field
          └─ repository      sets some fields; reason; optional expiry
              └─ .openctem.yml  tighten only (unchanged), only if allow_repo_policy
```

## 2. Fields

`mode`, `fail_on_severity`, `new_findings_only`, `fail_on_kev`, `epss_threshold`, `fixable_only`, `modes`,
`allow_repo_policy`, `baseline_on_first_run` (default on), `baseline_grace_days` (1–730, optional; the baseline
findings' due date), and `baseline_secrets_block` (default on).

## 3. Rules

| Rule | Where |
|---|---|
| A field a business unit or repository policy does not list is inherited from the layer above | `cirun.Resolve` |
| A lock is a floor: no layer below may loosen a locked field, whatever its permission. Stricter values stay allowed. A write that would loosen one is refused (409). A value written before the lock is ignored when the gate resolves the policy | service, `cirun.Resolve` |
| Loosening a business unit or repository policy needs a reason (10–500 characters) and a recent sign-in. It is audited at high severity (`ci_gate_policy.loosened`) and announced to every administrator | service |
| Removing a lock, or dropping or extending the end of a looser repository policy, counts as loosening | service |
| A repository policy may end (`expires_at`, within 365 days). After that, the repository inherits again | `cirun.Resolve` |
| The verdict always uses the policy resolved on the server at evaluation time. The repository file only tightens | `Evaluate` |
| Organization and business unit policies need an unrestricted data scope. Repository policies and the effective-settings read need the repository in the caller's data scope (404 otherwise). Writes need `scans:ci:policy`; reads need `scans:ci:read` | handler |

## 4. API

| Method | Path | Gate | What |
|---|---|---|---|
| POST, PATCH | `/api/v1/ci/gate-policies[/{id}]` | `scans:ci:policy` | adds `fields`, `locked_fields`, `reason`, `expires_at`, and the three baseline fields |
| GET | `/api/v1/ci/pipelines?has_policy_override=true` | `scans:ci:read` | pipelines whose repository has its own enabled, unexpired policy |
| GET | `/api/v1/ci/gate-policies` | `scans:ci:read` | adds `override_counts`: per field, the active repository policies (that the caller may see) that set it |
| GET | `/api/v1/ci/gate-settings/{id}` | `scans:ci:read` | each field: effective value, inherited value, source (`default`, `tenant`, `business_unit`, `repository`), lock, ignored. Also the repository's own policy and whether it expired |

Existing policies keep their behaviour: the migration gives every row all fields.

## 5. Console (designed)

The pipeline sheet gets a **Settings** tab. Each field shows its effective value. Inherited values are greyed
with their source; overrides are highlighted with their reason, end and the organization's value. Each field
has Override and Reset to inherited. A loosening edit asks for a reason and an end. The tab also shows the gate
baseline (Record now, Remove) and the expected capabilities. The Pipelines list gets a "has overrides"
filter. The organization policy dialog gets per-field Lock switches and "N repositories override this field".
Bulk apply writes ordinary repository policies to the repositories, within the caller's data scope, whose name
matches a pattern. Each write follows the same rules and is audited.
