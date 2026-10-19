# RFC-118: Rule sources for scans

| | |
|---|---|
| Status | Accepted (2026-10-19). Partly implemented: the platform half (scan and profile setting, dispatch, fail-closed template resolution, claim-time capability gate) has shipped; the sensor half (one nuclei run for both sources, secret-rule merge, opengrep/semgrep, `rule.sources@1`) is in sdk-go and the sensor; tenant rule-id namespacing and provenance on findings follow |
| Scope | api (`scans.rule_sources`, `scan_profiles.rule_sources`, `internal/app/scan/rule_sources.go`, the command payload, `sensor.CapabilityRuleSources`, placement), web (scan and profile forms), sdk-go (`core.RuleSources`, `core.CheckCustomTemplate`), sensor (nuclei, betterleaks, opengrep, semgrep) |
| Related | RFC-040 (mutual distrust, signed jobs), RFC-061 (content packs), RFC-099 (content catalog), RFC-029 (sensor-reported capabilities), RFC-073 (scan approval); `docs/architecture/rule-sources.md` |

## 1. Problem

A scan runs the platform's detection rules (the sensor's managed template or
rule pack) and, when the scan names them, the organization's own scanner
templates. Until now the two ran as separate tool runs on the sensor
(nuclei: the platform set, then the organization's templates alone with
dangerous types excluded), the secret scanner replaced its default rules with
the organization's file, and nobody could choose to run only one of the two.
A template that could not be resolved was dropped with a log line, so a scan
silently ran without the rules its owner picked.

## 2. Decision

1. A scan and a scan profile have **rule sources**: `both` (default),
   `platform` or `tenant`. A scan's own setting wins; a scan without one
   inherits its profile's; without a profile, both run.
2. The run resolves the value once at trigger, records it in the run context,
   and sends it in every command (`rule_sources`). `platform` sends no custom
   templates. `tenant` requires at least one custom template on the scan
   (refused at save and at trigger).
3. **Fail closed.** When the organization's templates are to run, every
   template the scan names must exist in the scan's organization and be
   active; otherwise the run fails with the reason (which templates were not
   found, which are not active). Nothing is skipped silently.
4. **Old sensors keep working.** A sensor whose scanners honor rule sources
   reports `rule.sources@1` (sdk-go `core.CapabilityRuleSources`). A
   `tenant` command requires it (`required_features`), so an older sensor,
   which would also run the platform's rules, never claims it; the placement
   view names the reason (`rule_sources_unsupported`). For `both` an older
   sensor keeps its two-run behaviour, which yields the same findings; for
   `platform` it simply receives no templates.
5. **One run on the sensor.** With `both`, a scanner loads the platform rules
   and the organization's rules in one invocation (nuclei: one run with both
   template directories; betterleaks: the organization's rules extend the
   default rules, which the organization cannot disable unless it runs only
   its own; opengrep/semgrep: both configs). This is safe because every
   custom template is checked on the sensor after its signature
   (`core.CheckCustomTemplate`: no `code`, `javascript`, `flow`, `file`,
   `headless`, self-contained requests, workflows or payload files), so the
   restricted separate run is no longer needed.
6. **Namespacing and provenance.** Findings of an organization's rule carry
   a `tenant:`-prefixed rule id, so they never collide with a platform rule of
   the same id, and record the rule source and the template's id and revision
   for the finding's "Detection rule" line.

## 3. Threat model

- **Tenant isolation.** Templates are read only in the scan's organization
  (`ListByIDs(tenant, ids)`); another organization's id is "not found" and
  fails the run. Commands carry only the scan's own templates, also on shared
  sensors; the sensor writes them to a per-command directory.
- **Downgrade.** A tenant-only run must never execute platform rules on a
  sensor that cannot honor the choice: the claim predicate requires the
  sensor's own report of `rule.sources@1` (an administrator cannot declare
  it). The value travels inside the signed job payload.
- **Code execution through custom templates.** The platform validator refuses
  dangerous protocols at upload; the sensor re-checks the content after the
  signature check and before writing, so a merged run cannot execute a code
  template even if the platform were wrong.
- **Silent loss of detection.** Unresolvable templates fail the run instead
  of being dropped; the approval digest (RFC-073) covers the scan's rule
  sources, so changing them needs a new approval.

## 4. Not in scope

Workflow scans (their steps run the platform's rules); content snapshots and
per-run content manifests (research 185 WP3/WP4); the template studio UI.
